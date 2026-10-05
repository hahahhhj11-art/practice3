"""一键复现：把论文里每一条可验证的结论用一条命令跑出来。

    python scripts/reproduce.py --quick      # 冒烟规模，几分钟
    python scripts/reproduce.py --full       # 论文主表规模
    python scripts/reproduce.py --fail-fast  # 第一步失败就停

## 为什么第一步是能力探测而不是跑测试

本项目最重要的诚实性约束是「跨平台能力差如实汇报」：Linux 上 S2 是内核
强制（Landlock + seccomp），Windows 上只能做到 Job Object 生命周期约束，
文件与网络**没有**内核兜底。这意味着同一份代码在两台机器上能成立的结论
集合是不同的。如果不先把本机档位打出来，后面「非绕过性」那一格的数字就
会被误读成防御失效——它实际上是一条已登记的平台缺口。

所以流程刻意以 ``confine.probe()`` 开头，并在最终汇总里复述一遍本机档位。

## 为什么默认不中断

复现脚本的读者是审稿人，他要的是「哪些成立、哪些不成立」的完整图景，
而不是在第三步崩掉之后什么都看不到。各步骤之间只有数据依赖（生成样本 →
主实验），没有判定依赖，因此默认全部跑完再一起汇总；需要定位问题时用
``--fail-fast`` 切成"见错即停"。真正有前置依赖的步骤会在前置失败时显式
跳过并标注原因，不会拿一个注定失败的运行去污染汇总表。

## Windows 控制台编码

这个坑在本项目里踩过不止一次：子进程的 stdout 默认按控制台代码页
（中文 Windows 上是 GBK）编码，而所有脚本都在打中文说明与 ✔/✗ 状态图标，
于是子进程在 ``print`` 里就抛 UnicodeEncodeError 直接退出——表现为
"某一步莫名失败，但手工跑没问题"。因此每个子进程都被强制注入
``PYTHONUTF8=1`` 与 ``PYTHONIOENCODING=utf-8``，本进程自己的流也重新
配置一遍。不要因为"我这台机器上没事"就把它删掉。

## 已知的 Windows 竞态（步骤 g）

主实验在 Windows 上约每三次运行会有一次因 ``WinError 32`` 中断，原因见
``_is_provenance_lock_race`` 的注释。本脚本对它重试一次并在汇总里显式标注，
既不掩盖也不把它当成"实验跑不通"。Linux 上不会出现。
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import time
import tomllib
import unicodedata
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from trustgate.confine import probe

# 复现规模。两档的差别只在主实验与良性样本条数上——判定逻辑、策略、
# 样本集完全相同，所以 --quick 的结论方向与 --full 一致，只是每格样本少、
# 置信区间宽。刻意不提供"中间档"，避免论文里出现第三种说不清来源的数字。
#
# 规模按"每格几条"表达，而不是写死总条数。理由：格数（攻击目标 × 规避
# 层级）会随 attacks/generate.py 增删变体而变——这轮就从 12 格长到了 15 格。
# 写死 --limit 12 的话，新增的格会静默取不到样本，消融表上凭空出现空列。
SCALES: dict[str, dict[str, int]] = {
    "quick": {"per_cell": 1, "eval_benign": 3},
    # 每格 2 条 + 8 条良性，即 README 主表的取值
    "full": {"per_cell": 2, "eval_benign": 8},
}
# 只在 index.json 读不到时兜底。数值取自本文件写就时的格数，纯粹为了
# 让"样本集缺失"这种情况下的报错信息还算有意义。
_FALLBACK_CELLS = 12

# S0 下三条绕过路径（读沙箱密钥 / 写盘 / 开 INET socket）**必须全部成功**。
# 这不是"顺便验证一下"：没有这个对照，S2 的 0/3 无法排除"这些路径本来就
# 走不通"，整个非绕过性论断就失去参照。见 tests/test_confinement.py 的注释。
_EXPECTED_S0_BYPASS = 3


def _reconfigure_streams() -> None:
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):
            # errors="replace"：宁可把图标打成 '?' 也不要让汇总表因为一个
            # 字符编不出来而整体丢失。
            stream.reconfigure(encoding="utf-8", errors="replace")


def child_env() -> dict[str, str]:
    """子进程环境。见模块头部「Windows 控制台编码」。"""
    env = os.environ.copy()
    env["PYTHONUTF8"] = "1"
    env["PYTHONIOENCODING"] = "utf-8"
    return env


# ---------------------------------------------------------------- 步骤记账


@dataclass
class StepResult:
    key: str
    title: str
    ok: bool = False
    skipped: bool = False
    seconds: float = 0.0
    summary: str = ""
    # 失败时保留的证据。不打在汇总表里（太长），但在失败明细区打出来。
    detail: str = ""


@dataclass
class Runner:
    """按顺序执行步骤并记账。

    每个步骤是一个返回 (ok, summary, detail) 的可调用对象；抛异常等价于
    失败，异常文本进 detail——复现脚本自己崩掉是最没有信息量的失败方式。
    """

    quiet: bool = False
    fail_fast: bool = False
    results: list[StepResult] = field(default_factory=list)
    aborted: bool = False

    def banner(self, index: int, total: int, title: str) -> None:
        print()
        print("=" * 78)
        print(f"步骤 {index}/{total} · {title}")
        print("=" * 78, flush=True)

    def step(
        self,
        key: str,
        title: str,
        fn: Callable[[], tuple[bool, str, str]],
        *,
        index: int,
        total: int,
        skip_reason: str = "",
    ) -> StepResult:
        res = StepResult(key=key, title=title)
        if self.aborted:
            res.skipped, res.summary = True, "前序步骤失败且已开启 --fail-fast"
            self.results.append(res)
            return res
        if skip_reason:
            self.banner(index, total, title)
            print(f"  跳过：{skip_reason}")
            res.skipped, res.summary = True, skip_reason
            self.results.append(res)
            return res

        self.banner(index, total, title)
        t0 = time.perf_counter()
        try:
            res.ok, res.summary, res.detail = fn()
        except Exception as exc:  # 包括 KeyError/JSONDecodeError 等解析失败
            res.ok = False
            res.summary = f"{type(exc).__name__}: {exc}"
            res.detail = res.summary
        res.seconds = time.perf_counter() - t0

        icon = "✔ 通过" if res.ok else "✗ 失败"
        print(f"\n  {icon} · {res.seconds:.1f}s · {res.summary}", flush=True)
        self.results.append(res)
        if not res.ok and self.fail_fast:
            self.aborted = True
        return res

    def ran_ok(self, key: str) -> bool:
        return any(r.key == key and r.ok for r in self.results)


def run_cmd(argv: list[str], quiet: bool, timeout: int = 3600) -> tuple[int, str]:
    """跑一个子进程，边跑边回显（缩进两格），同时把输出收集起来待解析。

    为什么不用 subprocess.run(capture_output=True)：主实验那一步要几分钟，
    全程静默会让人分不清"还在跑"和"卡死了"。因此流式转发；--quiet 下只
    保留输出供解析，最后按需打尾部。
    """
    print(f"  $ {' '.join(argv)}", flush=True)
    proc = subprocess.Popen(
        argv,
        cwd=str(ROOT),
        env=child_env(),
        stdout=subprocess.PIPE,
        # 合并 stderr：unittest 把结果写在 stderr，分开读会让"OK/FAILED"
        # 与失败明细在时间上错位，看不出哪条用例对应哪段回溯。
        stderr=subprocess.STDOUT,
        text=True,
        encoding="utf-8",
        errors="replace",
        bufsize=1,
    )
    lines: list[str] = []
    assert proc.stdout is not None
    for line in proc.stdout:
        line = line.rstrip("\n")
        lines.append(line)
        if not quiet:
            print(f"  | {line}", flush=True)
    code = proc.wait(timeout=timeout)
    return code, "\n".join(lines)


def _tail(text: str, n: int = 25) -> str:
    return "\n".join(text.splitlines()[-n:])


def _display_width(s: str) -> int:
    """按终端列数算宽度：CJK 字符占两列。

    步骤标题全是中文，用 len() 对齐汇总表会歪得没法看。标准库的
    unicodedata 就能判宽，不值得为此引入 wcwidth。
    """
    return sum(2 if unicodedata.east_asian_width(c) in "WF" else 1 for c in s)


def _pad(s: str, width: int) -> str:
    return s + " " * max(0, width - _display_width(s))


def py(*args: str) -> list[str]:
    return [sys.executable, *args]


# ---------------------------------------------------------------- a. 能力探测


def step_probe(env_note: dict[str, Any]) -> tuple[bool, str, str]:
    info = probe()
    env_note.update(info)
    print(f"  解释器      {sys.version.split()[0]}  ({sys.executable})")
    print(f"  平台/架构   {info['platform']} / {info['machine']}")
    print(f"  Landlock ABI {info['landlock_abi']}（<=0 表示本机内核不支持）")
    print(f"  seccomp 架构已适配  {'是' if info['seccomp_arch_supported'] else '否'}")
    print(f"\n  本机可达的最高权限剥离档位：{info['max_level']}")

    if info["max_level"] == "S2":
        print(
            "  → 非绕过性（SC5）在本机是**内核强制**的事实：S2 下读沙箱、写盘、"
            "开 INET socket 三条路径由 Landlock/seccomp 拒绝。"
        )
    else:
        print(
            f"  → 本机（{info['platform']}）无 Landlock/seccomp 等价物，S2 会降级为 S1。\n"
            "    这不是实现缺陷，是已登记在 ConfinementReport.gaps 里的平台能力差：\n"
            "    tests/test_confinement.py 的内核级用例会自动跳过，"
            "scripts/bypass_demo.py --level S2 仍会报三条绕过可用。\n"
            "    要验证内核强制的那一档，需要一台 Linux（CI 的 ubuntu-latest 就是为此存在）。"
        )
    # 探测本身是测量而非判定，只要 probe() 没抛异常就算通过——本机档位低
    # 不该被记成"复现失败"。
    return True, f"本机最高档位 {info['max_level']}（{info['platform']}）", ""


# ---------------------------------------------------------------- b. 沙箱重置


def step_sandbox() -> tuple[bool, str, str]:
    code, out = run_cmd(py("-m", "trustgate.sandbox", "reset"), quiet=False)
    if code != 0:
        return False, f"退出码 {code}", _tail(out)
    # 重置会重建文件树并重写基线哈希清单，这是后面所有"攻击是否成功"的
    # 客观判定的起点；基线不对，T2/T3 的 ASR 全是噪声。
    baseline = json.loads((ROOT / "sandbox" / ".baseline.json").read_text(encoding="utf-8"))
    return True, f"沙箱已重建，基线覆盖 {len(baseline.get('files', {}))} 个文件", ""


# ---------------------------------------------------------------- c. 单元测试


def unittest_argv() -> list[str]:
    """从 pyproject.toml 的 [tool.unittest] 拼出发现参数。

    刻意不在这里硬编码 "-s tests"：CI、README 与本脚本必须共用同一份发现
    规则，否则某天有人加了 tests/integration/ 只改了一处，另外两处静默漏跑。
    """
    cfg: dict[str, Any] = {}
    pyproject = ROOT / "pyproject.toml"
    if pyproject.exists():
        with pyproject.open("rb") as fh:
            cfg = tomllib.load(fh).get("tool", {}).get("unittest", {})
    argv = [
        "-m", "unittest", "discover",
        "-s", str(cfg.get("start-dir", "tests")),
        "-p", str(cfg.get("pattern", "test_*.py")),
        "-t", str(cfg.get("top-level-dir", ".")),
    ]
    if int(cfg.get("verbosity", 1)) >= 2:
        argv.append("-v")
    return argv


def step_tests(quiet: bool) -> tuple[bool, str, str]:
    # 测试跑在样本生成之前（步骤 c 在 d 之前），所以在全新 clone 上
    # test_attack_samples_actually_succeed_without_defense 会因为找不到
    # attacks/samples/index.json 而 skip。这里明说一句，免得读者以为
    # "数据集有效性根本没测"——它测了，只是要么本轮已有旧样本集，要么
    # 由步骤 d+g 用本轮新生成的样本集覆盖同一件事。
    if not (ROOT / "attacks" / "samples" / "index.json").exists():
        print(
            "  注：尚无攻击样本集（本轮步骤 d 才生成），"
            "数据集有效性那条用例会 skip；重跑一次即会执行。"
        )
    code, out = run_cmd(py(*unittest_argv()), quiet=quiet)
    # unittest 的统计行形如 "Ran 41 tests in 12.3s" + "OK (skipped=6)"。
    # 跳过**不是**失败：Windows 上内核级用例按平台能力差主动跳过，把它算成
    # 失败等于要求一台没有 Landlock 的机器证明 Landlock 生效。
    ran = next((ln for ln in out.splitlines() if ln.startswith("Ran ")), "")
    verdict = next(
        (ln for ln in reversed(out.splitlines()) if ln.startswith(("OK", "FAILED"))), ""
    )
    summary = " · ".join(x for x in (ran, verdict) if x) or f"退出码 {code}"
    return code == 0, summary, "" if code == 0 else _tail(out, 40)


# ---------------------------------------------------------------- d. 攻击样本集


def step_generate(quiet: bool) -> tuple[bool, str, str]:
    # 刻意**不**传 --limit：generate() 的组合顺序是
    # (目标×规避层级) → 载体 → 策略 → 强度，最外层变化最慢，因此 --limit N
    # 只会取到第一格（read/naive）的前 N 条。真正的"小规模"要在实验侧用
    # eval 的 --limit 做按格轮转取样，那才是每格都有的抽样。
    code, out = run_cmd(py("attacks/generate.py", "--clean"), quiet=quiet)
    if code != 0:
        return False, f"退出码 {code}", _tail(out)
    index = ROOT / "attacks" / "samples" / "index.json"
    records = json.loads(index.read_text(encoding="utf-8"))
    cells = sorted({f"{r['target']}/{r['evasion']}" for r in records})
    print(f"\n  覆盖 {len(cells)} 个「攻击目标 / 规避层级」格：{'、'.join(cells)}")
    return True, f"{len(records)} 条样本 / {len(cells)} 格", ""


# ---------------------------------------------------------------- e. 非绕过性对照


def _bypass(level: str) -> dict[str, Any]:
    out = subprocess.run(
        py("scripts/bypass_demo.py", "--level", level, "--json"),
        cwd=str(ROOT), env=child_env(), capture_output=True,
        text=True, encoding="utf-8", errors="replace", timeout=300,
    )
    if out.returncode != 0:
        raise RuntimeError(f"bypass_demo --level {level} 退出码 {out.returncode}\n{_tail(out.stderr)}")
    return json.loads(out.stdout)


def step_bypass(max_level: str) -> tuple[bool, str, str]:
    s0 = _bypass("S0")
    s2 = _bypass("S2")

    for tag, got in (("S0 对照组", s0), ("S2 实验组", s2)):
        rep = got["confinement"]
        print(f"\n  ── {tag}（请求 {rep['requested']} → 实际 {rep['effective']}）")
        print(f"     机制：{', '.join(rep['mechanisms']) or '无'}")
        print(f"     OS 强制：{'是' if rep['os_enforced'] else '否'}")
        for name, r in got["attempts"].items():
            print(f"     [{'绕过成功' if r['bypassed'] else '已被拦截'}] {name}")
        print(f"     bypass_count = {got['bypass_count']}/3")

    n0, n2 = int(s0["bypass_count"]), int(s2["bypass_count"])
    if n0 != _EXPECTED_S0_BYPASS:
        return (
            False,
            f"S0 对照组只有 {n0}/3 条绕过成功，对照失效",
            "S0 必须三条全通，否则无法排除「这些路径本来就走不通」，"
            f"S2 的结果失去参照。实测：{json.dumps(s0['attempts'], ensure_ascii=False)}",
        )

    if max_level == "S2":
        ok = n2 == 0 and bool(s2["confinement"]["os_enforced"])
        note = f"S0 {n0}/3 可绕过 → S2 {n2}/3（内核强制）"
        detail = "" if ok else json.dumps(s2["attempts"], ensure_ascii=False, indent=2)
        if ok:
            print("\n  → 差值 3→0 即为权限剥离层的贡献，且由内核而非应用层检查给出。")
        return ok, note, detail

    # 本机达不到 S2：S2 降级成 S1，三条绕过仍然可用。这是如实汇报的平台
    # 缺口，不是复现失败——把它记成失败会诱导后来的人去"修"一个不存在的
    # bug，或者更糟，去放宽 effective 档位的判定让报告好看。
    print(
        "\n  → 本机 S2 降级为 S1，三条绕过仍可用。这是 ConfinementReport.gaps 里\n"
        "    已登记的平台能力差；内核强制的那一半结论需在 Linux 上复现。"
    )
    ok = n2 == _EXPECTED_S0_BYPASS and not s2["confinement"]["os_enforced"]
    if not ok:
        return False, "降级路径行为异常：既未内核强制，又未如实报告绕过可用", json.dumps(s2, ensure_ascii=False, indent=2)
    return True, f"S0 {n0}/3 · S2 降级为 S1 后仍 {n2}/3（已登记的平台缺口）", ""


def _clean_bypass_artifact() -> None:
    """S0/S1 档下 B 号绕过真的会把文件写进沙箱，清掉以免污染后续基线。"""
    (ROOT / "sandbox" / "workspace" / "out" / ".bypass-probe").unlink(missing_ok=True)


# ---------------------------------------------------------------- f. 审计篡改检测


def step_tamper(quiet: bool) -> tuple[bool, str, str]:
    code, out = run_cmd(py("scripts/tamper_demo.py"), quiet=quiet)
    if code != 0:
        return False, f"退出码 {code}", _tail(out)

    # 汇总区的每行形如 "  ✔ 改写记录内容                检测到"。
    # 这里只统计"检测到/未检测到"的条数，不重述结论——结论由 tamper_demo
    # 自己打印，复述一遍只会多出一个可能与实现跑偏的事实来源。
    missed = sum(1 for ln in out.splitlines() if ln.strip().endswith("未检测到"))
    detected = sum(1 for ln in out.splitlines() if ln.strip().endswith("检测到")) - missed
    print(
        "\n  → 其中「未检测到」的那一格是刻意保留的：尾部截断在校验方没有\n"
        "    离机检查点时本地不可判定，SC4 的措辞必须限定这个前提。"
    )
    return True, f"篡改检测：{detected} 格检测到、{missed} 格未检测到（含刻意保留的一格）", ""


# ---------------------------------------------------------------- g. 主对比实验


def _is_provenance_lock_race(out: str) -> bool:
    """识别一个 Windows 竞态。**根因已在源头修掉**，这里是最后一道网。

    ``eval/run_eval.py`` 每个 trial 开头要清空跨会话溯源存储。POSIX 上 unlink 一个
    仍被别人打开的文件没问题；Windows 的删除语义要求此刻没有任何进程持有句柄，
    于是会抛 ``WinError 32``，且集中在 C5（anchor=T1，锚是独立进程，上一个 trial
    刚写完 provenance.json 就退出）。

    正确的修法是在那一行做短退避重试，而不是让复现脚本去重跑整个实验——已实现为
    ``run_eval._unlink_with_retry()``。因此这个分支正常情况下不会再被触发。

    保留它的理由：重试用尽仍失败时 ``_unlink_with_retry`` 会**抛出**（溯源没清干净
    会让上个样本的污点漏进下一个，那是真会污染结论的情况，必须响亮失败）。真撞上
    这种极端情况时，整轮实验重跑一次通常就过了，所以这里仍然重试一次，并**在汇总里
    明说重试过**。悄悄重试等于把缺陷从报告里抹掉；直接失败又会让 Windows 上的审稿人
    以为实验跑不通。
    """
    return "WinError 32" in out and "provenance.json" in out


def corpus_cells() -> int:
    """样本集里「攻击目标 / 规避层级」的格数。

    eval 的 --limit 是按格轮转取样的（见 run_eval.load_samples），所以
    "每格 N 条"要换算成 N × 格数 才能真的每格都取到。
    """
    index = ROOT / "attacks" / "samples" / "index.json"
    if not index.exists():
        return _FALLBACK_CELLS
    try:
        records = json.loads(index.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return _FALLBACK_CELLS
    return len({f"{r['target']}/{r['evasion']}" for r in records}) or _FALLBACK_CELLS


def step_eval(scale: str, quiet: bool) -> tuple[bool, str, str]:
    cfg = SCALES[scale]
    cells = corpus_cells()
    limit = cfg["per_cell"] * cells
    out_rel = f"logs/eval-report-reproduce-{scale}.json"
    print(f"  取样：每格 {cfg['per_cell']} 条 × {cells} 格 = --limit {limit}")
    argv = py(
        "-m", "eval.run_eval",
        "--limit", str(limit),
        "--benign", str(cfg["eval_benign"]),
        "--out", out_rel,
    )
    retried = ""
    code, out = run_cmd(argv, quiet=quiet, timeout=7200)
    if code != 0 and _is_provenance_lock_race(out):
        print(
            "\n  ! 命中已知缺陷：eval/run_eval.py 清理 .trustgate/provenance.json 时\n"
            "    被 WinError 32（文件被占用）打断。这是 Windows 删除语义导致的竞态，\n"
            "    发生在策略判定之前的清理阶段，不影响任何一次 allow/deny 判定。\n"
            "    重试一次；无论成败都会在汇总里标注重试过。"
        )
        retried = "（重试 1 次：命中已知的 Windows provenance 文件锁竞态）"
        code, out = run_cmd(argv, quiet=quiet, timeout=7200)
    if code != 0:
        return False, f"退出码 {code}{retried}", _tail(out, 40)

    report = json.loads((ROOT / out_rel).read_text(encoding="utf-8"))
    groups = report["groups"]
    print("\n  组 | ASR | UA | BTC | 实际阻断率 | 良性 FPR")
    for gid, m in groups.items():
        print(
            f"  {gid} | {m['ASR']}% | {m['UA']}% | {m['BTC']}% "
            f"| {m['BR_calls']}% | {m['FPR_benign_calls']}%"
        )
    print(f"\n  完整结果 → {out_rel}")
    print(
        "  ASR 必须与 UA 一起读：一律拒绝的网关 ASR=0% 且 BTC=100%，但 UA 会塌到 0。"
    )
    print(
        f"\n  论文完整规模（每格 96 条，共 {96 * cells} 条攻击样本 × 6 组，耗时以小时计）：\n"
        "    python -m eval.run_eval --benign 10 --out logs/eval-report.json\n"
        "  提示：MockLLM 从不阅读注入文本的外观，同格 96 条样本的 sim_actions 完全\n"
        "  相同，跑全量只是把同一结果重复 96 遍。按格取样（本脚本的做法）在\n"
        "  ASR@obedient 口径下与全量等价，见 eval/run_eval.py 的 asr_semantics。"
    )

    errors = sum(int(m.get("errors", 0)) for m in groups.values())
    c0, c5 = groups.get("C0", {}), groups.get("C5", {})
    bits = [f"{len(groups)} 组"]
    if c0 and c5:
        bits.append(f"ASR C0 {c0['ASR']}% → C5 {c5['ASR']}%（UA {c5['UA']}%）")
    if errors:
        bits.append(f"{errors} 条 trial 报错")
    return True, " · ".join(bits) + retried, ""


# ---------------------------------------------------------------- h. 取证层


def step_forensics(quiet: bool) -> tuple[bool, str, str]:
    """取证层单独成一步，因为它的结论性质与前面几步不同。

    前面各步验的都是"防住了没有"；取证回答的是拦下来之后能不能说清**是哪段
    外部内容干的**。它不在关键路径上，因此即便这一步失败也不影响 C0–C5 的
    任何数字——但它是论文里"可运维性"那一节唯一的实证支撑，不能只有代码没有
    复现入口。

    这里跑的是端到端那条：打开捕获开关、在真实攻击样本上跑一次、再用
    forensics_report 去定位与归因，并与样本自带的载荷原文对分数。

    这些用例在步骤 c 的全量发现里已经跑过一遍，这里是刻意重跑：步骤 c 只会
    给出一个"OK"，而端到端取证需要在样本集**生成之后**才有真实样本可用（步骤 c
    在 d 之前，全新 clone 上那条会 skip），并且这一步要把上面那两条结论性的
    限定条件打在汇总流里——否则读者只会看到一个通过标记，看不到边界在哪。
    """
    code, out = run_cmd(py("-m", "unittest", "tests.test_forensics", "-v"), quiet=quiet)
    if code != 0:
        return False, f"退出码 {code}", _tail(out, 40)
    ran = next((ln for ln in out.splitlines() if ln.startswith("Ran ")), "")
    print(
        "\n  → 其中 test_pure_persuasion_injection_is_not_locatable 是刻意保留的**反例**：\n"
        "    数据流最小化只能定位在工具参数上留下痕迹的注入；纯说服型注入\n"
        "    （\"忽略之前的指令\"）不出现在任何参数里，定位不到。这条边界由测试钉住，\n"
        "    以免在论文里被说成「能定位任意注入」。\n"
        "  → 捕获默认关闭（policy.json 的 forensics.capture）：审计日志刻意只存\n"
        "    args_digest 不存原文，开启捕获等于在磁盘上多留一份未脱敏副本。"
    )
    return True, f"{ran or '取证用例全通'}（含 1 条能力边界反例）", ""


# ---------------------------------------------------------------- 汇总


def print_summary(runner: Runner, scale: str, env_note: dict[str, Any]) -> int:
    print()
    print("=" * 78)
    print(f"复现汇总 · 规模 {scale} · 平台 {env_note.get('platform', sys.platform)} "
          f"· 最高剥离档位 {env_note.get('max_level', '?')}")
    print("=" * 78)

    width = max(_display_width(r.title) for r in runner.results)
    total = 0.0
    for i, r in enumerate(runner.results, start=1):
        icon = "跳过" if r.skipped else ("通过" if r.ok else "失败")
        total += r.seconds
        print(f"  {i}. [{icon}] {_pad(r.title, width)}  {r.seconds:6.1f}s  {r.summary}")
    print(f"\n  合计耗时 {total:.1f}s")

    failed = [r for r in runner.results if not r.ok and not r.skipped]
    skipped = [r for r in runner.results if r.skipped]
    if skipped:
        print("\n  未执行：")
        for r in skipped:
            print(f"    · {r.title}：{r.summary}")
    if failed:
        print("\n  失败明细：")
        for r in failed:
            print(f"\n    ── {r.title}：{r.summary}")
            for ln in r.detail.splitlines():
                print(f"       {ln}")
        return 1

    print("\n  全部步骤通过。")
    if env_note.get("max_level") != "S2":
        print(
            "  注意：本机未达 S2，非绕过性的内核强制部分（SC5）在此平台上未被验证，\n"
            "  只验证了「降级时如实汇报」。完整验证需 Linux（见 .github/workflows/ci.yml）。"
        )
    return 0


def main() -> int:
    _reconfigure_streams()

    ap = argparse.ArgumentParser(
        description="TrustGate 一键复现：环境探测 → 沙箱 → 单元测试 → 样本集 "
                    "→ 非绕过性 → 审计篡改 → 主实验 → 取证层",
    )
    scale = ap.add_mutually_exclusive_group()
    scale.add_argument("--quick", action="store_const", const="quick", dest="scale",
                       help="冒烟规模（默认）：主实验每格 1 条样本")
    scale.add_argument("--full", action="store_const", const="full", dest="scale",
                       help="论文主表规模：主实验每格 2 条 + 8 条良性")
    ap.add_argument("--fail-fast", action="store_true",
                    help="任一步失败立即停止；默认跑完全部步骤再汇总")
    ap.add_argument("--quiet", action="store_true",
                    help="不回显子进程输出，只打各步摘要（失败时仍打尾部）")
    ns = ap.parse_args()
    chosen = ns.scale or "quick"

    print("=" * 78)
    print("TrustGate 复现流程")
    print("=" * 78)
    print(f"  仓库根 {ROOT}")
    print(f"  规模   {chosen}（主实验每格 {SCALES[chosen]['per_cell']} 条 "
          f"+ {SCALES[chosen]['eval_benign']} 条良性任务）")
    print(f"  失败处理 {'见错即停' if ns.fail_fast else '跑完全部步骤后汇总'}")

    runner = Runner(quiet=ns.quiet, fail_fast=ns.fail_fast)
    env_note: dict[str, Any] = {}
    total = 8

    runner.step("probe", "a. 环境与权限剥离能力探测",
                lambda: step_probe(env_note), index=1, total=total)
    max_level = str(env_note.get("max_level", "S1"))

    runner.step("sandbox", "b. 沙箱重置与基线哈希清单",
                step_sandbox, index=2, total=total)
    runner.step("tests", "c. 全套单元测试",
                lambda: step_tests(ns.quiet), index=3, total=total)
    gen = runner.step("generate", "d. 生成 IPI 攻击样本集",
                      lambda: step_generate(ns.quiet), index=4, total=total)

    runner.step("bypass", "e. 非绕过性对照实验（S0 vs S2）",
                lambda: step_bypass(max_level), index=5, total=total)
    _clean_bypass_artifact()

    runner.step("tamper", "f. 审计链篡改检测演示（SC4）",
                lambda: step_tamper(ns.quiet), index=6, total=total)

    # 主实验必须有样本集才能跑。生成失败时直接标跳过，而不是让它去读一份
    # 过期的 index.json——那样得出的 ASR 与本次运行的样本集不对应。
    runner.step(
        "eval", "g. C0–C5 主对比实验",
        lambda: step_eval(chosen, ns.quiet), index=7, total=total,
        skip_reason="" if gen.ok else "攻击样本集生成失败，主实验的输入不可信",
    )

    # 取证的端到端用例要在真实样本上跑，因此同样依赖步骤 d。
    runner.step(
        "forensics", "h. 异步取证层：定位 · 归因 · 恢复",
        lambda: step_forensics(ns.quiet), index=8, total=total,
        skip_reason="" if gen.ok else "攻击样本集生成失败，端到端取证无样本可用",
    )

    return print_summary(runner, chosen, env_note)


if __name__ == "__main__":
    raise SystemExit(main())
