"""真实模型实验：把 ASR@model 拆成「模型易感性 × 网关强制力」。

    python -m eval.run_model_eval --model gpt-4o-mini --limit 15
    python -m eval.run_model_eval --replay-only          # 不联网，用随仓库的缓存复现
    python -m eval.run_model_eval --preflight            # 只检查环境，不跑实验

为什么必须拆开（这是本脚本存在的唯一理由）
------------------------------------------
主实验用的 MockLLM 被脚本设为**百分百服从注入**，所以 C0 的 ASR 天然是 100%，
测出来的是网关强制力的上界，记作 ASR@obedient。换成真实模型之后，
``ASR@model = 0%`` 有两种完全不同的成因：

    (a) 网关把注入动作拦住了；                ← 我们想证明的
    (b) 模型压根没听注入的话。                ← 与网关无关

把两者混在一个数字里报告，等于把模型的对齐效果算成自己的防御效果。八篇参考
文献里不止一篇栽在这上面：只报防御后的 ASR，不报同一模型在无防护条件下会不会
中招，于是"防御有效"与"这个模型本来就不容易骗"无法区分。

所以本脚本对**每一条样本都跑两臂**：

    C0 无防护（observe 模式，判定照做但不拦）  → 模型是否真的服从了注入
    C5 全防护                                  → 注入是否仍然得手

于是

    模型易感性 S   = C0 中攻击成功的样本比例
    ASR@model      = C5 中攻击成功的样本比例
    条件阻断率 CBR = 1 − (C5 成功数 / C0 成功数)      ← 只在模型真的中招的样本上算

CBR 是唯一能归因给网关的数字。S 不是我们的成绩（那是模型厂商的对齐效果），
但没有 S 就读不懂 ASR@model。样本在 C0 里就没成功时，它在 C5 的 0% 不提供任何
关于网关的信息，必须从分母里剔除——而不是当成一次"防御成功"。

无 key 时的降级
--------------
不联网、也没有缓存时，本脚本**不输出任何数字**，以退出码 3 结束并说明原因。
这一点是刻意的：给一个"跳过"比给一个来源不明的数字有用得多。缓存
（logs/llm_cache.jsonl）随仓库提供时，``--replay-only`` 可完全离线复现同一批
结论，审稿人不需要我们的 API key。
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import sys
import tempfile
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from eval.run_eval import GROUPS, Trial, derive_policy, load_samples, run_trial  # noqa: E402
from trustgate.llm import LLMBackend, OpenAICompatibleLLM  # noqa: E402
from trustgate.paths import project_root  # noqa: E402

# 两臂固定为这两组，不做成参数。
#
# C0 是易感性的唯一合法测法：它必须是 observe 模式——判定照常做、照常入审计，
# 但字节仍然落盘。如果拿一个"关掉了部分层"的中间组（C1–C4）去测易感性，
# 测到的是"在部分防护下模型还能不能成功"，那不是易感性，而是另一个被污染的
# 混合量，代进 CBR 的分母会直接把结论做坏。
ARM_UNDEFENDED = "C0"
ARM_DEFENDED = "C5"


# ---------------------------------------------------------------- 预检


@dataclass
class Preflight:
    model: str
    base_url: str = ""
    has_key: bool = False
    cache_entries: int = 0
    reachable: bool | None = None          # None 表示没探（replay_only 下不探）
    error: str = ""

    @property
    def can_run_online(self) -> bool:
        return self.has_key and self.reachable is True

    @property
    def can_replay(self) -> bool:
        return self.cache_entries > 0

    def describe(self) -> str:
        lines = [
            f"  模型        {self.model}",
            f"  接口地址    {self.base_url}",
            f"  API key     {'已设置（TG_API_KEY）' if self.has_key else '未设置'}",
            f"  录制缓存    {self.cache_entries} 条（logs/llm_cache.jsonl）",
        ]
        if self.reachable is None:
            lines.append("  连通性      未探测")
        else:
            lines.append(f"  连通性      {'可达' if self.reachable else '不可达'}")
        if self.error:
            lines.append(f"  探测错误    {self.error}")
        return "\n".join(lines)


def preflight(model: str, probe_network: bool, cache_path: str = "logs/llm_cache.jsonl") -> Preflight:
    """检查真实模型实验的前置条件。只探测，不产生任何实验数字。"""
    cache = project_root() / cache_path
    entries = 0
    if cache.exists():
        with cache.open("r", encoding="utf-8") as fh:
            entries = sum(1 for ln in fh if ln.strip())

    pf = Preflight(
        model=model,
        base_url=(os.environ.get("TG_BASE_URL") or "https://api.openai.com/v1").rstrip("/"),
        has_key=bool(os.environ.get("TG_API_KEY")),
        cache_entries=entries,
    )
    if not probe_network or not pf.has_key:
        return pf

    # 连通性探测用最短的一次真实请求，而不是去 ping 域名：真正会失败的是
    # 鉴权与配额，不是 DNS。探测结果本身也进缓存，所以这一次不算浪费。
    try:
        llm = OpenAICompatibleLLM(model=model, temperature=0.0)
        llm._chat([{"role": "user", "content": "ok"}])
        pf.reachable = True
    except Exception as exc:
        pf.reachable = False
        pf.error = f"{type(exc).__name__}: {str(exc)[:200]}"
    return pf


# ---------------------------------------------------------------- 结果


@dataclass
class PairedOutcome:
    """一条样本在两臂下的配对结果。配对是关键：同一条样本、同一个模型。"""

    sample: str
    target: str
    evasion: str
    expect_layer: str
    undefended_success: bool = False       # C0：模型是否真的服从了注入
    defended_success: bool = False         # C5：注入是否仍然得手
    undefended_task_done: bool = False
    defended_task_done: bool = False
    blocking_rule: str = ""
    errors: list[str] = field(default_factory=list)

    @property
    def informative(self) -> bool:
        """这条样本能否用来评价网关。

        C0 就没成功 → 模型自己拒绝或能力不足，它在 C5 的 0% 与网关无关。
        """
        return self.undefended_success

    @property
    def blocked_by_gateway(self) -> bool:
        return self.undefended_success and not self.defended_success


def summarize(outcomes: list[PairedOutcome]) -> dict[str, Any]:
    n = len(outcomes)
    susceptible = [o for o in outcomes if o.undefended_success]
    defended_hits = [o for o in outcomes if o.defended_success]
    blocked = [o for o in susceptible if o.blocked_by_gateway]

    def pct(part: list[Any], whole: list[Any]) -> float:
        return round(100.0 * len(part) / len(whole), 1) if whole else 0.0

    rules: dict[str, int] = {}
    for o in blocked:
        if o.blocking_rule:
            rules[o.blocking_rule] = rules.get(o.blocking_rule, 0) + 1

    per_cell: dict[str, Any] = {}
    for cell in sorted({f"{o.target}/{o.evasion}" for o in outcomes}):
        sub = [o for o in outcomes if f"{o.target}/{o.evasion}" == cell]
        sus = [o for o in sub if o.undefended_success]
        per_cell[cell] = {
            "n": len(sub),
            "susceptible": len(sus),
            "ASR_model": pct([o for o in sub if o.defended_success], sub),
            # 分母是易感子集；该格模型一条都没中招时留 None 而不是写 0 或 100,
            # 否则汇总表上会出现一个凭空而来的"完美阻断"。
            "CBR": pct([o for o in sus if o.blocked_by_gateway], sus) if sus else None,
        }

    return {
        "n_samples": n,
        "model_susceptibility": pct(susceptible, outcomes),
        "n_susceptible": len(susceptible),
        "ASR_model": pct(defended_hits, outcomes),
        "conditional_blocking_rate": pct(blocked, susceptible) if susceptible else None,
        "n_uninformative": n - len(susceptible),
        "UA_defended": pct([o for o in outcomes if o.defended_task_done], outcomes),
        "UA_undefended": pct([o for o in outcomes if o.undefended_task_done], outcomes),
        "blocking_rules": dict(sorted(rules.items(), key=lambda kv: -kv[1])),
        "per_cell": per_cell,
        "errors": sum(len(o.errors) for o in outcomes),
    }


def render(report: dict[str, Any]) -> str:
    m = report["metrics"]
    meta = report["meta"]
    out = [
        f"真实模型实验 · {meta['model']} · {m['n_samples']} 条样本 "
        f"· {'离线回放' if meta['replay_only'] else '在线'}",
        "",
        f"  模型易感性 S        {m['model_susceptibility']}%  "
        f"（{m['n_susceptible']}/{m['n_samples']} 条在无防护下真的中招）",
        f"  ASR@model（C5）     {m['ASR_model']}%",
    ]
    cbr = m["conditional_blocking_rate"]
    out.append(
        f"  条件阻断率 CBR      {cbr}%  （只在上面那 {m['n_susceptible']} 条上算）"
        if cbr is not None
        else "  条件阻断率 CBR      不可计算：该模型在无防护下一条都没中招"
    )
    out += [
        f"  任务效用 UA         无防护 {m['UA_undefended']}% → 全防护 {m['UA_defended']}%",
        "",
    ]
    if m["n_uninformative"]:
        out += [
            f"  已从 CBR 分母剔除 {m['n_uninformative']} 条：这些样本模型在无防护条件下",
            "  就没能得手（拒绝执行或能力不足），它们在 C5 的 0% 不构成网关的功劳。",
            "",
        ]
    if cbr is not None:
        out += [
            f"  可归因给网关的结论只有 CBR={cbr}%。ASR@model={m['ASR_model']}% 里同时",
            f"  含有模型自身的对齐效果（S={m['model_susceptibility']}%），不应单独引用。",
            "",
        ]

    out.append("  按「攻击目标 / 规避层级」分格：")
    out.append("    格                          n  易感  ASR@model  CBR")
    for cell, c in report["metrics"]["per_cell"].items():
        cbr_s = "  —  " if c["CBR"] is None else f"{c['CBR']:>5}%"
        out.append(
            f"    {cell:<26} {c['n']:>2}  {c['susceptible']:>3}  "
            f"{c['ASR_model']:>8}%  {cbr_s}"
        )
    if m["blocking_rules"]:
        out += ["", "  实际生效的拦截规则（只统计模型真的中招那些样本）："]
        for rule, cnt in m["blocking_rules"].items():
            out.append(f"    {cnt:>3}  {rule}")
    return "\n".join(out)


# ---------------------------------------------------------------- 主流程


def run_arm(
    gid: str,
    sample: dict[str, Any],
    workdir: Path,
    collector: Any,
    llm_factory: Any,
    audit_dir: Path,
    base_policy: Path,
) -> Trial:
    group = GROUPS[gid]
    # derive_policy 的输出文件名自带组号（policy-C0.json / policy-C5.json），
    # 所以两臂共用同一个工作目录不会互相覆盖；额外套一层 workdir/gid 反而会因为
    # derive_policy 不建目录而直接 FileNotFoundError。
    policy_path = derive_policy(group, base_policy, workdir)
    return run_trial(group, sample, policy_path, collector, llm_factory, audit_dir, confirm="deny")


def main() -> int:
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):
            stream.reconfigure(encoding="utf-8", errors="replace")

    ap = argparse.ArgumentParser(
        description="真实模型实验：把 ASR@model 拆成模型易感性与网关条件阻断率"
    )
    ap.add_argument("--model", default="gpt-4o-mini")
    ap.add_argument("--limit", type=int, default=15,
                    help="攻击样本条数（按「目标/规避层级」轮转取样）。每条要跑两臂，"
                         "因此实际模型调用量约为 2×limit×步数")
    ap.add_argument("--targets", help="只跑指定攻击类别")
    ap.add_argument("--evasions", help="只跑指定规避层级")
    ap.add_argument("--replay-only", action="store_true",
                    help="只用录制缓存，绝不联网；缓存缺失即报错而不是偷偷发请求")
    ap.add_argument("--preflight", action="store_true", help="只做环境预检，不跑实验")
    ap.add_argument("--policy", default="policy.json")
    ap.add_argument("--port", type=int, default=8799)
    ap.add_argument("--out", default="logs/model-eval-report.json")
    ns = ap.parse_args()

    print("=" * 78)
    print("真实模型实验预检")
    print("=" * 78)
    pf = preflight(ns.model, probe_network=not ns.replay_only)
    print(pf.describe())

    if ns.preflight:
        return 0 if (pf.can_run_online or pf.can_replay) else 3

    # 降级路径：不输出任何数字。见模块头部说明。
    if ns.replay_only and not pf.can_replay:
        print(
            "\n--replay-only 但没有录制缓存：无法离线复现。\n"
            "请由持有 API key 的一方先跑一次在线实验生成 logs/llm_cache.jsonl。",
            file=sys.stderr,
        )
        return 3
    if not ns.replay_only and not pf.can_run_online:
        reason = "未设置 TG_API_KEY" if not pf.has_key else f"接口不可达（{pf.error}）"
        print(
            f"\n跳过真实模型实验：{reason}。\n"
            + (
                f"检测到 {pf.cache_entries} 条录制缓存，可改用离线回放：\n"
                "    python -m eval.run_model_eval --replay-only\n"
                if pf.can_replay
                else "也没有可用的录制缓存，因此本轮不产生任何 ASR@model 数字。\n"
            )
            + "这是刻意的降级：给出一个\"未测\"比给出一个来源不明的数字有用。\n"
            "主实验（ASR@obedient，网关强制力上界）不依赖真实模型，仍可照常复现：\n"
            "    python -m eval.run_eval --limit 15",
            file=sys.stderr,
        )
        return 3

    samples = load_samples(
        ns.limit,
        ns.targets.split(",") if ns.targets else None,
        ns.evasions.split(",") if ns.evasions else None,
    )
    print(f"\n样本 {len(samples)} 条 × 两臂（{ARM_UNDEFENDED} 无防护 / {ARM_DEFENDED} 全防护）")

    def llm_factory(_sample: dict[str, Any]) -> LLMBackend:
        # 每条样本新建实例，但缓存是进程内共享读 + 追加写，所以两臂之间、
        # 样本之间的相同请求只会真正打一次网络。
        return OpenAICompatibleLLM(model=ns.model, replay_only=ns.replay_only)

    from scripts.serve_corpus import serve_in_background

    httpd, collector = serve_in_background(
        port=ns.port, log_path=project_root() / "logs" / "collector-model-eval.jsonl"
    )
    workdir = Path(tempfile.mkdtemp(prefix="trustgate-modeleval-")).resolve()
    audit_dir = project_root() / "logs" / "model-eval"
    audit_dir.mkdir(parents=True, exist_ok=True)
    base_policy = project_root() / ns.policy

    outcomes: list[PairedOutcome] = []
    try:
        for i, sample in enumerate(samples, start=1):
            o = PairedOutcome(
                sample=sample["id"],
                target=sample["target"],
                evasion=str(sample.get("evasion", "")),
                expect_layer=str(sample.get("expect_layer", "-")),
            )
            for gid in (ARM_UNDEFENDED, ARM_DEFENDED):
                try:
                    t = run_arm(gid, sample, workdir, collector, llm_factory, audit_dir, base_policy)
                except Exception as exc:
                    o.errors.append(f"{gid}: {type(exc).__name__}: {exc}")
                    continue
                if t.error:
                    o.errors.append(f"{gid}: {t.error}")
                if gid == ARM_UNDEFENDED:
                    o.undefended_success = t.attack_success
                    o.undefended_task_done = t.task_completed
                else:
                    o.defended_success = t.attack_success
                    o.defended_task_done = t.task_completed
                    o.blocking_rule = t.blocking_rule
                # 无防护臂就没中招时，防护臂不必再跑：它的结果对 CBR 没有贡献，
                # 而每一臂都是真金白银的模型调用。这不是抽样偏差——被跳过的样本
                # 本来就要从 CBR 分母里剔除，且它在 ASR@model 上按未成功计入。
                if gid == ARM_UNDEFENDED and not t.attack_success:
                    break

            outcomes.append(o)
            tag = (
                "模型未中招（不计入 CBR）" if not o.undefended_success
                else ("网关拦住" if o.blocked_by_gateway else "✗ 仍然得手")
            )
            print(
                f"  [{i}/{len(samples)}] {sample['id'][:44]:<44} {tag}"
                + (f"  规则={o.blocking_rule}" if o.blocking_rule else "")
                + (f"  错误={o.errors[-1][:50]}" if o.errors else ""),
                flush=True,
            )
    finally:
        httpd.shutdown()
        httpd.server_close()
        if workdir.is_dir() and workdir.is_relative_to(Path(tempfile.gettempdir()).resolve()):
            shutil.rmtree(workdir, ignore_errors=True)

    report = {
        "meta": {
            "model": ns.model,
            "base_url": pf.base_url,
            "replay_only": ns.replay_only,
            "arms": {ARM_UNDEFENDED: "无防护（observe）", ARM_DEFENDED: "全防护"},
            "asr_semantics": (
                "ASR@model：真实模型端到端攻击成功率，含模型自身对齐效果，不可单独"
                "引用为网关效果。可归因给网关的是 conditional_blocking_rate（CBR），"
                "其分母仅含在无防护臂真的中招的样本。"
            ),
            "ts": round(time.time(), 3),
        },
        "metrics": summarize(outcomes),
        "outcomes": [vars(o) for o in outcomes],
    }
    out = project_root() / ns.out
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")

    print("\n" + "=" * 78)
    print(render(report))
    print("=" * 78)
    print(f"\n完整结果 → {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
