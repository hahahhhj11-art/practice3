"""非绕过性演示：在权限剥离生效后，主动尝试绕过 Broker 直取资产。

这个脚本存在的意义是**提供对照**。只报告 S2 拦住了攻击没有说服力——必须同时
证明同样的绕过在 S0 下确实成功，否则无法排除「这条绕过路径本来就走不通」。

    python scripts/bypass_demo.py --level S0    # 预期：三项全部成功（绕过可行）
    python scripts/bypass_demo.py --level S2    # 预期：三项全部被内核拒绝

三项尝试对应威胁模型里 Agent 进程被完全控制后最直接的三条变现路径：
  A. 直接 open() 读沙箱敏感文件      —— 绕过 L1 路径黑名单与 L3 污点
  B. 直接 open("w") 写盘             —— 绕过 L4 时序与 L5 确认
  C. 直接开 INET socket 外连         —— 绕过全部外发长度与 DLP 判定
"""

from __future__ import annotations

import argparse
import json
import socket
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from trustgate.confine import apply_confinement, probe


def _attempt(fn) -> dict[str, object]:
    """执行一次绕过尝试。成功说明防线在这一点上不成立。"""
    try:
        detail = fn()
        return {"bypassed": True, "detail": str(detail)}
    except BaseException as exc:  # 内核拒绝会以 OSError/PermissionError 呈现
        return {"bypassed": False, "detail": f"{type(exc).__name__}: {exc}"}


def attempt_read_secret(target: Path) -> str:
    data = target.read_text(encoding="utf-8", errors="replace")
    return f"读到 {len(data)} 字节，首行 {data.splitlines()[0][:40]!r}"


def attempt_write(target: Path) -> str:
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text("bypass-marker\n", encoding="utf-8")
    return f"写入成功 {target}"


def attempt_socket() -> str:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        s.settimeout(0.3)
        # 不需要真连上：能建出 AF_INET socket 就已经说明外发通道没被切断
        return f"AF_INET socket 建立成功 fd={s.fileno()}"
    finally:
        s.close()


def main() -> int:
    ap = argparse.ArgumentParser(description="TrustGate 非绕过性演示")
    ap.add_argument("--level", default="S2", choices=["S0", "S1", "S2"])
    ap.add_argument("--json", action="store_true", help="只输出 JSON，便于测试断言")
    ns = ap.parse_args()

    secret = ROOT / "sandbox" / "private" / "id_rsa"
    scratch = ROOT / "sandbox" / "workspace" / "out" / ".bypass-probe"

    # 剥离必须发生在任何尝试之前，且此后不可撤销
    report = apply_confinement(ns.level)

    results = {
        "A_read_sandbox_secret": _attempt(lambda: attempt_read_secret(secret)),
        "B_write_filesystem": _attempt(lambda: attempt_write(scratch)),
        "C_open_inet_socket": _attempt(attempt_socket),
    }
    payload = {
        "level": ns.level,
        "probe": probe(),
        "confinement": report.to_wire(),
        "attempts": results,
        "bypass_count": sum(1 for r in results.values() if r["bypassed"]),
    }

    if ns.json:
        print(json.dumps(payload, ensure_ascii=False, indent=2))
        return 0

    print(report.describe())
    print()
    for name, r in results.items():
        icon = "绕过成功" if r["bypassed"] else "已被拦截"
        print(f"[{icon}] {name}\n           {r['detail']}")
    print(f"\n共 {payload['bypass_count']}/3 条绕过路径可用")

    # B 号绕过在 S0/S1 下是**真的**往沙箱里写了一个文件。必须提醒清理，因为
    # 残留文件会让后续的沙箱基线对不上，表现为下一轮实验里莫名多出一处"改动"。
    #
    # 刻意**不**在这里自动清理：tests/test_confinement.py 的
    # test_write_attempt_leaves_no_trace_on_disk 靠"父进程亲自检查这个文件在不在"
    # 来取证 Landlock 是否真的生效（Landlock 没有 /proc 内省，只能这样查）。
    # 脚本若自己删掉痕迹，那条测试在 Landlock 静默失效时也会通过——把唯一的
    # 证据擦掉，换来一点便利，不值得。清理交给调用方（reproduce.py 步骤 e 之后、
    # 测试的 tearDown）在父侧做。
    if results["B_write_filesystem"]["bypassed"]:
        print(
            f"\n提示：本次真的在沙箱里写下了 {scratch.relative_to(ROOT)}。\n"
            "      残留会让后续实验的基线比对多出一处'改动'，请执行：\n"
            "          python -m trustgate.sandbox reset"
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
