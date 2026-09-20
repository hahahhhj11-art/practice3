"""被剥权的 Agent 子进程宿主。

这个进程是**不可信域**。它没有任何工具实现，也（在 S2 档下）没有文件系统
与网络权限；它唯一的对外出口是一条到特权父进程的 JSON Lines 管道。

启动顺序是安全性的关键，顺序错了整层剥离就失效：

  1. 先把后续要用的全部模块导入完毕（剥离生效后再 import 会失败）；
  2. 施加权限剥离（Landlock + seccomp，不可撤销）；
  3. 向父进程报到，交出自报的剥离结果；
  4. 之后才开始 Agent 循环、才可能接触任何外部内容。

第 2 步在第 4 步之前，且剥离一旦生效不可撤销——因此 Agent 业务代码**没有
机会**在限制生效前插手。这与「让 Agent 自己调用剥离」有本质区别：不是
信任它会去剥，而是它醒来时权限已经没了。
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from dataclasses import asdict
from pathlib import Path
from typing import Any, TextIO

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

# ---- 第 1 步：在剥离之前把依赖全部导入 ----
from trustgate.agent import Agent                      # noqa: E402
from trustgate.broker import AttachedBrokerClient      # noqa: E402
from trustgate.confine import apply_confinement        # noqa: E402
from trustgate.llm import LLMBackend, MockLLM, Turn    # noqa: E402


def _preload_codecs() -> None:
    """预热编解码器。剥离后无法再从磁盘加载 encodings 子模块，
    而中文输出会触发 gbk/utf-8 的惰性加载，届时会以 LookupError 炸在半路。"""
    for enc in ("utf-8", "utf-16", "latin-1", "ascii"):
        "网关探针".encode(enc, errors="replace")
    json.dumps({"预热": "编解码"}, ensure_ascii=False).encode("utf-8")


class ProxyLLM(LLMBackend):
    """把模型推理交给特权父进程代办。

    S2 把子进程的网络整个切断了，而真实模型接口在网络另一端。与其为它开一个
    口子——Landlock 与 seccomp 都无法按主机名过滤，开一个口子等于开整张网——
    不如把模型端点声明为 TCB 内一条**目的地固定**的外发通道：父进程在这条
    通道上只做字节转发，不做任何策略判定，所以可信计算基没有因此承担新的
    语义职责；附带好处是每一次提示词都自然落进审计，为取证层留下了输入。
    """

    def __init__(self, channel: AttachedBrokerClient, name: str = "proxy"):
        self.name = name
        self._ch = channel

    def _ask(self, op: str, payload: dict[str, Any]) -> dict[str, Any]:
        resp = self._ch.request({"type": "llm_request", "op": op, **payload})
        if resp.get("type") == "error" or "error" in resp:
            raise RuntimeError(str(resp.get("error", "模型代办失败")))
        return dict(resp.get("output", {}))

    def plan(self, task: str, tools: list[str]) -> dict[str, Any]:
        return self._ask("plan", {"task": task, "tools": tools})

    def act(self, task: str, tools: list[str], plan: str, history: list[Turn]) -> dict[str, Any]:
        return self._ask(
            "act",
            {
                "task": task,
                "tools": tools,
                "plan": plan,
                "history": [{"role": t.role, "content": t.content} for t in history],
            },
        )


def _split_streams() -> tuple[TextIO, TextIO]:
    """把 fd 1 专供 RPC，其余一切输出改道 stderr。

    Agent 循环会 print 执行轨迹。如果它和协议共用 stdout，一行日志就能把
    JSON Lines 流冲垮——而且这正是不可信侧最容易被诱导去做的事（注入内容
    让它打印一段伪造的 tool_result）。物理隔开比约定「不要乱 print」可靠。
    """
    rpc = os.fdopen(os.dup(1), "w", encoding="utf-8", newline="\n", buffering=1)
    os.dup2(2, 1)
    sys.stdout = sys.stderr
    return sys.stdin, rpc


def main() -> int:
    ap = argparse.ArgumentParser(description="TrustGate 被剥权 Agent 宿主（由 Supervisor 拉起）")
    ap.add_argument("--task", required=True)
    ap.add_argument("--session", default="")
    ap.add_argument("--confine", default="S2", choices=["S0", "S1", "S2"])
    ap.add_argument("--llm", default="mock", choices=["mock", "proxy"])
    ap.add_argument("--llm-name", default="proxy")
    ap.add_argument("--mock-spec", default="", help="MockLLM 构造参数的 JSON，供评测注入攻击脚本")
    ap.add_argument("--max-steps", type=int, default=8)
    ap.add_argument("--quiet", action="store_true")
    ns = ap.parse_args()

    _preload_codecs()
    rpc_in, rpc_out = _split_streams()

    # ---- 第 2 步：剥权。此后本进程不再拥有沙箱读写与外连能力 ----
    report = apply_confinement(ns.confine)

    channel = AttachedBrokerClient(rpc_in, rpc_out)

    # ---- 第 3 步：报到，把自报结果交给父进程（父进程会独立核验） ----
    channel.request({"type": "child_hello", "pid": os.getpid(), "confinement": report.to_wire()})

    llm: LLMBackend
    if ns.llm == "mock":
        spec = json.loads(ns.mock_spec) if ns.mock_spec else {}
        llm = MockLLM(**spec)
    else:
        llm = ProxyLLM(channel, ns.llm_name)

    # ---- 第 4 步：Agent 循环。到这里权限已经拿不回来了 ----
    try:
        run = Agent(llm=llm, broker=channel, max_steps=ns.max_steps, verbose=not ns.quiet).run(
            ns.task, ns.session or None
        )
        channel.request({"type": "run_result", "result": asdict(run)})
        return 0
    except Exception as exc:
        channel.request({"type": "run_failed", "error": f"{type(exc).__name__}: {exc}"})
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
