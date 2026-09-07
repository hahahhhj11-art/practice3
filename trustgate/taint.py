"""污点跟踪与参数溯源（策略层 L3）。

回答的问题是：一次工具调用的参数，究竟来自用户的可信任务，还是来自
攻击者可控的网页内容？判定完全基于字符串溯源，不调用任何 LLM，
因此不存在"检测器同样被注入"的问题（见 docs/00-方案评审与优化.md 硬伤 2）。

Agent 与 Broker 各自持有一个实例：Agent 侧的结论仅作提示，
Broker/PDP 侧独立重算并取更保守的一方。
"""

from __future__ import annotations

import posixpath
import re
from dataclasses import dataclass, field
from urllib.parse import urlparse

from .dlp import SensitiveFingerprint
from .sanitize import normalize_text
from .types import Trust, join

_MIN_TOKEN = 3


def _norm(s: str) -> str:
    return normalize_text(str(s)).replace("\\", "/").lower()


def _candidates(value: str) -> list[str]:
    """为一个参数值生成用于溯源的字符串候选集。

    对**文件路径**，除完整值外还包括 basename 与不含扩展名的主干——因为
    Agent 常常只从文本里拿到文件名，再自行拼接出完整路径，这种宽松匹配
    是必要的。

    对 **URL** 则刻意只用完整值。早先这里额外把裸主机名放进候选集，那是
    一个可利用的洗白通道：`origin()` 只要有任一候选命中可信文本就判 TRUSTED，
    于是"用户任务里出现过 127.0.0.1" ⇒ "该主机下**任意** URL 都可信"。
    攻击者的外泄地址因此白拿三重豁免——L5 的清单信用、L4 的授权覆盖例外、
    以及外发载荷长度只计查询串的快捷路径——五层防御对路径编码外泄整体失效
    （样本 exfil/path_lowbw）。同理也不取 URL 的 basename：允许列表内的
    `…/collect/summary.md` 会因为任务里提过 summary.md 而被洗白。

    换言之：主机名是**权限**问题，由 L1 的域名允许列表负责；溯源回答的是
    **这个具体地址是不是用户要求访问的**，粒度必须是整条 URL。
    """
    v = _norm(value).strip()
    if len(v) < _MIN_TOKEN:
        return []
    if "://" in v:
        return [v]
    out = {v}
    base = posixpath.basename(v.rstrip("/"))
    if len(base) >= _MIN_TOKEN:
        out.add(base)
        stem = base.rsplit(".", 1)[0]
        if len(stem) >= _MIN_TOKEN:
            out.add(stem)
    return sorted(out, key=len, reverse=True)


@dataclass
class TaintTracker:
    task: str = ""
    trusted_texts: list[str] = field(default_factory=list)
    untrusted_texts: list[str] = field(default_factory=list)
    untrusted_sources: list[str] = field(default_factory=list)
    _trusted_blob: str = field(default="", repr=False)
    _untrusted_blob: str = field(default="", repr=False)
    # 不可信文本的窗口指纹，用于回答"这段新文本是不是从外部内容派生出来的"。
    _untrusted_fp: SensitiveFingerprint = field(default_factory=SensitiveFingerprint, repr=False)

    def __post_init__(self) -> None:
        if self.task:
            self.add_trusted(self.task)

    @property
    def session_tainted(self) -> bool:
        """一旦有外部内容进入上下文，会话即被标记为已污染。"""
        return bool(self.untrusted_texts)

    def add_trusted(self, text: str) -> None:
        self.trusted_texts.append(text)
        self._trusted_blob += "\n" + _norm(text)

    def add_untrusted(self, text: str, source: str = "") -> None:
        self.untrusted_texts.append(text)
        if source:
            self.untrusted_sources.append(source)
        self._untrusted_blob += "\n" + _norm(text)
        self._untrusted_fp.add(text, source)

    def observe_agent_output(self, text: str) -> None:
        """Agent 自产文本的信任等级取决于会话是否已被污染。

        污染后一律降级为不可信，用于缓解"上下文洗白"绕过
        （威胁模型 §5 已知边界 L3）：攻击者诱导 Agent 先把敏感内容
        复述进自己的推理，再声称那是"自己想到的"。
        """
        if self.session_tainted:
            self.add_untrusted(text, source="agent:post-taint")
        else:
            self.add_trusted(text)

    def origin(self, value: object) -> Trust:
        """三值溯源判定。unknown 的处置交由策略层决定（要求命中 Manifest）。"""
        if not isinstance(value, str):
            return Trust.TRUSTED
        cands = _candidates(value)
        if not cands:
            return Trust.TRUSTED
        if any(c in self._trusted_blob for c in cands):
            return Trust.TRUSTED
        if any(c in self._untrusted_blob for c in cands):
            return Trust.UNTRUSTED
        return Trust.UNKNOWN

    def origins(self, args: dict[str, object]) -> dict[str, Trust]:
        return {k: self.origin(v) for k, v in args.items()}

    def call_trust(self, args: dict[str, object]) -> Trust:
        """整个调用的信任等级 = 各参数溯源结果的格上界。"""
        labels = list(self.origins(args).values())
        return join(*labels) if labels else Trust.TRUSTED

    def derived_from_untrusted(self, text: str, min_matches: int = 2) -> bool:
        """这段文本是不是从外部内容派生来的？

        判据是窗口重合，不是整段子串匹配。区别很要紧：早先用的是
        `_norm(text) in _untrusted_blob`，要求**整段**文本逐字出现在不可信
        文本里。攻击者只要在注入内容前面多加一句话，整段就不再是子串，
        判定立刻失效——L4 的记忆投毒规则因此几乎从未真正触发过。
        改成窗口重合之后，"网页原文 + 少量改写"这种最常见的形态也能识别。
        """
        return self._untrusted_fp.leaks(text, min_matches)

    # 旧名保留：语义已换成窗口重合判定，调用点无需改动。
    contains_untrusted = derived_from_untrusted


CANARY_RE = re.compile(r"TG-CANARY-[0-9a-f]{8,}", re.IGNORECASE)


def find_canaries(text: str) -> list[str]:
    """检出 honeytoken。任何位置出现即为敏感数据流动的确凿证据。

    **仅供评测侧使用。** canary 是判定攻击是否成功的 ground-truth 预言机，
    任何防御路径都不得引用它，否则等于让被测系统预先知道答案
    （详见 trustgate/dlp.py 模块注释）。
    """
    return sorted({m.group(0).upper() for m in CANARY_RE.finditer(text or "")})
