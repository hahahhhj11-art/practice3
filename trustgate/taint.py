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


def _candidate_sets(value: str) -> tuple[list[str], list[str]]:
    """为一个参数值生成溯源候选集，并区分**精确**与**宽松**两档。

    返回 (exact, loose)。这个区分是安全性的关键，不是代码整洁问题：

    · exact —— 完整归一化后的值。只有它命中可信文本才足以判 TRUSTED，
      因为只有它能回答"用户要的就是**这一个**对象"。
    · loose —— 文件路径的 basename 与不含扩展名的主干。保留它是因为 Agent
      常常只从文本里拿到一个文件名再自行拼出完整路径，一刀切成 UNTRUSTED
      会误杀大量正常任务。但它**最多只能得到 UNKNOWN**。

    为什么 loose 不能给 TRUSTED：basename 匹配是一条可利用的洗白通道。
    用户任务里出现 `…/out/summary.md`，攻击者便指向同名但**不同目录**的
    `…/project/summary.md`——完整路径只存在于注入内容里，却因为同名被判
    TRUSTED，于是 L3 的 untrusted_irreversible 完全不触发，破坏性覆盖畅通。
    现实中 readme.md / notes.md / config.json 这类文件名遍地都是，攻击者
    几乎总能找到一个同名受害者。这与此前修掉的 URL 主机名洗白是同一类
    错误：把「同类」当成了「同一个」。
    降级为 UNKNOWN 之后，宽松匹配仍不被硬拒，但必须另外命中能力清单才能
    通过——这正是三值格里 UNKNOWN 一档当初被设计出来的用途。

    URL 刻意不产生任何 loose 候选。早先把裸主机名放进候选集，等于宣称
    "任务里出现过 127.0.0.1" ⇒ "该主机下任意 URL 都可信"，攻击者的外泄地址
    因此白拿三重豁免（L5 清单信用、L4 授权覆盖例外、外发长度只计查询串的
    快捷路径），五层防御对路径编码外泄整体失效（样本 exfil/path_lowbw）。
    主机名是**权限**问题，归 L1 的域名允许列表管；溯源回答的是**这个具体
    地址是不是用户要求访问的**，粒度必须是整条 URL。
    """
    v = _norm(value).strip()
    if len(v) < _MIN_TOKEN:
        return [], []
    if "://" in v:
        return [v], []
    loose: set[str] = set()
    base = posixpath.basename(v.rstrip("/"))
    if len(base) >= _MIN_TOKEN and base != v:
        loose.add(base)
        stem = base.rsplit(".", 1)[0]
        if len(stem) >= _MIN_TOKEN:
            loose.add(stem)
    return [v], sorted(loose, key=len, reverse=True)


def _candidates(value: str) -> list[str]:
    """全部候选（精确 + 宽松）。仅用于「是否被不可信内容提及」这类悲观判定。"""
    exact, loose = _candidate_sets(value)
    return exact + loose


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
        """三值溯源判定。unknown 的处置交由策略层决定（要求命中 Manifest）。

        判定次序有讲究：
        1. **精确**命中可信文本 → TRUSTED。哪怕攻击者也提到了同一个路径也不
           降级，否则对手只要在网页里复述一遍用户的目标文件，就能让正常任务
           失败——那是一条免费的拒绝服务。
        2. 任一候选（含 basename）命中不可信文本 → UNTRUSTED。这一步取悲观：
           攻击者提过的名字，宁可当脏的。
        3. 仅**宽松**命中可信文本 → UNKNOWN。同名不等于同一个对象，详见
           `_candidate_sets` 对洗白通道的说明。
        """
        if not isinstance(value, str):
            return Trust.TRUSTED
        exact, loose = _candidate_sets(value)
        if not exact:
            return Trust.TRUSTED
        if any(c in self._trusted_blob for c in exact):
            return Trust.TRUSTED
        if any(c in self._untrusted_blob for c in exact + loose):
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
