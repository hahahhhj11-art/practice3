"""异步取证层：注入定位、来源归因、数据恢复。

**不在关键路径上。** 拦截由 policy.py 的五层判定完成；本模块回答的是拦下来
之后（或 observe 模式下事后复盘时）的三个运维问题：

  1. 定位：注入到底藏在哪一段外部内容里？
  2. 归因：是哪一个来源驱动了这次违规动作？
  3. 恢复：能不能把毒段摘掉，把剩下的数据还给任务，而不是整页丢弃？

与文献的关系（必须先说清，以免被误读为复现）
------------------------------------------
PromptLocate（IEEE S&P'26）的三阶段流水线里含一个 LLM 检测器；AttnTrace
（IEEE S&P'26）用模型的注意力权重做上下文归因。**本模块两者都没有复刻，
也不引用它们的任何数字。** 不是不想，是有两条硬约束：

  · 接 OpenAI 兼容 API 时拿不到注意力权重，AttnTrace 的机制在这个部署形态下
    根本不可用（本地白盒模型才行，那是另一个威胁模型）；
  · 项目刻意不做基于关键词或 LLM 的语义判别——这与 policy.py 删掉
    `_looks_like_instruction()` 是同一条理由：换个措辞即失效，而正常文本里
    出现"请""必须"又会误伤，两头不讨好。

所以这里换了一条在本项目约束内站得住的路：**数据流最小化**。

    注入段 ≔ 违规调用的参数能从之派生的最小外部内容片段。

判据是窗口重合（复用 dlp 的归一化与窗口机制），不看任何关键词，因此改写措辞
无从规避；而且完全确定、零模型调用、可离线复算——审计方拿着日志就能自己算
一遍，不需要信任我们的模型。

能力边界（写在这里而不是藏起来）
------------------------------
数据流定位只能找到**在数据流上留下痕迹**的注入：注入内容里出现过那个路径、
那个 URL、那段被外发的凭据。纯说服型的注入定位不到——"忽略之前的指令，你现在
是运维模式"这句话本身不出现在任何工具参数里，它只改变模型的意图。这类注入的
处置仍然依赖 L2/L4/L5 的结构性约束，而不是取证。

需要因果归因时，用 `leave_one_out()` 接口：把候选段摘掉后重放 Agent 决策，看
违规动作是否消失。黑盒下这是唯一站得住的因果归因，代价是 k 次模型调用，因此
不默认开启。
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Callable, Iterable, Sequence

# 刻意复用 dlp 的归一化与解码，而不是另写一套。
#
# 这不是图省事：取证要回答的是「L3 当时看到了什么」。如果取证用另一套归一化
# （比如不折叠空白、不还原 Base64），它算出的结论就与判定层看到的世界不对应，
# 定位结果无法用来解释拦截原因，也无法用来复算。两者必须共用同一把尺子。
from .dlp import _canon, _decodings

# 取证窗口比 DLP 的 16 小。DLP 要的是「几乎不可能巧合」，所以窗口取大；
# 取证要的是「把注入段从正常正文里挑出来」，而工具参数常常很短（一个文件名
# 八九个字符），窗口取 16 就什么都匹配不到了。窗口变小带来的误配风险，由
# 「分数排序 + 阈值」以及取证本身不参与任何拦截决策来兜底。
FORENSIC_WINDOW = 8
MIN_SPAN_CHARS = 4

# 中文标点与换行是明确的句末，可直接切；半角 . ! ? ; 只有**后面跟空白或结尾**时
# 才算句末。这个条件不是讲究，是必需的：不加限制的话
# `sandbox/workspace/out/summary.md` 会在点号处被切成两半，而文件路径与 URL 恰恰
# 是定位所依赖的数据流痕迹——在痕迹中间切开，会让注入段被拆得既定位不准、也
# 无法整段摘除（恢复时只删掉半句，剩下的半句仍留在正文里）。
_SENT_SPLIT = re.compile(r"(?<=[。．！？；\n])|(?<=[.!?;])(?=\s|$)")


# ---------------------------------------------------------------- 数据结构


@dataclass(frozen=True)
class IngestedDoc:
    """一段进入过 Agent 上下文的外部内容。"""

    doc_id: str
    source: str
    content: str


@dataclass(frozen=True)
class Span:
    doc_id: str
    source: str
    start: int
    end: int
    text: str

    @property
    def length(self) -> int:
        return self.end - self.start


@dataclass
class ScoredSpan:
    span: Span
    score: int = 0
    # 哪些违规参数是从这一段派生出来的。定位结论要能解释，不能只给一个分数。
    matched: list[str] = field(default_factory=list)


@dataclass
class Localization:
    spans: list[ScoredSpan] = field(default_factory=list)
    suspect_values: list[str] = field(default_factory=list)
    window: int = FORENSIC_WINDOW

    @property
    def hits(self) -> list[ScoredSpan]:
        return [s for s in self.spans if s.score > 0]

    @property
    def located(self) -> bool:
        return bool(self.hits)

    def top(self, n: int = 3) -> list[ScoredSpan]:
        return sorted(self.spans, key=lambda s: (-s.score, s.span.start))[:n]

    def char_set(self, doc_id: str | None = None) -> set[int]:
        """被判定为注入的字符位置集合，用于与 ground truth 算 PRF。"""
        out: set[int] = set()
        for s in self.hits:
            if doc_id is not None and s.span.doc_id != doc_id:
                continue
            out.update(range(s.span.start, s.span.end))
        return out

    def by_source(self) -> list[tuple[str, int]]:
        """来源归因：把片段分数按来源聚合。分数最高的来源即最可能的注入入口。"""
        agg: dict[str, int] = {}
        for s in self.hits:
            agg[s.span.source] = agg.get(s.span.source, 0) + s.score
        return sorted(agg.items(), key=lambda kv: -kv[1])


# ---------------------------------------------------------------- 分段


def segment(doc: IngestedDoc, granularity: str = "sentence") -> list[Span]:
    """把一段外部内容切成候选片段。

    默认按句子切而不是按行：载体是 HTML 时，注入常常与正常正文挤在同一行
    （`<p>正常介绍</p><!-- 注入 -->` 抽取成纯文本后可能只有一行），按行切会把
    毒段和正文绑成一个不可分割的整体，定位粒度退化到"整篇可疑"，恢复功能也就
    没有意义了（摘掉毒段等于摘掉全文）。
    """
    text = doc.content
    if granularity == "line":
        pieces = _offsets(text, text.splitlines(keepends=True))
    else:
        pieces = _offsets(text, _SENT_SPLIT.split(text))
    out: list[Span] = []
    for start, piece in pieces:
        stripped = piece.strip()
        if len(stripped) < MIN_SPAN_CHARS:
            continue
        lead = len(piece) - len(piece.lstrip())
        out.append(
            Span(doc.doc_id, doc.source, start + lead, start + lead + len(stripped), stripped)
        )
    return out


def _offsets(text: str, pieces: Iterable[str]) -> list[tuple[int, str]]:
    """给切分结果补回在原文里的起始偏移。恢复功能要按偏移回删，不能按内容查找
    ——同一句话可能出现多次，按内容查找会删错位置。"""
    out: list[tuple[int, str]] = []
    cursor = 0
    for piece in pieces:
        if not piece:
            continue
        out.append((cursor, piece))
        cursor += len(piece)
    return out


# ---------------------------------------------------------------- 定位与归因


def _windows(text: str, window: int) -> set[str]:
    if len(text) < window:
        return {text} if text else set()
    return {text[i: i + window] for i in range(len(text) - window + 1)}


def derivability(span_text: str, value: str, window: int = FORENSIC_WINDOW) -> int:
    """value 有多少个窗口能在 span_text 里逐字找到。

    方向是刻意的：以**片段**建窗口集，再拿**违规参数**去比。反过来（以参数建
    窗口集去比片段）会让长片段天然占优，正常正文里偶然出现的短重合也会被算进
    分数，排序随之失真。
    """
    span_windows = _windows(_canon(span_text), window)
    if not span_windows:
        return 0
    best = 0
    for form in _decodings(value):
        best = max(best, len(_windows(_canon(form), window) & span_windows))
    return best


def localize(
    docs: Sequence[IngestedDoc],
    suspect_values: Sequence[str],
    granularity: str = "sentence",
    window: int = FORENSIC_WINDOW,
    min_score: int = 1,
) -> Localization:
    """定位注入段。

    suspect_values 是**违规调用的参数值**——被拦下的那次 fs.write 的路径、那条
    外发 URL、那段要写入的内容。它们是攻击在数据流上留下的痕迹，定位就是把这些
    痕迹反查回外部内容。
    """
    values = [v for v in suspect_values if isinstance(v, str) and len(v.strip()) >= MIN_SPAN_CHARS]
    loc = Localization(suspect_values=list(values), window=window)
    for doc in docs:
        for span in segment(doc, granularity):
            scored = ScoredSpan(span=span)
            for v in values:
                n = derivability(span.text, v, window)
                if n >= min_score:
                    scored.score += n
                    scored.matched.append(v)
            loc.spans.append(scored)
    return loc


def sanitize(doc: IngestedDoc, loc: Localization, keep_marker: bool = True) -> str:
    """把定位到的注入段从文档里摘掉，剩下的正文交还任务。

    这是"恢复"而非"拦截"：整页丢弃会让任务直接失败，而攻击往往只污染了几句话。
    默认留一个占位标记，不静默删除——下游（包括人）必须能看出这里被动过，否则
    取证层自己就成了一个不可见的内容改写通道。
    """
    cuts = sorted(
        ((s.span.start, s.span.end) for s in loc.hits if s.span.doc_id == doc.doc_id),
        reverse=True,
    )
    out = doc.content
    for start, end in cuts:
        marker = f"[已移除疑似注入内容 {end - start} 字符]" if keep_marker else ""
        out = out[:start] + marker + out[end:]
    return out


def leave_one_out(
    docs: Sequence[IngestedDoc],
    loc: Localization,
    replay: Callable[[Sequence[IngestedDoc]], bool],
    top_n: int = 3,
) -> list[tuple[Span, bool]]:
    """因果归因：逐个摘掉候选段并重放决策，看违规动作是否消失。

    replay(docs) 应返回"违规动作是否仍然发生"。返回 [(片段, 摘掉后是否仍违规)]，
    因此 False 表示这一段是**必要原因**。

    默认不调用：每个候选段一次模型调用，k 段就是 k 次，成本与延迟都不适合放进
    在线路径。它存在的意义是在需要给出因果结论时（例如事故复盘要认定责任来源）
    有一条比相关性更强的证据，而不是让相关性冒充因果。
    """
    out: list[tuple[Span, bool]] = []
    for scored in loc.top(top_n):
        reduced = [
            IngestedDoc(d.doc_id, d.source, sanitize(d, _only(loc, scored), keep_marker=False))
            if d.doc_id == scored.span.doc_id else d
            for d in docs
        ]
        out.append((scored.span, bool(replay(reduced))))
    return out


def _only(loc: Localization, keep: ScoredSpan) -> Localization:
    sub = Localization(suspect_values=loc.suspect_values, window=loc.window)
    sub.spans = [keep]
    return sub


# ---------------------------------------------------------------- 评测


def span_prf(found: set[int], truth: set[int]) -> tuple[float, float, float]:
    """定位精度/召回/F1，按**字符位置**算而不是按片段算。

    按片段算会被切分粒度左右：把整篇当成一个片段也能拿到 100% 召回。按字符算
    才能同时反映"找到了"与"找得准不准"，也才能和 PromptLocate 那类以文本重合度
    （ROUGE-L / 句向量相似度）报告的结果放在同一个量纲上讨论——注意只是量纲
    可比，方法不同，数字不可直接对照。
    """
    if not truth:
        return (0.0, 0.0, 0.0)
    tp = len(found & truth)
    p = tp / len(found) if found else 0.0
    r = tp / len(truth)
    f1 = 2 * p * r / (p + r) if (p + r) else 0.0
    return (round(p, 4), round(r, 4), round(f1, 4))


def truth_span(content: str, payload: str) -> set[int]:
    """ground truth：注入载荷在文档里占据的字符位置。

    载体（HTML 注释、img alt、隐藏 div…）会对载荷做转义，所以不能指望原文逐字
    出现。先试逐字定位，失败再退化为按归一化后的最长公共片段近似。定位不到就
    返回空集，由调用方跳过该样本而不是计入 0 分——把"ground truth 抽取失败"
    记成"定位失败"会低估取证效果，那是另一种自欺。
    """
    idx = content.find(payload)
    if idx >= 0:
        return set(range(idx, idx + len(payload)))
    head = payload.strip()[:40]
    if head:
        idx = content.find(head)
        if idx >= 0:
            return set(range(idx, min(idx + len(payload), len(content))))
    return set()


def summarize(loc: Localization, docs: Sequence[IngestedDoc]) -> dict[str, Any]:
    """给报告用的紧凑结论。"""
    top = loc.top(3)
    return {
        "located": loc.located,
        "suspect_values": loc.suspect_values,
        "span_count": len(loc.spans),
        "hit_count": len(loc.hits),
        "attribution": loc.by_source(),
        "top_spans": [
            {
                "source": s.span.source,
                "start": s.span.start,
                "end": s.span.end,
                "score": s.score,
                "text": s.span.text[:160],
                "matched": s.matched[:3],
            }
            for s in top
        ],
        "docs": [{"doc_id": d.doc_id, "source": d.source, "chars": len(d.content)} for d in docs],
    }
