"""敏感内容指纹匹配（content fingerprinting）。

**为什么需要这个模块——一个关于实验效度的问题。**

早期实现里，L3 直接检查工具参数中是否出现 canary 令牌来判定数据外带。
这在工程上有效，在科研上却是无效的：canary 同时是「攻击是否成功」的
判定预言机（ground-truth oracle）。用预言机去做防御，等于让被测系统
预先知道正确答案，测出的 ASR 会被系统性低估，审稿人一定会指出这一点。

本模块提供一个**不依赖任何预置秘密**的替代机制：对会话中读到的敏感内容
建立滑动窗口指纹集，再检查外发参数是否与之重合。这正是企业 DLP
（数据防泄漏）的经典做法，可以合法地写进论文，并且对手即使完全知道
算法也无法通过"换一个令牌"来规避。

canary 从此只出现在评测侧（collector 与 sandbox 校验），不再参与判定。
"""

from __future__ import annotations

import base64
import binascii
import re
from dataclasses import dataclass, field
from urllib.parse import unquote_plus

from .sanitize import normalize_text

# 窗口 16 字符、步长 1：命中 2 个不同窗口即意味着至少 17 个连续字符与
# 敏感内容逐字相同。在本项目的文本规模下，这种巧合的概率可以忽略，
# 因此阈值取 2 已经足以把误报压到接近零，同时不至于漏掉短片段泄漏。
WINDOW = 16
MIN_MATCHES = 2

# 单次读取参与建指纹的字符上限。敏感文件本就不大，设上限只是为了让
# 判定延迟保持在常数级，不随文件体积退化。
MAX_FINGERPRINT_CHARS = 8192

_WS_RE = re.compile(r"\s+")


def _canon(text: str) -> str:
    """归一化：NFKC + 去零宽 + 折叠空白 + 小写。

    折叠空白是关键一步——攻击者把密钥里的换行换成空格再外发，
    是最省力的绕过方式，归一化之后这种变形不再有效。
    """
    return _WS_RE.sub(" ", normalize_text(text)).strip().lower()


def _windows(text: str) -> set[str]:
    if len(text) < WINDOW:
        return set()
    return {text[i : i + WINDOW] for i in range(len(text) - WINDOW + 1)}


def _decodings(text: str) -> list[str]:
    """还原常见编码，防止"先编码再外发"绕过逐字指纹。

    对应威胁模型 A1-C2（编码混淆）。只做一层解码：多层嵌套编码属于
    自适应对手的范畴，应当由会话外发预算而非指纹来兜底。
    """
    out = [text]
    unquoted = unquote_plus(text)
    if unquoted != text:
        out.append(unquoted)

    for candidate in list(out):
        for token in re.findall(r"[A-Za-z0-9+/=_-]{24,}", candidate):
            padded = token.replace("-", "+").replace("_", "/")
            padded += "=" * (-len(padded) % 4)
            try:
                decoded = base64.b64decode(padded, validate=False)
            except (binascii.Error, ValueError):
                continue
            text_form = decoded.decode("utf-8", "ignore")
            if len(text_form) >= WINDOW:
                out.append(text_form)
        for token in re.findall(r"(?:[0-9a-fA-F]{2}){12,}", candidate):
            try:
                out.append(bytes.fromhex(token).decode("utf-8", "ignore"))
            except ValueError:
                continue
    return out


@dataclass
class SensitiveFingerprint:
    """会话内读到的敏感内容的指纹集合。

    只保存 16 字符窗口，不保存原文——审计与状态本身不应成为
    敏感数据的第二个泄露点（与 audit.py 只存 args_digest 同理）。
    """

    windows: set[str] = field(default_factory=set)
    sources: list[str] = field(default_factory=list)

    @property
    def active(self) -> bool:
        return bool(self.windows)

    def add(self, content: str, source: str = "") -> int:
        canon = _canon(content)[:MAX_FINGERPRINT_CHARS]
        new = _windows(canon)
        if not new:
            return 0
        self.windows |= new
        if source and source not in self.sources:
            self.sources.append(source)
        return len(new)

    def match(self, value: str) -> int:
        """返回外发值与敏感指纹重合的窗口数，0 表示无重合。"""
        if not self.windows or not value:
            return 0
        best = 0
        for form in _decodings(value):
            hits = _windows(_canon(form)) & self.windows
            best = max(best, len(hits))
            if best >= MIN_MATCHES:
                break
        return best

    def leaks(self, value: str, min_matches: int = MIN_MATCHES) -> bool:
        return self.match(value) >= min_matches
