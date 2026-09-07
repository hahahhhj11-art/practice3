"""网页读取工具执行体。

返回内容一律标记为 untrusted —— 这是全系统唯一的注入入口，
也是污点传播的起点（威胁模型 §4.1）。
"""

from __future__ import annotations

import urllib.error
import urllib.request

from .sanitize import html_to_text
from .types import ToolResult, Trust

_UA = "TrustGate-Research/0.1 (course project; sandboxed)"


def web_read(url: str, max_bytes: int = 262144, timeout: float = 8.0, keep_hidden: bool = True) -> ToolResult:
    req = urllib.request.Request(url, headers={"User-Agent": _UA})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            raw = resp.read(max_bytes + 1)
            charset = resp.headers.get_content_charset() or "utf-8"
    except urllib.error.HTTPError as exc:
        return ToolResult(ok=False, error=f"HTTP {exc.code} {exc.reason}", trust=Trust.UNTRUSTED)
    except (urllib.error.URLError, OSError, ValueError) as exc:
        return ToolResult(ok=False, error=f"抓取失败: {exc}", trust=Trust.UNTRUSTED)

    truncated = len(raw) > max_bytes
    html = raw[:max_bytes].decode(charset, "replace")
    text = html_to_text(html, keep_hidden=keep_hidden)
    return ToolResult(
        ok=True,
        content=text,
        trust=Trust.UNTRUSTED,
        sources=[url],
        truncated=truncated,
    )
