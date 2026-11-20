"""网页读取工具执行体。

返回内容一律标记为 untrusted —— 这是全系统唯一的注入入口，
也是污点传播的起点（威胁模型 §4.1）。
"""

from __future__ import annotations

import urllib.error
import urllib.parse
import urllib.request

from .sanitize import html_to_text
from .types import ToolResult, Trust

_UA = "TrustGate-Research/0.1 (course project; sandboxed)"


class _RefuseRedirect(urllib.request.HTTPRedirectHandler):
    """3xx 不跟随。域名允许列表只核验了调用方提交的那条 URL。"""

    def http_error_302(self, req, fp, code, msg, headers):
        loc = headers.get("Location") or headers.get("URI") or ""
        if loc:
            loc = urllib.parse.urljoin(req.full_url, loc)
        reason = (
            f"拒绝跟随重定向 Location: {loc}" if loc else "拒绝跟随重定向（响应没有 Location）"
        )
        try:
            fp.close()
        except Exception:
            pass
        raise urllib.error.HTTPError(req.full_url, code, reason, headers, None)

    http_error_301 = http_error_303 = http_error_307 = http_error_308 = http_error_302


def web_read(url: str, max_bytes: int = 262144, timeout: float = 8.0, keep_hidden: bool = True) -> ToolResult:
    req = urllib.request.Request(url, headers={"User-Agent": _UA})
    opener = urllib.request.build_opener(_RefuseRedirect())
    try:
        with opener.open(req, timeout=timeout) as resp:
            raw = resp.read(max_bytes + 1)
            charset = resp.headers.get_content_charset() or "utf-8"
    except urllib.error.HTTPError as exc:
        # fp 为 None 时 HTTPError 自己包了一个 BytesIO，不关会在进程退出时报警。
        exc.close()
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
