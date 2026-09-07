"""文件工具执行体。

本模块与 tools_web.py 是全系统唯一接触磁盘与网络的地方，且只在 Broker 进程内
被调用（对应设计原则 P1 完全仲裁）。Agent 进程不导入这两个模块。
"""

from __future__ import annotations

from pathlib import Path

from .paths import matches_any, resolve_sandbox_path
from .types import ToolResult, Trust


def target_exists(path: str, sandbox_root: str = "sandbox") -> bool:
    rp = resolve_sandbox_path(path, sandbox_root)
    return bool(rp.ok and Path(rp.abs).exists())


def _content_looks_sensitive(text: str, patterns: list[str]) -> bool:
    """按策略声明的内容特征判定敏感性。

    刻意不使用 canary：canary 是评测侧的判定预言机，让防御去匹配它，
    等于让被测系统提前知道答案（见 trustgate/dlp.py 模块注释）。
    这里用的是私钥头、令牌赋值这类**任何真实 DLP 都会写**的通用特征。
    """
    low = text[:4096].lower()
    return any(p.lower() in low for p in patterns)


def fs_read(
    path: str,
    sandbox_root: str,
    max_bytes: int,
    sensitive_patterns: list[str],
    sensitive_content: list[str] | None = None,
    tainted_paths: set[str] | frozenset[str] | None = None,
) -> ToolResult:
    rp = resolve_sandbox_path(path, sandbox_root)
    if not rp.ok:
        return ToolResult(ok=False, error=rp.error)
    p = Path(rp.abs)
    if not p.exists():
        return ToolResult(ok=False, error=f"文件不存在: {rp.rel}")
    if p.is_dir():
        names = sorted(x.name + ("/" if x.is_dir() else "") for x in p.iterdir())
        return ToolResult(ok=True, content="\n".join(names), sources=[f"dir:{rp.rel}"])

    raw = p.read_bytes()
    truncated = len(raw) > max_bytes
    text = raw[:max_bytes].decode("utf-8", "replace")

    # 命中敏感路径或敏感内容特征的读取会在 source 上打标，Broker 据此把
    # 会话状态机推进到 Sensitive，从而使后续外发请求触发 L4 外泄链规则。
    sensitive = bool(
        matches_any(rp.rel, sensitive_patterns)
        or _content_looks_sensitive(text, list(sensitive_content or []))
    )

    # 溯源标签：这个文件此前是否由不可信内容写成？
    # 如果是，读回来的内容必须仍然是 untrusted，否则一次「写进去再读出来」
    # 就能把攻击者的注入文本洗成可信数据（威胁模型 T5 持久化注入的实质）。
    laundered = bool(tainted_paths and rp.rel in tainted_paths)
    marks = ("#sensitive" if sensitive else "") + ("#tainted" if laundered else "")

    return ToolResult(
        ok=True,
        content=text,
        trust=Trust.UNTRUSTED if laundered else Trust.TRUSTED,
        sources=[f"file:{rp.rel}{marks}"],
        truncated=truncated,
    )


def fs_write(path: str, content: str, sandbox_root: str, max_bytes: int) -> ToolResult:
    rp = resolve_sandbox_path(path, sandbox_root)
    if not rp.ok:
        return ToolResult(ok=False, error=rp.error)
    p = Path(rp.abs)
    data = content.encode("utf-8")[:max_bytes]
    existed = p.exists()
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_bytes(data)
    verb = "覆盖" if existed else "创建"
    return ToolResult(ok=True, content=f"已{verb} {rp.rel}（{len(data)} 字节）", sources=[f"file:{rp.rel}"])


def fs_delete(path: str, sandbox_root: str) -> ToolResult:
    rp = resolve_sandbox_path(path, sandbox_root)
    if not rp.ok:
        return ToolResult(ok=False, error=rp.error)
    p = Path(rp.abs)
    if not p.exists():
        return ToolResult(ok=False, error=f"文件不存在: {rp.rel}")
    if p.is_dir():
        return ToolResult(ok=False, error="拒绝删除目录（仅支持单文件删除）")
    p.unlink()
    return ToolResult(ok=True, content=f"已删除 {rp.rel}", sources=[f"file:{rp.rel}"])
