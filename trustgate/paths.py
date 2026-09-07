"""沙箱路径归一化。

所有路径判定都必须先经过 resolve_sandbox_path，用 realpath 消解 ".." 与符号链接，
再做前缀比较——否则 "sandbox/workspace/../private/id_rsa" 这类穿越会绕过白名单。
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path


def project_root() -> Path:
    return Path(__file__).resolve().parent.parent


@dataclass(frozen=True)
class ResolvedPath:
    ok: bool
    rel: str = ""          # 相对项目根的 posix 路径，用于策略前缀比较
    abs: str = ""
    error: str = ""


def resolve_sandbox_path(path: str, sandbox_root: str = "sandbox") -> ResolvedPath:
    """把任意用户/模型给出的路径收敛到沙箱内的规范相对路径。"""
    if not isinstance(path, str) or not path.strip():
        return ResolvedPath(False, error="路径为空")

    root = project_root()
    sandbox = (root / sandbox_root).resolve()

    raw = Path(path.replace("\\", "/"))
    candidate = raw if raw.is_absolute() else root / raw

    try:
        real = Path(os.path.realpath(candidate))
    except OSError as exc:
        return ResolvedPath(False, error=f"路径解析失败: {exc}")

    try:
        real.relative_to(sandbox)
    except ValueError:
        return ResolvedPath(
            False,
            error=f"路径越出沙箱根 {sandbox_root}/（疑似路径穿越）",
            abs=str(real),
        )

    return ResolvedPath(True, rel=real.relative_to(root).as_posix(), abs=str(real))


def matches_any(rel: str, patterns: list[str]) -> str | None:
    """前缀 / 子串匹配。以 '/' 结尾视为目录前缀，否则视为子串（便于写 'id_rsa'、'.env'）。"""
    low = rel.lower()
    for pat in patterns:
        p = pat.replace("\\", "/").lower()
        if p.endswith("/"):
            if low.startswith(p):
                return pat
        elif p in low:
            return pat
    return None
