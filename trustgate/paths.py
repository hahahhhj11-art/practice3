"""沙箱路径归一化。

所有路径判定都必须先经过 resolve_sandbox_path，用 realpath 消解 ".." 与符号链接，
再做前缀比较——否则 "sandbox/workspace/../private/id_rsa" 这类穿越会绕过白名单。
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import unquote


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

    # 百分号先解开再 realpath。`deploy-notes%2emd` 和 `deploy-notes.md` 是同一个文件；
    # 留着编码，精确路径不存在，读取在任何系统上都会失败，数据集就无法证明
    # 这格攻击在无防护时真的打得中。两层解码与溯源侧一致。
    text = unquote(unquote(path.replace("\\", "/")))
    raw = Path(text)
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


def casefold_existing(abs_path: str, sandbox_root: str = "sandbox") -> str | None:
    """精确路径不存在时，在沙箱内找唯一的大小写匹配。

    Linux 上 `Deploy-Notes.md` 打不开 `deploy-notes.md`，Windows 上打得开。
    数据集要在两边都让无防护读取成功，否则这格攻击在 CI 里测成「没打中」。
    匹配不唯一就不猜：猜错会把写入落到另一个文件上。调用方只应在读取时使用。
    """
    sandbox = (project_root() / sandbox_root).resolve()
    target = Path(abs_path)
    try:
        rel = target.resolve().relative_to(sandbox) if target.exists() else target.relative_to(sandbox)
    except ValueError:
        try:
            rel = Path(os.path.realpath(target)).relative_to(sandbox)
        except ValueError:
            return None
    cur = sandbox
    for part in rel.parts:
        if not cur.is_dir():
            return None
        exact = cur / part
        if exact.exists():
            cur = exact
            continue
        matches = [p for p in cur.iterdir() if p.name.lower() == part.lower()]
        if len(matches) != 1:
            return None
        cur = matches[0]
    try:
        if cur.exists() and cur.resolve().is_relative_to(sandbox):
            return str(cur.resolve())
    except OSError:
        return None
    return None


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
