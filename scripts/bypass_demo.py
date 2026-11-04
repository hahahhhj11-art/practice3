"""非绕过性演示：在权限剥离生效后，主动尝试绕过 Broker 直取资产。

这个脚本存在的意义是**提供对照**。只报告 S2 拦住了攻击没有说服力——必须同时
证明同样的绕过在 S0 下确实成功，否则无法排除「这条绕过路径本来就走不通」。

    python scripts/bypass_demo.py --level S0    # 预期：每条适用路径都成功
    python scripts/bypass_demo.py --level S2    # 预期：适用路径被内核拒绝

基础三项在常见平台上都走得通：
  A. 直接 open() 读沙箱敏感文件
  B. 直接 open("w") 写盘
  C. 直接开 INET socket

另外三条只在相应内核上才算数。剥权前探针失败（Windows、内核不提供 x32、
io_uring 被 sysctl 关掉、S0 下即 ENOSYS）时记 ``not_applicable``，不记成
绕过，也不记成拦截。适用性必须在剥权前判定：过滤器装上之后看到的 EPERM
分不清「内核本来就没有这条调用」和「过滤器拦住了」。
  D. AF_UNIX socket
  E. io_uring_setup（原始系统调用）
  F. x32 socket（仅 x86_64 Linux，调用号带 0x40000000）
"""

from __future__ import annotations

import argparse
import ctypes
import errno
import json
import os
import platform
import socket
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from trustgate.confine import (  # noqa: E402
    _NR_IO_URING_SETUP,
    _NR_SOCKET,
    _X32_SYSCALL_BIT,
    apply_confinement,
    probe,
)

# 这些 errno 说明「这条路在本内核上本来就没有」，不能当成被过滤器拦住。
_NOT_APPLICABLE_ERRNO = {
    errno.ENOSYS,
    errno.EAFNOSUPPORT,
    errno.EPROTONOSUPPORT,
    errno.EOPNOTSUPP,
    errno.EPERM,
    errno.EACCES,
}


def _attempt(fn) -> dict[str, object]:
    """执行一次绕过尝试。成功说明防线在这一点上不成立。"""
    try:
        detail = fn()
        return {"bypassed": True, "not_applicable": False, "detail": str(detail)}
    except BaseException as exc:  # 内核拒绝会以 OSError/PermissionError 呈现
        return {
            "bypassed": False,
            "not_applicable": False,
            "detail": f"{type(exc).__name__}: {exc}",
        }


def _not_applicable(detail: str) -> dict[str, object]:
    return {"bypassed": False, "not_applicable": True, "detail": detail}


def _supported(fn) -> tuple[bool, str]:
    """剥权前调用。只有这时成功，才说明本内核上这条路径确实走得通。"""
    try:
        return True, str(fn())
    except OSError as exc:
        if exc.errno in _NOT_APPLICABLE_ERRNO:
            return False, f"{type(exc).__name__}: {exc}"
        raise


def attempt_read_secret(target: Path) -> str:
    data = target.read_text(encoding="utf-8", errors="replace")
    return f"读到 {len(data)} 字节，首行 {data.splitlines()[0][:40]!r}"


def attempt_write(target: Path) -> str:
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text("bypass-marker\n", encoding="utf-8")
    return f"写入成功 {target}"


def attempt_socket() -> str:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        s.settimeout(0.3)
        # 不需要真连上：能建出 AF_INET socket 就已经说明外发通道没被切断
        return f"AF_INET socket 建立成功 fd={s.fileno()}"
    finally:
        s.close()


def attempt_unix_socket() -> str:
    if not hasattr(socket, "AF_UNIX"):
        raise OSError(errno.EAFNOSUPPORT, "本解释器没有 AF_UNIX")
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        return f"AF_UNIX socket 建立成功 fd={s.fileno()}"
    finally:
        s.close()


def _libc_syscall():
    libc = ctypes.CDLL(None, use_errno=True)
    libc.syscall.restype = ctypes.c_long
    return libc.syscall


def attempt_io_uring_setup() -> str:
    if sys.platform != "linux":
        raise OSError(errno.ENOSYS, "io_uring 仅 Linux 提供")
    syscall = _libc_syscall()
    syscall.argtypes = [ctypes.c_long, ctypes.c_uint, ctypes.c_void_p]
    params = ctypes.create_string_buffer(4096)
    ctypes.set_errno(0)
    fd = syscall(
        ctypes.c_long(_NR_IO_URING_SETUP),
        ctypes.c_uint(8),
        ctypes.c_void_p(ctypes.addressof(params)),
    )
    if fd < 0:
        err = ctypes.get_errno()
        raise OSError(err, os.strerror(err) if err else "io_uring_setup failed")
    os.close(int(fd))
    return f"io_uring_setup 成功 fd={int(fd)}"


def attempt_x32_socket() -> str:
    if sys.platform != "linux" or platform.machine() != "x86_64":
        raise OSError(errno.ENOSYS, "x32 socket 仅 x86_64 Linux 有意义")
    syscall = _libc_syscall()
    syscall.argtypes = [ctypes.c_long, ctypes.c_int, ctypes.c_int, ctypes.c_int]
    nr = _NR_SOCKET["x86_64"] | _X32_SYSCALL_BIT
    ctypes.set_errno(0)
    fd = syscall(
        ctypes.c_long(nr),
        ctypes.c_int(socket.AF_INET),
        ctypes.c_int(socket.SOCK_STREAM),
        ctypes.c_int(0),
    )
    if fd < 0:
        err = ctypes.get_errno()
        raise OSError(err, os.strerror(err) if err else "x32 socket failed")
    os.close(int(fd))
    return f"x32 socket 建立成功 fd={int(fd)}"


def _unix_supported() -> tuple[bool, str]:
    if not hasattr(socket, "AF_UNIX"):
        return False, "本解释器没有 AF_UNIX"
    return _supported(attempt_unix_socket)


def _io_uring_supported() -> tuple[bool, str]:
    if sys.platform != "linux":
        return False, "非 Linux，无 io_uring"
    flag = Path("/proc/sys/kernel/io_uring_disabled")
    if flag.exists():
        value = flag.read_text(encoding="utf-8", errors="replace").strip()
        if value not in ("", "0"):
            return False, f"io_uring_disabled={value}"
    return _supported(attempt_io_uring_setup)


def _x32_supported() -> tuple[bool, str]:
    if sys.platform != "linux" or platform.machine() != "x86_64":
        return False, "仅 x86_64 Linux 有 x32 ABI"
    return _supported(attempt_x32_socket)


def _record(applicable: bool, why: str, fn) -> dict[str, object]:
    if not applicable:
        return _not_applicable(why)
    return _attempt(fn)


def main() -> int:
    ap = argparse.ArgumentParser(description="TrustGate 非绕过性演示")
    ap.add_argument("--level", default="S2", choices=["S0", "S1", "S2"])
    ap.add_argument("--json", action="store_true", help="只输出 JSON，便于测试断言")
    ns = ap.parse_args()

    secret = ROOT / "sandbox" / "private" / "id_rsa"
    scratch = ROOT / "sandbox" / "workspace" / "out" / ".bypass-probe"

    unix_ok, unix_why = _unix_supported()
    ioring_ok, ioring_why = _io_uring_supported()
    x32_ok, x32_why = _x32_supported()

    # 剥离必须发生在任何计入结果的尝试之前，且此后不可撤销。
    # 上面三次探针已经把它们打开的 fd 关掉了。
    report = apply_confinement(ns.level)

    results = {
        "A_read_sandbox_secret": _attempt(lambda: attempt_read_secret(secret)),
        "B_write_filesystem": _attempt(lambda: attempt_write(scratch)),
        "C_open_inet_socket": _attempt(attempt_socket),
        "D_open_unix_socket": _record(unix_ok, unix_why, attempt_unix_socket),
        "E_io_uring_setup": _record(ioring_ok, ioring_why, attempt_io_uring_setup),
        "F_x32_socket": _record(x32_ok, x32_why, attempt_x32_socket),
    }
    applicable = sum(1 for r in results.values() if not r["not_applicable"])
    payload = {
        "level": ns.level,
        "probe": probe(),
        "confinement": report.to_wire(),
        "attempts": results,
        "bypass_count": sum(1 for r in results.values() if r["bypassed"]),
        "applicable_count": applicable,
    }

    if ns.json:
        print(json.dumps(payload, ensure_ascii=False, indent=2))
        return 0

    print(report.describe())
    print()
    for name, r in results.items():
        if r["not_applicable"]:
            icon = "不适用"
        elif r["bypassed"]:
            icon = "绕过成功"
        else:
            icon = "已被拦截"
        print(f"[{icon}] {name}\n           {r['detail']}")
    skipped = sum(1 for r in results.values() if r["not_applicable"])
    print(f"\n共 {payload['bypass_count']}/{applicable} 条适用绕过路径可用（{skipped} 条不适用）")

    # B 号绕过在 S0/S1 下是**真的**往沙箱里写了一个文件。必须提醒清理，因为
    # 残留文件会让后续的沙箱基线对不上，表现为下一轮实验里莫名多出一处"改动"。
    #
    # 刻意**不**在这里自动清理：tests/test_confinement.py 的
    # test_write_attempt_leaves_no_trace_on_disk 靠"父进程亲自检查这个文件在不在"
    # 来取证 Landlock 是否真的生效（Landlock 没有 /proc 内省，只能这样查）。
    # 脚本若自己删掉痕迹，那条测试在 Landlock 静默失效时也会通过——把唯一的
    # 证据擦掉，换来一点便利，不值得。清理交给调用方（reproduce.py 步骤 e 之后、
    # 测试的 tearDown）在父侧做。
    if results["B_write_filesystem"]["bypassed"]:
        print(
            f"\n提示：本次真的在沙箱里写下了 {scratch.relative_to(ROOT)}。\n"
            "      残留会让后续实验的基线比对多出一处'改动'，请执行：\n"
            "          python -m trustgate.sandbox reset"
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
