"""进程级权限剥离：把「Agent 绕不过 Broker」从**约定**变成**内核强制**。

为什么必须有这一层
------------------
参照监视器（reference monitor）成立需要三个条件：完全仲裁、防篡改、可验证。
TrustGate 的五层策略引擎解决的是「仲裁逻辑对不对」，可信锚解决的是「判定
状态会不会被改」。但**完全仲裁**在原先的实现里是靠代码风纪维持的：Agent
模块只是「没有 import tools_fs」，而不是「import 不到」。一个被间接提示注入
控制的 Agent——或者一个会生成并执行代码的真实模型——只需要一行
``open("sandbox/private/id_rsa")`` 就绕开了整条策略链，五层判定一次都不会
被触发。这不是策略强度问题，是**威胁模型的地基漏了**。

所以本模块提供的不是又一层检查，而是把工具能力从 Agent 进程里**物理拿走**。

三个档位（与可信锚的 T0/T1/T2 同构，如实汇报能力差值）
----------------------------------------------------
S0 ``none``     不剥离，Agent 与工具同进程。仅用于测量延迟下界，并在
                非绕过性测试里**证明绕过确实可行**——没有这个对照组，
                S2 的结论就没有参照。
S1 ``process``  Agent 独立进程 + 能力面裁剪（不可导入工具模块、环境变量
                清洗、字节码不落盘）。**不是 OS 强制**：进程仍以用户身份
                运行，``open()`` 依然可用。如实标记 ``os_enforced=False``。
S2 ``os``       S1 之上叠加内核强制。Linux 用 Landlock（路径粒度文件系统
                白名单）+ seccomp-BPF（禁止 AF_INET/AF_INET6 socket）。
                Windows 只能做到 Job Object 生命周期约束，文件与网络无内核
                强制——这个缺口写在 ``gaps`` 里，不靠措辞含糊过去。

S2 在 Linux 上的确切保证（可测，且刻意不夸大）
--------------------------------------------
被剥权进程无论执行任何代码：
  1. 读不到、也写不了 ``sandbox/`` 下的任何路径；
  2. 在**整个**文件系统上没有写权限（scratch 白名单除外）；
  3. 开不出 AF_INET / AF_INET6 socket，因此无法直连网络。
明确**不**保证：读不到 ``/usr``、``/etc`` 等运行 Python 必需的系统目录。
这些不在资产集合内——受保护资产是沙箱文件树与网络出口。把「什么没保护」
写清楚，比声称「全隔离」更有用。

使用禁忌
--------
``apply_confinement`` 作用于**当前进程且不可撤销**，所以只能由那个注定要被
剥权的子进程对自己调用。绝不要在特权父进程或测试运行器里调它：Windows 档位
会把调用方塞进 ``ActiveProcessLimit=1`` 的 Job Object，此后该进程再也拉不起
任何子进程（表现为 ``WinError 1816`` 配额不足），而 Linux 档位会让它此后读不到
沙箱、连不上网。需要检测能力时用只读的 ``probe()``。

剥离时机
--------
Landlock 与 seccomp 一旦生效即不可撤销（配合 ``PR_SET_NO_NEW_PRIVS``），
因此必须在**导入全部依赖之后、接触任何外部内容之前**由子进程对自己施加。
这保证了「Agent 业务代码严格运行在限制生效之后」，而不需要信任 Agent 自己
去调用剥离——它没有机会在剥离前插手。
"""

from __future__ import annotations

import ctypes
import os
import platform
import sys
from dataclasses import dataclass, field
from pathlib import Path

LEVELS = ("S0", "S1", "S2")

# ---------------------------------------------------------------- 能力报告


@dataclass(frozen=True)
class ConfinementReport:
    """剥离结果的如实描述。

    ``requested`` 与 ``effective`` 分开记录：在不支持的平台上请求 S2 会降级，
    而实验报告必须能看出「这一轮到底是不是内核强制的」，否则跨平台的数字
    根本不可比。
    """

    requested: str = "S0"
    effective: str = "S0"
    platform: str = field(default_factory=lambda: sys.platform)
    mechanisms: tuple[str, ...] = ()
    # 三条保证是否由 OS 强制。注意 fs_read_denied 指的是「沙箱资产不可读」，
    # 不是「任何文件不可读」——见模块头部对保证边界的说明。
    fs_read_denied: bool = False
    fs_write_denied: bool = False
    net_denied: bool = False
    gaps: tuple[str, ...] = ()
    errors: tuple[str, ...] = ()

    @property
    def os_enforced(self) -> bool:
        """是否至少有一条保证真正由内核兜底。"""
        return self.effective == "S2" and (self.fs_read_denied or self.net_denied)

    def describe(self) -> str:
        head = f"权限剥离 {self.effective}"
        if self.effective != self.requested:
            head += f"（请求 {self.requested}，本平台降级）"
        bits = [
            f"沙箱资产不可读={_yn(self.fs_read_denied)}",
            f"全盘不可写={_yn(self.fs_write_denied)}",
            f"网络不可达={_yn(self.net_denied)}",
        ]
        out = f"{head} · 机制[{', '.join(self.mechanisms) or '无'}] · " + " ".join(bits)
        if self.gaps:
            out += "\n  未覆盖：" + "；".join(self.gaps)
        if self.errors:
            out += "\n  施加失败：" + "；".join(self.errors)
        return out

    def to_wire(self) -> dict[str, object]:
        return {
            "requested": self.requested,
            "effective": self.effective,
            "platform": self.platform,
            "mechanisms": list(self.mechanisms),
            "fs_read_denied": self.fs_read_denied,
            "fs_write_denied": self.fs_write_denied,
            "net_denied": self.net_denied,
            "os_enforced": self.os_enforced,
            "gaps": list(self.gaps),
            "errors": list(self.errors),
        }


def _yn(b: bool) -> str:
    return "是" if b else "否"


# ---------------------------------------------------------------- Linux: Landlock

# 系统调用号（x86_64 与 aarch64 上一致）
_NR_LANDLOCK_CREATE_RULESET = 444
_NR_LANDLOCK_ADD_RULE = 445
_NR_LANDLOCK_RESTRICT_SELF = 446

_LANDLOCK_CREATE_RULESET_VERSION = 1 << 0
_LANDLOCK_RULE_PATH_BENEATH = 1

# 文件系统访问位。handled_access_fs 只能包含当前 ABI 支持的位，多一位就 EINVAL，
# 所以下面按 ABI 分档累加。
_FS_EXECUTE = 1 << 0
_FS_WRITE_FILE = 1 << 1
_FS_READ_FILE = 1 << 2
_FS_READ_DIR = 1 << 3
_FS_REMOVE_DIR = 1 << 4
_FS_REMOVE_FILE = 1 << 5
_FS_MAKE_CHAR = 1 << 6
_FS_MAKE_DIR = 1 << 7
_FS_MAKE_REG = 1 << 8
_FS_MAKE_SOCK = 1 << 9
_FS_MAKE_FIFO = 1 << 10
_FS_MAKE_BLOCK = 1 << 11
_FS_MAKE_SYM = 1 << 12
_FS_REFER = 1 << 13          # ABI 2+
_FS_TRUNCATE = 1 << 14       # ABI 3+
_FS_IOCTL_DEV = 1 << 15      # ABI 5+

_NET_BIND_TCP = 1 << 0       # ABI 4+
_NET_CONNECT_TCP = 1 << 1    # ABI 4+

_ABI1_FS = (
    _FS_EXECUTE | _FS_WRITE_FILE | _FS_READ_FILE | _FS_READ_DIR
    | _FS_REMOVE_DIR | _FS_REMOVE_FILE | _FS_MAKE_CHAR | _FS_MAKE_DIR
    | _FS_MAKE_REG | _FS_MAKE_SOCK | _FS_MAKE_FIFO | _FS_MAKE_BLOCK | _FS_MAKE_SYM
)

# 只读目录需要的权限组合：进目录 + 读文件 + 列目录
_READ_ACCESS = _FS_EXECUTE | _FS_READ_FILE | _FS_READ_DIR


class _RulesetAttrNet(ctypes.Structure):
    _fields_ = [("handled_access_fs", ctypes.c_uint64), ("handled_access_net", ctypes.c_uint64)]


class _RulesetAttrFs(ctypes.Structure):
    _fields_ = [("handled_access_fs", ctypes.c_uint64)]


class _PathBeneathAttr(ctypes.Structure):
    _pack_ = 1
    _fields_ = [("allowed_access", ctypes.c_uint64), ("parent_fd", ctypes.c_int32)]


def _libc() -> ctypes.CDLL:
    return ctypes.CDLL(None, use_errno=True)


def landlock_abi() -> int:
    """返回内核 Landlock ABI 版本；<=0 表示不支持。"""
    if sys.platform != "linux":
        return -1
    try:
        libc = _libc()
        ctypes.set_errno(0)
        v = libc.syscall(
            ctypes.c_long(_NR_LANDLOCK_CREATE_RULESET),
            None,
            ctypes.c_size_t(0),
            ctypes.c_uint32(_LANDLOCK_CREATE_RULESET_VERSION),
        )
        return int(v)
    except Exception:
        return -1


def _handled_fs_for(abi: int) -> int:
    handled = _ABI1_FS
    if abi >= 2:
        handled |= _FS_REFER
    if abi >= 3:
        handled |= _FS_TRUNCATE
    if abi >= 5:
        handled |= _FS_IOCTL_DEV
    return handled


def _apply_landlock(
    read_paths: list[str], write_paths: list[str], block_net: bool
) -> tuple[list[str], list[str]]:
    """对当前进程施加 Landlock 白名单。返回 (已生效机制, 错误)。"""
    abi = landlock_abi()
    if abi <= 0:
        return [], [f"Landlock 不可用（ABI={abi}）"]

    libc = _libc()
    handled_fs = _handled_fs_for(abi)
    net_ok = abi >= 4 and block_net

    if net_ok:
        attr: ctypes.Structure = _RulesetAttrNet(handled_fs, _NET_BIND_TCP | _NET_CONNECT_TCP)
    else:
        attr = _RulesetAttrFs(handled_fs)

    ctypes.set_errno(0)
    fd = libc.syscall(
        ctypes.c_long(_NR_LANDLOCK_CREATE_RULESET),
        ctypes.byref(attr),
        ctypes.c_size_t(ctypes.sizeof(attr)),
        ctypes.c_uint32(0),
    )
    if fd < 0:
        return [], [f"landlock_create_ruleset 失败 errno={ctypes.get_errno()}"]

    errors: list[str] = []
    try:
        # 写权限集合也必须含读权限，否则「可写目录」连打开都做不到
        write_access = handled_fs
        for group, access in ((read_paths, _READ_ACCESS), (write_paths, write_access)):
            for p in group:
                if not os.path.exists(p):
                    continue
                try:
                    pfd = os.open(p, os.O_PATH | os.O_CLOEXEC)
                except OSError as exc:
                    errors.append(f"打开 {p} 失败: {exc}")
                    continue
                try:
                    rule = _PathBeneathAttr(access, pfd)
                    ctypes.set_errno(0)
                    rc = libc.syscall(
                        ctypes.c_long(_NR_LANDLOCK_ADD_RULE),
                        ctypes.c_int(fd),
                        ctypes.c_uint32(_LANDLOCK_RULE_PATH_BENEATH),
                        ctypes.byref(rule),
                        ctypes.c_uint32(0),
                    )
                    if rc != 0:
                        errors.append(f"add_rule {p} 失败 errno={ctypes.get_errno()}")
                finally:
                    os.close(pfd)

        # NO_NEW_PRIVS 是 restrict_self 的前置条件，同时保证 exec 后限制不被提权绕过
        if libc.prctl(38, 1, 0, 0, 0) != 0:
            return [], [f"PR_SET_NO_NEW_PRIVS 失败 errno={ctypes.get_errno()}"]

        ctypes.set_errno(0)
        rc = libc.syscall(ctypes.c_long(_NR_LANDLOCK_RESTRICT_SELF), ctypes.c_int(fd), ctypes.c_uint32(0))
        if rc != 0:
            return [], [f"landlock_restrict_self 失败 errno={ctypes.get_errno()}"]
    finally:
        os.close(fd)

    mech = [f"landlock-fs(abi{abi})"]
    if net_ok:
        mech.append("landlock-net-tcp")
    return mech, errors


# ---------------------------------------------------------------- Linux: seccomp

_PR_SET_NO_NEW_PRIVS = 38
_PR_SET_SECCOMP = 22
_SECCOMP_MODE_FILTER = 2

_BPF_LD = 0x00
_BPF_W = 0x00
_BPF_ABS = 0x20
_BPF_JMP = 0x05
_BPF_JEQ = 0x10
_BPF_K = 0x00
_BPF_RET = 0x06

_SECCOMP_RET_ALLOW = 0x7FFF0000
_SECCOMP_RET_ERRNO = 0x00050000
_EPERM = 1

_AUDIT_ARCH_X86_64 = 0xC000003E
_AUDIT_ARCH_AARCH64 = 0xC00000B7

# socket() 的调用号。i386 走 socketcall，不在支持范围内，届时直接降级并如实汇报。
_SYS_SOCKET = {"x86_64": 41, "aarch64": 198}
_AF_UNIX = 1


class _SockFilter(ctypes.Structure):
    _fields_ = [
        ("code", ctypes.c_uint16),
        ("jt", ctypes.c_uint8),
        ("jf", ctypes.c_uint8),
        ("k", ctypes.c_uint32),
    ]


class _SockFprog(ctypes.Structure):
    _fields_ = [("len", ctypes.c_uint16), ("filter", ctypes.POINTER(_SockFilter))]


def _seccomp_block_inet() -> tuple[list[str], list[str]]:
    """用 seccomp-BPF 拒绝 AF_INET/AF_INET6 的 socket()，放行 AF_UNIX。

    为什么不是直接禁掉整个 socket：Landlock 的网络规则只覆盖 TCP bind/connect，
    UDP（含 DNS）与 raw socket 不在其内；而完全禁掉 socket 又会连带影响进程内
    可能用到的 AF_UNIX 通道。按 args[0]（domain）过滤能精确切断外发通道，
    同时不动本机 IPC。
    """
    machine = platform.machine()
    nr_socket = _SYS_SOCKET.get(machine)
    arch = {"x86_64": _AUDIT_ARCH_X86_64, "aarch64": _AUDIT_ARCH_AARCH64}.get(machine)
    if nr_socket is None or arch is None:
        return [], [f"seccomp 未适配架构 {machine}"]

    # seccomp_data 布局：nr@0, arch@4, ip@8, args[0]@16
    prog = [
        (_BPF_LD | _BPF_W | _BPF_ABS, 0, 0, 4),            # 0: A = arch
        (_BPF_JMP | _BPF_JEQ | _BPF_K, 0, 2, arch),        # 1: arch 不符 → 放行（不误伤）
        (_BPF_LD | _BPF_W | _BPF_ABS, 0, 0, 0),            # 2: A = nr
        (_BPF_JMP | _BPF_JEQ | _BPF_K, 1, 0, nr_socket),   # 3: 是 socket 则查 domain
        (_BPF_RET | _BPF_K, 0, 0, _SECCOMP_RET_ALLOW),     # 4: 其余一律放行
        (_BPF_LD | _BPF_W | _BPF_ABS, 0, 0, 16),           # 5: A = args[0] = domain
        (_BPF_JMP | _BPF_JEQ | _BPF_K, 1, 0, _AF_UNIX),    # 6: AF_UNIX 放行
        (_BPF_RET | _BPF_K, 0, 0, _SECCOMP_RET_ERRNO | _EPERM),  # 7: 其余 domain → EPERM
        (_BPF_RET | _BPF_K, 0, 0, _SECCOMP_RET_ALLOW),     # 8: AF_UNIX 落点
    ]

    arr = (_SockFilter * len(prog))(*[_SockFilter(*ins) for ins in prog])
    fprog = _SockFprog(len(prog), arr)

    libc = _libc()
    if libc.prctl(_PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0:
        return [], [f"PR_SET_NO_NEW_PRIVS 失败 errno={ctypes.get_errno()}"]
    ctypes.set_errno(0)
    if libc.prctl(_PR_SET_SECCOMP, _SECCOMP_MODE_FILTER, ctypes.byref(fprog), 0, 0) != 0:
        return [], [f"PR_SET_SECCOMP 失败 errno={ctypes.get_errno()}"]
    return ["seccomp-bpf(no-AF_INET)"], []


# ---------------------------------------------------------------- Windows

def _apply_windows_job() -> tuple[list[str], list[str], list[str]]:
    """Windows 上能做到的部分：Job Object 生命周期与资源约束。

    返回 (机制, 错误, 缺口)。必须强调它**不**提供文件系统与网络的内核强制：
    要达到 Linux S2 的等价保证，需要 AppContainer（去掉 internetClient 能力）
    或低完整性令牌重生，两者都需要由父进程在创建时设定，且会连带剥夺子进程
    读取项目目录的权限。这个差值是平台能力差，不是实现偷懒，如实登记在 gaps。
    """
    mech: list[str] = []
    errors: list[str] = []
    gaps = [
        "Windows 无 Landlock/seccomp 等价物：文件读写与网络均无内核强制",
        "达到等价保证需 AppContainer（剔除 internetClient 能力），需父进程创建时设定",
    ]
    try:
        k32 = ctypes.WinDLL("kernel32", use_last_error=True)  # type: ignore[attr-defined]
    except Exception as exc:
        return mech, [f"加载 kernel32 失败: {exc}"], gaps

    # 必须显式声明 restype：ctypes 默认按 c_int 返回，会把 64 位 HANDLE 截断成
    # 低 32 位，于是后续 SetInformationJobObject 拿着一个无效句柄静默失败。
    k32.CreateJobObjectW.restype = ctypes.c_void_p
    k32.CreateJobObjectW.argtypes = [ctypes.c_void_p, ctypes.c_wchar_p]
    k32.GetCurrentProcess.restype = ctypes.c_void_p
    k32.GetCurrentProcess.argtypes = []
    k32.SetInformationJobObject.restype = ctypes.c_bool
    k32.SetInformationJobObject.argtypes = [
        ctypes.c_void_p, ctypes.c_int, ctypes.c_void_p, ctypes.c_uint32,
    ]
    k32.AssignProcessToJobObject.restype = ctypes.c_bool
    k32.AssignProcessToJobObject.argtypes = [ctypes.c_void_p, ctypes.c_void_p]

    class _IoCounters(ctypes.Structure):
        _fields_ = [(n, ctypes.c_uint64) for n in
                    ("ReadOperationCount", "WriteOperationCount", "OtherOperationCount",
                     "ReadTransferCount", "WriteTransferCount", "OtherTransferCount")]

    class _BasicLimit(ctypes.Structure):
        _fields_ = [
            ("PerProcessUserTimeLimit", ctypes.c_int64),
            ("PerJobUserTimeLimit", ctypes.c_int64),
            ("LimitFlags", ctypes.c_uint32),
            ("MinimumWorkingSetSize", ctypes.c_size_t),
            ("MaximumWorkingSetSize", ctypes.c_size_t),
            ("ActiveProcessLimit", ctypes.c_uint32),
            ("Affinity", ctypes.c_size_t),
            ("PriorityClass", ctypes.c_uint32),
            ("SchedulingClass", ctypes.c_uint32),
        ]

    class _ExtLimit(ctypes.Structure):
        _fields_ = [
            ("BasicLimitInformation", _BasicLimit),
            ("IoInfo", _IoCounters),
            ("ProcessMemoryLimit", ctypes.c_size_t),
            ("JobMemoryLimit", ctypes.c_size_t),
            ("PeakProcessMemoryUsed", ctypes.c_size_t),
            ("PeakJobMemoryUsed", ctypes.c_size_t),
        ]

    JOB_OBJECT_LIMIT_ACTIVE_PROCESS = 0x8
    JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE = 0x2000
    JobObjectExtendedLimitInformation = 9

    h = k32.CreateJobObjectW(None, None)
    if not h:
        return mech, [f"CreateJobObjectW 失败 err={ctypes.get_last_error()}"], gaps

    info = _ExtLimit()
    info.BasicLimitInformation.LimitFlags = (
        JOB_OBJECT_LIMIT_ACTIVE_PROCESS | JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
    )
    # 禁止子进程再派生新进程：切断「用 subprocess 重新拿回权限」这条路
    info.BasicLimitInformation.ActiveProcessLimit = 1
    if not k32.SetInformationJobObject(
        h, JobObjectExtendedLimitInformation, ctypes.byref(info), ctypes.sizeof(info)
    ):
        errors.append(f"SetInformationJobObject 失败 err={ctypes.get_last_error()}")
    elif not k32.AssignProcessToJobObject(h, k32.GetCurrentProcess()):
        errors.append(f"AssignProcessToJobObject 失败 err={ctypes.get_last_error()}")
    else:
        mech.append("win32-job-object(no-child-spawn)")
    return mech, errors, gaps


# ---------------------------------------------------------------- 对外入口


def default_read_paths() -> list[str]:
    """运行 Python 所必需的只读目录。刻意**不含**项目根，以免顺带放通 sandbox/。"""
    root = Path(__file__).resolve().parent.parent
    paths = {
        sys.base_prefix,
        sys.prefix,
        str(Path(sys.executable).resolve().parent),
        "/usr", "/lib", "/lib64", "/bin", "/etc", "/proc", "/dev",
        # 只放通代码目录；sandbox/、logs/、.trustgate/ 一律不在白名单内
        str(root / "trustgate"),
    }
    for entry in sys.path:
        if entry and os.path.isdir(entry) and not _under(entry, root):
            paths.add(entry)
    return sorted(p for p in paths if p and os.path.exists(p))


def _under(path: str, root: Path) -> bool:
    try:
        Path(path).resolve().relative_to(root)
        return True
    except ValueError:
        return False


def probe() -> dict[str, object]:
    """只检测不施加，用于在报告里说明本机到底能强制到什么程度。"""
    return {
        "platform": sys.platform,
        "machine": platform.machine(),
        "landlock_abi": landlock_abi(),
        "seccomp_arch_supported": platform.machine() in _SYS_SOCKET,
        "max_level": "S2" if (sys.platform == "linux" and landlock_abi() > 0) else "S1",
    }


def apply_confinement(
    level: str = "S2",
    read_paths: list[str] | None = None,
    write_paths: list[str] | None = None,
) -> ConfinementReport:
    """由子进程对**自己**施加权限剥离。不可撤销，调用后立即生效。"""
    level = level.upper()
    if level not in LEVELS:
        raise ValueError(f"未知剥离档位 {level}，可选 {LEVELS}")

    if level == "S0":
        return ConfinementReport(
            requested="S0", effective="S0",
            gaps=("S0 不施加任何限制：Agent 可直接绕过 Broker 访问文件与网络",),
        )

    # S1：不依赖平台的能力面裁剪。这些不是内核强制，因此不置 *_denied 标志。
    mech: list[str] = ["no-tool-imports", "scrubbed-env"]
    errors: list[str] = []
    gaps: list[str] = []

    if level == "S1":
        return ConfinementReport(
            requested="S1", effective="S1", mechanisms=tuple(mech),
            gaps=("S1 非 OS 强制：进程仍以用户身份运行，open()/socket() 依然可用",),
        )

    # S2
    if sys.platform == "linux":
        reads = read_paths if read_paths is not None else default_read_paths()
        writes = write_paths or []
        ll_mech, ll_err = _apply_landlock(reads, writes, block_net=True)
        sc_mech, sc_err = _seccomp_block_inet()
        mech += ll_mech + sc_mech
        errors += ll_err + sc_err
        fs_ok = bool(ll_mech)
        net_ok = bool(sc_mech) or "landlock-net-tcp" in ll_mech
        if not fs_ok:
            gaps.append("Landlock 未生效，文件系统限制退化为 S1")
        if not net_ok:
            gaps.append("seccomp 未生效，网络限制退化为 S1")
        if fs_ok:
            gaps.append("系统目录（/usr、/etc 等）仍可读：运行 Python 所必需，不在资产集合内")
        effective = "S2" if (fs_ok or net_ok) else "S1"
        return ConfinementReport(
            requested="S2", effective=effective, mechanisms=tuple(mech),
            fs_read_denied=fs_ok, fs_write_denied=fs_ok, net_denied=net_ok,
            gaps=tuple(gaps), errors=tuple(errors),
        )

    if sys.platform == "win32":
        w_mech, w_err, w_gaps = _apply_windows_job()
        mech += w_mech
        return ConfinementReport(
            requested="S2",
            # 没有文件/网络强制就不配叫 S2。宁可标成 S1 也不要让报告读者误会。
            effective="S1",
            mechanisms=tuple(mech), gaps=tuple(w_gaps), errors=tuple(w_err),
        )

    return ConfinementReport(
        requested="S2", effective="S1", mechanisms=tuple(mech),
        gaps=(f"平台 {sys.platform} 无已适配的内核强制机制",),
    )
