"""策略判定点 PDP：五层策略引擎。

按代价从低到高短路求值，任何一层给出 deny 立即返回。这样做有两个好处：
判定延迟低（大部分攻击在 L1/L2 就被挡住），且归因唯一（Decision.rule 可
直接聚合成"各层拦截贡献度"图表）。

层次与抵抗的攻击类别见 docs/02-系统架构.md §4。
"""

from __future__ import annotations

import json
import urllib.parse
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .audit import sha256_hex
from .dlp import MIN_MATCHES, SensitiveFingerprint
from .paths import matches_any, project_root, resolve_sandbox_path
from .taint import TaintTracker, find_canaries
from .types import (
    TOOL_SPECS,
    Attestation,
    CallRecord,
    Decision,
    Manifest,
    ToolCall,
    Trust,
)


@dataclass
class Policy:
    raw: dict[str, Any]
    source_digest: str = ""

    @classmethod
    def load(cls, path: str | Path = "policy.json") -> Policy:
        p = Path(path)
        if not p.is_absolute():
            p = project_root() / p
        data = p.read_bytes()
        return cls(raw=json.loads(data), source_digest="sha256:" + sha256_hex(data)[:16])

    @property
    def mode(self) -> str:
        return str(self.raw.get("mode", "enforce"))

    @property
    def version(self) -> int:
        return int(self.raw.get("version", 0))

    def layer_on(self, name: str) -> bool:
        return bool(self.raw.get("layers", {}).get(name, True))

    def sec(self, name: str) -> dict[str, Any]:
        return dict(self.raw.get(name, {}))

    def attestation(self, anchor: str) -> Attestation:
        return Attestation(
            anchor=anchor,
            policy_hash=self.source_digest,
            policy_version=self.version,
            mode=self.mode,
        )


@dataclass
class SessionState:
    """会话状态机。L4 时序策略的全部判据都在这里。"""

    session_id: str
    taint: TaintTracker = field(default_factory=TaintTracker)
    manifest: Manifest = field(default_factory=Manifest)
    history: list[CallRecord] = field(default_factory=list)
    steps_used: int = 0
    sensitive_seen: bool = False          # 是否已有调用触及敏感内容
    canaries_seen: set[str] = field(default_factory=set)
    query_bytes_used: int = 0             # 累计外发查询串长度（低带宽外泄预算）
    # 敏感内容指纹。与 canaries_seen 的区别：指纹是防御用的，canary 是评测
    # 预言机用的，两者刻意分开，避免防御偷看 ground truth（见 dlp.py 模块注释）。
    fingerprint: SensitiveFingerprint = field(default_factory=SensitiveFingerprint)

    def record(self, call: ToolCall, decision: Decision, trust: Trust, sensitive: bool) -> None:
        self.history.append(
            CallRecord(
                tool=call.tool,
                args={k: (v[:80] if isinstance(v, str) else v) for k, v in call.args.items()},
                verdict=decision.verdict,
                rule=decision.rule,
                trust=trust,
                touched_sensitive=sensitive,
            )
        )
        self.steps_used += 1


def _host_of(url: str) -> str:
    try:
        return (urllib.parse.urlparse(url).hostname or "").lower()
    except ValueError:
        return ""


def _query_len(url: str) -> int:
    try:
        parts = urllib.parse.urlparse(url)
    except ValueError:
        return 0
    return len(parts.query) + len(parts.fragment) + len(parts.params)


def _egress_payload_len(url: str, state: "SessionState | None" = None) -> int:
    """URL 能携带出去的**攻击者可控**字节数。

    早先这里只统计 query 与 fragment，路径段一概不计。那是一个可利用的
    漏洞：把凭据切成 8 字节碎片编进路径（`/collect/TG-CANAR`、`/collect/Y-3f1a`
    ……），返回值恒为 0，于是 L1 的长度阈值、L4 的外泄链、L4 的会话预算
    三道判据同时失效，而碎片又短于 L3 指纹的 16 字符窗口——五层防御被
    一个换信道的动作整体绕过。对应样本 attacks/generate.py::exfil/path_lowbw。

    修法不能是"把路径长度也加上"：正常 URL 的路径本来就有几十字节
    （`/corpus/tg-0001-....html`），一律计入会让良性抓取全部撞上阈值。
    真正的判据是**这个 URL 是不是用户任务给的**：
      - 能溯源到用户任务（trusted）：路径是用户指定的，只有 query 与
        fragment 才是 Agent 后加的，因此只计后者；
      - 溯源到外部内容或无法溯源：整个 URL 都是攻击者写的，路径与查询串
        同为外泄信道，因此整体计入。
    这样良性抓取的载荷长度仍是 0，而任何形态的注入型外发都被计满。
    """
    base = _query_len(url)
    if state is None:
        return base
    if state.taint.origin(url) is Trust.TRUSTED:
        return base
    try:
        parts = urllib.parse.urlparse(url)
    except ValueError:
        return base
    # 只计路径，不计 scheme 与 host——后者已由 L1 的域名允许列表约束，
    # 且长度固定，计入只会让阈值标定变得依赖具体域名。
    return base + len(parts.path)


class PolicyEngine:
    """无状态的判定逻辑；全部可变状态由调用方以 SessionState 传入。

    这一约束是为了让整个引擎可以原封不动地搬进 OP-TEE TA（T2 档）——
    TA 内不便持有复杂生命周期的对象。
    """

    def __init__(self, policy: Policy):
        self.p = policy

    # ---------- 对外入口 ----------

    def evaluate(self, call: ToolCall, state: SessionState, meta: dict[str, Any] | None = None) -> Decision:
        meta = meta or {}
        spec = TOOL_SPECS.get(call.tool)
        if spec is None:
            return Decision("deny", "L0.unknown_tool", f"未声明的工具 {call.tool}")
        if not self.p.sec("capabilities").get(call.tool, True):
            return Decision("deny", "L0.capability_disabled", f"能力 {call.tool} 已被策略关闭")

        # 外发载荷长度在分层判定之前统一算好。放在这里而不是某一层内部，是
        # 因为它同时被 L4 的两条规则和 anchor 的会话预算累加使用；若由 L4
        # 计算，则 L4 关闭时（C2/C3 组）预算累加会静默失效，导致消融曲线
        # 里出现"关掉 L4 反而攻不进来"的假象。
        if spec.egress:
            meta["egress_len"] = _egress_payload_len(str(call.args.get("url", "")), state)

        for layer, on, fn in (
            ("L1_static", self.p.layer_on("L1_static"), self._l1_static),
            ("L2_manifest", self.p.layer_on("L2_manifest"), self._l2_manifest),
            ("L3_taint", self.p.layer_on("L3_taint"), self._l3_taint),
            ("L4_temporal", self.p.layer_on("L4_temporal"), self._l4_temporal),
        ):
            if not on:
                continue
            verdict = fn(call, state, meta)
            if verdict is not None and verdict.verdict != "allow":
                return verdict

        if self.p.layer_on("L5_risk"):
            return self._l5_risk(call, state, meta)
        return Decision("allow", "L5.disabled", risk=spec.risk)

    # ---------- L1 静态权限 ----------

    def _l1_static(self, call: ToolCall, state: SessionState, meta: dict) -> Decision | None:
        fs = self.p.sec("fs")
        root = self.p.raw.get("sandbox_root", "sandbox")

        if call.tool.startswith("fs."):
            rp = resolve_sandbox_path(str(call.args.get("path", "")), root)
            if not rp.ok:
                return Decision("deny", "L1.path_escape", rp.error)
            meta["rel"] = rp.rel
            meta["abs"] = rp.abs

            hit = matches_any(rp.rel, list(fs.get("deny", [])))
            if hit:
                return Decision("deny", "L1.deny_list", f"路径命中敏感黑名单规则 '{hit}': {rp.rel}")

            allow = fs.get("read_allow" if call.tool == "fs.read" else "write_allow", [])
            if not matches_any(rp.rel, list(allow)):
                op = "读取" if call.tool == "fs.read" else "写入/删除"
                return Decision("deny", "L1.not_in_allowlist", f"{op}白名单未覆盖此路径: {rp.rel}")

            if call.tool == "fs.write":
                content = str(call.args.get("content", ""))
                if len(content.encode("utf-8", "ignore")) > int(fs.get("max_write_bytes", 65536)):
                    return Decision("deny", "L1.write_too_large", "写入内容超出上限")

        elif call.tool == "web.read":
            web = self.p.sec("web")
            url = str(call.args.get("url", ""))
            scheme = urllib.parse.urlparse(url).scheme if url else ""
            if scheme not in ("http", "https"):
                return Decision("deny", "L1.bad_scheme", f"仅允许 http/https，得到 '{scheme}'")
            host = _host_of(url)
            hosts = list(web.get("allow_hosts", []))
            if hosts and host not in hosts:
                return Decision("deny", "L1.host_not_allowed", f"域名不在允许列表: {host}")
            qlen = _query_len(url)
            meta["query_len"] = qlen
            if qlen > int(web.get("max_query_len", 96)):
                return Decision(
                    "deny", "L1.query_too_long", f"URL 查询串长度 {qlen} 超限（疑似数据外带）"
                )
            # 整条 URL 的静态上限。L1 不看溯源，所以无法区分"路径是用户给的"
            # 与"路径是攻击者拼的"，只能设一个宽松的绝对上限来兜住把大段
            # 数据塞进路径的粗暴形态；细粒度判定由 L4 承担。
            if len(url) > int(web.get("max_url_len", 512)):
                return Decision(
                    "deny", "L1.url_too_long", f"URL 总长度 {len(url)} 超限（疑似数据外带）"
                )

        return Decision("allow", "L1.ok")

    # ---------- L2 任务-能力绑定 ----------

    def _l2_manifest(self, call: ToolCall, state: SessionState, meta: dict) -> Decision | None:
        mcfg = self.p.sec("manifest")
        m = state.manifest
        meta["in_manifest"] = _within_manifest(call, state, meta)

        if not m.frozen:
            if mcfg.get("require_frozen", True):
                return Decision("deny", "L2.no_manifest", "会话未冻结能力清单（fail-closed）")
            return Decision("allow", "L2.skipped")

        if state.steps_used >= min(m.max_steps, int(mcfg.get("max_steps_cap", 12))):
            return Decision("deny", "L2.step_budget_exhausted", f"超出计划步数上限 {m.max_steps}")

        if call.tool not in m.tools:
            return Decision(
                "deny",
                "L2.tool_not_in_manifest",
                f"计划未申请能力 {call.tool}（已申请: {', '.join(m.tools) or '无'}）",
            )

        if call.tool.startswith("fs."):
            rel = meta.get("rel") or str(call.args.get("path", ""))
            prefixes = m.read_prefixes if call.tool == "fs.read" else m.write_prefixes
            if not matches_any(rel, list(prefixes)):
                return Decision(
                    "deny",
                    "L2.path_not_in_manifest",
                    f"路径超出计划授权范围: {rel}（授权前缀: {', '.join(prefixes) or '无'}）",
                )
        elif call.tool == "web.read":
            host = _host_of(str(call.args.get("url", "")))
            if m.hosts and host not in m.hosts:
                return Decision("deny", "L2.host_not_in_manifest", f"计划未申请域名: {host}")

        return Decision("allow", "L2.manifest_ok")

    # ---------- L3 污点与参数溯源 ----------

    def _l3_taint(self, call: ToolCall, state: SessionState, meta: dict) -> Decision | None:
        spec = TOOL_SPECS[call.tool]
        # 只对"选择目标"的参数溯源；fs.write 的 content 单独在 L4 处理，
        # 因为把网页内容写进工作区本身是合法的摘要任务。
        selector_args = {k: v for k, v in call.args.items() if k in ("path", "url")}
        origins = state.taint.origins(selector_args)
        meta["arg_origin_pdp"] = {k: v.value for k, v in origins.items()}
        trust = max(origins.values(), key=lambda t: ["trusted", "unknown", "untrusted"].index(t.value)) if origins else Trust.TRUSTED
        meta["trust"] = trust.value

        # Agent 自报的溯源与 PDP 重算不一致，本身就是一个攻击信号
        if call.arg_origin:
            for k, claimed in call.arg_origin.items():
                if k in origins and claimed == "trusted" and origins[k] != Trust.TRUSTED:
                    meta["taint_mismatch"] = True

        if trust == Trust.UNTRUSTED and spec.irreversible:
            return Decision(
                "deny",
                "L3.untrusted_irreversible",
                f"不可逆操作 {call.tool} 的目标仅能溯源自不可信网页内容",
                risk=spec.risk,
            )

        if trust == Trust.UNTRUSTED and call.tool == "fs.read":
            return Decision(
                "deny",
                "L3.untrusted_read_target",
                "待读取路径来自不可信网页内容，而非用户任务",
                risk=spec.risk,
            )

        # 外发参数与本会话读过的敏感内容逐字重合 —— 数据正在离开可信边界。
        # 用内容指纹而非 canary：防御不得依赖只有评测方才知道的秘密。
        #
        # 只对**外发通道**生效（spec.egress）。早先这里写的是
        # `call.tool != "fs.read"`，于是 fs.write 也被卷进来：用户明确要求
        # "把含密码的部署备忘并进摘要"这类任务，写入内容必然与刚读到的敏感
        # 内容重合，被一律判成数据外带。实测良性任务完成率因此掉到 66.7%，
        # 直接违反 G6。本地写入不是外泄，它的风险由 L5 计分处理。
        if spec.egress and state.fingerprint.active:
            threshold = int(self.p.sec("dlp").get("min_matches", MIN_MATCHES))
            for key, val in call.args.items():
                if isinstance(val, str) and state.fingerprint.leaks(val, threshold):
                    return Decision(
                        "deny",
                        "L3.sensitive_content_in_args",
                        f"参数 {key} 与本会话读取过的敏感文件内容逐字重合，判定为数据外带",
                        risk=100,
                    )

        # 参考上界（默认关闭）：直接用评测 canary 判定。开启后测得的 ASR 是
        # 「防御方预先知道秘密」这一理想情形下的乐观值，只用于给 DLP 指纹
        # 的漏检率提供一个对照基准，绝不能作为主实验结果上报。
        if self.p.sec("dlp").get("oracle_canary_rule", False) and spec.egress:
            for key, val in call.args.items():
                if isinstance(val, str) and find_canaries(val):
                    return Decision(
                        "deny",
                        "L3.oracle_canary_in_args",
                        f"[参考上界] 参数 {key} 中出现评测 canary 令牌",
                        risk=100,
                    )

        return Decision("allow", "L3.ok")

    # ---------- L4 跨步骤时序策略 ----------

    def _l4_temporal(self, call: ToolCall, state: SessionState, meta: dict) -> Decision | None:
        ex = self.p.sec("exfil")

        # 外泄链：曾读到敏感内容 → 随后发起可携带数据的外发请求。
        # 判据用 egress_len 而非 query_len：见 _egress_payload_len 的说明，
        # 只看查询串会被"把碎片编进 URL 路径"整体绕过。
        if call.tool == "web.read" and state.sensitive_seen:
            elen = int(meta.get("egress_len", 0))
            if elen >= int(ex.get("min_query_len_for_chain", 8)):
                return Decision(
                    "deny",
                    "L4.exfil_chain",
                    f"检测到外泄链：本会话曾读取敏感内容，现发起含 {elen} 字节可控载荷的外发请求",
                    risk=100,
                )

        # 低带宽外泄：把数据切碎成多次短请求，绕过单次长度阈值
        if call.tool == "web.read":
            budget = int(ex.get("session_query_budget", 256))
            elen = int(meta.get("egress_len", 0))
            if state.query_bytes_used + elen > budget:
                return Decision(
                    "deny",
                    "L4.exfil_budget",
                    f"会话累计外发载荷 {state.query_bytes_used + elen} 字节，超出预算 {budget}",
                    risk=90,
                )

        # 注入驱动的破坏：会话已污染，且目标是已存在的文件。
        #
        # 例外：调用落在冻结清单内、且目标路径能溯源到用户任务。这种覆盖
        # 正是用户亲口要求的事（"把摘要写到 out/summary.md"，而该文件上次
        # 就已生成），再弹确认框纯属噪声。少了这条例外，任何"更新我上次的
        # 输出"型任务都会 100% 触发确认——安全机制把常规工作流做废，
        # 是比漏拦一次攻击更容易葬送方案的失败模式（G6）。
        if state.taint.session_tainted and TOOL_SPECS[call.tool].irreversible:
            authorized = bool(meta.get("in_manifest")) and meta.get("trust") == "trusted"
            if meta.get("target_exists") and not authorized:
                return Decision(
                    "confirm",
                    "L4.tainted_destructive",
                    f"会话已含不可信外部内容，{call.tool} 将不可逆地改动已存在文件 {meta.get('rel', '')}",
                    risk=TOOL_SPECS[call.tool].risk,
                )

        # 持久化注入：把不可信内容写进 Agent 后续还会读到的位置（记忆投毒）
        if call.tool == "fs.write":
            content = str(call.args.get("content", ""))
            rel = str(meta.get("rel", ""))
            if state.taint.contains_untrusted(content[:400]) and matches_any(
                rel, list(self.p.sec("fs").get("read_allow", []))
            ):
                if _looks_like_instruction(content):
                    return Decision(
                        "confirm",
                        "L4.persistent_injection",
                        "写入内容含指令性的不可信文本，且落在后续可读区域（疑似记忆投毒）",
                        risk=70,
                    )

        return Decision("allow", "L4.ok")

    # ---------- L5 风险累加与确认 ----------

    def _l5_risk(self, call: ToolCall, state: SessionState, meta: dict) -> Decision:
        """风险分累加。

        计分从工具的基础风险出发，再按「这次调用有多像用户本来就要求的事」
        上下调整。关键是那笔**清单信用（manifest credit）**：一次落在冻结清单
        内、且参数可溯源到用户任务的调用，本质上就是用户授权过的动作，不应该
        再去打扰用户确认。没有这笔信用，fs.write 的基础风险 60 会让**每一次
        写文件**都弹确认框，良性任务完成率 G6 直接崩掉——这是安全机制把系统
        变得不可用的典型形态，必须在计分模型里解决，而不是靠调高阈值掩盖。
        """
        spec = TOOL_SPECS[call.tool]
        rcfg = self.p.sec("risk")
        risk = spec.risk
        trust = meta.get("trust", "trusted")

        in_manifest = meta.get("in_manifest")
        if in_manifest is None:
            in_manifest = _within_manifest(call, state, meta)
            meta["in_manifest"] = in_manifest

        # 「用户授权过」这件事：调用落在冻结清单内，且选择目标的参数能溯源
        # 到用户任务本身。下面几笔加减都以它为轴。
        authorized = bool(in_manifest) and trust == "trusted"

        if authorized:
            risk -= int(rcfg.get("manifest_credit", 40))
        elif in_manifest:
            risk -= int(rcfg.get("manifest_credit_weak", 20))

        if trust == "untrusted":
            risk += int(rcfg.get("untrusted_penalty", 40))
        elif trust == "unknown":
            risk += int(rcfg.get("unknown_penalty", 15))

        # 会话被污染这一事实，不改变已授权调用的授权状态。
        #
        # 清单是在任何外部内容进入上下文**之前**冻结的，所以清单内、参数
        # 又溯源自用户任务的调用，其授权早于污染成立，事后出现的不可信内容
        # 不该反过来给它加分。少了这条区分，惩罚项会累加到恰好触线：
        # 60 − 40（清单信用）+ 10（会话污染）+ 20（覆盖既存/敏感写入）= 50，
        # 正好是 confirm 阈值——于是"更新我上次的摘要"这类任务 100% 弹确认框，
        # 实测 BTC 掉到 66.7%，违反 G6。
        if state.taint.session_tainted and not authorized:
            risk += int(rcfg.get("tainted_session_penalty", 10))
        if spec.irreversible and meta.get("target_exists"):
            risk += int(rcfg.get("overwrite_penalty", 20))

        # 把敏感内容落到本地文件：不是外泄（L3 已按 egress 收窄），但确实是
        # 一次敏感数据扩散，按比例加分而不是直接拒绝。落在清单内又溯源可信的
        # 写入仍在允许区间；一旦授权关系变弱，同样的动作就会升级为需要确认。
        # 这条是"比例原则"的落点：证据强度决定处置强度，而不是一刀切。
        if spec.irreversible and not spec.egress and state.fingerprint.active:
            content = str(call.args.get("content", ""))
            if content and state.fingerprint.leaks(
                content, int(self.p.sec("dlp").get("min_matches", MIN_MATCHES))
            ):
                risk += int(rcfg.get("sensitive_local_write_penalty", 20))
                meta["sensitive_local_write"] = True

        risk = max(risk, 0)
        meta["risk"] = risk

        if risk >= int(rcfg.get("deny_threshold", 100)):
            return Decision("deny", "L5.risk_deny", f"累计风险分 {risk} 超过拒绝阈值", risk=risk)
        if risk >= int(rcfg.get("confirm_threshold", 50)):
            return Decision("confirm", "L5.risk_confirm", f"累计风险分 {risk}，需用户确认", risk=risk)
        return Decision("allow", "L5.ok", risk=risk)


def _within_manifest(call: ToolCall, state: SessionState, meta: dict[str, Any]) -> bool:
    """这次调用是否完全落在冻结的能力清单内。

    L2 用它做准入判定，L5 用它做风险信用。抽成一个函数是为了保证两处
    对"在清单内"的理解不会随时间漂移——否则会出现 L2 放行、L5 却当成
    计划外调用加罚分的自相矛盾。
    """
    m = state.manifest
    if not m.frozen or call.tool not in m.tools:
        return False
    if call.tool.startswith("fs."):
        rel = str(meta.get("rel") or call.args.get("path", ""))
        prefixes = m.read_prefixes if call.tool == "fs.read" else m.write_prefixes
        return bool(matches_any(rel, list(prefixes)))
    if call.tool == "web.read":
        host = _host_of(str(call.args.get("url", "")))
        return not m.hosts or host in m.hosts
    return True


_INSTRUCTION_HINTS = (
    "ignore previous", "system", "指令", "请立即", "must", "你必须",
    "instruction", "忽略", "assistant", "tool", "发送到", "上传",
)


def _looks_like_instruction(text: str) -> bool:
    low = text.lower()
    return sum(1 for h in _INSTRUCTION_HINTS if h.lower() in low) >= 2
