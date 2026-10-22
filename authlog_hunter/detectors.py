"""Detection logic. Each detector consumes the full ordered event stream and
returns findings mapped to MITRE ATT&CK (Enterprise) techniques."""

from __future__ import annotations

from collections import defaultdict, deque
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Callable, Iterable, Sequence

from .parser import Event

SEVERITY_ORDER = {"low": 1, "medium": 2, "high": 3, "critical": 4}

PRIVILEGED_GROUPS = frozenset(
    {"sudo", "wheel", "admin", "adm", "root", "shadow", "docker", "lxd", "disk", "astra-admin"}
)
SHELL_BINARIES = frozenset(
    {"sh", "bash", "zsh", "dash", "ksh", "fish", "su", "python", "python3", "perl", "vi", "vim", "less", "find", "awk"}
)


@dataclass
class Finding:
    rule_id: str
    title: str
    severity: str
    technique_id: str
    technique_name: str
    tactic: str
    first_seen: datetime
    last_seen: datetime
    description: str
    entities: dict = field(default_factory=dict)
    evidence: list[int] = field(default_factory=list)  # line numbers

    def to_dict(self) -> dict:
        return {
            "rule_id": self.rule_id,
            "title": self.title,
            "severity": self.severity,
            "mitre": {
                "technique_id": self.technique_id,
                "technique_name": self.technique_name,
                "tactic": self.tactic,
                "url": attack_url(self.technique_id),
            },
            "first_seen": self.first_seen.isoformat(),
            "last_seen": self.last_seen.isoformat(),
            "description": self.description,
            "entities": self.entities,
            "evidence_lines": self.evidence,
        }


def attack_url(technique_id: str) -> str:
    return "https://attack.mitre.org/techniques/" + technique_id.replace(".", "/") + "/"


@dataclass
class Config:
    brute_force_threshold: int = 10
    brute_force_window: timedelta = timedelta(minutes=5)
    spray_user_threshold: int = 5
    spray_window: timedelta = timedelta(minutes=30)
    success_after_fail_threshold: int = 5
    success_after_fail_window: timedelta = timedelta(hours=1)
    sudo_fail_threshold: int = 3
    sudo_fail_window: timedelta = timedelta(minutes=10)
    off_hours: tuple[int, int] = (0, 6)  # [start, end) local hours considered off-hours
    trusted_networks: tuple[str, ...] = ()


Detector = Callable[[Sequence[Event], Config], list[Finding]]
DETECTORS: list[Detector] = []


def detector(fn: Detector) -> Detector:
    DETECTORS.append(fn)
    return fn


def _is_trusted(ip: str | None, cfg: Config) -> bool:
    if not ip or not cfg.trusted_networks:
        return False
    import ipaddress

    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return any(addr in ipaddress.ip_network(net, strict=False) for net in cfg.trusted_networks)


def _sliding_bursts(events: list[Event], threshold: int, window: timedelta) -> list[list[Event]]:
    """Return maximal bursts where at least ``threshold`` events fall inside ``window``."""
    bursts: list[list[Event]] = []
    win: deque[Event] = deque()
    current: list[Event] | None = None
    for ev in events:
        win.append(ev)
        while win and ev.timestamp - win[0].timestamp > window:
            win.popleft()
        if len(win) >= threshold:
            if current is None:
                current = list(win)
                bursts.append(current)
            else:
                current.append(ev)
        elif current is not None and ev.timestamp - current[-1].timestamp > window:
            current = None
    return bursts


@detector
def ssh_brute_force(events: Sequence[Event], cfg: Config) -> list[Finding]:
    by_ip: dict[str, list[Event]] = defaultdict(list)
    for ev in events:
        if ev.kind == "ssh_failed" and not _is_trusted(ev.src_ip, cfg):
            by_ip[ev.src_ip].append(ev)

    findings = []
    for ip, evs in by_ip.items():
        for burst in _sliding_bursts(evs, cfg.brute_force_threshold, cfg.brute_force_window):
            users = sorted({e.user for e in burst})
            if len(users) >= cfg.spray_user_threshold:
                continue  # reported by the password-spraying detector instead
            findings.append(
                Finding(
                    rule_id="AH-001",
                    title="SSH password brute force",
                    severity="medium",
                    technique_id="T1110.001",
                    technique_name="Brute Force: Password Guessing",
                    tactic="Credential Access",
                    first_seen=burst[0].timestamp,
                    last_seen=burst[-1].timestamp,
                    description=f"{len(burst)} failed SSH logins from {ip} against {', '.join(users)}.",
                    entities={"src_ip": ip, "users": users, "attempts": len(burst)},
                    evidence=[e.line_no for e in burst],
                )
            )
    return findings


@detector
def ssh_password_spraying(events: Sequence[Event], cfg: Config) -> list[Finding]:
    by_ip: dict[str, list[Event]] = defaultdict(list)
    for ev in events:
        if ev.kind in {"ssh_failed", "ssh_invalid_user"} and not _is_trusted(ev.src_ip, cfg):
            by_ip[ev.src_ip].append(ev)

    findings = []
    for ip, evs in by_ip.items():
        win: deque[Event] = deque()
        reported = False
        for ev in evs:
            win.append(ev)
            while win and ev.timestamp - win[0].timestamp > cfg.spray_window:
                win.popleft()
            users = {e.user for e in win}
            if len(users) >= cfg.spray_user_threshold and not reported:
                reported = True
                all_users = sorted({e.user for e in evs})
                invalid = sorted({e.user for e in evs if e.kind == "ssh_invalid_user" or e.extra.get("invalid_user")})
                findings.append(
                    Finding(
                        rule_id="AH-002",
                        title="SSH password spraying / account enumeration",
                        severity="high",
                        technique_id="T1110.003",
                        technique_name="Brute Force: Password Spraying",
                        tactic="Credential Access",
                        first_seen=evs[0].timestamp,
                        last_seen=evs[-1].timestamp,
                        description=(
                            f"{ip} tried {len(all_users)} different accounts "
                            f"({len(invalid)} of them do not exist on the host)."
                        ),
                        entities={"src_ip": ip, "users": all_users, "nonexistent_users": invalid, "attempts": len(evs)},
                        evidence=[e.line_no for e in evs],
                    )
                )
    return findings


@detector
def success_after_failures(events: Sequence[Event], cfg: Config) -> list[Finding]:
    fails: dict[str, deque[Event]] = defaultdict(deque)
    findings = []
    for ev in events:
        if ev.src_ip is None or _is_trusted(ev.src_ip, cfg):
            continue
        q = fails[ev.src_ip]
        while q and ev.timestamp - q[0].timestamp > cfg.success_after_fail_window:
            q.popleft()
        if ev.kind in {"ssh_failed", "ssh_invalid_user"}:
            q.append(ev)
        elif ev.kind == "ssh_accepted" and len(q) >= cfg.success_after_fail_threshold:
            findings.append(
                Finding(
                    rule_id="AH-003",
                    title="Successful SSH login after repeated failures",
                    severity="critical",
                    technique_id="T1078",
                    technique_name="Valid Accounts",
                    tactic="Initial Access",
                    first_seen=q[0].timestamp,
                    last_seen=ev.timestamp,
                    description=(
                        f"{ev.src_ip} logged in as '{ev.user}' via {ev.extra.get('method')} after "
                        f"{len(q)} failed attempts. Credentials are likely compromised."
                    ),
                    entities={"src_ip": ev.src_ip, "user": ev.user, "failed_before": len(q)},
                    evidence=[e.line_no for e in q] + [ev.line_no],
                )
            )
            q.clear()
    return findings


@detector
def root_ssh_login(events: Sequence[Event], cfg: Config) -> list[Finding]:
    return [
        Finding(
            rule_id="AH-004",
            title="Direct SSH login as root",
            severity="high",
            technique_id="T1078.003",
            technique_name="Valid Accounts: Local Accounts",
            tactic="Privilege Escalation",
            first_seen=ev.timestamp,
            last_seen=ev.timestamp,
            description=(
                f"root logged in over SSH from {ev.src_ip} ({ev.extra.get('method')}). "
                "Direct root login bypasses individual accountability; set PermitRootLogin no."
            ),
            entities={"src_ip": ev.src_ip, "user": "root"},
            evidence=[ev.line_no],
        )
        for ev in events
        if ev.kind == "ssh_accepted" and ev.user == "root"
    ]


@detector
def off_hours_login(events: Sequence[Event], cfg: Config) -> list[Finding]:
    start, end = cfg.off_hours
    out = []
    for ev in events:
        if ev.kind == "ssh_accepted" and start <= ev.timestamp.hour < end and not _is_trusted(ev.src_ip, cfg):
            out.append(
                Finding(
                    rule_id="AH-005",
                    title="SSH login outside working hours",
                    severity="low",
                    technique_id="T1078",
                    technique_name="Valid Accounts",
                    tactic="Defense Evasion",
                    first_seen=ev.timestamp,
                    last_seen=ev.timestamp,
                    description=f"'{ev.user}' logged in from {ev.src_ip} at {ev.timestamp:%H:%M}.",
                    entities={"src_ip": ev.src_ip, "user": ev.user},
                    evidence=[ev.line_no],
                )
            )
    return out


def _command_binary(command: str) -> str:
    first = command.split()[0] if command.split() else ""
    return first.rsplit("/", 1)[-1]


@detector
def sudo_shell(events: Sequence[Event], cfg: Config) -> list[Finding]:
    out = []
    for ev in events:
        if ev.kind != "sudo_command":
            continue
        cmd = ev.extra.get("command", "")
        binary = _command_binary(cmd)
        sensitive = any(p in cmd for p in ("/etc/shadow", "/etc/sudoers", "authorized_keys"))
        if binary in SHELL_BINARIES or sensitive:
            out.append(
                Finding(
                    rule_id="AH-006",
                    title="Interactive shell or sensitive file access via sudo",
                    severity="high" if ev.extra.get("target_user") == "root" else "medium",
                    technique_id="T1548.003",
                    technique_name="Abuse Elevation Control Mechanism: Sudo and Sudo Caching",
                    tactic="Privilege Escalation",
                    first_seen=ev.timestamp,
                    last_seen=ev.timestamp,
                    description=f"'{ev.user}' ran `{cmd}` as {ev.extra.get('target_user')}.",
                    entities={"user": ev.user, "target_user": ev.extra.get("target_user"), "command": cmd},
                    evidence=[ev.line_no],
                )
            )
    return out


@detector
def sudo_abuse_attempts(events: Sequence[Event], cfg: Config) -> list[Finding]:
    by_user: dict[str, list[Event]] = defaultdict(list)
    for ev in events:
        if ev.kind == "sudo_denied":
            by_user[ev.user].append(ev)
        elif ev.kind == "sudo_auth_failure" and ev.user:
            by_user[ev.user].append(ev)
        elif ev.kind == "sudo_command" and ev.extra.get("failures", 0) >= cfg.sudo_fail_threshold:
            by_user[ev.user].append(ev)

    out = []
    for user, evs in by_user.items():
        denied = [e for e in evs if e.kind == "sudo_denied"]
        bursts = _sliding_bursts(evs, cfg.sudo_fail_threshold, cfg.sudo_fail_window)
        if not denied and not bursts:
            continue
        sample = denied or bursts[0]
        out.append(
            Finding(
                rule_id="AH-007",
                title="Unauthorized sudo attempts",
                severity="medium",
                technique_id="T1548.003",
                technique_name="Abuse Elevation Control Mechanism: Sudo and Sudo Caching",
                tactic="Privilege Escalation",
                first_seen=sample[0].timestamp,
                last_seen=evs[-1].timestamp,
                description=(
                    f"'{user}' had {len(evs)} failed or denied sudo attempts"
                    + (f", including {len(denied)} as a user not in sudoers." if denied else ".")
                ),
                entities={"user": user, "attempts": len(evs)},
                evidence=[e.line_no for e in evs],
            )
        )
    return out


@detector
def account_created(events: Sequence[Event], cfg: Config) -> list[Finding]:
    return [
        Finding(
            rule_id="AH-008",
            title="New local account created",
            severity="medium" if ev.extra.get("uid", 1000) >= 1000 else "high",
            technique_id="T1136.001",
            technique_name="Create Account: Local Account",
            tactic="Persistence",
            first_seen=ev.timestamp,
            last_seen=ev.timestamp,
            description=(
                f"Account '{ev.user}' created with UID {ev.extra.get('uid')}"
                + (" (system UID range, unusual for a human user)." if ev.extra.get("uid", 1000) < 1000 else ".")
            ),
            entities={"user": ev.user, "uid": ev.extra.get("uid")},
            evidence=[ev.line_no],
        )
        for ev in events
        if ev.kind == "user_created"
    ]


@detector
def privileged_group_change(events: Sequence[Event], cfg: Config) -> list[Finding]:
    return [
        Finding(
            rule_id="AH-009",
            title="User added to privileged group",
            severity="high",
            technique_id="T1098",
            technique_name="Account Manipulation",
            tactic="Persistence",
            first_seen=ev.timestamp,
            last_seen=ev.timestamp,
            description=f"'{ev.user}' was added to privileged group '{ev.extra['group']}'.",
            entities={"user": ev.user, "group": ev.extra["group"]},
            evidence=[ev.line_no],
        )
        for ev in events
        if ev.kind == "group_membership_added" and ev.extra.get("group") in PRIVILEGED_GROUPS
    ]


@detector
def persistence_chain(events: Sequence[Event], cfg: Config) -> list[Finding]:
    """Correlate: account created and promoted to a privileged group within 15 minutes."""
    created = {ev.user: ev for ev in events if ev.kind == "user_created"}
    out = []
    for ev in events:
        if ev.kind != "group_membership_added" or ev.extra.get("group") not in PRIVILEGED_GROUPS:
            continue
        origin = created.get(ev.user)
        if origin and timedelta(0) <= ev.timestamp - origin.timestamp <= timedelta(minutes=15):
            out.append(
                Finding(
                    rule_id="AH-010",
                    title="Backdoor account: created and immediately granted privileges",
                    severity="critical",
                    technique_id="T1136.001",
                    technique_name="Create Account: Local Account",
                    tactic="Persistence",
                    first_seen=origin.timestamp,
                    last_seen=ev.timestamp,
                    description=(
                        f"'{ev.user}' was created and added to '{ev.extra['group']}' "
                        f"{int((ev.timestamp - origin.timestamp).total_seconds())} s later."
                    ),
                    entities={"user": ev.user, "group": ev.extra["group"]},
                    evidence=[origin.line_no, ev.line_no],
                )
            )
    return out


def run_all(events: Iterable[Event], cfg: Config | None = None) -> list[Finding]:
    cfg = cfg or Config()
    ordered = sorted(events, key=lambda e: (e.timestamp, e.line_no))
    findings: list[Finding] = []
    for det in DETECTORS:
        findings.extend(det(ordered, cfg))
    findings.sort(key=lambda f: (-SEVERITY_ORDER[f.severity], f.first_seen))
    return findings
