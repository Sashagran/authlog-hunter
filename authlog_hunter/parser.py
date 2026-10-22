"""Parsing of Linux authentication logs (auth.log / secure) into normalized events.

Supports both classic BSD syslog timestamps (``Oct 22 10:15:01``) and
RFC 3339 timestamps written by modern rsyslog / journald exports
(``2026-10-22T10:15:01.123456+03:00``).
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import datetime
from typing import Iterable, Iterator, Optional

# --- line header -----------------------------------------------------------

_BSD_HEADER = re.compile(
    r"^(?P<ts>[A-Z][a-z]{2}\s+\d{1,2}\s\d{2}:\d{2}:\d{2})\s+"
    r"(?P<host>\S+)\s+(?P<proc>[\w\-./()]+?)(?:\[(?P<pid>\d+)\])?:\s(?P<msg>.*)$"
)
_ISO_HEADER = re.compile(
    r"^(?P<ts>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?)\s+"
    r"(?P<host>\S+)\s+(?P<proc>[\w\-./()]+?)(?:\[(?P<pid>\d+)\])?:\s(?P<msg>.*)$"
)

# --- message patterns ------------------------------------------------------

_IP = r"(?P<ip>[0-9a-fA-F:.]+)"

_SSH_FAILED = re.compile(
    r"^Failed (?P<method>password|publickey|keyboard-interactive/pam) for "
    r"(?P<invalid>invalid user )?(?P<user>\S*) from " + _IP + r" port (?P<port>\d+)"
)
_SSH_ACCEPTED = re.compile(
    r"^Accepted (?P<method>password|publickey|keyboard-interactive/pam|gssapi-with-mic) for "
    r"(?P<user>\S+) from " + _IP + r" port (?P<port>\d+)"
)
_SSH_INVALID_USER = re.compile(r"^Invalid user (?P<user>\S*) from " + _IP + r"(?: port (?P<port>\d+))?")
_SUDO_CMD = re.compile(
    r"^\s*(?P<user>\S+) : (?:(?P<failures>\d+) incorrect password attempts? ; )?"
    r"(?:.*?)USER=(?P<target>\S+) ; COMMAND=(?P<command>.+)$"
)
_SUDO_AUTH_FAIL = re.compile(
    r"pam_unix\(sudo:auth\): authentication failure;.*?ruser=(?P<user>\S*)"
)
_USERADD = re.compile(r"^new user: name=(?P<user>[^,]+), UID=(?P<uid>\d+)")
_GROUP_ADD = re.compile(
    r"^(?:add|added) '?(?P<user>[^' ]+)'? to (?P<shadow>shadow )?group '?(?P<group>[^' ]+)'?"
)
_USERDEL = re.compile(r"^delete user '?(?P<user>[^' ]+)'?")
_PASSWD_CHANGE = re.compile(r"^pam_unix\(passwd:chauthtok\): password changed for (?P<user>\S+)")


@dataclass(frozen=True)
class Event:
    """A single normalized security-relevant event."""

    timestamp: datetime
    host: str
    process: str
    kind: str
    user: Optional[str] = None
    src_ip: Optional[str] = None
    extra: dict = field(default_factory=dict, hash=False, compare=False)
    raw: str = field(default="", compare=False)
    line_no: int = 0


def _parse_timestamp(value: str, year: int) -> datetime:
    if value[0].isdigit():
        value = value.replace("Z", "+00:00")
        # journalctl short-iso writes +0300; Python 3.10 fromisoformat needs +03:00
        value = re.sub(r"([+-]\d{2})(\d{2})$", r"\1:\2", value)
        return datetime.fromisoformat(value)
    return datetime.strptime(f"{year} {' '.join(value.split())}", "%Y %b %d %H:%M:%S")


def _classify(proc: str, msg: str) -> Optional[tuple[str, dict]]:
    base = proc.split("/")[-1]

    if base.startswith("sshd"):
        if m := _SSH_FAILED.match(msg):
            return "ssh_failed", {
                "user": m["user"] or "<empty>",
                "src_ip": m["ip"],
                "method": m["method"],
                "invalid_user": bool(m["invalid"]),
            }
        if m := _SSH_ACCEPTED.match(msg):
            return "ssh_accepted", {"user": m["user"], "src_ip": m["ip"], "method": m["method"]}
        if m := _SSH_INVALID_USER.match(msg):
            return "ssh_invalid_user", {"user": m["user"] or "<empty>", "src_ip": m["ip"]}
        return None

    if base == "sudo":
        if m := _SUDO_AUTH_FAIL.search(msg):
            return "sudo_auth_failure", {"user": m["user"] or None}
        if m := _SUDO_CMD.match(msg):
            kind = "sudo_denied" if "NOT in sudoers" in msg or "command not allowed" in msg else "sudo_command"
            return kind, {
                "user": m["user"],
                "target_user": m["target"],
                "command": m["command"].strip(),
                "failures": int(m["failures"] or 0),
            }
        return None

    if base == "useradd":
        if m := _USERADD.match(msg):
            return "user_created", {"user": m["user"], "uid": int(m["uid"])}
        return None

    if base in {"usermod", "gpasswd", "groupmems"}:
        # usermod logs every change twice (/etc/group and /etc/gshadow); keep one.
        if (m := _GROUP_ADD.match(msg)) and not m["shadow"]:
            return "group_membership_added", {"user": m["user"], "group": m["group"]}
        return None

    if base == "userdel":
        if m := _USERDEL.match(msg):
            return "user_deleted", {"user": m["user"]}
        return None

    if base == "passwd":
        if m := _PASSWD_CHANGE.match(msg):
            return "password_changed", {"user": m["user"]}
        return None

    return None


def parse_line(line: str, *, year: int, line_no: int = 0) -> Optional[Event]:
    """Parse one log line. Returns ``None`` for lines that are not security relevant."""
    line = line.rstrip("\n")
    header = _ISO_HEADER.match(line) or _BSD_HEADER.match(line)
    if not header:
        return None

    classified = _classify(header["proc"], header["msg"])
    if classified is None:
        return None
    kind, fields = classified

    try:
        ts = _parse_timestamp(header["ts"], year)
    except ValueError:
        return None

    user = fields.pop("user", None)
    src_ip = fields.pop("src_ip", None)
    return Event(
        timestamp=ts,
        host=header["host"],
        process=header["proc"],
        kind=kind,
        user=user,
        src_ip=src_ip,
        extra=fields,
        raw=line,
        line_no=line_no,
    )


def parse_lines(lines: Iterable[str], *, year: Optional[int] = None) -> Iterator[Event]:
    """Parse an iterable of lines, skipping irrelevant ones."""
    year = year or datetime.now().year
    for no, line in enumerate(lines, start=1):
        event = parse_line(line, year=year, line_no=no)
        if event is not None:
            yield event
