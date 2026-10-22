"""Generate a synthetic auth.log with a realistic attack story.

All IP addresses belong to documentation ranges (RFC 5737), all users are fictional.

Story:
  1. Background noise: normal logins and sudo usage by admins.
  2. 03:12  Password spraying from 198.51.100.23 against many usernames.
  3. 09:40  Brute force from 203.0.113.77 against 'deploy', eventually successful.
  4. 09:47  Attacker uses sudo to spawn a root shell, creates a backdoor account
            and adds it to the sudo group.
  5. 10:05  Another user repeatedly fails sudo / is not in sudoers.
"""

from __future__ import annotations

import random
from datetime import datetime, timedelta
from pathlib import Path

random.seed(1337)
HOST = "web-prod-01"
lines: list[tuple[datetime, str]] = []


def log(ts: datetime, proc: str, msg: str, pid: int | None = None) -> None:
    pid = pid or random.randint(1000, 65000)
    lines.append((ts, f"{ts:%b} {ts.day:2d} {ts:%H:%M:%S} {HOST} {proc}[{pid}]: {msg}"))


def sudo(ts: datetime, user: str, cmd: str, target: str = "root") -> None:
    lines.append(
        (ts, f"{ts:%b} {ts.day:2d} {ts:%H:%M:%S} {HOST} sudo:    {user} : TTY=pts/0 ; "
             f"PWD=/home/{user} ; USER={target} ; COMMAND={cmd}")
    )


day = datetime(2026, 10, 21)

# 1. background noise
for hour in range(8, 19):
    t = day + timedelta(hours=hour, minutes=random.randint(0, 59))
    who = random.choice(["alice", "bob", "ivan.petrov"])
    log(t, "sshd", f"Accepted publickey for {who} from 192.0.2.{random.randint(10, 40)} port {random.randint(40000, 60000)} ssh2")
    sudo(t + timedelta(minutes=2), who, random.choice(["/usr/bin/systemctl restart nginx", "/usr/bin/apt update", "/usr/bin/journalctl -u nginx"]))

# 2. password spraying at night
t = day + timedelta(hours=3, minutes=12)
for user in ["admin", "test", "oracle", "postgres", "ubuntu", "git", "user", "support", "guest", "ftpuser", "alice"]:
    for _ in range(random.randint(1, 3)):
        t += timedelta(seconds=random.randint(3, 20))
        port = random.randint(30000, 60000)
        if user == "alice":
            log(t, "sshd", f"Failed password for alice from 198.51.100.23 port {port} ssh2")
        else:
            log(t, "sshd", f"Invalid user {user} from 198.51.100.23 port {port}")
            log(t + timedelta(seconds=1), "sshd", f"Failed password for invalid user {user} from 198.51.100.23 port {port} ssh2")

# 3. brute force -> success
t = day + timedelta(hours=9, minutes=40)
for _ in range(24):
    t += timedelta(seconds=random.randint(2, 9))
    log(t, "sshd", f"Failed password for deploy from 203.0.113.77 port {random.randint(30000, 60000)} ssh2")
t += timedelta(seconds=5)
log(t, "sshd", "Accepted password for deploy from 203.0.113.77 port 51515 ssh2")

# 4. privilege escalation and persistence
t += timedelta(minutes=3)
sudo(t, "deploy", "/bin/bash")
t += timedelta(minutes=1)
sudo(t, "deploy", "/usr/bin/cat /etc/shadow")
t += timedelta(minutes=2)
log(t, "useradd", "new user: name=sysupdate, UID=998, GID=998, home=/var/lib/sysupdate, shell=/bin/bash, from=/dev/pts/1")
t += timedelta(seconds=40)
log(t, "usermod", "add 'sysupdate' to group 'sudo'")
log(t, "usermod", "add 'sysupdate' to shadow group 'sudo'")
t += timedelta(minutes=5)
log(t, "sshd", "Accepted password for root from 203.0.113.77 port 51999 ssh2")

# 5. insider poking at sudo
t = day + timedelta(hours=10, minutes=5)
for cmd in ["/usr/bin/id", "/bin/cat /etc/sudoers", "/usr/bin/su -"]:
    t += timedelta(seconds=50)
    lines.append(
        (t, f"{t:%b} {t.day:2d} {t:%H:%M:%S} {HOST} sudo:    intern : user NOT in sudoers ; "
            f"TTY=pts/2 ; PWD=/home/intern ; USER=root ; COMMAND={cmd}")
    )

lines.sort(key=lambda x: x[0])
out = Path(__file__).with_name("auth.log")
out.write_text("\n".join(line for _, line in lines) + "\n", encoding="utf-8")
print(f"wrote {len(lines)} lines to {out}")
