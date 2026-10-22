import json
import subprocess
import sys
import unittest
from datetime import datetime, timedelta
from pathlib import Path

from authlog_hunter.detectors import Config, run_all
from authlog_hunter.parser import parse_line, parse_lines
from authlog_hunter.report import to_navigator_layer

ROOT = Path(__file__).resolve().parents[1]
SAMPLE = ROOT / "samples" / "auth.log"


def _ssh_fail(ts: datetime, user: str, ip: str, invalid: bool = False) -> str:
    inv = "invalid user " if invalid else ""
    return f"{ts:%b} {ts.day:2d} {ts:%H:%M:%S} host sshd[1]: Failed password for {inv}{user} from {ip} port 4242 ssh2"


class ParserTests(unittest.TestCase):
    def test_bsd_failed_password(self):
        ev = parse_line(
            "Oct  2 10:15:01 srv sshd[812]: Failed password for invalid user admin from 203.0.113.5 port 52314 ssh2",
            year=2026,
        )
        self.assertEqual(ev.kind, "ssh_failed")
        self.assertEqual(ev.user, "admin")
        self.assertEqual(ev.src_ip, "203.0.113.5")
        self.assertTrue(ev.extra["invalid_user"])
        self.assertEqual(ev.timestamp, datetime(2026, 10, 2, 10, 15, 1))

    def test_iso_timestamp_and_ipv6(self):
        ev = parse_line(
            "2026-10-22T10:15:01.123456+03:00 srv sshd[812]: Accepted publickey for alice from 2001:db8::1 port 2222 ssh2",
            year=2000,
        )
        self.assertEqual(ev.kind, "ssh_accepted")
        self.assertEqual(ev.src_ip, "2001:db8::1")
        self.assertEqual(ev.timestamp.year, 2026)
        self.assertIsNotNone(ev.timestamp.tzinfo)

    def test_journalctl_short_iso_offset(self):
        ev = parse_line(
            "2026-10-22T10:15:01+0300 srv sshd[812]: Failed password for root from 192.0.2.1 port 22 ssh2",
            year=2000,
        )
        self.assertEqual(ev.timestamp.utcoffset().total_seconds(), 3 * 3600)

    def test_sudo_command(self):
        ev = parse_line(
            "Oct 22 10:20:01 srv sudo:    bob : TTY=pts/0 ; PWD=/home/bob ; USER=root ; COMMAND=/bin/bash -i",
            year=2026,
        )
        self.assertEqual(ev.kind, "sudo_command")
        self.assertEqual(ev.user, "bob")
        self.assertEqual(ev.extra["command"], "/bin/bash -i")

    def test_sudo_not_in_sudoers(self):
        ev = parse_line(
            "Oct 22 10:20:01 srv sudo:    eve : user NOT in sudoers ; TTY=pts/0 ; PWD=/home/eve ; USER=root ; COMMAND=/usr/bin/id",
            year=2026,
        )
        self.assertEqual(ev.kind, "sudo_denied")

    def test_gshadow_duplicate_is_ignored(self):
        self.assertIsNotNone(parse_line("Oct 22 10:20:01 srv usermod[5]: add 'x' to group 'sudo'", year=2026))
        self.assertIsNone(parse_line("Oct 22 10:20:01 srv usermod[5]: add 'x' to shadow group 'sudo'", year=2026))

    def test_irrelevant_lines_are_skipped(self):
        lines = ["garbage", "Oct 22 10:20:01 srv CRON[5]: pam_unix(cron:session): session opened for user root"]
        self.assertEqual(list(parse_lines(lines, year=2026)), [])


class DetectorTests(unittest.TestCase):
    def setUp(self):
        self.t0 = datetime(2026, 10, 22, 12, 0, 0)

    def rules(self, lines, cfg=None):
        return [f.rule_id for f in run_all(parse_lines(lines, year=2026), cfg)]

    def test_brute_force_threshold(self):
        below = [_ssh_fail(self.t0 + timedelta(seconds=i), "root", "203.0.113.9") for i in range(9)]
        self.assertNotIn("AH-001", self.rules(below))
        above = below + [_ssh_fail(self.t0 + timedelta(seconds=10), "root", "203.0.113.9")]
        self.assertIn("AH-001", self.rules(above))

    def test_brute_force_outside_window_is_ignored(self):
        lines = [_ssh_fail(self.t0 + timedelta(minutes=i), "root", "203.0.113.9") for i in range(12)]
        self.assertNotIn("AH-001", self.rules(lines))

    def test_trusted_network_excluded(self):
        lines = [_ssh_fail(self.t0 + timedelta(seconds=i), "root", "10.0.0.5") for i in range(20)]
        self.assertNotIn("AH-001", self.rules(lines, Config(trusted_networks=("10.0.0.0/8",))))

    def test_spraying(self):
        users = ["a", "b", "c", "d", "e"]
        lines = [_ssh_fail(self.t0 + timedelta(seconds=i), u, "198.51.100.1", True) for i, u in enumerate(users)]
        self.assertIn("AH-002", self.rules(lines))

    def test_success_after_failures(self):
        lines = [_ssh_fail(self.t0 + timedelta(seconds=i), "deploy", "203.0.113.7") for i in range(5)]
        lines.append(f"Oct 22 12:01:00 host sshd[1]: Accepted password for deploy from 203.0.113.7 port 1 ssh2")
        self.assertIn("AH-003", self.rules(lines))

    def test_backdoor_chain(self):
        lines = [
            "Oct 22 12:00:00 host useradd[1]: new user: name=svc, UID=999, GID=999, home=/, shell=/bin/bash",
            "Oct 22 12:01:00 host usermod[2]: add 'svc' to group 'wheel'",
        ]
        rules = self.rules(lines)
        self.assertIn("AH-010", rules)
        self.assertIn("AH-009", rules)
        self.assertIn("AH-008", rules)


class EndToEndTests(unittest.TestCase):
    def test_sample_story_is_fully_detected(self):
        findings = run_all(parse_lines(SAMPLE.read_text().splitlines(), year=2026))
        rules = {f.rule_id for f in findings}
        for expected in ["AH-001", "AH-002", "AH-003", "AH-004", "AH-006", "AH-007", "AH-008", "AH-009", "AH-010"]:
            self.assertIn(expected, rules)
        self.assertEqual(findings[0].severity, "critical")

    def test_navigator_layer_is_valid_json(self):
        findings = run_all(parse_lines(SAMPLE.read_text().splitlines(), year=2026))
        layer = json.loads(to_navigator_layer(findings))
        self.assertEqual(layer["domain"], "enterprise-attack")
        self.assertIn("T1110.003", {t["techniqueID"] for t in layer["techniques"]})

    def test_cli_fail_on_exit_code(self):
        proc = subprocess.run(
            [sys.executable, "-m", "authlog_hunter", str(SAMPLE), "--year", "2026", "--format", "json", "--fail-on", "critical"],
            capture_output=True, text=True, cwd=ROOT,
        )
        self.assertEqual(proc.returncode, 3, proc.stderr)
        self.assertEqual(json.loads(proc.stdout)["summary"]["by_severity"]["critical"], 2)


if __name__ == "__main__":
    unittest.main()
