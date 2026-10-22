"""Command line interface."""

from __future__ import annotations

import argparse
import gzip
import sys
from dataclasses import replace
from datetime import timedelta
from pathlib import Path

from . import __version__
from .detectors import SEVERITY_ORDER, Config, run_all
from .parser import parse_lines
from .report import to_html, to_json, to_navigator_layer, to_text


def _open(path: str):
    if path == "-":
        return sys.stdin
    p = Path(path)
    if p.suffix == ".gz":
        return gzip.open(p, "rt", encoding="utf-8", errors="replace")
    return p.open("r", encoding="utf-8", errors="replace")


def build_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(
        prog="authlog-hunter",
        description="Detect attacks in Linux auth logs and map them to MITRE ATT&CK.",
    )
    ap.add_argument("logs", nargs="+", help="auth.log / secure files (.gz supported), '-' for stdin")
    ap.add_argument("--year", type=int, help="year for syslog timestamps without a year (default: current)")
    ap.add_argument("--format", choices=["text", "json"], default="text", help="console output format")
    ap.add_argument("--html", metavar="FILE", help="write a standalone HTML report")
    ap.add_argument("--navigator", metavar="FILE", help="write a MITRE ATT&CK Navigator layer (JSON)")
    ap.add_argument("--min-severity", choices=list(SEVERITY_ORDER), default="low")
    ap.add_argument("--trusted", action="append", default=[], metavar="CIDR",
                    help="trusted network excluded from network-based rules (repeatable)")
    ap.add_argument("--bf-threshold", type=int, default=10, help="failed logins per window for brute force")
    ap.add_argument("--bf-window", type=int, default=5, help="brute force window, minutes")
    ap.add_argument("--no-color", action="store_true")
    ap.add_argument("--fail-on", choices=list(SEVERITY_ORDER),
                    help="exit with code 3 if a finding of this severity or higher exists (for CI/cron)")
    ap.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    return ap


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    cfg = Config(
        brute_force_threshold=args.bf_threshold,
        brute_force_window=timedelta(minutes=args.bf_window),
        trusted_networks=tuple(args.trusted),
    )

    events, raw = [], {}
    offset = 0
    for path in args.logs:
        with _open(path) as fh:
            lines = fh.readlines()
        for ev in parse_lines(lines, year=args.year):
            ev = replace(ev, line_no=ev.line_no + offset)
            events.append(ev)
            raw[ev.line_no] = ev.raw
        offset += len(lines)

    findings = [
        f for f in run_all(events, cfg) if SEVERITY_ORDER[f.severity] >= SEVERITY_ORDER[args.min_severity]
    ]

    if args.format == "json":
        print(to_json(findings, len(events)))
    else:
        print(to_text(findings, len(events), color=not args.no_color and sys.stdout.isatty()))

    if args.html:
        Path(args.html).write_text(to_html(findings, len(events), ", ".join(args.logs), raw), encoding="utf-8")
        print(f"HTML report written to {args.html}", file=sys.stderr)
    if args.navigator:
        Path(args.navigator).write_text(to_navigator_layer(findings), encoding="utf-8")
        print(f"ATT&CK Navigator layer written to {args.navigator}", file=sys.stderr)

    if args.fail_on and any(SEVERITY_ORDER[f.severity] >= SEVERITY_ORDER[args.fail_on] for f in findings):
        return 3
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
