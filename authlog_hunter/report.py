"""Output formats: console, JSON, standalone HTML and MITRE ATT&CK Navigator layer."""

from __future__ import annotations

import html
import json
from collections import Counter
from datetime import datetime, timezone
from typing import Sequence

from . import __version__
from .detectors import SEVERITY_ORDER, Finding, attack_url

_COLORS = {"critical": "\033[1;97;41m", "high": "\033[1;31m", "medium": "\033[33m", "low": "\033[36m"}
_RESET = "\033[0m"


def summary(findings: Sequence[Finding], events_total: int) -> dict:
    sev = Counter(f.severity for f in findings)
    return {
        "events_analyzed": events_total,
        "findings": len(findings),
        "by_severity": {k: sev.get(k, 0) for k in ("critical", "high", "medium", "low")},
        "techniques": sorted({f.technique_id for f in findings}),
    }


def to_text(findings: Sequence[Finding], events_total: int, color: bool = True) -> str:
    s = summary(findings, events_total)
    lines = [
        f"authlog-hunter {__version__} | {s['events_analyzed']} security events | {s['findings']} findings",
        "  " + "  ".join(f"{k}: {v}" for k, v in s["by_severity"].items()),
        "",
    ]
    for f in findings:
        tag = f"[{f.severity.upper():8}]"
        if color:
            tag = _COLORS[f.severity] + tag + _RESET
        lines.append(f"{tag} {f.rule_id} {f.title}")
        lines.append(f"           {f.technique_id} {f.technique_name} ({f.tactic})")
        lines.append(f"           {f.first_seen:%Y-%m-%d %H:%M:%S} -> {f.last_seen:%H:%M:%S}  {f.description}")
        lines.append("")
    if not findings:
        lines.append("No suspicious activity detected.")
    return "\n".join(lines)


def to_json(findings: Sequence[Finding], events_total: int) -> str:
    return json.dumps(
        {
            "tool": "authlog-hunter",
            "version": __version__,
            "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "summary": summary(findings, events_total),
            "findings": [f.to_dict() for f in findings],
        },
        indent=2,
        ensure_ascii=False,
    )


def to_navigator_layer(findings: Sequence[Finding], name: str = "authlog-hunter findings") -> str:
    """Build a layer file for https://mitre-attack.github.io/attack-navigator/"""
    per_tech: dict[str, list[Finding]] = {}
    for f in findings:
        per_tech.setdefault(f.technique_id, []).append(f)

    techniques = []
    for tid, fs in sorted(per_tech.items()):
        worst = max(SEVERITY_ORDER[f.severity] for f in fs)
        techniques.append(
            {
                "techniqueID": tid,
                "score": worst,
                "comment": "; ".join(sorted({f"{f.rule_id} {f.title}" for f in fs})),
                "enabled": True,
                "showSubtechniques": True,
            }
        )
    layer = {
        "name": name,
        "versions": {"attack": "15", "navigator": "5.0.0", "layer": "4.5"},
        "domain": "enterprise-attack",
        "description": "Techniques observed in Linux authentication logs. Score: 1=low .. 4=critical.",
        "gradient": {"colors": ["#fff3b0", "#ff9f43", "#e63946"], "minValue": 1, "maxValue": 4},
        "techniques": techniques,
    }
    return json.dumps(layer, indent=2)


_HTML_CSS = """
:root{--bg:#0d1117;--card:#161b22;--border:#30363d;--fg:#e6edf3;--muted:#8b949e;
--critical:#ff4d4f;--high:#ff7b39;--medium:#e3b341;--low:#58a6ff}
*{box-sizing:border-box}body{margin:0;font:15px/1.5 -apple-system,Segoe UI,Roboto,sans-serif;background:var(--bg);color:var(--fg)}
main{max-width:1100px;margin:0 auto;padding:32px 16px}h1{margin:0 0 4px}p.sub{color:var(--muted);margin:0 0 24px}
.tiles{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:12px;margin-bottom:28px}
.tile{background:var(--card);border:1px solid var(--border);border-radius:10px;padding:14px 16px}
.tile b{display:block;font-size:28px}.tile span{color:var(--muted);font-size:13px;text-transform:uppercase;letter-spacing:.04em}
.f{background:var(--card);border:1px solid var(--border);border-left:4px solid var(--sev);border-radius:10px;padding:16px 18px;margin-bottom:12px}
.f h3{margin:0 0 6px;font-size:16px}.badge{display:inline-block;padding:1px 8px;border-radius:999px;font-size:12px;font-weight:700;
background:var(--sev);color:#0d1117;margin-right:8px;text-transform:uppercase}.meta{color:var(--muted);font-size:13px}
a{color:#58a6ff}code{background:#0b0f14;padding:2px 6px;border-radius:6px;font-size:13px}
details{margin-top:8px}summary{cursor:pointer;color:var(--muted);font-size:13px}
"""


def to_html(findings: Sequence[Finding], events_total: int, source: str, raw_lines: dict[int, str]) -> str:
    s = summary(findings, events_total)
    esc = html.escape
    tiles = [("Events", s["events_analyzed"]), ("Findings", s["findings"])] + [
        (k.capitalize(), v) for k, v in s["by_severity"].items()
    ]
    parts = [
        "<!doctype html><html lang=en><head><meta charset=utf-8>",
        "<meta name=viewport content='width=device-width,initial-scale=1'>",
        f"<title>authlog-hunter report</title><style>{_HTML_CSS}</style></head><body><main>",
        "<h1>authlog-hunter report</h1>",
        f"<p class=sub>Source: <code>{esc(source)}</code> &middot; generated "
        f"{datetime.now():%Y-%m-%d %H:%M} &middot; v{__version__}</p>",
        "<div class=tiles>",
        *[f"<div class=tile><span>{esc(k)}</span><b>{v}</b></div>" for k, v in tiles],
        "</div>",
    ]
    if not findings:
        parts.append("<p>No suspicious activity detected.</p>")
    for f in findings:
        evidence = "\n".join(esc(raw_lines.get(n, "")) for n in f.evidence[:50])
        more = f"\n... and {len(f.evidence) - 50} more lines" if len(f.evidence) > 50 else ""
        parts.append(
            f"<div class=f style='--sev:var(--{f.severity})'>"
            f"<h3><span class=badge>{f.severity}</span>{esc(f.rule_id)} &mdash; {esc(f.title)}</h3>"
            f"<div class=meta><a href='{attack_url(f.technique_id)}' target=_blank rel=noopener>"
            f"{f.technique_id} {esc(f.technique_name)}</a> &middot; {esc(f.tactic)} &middot; "
            f"{f.first_seen:%Y-%m-%d %H:%M:%S} &rarr; {f.last_seen:%H:%M:%S}</div>"
            f"<p>{esc(f.description)}</p>"
            f"<details><summary>Evidence ({len(f.evidence)} lines)</summary><pre><code>{evidence}{more}</code></pre></details>"
            "</div>"
        )
    parts.append("</main></body></html>")
    return "\n".join(parts)
