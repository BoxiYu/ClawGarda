from __future__ import annotations

from collections import Counter, defaultdict
import re
from typing import Any

from .scanner import Finding

URL_RE = re.compile(r"https?://[^\s`]+")


def _extract_target(evidence: str) -> str:
    m = URL_RE.search(evidence)
    if m:
        return m.group(0)
    return "unknown"


def summarize_dast_findings(findings: list[Finding]) -> dict[str, Any]:
    by_rule: Counter[str] = Counter()
    by_target: Counter[str] = Counter()
    by_sev: Counter[str] = Counter()

    for f in findings:
        by_rule[f.id] += 1
        by_target[_extract_target(f.evidence)] += 1
        by_sev[f.severity] += 1

    return {
        "total": len(findings),
        "by_rule": dict(by_rule),
        "by_severity": dict(by_sev),
        "targets": [{"target": t, "count": c} for t, c in by_target.most_common(20)],
    }


def render_dast_summary_markdown(summary: dict[str, Any]) -> str:
    lines = [
        "# ClawGarda DAST Summary",
        "",
        f"- Total findings: **{summary.get('total', 0)}**",
        "",
        "## Severity breakdown",
        "",
        "| Severity | Count |",
        "|---|---:|",
    ]

    for sev, cnt in sorted(summary.get("by_severity", {}).items()):
        lines.append(f"| {sev} | {cnt} |")

    lines.extend([
        "",
        "## Rule breakdown",
        "",
        "| Rule | Count |",
        "|---|---:|",
    ])
    for rid, cnt in sorted(summary.get("by_rule", {}).items()):
        lines.append(f"| {rid} | {cnt} |")

    lines.extend([
        "",
        "## Target hotspots",
        "",
        "| Target | Findings |",
        "|---|---:|",
    ])
    for item in summary.get("targets", []):
        lines.append(f"| {item['target']} | {item['count']} |")

    return "\n".join(lines)
