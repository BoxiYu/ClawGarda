from __future__ import annotations

from collections import Counter, defaultdict
import re
from typing import Any

from .scanner import Finding

PATH_RE = re.compile(r"^(.+?):\s*`")


def _extract_path(evidence: str) -> str:
    m = PATH_RE.match(evidence)
    if m:
        return m.group(1)
    return "unknown"


def summarize_sast_findings(findings: list[Finding], top_n: int = 10) -> dict[str, Any]:
    by_rule: dict[str, Counter[str]] = defaultdict(Counter)
    by_file: Counter[str] = Counter()
    for f in findings:
        by_rule[f.id][f.severity] += 1
        by_file[_extract_path(f.evidence)] += 1

    rule_summary = []
    for rid, counter in sorted(by_rule.items()):
        total = sum(counter.values())
        sev = ", ".join(f"{k}:{v}" for k, v in counter.items())
        rule_summary.append({"id": rid, "total": total, "severity_mix": sev})

    hotspots = [{"path": p, "count": c} for p, c in by_file.most_common(top_n)]

    return {
        "total": len(findings),
        "rules": rule_summary,
        "hotspots": hotspots,
    }


def render_sast_summary_markdown(summary: dict[str, Any]) -> str:
    lines = [
        "# ClawGarda SAST Summary",
        "",
        f"- Total findings: **{summary.get('total', 0)}**",
        "",
        "## Rule breakdown",
        "",
        "| Rule | Total | Severity mix |",
        "|---|---:|---|",
    ]

    for r in summary.get("rules", []):
        lines.append(f"| {r['id']} | {r['total']} | {r['severity_mix']} |")

    lines.extend([
        "",
        "## Top hotspot files",
        "",
        "| File | Findings |",
        "|---|---:|",
    ])
    for h in summary.get("hotspots", []):
        lines.append(f"| {h['path']} | {h['count']} |")

    return "\n".join(lines)
