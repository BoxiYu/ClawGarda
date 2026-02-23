from __future__ import annotations

from collections import defaultdict
from pathlib import Path
import json
from typing import Any

from .scanner import Finding

PRIORITY_BY_SEVERITY = {
    "critical": "P0",
    "high": "P1",
    "medium": "P2",
    "low": "P3",
}


def load_findings_json(path: Path) -> list[Finding]:
    raw = json.loads(path.read_text(encoding="utf-8"))
    findings: list[Finding] = []
    if isinstance(raw, list):
        for item in raw:
            if isinstance(item, dict):
                findings.append(Finding(**item))
    return findings


def render_plan_markdown(findings: list[Finding], workspace: Path) -> str:
    grouped: dict[str, list[Finding]] = defaultdict(list)
    for f in findings:
        grouped[f.id].append(f)

    ordered = sorted(
        grouped.items(),
        key=lambda kv: (PRIORITY_BY_SEVERITY.get(kv[1][0].severity, "P9"), kv[0]),
    )

    lines = [
        "# ClawGarda Copilot Plan",
        "",
        f"Workspace: `{workspace.resolve()}`",
        f"Total findings: **{len(findings)}**",
        "",
        "## Prioritized remediation roadmap",
    ]

    if not findings:
        lines.append("- No findings. ✅")
        return "\n".join(lines)

    for rid, items in ordered:
        top = items[0]
        priority = PRIORITY_BY_SEVERITY.get(top.severity, "P3")
        lines.extend(
            [
                "",
                f"### {priority} · {rid} — {top.title}",
                f"- Severity: **{top.severity}**",
                f"- Confidence: **{top.confidence}**",
                f"- Instances: **{len(items)}**",
                f"- Recommended action: {top.fix}",
                "- Owner: _(assign)_",
                "- ETA: _(set)_",
            ]
        )

    lines.extend(
        [
            "",
            "## Validation checklist",
            "- [ ] Re-run `clawgarda scan` and confirm reduced findings",
            "- [ ] Re-run `clawgarda baseline compare`",
            "- [ ] Update PR_BODY.md with changes",
        ]
    )

    return "\n".join(lines)
