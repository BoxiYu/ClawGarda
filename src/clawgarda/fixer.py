from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Iterable
import json

from .scanner import Finding

DEFAULT_POLICY = {
    "ignore_globs": [
        "projects/adk-python/contributing/samples/**",
        "projects/nanoclaw/.claude/skills/**",
    ],
    "exceptions": {"CGA-006": ["sample", "example"]},
}


@dataclass(frozen=True)
class FixPlan:
    actions: list[str]
    wrote_files: list[Path]


def _remediation_markdown(findings: Iterable[Finding], workspace: Path) -> str:
    lines = [
        "# ClawGarda Safe Fix Plan",
        "",
        f"Workspace: `{workspace.resolve()}`",
        "",
        "## Proposed low-risk actions",
        "- Add/update policy file for noisy sample paths",
        "- Keep config secrets unchanged (no mutation of openclaw.json)",
        "",
        "## Findings summary",
    ]
    findings = list(findings)
    if not findings:
        lines.append("- No findings")
    else:
        for f in findings[:50]:
            lines.append(f"- [{f.severity.upper()}] {f.id}: {f.title}")
    lines.append("")
    return "\n".join(lines)


def run_fix_safe(workspace: Path, findings: list[Finding], dry_run: bool = True) -> FixPlan:
    workspace = workspace.resolve()
    policy_path = workspace / ".clawgarda" / "policy.json"
    plan_path = workspace / ".clawgarda" / "remediation-plan.md"

    actions: list[str] = []
    wrote: list[Path] = []

    if not policy_path.exists():
        actions.append(f"Create policy file: {policy_path}")
        if not dry_run:
            policy_path.parent.mkdir(parents=True, exist_ok=True)
            policy_path.write_text(json.dumps(DEFAULT_POLICY, indent=2), encoding="utf-8")
            wrote.append(policy_path)
    else:
        actions.append(f"Policy already exists: {policy_path}")

    actions.append(f"Create remediation preview: {plan_path}")
    if not dry_run:
        plan_path.parent.mkdir(parents=True, exist_ok=True)
        plan_path.write_text(_remediation_markdown(findings, workspace), encoding="utf-8")
        wrote.append(plan_path)

    return FixPlan(actions=actions, wrote_files=wrote)
