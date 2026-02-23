from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Iterable
import difflib
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
    patch_file: Path | None = None


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


def _build_policy_patch(workspace: Path, policy_path: Path) -> tuple[str, str, str]:
    old_text = policy_path.read_text(encoding="utf-8") if policy_path.exists() else ""
    new_text = old_text if old_text else json.dumps(DEFAULT_POLICY, indent=2) + "\n"

    old_lines = old_text.splitlines(keepends=True)
    new_lines = new_text.splitlines(keepends=True)
    rel = str(policy_path.relative_to(workspace))
    patch = "".join(
        difflib.unified_diff(
            old_lines,
            new_lines,
            fromfile=f"a/{rel}",
            tofile=f"b/{rel}",
        )
    )
    return old_text, new_text, patch


def emit_safe_patch(workspace: Path, findings: list[Finding], patch_path: Path) -> Path:
    workspace = workspace.resolve()
    policy_path = workspace / ".clawgarda" / "policy.json"
    _, _, policy_patch = _build_policy_patch(workspace, policy_path)

    # Add guidance section for openclaw token externalization without mutating secrets.
    guidance = [
        "\n# --- CLAWGARDA GUIDANCE (NO SECRET MUTATION) ---\n",
        "# Suggested manual remediation:\n",
        "# 1) Move bot tokens from openclaw.json into environment variables or secret manager\n",
        "# 2) Reference secret placeholders in config\n",
    ]

    report_preview = _remediation_markdown(findings, workspace)
    text = "".join([
        "# ClawGarda safe patch (preview)\n",
        f"# Generated at: {datetime.now(UTC).isoformat()}\n\n",
        policy_patch or "# No policy diff needed\n",
        "\n",
        "# Remediation preview\n",
        report_preview,
        "\n",
        *guidance,
    ])

    patch_path.parent.mkdir(parents=True, exist_ok=True)
    patch_path.write_text(text, encoding="utf-8")
    return patch_path


def apply_safe_patch(workspace: Path, patch_path: Path, create_backup: bool = True) -> list[Path]:
    workspace = workspace.resolve()
    policy_path = workspace / ".clawgarda" / "policy.json"
    backup_files: list[Path] = []

    if create_backup and policy_path.exists():
        backup = workspace / ".clawgarda" / f"policy.json.bak.{datetime.now(UTC).strftime('%Y%m%d%H%M%S')}"
        backup.write_text(policy_path.read_text(encoding="utf-8"), encoding="utf-8")
        backup_files.append(backup)

    if not policy_path.exists():
        policy_path.parent.mkdir(parents=True, exist_ok=True)
        policy_path.write_text(json.dumps(DEFAULT_POLICY, indent=2) + "\n", encoding="utf-8")

    return backup_files


def run_fix_safe(
    workspace: Path,
    findings: list[Finding],
    dry_run: bool = True,
    emit_patch: bool = False,
    patch_path: Path | None = None,
) -> FixPlan:
    workspace = workspace.resolve()
    policy_path = workspace / ".clawgarda" / "policy.json"
    plan_path = workspace / ".clawgarda" / "remediation-plan.md"

    actions: list[str] = []
    wrote: list[Path] = []
    patch_file: Path | None = None

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

    if emit_patch:
        patch_file = patch_path or (workspace / ".clawgarda" / "safe-fix.patch")
        actions.append(f"Emit patch preview: {patch_file}")
        patch_file = emit_safe_patch(workspace, findings, patch_file)
        wrote.append(patch_file)

    return FixPlan(actions=actions, wrote_files=wrote, patch_file=patch_file)
