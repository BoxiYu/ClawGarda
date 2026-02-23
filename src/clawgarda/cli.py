from __future__ import annotations

import argparse
from pathlib import Path
import sys
import json

from .deepscan import findings_to_json as deep_findings_to_json, run_deep_scan
from .fixer import apply_safe_patch, run_fix_safe
from .reporting import (
    compare_findings,
    load_baseline,
    render_markdown_report,
    render_pr_template,
    save_baseline,
    should_fail_on_added_severity,
)
from .scanner import Finding, findings_to_json, findings_to_sarif, run_scan


def _render_table(findings: list[Finding]) -> str:
    if not findings:
        return "No findings."

    headers = ["ID", "Severity", "Confidence", "Title", "Evidence", "Fix"]
    rows = [[f.id, f.severity, f.confidence, f.title, f.evidence, f.fix] for f in findings]
    widths = [len(h) for h in headers]

    for row in rows:
        for idx, cell in enumerate(row):
            widths[idx] = min(max(widths[idx], len(cell)), 80)

    def clip(text: str, width: int) -> str:
        if len(text) <= width:
            return text
        return text[: width - 3] + "..."

    line = " | ".join(headers[i].ljust(widths[i]) for i in range(len(headers)))
    sep = "-+-".join("-" * widths[i] for i in range(len(headers)))
    out = [line, sep]

    for row in rows:
        out.append(" | ".join(clip(row[i], widths[i]).ljust(widths[i]) for i in range(len(row))))

    return "\n".join(out)


def _add_common_scan_args(p: argparse.ArgumentParser) -> None:
    p.add_argument("--workspace", default=".", help="Path to workspace to scan")
    p.add_argument("--allowed-root", default="/Users/ddq/openclaw", help="Expected allowed workspace root")
    p.add_argument("--rules", default=None, help="Path to external JSON rules file")
    p.add_argument("--policy", default=None, help="Path to policy JSON (ignore globs / exceptions)")


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="clawgarda", description="OpenClaw MVP security scanner")
    subparsers = parser.add_subparsers(dest="command", required=True)

    scan = subparsers.add_parser("scan", help="Run workspace security checks")
    _add_common_scan_args(scan)
    scan.add_argument("--json", action="store_true", help="Output findings as JSON (legacy shorthand)")
    scan.add_argument("--format", choices=["table", "json", "sarif"], default="table", help="Output format")

    deep = subparsers.add_parser("deep-scan", help="Run deep scan (logs/artifacts/deps, optional RLM)")
    deep.add_argument("--workspace", default=".", help="Path to workspace to scan")
    deep.add_argument("--format", choices=["table", "json"], default="table", help="Output format")
    deep.add_argument("--use-rlm", action="store_true", help="Enable recursive-llm assisted context analysis")
    deep.add_argument("--rlm-model", default="gpt-5-mini", help="Model name for RLM analysis")

    baseline = subparsers.add_parser("baseline", help="Save or compare scan baselines")
    baseline_sub = baseline.add_subparsers(dest="baseline_command", required=True)

    bsave = baseline_sub.add_parser("save", help="Save current findings as baseline")
    _add_common_scan_args(bsave)
    bsave.add_argument("--path", default=".clawgarda/baseline.json", help="Baseline file path")

    bcmp = baseline_sub.add_parser("compare", help="Compare current scan against baseline")
    _add_common_scan_args(bcmp)
    bcmp.add_argument("--path", default=".clawgarda/baseline.json", help="Baseline file path")
    bcmp.add_argument("--format", choices=["table", "json"], default="table", help="Output format")
    bcmp.add_argument(
        "--fail-on-severity",
        choices=["critical", "high", "medium", "low"],
        default=None,
        help="Fail only when added findings meet/exceed this severity",
    )

    report = subparsers.add_parser("report", help="Generate markdown report")
    _add_common_scan_args(report)
    report.add_argument("--output", default="-", help="Output markdown path, '-' for stdout")
    report.add_argument("--pr-template", action="store_true", help="Render PR template markdown")

    fix = subparsers.add_parser("fix", help="Apply safe low-risk fixes")
    fix_sub = fix.add_subparsers(dest="fix_command", required=True)

    fix_run = fix_sub.add_parser("run", help="Run safe fix workflow")
    _add_common_scan_args(fix_run)
    fix_run.add_argument("--safe", action="store_true", help="Enable safe fix mode")
    fix_run.add_argument("--dry-run", action="store_true", help="Preview only; do not write files")
    fix_run.add_argument("--emit-patch", action="store_true", help="Emit safe patch preview file")
    fix_run.add_argument("--patch-path", default=None, help="Patch output path")

    fix_apply = fix_sub.add_parser("apply", help="Apply safe patch outputs (policy only)")
    fix_apply.add_argument("--workspace", default=".", help="Workspace path")
    fix_apply.add_argument("--patch", required=True, help="Patch file path emitted by fix run")
    fix_apply.add_argument("--no-backup", action="store_true", help="Do not create backup before apply")

    return parser


def _scan_with_args(args: argparse.Namespace) -> tuple[list[Finding], Path]:
    workspace = Path(args.workspace)
    allowed_root = Path(args.allowed_root)
    rules_path = Path(args.rules) if args.rules else None
    policy_path = Path(args.policy) if args.policy else None
    findings = run_scan(workspace, allowed_root, rules_path=rules_path, policy_path=policy_path)
    return findings, workspace


def main(argv: list[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)

    if args.command == "scan":
        output_format = "json" if args.json else args.format
        findings, _ = _scan_with_args(args)
        if output_format == "json":
            print(findings_to_json(findings))
        elif output_format == "sarif":
            print(findings_to_sarif(findings))
        else:
            print(_render_table(findings))
        return 1 if findings else 0

    if args.command == "deep-scan":
        findings = run_deep_scan(
            workspace=Path(args.workspace),
            use_rlm=args.use_rlm,
            rlm_model=args.rlm_model,
        )
        if args.format == "json":
            print(deep_findings_to_json(findings))
        else:
            print(_render_table(findings))
        return 1 if findings else 0

    if args.command == "baseline" and args.baseline_command == "save":
        findings, workspace = _scan_with_args(args)
        out = Path(args.path)
        save_baseline(out, findings, workspace)
        print(f"Saved baseline with {len(findings)} findings: {out}")
        return 0

    if args.command == "baseline" and args.baseline_command == "compare":
        findings, _ = _scan_with_args(args)
        payload = load_baseline(Path(args.path))
        diff = compare_findings(findings, payload)
        if args.format == "json":
            print(json.dumps(diff, indent=2))
        else:
            summary = diff["summary"]
            print("Baseline comparison")
            print(f"current={summary['current_total']} previous={summary['previous_total']} added={summary['added']} removed={summary['removed']}")
            print("added IDs:", ", ".join(sorted({f['id'] for f in diff['added']})) or "none")
            print("removed IDs:", ", ".join(sorted({f['id'] for f in diff['removed']})) or "none")
            if args.fail_on_severity:
                print(f"fail threshold: {args.fail_on_severity}")

        if args.fail_on_severity:
            return 1 if should_fail_on_added_severity(diff, args.fail_on_severity) else 0
        return 1 if diff["summary"]["added"] > 0 else 0

    if args.command == "report":
        findings, workspace = _scan_with_args(args)
        md = render_pr_template(findings, workspace) if args.pr_template else render_markdown_report(findings, workspace)
        if args.output == "-":
            print(md)
        else:
            out = Path(args.output)
            out.parent.mkdir(parents=True, exist_ok=True)
            out.write_text(md, encoding="utf-8")
            print(f"Wrote markdown report: {out}")
        return 1 if findings else 0

    if args.command == "fix" and args.fix_command == "run":
        if not args.safe:
            print("Refusing to run: only --safe mode is implemented.")
            return 2
        findings, workspace = _scan_with_args(args)
        patch_path = Path(args.patch_path) if args.patch_path else None
        plan = run_fix_safe(
            workspace,
            findings,
            dry_run=args.dry_run,
            emit_patch=args.emit_patch,
            patch_path=patch_path,
        )
        mode = "DRY-RUN" if args.dry_run else "APPLY"
        print(f"Fix mode: {mode}")
        for action in plan.actions:
            print(f"- {action}")
        if plan.wrote_files:
            print("Wrote files:")
            for p in plan.wrote_files:
                print(f"  - {p}")
        return 1 if findings else 0

    if args.command == "fix" and args.fix_command == "apply":
        patch = Path(args.patch)
        if not patch.exists():
            print(f"Patch not found: {patch}")
            return 2
        backups = apply_safe_patch(Path(args.workspace), patch, create_backup=not args.no_backup)
        print(f"Applied safe patch actions from: {patch}")
        if backups:
            print("Backups:")
            for b in backups:
                print(f"- {b}")
        return 0

    parser.print_help()
    return 2


if __name__ == "__main__":
    sys.exit(main())
