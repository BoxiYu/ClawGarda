from __future__ import annotations

import argparse
from pathlib import Path
import sys
import json

from .copilot import load_findings_json, render_plan_markdown
from .deepscan import findings_to_json as deep_findings_to_json, run_deep_scan
from .fixer import apply_safe_patch, run_fix_safe
from .sast import run_sast_scan
from .sast_reporting import render_sast_summary_markdown, summarize_sast_findings
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

    sast = subparsers.add_parser("sast", help="Run static code security scan")
    sast_sub = sast.add_subparsers(dest="sast_command", required=True)

    sast_scan = sast_sub.add_parser("scan", help="Run SAST rules")
    sast_scan.add_argument("--workspace", default=".", help="Workspace path")
    sast_scan.add_argument("--format", choices=["table", "json"], default="table", help="Output format")
    sast_scan.add_argument("--exclude-glob", action="append", default=None, help="Exclude path glob (repeatable)")

    sast_base = sast_sub.add_parser("baseline", help="Save or compare SAST baseline")
    sast_base_sub = sast_base.add_subparsers(dest="sast_baseline_command", required=True)

    ssave = sast_base_sub.add_parser("save", help="Save SAST baseline")
    ssave.add_argument("--workspace", default=".", help="Workspace path")
    ssave.add_argument("--path", default=".clawgarda/sast-baseline.json", help="Baseline file path")
    ssave.add_argument("--exclude-glob", action="append", default=None, help="Exclude path glob (repeatable)")

    scmp = sast_base_sub.add_parser("compare", help="Compare SAST against baseline")
    scmp.add_argument("--workspace", default=".", help="Workspace path")
    scmp.add_argument("--path", default=".clawgarda/sast-baseline.json", help="Baseline file path")
    scmp.add_argument("--format", choices=["table", "json"], default="table", help="Output format")
    scmp.add_argument("--fail-on-severity", choices=["critical", "high", "medium", "low"], default=None, help="Fail only when added findings meet/exceed this severity")
    scmp.add_argument("--exclude-glob", action="append", default=None, help="Exclude path glob (repeatable)")

    ssum = sast_sub.add_parser("summary", help="Summarize SAST findings and hotspots")
    ssum.add_argument("--workspace", default=".", help="Workspace path")
    ssum.add_argument("--exclude-glob", action="append", default=None, help="Exclude path glob (repeatable)")
    ssum.add_argument("--format", choices=["markdown", "json"], default="markdown", help="Output format")
    ssum.add_argument("--output", default="-", help="Output path, '-' for stdout")

    deep = subparsers.add_parser("deep-scan", help="Run deep scan (logs/artifacts/deps, optional RLM)")
    deep.add_argument("--workspace", default=".", help="Path to workspace to scan")
    deep.add_argument("--format", choices=["table", "json"], default="table", help="Output format")
    deep.add_argument("--use-rlm", action="store_true", help="Enable recursive-llm assisted context analysis")
    deep.add_argument("--rlm-model", default="gpt-5-mini", help="Model name for RLM analysis")
    deep.add_argument(
        "--exclude-glob",
        action="append",
        default=None,
        help="Exclude path glob for deep scan (repeatable)",
    )

    deep_baseline = subparsers.add_parser("deep-baseline", help="Save or compare deep-scan baselines")
    deep_base_sub = deep_baseline.add_subparsers(dest="deep_baseline_command", required=True)

    dbsave = deep_base_sub.add_parser("save", help="Save deep-scan baseline")
    dbsave.add_argument("--workspace", default=".", help="Workspace path")
    dbsave.add_argument("--path", default=".clawgarda/deep-baseline.json", help="Baseline file path")
    dbsave.add_argument("--use-rlm", action="store_true", help="Enable recursive-llm assisted context analysis")
    dbsave.add_argument("--rlm-model", default="gpt-5-mini", help="Model name for RLM analysis")
    dbsave.add_argument("--exclude-glob", action="append", default=None, help="Exclude path glob (repeatable)")

    dbcmp = deep_base_sub.add_parser("compare", help="Compare deep-scan against baseline")
    dbcmp.add_argument("--workspace", default=".", help="Workspace path")
    dbcmp.add_argument("--path", default=".clawgarda/deep-baseline.json", help="Baseline file path")
    dbcmp.add_argument("--format", choices=["table", "json"], default="table", help="Output format")
    dbcmp.add_argument("--fail-on-severity", choices=["critical", "high", "medium", "low"], default=None, help="Fail only when added findings meet/exceed this severity")
    dbcmp.add_argument("--use-rlm", action="store_true", help="Enable recursive-llm assisted context analysis")
    dbcmp.add_argument("--rlm-model", default="gpt-5-mini", help="Model name for RLM analysis")
    dbcmp.add_argument("--exclude-glob", action="append", default=None, help="Exclude path glob (repeatable)")

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

    copilot = subparsers.add_parser("copilot", help="Copilot planning helpers")
    copilot_sub = copilot.add_subparsers(dest="copilot_command", required=True)

    cplan = copilot_sub.add_parser("plan", help="Generate prioritized remediation plan")
    _add_common_scan_args(cplan)
    cplan.add_argument("--from-json", default=None, help="Use existing findings JSON instead of running scan")
    cplan.add_argument("--output", default="-", help="Output markdown path, '-' for stdout")

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

    if args.command == "sast" and args.sast_command == "scan":
        findings = run_sast_scan(Path(args.workspace), exclude_globs=args.exclude_glob)
        if args.format == "json":
            print(findings_to_json(findings))
        else:
            print(_render_table(findings))
        return 1 if findings else 0

    if args.command == "sast" and args.sast_command == "summary":
        findings = run_sast_scan(Path(args.workspace), exclude_globs=args.exclude_glob)
        summary = summarize_sast_findings(findings)
        if args.format == "json":
            content = json.dumps(summary, indent=2)
        else:
            content = render_sast_summary_markdown(summary)

        if args.output == "-":
            print(content)
        else:
            out = Path(args.output)
            out.parent.mkdir(parents=True, exist_ok=True)
            out.write_text(content, encoding="utf-8")
            print(f"Wrote SAST summary: {out}")
        return 1 if findings else 0

    if args.command == "sast" and args.sast_command == "baseline" and args.sast_baseline_command == "save":
        workspace = Path(args.workspace)
        findings = run_sast_scan(workspace, exclude_globs=args.exclude_glob)
        out = Path(args.path)
        save_baseline(out, findings, workspace)
        print(f"Saved SAST baseline with {len(findings)} findings: {out}")
        return 0

    if args.command == "sast" and args.sast_command == "baseline" and args.sast_baseline_command == "compare":
        workspace = Path(args.workspace)
        findings = run_sast_scan(workspace, exclude_globs=args.exclude_glob)
        payload = load_baseline(Path(args.path))
        diff = compare_findings(findings, payload)
        if args.format == "json":
            print(json.dumps(diff, indent=2))
        else:
            summary = diff["summary"]
            print("SAST baseline comparison")
            print(f"current={summary['current_total']} previous={summary['previous_total']} added={summary['added']} removed={summary['removed']}")
            print("added IDs:", ", ".join(sorted({f['id'] for f in diff['added']})) or "none")
            print("removed IDs:", ", ".join(sorted({f['id'] for f in diff['removed']})) or "none")
            if args.fail_on_severity:
                print(f"fail threshold: {args.fail_on_severity}")
        if args.fail_on_severity:
            return 1 if should_fail_on_added_severity(diff, args.fail_on_severity) else 0
        return 1 if diff["summary"]["added"] > 0 else 0

    if args.command == "deep-scan":
        findings = run_deep_scan(
            workspace=Path(args.workspace),
            use_rlm=args.use_rlm,
            rlm_model=args.rlm_model,
            exclude_globs=args.exclude_glob,
        )
        if args.format == "json":
            print(deep_findings_to_json(findings))
        else:
            print(_render_table(findings))
        return 1 if findings else 0

    if args.command == "deep-baseline" and args.deep_baseline_command == "save":
        workspace = Path(args.workspace)
        findings = run_deep_scan(
            workspace=workspace,
            use_rlm=args.use_rlm,
            rlm_model=args.rlm_model,
            exclude_globs=args.exclude_glob,
        )
        out = Path(args.path)
        save_baseline(out, findings, workspace)
        print(f"Saved deep baseline with {len(findings)} findings: {out}")
        return 0

    if args.command == "deep-baseline" and args.deep_baseline_command == "compare":
        workspace = Path(args.workspace)
        findings = run_deep_scan(
            workspace=workspace,
            use_rlm=args.use_rlm,
            rlm_model=args.rlm_model,
            exclude_globs=args.exclude_glob,
        )
        payload = load_baseline(Path(args.path))
        diff = compare_findings(findings, payload)
        if args.format == "json":
            print(json.dumps(diff, indent=2))
        else:
            summary = diff["summary"]
            print("Deep baseline comparison")
            print(f"current={summary['current_total']} previous={summary['previous_total']} added={summary['added']} removed={summary['removed']}")
            print("added IDs:", ", ".join(sorted({f['id'] for f in diff['added']})) or "none")
            print("removed IDs:", ", ".join(sorted({f['id'] for f in diff['removed']})) or "none")
            if args.fail_on_severity:
                print(f"fail threshold: {args.fail_on_severity}")

        if args.fail_on_severity:
            return 1 if should_fail_on_added_severity(diff, args.fail_on_severity) else 0
        return 1 if diff["summary"]["added"] > 0 else 0

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

    if args.command == "copilot" and args.copilot_command == "plan":
        if args.from_json:
            findings = load_findings_json(Path(args.from_json))
            workspace = Path(args.workspace)
        else:
            findings, workspace = _scan_with_args(args)

        md = render_plan_markdown(findings, workspace)
        if args.output == "-":
            print(md)
        else:
            out = Path(args.output)
            out.parent.mkdir(parents=True, exist_ok=True)
            out.write_text(md, encoding="utf-8")
            print(f"Wrote copilot plan: {out}")
        return 1 if findings else 0

    parser.print_help()
    return 2


if __name__ == "__main__":
    sys.exit(main())
