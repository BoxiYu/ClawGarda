from __future__ import annotations

import argparse
from pathlib import Path
import sys

from .scanner import Finding, findings_to_json, run_scan


def _render_table(findings: list[Finding]) -> str:
    if not findings:
        return "No findings."

    headers = ["ID", "Severity", "Title", "Evidence", "Fix"]
    rows = [[f.id, f.severity, f.title, f.evidence, f.fix] for f in findings]
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


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="clawgarda", description="OpenClaw MVP security scanner")
    subparsers = parser.add_subparsers(dest="command", required=True)

    scan = subparsers.add_parser("scan", help="Run workspace security checks")
    scan.add_argument("--workspace", default=".", help="Path to workspace to scan")
    scan.add_argument("--allowed-root", default="/Users/ddq/openclaw", help="Expected allowed workspace root")
    scan.add_argument("--json", action="store_true", help="Output findings as JSON")
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)

    if args.command == "scan":
        findings = run_scan(Path(args.workspace), Path(args.allowed_root))
        if args.json:
            print(findings_to_json(findings))
        else:
            print(_render_table(findings))
        return 1 if findings else 0

    parser.print_help()
    return 2


if __name__ == "__main__":
    sys.exit(main())
