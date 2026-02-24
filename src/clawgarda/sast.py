from __future__ import annotations

from pathlib import Path
import re
from typing import Iterable

from .scanner import Finding

MAX_FILES = 600
MAX_FILE_SIZE = 1_500_000

RULES: list[tuple[str, str, str, re.Pattern[str], str]] = [
    (
        "CGS-001",
        "high",
        "Python subprocess shell=True",
        re.compile(r"subprocess\.(run|Popen|call|check_output|check_call)\([^\n]{0,220}shell\s*=\s*True"),
        "Avoid shell=True for untrusted input; use argument arrays and strict validation.",
    ),
    (
        "CGS-002",
        "high",
        "Python eval/exec usage",
        re.compile(r"\b(eval|exec)\s*\("),
        "Remove eval/exec on untrusted input; use safe parsers/interpreters.",
    ),
    (
        "CGS-003",
        "high",
        "Node child_process exec usage",
        re.compile(r"child_process\.(exec|execSync)\s*\("),
        "Prefer spawn/execFile with fixed argv; sanitize all user-controlled segments.",
    ),
    (
        "CGS-004",
        "medium",
        "Insecure temporary file handling",
        re.compile(r"mktemp\(|tempfile\.mktemp\("),
        "Use secure tempfile APIs (NamedTemporaryFile/mkdtemp) with restrictive permissions.",
    ),
    (
        "CGS-005",
        "high",
        "Potential hardcoded private key",
        re.compile(r"-----BEGIN (RSA|EC|OPENSSH|PGP) PRIVATE KEY-----"),
        "Remove private keys from source; rotate compromised credentials immediately.",
    ),
    (
        "CGS-006",
        "high",
        "Potential hardcoded API token",
        re.compile(r"\b(sk-[A-Za-z0-9_-]{20,}|ghp_[A-Za-z0-9]{30,}|xox[baprs]-[A-Za-z0-9-]{20,})\b"),
        "Move secrets to env/secret manager and rotate leaked tokens.",
    ),
    (
        "CGS-007",
        "medium",
        "Flask debug mode enabled",
        re.compile(r"app\.run\([^\n]{0,150}debug\s*=\s*True"),
        "Disable debug mode in production and gate by environment.",
    ),
    (
        "CGS-008",
        "medium",
        "Binding service to all interfaces",
        re.compile(r"(host\s*=\s*[\"']0\.0\.0\.0[\"']|--host\s+0\.0\.0\.0)"),
        "Prefer loopback bind and front with controlled ingress.",
    ),
    (
        "CGS-009",
        "high",
        "CORS wildcard with credentials",
        re.compile(r"Access-Control-Allow-Origin\s*[:=]\s*\*|cors\([^\n]{0,160}credentials\s*[:=]\s*true"),
        "Do not combine wildcard origins with credentials; use explicit allowlists.",
    ),
    (
        "CGS-010",
        "medium",
        "Potential SQL string concatenation",
        re.compile(r"(SELECT|INSERT|UPDATE|DELETE)[^\n]{0,120}(\+\s*\w+|f\"|format\()", re.IGNORECASE),
        "Use parameterized queries/prepared statements.",
    ),
]

EXTENSIONS = {".py", ".ts", ".tsx", ".js", ".jsx", ".sh"}
EXCLUDE = {".git", "node_modules", "dist", "build", "__pycache__", ".venv", "venv"}


def _iter_files(workspace: Path) -> Iterable[Path]:
    count = 0
    for p in workspace.rglob("*"):
        if count >= MAX_FILES:
            break
        if any(part in EXCLUDE for part in p.parts):
            continue
        if not p.is_file() or p.is_symlink():
            continue
        if p.suffix.lower() not in EXTENSIONS:
            continue
        try:
            if p.stat().st_size > MAX_FILE_SIZE:
                continue
        except OSError:
            continue
        count += 1
        yield p


def run_sast_scan(workspace: Path) -> list[Finding]:
    workspace = workspace.resolve()
    findings: list[Finding] = []

    for path in _iter_files(workspace):
        try:
            text = path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue

        for rid, severity, title, pattern, fix in RULES:
            for m in pattern.finditer(text):
                start = max(0, m.start() - 30)
                end = min(len(text), m.end() + 30)
                snippet = text[start:end].replace("\n", " ").strip()
                findings.append(
                    Finding(
                        id=rid,
                        title=title,
                        severity=severity,
                        confidence="medium",
                        evidence=f"{path}: `{snippet[:160]}`",
                        fix=fix,
                    )
                )
                break

    # dedup
    uniq: dict[tuple[str, str], Finding] = {}
    for f in findings:
        uniq[(f.id, f.evidence)] = f
    out = list(uniq.values())
    rank = {"critical": 4, "high": 3, "medium": 2, "low": 1}
    out.sort(key=lambda x: rank.get(x.severity, 0), reverse=True)
    return out
