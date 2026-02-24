from __future__ import annotations

from pathlib import Path
import json
import re
import subprocess
from typing import Iterable

from .scanner import Finding

PATTERNS: list[tuple[str, str, re.Pattern[str], str]] = [
    (
        "CGH-001",
        "high",
        re.compile(r"\b\d{8,10}:[A-Za-z0-9_-]{30,}\b"),
        "Rotate Telegram bot token and load from env/secret manager.",
    ),
    (
        "CGH-002",
        "high",
        re.compile(r"\b(sk-[A-Za-z0-9_-]{20,}|ghp_[A-Za-z0-9]{30,}|xox[baprs]-[A-Za-z0-9-]{20,})\b"),
        "Rotate leaked API token and remove from tracked files.",
    ),
    (
        "CGH-003",
        "high",
        re.compile(r"-----BEGIN (RSA|EC|OPENSSH|PGP) PRIVATE KEY-----"),
        "Remove private key from repository and rotate compromised credentials.",
    ),
]

SKIP_PATH_PATTERNS = [
    ".venv/",
    "node_modules/",
    "__pycache__/",
    "/tests/",
]


def _git_ls_files(workspace: Path) -> list[Path]:
    proc = subprocess.run(
        ["git", "-C", str(workspace), "ls-files"],
        capture_output=True,
        text=True,
        timeout=10,
    )
    if proc.returncode != 0:
        return []
    return [workspace / line for line in proc.stdout.splitlines() if line.strip()]


def _iter_candidate_files(workspace: Path) -> Iterable[Path]:
    tracked = _git_ls_files(workspace)
    if tracked:
        for p in tracked:
            if any(skip in str(p).replace("\\", "/") for skip in SKIP_PATH_PATTERNS):
                continue
            if p.is_file():
                yield p
        return

    for p in workspace.rglob("*"):
        if not p.is_file() or p.is_symlink():
            continue
        if any(skip in str(p).replace("\\", "/") for skip in SKIP_PATH_PATTERNS):
            continue
        yield p


def run_hygiene_secret_scan(workspace: Path) -> list[Finding]:
    workspace = workspace.resolve()
    findings: list[Finding] = []

    for path in _iter_candidate_files(workspace):
        try:
            text = path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue

        for rid, sev, pattern, fix in PATTERNS:
            m = pattern.search(text)
            if not m:
                continue
            snippet = m.group(0)
            masked = snippet[:6] + "..." + snippet[-4:] if len(snippet) > 16 else snippet
            findings.append(
                Finding(
                    id=rid,
                    title="Potential secret in tracked file",
                    severity=sev,
                    confidence="high",
                    evidence=f"{path}: matched `{masked}`",
                    fix=fix,
                )
            )
            break

    uniq: dict[tuple[str, str], Finding] = {}
    for f in findings:
        uniq[(f.id, f.evidence)] = f
    out = list(uniq.values())
    rank = {"critical": 4, "high": 3, "medium": 2, "low": 1}
    out.sort(key=lambda x: rank.get(x.severity, 0), reverse=True)
    return out


def findings_to_json(findings: list[Finding]) -> str:
    return json.dumps([f.as_dict() for f in findings], indent=2)
