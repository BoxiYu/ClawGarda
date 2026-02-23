from __future__ import annotations

from pathlib import Path
import json
import re
from typing import Any

from .scanner import Finding

MAX_DEEP_FILES = 400
MAX_DEEP_FILE_SIZE = 2_000_000

LOG_PATTERNS: list[tuple[str, str, str, str]] = [
    ("CGD-001", "high", r"(?i)pairing required", "Gateway pairing/auth failures observed in logs."),
    ("CGD-002", "high", r"(?i)401\s+unauthorized|getme failed", "Auth failures detected (possibly revoked/invalid token)."),
    ("CGD-003", "medium", r"(?i)gateway connect failed|websocket.*closed", "Gateway connectivity instability detected."),
    ("CGD-004", "high", r"(?i)exec\.approvals\.set\s*=\s*off|tools\.exec\.host\s*=\s*gateway", "Potentially dangerous exec policy change detected in logs."),
]

SECRET_PATTERNS: list[tuple[str, str, str, str]] = [
    ("CGD-010", "high", r"\b\d{8,10}:[A-Za-z0-9_-]{30,}\b", "Token-like value appears in runtime artifacts/logs."),
    ("CGD-011", "high", r"(?i)(openai|anthropic|gemini|google)_api_key\s*[=:]\s*\S+", "API key assignment string appears in artifacts/logs."),
]


def _iter_files(workspace: Path) -> list[Path]:
    out: list[Path] = []
    for p in workspace.rglob("*"):
        if len(out) >= MAX_DEEP_FILES:
            break
        if not p.is_file() or p.is_symlink():
            continue
        if p.suffix.lower() not in {".log", ".jsonl", ".txt", ".md", ".json"}:
            continue
        try:
            if p.stat().st_size > MAX_DEEP_FILE_SIZE:
                continue
        except OSError:
            continue
        out.append(p)
    return out


def _scan_file_text(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return ""


def _make(rule_id: str, title: str, severity: str, evidence: str, fix: str, confidence: str = "medium") -> Finding:
    return Finding(
        id=rule_id,
        title=title,
        severity=severity,
        confidence=confidence,
        evidence=evidence,
        fix=fix,
    )


def run_deep_scan(workspace: Path, use_rlm: bool = False, rlm_model: str = "gpt-5-mini") -> list[Finding]:
    workspace = workspace.resolve()
    findings: list[Finding] = []

    files = _iter_files(workspace)
    for path in files:
        text = _scan_file_text(path)
        if not text:
            continue

        for rid, sev, pat, title in LOG_PATTERNS:
            if re.search(pat, text):
                findings.append(
                    _make(
                        rid,
                        title,
                        sev,
                        f"{path}: matched pattern `{pat}`",
                        "Investigate log context and harden gateway auth/network policy.",
                        confidence="high",
                    )
                )

        for rid, sev, pat, title in SECRET_PATTERNS:
            if re.search(pat, text):
                findings.append(
                    _make(
                        rid,
                        title,
                        sev,
                        f"{path}: matched sensitive pattern `{pat}`",
                        "Remove/rotate exposed credentials and avoid logging secrets.",
                        confidence="medium",
                    )
                )

    # Dependency hygiene signals
    package_json = workspace / "package.json"
    pyproject = workspace / "pyproject.toml"
    npm_lock = workspace / "package-lock.json"
    uv_lock = workspace / "uv.lock"

    if package_json.exists() and not npm_lock.exists():
        findings.append(
            _make(
                "CGD-020",
                "Node dependency lockfile missing",
                "medium",
                f"{package_json} exists but package-lock.json is missing",
                "Add and commit lockfile for reproducible dependency resolution.",
            )
        )
    if pyproject.exists() and not uv_lock.exists():
        findings.append(
            _make(
                "CGD-021",
                "Python lockfile missing",
                "low",
                f"{pyproject} exists but uv.lock is missing",
                "Consider lockfile pinning for reproducible builds.",
                confidence="low",
            )
        )

    # Optional RLM context analyzer (best-effort, non-blocking)
    if use_rlm:
        try:
            from rlm import RLM  # type: ignore

            context_fragments: list[str] = []
            for p in files[:40]:
                txt = _scan_file_text(p)
                if txt:
                    context_fragments.append(f"\n\n# FILE: {p}\n{txt[:2000]}")
            context = "".join(context_fragments)[:120_000]
            if context.strip():
                rlm = RLM(model=rlm_model)
                summary = rlm.complete(
                    query=(
                        "Find latent security risks, suspicious auth patterns, and secret-leak traces. "
                        "Return concise bullet points."
                    ),
                    context=context,
                )
                if isinstance(summary, str) and summary.strip():
                    findings.append(
                        _make(
                            "CGD-900",
                            "RLM deep-context advisory",
                            "low",
                            "RLM generated additional advisory context",
                            summary.strip()[:800],
                            confidence="low",
                        )
                    )
        except Exception as exc:  # best effort only
            findings.append(
                _make(
                    "CGD-901",
                    "RLM analysis skipped",
                    "low",
                    f"RLM unavailable or failed: {exc}",
                    "Install recursive-llm and provider keys, then rerun with --use-rlm.",
                    confidence="low",
                )
            )

    # de-dup by tuple
    uniq: dict[tuple[str, str], Finding] = {}
    for f in findings:
        uniq[(f.id, f.evidence)] = f

    sev_rank = {"critical": 4, "high": 3, "medium": 2, "low": 1}
    out = list(uniq.values())
    out.sort(key=lambda x: sev_rank.get(x.severity, 0), reverse=True)
    return out


def findings_to_json(findings: list[Finding]) -> str:
    return json.dumps([f.as_dict() for f in findings], indent=2)
