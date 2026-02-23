from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import fnmatch
import json
from typing import Any


@dataclass(frozen=True)
class Policy:
    ignore_globs: list[str]
    exceptions: dict[str, list[str]]


def load_policy(path: Path | None = None) -> Policy:
    if path is None:
        return Policy(ignore_globs=[], exceptions={})
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return Policy(ignore_globs=[], exceptions={})

    ignore_globs = raw.get("ignore_globs", []) if isinstance(raw, dict) else []
    exceptions_raw = raw.get("exceptions", {}) if isinstance(raw, dict) else {}

    clean_ignore = [g for g in ignore_globs if isinstance(g, str) and g.strip()]
    clean_ex: dict[str, list[str]] = {}
    if isinstance(exceptions_raw, dict):
        for k, v in exceptions_raw.items():
            if isinstance(k, str) and isinstance(v, list):
                clean_ex[k] = [x for x in v if isinstance(x, str) and x.strip()]

    return Policy(ignore_globs=clean_ignore, exceptions=clean_ex)


def path_matches_any(path: Path, patterns: list[str], workspace: Path) -> bool:
    try:
        rel = str(path.relative_to(workspace))
    except Exception:
        rel = str(path)
    rel_posix = rel.replace("\\", "/")
    for pat in patterns:
        if fnmatch.fnmatch(rel_posix, pat):
            return True
    return False


def finding_is_excepted(rule_id: str, evidence: str, patterns: dict[str, list[str]]) -> bool:
    pats = patterns.get(rule_id, [])
    for pat in pats:
        if fnmatch.fnmatch(evidence, f"*{pat}*"):
            return True
    return False
