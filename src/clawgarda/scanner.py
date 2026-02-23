from __future__ import annotations

from dataclasses import asdict, dataclass
import importlib.resources as resources
from pathlib import Path
import json
import re
import socket
from typing import Any

from .policy import Policy, finding_is_excepted, load_policy, path_matches_any

MAX_FILES = 200
MAX_FILE_SIZE_BYTES = 1_000_000
DEFAULT_ALLOWED_WORKSPACE = Path("/Users/ddq/openclaw")
DEFAULT_GATEWAY_PORT = 3000

SEVERITY_SCORE = {
    "critical": 10,
    "high": 8,
    "medium": 5,
    "low": 2,
}

SARIF_LEVEL_MAP = {
    "critical": "error",
    "high": "error",
    "medium": "warning",
    "low": "note",
}

TELEGRAM_TOKEN_PATTERN = re.compile(r"\b\d{8,10}:[A-Za-z0-9_-]{30,}\b")
PLAINTEXT_SECRET_PATTERNS = [
    re.compile(r"(?i)(api[_-]?key|secret|token|password)\s*[:=]\s*[\"']?[A-Za-z0-9_\-./+=]{12,}[\"']?"),
    re.compile(r"AKIA[0-9A-Z]{16}"),
    re.compile(r"(?i)-----BEGIN (RSA|EC|OPENSSH|PGP) PRIVATE KEY-----"),
]


@dataclass(frozen=True)
class Finding:
    id: str
    title: str
    severity: str
    evidence: str
    fix: str

    def as_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class Rule:
    id: str
    title: str
    severity: str
    fix: str


def _default_rules_path() -> Path:
    return resources.files("clawgarda").joinpath("rules/default.json")


def load_rules(path: Path | None = None) -> dict[str, Rule]:
    src = path or _default_rules_path()
    try:
        raw = json.loads(Path(src).read_text(encoding="utf-8"))
    except Exception:
        raw = {"rules": []}

    rules: dict[str, Rule] = {}
    for item in raw.get("rules", []):
        if not isinstance(item, dict):
            continue
        rid = item.get("id")
        title = item.get("title")
        severity = item.get("severity")
        fix = item.get("fix")
        if not all(isinstance(v, str) and v.strip() for v in (rid, title, severity, fix)):
            continue
        rules[rid] = Rule(id=rid, title=title, severity=severity, fix=fix)
    return rules


def _make_finding(rules: dict[str, Rule], rid: str, evidence: str, severity: str | None = None, title: str | None = None, fix: str | None = None) -> Finding:
    rule = rules.get(rid)
    base_title = title or (rule.title if rule else rid)
    base_severity = severity or (rule.severity if rule else "medium")
    base_fix = fix or (rule.fix if rule else "Review and remediate.")
    return Finding(id=rid, title=base_title, severity=base_severity, evidence=evidence, fix=base_fix)


def _find_gateway_config(workspace: Path) -> Path | None:
    home = Path.home()
    candidates = [
        workspace / "gateway.json",
        workspace / "config" / "gateway.json",
        workspace / "openclaw.json",
        workspace / "config.json",
        home / ".openclaw" / "openclaw.json",
        home / "openclaw" / "state" / "openclaw.json",
    ]
    for candidate in candidates:
        if candidate.is_file():
            return candidate
    return None


def _load_json(path: Path) -> dict[str, Any]:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return {}


def _extract_gateway_settings(data: dict[str, Any]) -> tuple[str | None, int | None, str | None, str | None]:
    gateway = data.get("gateway") if isinstance(data.get("gateway"), dict) else data
    bind = gateway.get("bind") if isinstance(gateway, dict) else None
    host = gateway.get("host") if isinstance(gateway, dict) else None
    token = gateway.get("auth_token") if isinstance(gateway, dict) else None
    password = gateway.get("password") if isinstance(gateway, dict) else None
    port = gateway.get("port") if isinstance(gateway, dict) else None

    bind_value = bind or host
    port_value = int(port) if isinstance(port, int) or (isinstance(port, str) and port.isdigit()) else DEFAULT_GATEWAY_PORT
    token_value = token if isinstance(token, str) else None
    password_value = password if isinstance(password, str) else None
    return bind_value, port_value, token_value, password_value


def _is_loopback(bind_value: str | None) -> bool:
    if not bind_value:
        return False
    value = bind_value.strip().lower()
    return value in {"127.0.0.1", "localhost", "::1", "loopback"}


def _scan_text_files_for_secrets(workspace: Path, rules: dict[str, Rule], policy: Policy) -> list[Finding]:
    findings: list[Finding] = []
    scanned = 0

    for path in sorted(workspace.rglob("*")):
        if scanned >= MAX_FILES:
            break
        if not path.is_file():
            continue
        if path.is_symlink():
            continue
        if path_matches_any(path, policy.ignore_globs, workspace):
            continue
        if path.suffix.lower() not in {".md", ".json"}:
            continue
        try:
            if path.stat().st_size > MAX_FILE_SIZE_BYTES:
                continue
            text = path.read_text(encoding="utf-8", errors="ignore")
            scanned += 1
        except OSError:
            continue

        for pattern in PLAINTEXT_SECRET_PATTERNS:
            match = pattern.search(text)
            if not match:
                continue
            excerpt = match.group(0)
            if len(excerpt) > 120:
                excerpt = excerpt[:117] + "..."
            findings.append(
                _make_finding(
                    rules,
                    rid="CGA-006",
                    evidence=f"{path}: matched `{excerpt}`",
                )
            )
            break

    return findings


def _check_gateway_bind(bind_value: str | None, config_path: Path | None, rules: dict[str, Rule]) -> Finding | None:
    if bind_value is None:
        return _make_finding(
            rules,
            rid="CGA-001",
            severity="medium",
            title="Gateway bind address missing",
            evidence=f"No bind/host found in {config_path or 'gateway config'}",
            fix="Set gateway bind to loopback (127.0.0.1 or localhost) unless remote access is explicitly required.",
        )
    if _is_loopback(bind_value):
        return None
    return _make_finding(
        rules,
        rid="CGA-001",
        evidence=f"Gateway bind/host is `{bind_value}` in {config_path or 'config'}",
    )


def _check_gateway_auth(token: str | None, password: str | None, config_path: Path | None, rules: dict[str, Rule]) -> Finding | None:
    if (token and token.strip()) or (password and password.strip()):
        return None
    return _make_finding(
        rules,
        rid="CGA-002",
        evidence=f"Neither `auth_token` nor `password` is configured in {config_path or 'gateway config'}",
    )


def _check_telegram_token_in_config(config_text: str, config_path: Path | None, rules: dict[str, Rule]) -> Finding | None:
    match = TELEGRAM_TOKEN_PATTERN.search(config_text)
    if not match:
        return None
    token = match.group(0)
    masked = token[:6] + "..." + token[-4:]
    return _make_finding(
        rules,
        rid="CGA-003",
        evidence=f"Token-like value `{masked}` found in {config_path or 'config'}",
    )


def _check_workspace_path(workspace: Path, allowed_root: Path, rules: dict[str, Rule]) -> Finding | None:
    resolved_workspace = workspace.resolve()
    resolved_allowed = allowed_root.resolve()
    try:
        resolved_workspace.relative_to(resolved_allowed)
        return None
    except ValueError:
        return _make_finding(
            rules,
            rid="CGA-004",
            evidence=f"Workspace is `{resolved_workspace}`, expected under `{resolved_allowed}`",
        )


def _check_default_port_exposure(bind_value: str | None, port: int | None, rules: dict[str, Rule]) -> Finding | None:
    if port != DEFAULT_GATEWAY_PORT:
        return None
    if bind_value is None:
        return _make_finding(
            rules,
            rid="CGA-005",
            severity="medium",
            title="Default gateway port in use with unknown bind",
            evidence=f"Gateway uses default port {DEFAULT_GATEWAY_PORT} and bind was not found",
            fix="Use a non-default port and explicitly bind to loopback.",
        )
    if _is_loopback(bind_value):
        return None
    return _make_finding(
        rules,
        rid="CGA-005",
        evidence=f"Gateway bind `{bind_value}` with default port {DEFAULT_GATEWAY_PORT}",
    )


def _check_local_port_listening(bind_value: str | None, port: int | None, rules: dict[str, Rule]) -> Finding | None:
    if port != DEFAULT_GATEWAY_PORT:
        return None

    host = "127.0.0.1" if _is_loopback(bind_value) else "0.0.0.0"
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(0.25)
    try:
        result = sock.connect_ex((host, port))
    except OSError:
        return None
    finally:
        sock.close()

    if result != 0:
        return None

    severity = "low" if _is_loopback(bind_value) else "medium"
    return _make_finding(
        rules,
        rid="CGA-005",
        severity=severity,
        title="Default gateway port is currently listening",
        evidence=f"TCP {host}:{port} is accepting connections",
        fix="If this is unexpected, stop the service or restrict listening scope to loopback and firewall rules.",
    )


def run_scan(
    workspace: Path,
    allowed_root: Path = DEFAULT_ALLOWED_WORKSPACE,
    rules_path: Path | None = None,
    policy_path: Path | None = None,
) -> list[Finding]:
    workspace = workspace.resolve()
    findings: list[Finding] = []
    rules = load_rules(rules_path)
    policy = load_policy(policy_path)

    config_path = _find_gateway_config(workspace)
    config_data: dict[str, Any] = {}
    config_text = ""

    if config_path:
        try:
            config_text = config_path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            config_text = ""
        config_data = _load_json(config_path)

    bind_value, port, token, password = _extract_gateway_settings(config_data)

    for check in (
        _check_workspace_path(workspace, allowed_root, rules),
        _check_gateway_bind(bind_value, config_path, rules),
        _check_gateway_auth(token, password, config_path, rules),
        _check_telegram_token_in_config(config_text, config_path, rules),
        _check_default_port_exposure(bind_value, port, rules),
        _check_local_port_listening(bind_value, port, rules),
    ):
        if check:
            findings.append(check)

    findings.extend(_scan_text_files_for_secrets(workspace, rules, policy))

    findings = [f for f in findings if not finding_is_excepted(f.id, f.evidence, policy.exceptions)]
    findings.sort(key=lambda f: SEVERITY_SCORE.get(f.severity, 0), reverse=True)
    return findings


def findings_to_json(findings: list[Finding]) -> str:
    return json.dumps([f.as_dict() for f in findings], indent=2)


def findings_to_sarif(findings: list[Finding], tool_name: str = "clawgarda") -> str:
    rules_seen: dict[str, dict[str, Any]] = {}
    results: list[dict[str, Any]] = []

    for finding in findings:
        if finding.id not in rules_seen:
            rules_seen[finding.id] = {
                "id": finding.id,
                "name": finding.id,
                "shortDescription": {"text": finding.title},
                "help": {"text": finding.fix},
                "properties": {"severity": finding.severity},
            }

        results.append(
            {
                "ruleId": finding.id,
                "level": SARIF_LEVEL_MAP.get(finding.severity, "warning"),
                "message": {
                    "text": f"{finding.title}. Evidence: {finding.evidence}. Fix: {finding.fix}",
                },
            }
        )

    sarif = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": tool_name,
                        "rules": list(rules_seen.values()),
                    }
                },
                "results": results,
            }
        ],
    }
    return json.dumps(sarif, indent=2)
