from __future__ import annotations

from dataclasses import asdict, dataclass
from pathlib import Path
import json
import re
import socket
from typing import Any

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


def _find_gateway_config(workspace: Path) -> Path | None:
    candidates = [
        workspace / "gateway.json",
        workspace / "config" / "gateway.json",
        workspace / "openclaw.json",
        workspace / "config.json",
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
    return value in {"127.0.0.1", "localhost", "::1"}


def _scan_text_files_for_secrets(workspace: Path) -> list[Finding]:
    findings: list[Finding] = []
    scanned = 0

    for path in sorted(workspace.rglob("*")):
        if scanned >= MAX_FILES:
            break
        if not path.is_file():
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
                Finding(
                    id="CGA-006",
                    title="Possible plaintext secret in workspace file",
                    severity="high",
                    evidence=f"{path}: matched `{excerpt}`",
                    fix="Remove plaintext secrets and move them to environment variables or a secret manager.",
                )
            )
            break

    return findings


def _check_gateway_bind(bind_value: str | None, config_path: Path | None) -> Finding | None:
    if bind_value is None:
        return Finding(
            id="CGA-001",
            title="Gateway bind address missing",
            severity="medium",
            evidence=f"No bind/host found in {config_path or 'gateway config'}",
            fix="Set gateway bind to loopback (127.0.0.1 or localhost) unless remote access is explicitly required.",
        )
    if _is_loopback(bind_value):
        return None
    return Finding(
        id="CGA-001",
        title="Gateway bind is not loopback",
        severity="high",
        evidence=f"Gateway bind/host is `{bind_value}` in {config_path or 'config'}",
        fix="Bind gateway to 127.0.0.1 or localhost and place it behind a secure reverse proxy if external access is needed.",
    )


def _check_gateway_auth(token: str | None, password: str | None, config_path: Path | None) -> Finding | None:
    if (token and token.strip()) or (password and password.strip()):
        return None
    return Finding(
        id="CGA-002",
        title="Missing gateway auth token/password",
        severity="critical",
        evidence=f"Neither `auth_token` nor `password` is configured in {config_path or 'gateway config'}",
        fix="Configure a strong auth token or password for the gateway and load it from environment variables.",
    )


def _check_telegram_token_in_config(config_text: str, config_path: Path | None) -> Finding | None:
    match = TELEGRAM_TOKEN_PATTERN.search(config_text)
    if not match:
        return None
    token = match.group(0)
    masked = token[:6] + "..." + token[-4:]
    return Finding(
        id="CGA-003",
        title="Telegram bot token found in config",
        severity="high",
        evidence=f"Token-like value `{masked}` found in {config_path or 'config'}",
        fix="Remove bot token from tracked config files and load it from environment variables or a secret store.",
    )


def _check_workspace_path(workspace: Path, allowed_root: Path) -> Finding | None:
    resolved_workspace = workspace.resolve()
    resolved_allowed = allowed_root.resolve()
    try:
        resolved_workspace.relative_to(resolved_allowed)
        return None
    except ValueError:
        return Finding(
            id="CGA-004",
            title="Workspace path outside allowed OpenClaw root",
            severity="medium",
            evidence=f"Workspace is `{resolved_workspace}`, expected under `{resolved_allowed}`",
            fix="Use a workspace under /Users/ddq/openclaw or update policy if this path is intentional.",
        )


def _check_default_port_exposure(bind_value: str | None, port: int | None) -> Finding | None:
    if port != DEFAULT_GATEWAY_PORT:
        return None
    if bind_value is None:
        return Finding(
            id="CGA-005",
            title="Default gateway port in use with unknown bind",
            severity="medium",
            evidence=f"Gateway uses default port {DEFAULT_GATEWAY_PORT} and bind was not found",
            fix="Use a non-default port and explicitly bind to loopback.",
        )
    if _is_loopback(bind_value):
        return None
    return Finding(
        id="CGA-005",
        title="Gateway exposes default port on non-loopback interface",
        severity="high",
        evidence=f"Gateway bind `{bind_value}` with default port {DEFAULT_GATEWAY_PORT}",
        fix="Change port from default and bind to loopback or protect with network controls.",
    )


def _check_local_port_listening(bind_value: str | None, port: int | None) -> Finding | None:
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
    return Finding(
        id="CGA-005",
        title="Default gateway port is currently listening",
        severity=severity,
        evidence=f"TCP {host}:{port} is accepting connections",
        fix="If this is unexpected, stop the service or restrict listening scope to loopback and firewall rules.",
    )


def run_scan(workspace: Path, allowed_root: Path = DEFAULT_ALLOWED_WORKSPACE) -> list[Finding]:
    workspace = workspace.resolve()
    findings: list[Finding] = []

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
        _check_workspace_path(workspace, allowed_root),
        _check_gateway_bind(bind_value, config_path),
        _check_gateway_auth(token, password, config_path),
        _check_telegram_token_in_config(config_text, config_path),
        _check_default_port_exposure(bind_value, port),
        _check_local_port_listening(bind_value, port),
    ):
        if check:
            findings.append(check)

    findings.extend(_scan_text_files_for_secrets(workspace))

    findings.sort(key=lambda f: SEVERITY_SCORE.get(f.severity, 0), reverse=True)
    return findings


def findings_to_json(findings: list[Finding]) -> str:
    return json.dumps([f.as_dict() for f in findings], indent=2)
