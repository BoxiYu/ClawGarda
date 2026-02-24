from __future__ import annotations

from urllib.parse import urljoin
from urllib.request import Request, urlopen
from urllib.error import URLError, HTTPError
from typing import Iterable

from .scanner import Finding

DEFAULT_PATHS = ["/", "/health", "/status", "/metrics", "/admin", "/debug", "/openapi.json"]
SEC_HEADERS = [
    "strict-transport-security",
    "x-content-type-options",
    "x-frame-options",
    "content-security-policy",
]


def _req(url: str, timeout: float = 4.0) -> tuple[int | None, dict[str, str], str]:
    request = Request(url, headers={"User-Agent": "ClawGarda-DAST/0.1"})
    try:
        with urlopen(request, timeout=timeout) as resp:
            status = getattr(resp, "status", None)
            headers = {k.lower(): v for k, v in resp.headers.items()}
            body = resp.read(2048).decode("utf-8", errors="ignore")
            return status, headers, body
    except HTTPError as e:
        try:
            body = e.read(2048).decode("utf-8", errors="ignore")
        except Exception:
            body = ""
        return e.code, {k.lower(): v for k, v in getattr(e, "headers", {}).items()}, body
    except URLError:
        return None, {}, ""


def run_dast_smoke(base_url: str, paths: Iterable[str] | None = None) -> list[Finding]:
    findings: list[Finding] = []
    scan_paths = list(paths) if paths is not None else DEFAULT_PATHS

    root_status, root_headers, _ = _req(base_url)
    if root_status is None:
        findings.append(
            Finding(
                id="CGDAS-001",
                title="Target unreachable",
                severity="high",
                confidence="high",
                evidence=f"Unable to connect to {base_url}",
                fix="Verify target URL/network reachability before running DAST.",
            )
        )
        return findings

    missing = [h for h in SEC_HEADERS if h not in root_headers]
    if missing:
        findings.append(
            Finding(
                id="CGDAS-002",
                title="Missing common security headers",
                severity="medium",
                confidence="medium",
                evidence=f"{base_url} missing headers: {', '.join(missing)}",
                fix="Add recommended security headers at gateway/reverse proxy layer.",
            )
        )

    for p in scan_paths:
        u = urljoin(base_url.rstrip("/") + "/", p.lstrip("/"))
        status, headers, body = _req(u)
        if status is None:
            continue

        if p in {"/admin", "/debug", "/metrics"} and status in {200, 204}:
            findings.append(
                Finding(
                    id="CGDAS-003",
                    title="Potentially sensitive endpoint publicly accessible",
                    severity="high",
                    confidence="medium",
                    evidence=f"{u} returned HTTP {status}",
                    fix="Require authentication or network restrictions for sensitive endpoints.",
                )
            )

        ctype = headers.get("content-type", "")
        if "application/json" in ctype and status == 200 and ("token" in body.lower() or "apikey" in body.lower()):
            findings.append(
                Finding(
                    id="CGDAS-004",
                    title="Possible credential disclosure in endpoint response",
                    severity="high",
                    confidence="low",
                    evidence=f"{u} returned JSON containing token/apikey-like terms",
                    fix="Review response payloads and remove sensitive fields from public endpoints.",
                )
            )

    rank = {"critical": 4, "high": 3, "medium": 2, "low": 1}
    dedup: dict[tuple[str, str], Finding] = {}
    for f in findings:
        dedup[(f.id, f.evidence)] = f
    out = list(dedup.values())
    out.sort(key=lambda x: rank.get(x.severity, 0), reverse=True)
    return out
