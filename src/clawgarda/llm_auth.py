from __future__ import annotations

import subprocess
from dataclasses import dataclass


@dataclass(frozen=True)
class LLMAuthStatus:
    provider: str
    authenticated: bool
    detail: str


def codex_login_status() -> LLMAuthStatus:
    try:
        proc = subprocess.run(
            ["codex", "login", "status"],
            capture_output=True,
            text=True,
            timeout=10,
        )
    except Exception as exc:
        return LLMAuthStatus(provider="openai-oauth-codex", authenticated=False, detail=f"status check failed: {exc}")

    out = (proc.stdout or "") + (proc.stderr or "")
    text = out.strip()
    ok = proc.returncode == 0 and ("logged in" in text.lower() or "authenticated" in text.lower() or "oauth" in text.lower())
    return LLMAuthStatus(provider="openai-oauth-codex", authenticated=ok, detail=text or f"exit={proc.returncode}")


def codex_login_device_auth() -> int:
    proc = subprocess.run(["codex", "login", "--device-auth"])
    return proc.returncode
