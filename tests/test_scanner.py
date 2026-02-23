from __future__ import annotations

import json
from pathlib import Path
import tempfile
import unittest

from clawgarda.scanner import run_scan


class ScannerTests(unittest.TestCase):
    def test_workspace_outside_allowed_root(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            workspace = Path(tmp)
            findings = run_scan(workspace, allowed_root=workspace / "allowed")
            ids = {f.id for f in findings}
            self.assertIn("CGA-004", ids)

    def test_telegram_token_in_config(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            workspace = Path(tmp)
            config = {
                "gateway": {
                    "bind": "127.0.0.1",
                    "port": 4000,
                    "auth_token": "present",
                    "telegram_bot_token": "12345678:ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef",
                }
            }
            (workspace / "gateway.json").write_text(json.dumps(config), encoding="utf-8")

            findings = run_scan(workspace, allowed_root=workspace)
            ids = {f.id for f in findings}
            self.assertIn("CGA-003", ids)

    def test_missing_auth_token_and_password(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            workspace = Path(tmp)
            config = {"gateway": {"bind": "127.0.0.1", "port": 4000}}
            (workspace / "gateway.json").write_text(json.dumps(config), encoding="utf-8")

            findings = run_scan(workspace, allowed_root=workspace)
            ids = {f.id for f in findings}
            self.assertIn("CGA-002", ids)


if __name__ == "__main__":
    unittest.main()
