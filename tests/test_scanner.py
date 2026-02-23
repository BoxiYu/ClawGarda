from __future__ import annotations

import json
from pathlib import Path
import tempfile
import unittest

from clawgarda.reporting import compare_findings, render_markdown_report
from clawgarda.scanner import findings_to_sarif, run_scan


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

    def test_sarif_output_contains_rule(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            workspace = Path(tmp)
            findings = run_scan(workspace, allowed_root=workspace)
            sarif = json.loads(findings_to_sarif(findings))
            self.assertEqual(sarif["version"], "2.1.0")
            self.assertIn("runs", sarif)
            self.assertGreaterEqual(len(sarif["runs"][0]["results"]), 1)

    def test_baseline_compare_and_markdown(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            workspace = Path(tmp)
            # previous baseline has no findings
            previous = {"findings": []}
            current = run_scan(workspace, allowed_root=workspace)
            diff = compare_findings(current, previous)
            self.assertGreaterEqual(diff["summary"]["added"], 1)
            report = render_markdown_report(current, workspace)
            self.assertIn("# ClawGarda Report", report)

    def test_policy_ignore_glob_suppresses_secret_finding(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            workspace = Path(tmp)
            noisy = workspace / "docs" / "sample.md"
            noisy.parent.mkdir(parents=True, exist_ok=True)
            noisy.write_text('token = "sk-example-1234567890abcdef"', encoding="utf-8")

            policy = workspace / "policy.json"
            policy.write_text(
                json.dumps({"ignore_globs": ["docs/**"], "exceptions": {}}),
                encoding="utf-8",
            )

            findings = run_scan(workspace, allowed_root=workspace, policy_path=policy)
            ids = {f.id for f in findings}
            self.assertNotIn("CGA-006", ids)


if __name__ == "__main__":
    unittest.main()
