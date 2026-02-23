from __future__ import annotations

import json
from pathlib import Path
import tempfile
import unittest

from clawgarda.cli import _render_table
from clawgarda.fixer import run_fix_safe
from clawgarda.reporting import compare_findings, render_markdown_report
from clawgarda.scanner import findings_to_json, findings_to_sarif, run_scan


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
            auth_finding = next((f for f in findings if f.id == "CGA-002"), None)
            self.assertIsNotNone(auth_finding)
            self.assertEqual(auth_finding.severity, "medium")

    def test_nested_gateway_auth_mode_token_missing_token_is_critical(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            workspace = Path(tmp)
            config = {"gateway": {"bind": "127.0.0.1", "auth": {"mode": "token"}}}
            (workspace / "openclaw.json").write_text(json.dumps(config), encoding="utf-8")

            findings = run_scan(workspace, allowed_root=workspace)
            auth_finding = next((f for f in findings if f.id == "CGA-002"), None)
            self.assertIsNotNone(auth_finding)
            self.assertEqual(auth_finding.severity, "critical")
            self.assertEqual(auth_finding.confidence, "high")

    def test_nested_gateway_auth_mode_password_missing_password_is_critical(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            workspace = Path(tmp)
            config = {"gateway": {"bind": "127.0.0.1", "auth": {"mode": "password"}}}
            (workspace / "openclaw.json").write_text(json.dumps(config), encoding="utf-8")

            findings = run_scan(workspace, allowed_root=workspace)
            auth_finding = next((f for f in findings if f.id == "CGA-002"), None)
            self.assertIsNotNone(auth_finding)
            self.assertEqual(auth_finding.severity, "critical")
            self.assertEqual(auth_finding.confidence, "high")

    def test_nested_gateway_auth_mode_off_is_high(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            workspace = Path(tmp)
            config = {"gateway": {"bind": "127.0.0.1", "auth": {"mode": "off"}}}
            (workspace / "openclaw.json").write_text(json.dumps(config), encoding="utf-8")

            findings = run_scan(workspace, allowed_root=workspace)
            auth_finding = next((f for f in findings if f.id == "CGA-002"), None)
            self.assertIsNotNone(auth_finding)
            self.assertEqual(auth_finding.severity, "high")

    def test_nested_gateway_auth_mode_token_with_token_passes(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            workspace = Path(tmp)
            config = {"gateway": {"bind": "127.0.0.1", "auth": {"mode": "token", "token": "secret-token"}}}
            (workspace / "openclaw.json").write_text(json.dumps(config), encoding="utf-8")

            findings = run_scan(workspace, allowed_root=workspace)
            ids = {f.id for f in findings}
            self.assertNotIn("CGA-002", ids)

    def test_telegram_placeholder_token_is_ignored(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            workspace = Path(tmp)
            config = {
                "gateway": {
                    "bind": "127.0.0.1",
                    "auth_token": "present",
                    "telegram_bot_token": "12345678:example_sample_placeholder_token_abcdefghi123456789",
                }
            }
            (workspace / "gateway.json").write_text(json.dumps(config), encoding="utf-8")

            findings = run_scan(workspace, allowed_root=workspace)
            ids = {f.id for f in findings}
            self.assertNotIn("CGA-003", ids)

    def test_sarif_output_contains_rule(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            workspace = Path(tmp)
            findings = run_scan(workspace, allowed_root=workspace)
            sarif = json.loads(findings_to_sarif(findings))
            self.assertEqual(sarif["version"], "2.1.0")
            self.assertIn("runs", sarif)
            self.assertGreaterEqual(len(sarif["runs"][0]["results"]), 1)
            self.assertIn("confidence", sarif["runs"][0]["results"][0]["properties"])

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

    def test_json_and_table_outputs_include_confidence(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            workspace = Path(tmp)
            findings = run_scan(workspace, allowed_root=workspace)
            payload = json.loads(findings_to_json(findings))
            self.assertIn("confidence", payload[0])

            table = _render_table(findings)
            self.assertIn("Confidence", table.splitlines()[0])

    def test_fix_safe_dry_run_and_apply(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            workspace = Path(tmp)
            findings = run_scan(workspace, allowed_root=workspace)

            plan = run_fix_safe(workspace, findings, dry_run=True)
            self.assertGreaterEqual(len(plan.actions), 1)
            self.assertEqual(plan.wrote_files, [])

            plan_apply = run_fix_safe(workspace, findings, dry_run=False)
            self.assertGreaterEqual(len(plan_apply.wrote_files), 1)
            self.assertTrue((workspace / ".clawgarda" / "policy.json").exists())
            self.assertTrue((workspace / ".clawgarda" / "remediation-plan.md").exists())


if __name__ == "__main__":
    unittest.main()
