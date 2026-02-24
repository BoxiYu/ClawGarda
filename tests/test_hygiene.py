from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from clawgarda.hygiene import run_hygiene_secret_scan


class HygieneTests(unittest.TestCase):
    def test_detects_token_pattern(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            (ws / "config.json").write_text('{"token":"12345678:abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMN"}', encoding="utf-8")
            findings = run_hygiene_secret_scan(ws)
            self.assertTrue(any(f.id == "CGH-001" for f in findings))

    def test_no_findings_on_clean_workspace(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            (ws / "README.md").write_text("hello", encoding="utf-8")
            findings = run_hygiene_secret_scan(ws)
            self.assertEqual(findings, [])


if __name__ == "__main__":
    unittest.main()
