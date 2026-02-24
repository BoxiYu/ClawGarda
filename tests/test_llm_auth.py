from __future__ import annotations

import unittest
from unittest.mock import patch

from clawgarda.llm_auth import codex_login_status


class LLMAuthTests(unittest.TestCase):
    @patch("subprocess.run")
    def test_codex_login_status_authenticated(self, mock_run):
        class R:
            returncode = 0
            stdout = "Logged in via OAuth"
            stderr = ""

        mock_run.return_value = R()
        st = codex_login_status()
        self.assertTrue(st.authenticated)

    @patch("subprocess.run")
    def test_codex_login_status_not_authenticated(self, mock_run):
        class R:
            returncode = 1
            stdout = "not logged in"
            stderr = ""

        mock_run.return_value = R()
        st = codex_login_status()
        self.assertFalse(st.authenticated)


if __name__ == "__main__":
    unittest.main()
