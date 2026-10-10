"""Comprehensive unit and integration test suite for Git Security Sentinel.

All synthetic test secrets are constructed programmatically at runtime to avoid
placing real-looking credential leaks in the repository's version history.
"""

from __future__ import annotations

import io
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import MagicMock, patch

# Add repository root and scripts directory to sys.path
REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))
sys.path.insert(0, str(REPO_ROOT / "scripts"))

import scan_diff
import ai_review


class TestDiffParsing(unittest.TestCase):
    """Test unified git diff parsing and line number tracking."""

    def test_empty_diff(self):
        lines = scan_diff.parse_unified_diff("")
        self.assertEqual(lines, [])

    def test_clean_diff_without_added_lines(self):
        diff_text = """diff --git a/file.py b/file.py
index 1234567..89abcdef 100644
--- a/file.py
+++ b/file.py
@@ -10,3 +10,2 @@
 context line 1
-deleted line
 context line 2
"""
        lines = scan_diff.parse_unified_diff(diff_text)
        self.assertEqual(len(lines), 0)

    def test_added_lines_and_line_numbers(self):
        diff_text = """diff --git a/app.py b/app.py
new file mode 100644
index 0000000..abcdef1
--- /dev/null
+++ b/app.py
@@ -0,0 +1,3 @@
+line one
+line two
+line three
"""
        lines = scan_diff.parse_unified_diff(diff_text)
        self.assertEqual(len(lines), 3)
        self.assertEqual(lines[0].file_path, "app.py")
        self.assertEqual(lines[0].line_number, 1)
        self.assertEqual(lines[0].content, "line one")
        self.assertEqual(lines[1].line_number, 2)
        self.assertEqual(lines[2].line_number, 3)

    def test_multiple_files_and_spaces_in_paths(self):
        diff_text = """diff --git a/my path/file one.py b/my path/file one.py
index 1111111..2222222 100644
--- a/my path/file one.py
+++ b/my path/file one.py
@@ -5,4 +5,5 @@
 context
+new code 1
 context
diff --git a/file2.py b/file2.py
index 3333333..4444444 100644
--- a/file2.py
+++ b/file2.py
@@ -1,2 +1,3 @@
+new code 2
 context
"""
        lines = scan_diff.parse_unified_diff(diff_text)
        self.assertEqual(len(lines), 2)
        self.assertEqual(lines[0].file_path, "my path/file one.py")
        self.assertEqual(lines[0].line_number, 6)
        self.assertEqual(lines[0].content, "new code 1")
        self.assertEqual(lines[1].file_path, "file2.py")
        self.assertEqual(lines[1].line_number, 1)
        self.assertEqual(lines[1].content, "new code 2")


class TestSecretDetectionRules(unittest.TestCase):
    """Test individual security rules using programmatically generated synthetic tokens."""

    def test_aws_access_key_detection(self):
        # Generate synthetic AWS key: AKIA + 16 chars
        synthetic_key = "AKIA" + "0123456789ABCDEF"
        line = scan_diff.DiffHunkLine("config.py", 10, f"aws_key = '{synthetic_key}'")
        findings = scan_diff.scan_added_lines([line])
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].rule_id, "secret.aws_access_key")
        self.assertEqual(findings[0].severity, "high")
        # Ensure raw key is redacted
        self.assertNotIn(synthetic_key, findings[0].evidence)
        self.assertTrue("*" in findings[0].evidence or "[REDACTED]" in findings[0].evidence)

    def test_aws_secret_key_detection(self):
        # 40-char secret
        synthetic_secret = "A" * 40
        line = scan_diff.DiffHunkLine("aws.py", 5, f'aws_secret_access_key = "{synthetic_secret}"')
        findings = scan_diff.scan_added_lines([line])
        self.assertTrue(any(f.rule_id == "secret.aws_secret_key" for f in findings))
        for f in findings:
            self.assertNotIn(synthetic_secret, f.evidence)

    def test_github_pat_classic_detection(self):
        synthetic_pat = "ghp_" + ("x" * 36)
        line = scan_diff.DiffHunkLine("token.py", 12, f"github_token = '{synthetic_pat}'")
        findings = scan_diff.scan_added_lines([line])
        self.assertTrue(any(f.rule_id == "secret.github_pat_classic" for f in findings))
        for f in findings:
            self.assertNotIn(synthetic_pat, f.evidence)

    def test_github_fine_grained_pat_detection(self):
        synthetic_fg = "github_pat_" + ("y" * 82)
        line = scan_diff.DiffHunkLine("ci.py", 15, f"export GITHUB_TOKEN={synthetic_fg}")
        findings = scan_diff.scan_added_lines([line])
        self.assertTrue(any(f.rule_id == "secret.github_pat_fine_grained" for f in findings))
        for f in findings:
            self.assertNotIn(synthetic_fg, f.evidence)

    def test_github_scoped_token_detection(self):
        synthetic_oauth = "gho_" + ("z" * 36)
        line = scan_diff.DiffHunkLine("auth.py", 8, f"client_token = '{synthetic_oauth}'")
        findings = scan_diff.scan_added_lines([line])
        self.assertTrue(any(f.rule_id == "secret.github_token_scoped" for f in findings))

    def test_private_key_detection(self):
        line = scan_diff.DiffHunkLine("id_rsa", 1, "-----BEGIN RSA PRIVATE KEY-----")
        findings = scan_diff.scan_added_lines([line])
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].rule_id, "secret.private_key")
        self.assertEqual(findings[0].severity, "critical")

    def test_slack_token_detection(self):
        synthetic_slack = "xoxb-" + ("1234567890abcdef")
        line = scan_diff.DiffHunkLine("slack.py", 3, f"token = '{synthetic_slack}'")
        findings = scan_diff.scan_added_lines([line])
        self.assertTrue(any(f.rule_id == "secret.slack_token" for f in findings))

    def test_generic_credential_detection(self):
        synthetic_pass = "P@ssw0rd99!SuperSecret"
        line = scan_diff.DiffHunkLine("db.py", 22, f'db_password = "{synthetic_pass}"')
        findings = scan_diff.scan_added_lines([line])
        self.assertTrue(any(f.rule_id == "secret.generic_credential" for f in findings))
        for f in findings:
            self.assertNotIn(synthetic_pass, f.evidence)

    def test_generic_credential_false_positives(self):
        # Benign examples that must NOT trigger false positives
        benign_lines = [
            "password = os.environ.get('DB_PASSWORD')",
            "api_key = process.env.API_KEY;",
            'secret = "${VAULT_SECRET}"',
            'token = "<INSERT_TOKEN_HERE>"',
            'password = ""',
            'api_key = None',
        ]
        for idx, text in enumerate(benign_lines, start=1):
            line = scan_diff.DiffHunkLine("settings.py", idx, text)
            findings = scan_diff.scan_added_lines([line])
            self.assertEqual(
                len(findings),
                0,
                f"Expected no findings for benign line: {text}, got: {findings}",
            )


class TestRiskyCodeAndConfig(unittest.TestCase):
    """Test eval/exec and localhost detection."""

    def test_dangerous_eval_detection(self):
        line = scan_diff.DiffHunkLine("parser.py", 42, "result = eval(user_input)")
        findings = scan_diff.scan_added_lines([line])
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].rule_id, "code.dangerous_eval")
        self.assertEqual(findings[0].category, "risky_code")

    def test_hardcoded_localhost_detection(self):
        line = scan_diff.DiffHunkLine("client.py", 10, 'BASE_URL = "http://127.0.0.1:8000/api"')
        findings = scan_diff.scan_added_lines([line])
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].rule_id, "config.hardcoded_localhost")
        self.assertEqual(findings[0].severity, "low")


class TestRedactionAndSanitizedDiff(unittest.TestCase):
    """Test that redaction functions mask secrets without data leaks."""

    def test_redact_sensitive_string(self):
        synthetic = "AKIA" + "1234567890ABCDEF"
        redacted = scan_diff.redact_sensitive_string(synthetic)
        self.assertTrue(redacted.startswith("AKIA"))
        self.assertTrue("*" in redacted)
        self.assertNotIn("1234567890", redacted)

    def test_generate_sanitized_patch(self):
        synthetic_key = "AKIA" + "ABCDEFGHIJKLMNOP"
        diff_input = f"""--- a/conf.py
+++ b/conf.py
@@ -1,1 +1,1 @@
+api_key = "{synthetic_key}"
"""
        sanitized = scan_diff.generate_sanitized_patch(diff_input)
        self.assertNotIn(synthetic_key, sanitized)
        self.assertIn("AKIA", sanitized)
        self.assertIn("*", sanitized)


class TestLicenseDetection(unittest.TestCase):
    """Test detection of standard root open-source license files."""

    def setUp(self):
        self.test_dir = tempfile.mkdtemp()
        self.test_path = Path(self.test_dir)

    def tearDown(self):
        shutil.rmtree(self.test_dir, ignore_errors=True)

    def test_missing_license(self):
        status = scan_diff.check_root_license(self.test_path)
        self.assertFalse(status.root_license_present)
        self.assertIsNone(status.license_file)

    def test_accepted_license_names(self):
        for candidate in ("LICENSE", "LICENSE.md", "LICENSE.txt", "COPYING"):
            cand_path = self.test_path / candidate
            cand_path.write_text("Sample License", encoding="utf-8")
            status = scan_diff.check_root_license(self.test_path)
            self.assertTrue(status.root_license_present, f"Failed for {candidate}")
            self.assertEqual(status.license_file, candidate)
            cand_path.unlink()


class TestCLIAndExitCodes(unittest.TestCase):
    """Test CLI behavior, report writing, and exit codes."""

    def setUp(self):
        self.test_dir = tempfile.mkdtemp()
        self.test_path = Path(self.test_dir)
        # Create a mock clean diff file
        self.clean_diff = self.test_path / "clean.diff"
        self.clean_diff.write_text("""--- a/clean.py
+++ b/clean.py
@@ -0,0 +1,1 @@
+print("Hello World")
""", encoding="utf-8")

        # Create a diff with high-severity secret
        synthetic_key = "AKIA" + "0123456789ABCDEF"
        self.secret_diff = self.test_path / "secret.diff"
        self.secret_diff.write_text(f"""--- a/secret.py
+++ b/secret.py
@@ -0,0 +1,1 @@
+AWS_KEY = "{synthetic_key}"
""", encoding="utf-8")

    def tearDown(self):
        shutil.rmtree(self.test_dir, ignore_errors=True)

    def test_clean_diff_exit_code_zero(self):
        report_out = self.test_path / "report.json"
        code = scan_diff.main([
            "--diff-file", str(self.clean_diff),
            "--format", "json",
            "--output", str(report_out),
            "--repo-root", str(self.test_path),
        ])
        self.assertEqual(code, 0)
        report_data = json.loads(report_out.read_text(encoding="utf-8"))
        self.assertEqual(report_data["status"], "completed")
        self.assertEqual(report_data["summary"]["total"], 0)

    def test_secret_diff_exit_code_one(self):
        report_out = self.test_path / "secret-report.json"
        code = scan_diff.main([
            "--diff-file", str(self.secret_diff),
            "--fail-on", "high",
            "--output", str(report_out),
            "--repo-root", str(self.test_path),
        ])
        self.assertEqual(code, 1)
        report_data = json.loads(report_out.read_text(encoding="utf-8"))
        self.assertEqual(report_data["summary"]["high"], 1)

    def test_threshold_none_exits_zero(self):
        code = scan_diff.main([
            "--diff-file", str(self.secret_diff),
            "--fail-on", "none",
            "--repo-root", str(self.test_path),
        ])
        self.assertEqual(code, 0)

    def test_exclude_patterns_skips_files(self):
        report_out = self.test_path / "excluded-report.json"
        code = scan_diff.main([
            "--diff-file", str(self.secret_diff),
            "--exclude", "secret.py",
            "--output", str(report_out),
            "--repo-root", str(self.test_path),
        ])
        self.assertEqual(code, 0)
        report_data = json.loads(report_out.read_text(encoding="utf-8"))
        self.assertEqual(report_data["summary"]["total"], 0)

    def test_missing_diff_file_exit_code_two(self):
        code = scan_diff.main([
            "--diff-file", str(self.test_path / "nonexistent.diff"),
            "--repo-root", str(self.test_path),
        ])
        self.assertEqual(code, 2)

    @patch("urllib.request.urlopen")
    def test_scan_diff_direct_ai_integration(self, mock_urlopen):
        mock_response = MagicMock()
        mock_response.read.return_value = json.dumps({
            "response": json.dumps({
                "summary": "Reviewed 1 AWS key finding.",
                "reviews": [
                    {
                        "rule_id": "secret.aws_access_key",
                        "file": "secret.py",
                        "line": 1,
                        "assessment": "genuine_risk",
                        "risk_explanation": "Exposed AWS access keys must be revoked.",
                        "safe_alternative": "Use IAM roles."
                    }
                ]
            })
        }).encode("utf-8")
        mock_urlopen.return_value.__enter__.return_value = mock_response

        report_out = self.test_path / "ai-integrated-report.json"
        code = scan_diff.main([
            "--diff-file", str(self.secret_diff),
            "--ai",
            "--ai-model", "gemma3:4b",
            "--output", str(report_out),
            "--repo-root", str(self.test_path),
        ])
        self.assertEqual(code, 1) # Still fails on high severity finding
        report_data = json.loads(report_out.read_text(encoding="utf-8"))
        self.assertIn("ai_review", report_data)
        self.assertEqual(report_data["ai_review"]["status"], "success")
        self.assertEqual(report_data["ai_review"]["model"], "gemma3:4b")

    def test_scan_diff_require_ai_failure(self):
        report_out = self.test_path / "ai-fail-report.json"
        code = scan_diff.main([
            "--diff-file", str(self.secret_diff),
            "--ai",
            "--ai-url", "http://127.0.0.1:65432",
            "--require-ai",
            "--output", str(report_out),
            "--repo-root", str(self.test_path),
        ])
        self.assertEqual(code, 2)
        report_data = json.loads(report_out.read_text(encoding="utf-8"))
        self.assertEqual(report_data["status"], "error")


class TestGitIntegration(unittest.TestCase):
    """Test git command integration within temporary Git repositories."""

    def setUp(self):
        self.repo_dir = tempfile.mkdtemp()
        self.repo_path = Path(self.repo_dir)
        # Initialize temp git repo
        subprocess.run(["git", "init"], cwd=self.repo_dir, capture_output=True, check=True)
        subprocess.run(["git", "config", "user.name", "Test User"], cwd=self.repo_dir, capture_output=True, check=True)
        subprocess.run(["git", "config", "user.email", "test@example.com"], cwd=self.repo_dir, capture_output=True, check=True)

    def tearDown(self):
        shutil.rmtree(self.repo_dir, ignore_errors=True)

    def test_unstaged_and_staged_scans(self):
        # Create an initial commit
        initial_file = self.repo_path / "README.md"
        initial_file.write_text("# Project", encoding="utf-8")
        subprocess.run(["git", "add", "README.md"], cwd=self.repo_dir, capture_output=True, check=True)
        subprocess.run(["git", "commit", "-m", "Initial commit"], cwd=self.repo_dir, capture_output=True, check=True)

        # Create staged change with synthetic secret
        staged_file = self.repo_path / "secret.py"
        synth_token = "ghp_" + ("a" * 36)
        staged_file.write_text(f"TOKEN = '{synth_token}'\n", encoding="utf-8")
        subprocess.run(["git", "add", "secret.py"], cwd=self.repo_dir, capture_output=True, check=True)

        # Create unstaged change without secrets
        unstaged_file = self.repo_path / "clean.py"
        unstaged_file.write_text("x = 42\n", encoding="utf-8")

        # Scan staged only
        report_staged = self.repo_path / "staged.json"
        rc_staged = scan_diff.main([
            "--staged",
            "--repo-root", str(self.repo_path),
            "--output", str(report_staged),
        ])
        self.assertEqual(rc_staged, 1)
        data_staged = json.loads(report_staged.read_text(encoding="utf-8"))
        self.assertEqual(data_staged["summary"]["total"], 1)

        # Scan unstaged only
        report_unstaged = self.repo_path / "unstaged.json"
        rc_unstaged = scan_diff.main([
            "--unstaged",
            "--repo-root", str(self.repo_path),
            "--output", str(report_unstaged),
        ])
        self.assertEqual(rc_unstaged, 0)
        data_unstaged = json.loads(report_unstaged.read_text(encoding="utf-8"))
        self.assertEqual(data_unstaged["summary"]["total"], 0)


class TestAIReviewComponent(unittest.TestCase):
    """Test AI reviewer logic with mocked HTTP responses and error conditions."""

    def test_loopback_validation(self):
        self.assertTrue(ai_review.is_loopback_host("http://127.0.0.1:11434"))
        self.assertTrue(ai_review.is_loopback_host("http://localhost:11434"))
        self.assertFalse(ai_review.is_loopback_host("https://api.openai.com/v1"))
        self.assertFalse(ai_review.is_loopback_host("http://192.168.1.50:11434"))

    def test_remote_host_rejected_without_flag(self):
        exit_code = ai_review.main([
            "--report", "nonexistent.json",
            "--ollama-url", "http://external-server.com:11434",
        ])
        self.assertEqual(exit_code, 2)

    def test_connection_error_handling(self):
        # Call non-running port on loopback
        result = ai_review.call_ollama(
            endpoint="http://127.0.0.1:65432",
            model="gemma3:4b",
            system_prompt="sys",
            user_prompt="user",
            timeout=2,
        )
        self.assertEqual(result["status"], "error")
        self.assertEqual(result["error_type"], "connection_error")
        self.assertIn("Ensure Ollama is running", result["message"])

    @patch("urllib.request.urlopen")
    def test_mock_successful_ai_review(self, mock_urlopen):
        # Mock valid Ollama response
        mock_response = MagicMock()
        mock_response.read.return_value = json.dumps({
            "response": json.dumps({
                "summary": "Detected 1 potential AWS key in config.py.",
                "reviews": [
                    {
                        "rule_id": "secret.aws_access_key",
                        "file": "config.py",
                        "line": 12,
                        "assessment": "genuine_risk",
                        "risk_explanation": "Exposing AWS keys enables unauthorized cloud resource access.",
                        "safe_alternative": "Load credentials via AWS IAM Roles or environment variables."
                    }
                ]
            })
        }).encode("utf-8")
        mock_urlopen.return_value.__enter__.return_value = mock_response

        findings = [
            {
                "rule_id": "secret.aws_access_key",
                "category": "secrets",
                "severity": "high",
                "confidence": "high",
                "file": "config.py",
                "line": 12,
                "evidence": "AKIA****************",
                "recommendation": "Rotate key immediately.",
            }
        ]

        with tempfile.NamedTemporaryFile("w", delete=False, suffix=".json") as tmp:
            tmp.write(json.dumps({"findings": findings}))
            tmp_path = tmp.name

        try:
            exit_code = ai_review.main([
                "--report", tmp_path,
                "--model", "gemma3:4b",
            ])
            self.assertEqual(exit_code, 0)
        finally:
            os.remove(tmp_path)


if __name__ == "__main__":
    unittest.main()
