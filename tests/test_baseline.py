import json
import platform
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PY = sys.executable
SCRIPT = "skills/baseline-inspector/scripts/baseline_check.py"
STATUSES = {"PASS", "FAIL", "REVIEW", "SKIP"}


def run(args):
    return subprocess.run(
        [PY, SCRIPT, *args], cwd=ROOT, capture_output=True,
        text=True, encoding="utf-8", errors="replace",
    )


class BaselineTests(unittest.TestCase):
    def test_list_checks(self):
        result = run(["--list-checks"])
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("win-uac", result.stdout)
        self.assertIn("linux-firewall", result.stdout)
        self.assertIn("linux-sudo-nopasswd", result.stdout)

    def test_json_single_check(self):
        check_id = "win-uac" if platform.system() == "Windows" else "linux-ssh-root"
        result = run(["--json", "--only", check_id, "--fail-on", "none"])
        self.assertEqual(result.returncode, 0, result.stderr)
        payload = json.loads(result.stdout)
        self.assertEqual(len(payload["results"]), 1)
        item = payload["results"][0]
        self.assertEqual(item["id"], check_id)
        self.assertIn(item["status"], STATUSES)
        self.assertTrue(item["expected"])

    def test_markdown_output(self):
        check_id = "win-uac" if platform.system() == "Windows" else "linux-ssh-root"
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "baseline.md"
            result = run(["--only", check_id, "--md", str(out), "--fail-on", "none"])
            self.assertEqual(result.returncode, 0, result.stderr)
            text = out.read_text(encoding="utf-8")
        self.assertIn("基线核查报告", text)
        self.assertIn(check_id, text)


if __name__ == "__main__":
    unittest.main()
