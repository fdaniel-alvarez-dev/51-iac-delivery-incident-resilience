import os
import subprocess
import tempfile
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]


class SmokeTests(unittest.TestCase):
    def test_report_generates_markdown(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            artifacts = Path(td) / "artifacts"
            env = os.environ.copy()
            env["PYTHONPATH"] = str(REPO_ROOT / "src")
            subprocess.check_call(
                [
                    "python3",
                    "-m",
                    "portfolio_proof",
                    "--repo-root",
                    str(REPO_ROOT),
                    "report",
                    "--examples",
                    "examples",
                    "--artifacts",
                    str(artifacts),
                ],
                env=env,
            )
            report = artifacts / "report.md"
            self.assertTrue(report.exists())
            text = report.read_text(encoding="utf-8")
            self.assertIn("Infrastructure drift", text)
            self.assertIn("Delivery friction", text)
            self.assertIn("on-call", text.lower())

    def test_validate_fails_in_strict_mode_with_examples(self) -> None:
        env = os.environ.copy()
        env["PYTHONPATH"] = str(REPO_ROOT / "src")
        p = subprocess.run(
            [
                "python3",
                "-m",
                "portfolio_proof",
                "--repo-root",
                str(REPO_ROOT),
                "validate",
                "--examples",
                "examples",
                "--strict",
            ],
            env=env,
            capture_output=True,
            text=True,
        )
        self.assertNotEqual(p.returncode, 0)
        self.assertIn("Validation failed", p.stdout)
