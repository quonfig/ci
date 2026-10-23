"""Tests for deps_scan.py's baseline (diff-aware) mode. Run with Python 3.11+:
    python3 -m unittest discover -s .github/actions/deps-scan
"""

from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

SCRIPT = Path(__file__).with_name("deps_scan.py")


def finding(name: str, version: str, ghsa: str, lockfile: str, repo: Path) -> dict:
    """One osv-scanner JSON result with a single HIGH advisory."""
    return {
        "source": {"path": str(repo / lockfile), "type": "lockfile"},
        "packages": [
            {
                "package": {"name": name, "version": version, "ecosystem": "npm"},
                "vulnerabilities": [
                    {
                        "id": ghsa,
                        "database_specific": {"severity": "HIGH"},
                        "affected": [{"ranges": [{"events": [{"introduced": "0"}, {"fixed": "9.9.9"}]}]}],
                    }
                ],
                "groups": [{"ids": [ghsa], "aliases": [ghsa], "max_severity": "7.5"}],
            }
        ],
    }


class BaselineTest(unittest.TestCase):
    def setUp(self) -> None:
        # resolve(): macOS /var is a symlink, and the script compares resolved paths.
        self.tmp = Path(tempfile.mkdtemp()).resolve()
        self.head = self.tmp / "head"
        self.base = self.tmp / "base"
        self.head.mkdir()
        self.base.mkdir()

    def scan(self, head_results: list, base_results: list | None) -> subprocess.CompletedProcess:
        head_json = self.tmp / "head.json"
        head_json.write_text(json.dumps({"results": head_results}))
        cmd = [sys.executable, str(SCRIPT), "--repo", str(self.head), "--osv-json", str(head_json)]
        if base_results is not None:
            base_json = self.tmp / "base.json"
            base_json.write_text(json.dumps({"results": base_results}))
            cmd += ["--base-repo", str(self.base), "--base-osv-json", str(base_json)]
        return subprocess.run(cmd, capture_output=True, text=True)

    def test_no_baseline_blocks_existing_finding(self) -> None:
        r = self.scan([finding("zod", "4.3.6", "GHSA-mrhx", "pnpm-lock.yaml", self.head)], None)
        self.assertEqual(r.returncode, 1, r.stdout)

    def test_finding_already_on_base_is_reported_not_blocking(self) -> None:
        r = self.scan(
            [finding("zod", "4.3.6", "GHSA-mrhx", "pnpm-lock.yaml", self.head)],
            [finding("zod", "4.3.6", "GHSA-mrhx", "pnpm-lock.yaml", self.base)],
        )
        self.assertEqual(r.returncode, 0, r.stdout)
        self.assertIn("already on the base branch", r.stdout)
        self.assertIn("1 pre-existing", r.stdout)

    def test_version_change_within_same_advisory_is_still_pre_existing(self) -> None:
        r = self.scan(
            [finding("zod", "4.4.0", "GHSA-mrhx", "pnpm-lock.yaml", self.head)],
            [finding("zod", "4.3.6", "GHSA-mrhx", "pnpm-lock.yaml", self.base)],
        )
        self.assertEqual(r.returncode, 0, r.stdout)

    def test_new_package_introduced_by_pr_blocks(self) -> None:
        r = self.scan(
            [
                finding("zod", "4.3.6", "GHSA-mrhx", "pnpm-lock.yaml", self.head),
                finding("lodash", "4.17.0", "GHSA-lodash", "pnpm-lock.yaml", self.head),
            ],
            [finding("zod", "4.3.6", "GHSA-mrhx", "pnpm-lock.yaml", self.base)],
        )
        self.assertEqual(r.returncode, 1, r.stdout)
        self.assertIn("1 blocking", r.stdout)
        self.assertIn("lodash", r.stdout)

    def test_same_package_new_advisory_blocks(self) -> None:
        r = self.scan(
            [finding("zod", "4.3.6", "GHSA-other", "pnpm-lock.yaml", self.head)],
            [finding("zod", "4.3.6", "GHSA-mrhx", "pnpm-lock.yaml", self.base)],
        )
        self.assertEqual(r.returncode, 1, r.stdout)

    def test_same_advisory_in_a_different_lockfile_blocks(self) -> None:
        r = self.scan(
            [finding("zod", "4.3.6", "GHSA-mrhx", "sub/package-lock.json", self.head)],
            [finding("zod", "4.3.6", "GHSA-mrhx", "pnpm-lock.yaml", self.base)],
        )
        self.assertEqual(r.returncode, 1, r.stdout)

    def test_go_vuln_newly_called_by_pr_blocks(self) -> None:
        base = finding("golang.org/x/net", "0.1.0", "GO-2026-1", "go.mod", self.base)
        base["packages"][0]["groups"][0]["experimental_analysis"] = {"GO-2026-1": {"called": False}}
        r = self.scan([finding("golang.org/x/net", "0.1.0", "GO-2026-1", "go.mod", self.head)], [base])
        self.assertEqual(r.returncode, 1, r.stdout)

    def test_unreadable_baseline_fails_closed(self) -> None:
        head_json = self.tmp / "head.json"
        head_json.write_text(json.dumps({"results": [finding("zod", "4.3.6", "GHSA-mrhx", "pnpm-lock.yaml", self.head)]}))
        r = subprocess.run(
            [sys.executable, str(SCRIPT), "--repo", str(self.head), "--osv-json", str(head_json),
             "--base-repo", str(self.base), "--base-osv-json", str(self.tmp / "missing.json")],
            capture_output=True, text=True,
        )
        self.assertEqual(r.returncode, 1, r.stdout)
        self.assertIn("baseline", r.stdout)


if __name__ == "__main__":
    unittest.main()
