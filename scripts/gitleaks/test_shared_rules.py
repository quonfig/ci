"""Tests for the shared Quonfig gitleaks rules in the `ssdlc / secrets` job.

They run the job's real "Resolve config from the base branch" script, taken
from .github/workflows/ssdlc.yml, against throwaway git repos, then scan the
PR range with gitleaks the way the "Scan PR commits" step does. Needs the
gitleaks binary on PATH (the version pinned in ssdlc.yml). Run with:
    python3 -m unittest discover -s scripts/gitleaks

No private-key-shaped literal is committed here: every qf1 entry is built at
run time from random bytes, so this file passes the gate it tests.
"""

from __future__ import annotations

import base64
import json
import os
import re
import secrets
import shutil
import string
import subprocess
import tempfile
import textwrap
import unittest
from pathlib import Path

WORKFLOW = Path(__file__).resolve().parents[2] / ".github" / "workflows" / "ssdlc.yml"
RULE = "quonfig-qf1-private-key-entry"
PRIV = "qf1-" + "priv-"  # split so this file holds no rule match
PUB = "qf1-" + "pub-"


def resolve_script() -> str:
    """The `run: |` block of the "Resolve config from the base branch" step."""
    lines = WORKFLOW.read_text().splitlines()
    start = next(i for i, l in enumerate(lines) if l.strip() == "- name: Resolve config from the base branch")
    run = next(i for i in range(start, len(lines)) if lines[i].strip() == "run: |")
    body: list[str] = []
    indent = None
    for line in lines[run + 1 :]:
        if line.strip() == "":
            body.append("")
            continue
        cur = len(line) - len(line.lstrip(" "))
        if indent is None:
            indent = cur
        if cur < indent:
            break
        body.append(line[indent:])
    return "\n".join(body) + "\n"


def body(n: int = 43) -> str:
    """n base64url characters, never all from one class (looks like a real key)."""
    raw = base64.urlsafe_b64encode(secrets.token_bytes(48)).decode().rstrip("=")
    return raw[:n]


def priv(n: int = 43) -> str:
    return PRIV + body(n)


def github_pat() -> str:
    alphabet = string.ascii_letters + string.digits
    return "ghp_" + "".join(secrets.choice(alphabet) for _ in range(36))


class Repo:
    """A git repo with a base commit (optionally holding .gitleaks.toml) and a PR commit."""

    def __init__(self, root: Path, base_files: dict[str, str], pr_files: dict[str, str]) -> None:
        self.path = root / "repo"
        self.path.mkdir()
        self.git("init", "-q")
        self.write(base_files)
        self.git("add", "-A")
        self.git("commit", "-q", "--allow-empty", "-m", "base")
        self.base = self.git("rev-parse", "HEAD")
        self.write(pr_files)
        self.git("add", "-A")
        self.git("commit", "-q", "-m", "pr")
        self.head = self.git("rev-parse", "HEAD")

    def git(self, *args: str) -> str:
        env = {
            **os.environ,
            "GIT_AUTHOR_NAME": "t",
            "GIT_AUTHOR_EMAIL": "t@example.invalid",
            "GIT_COMMITTER_NAME": "t",
            "GIT_COMMITTER_EMAIL": "t@example.invalid",
            "GIT_CONFIG_GLOBAL": os.devnull,
            "GIT_CONFIG_NOSYSTEM": "1",
        }
        return subprocess.run(
            ["git", "-C", str(self.path), *args], check=True, capture_output=True, text=True, env=env
        ).stdout.strip()

    def write(self, files: dict[str, str]) -> None:
        for name, content in files.items():
            p = self.path / name
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text(content)


# CI sets REQUIRE_GITLEAKS=1 so a missing binary fails instead of skipping.
@unittest.skipUnless(shutil.which("gitleaks") or os.environ.get("REQUIRE_GITLEAKS"), "gitleaks not on PATH")
class SharedRulesTest(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = Path(tempfile.mkdtemp()).resolve()
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)

    def scan(self, pr_files: dict[str, str], base_files: dict[str, str] | None = None) -> list[dict]:
        """Resolve the config with the workflow's script, then scan base..head like the job."""
        root = self.tmp / f"case{len(list(self.tmp.iterdir()))}"
        root.mkdir()
        repo = Repo(root, base_files or {}, pr_files)
        runner_temp = root / "runner"
        runner_temp.mkdir()
        output = root / "github_output"
        output.touch()
        env = {**os.environ, "BASE_SHA": repo.base, "RUNNER_TEMP": str(runner_temp), "GITHUB_OUTPUT": str(output)}
        subprocess.run(["bash", "-c", resolve_script()], cwd=repo.path, env=env, check=True, capture_output=True)
        cfg_dir = Path(dict(l.split("=", 1) for l in output.read_text().splitlines())["dir"])
        report = root / "report.json"
        rc = subprocess.run(
            [
                "gitleaks", "git", str(repo.path),
                f"--log-opts={repo.base}..{repo.head}",
                "--config", str(cfg_dir / "gitleaks.toml"),
                "--gitleaks-ignore-path", str(cfg_dir / ".gitleaksignore"),
                "--redact", "--no-banner",
                "--report-format", "json", "--report-path", str(report),
                "--exit-code", "2",
            ],
            capture_output=True, text=True,
        )
        self.assertIn(rc.returncode, (0, 2), rc.stderr)
        return json.loads(report.read_text())

    def hits(self, findings: list[dict], rule: str = RULE) -> list[tuple[str, int]]:
        return sorted((f["File"], f["StartLine"]) for f in findings if f["RuleID"] == rule)

    # --- no .gitleaks.toml on base: defaults + shared rules -------------------

    def test_bare_entry_flagged(self) -> None:
        self.assertEqual(self.hits(self.scan({"a.txt": priv() + "\n"})), [("a.txt", 1)])

    def test_comma_separated_env_value_flags_each_entry(self) -> None:
        line = f"QUONFIG_KEYSET={priv()},{priv()}, {priv()}\n"
        f = self.scan({".env": line})
        self.assertEqual(len(self.hits(f)), 3)

    def test_json_and_yaml_flagged(self) -> None:
        f = self.scan({
            "c.json": json.dumps({"keyset": priv()}) + "\n",
            "c.yaml": f"env:\n  QUONFIG_KEYSET: \"{priv()}\"\n",
        })
        self.assertEqual(self.hits(f), [("c.json", 1), ("c.yaml", 2)])

    def test_public_entry_not_flagged(self) -> None:
        f = self.scan({"quonfig.json": json.dumps({"publicKeys": [PUB + body()]}) + "\n"})
        self.assertEqual(self.hits(f), [])

    def test_body_length(self) -> None:
        # 42 characters is not an entry and is not flagged. 44 or more is not a
        # valid entry either, but its first 43 characters match: flagged, on the
        # side of caution (a stray extra character must not hide a real key).
        f = self.scan({"short.txt": priv(42) + "\n", "long.txt": priv(44) + "\n"})
        self.assertEqual(self.hits(f), [("long.txt", 1)])

    def test_gitleaks_allow_comment_suppresses(self) -> None:
        f = self.scan({"a.py": f"KEY = \"{priv()}\"  # gitleaks:allow\n"})
        self.assertEqual(self.hits(f), [])

    def test_default_rules_still_apply(self) -> None:
        f = self.scan({"t.txt": f"token = {github_pat()}\n"})
        self.assertEqual(self.hits(f, "github-pat"), [("t.txt", 1)])

    def test_gitleaksignore_from_base_still_applies(self) -> None:
        # Same flow as today: a fingerprint on base suppresses that finding.
        entry = priv()
        first = self.scan({"a.txt": entry + "\n"})
        self.assertEqual(len(self.hits(first)), 1)
        # Rebuild with the fingerprint (commit-independent form: file:rule:line).
        ignore = f"a.txt:{RULE}:1\n"
        f = self.scan({"a.txt": entry + "\n"}, base_files={".gitleaksignore": ignore})
        self.assertEqual(self.hits(f), [])

    # --- repo with its own .gitleaks.toml on base ----------------------------

    def test_repo_config_without_rule_still_gets_it(self) -> None:
        base = {".gitleaks.toml": "[extend]\nuseDefault = true\n"}
        f = self.scan({"a.txt": priv() + "\n", "t.txt": f"token = {github_pat()}\n"}, base)
        self.assertEqual(self.hits(f), [("a.txt", 1)])
        self.assertEqual(self.hits(f, "github-pat"), [("t.txt", 1)])

    def test_repo_config_without_defaults_still_gets_rule(self) -> None:
        base = {".gitleaks.toml": textwrap.dedent("""\
            [[rules]]
            id = "own-rule"
            regex = '''own-[0-9]{6}'''
            """)}
        f = self.scan({"a.txt": f"{priv()}\nown-123456\n"}, base)
        self.assertEqual(self.hits(f), [("a.txt", 1)])
        self.assertEqual(self.hits(f, "own-rule"), [("a.txt", 2)])

    # A config-key line that generic-api-key reports (see the control test),
    # assembled at run time so this file does not trip that rule itself.
    KEY_LINE = "- key: " + '"qf1.secret.' + 'zx81kq0vwm3tbpa7j"' + "\n"
    KEY_ALLOWLIST = textwrap.dedent("""\
        [[allowlists]]
        targetRules = ["generic-api-key"]
        regexTarget = "line"
        regexes = ['''^\\s*(?:-\\s+)?"?key"?:\\s*"qf1\\.[a-z0-9.]+",?\\s*$''']
        """)

    def test_repo_config_allowlists_and_disabled_rules_still_apply(self) -> None:
        # Shape of integration-test-data's config (minus its own copy of the
        # rule): a global path allowlist for the vectors file and a
        # targetRules allowlist on a default rule, plus a disabled default
        # rule. The shared rule is added, the path allowlist covers the
        # vectors, and the targeted allowlist and disabledRules keep working.
        # (gitleaks drops the targetRules allowlists of a config pulled in
        # through [extend] path, which is why the job appends instead.)
        base = {".gitleaks.toml": textwrap.dedent("""\
            [extend]
            useDefault = true
            disabledRules = ["github-pat"]

            [[allowlists]]
            paths = ['''^tests/secrets/qf1-vectors\\.json$''']

            """) + self.KEY_ALLOWLIST}
        f = self.scan({
            "tests/secrets/qf1-vectors.json": json.dumps({"priv": priv()}) + "\n",
            "elsewhere.json": json.dumps({"priv": priv()}) + "\n",
            "t.txt": f"token = {github_pat()}\n",
            "c.yaml": self.KEY_LINE,
        }, base)
        self.assertEqual(self.hits(f), [("elsewhere.json", 1)])
        self.assertEqual(self.hits(f, "github-pat"), [])
        self.assertNotIn(("c.yaml", 1), self.hits(f, "generic-api-key"))

    def test_key_line_is_a_finding_without_the_targeted_allowlist(self) -> None:
        # Control: the test above is not vacuous.
        f = self.scan({"c.yaml": self.KEY_LINE}, {".gitleaks.toml": "[extend]\nuseDefault = true\n"})
        self.assertEqual(self.hits(f, "generic-api-key"), [("c.yaml", 1)])

    def test_repo_declaring_the_rule_id_keeps_its_declaration(self) -> None:
        # integration-test-data declares the same id itself. The job then does
        # not append a second copy: one rule, and the repo's is in force (here
        # narrowed to entries starting AAAA so the test can tell them apart).
        base = {".gitleaks.toml": textwrap.dedent(f"""\
            [extend]
            useDefault = true

            [[rules]]
            id = "{RULE}"
            description = "local copy"
            regex = '''qf1-priv-AAAA[A-Za-z0-9_-]{{39}}'''
            keywords = ["qf1-priv-"]
            """) + self.KEY_ALLOWLIST}
        f = self.scan({"a.txt": f"{PRIV}AAAA{body(39)}\n{priv()}\n", "c.yaml": self.KEY_LINE}, base)
        self.assertEqual(self.hits(f), [("a.txt", 1)])
        self.assertEqual(self.hits(f, "generic-api-key"), [])

    def test_repo_config_without_trailing_newline(self) -> None:
        f = self.scan({"a.txt": priv() + "\n"}, {".gitleaks.toml": "[extend]\nuseDefault = true"})
        self.assertEqual(self.hits(f), [("a.txt", 1)])

    def test_resolve_script_extracted(self) -> None:
        script = resolve_script()
        self.assertIn(RULE, script)
        self.assertTrue(re.search(r"^SHARED_RULES$", script, re.M), "heredoc terminator must be at column 0")


if __name__ == "__main__":
    unittest.main()
