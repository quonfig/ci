"""Tests for the shared Quonfig gitleaks rules in the `ssdlc / secrets` job.

They run the job's real "Resolve config from the base branch" and "Scan PR
commits (base..head)" scripts, both taken from .github/workflows/ssdlc.yml,
in throwaway git repos with a base commit and a PR commit. Needs the gitleaks
binary on PATH (the version pinned in ssdlc.yml), jq, and python3 3.11+ (the
resolve step uses tomllib). Run with:
    python3 -m unittest discover -s scripts/gitleaks

SSDLC_WORKFLOW=<path> runs the tests against another copy of ssdlc.yml (used
to check that mutations of the step go red).

No private-key-shaped literal is committed here: every qf1 entry is built at
run time from random bytes, so this file passes the gate it tests.
"""

from __future__ import annotations

import base64
import json
import os
import secrets
import shutil
import stat
import string
import subprocess
import tempfile
import textwrap
import unittest
from pathlib import Path

WORKFLOW = Path(os.environ.get("SSDLC_WORKFLOW") or Path(__file__).resolve().parents[2] / ".github" / "workflows" / "ssdlc.yml")
RESOLVE_STEP = "Resolve config from the base branch"
SCAN_STEP = "Scan PR commits (base..head)"
RULE = "quonfig-qf1-private-key-entry"
PRIV = "qf1-" + "priv-"  # split so this file holds no rule match
PUB = "qf1-" + "pub-"


def step_script(name: str) -> str:
    """The `run: |` block of the secrets job step called `name`."""
    lines = WORKFLOW.read_text().splitlines()
    start = next(i for i, l in enumerate(lines) if l.strip() == f"- name: {name}")
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
    """n random base64url characters."""
    raw = base64.urlsafe_b64encode(secrets.token_bytes(48)).decode().rstrip("=")
    return raw[:n]


def priv(n: int = 43) -> str:
    return PRIV + body(n)


def github_pat() -> str:
    alphabet = string.ascii_letters + string.digits
    return "ghp_" + "".join(secrets.choice(alphabet) for _ in range(36))


class Repo:
    """A git repo with a base commit and a PR commit. A None value deletes the file in the PR."""

    def __init__(self, root: Path, base_files: dict[str, str], pr_files: dict[str, str | None]) -> None:
        self.path = root / "repo"
        self.path.mkdir()
        self.git("init", "-q")
        self.write(base_files)
        self.git("add", "-A")
        self.git("commit", "-q", "--allow-empty", "-m", "base")
        self.base = self.git("rev-parse", "HEAD")
        self.write(pr_files)
        self.git("add", "-A")
        self.git("commit", "-q", "--allow-empty", "-m", "pr")
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

    def write(self, files: dict[str, str | None]) -> None:
        for name, content in files.items():
            p = self.path / name
            if content is None:
                p.unlink()
                continue
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text(content)


class Run:
    def __init__(self, repo: Repo, resolve: subprocess.CompletedProcess, scan: subprocess.CompletedProcess | None,
                 findings: list[dict], config: bytes | None):
        self.repo, self.resolve, self.scan, self.findings, self.config = repo, resolve, scan, findings, config


# CI sets REQUIRE_GITLEAKS=1 so a missing binary fails instead of skipping.
@unittest.skipUnless(shutil.which("gitleaks") or os.environ.get("REQUIRE_GITLEAKS"), "gitleaks not on PATH")
class SharedRulesTest(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = Path(tempfile.mkdtemp()).resolve()
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)

    def job(self, pr_files: dict[str, str | None], base_files: dict[str, str] | None = None, path_prefix: str = "",
            extra_env: dict[str, str] | None = None) -> Run:
        """Run the job's Resolve step, then (if it passed) its Scan step, like the job does."""
        root = self.tmp / f"case{len(list(self.tmp.iterdir()))}"
        root.mkdir()
        repo = Repo(root, base_files or {}, pr_files)
        runner_temp = root / "runner"
        runner_temp.mkdir()
        output = root / "github_output"
        output.touch()
        env = {
            **os.environ,
            "PATH": path_prefix + os.environ["PATH"],
            "BASE_SHA": repo.base,
            "HEAD_SHA": repo.head,
            "HAS_HOTFIX": "false",
            "RUNNER_TEMP": str(runner_temp),
            "GITHUB_OUTPUT": str(output),
            **(extra_env or {}),
        }
        resolve = subprocess.run(["bash", "-e", "-c", step_script(RESOLVE_STEP)], cwd=repo.path, env=env, capture_output=True, text=True)
        if resolve.returncode != 0:
            return Run(repo, resolve, None, [], None)
        env["CFG_DIR"] = dict(l.split("=", 1) for l in output.read_text().splitlines())["dir"]
        config = (Path(env["CFG_DIR"]) / "gitleaks.toml").read_bytes()
        scan = subprocess.run(["bash", "-e", "-c", step_script(SCAN_STEP)], cwd=repo.path, env=env, capture_output=True, text=True)
        report = runner_temp / "gitleaks-report.json"
        findings = json.loads(report.read_text()) if report.exists() and report.stat().st_size else []
        return Run(repo, resolve, scan, findings, config)

    def scan(self, pr_files: dict[str, str | None], base_files: dict[str, str] | None = None) -> list[dict]:
        """Findings of a job run that must resolve and scan cleanly; the Scan step's exit code must match."""
        r = self.job(pr_files, base_files)
        self.assertEqual(r.resolve.returncode, 0, r.resolve.stdout + r.resolve.stderr)
        self.assertEqual(r.scan.returncode, 1 if r.findings else 0, r.scan.stdout + r.scan.stderr)
        return r.findings

    def hits(self, findings: list[dict], rule: str = RULE) -> list[tuple[str, int]]:
        return sorted((f["File"], f["StartLine"]) for f in findings if f["RuleID"] == rule)

    # --- the rule (no .gitleaks.toml on base: defaults + shared rules) -------

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
        # One file with both kinds, so the keyword prefilter (qf1-priv-) lets
        # the regex see the public entry: exactly one finding, on the private one.
        f = self.scan({"keys.txt": f"{PUB}{body()}\n{priv()}\n{PUB}{body()}\n"})
        self.assertEqual(self.hits(f), [("keys.txt", 2)])

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

    def test_base_gitleaksignore_applies(self) -> None:
        # The fingerprint is in the BASE .gitleaksignore and the PR deletes the
        # file, so the head checkout has none: only the job's copy of the base
        # file (--gitleaks-ignore-path) can suppress the finding. What gitleaks
        # does with a .gitleaksignore in the PR head is bead qfg-s0ary.
        entry = priv()
        f = self.scan({"a.txt": entry + "\n", ".gitleaksignore": None},
                      base_files={".gitleaksignore": f"a.txt:{RULE}:1\n"})
        self.assertEqual(self.hits(f), [])
        # Control: without that base entry the same change is a finding.
        f = self.scan({"a.txt": entry + "\n", ".gitleaksignore": None},
                      base_files={".gitleaksignore": "other.txt:x:1\n"})
        self.assertEqual(self.hits(f), [("a.txt", 1)])

    # --- config comes from the BASE commit, never the PR ---------------------

    def test_pr_cannot_allowlist_itself_with_its_own_gitleaks_toml(self) -> None:
        allow_all = textwrap.dedent("""\
            [extend]
            useDefault = true

            [[allowlists]]
            paths = ['''.*''']
            regexes = ['''.*''']
            """)
        r = self.job({".gitleaks.toml": allow_all, "a.txt": priv() + "\n"})
        self.assertEqual(self.hits(r.findings), [("a.txt", 1)])
        self.assertEqual(r.scan.returncode, 1)

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
        # through [extend] path, which is why the job does not wrap.)
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

    def test_disabled_rules_cannot_turn_off_the_shared_rule(self) -> None:
        # disabledRules only removes rules of the config a repo extends (the
        # gitleaks defaults); the shared rule is added on top, so it stays on.
        base = {".gitleaks.toml": f'[extend]\nuseDefault = true\ndisabledRules = ["{RULE}"]\n'}
        f = self.scan({"a.txt": priv() + "\n"}, base)
        self.assertEqual(self.hits(f), [("a.txt", 1)])

    NARROW_RULE = textwrap.dedent(f"""\
        [[rules]]
        id = "{RULE}"
        description = "local copy"
        regex = '''qf1-priv-AAAA[A-Za-z0-9_-]{{39}}'''
        keywords = ["qf1-priv-"]
        """)

    def narrowed_pair(self) -> str:
        """Line 1 matches the narrowed local rule, line 2 only the shared one."""
        b = body()
        while b.startswith("AAAA"):
            b = body()
        return f"{PRIV}AAAA{body(39)}\n{PRIV}{b}\n"

    def test_repo_declaring_the_rule_id_keeps_its_declaration(self) -> None:
        # integration-test-data declares the same id itself. The shared copy is
        # not added: one rule, and the repo's is in force (here narrowed to
        # entries starting AAAA so the test can tell them apart).
        base = {".gitleaks.toml": "[extend]\nuseDefault = true\n\n" + self.NARROW_RULE + "\n" + self.KEY_ALLOWLIST}
        f = self.scan({"a.txt": self.narrowed_pair(), "c.yaml": self.KEY_LINE}, base)
        self.assertEqual(self.hits(f), [("a.txt", 1)])
        self.assertEqual(self.hits(f, "generic-api-key"), [])

    def test_quoted_id_key_is_a_declaration(self) -> None:
        # `"id" = ...` is the same TOML key as `id = ...`: the repo's rule is in force.
        base = {".gitleaks.toml": "[extend]\nuseDefault = true\n\n" + self.NARROW_RULE.replace("\nid = ", '\n"id" = ')}
        f = self.scan({"a.txt": self.narrowed_pair()}, base)
        self.assertEqual(self.hits(f), [("a.txt", 1)])

    def test_id_in_a_comment_is_not_a_declaration(self) -> None:
        base = {".gitleaks.toml": f'[extend]\nuseDefault = true\n# id = "{RULE}"\n'}
        f = self.scan({"a.txt": priv() + "\n"}, base)
        self.assertEqual(self.hits(f), [("a.txt", 1)])

    def test_id_in_a_multiline_string_is_not_a_declaration(self) -> None:
        base = {".gitleaks.toml": textwrap.dedent(f'''\
            description = """
            id = "{RULE}"
            """
            [extend]
            useDefault = true
            ''')}
        f = self.scan({"a.txt": priv() + "\n"}, base)
        self.assertEqual(self.hits(f), [("a.txt", 1)])

    def test_repo_config_without_trailing_newline(self) -> None:
        f = self.scan({"a.txt": priv() + "\n"}, {".gitleaks.toml": "[extend]\nuseDefault = true"})
        self.assertEqual(self.hits(f), [("a.txt", 1)])

    # --- fails closed ---------------------------------------------------------

    def assert_resolve_fails(self, r: Run, needle: str) -> None:
        self.assertNotEqual(r.resolve.returncode, 0)
        self.assertIsNone(r.scan)
        self.assertIn(needle, r.resolve.stdout + r.resolve.stderr)

    def test_invalid_repo_config_fails_closed(self) -> None:
        r = self.job({"a.txt": "x\n"}, {".gitleaks.toml": "[extend\nuseDefault = true\n"})
        self.assert_resolve_fails(r, "not valid TOML")

    def test_rules_not_an_array_of_tables_fails_closed(self) -> None:
        r = self.job({"a.txt": "x\n"}, {".gitleaks.toml": 'rules = "nope"\n'})
        self.assert_resolve_fails(r, "`rules` is a str, not an array of tables")

    def test_missing_tomllib_fails_closed(self) -> None:
        # A python3 without tomllib on PATH: a repo with its own config fails
        # the check with the cause; a repo without one does not need python.
        fake = self.tmp / "oldpython"
        fake.mkdir()
        py = fake / "python3"
        py.write_text("#!/bin/sh\necho 'Python 3.9.0'; exit 1\n")
        py.chmod(py.stat().st_mode | stat.S_IEXEC)
        r = self.job({"a.txt": "x\n"}, {".gitleaks.toml": "[extend]\nuseDefault = true\n"}, path_prefix=f"{fake}:")
        self.assert_resolve_fails(r, "tomllib")
        r = self.job({"a.txt": priv() + "\n"}, path_prefix=f"{fake}:")
        self.assertEqual(r.resolve.returncode, 0, r.resolve.stdout + r.resolve.stderr)
        self.assertEqual(self.hits(r.findings), [("a.txt", 1)])

    # --- unusual config shapes: append when provably right, else fail closed --

    def test_inline_rules_array_fails_closed(self) -> None:
        # `rules = [{...}]` cannot take an appended [[rules]] table.
        r = self.job({"a.txt": priv() + "\n"}, {".gitleaks.toml":
                     "rules = [{id = \"own-rule\", regex = '''own-[0-9]{6}'''}]\n[extend]\nuseDefault = true\n"})
        self.assert_resolve_fails(r, "inline array")

    def test_single_table_rules_fails_closed(self) -> None:
        r = self.job({"a.txt": priv() + "\n"}, {".gitleaks.toml":
                     "[rules]\nid = \"own-rule\"\nregex = '''own-[0-9]{6}'''\n"})
        self.assert_resolve_fails(r, "single table")

    def test_capitalised_rules_key_fails_closed(self) -> None:
        # gitleaks keeps [[Rules]] and silently ignores an added lowercase [[rules]].
        r = self.job({"a.txt": priv() + "\n"}, {".gitleaks.toml":
                     "[extend]\nuseDefault = true\n\n[[Rules]]\nid = \"own-rule\"\nregex = '''own-[0-9]{6}'''\n"})
        self.assert_resolve_fails(r, "'Rules'")

    def test_bom_fails_closed(self) -> None:
        # gitleaks itself rejects a BOM ("invalid character at start of key"),
        # so this config already failed the check before.
        r = self.job({"a.txt": priv() + "\n"}, {".gitleaks.toml": "﻿[extend]\nuseDefault = true\n"})
        self.assert_resolve_fails(r, "not valid TOML")

    def test_empty_config_gets_the_rule(self) -> None:
        r = self.job({"a.txt": priv() + "\n", "t.txt": f"token = {github_pat()}\n"}, {".gitleaks.toml": ""})
        self.assertEqual(r.resolve.returncode, 0, r.resolve.stdout + r.resolve.stderr)
        self.assertEqual(self.hits(r.findings), [("a.txt", 1)])
        self.assertEqual(self.hits(r.findings, "github-pat"), [])  # an empty config has no defaults

    def test_uppercase_id_key_is_a_declaration(self) -> None:
        # gitleaks reads keys case-insensitively: `ID = ...` declares the rule,
        # so the file is used byte for byte.
        base = {".gitleaks.toml": "[extend]\nuseDefault = true\n\n" + self.NARROW_RULE.replace("\nid = ", "\nID = ")}
        r = self.job({"a.txt": self.narrowed_pair()}, base)
        self.assertEqual(self.hits(r.findings), [("a.txt", 1)])
        self.assertEqual(r.config, base[".gitleaks.toml"].encode())

    def test_per_rule_allowlists_survive(self) -> None:
        base = {".gitleaks.toml": textwrap.dedent("""\
            [extend]
            useDefault = true

            [[rules]]
            id = "own-rule"
            regex = '''own-[0-9]{6}'''

            [[rules.allowlists]]
            paths = ['''^b\\.txt$''']
            """)}
        f = self.scan({"a.txt": f"{priv()}\nown-123456\n", "b.txt": f"own-123456\n{priv()}\n"}, base)
        self.assertEqual(self.hits(f, "own-rule"), [("a.txt", 2)])
        # The appended block is a new top-level rule, not part of own-rule:
        # own-rule's per-rule allowlist does not hide it in b.txt.
        self.assertEqual(self.hits(f), [("a.txt", 1), ("b.txt", 2)])

    def test_last_table_extend_gets_a_top_level_rule(self) -> None:
        base = {".gitleaks.toml": "[[rules]]\nid = \"own-rule\"\nregex = '''own-[0-9]{6}'''\n\n[extend]\nuseDefault = true"}
        f = self.scan({"a.txt": f"{priv()}\nown-123456\n"}, base)
        self.assertEqual(self.hits(f), [("a.txt", 1)])
        self.assertEqual(self.hits(f, "own-rule"), [("a.txt", 2)])

    def test_allow_everything_repo_config_fails_the_self_check(self) -> None:
        # A base config whose allowlist hides everything would hide the shared
        # rule too: the step's self-check fails closed instead of scanning.
        base = {".gitleaks.toml": "[extend]\nuseDefault = true\n\n[[allowlists]]\npaths = ['''.*''']\n"}
        r = self.job({"a.txt": priv() + "\n"}, base)
        self.assert_resolve_fails(r, "self-check failed")

    def test_python_cannot_be_hijacked_from_the_pr(self) -> None:
        # The PR plants modules python would import from the checkout, or from
        # PYTHONPATH/PYTHONSTARTUP pointed at the checkout as a hostile
        # environment would. Each leaves a marker; the fake tomllib also makes
        # the config look "declared" so the shared rule would be skipped.
        # None may run, and the planted secrets must still be reported.
        markers = self.tmp / "markers"
        markers.mkdir()

        def planted(name: str, extra: str = "") -> str:
            return f"import pathlib\npathlib.Path({str(markers / name)!r}).write_text('ran')\n{extra}"

        fake_tomllib = planted("tomllib", (
            "class TOMLDecodeError(Exception):\n    pass\n"
            f"def loads(s, **k):\n    return {{'rules': [{{'id': {RULE!r}}}]}}\n"
            "def load(f, **k):\n    return loads('')\n"))
        pr = {
            "a.txt": priv() + "\n",
            "t.txt": f"token = {github_pat()}\n",
            "tomllib.py": fake_tomllib,
            "json.py": planted("json"),
            "sitecustomize.py": planted("sitecustomize"),
            "usercustomize.py": planted("usercustomize"),
        }
        checkout = self.tmp / f"case{len(list(self.tmp.iterdir()))}" / "repo"
        hostile = {"PYTHONPATH": str(checkout), "PYTHONSTARTUP": str(checkout / "json.py"), "PYTHONINSPECT": "1"}
        r = self.job(pr, {".gitleaks.toml": "[extend]\nuseDefault = true\n"}, extra_env=hostile)
        self.assertEqual(r.repo.path, checkout)
        self.assertEqual(sorted(p.name for p in markers.iterdir()), [])
        self.assertEqual(r.resolve.returncode, 0, r.resolve.stdout + r.resolve.stderr)
        self.assertEqual(self.hits(r.findings), [("a.txt", 1)])
        self.assertEqual(self.hits(r.findings, "github-pat"), [("t.txt", 1)])
        self.assertEqual(r.scan.returncode, 1)

    # --- fidelity: the repo's bytes are never rewritten -----------------------

    FIDELITY_CONFIGS = {
        "plain": "[extend]\nuseDefault = true\n",
        "own rules, per-rule and targeted allowlists": textwrap.dedent("""\
            title = "x"
            [extend]
            useDefault = true
            disabledRules = ["github-pat"]

            [[rules]]
            id = "own-rule"
            regex = '''own-[0-9]{6}'''
            [[rules.allowlists]]
            paths = ['''^b\\.txt$''']

            [[allowlists]]
            targetRules = ["generic-api-key"]
            regexTarget = "line"
            regexes = ['''^\\s*(?:-\\s+)?"?key"?:\\s*"qf1\\.[a-z0-9.]+",?\\s*$''']
            """),
        "CRLF, line break inside a rule regex":
            "[extend]\r\nuseDefault = true\r\n\r\n[[rules]]\r\nid = \"own-rule\"\r\n"
            "regex = '''\r\nown-[0-9]{6}|zz\r\nqq'''\r\n",
        "CRLF, line break inside an allowlist regex":
            "[extend]\r\nuseDefault = true\r\n\r\n[[rules]]\r\nid = \"own-rule\"\r\nregex = '''own-[0-9]{6}'''\r\n"
            "[[rules.allowlists]]\r\nregexes = ['''\r\nown-111111\r\n|own-222222''']\r\n",
        "last table [[rules.allowlists]], no trailing newline":
            "[extend]\nuseDefault = true\n\n[[rules]]\nid = \"own-rule\"\nregex = '''own-[0-9]{6}'''\n"
            "[[rules.allowlists]]\nregexes = ['''own-222222''']",
        "id only in a comment and a string":
            f'# id = "{RULE}"\ndescription = """\nid = "{RULE}"\n"""\n[extend]\nuseDefault = true\n',
        "empty": "",
    }

    def fidelity_corpus(self) -> dict[str, str]:
        return {
            "a.txt": f"{priv()}\nown-123456\nown-111111\nown-222222\ntoken = {github_pat()}\n",
            "b.txt": f"own-123456\n{priv()}\n",
            "c.yaml": self.KEY_LINE,
        }

    def test_fidelity_bytes_kept_and_findings_superset(self) -> None:
        for i, (name, text) in enumerate(self.FIDELITY_CONFIGS.items()):
            with self.subTest(config=name):
                original = text.encode()
                r = self.job(self.fidelity_corpus(), {".gitleaks.toml": text})
                self.assertEqual(r.resolve.returncode, 0, r.resolve.stdout + r.resolve.stderr)
                self.assertTrue(r.config.startswith(original), "the repo's bytes must be kept as they are")
                # Findings with the repo's original config alone, same range.
                cfg = self.tmp / f"orig-{i}.toml"
                cfg.write_bytes(original)
                report = self.tmp / f"orig-{i}.json"
                subprocess.run(["gitleaks", "git", str(r.repo.path), f"--log-opts={r.repo.base}..{r.repo.head}",
                                "--config", str(cfg), "--gitleaks-ignore-path", str(self.tmp / "none"), "--no-banner",
                                "--report-format", "json", "--report-path", str(report), "--exit-code", "0"],
                               check=True, capture_output=True)

                def key(f: dict) -> tuple[str, int, str]:
                    return (f["File"], f["StartLine"], f["RuleID"])

                before = {key(f) for f in json.loads(report.read_text())}
                after = {key(f) for f in r.findings}
                self.assertLessEqual(before, after)
                self.assertEqual({k for k in after - before if k[2] != RULE}, set())
                self.assertIn(("a.txt", 1, RULE), after)

    def test_steps_extracted(self) -> None:
        self.assertIn(RULE, step_script(RESOLVE_STEP))
        self.assertIn("gitleaks git .", step_script(SCAN_STEP))


if __name__ == "__main__":
    unittest.main()
