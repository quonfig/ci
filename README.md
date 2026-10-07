# quonfig/ci

Shared CI for the Quonfig org: the SSDLC pull-request gate required by the
SOC 2 Secure Software Development Lifecycle policy (epic `qfg-66ko`).

This repo is private. Its Actions access level is **organization**, so any
quonfig repo can call its reusable workflows and composite actions.

## How repos use it

Each in-scope repo has one thin caller, `.github/workflows/ssdlc.yml`, copied
from [`templates/ssdlc.yml`](templates/ssdlc.yml):

```yaml
jobs:
  ssdlc:
    uses: quonfig/ci/.github/workflows/ssdlc.yml@main
    secrets: inherit
```

It triggers on `pull_request` (`opened, synchronize, reopened, ready_for_review,
labeled, unlabeled`). All logic lives here in
[`.github/workflows/ssdlc.yml`](.github/workflows/ssdlc.yml); changing it here
changes every repo at once. This repo gates its own PRs with
[`.github/workflows/ssdlc-pr.yml`](.github/workflows/ssdlc-pr.yml).

### Required status checks

When branch protection is turned on (deferred; the org is on the Free plan),
require these check names, as shown on a PR for a caller whose job id is
`ssdlc`:

| Check | Job |
|-------|-----|
| `ssdlc / sanity` | AI sanity check |
| `ssdlc / secrets` | gitleaks scan of the PR's commits |
| `ssdlc / deps` | osv-scanner dependency vulnerability scan |
| `ssdlc / sast` | Semgrep CE static analysis |

A caller that sets `deps: false` or `sast: false` reports that check as
skipped, which satisfies a required check.

## Jobs

### `sanity`: AI sanity check

A cheap, basic check, not a full code review.

- Model `claude-haiku-4-5-20251001`, at most 6 turns, read-only tools
  (`Read, Grep, Glob`), via `anthropics/claude-code-action@v1`.
- Prompt: the calling repo's `.github/claude-sanity-prompt.md` if present,
  otherwise the default
  [`.github/actions/sanity-prompt/prompt.md`](.github/actions/sanity-prompt/prompt.md).
  The workflow appends the fixed output contract (diff location, last line
  `VERDICT: PASS|WARN|BLOCK`), so a repo prompt only needs the review criteria.
- Findings go to one sticky PR comment, updated in place on each run.
- **Only `VERDICT: BLOCK` fails the check.** WARN and PASS pass. A missing
  verdict line passes with a warning annotation.
- Draft PRs are skipped. Marking the PR ready for review runs the check.
- Budget guard: diffs over 3000 changed lines (additions + deletions) skip the
  AI and pass with a notice. The diff handed to the model is also capped at
  200 KB.
- Label changes: adding or removing a label other than `hotfix` does **not**
  re-run the AI. The job re-reports the last sanity verdict on the same commit
  (so adding an unrelated label cannot turn a BLOCK green).
- If `ANTHROPIC_API_KEY` is empty or not visible to the repo, the check fails
  with a clear message rather than silently passing. On the GitHub Free plan
  org secrets do not reach private repos, so private repos need a repo secret.

Inputs (all optional): `max_changed_lines` (3000), `model`, `max_turns` (6).

### `secrets`: gitleaks secret scan

- Runs the [gitleaks](https://github.com/gitleaks/gitleaks) CLI binary (not
  `gitleaks-action`, which needs a paid license for orgs), pinned to a release
  and verified against a pinned SHA-256 (`GITLEAKS_VERSION` /
  `GITLEAKS_SHA256` in the workflow; bump both together from the release's
  `checksums.txt`).
- Scans only the PR's own commits, `base.sha..head.sha`, so findings already in
  history do not fail every PR. Secrets are redacted in logs; findings show as
  annotations with rule, file, line and commit.
- Fails on any finding. Runs on every PR event including drafts and label
  changes (it is cheap and deterministic).
- Per-repo tuning, optional: `.gitleaks.toml` (start it with
  `[extend]` / `useDefault = true` to keep the default rules) and/or
  `.gitleaksignore` (one finding fingerprint per line; the failing run prints
  them). Both are read from the **base** commit, never from the PR, so a PR
  cannot allowlist its own leak; a change to them takes effect once merged.
  An inline `gitleaks:allow` comment on the line also works and is visible in
  review.
- A real leaked credential must be rotated; removing it from the branch is not
  enough once it has been pushed.

GitHub secret scanning and push protection are also enabled on every public
in-scope repo (repo settings). Private repos would need paid GHAS for that,
so this job is the control there.

### `deps`: dependency vulnerability scan

Scans every lockfile and manifest in the repo at the PR head (the whole
dependency tree, not just the diff, so a newly published advisory shows up on
the next PR) and fails only on **HIGH/CRITICAL** findings that are not ignored.

- Engine: [osv-scanner](https://github.com/google/osv-scanner) v2 for every
  ecosystem, pinned and SHA-256 verified (`OSV_VERSION` / `OSV_SHA256` in
  [`.github/actions/deps-scan/action.yml`](.github/actions/deps-scan/action.yml)).
  The policy layer is
  [`deps_scan.py`](.github/actions/deps-scan/deps_scan.py) (stdlib only,
  Python 3.11+).
- HIGH/CRITICAL means: the advisory group's highest CVSS score is >= 7.0, or
  GitHub rates the advisory HIGH or CRITICAL (this covers advisories that have
  no CVSS vector). Lower severities are not reported here; Dependabot covers
  them.
- Dev dependencies are enforced like runtime ones. pnpm and yarn lockfiles do
  not mark dev-only packages reliably, so a dev exemption would only work for
  npm, and test/build tooling runs in CI next to secrets.
- Results: one annotation per finding (package, advisory, severity, fixed
  version, lockfile) plus a table in the job summary. GitHub shows at most 10
  annotations of each level per step; the log and the summary have them all.
- Manifests that resolve to no packages (Gradle without dependency locking,
  Swift without a committed `Package.resolved`, .NET central package
  management without `packages.lock.json`, a `pyproject.toml` with no lock)
  produce a warning saying they are **not scanned**.

Ecosystem coverage and why osv-scanner everywhere instead of each native tool:

| Ecosystem | Detected from | Checker | Why |
|-----------|---------------|---------|-----|
| npm / pnpm / yarn | `package-lock.json`, `pnpm-lock.yaml`, `yarn.lock` | osv-scanner | Same GitHub advisory data as `npm/pnpm/yarn audit`, but no package-manager install, one behaviour across all three (yarn 1 vs berry audit differ), and offline lockfile parsing. |
| Go | `go.mod` | osv-scanner with call analysis | osv-scanner v2 embeds the govulncheck engine: vulns whose vulnerable symbols are never called are reported as warnings, not failures, exactly like `govulncheck`. Go is set up from the repo's `go.mod` for this. |
| Ruby | `Gemfile.lock` | osv-scanner | bundler-audit uses ruby-advisory-db, which is also ingested by OSV; no Ruby toolchain needed. |
| Python | `poetry.lock`, `uv.lock`, `requirements*.txt` | osv-scanner | pip-audit needs an installed environment; OSV includes PyPA's advisory DB. |
| .NET | `packages.lock.json`, `*.csproj` with inline versions | osv-scanner | `dotnet list package --vulnerable` needs a restore. Central package management needs `packages.lock.json` to be scanned. |
| Java | `pom.xml`, `gradle.lockfile` | osv-scanner | Maven resolves transitives via deps.dev. Gradle needs dependency locking enabled. |
| Swift | `Package.resolved` | osv-scanner | No mature native auditor. |

One engine means one severity rule, one ignore file format and one output
format for the SOC 2 evidence, whatever the language.

#### Ignoring a finding

Put an `osv-scanner.toml` at the repo root (osv-scanner's own format, so a
local `osv-scanner scan source -r .` honours it too):

```toml
[[IgnoredVulns]]
id = "GHSA-xxxx-xxxx-xxxx"        # GHSA, CVE or GO- id; any alias matches
ignoreUntil = 2026-12-31          # optional but expected; expired = enforced again
reason = "Not reachable: we never parse untrusted YAML. Upgrade tracked in qfg-xxxx."
```

- `reason` is **mandatory**. An entry without one, or any other table such as
  `[[PackageOverrides]]`, fails the check as a config error.
- The file is read from the **PR head**, unlike the gitleaks config. A
  dependency ignore exposes nothing by being pushed, the entry is in the diff
  for the reviewer and the AI sanity check, and a new advisory must be
  ignorable in the same PR that it starts failing. Nested
  `osv-scanner.toml` files are not honoured.

#### Enforcement rollout

Inputs: `deps` (default `true`) runs the job; `deps_enforce` (default
**`false`** for now) makes findings fail the check. Report-only mode posts the
same annotations and summary but the check passes.

All in-scope repos, SDKs included, run the scan (`deps: true`). The SDK
findings are real (mostly stale transitive JS packages and test tooling, fixed
by a lockfile refresh), not false-positive noise, and an SDK ships to
customers, so it gets the same control. Enforcement is off by default only
because every JS repo already has HIGH/CRITICAL findings; once that backlog is
fixed (bead `qfg-66ko.3` follow-up), flip the `deps_enforce` default to `true`
here and every repo is gated at once. A repo that wants enforcement earlier
sets `deps_enforce: true` in its caller.

To run the check locally before pushing (any OS; needs Python 3.11+):

```bash
# download osv-scanner_<os>_<arch> from the pinned release, then from the repo root:
python3 path/to/ci/.github/actions/deps-scan/deps_scan.py --osv-bin ./osv-scanner --repo .
```

Run it on a clean clone: osv-scanner skips git-ignored paths, and a sub-repo
nested inside the gitignored monorepo checkout looks ignored to it.

### `sast`: Semgrep static analysis

Lightweight SAST with [Semgrep CE](https://semgrep.dev) (no account, no token,
`--metrics=off`), using the high-confidence `p/ci` registry ruleset. CodeQL on
private repos needs paid GHAS, so Semgrep is the control here.

- Install: `pip install semgrep==<SEMGREP_VERSION>` into a venv on the runner
  (pinned in the workflow env; bump deliberately). The `p/ci` rules are
  fetched from the Semgrep registry at run time.
- **Only ERROR-severity findings fail the check** (semgrep's newer
  `HIGH`/`CRITICAL` levels count as ERROR). WARNING/INFO findings are listed
  in the job summary and the log but pass.
- **Diff-aware**: the scan runs with `--baseline-commit <merge base>`, so only
  findings the PR introduces are reported. Pre-existing findings never block.
- Findings show as annotations (rule, file, line) plus a table in the job
  summary. Files semgrep cannot fully parse are counted, not failed.
- Runs on every PR event, drafts and label changes included (deterministic).
- A semgrep tool failure (registry unreachable, bad config) fails the check
  with a clear "tool error" message; re-run it or use the hotfix label.
- Input: `sast` (default `true`).

False positives, per repo, both visible in the PR diff:

- Inline, on the flagged line, with a reason:
  `foo() // nosemgrep: <rule-id> -- why this is safe`
  (`# nosemgrep: ...` in YAML/Python/Ruby).
- A root `.semgrepignore` (semgrep's own gitignore-style format) to exclude
  paths such as generated code or fixtures. Start it with
  `:include .gitignore`, because a repo `.semgrepignore` replaces semgrep's
  built-in default ignores. Read from the PR head, like `osv-scanner.toml`.

The caller template's own `secrets: inherit` carries a reasoned `nosemgrep`
(the `secrets-inherit` rule is ERROR in `p/ci`): the callee is this
first-party workflow and declares only `ANTHROPIC_API_KEY`.

Run it locally the same way before pushing:

```bash
pip install semgrep==1.179.0
semgrep scan --config p/ci --metrics=off --baseline-commit "$(git merge-base origin/main HEAD)"
semgrep scan --config p/ci --metrics=off --severity ERROR   # full scan
```

## Hotfix override

Adding the `hotfix` label to a PR always overrides the gate: `sanity` passes
without running the AI, and `secrets`, `deps` and `sast` report findings as
warnings but pass,
so Jeff is never hard-blocked. On the first hotfix run
the workflow posts one comment asking for:

1. a justification comment on the PR, and
2. a follow-up bead for skipped review or tests,

both within **2 business days**. Removing the label re-runs the AI.

## Monthly hotfix audit

Evidence for the SPO review: list every merged hotfix-labeled PR across the org.

```bash
scripts/hotfix-report.sh                      # previous calendar month
scripts/hotfix-report.sh 2026-10-01 2026-10-31
```

which wraps:

```bash
gh search prs --owner quonfig --label hotfix --merged \
  --merged-at 2026-10-01..2026-10-31 --limit 200
```

For each PR, confirm the justification comment and follow-up bead exist.

## Notes

- Callers pin `@main`. A change merged here takes effect on the next PR event
  in every repo. The composite action is also referenced at `@main`, so prompt
  changes in a ci PR only take effect after merge.
- `.github/actions/sanity-prompt` exists because a caller's `GITHUB_TOKEN`
  cannot check out this private repo; composite actions are downloaded with the
  whole repo, which makes the default `prompt.md` reachable.
