# quonfig/ci

Shared CI for the Quonfig org: the SSDLC pull-request gate required by the
SOC 2 Secure Software Development Lifecycle policy (epic `qfg-66ko`).

This repo is public, so every quonfig repo, public or private, can call its
reusable workflows and composite actions (a public repo cannot call a private
repo's workflows). It holds no secrets: callers pass `ANTHROPIC_API_KEY` in.

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

- One Messages API call per PR: model `claude-sonnet-5-5` at effort `medium`,
  the diff **inline** in the user message, **no tools**, no agent turns, and a
  **structured verdict** (JSON schema: up to 5 findings, each `BLOCK` or
  `WARN` with `file:line`). The code is
  [`scripts/sanity/sanity_review.py`](scripts/sanity/sanity_review.py)
  (Python stdlib only, so the job installs nothing). The job checks it out
  from quonfig/ci `main`. A quonfig/ci PR uses the PR head instead, so a change
  to the reviewer is tested on the PR that makes it.
- The verdict is derived from the findings: BLOCK only if at least one finding
  is BLOCK, WARN if there is any finding, PASS otherwise. A bare
  "verdict: BLOCK" with no BLOCK finding cannot fail a PR.
- Why not the old agent setup (Haiku 4.5 + `claude-code-action`, 6 turns,
  `Read, Grep, Glob`): the model spent its turns opening the diff file and
  exploring the repo, and hit `error_max_turns` on small diffs (openfeature-go
  run 38151833384: 7 turns in 14 s; also openfeature-node#17), which passed
  silently as WARN. Its free-text `VERDICT:` line also flip-flopped on the same
  diff (sdk-react-native#40 BLOCK then PASS). See
  [Model choice](#model-choice-replay-set).
- Prompt: the calling repo's `.github/claude-sanity-prompt.md` **as it is on
  the PR's base commit** (`pull_request.base.sha`, read via the contents API),
  otherwise the default
  [`.github/actions/sanity-prompt/prompt.md`](.github/actions/sanity-prompt/prompt.md).
  Reading from the base means a PR can never rewrite its own review: a PR that
  changes the prompt is reviewed by the old one, and the new prompt applies
  from the next PR after merge. The workflow appends the fixed output contract
  (diff location, last line `VERDICT: PASS|WARN|BLOCK`), so a repo prompt only
  needs the review criteria. The sticky comment footer names the prompt used
  (`repo@<base sha>` or `default`).
- Version numbers and dependency floors are WARN at most, never BLOCK (house
  policy, in every prompt): raising a dependency, peer-dependency, `engines` or
  language-version floor, and patch vs minor vs major. Raising the floor of a
  first-party Quonfig package within the same major is a patch or minor.
- Findings go to one sticky PR comment, updated in place on each run.
- **Only `VERDICT: BLOCK` fails the check.** WARN and PASS pass. A missing
  verdict line passes with a warning annotation.
- AI infrastructure failures never fail the check: if the review does not
  finish (API error after retries, a refusal, unparseable output, a crash) the
  check passes as a non-blocking `WARN` with a warning annotation and a sticky
  comment saying so. Re-run the job for a real review. Each API attempt times
  out after 90 s, with 3 retries.
- Draft PRs are skipped. Marking the PR ready for review runs the check.
- Lockfiles and generated files are stripped from the diff before it reaches
  the model (`package-lock.json`, `npm-shrinkwrap.json`, `pnpm-lock.yaml`,
  `yarn.lock`, `go.sum`, `poetry.lock`, `Gemfile.lock`, any `*.lock`,
  `Package.resolved`, `packages.lock.json`, `bun.lockb`, `*.min.js`,
  `*.min.css`, `*.js.map`, `*.css.map`; matched on the file name). The prompt
  lists what was omitted. Dependency changes stay covered by the `deps` job.
  If nothing reviewable remains (a lockfile-only or empty diff) the AI is
  skipped and the check passes with a notice.
- Budget guard: more than 3000 reviewable changed lines (counted after
  stripping) skips the AI and passes with a notice, as does a diff too large
  for the GitHub diff API. The diff handed to the model is also capped at
  200 KB. The diff is fenced in `<diff>` tags and the fixed output contract
  tells the model it is untrusted data, never instructions.
- Label changes: adding or removing a label other than `hotfix` or
  `ssdlc-approved` does **not** re-run the AI. The job re-reports the last
  sanity verdict on the same commit (so adding an unrelated label cannot turn
  a BLOCK green). See [Overrides](#overrides) for those two labels.
- If `ANTHROPIC_API_KEY` is empty or not visible to the repo, the check fails
  with a clear message rather than silently passing. On the GitHub Free plan
  org secrets do not reach private repos, so private repos need a repo secret.
- **Dependabot PRs**: runs triggered by Dependabot (`github.actor ==
  dependabot[bot]`) get only Dependabot secrets, never Actions secrets, so the
  AI cannot run. The check is skipped and passes with a notice. The dependency
  change is still gated by the `deps` (osv-scanner), `secrets` (gitleaks) and
  `sast` (Semgrep) jobs. If a human pushes a commit to the Dependabot branch,
  that run is a normal AI review.
- **Fork PRs** (public repos): GitHub never passes secrets to `pull_request`
  runs from a fork, so the check fails with a message saying so. A maintainer
  reviews the PR by hand, then adds the `ssdlc-approved` label to pass the
  check. On a fork PR the token is read-only, so if the attribution comment
  cannot be posted the job warns instead of failing.

Inputs (all optional): `max_changed_lines` (3000), `model`
(`claude-sonnet-5-5`), `effort` (`medium`), `confirm_block` (`false`: when
true, a BLOCK is re-sampled and fails only on 2 of 3). `max_turns` is
deprecated and ignored.

#### Model choice (replay set)

[`scripts/sanity/replay.py`](scripts/sanity/replay.py) replays real PRs
through `sanity_review.py` (the same request CI sends: the repo prompt from the
PR's base commit plus the lockfile-stripped diff), several times per model.
The set is [`scripts/sanity/replay-set.tsv`](scripts/sanity/replay-set.tsv):

- 4 known-bad throwaway PRs: hard-coded `sk_live_` key (app-quonfig#9), `DROP
  TABLE` migration (ci#11), removed public exports (openfeature-go#7), and SQL
  built from request input (api-delivery#16, "should flag": api-delivery's
  prompt puts injection below its BLOCK bar, and `sast` owns it).
- 12 real clean or judgment-call PRs, including the flip-flop and
  peer-floor cases (sdk-react-native#40, openfeature-node#16,
  openfeature-python#8).
- 5 seeded bugs in real public-repo PRs ([`mutations.json`](scripts/sanity/mutations.json)):
  an inverted condition, a dead branch, a dropped nil-safe call, an AND that
  passes failing assertions, and a hard-coded production SDK key.

Run it from the monorepo root (diffs are fetched with `gh` into a temp cache,
never into this public repo):

```bash
qfg run -w mhw-works/our-config --environment development \
  --env ANTHROPIC_API_KEY=anthropic.api-key.github-ci -- \
  python3 ci/scripts/sanity/replay.py --runs 5 --variants sonnet55-medium,haiku45-temp0
```

Results, 2026-10-12, 21 PRs x 5 runs per variant (qfg-66ko.16). "Same gate"
means the PR got the same fail/pass outcome on every run. Catch rate is the
share of runs that BLOCKed a must-block PR (3 throwaways + the seeded key).
Flag rate is the share of runs that returned WARN or BLOCK on a should-flag PR.
Noise is the share of runs on clean PRs that returned WARN. Cost uses list
prices: Haiku 4.5 $1/$5, Haiku 5.5 $0.10/$0.50, Sonnet 5.5 $2/$10, Opus 5.5
$4/$20, Fable 5.1 $10/$50 per million input/output tokens.

| Variant | Same verdict every run | Same gate every run | Catch rate | Flag rate | False BLOCK (clean) | Noise (WARN on clean) | Latency p50 / p90 | Cost per PR |
|---|---|---|---|---|---|---|---|---|
| Haiku 4.5, old free-text verdict (baseline) | 12/21 | 18/21 | 100% | 76% | 5% | 15% | 5.6s / 11.7s | $0.005 |
| Haiku 4.5, structured, temperature 0 | 21/21 | 21/21 | **75%** | 80% | 0% | 16% | 2.0s / 6.5s | $0.004 |
| Haiku 5.5, structured, effort low | 17/21 | 20/21 | 100% | 100% | 0% | **88%** | 3.5s / 7.3s | $0.0007 |
| **Sonnet 5.5, structured, effort medium** | 16/21 | 19/21 | 100% | 100% | 0% | 11% | 3.3s / 8.2s | **$0.012** |
| Sonnet 5.5, structured, effort low | 17/21 | 20/21 | 100% | 100% | 0% | 30% | 3.3s / 5.7s | $0.011 |
| Opus 5.5, structured, effort medium | 15/21 | 19/21 | 100% | 100% | 0% | 26% | 5.7s / 12.8s | $0.026 |
| Fable 5.1, structured, effort low | 17/21 | 19/21 | 100% | 100% | 0% | 25% | 4.5s / 14.7s | $0.063 |

For comparison, the old agent path cost $0.020 to $0.046 per PR (median about
$0.025, from `total_cost_usd` in 10 recent sanity runs), mostly the agent's own
system prompt sent on every turn.

What it showed:

- **The structured verdict fixes the flip-flop.** The old free-text contract
  BLOCKed clean ci#7 on 3 of 5 runs. With the structured verdict no variant
  BLOCKed a clean PR in 60 runs each. Every "same gate" miss above is a
  should-flag seeded bug that moved between WARN and BLOCK, where either is
  acceptable. Must-block and clean PRs got the same gate on every run.
- **Temperature 0** makes Haiku 4.5 fully repeatable (21/21 identical
  verdicts, vs 14/21 at temperature 1), but repeatably wrong: it returned WARN
  on all 10 runs for the hard-coded production SDK key, and PASS on all 5 for
  the dropped nil-safe call. The 5.x models reject a temperature other than 1,
  so they rely on the structured verdict.
- **A confirming second sample is not needed by default.** It only changes
  anything when the first sample BLOCKs, and the replay set had no false
  BLOCKs to suppress. It would mainly turn borderline real bugs into WARN.
  It stays available as `confirm_block: true`.
- **Haiku 5.5** catches everything at a tenth of a cent, but WARNs on 88% of
  clean PRs. Some of those WARNs contradict the house floor policy, and a
  check that always WARNs gets ignored.
- **Sonnet 5.5 at medium** has the same catch and flag rates as Opus 5.5 and
  Fable 5.1, with the least noise and the lowest cost of the three. Its
  findings name the line and the consequence. At low effort it hedges more
  (30% noise) for the same price.

Decision: **Sonnet 5.5, effort medium.** About $0.004 to $0.026 per PR on this
set (mean $0.012), roughly half of the old Haiku agent path, and well under the
$0.02 to $0.10 budget.

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

Scans every lockfile and manifest in the repo at the PR head, and again at
the PR's merge base. It fails only on **HIGH/CRITICAL** findings that are not
ignored **and that the PR introduces**.

- **Diff-aware.** A finding already on the base branch (same ecosystem,
  package, lockfile and advisory id) is reported as a warning and listed as
  "already on the base branch" in the summary, but it does not fail the PR.
  So a newly published advisory against a dependency on `main` does not block
  every unrelated PR in that repo. It is fixed in its own PR (a bump or an
  `osv-scanner.toml` ignore). The version is not part of the match, so bumping
  to another still-affected version is not a new finding.
- A PR fails when it adds a vulnerable package, adds a new advisory to an
  existing package, adds the vulnerable package to another lockfile, or makes
  a Go vuln reachable that was "not called" on the base.
- Fail closed: if the merge base cannot be found, checked out or scanned, every
  finding is enforced, as before.

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
# diff-aware, like CI: add a checkout of the merge base
git worktree add --detach /tmp/deps-base "$(git merge-base origin/main HEAD)"
python3 path/to/ci/.github/actions/deps-scan/deps_scan.py --osv-bin ./osv-scanner --repo . --base-repo /tmp/deps-base
```

The policy script's tests: `python3 -m unittest discover -s .github/actions/deps-scan`.

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

## Overrides

Two labels override a failing check. Only a human applies either one, after
reading the finding; agents never apply them.

| Label | Relaxes | Scope | Follow-up |
|-------|---------|-------|-----------|
| `ssdlc-approved` | `sanity` only | the head commit it was added on | none; the attribution comment is the evidence |
| `hotfix` | all four checks | every run while the label is on | justification comment + bead within 2 business days |

### `ssdlc-approved`: accept an AI sanity finding

Use it when the AI sanity check BLOCKs and a human disagrees with or accepts
the finding (for example a judgment call the model got wrong).

- Adding the label makes `ssdlc / sanity` pass on the PR's current head commit
  without running the AI, and posts (or updates in place) one PR comment:
  "AI sanity finding overridden by @<who added the label> via
  `ssdlc-approved` on <full sha>". That comment is the audit evidence; no
  follow-up bead is needed.
- `secrets`, `deps` and `sast` are **not** relaxed.
- The approval is tied to that commit. It only exists in the check result of
  the run triggered by the `labeled` event. A new push runs the AI review
  normally, even with the label still on. If that run BLOCKs, remove and
  re-add the label to approve the new commit.
- Removing the label re-runs the AI review, so the check is enforced again.
- A label added by a bot account (`sender.type == Bot`) fails instead of
  approving. Agents acting through a human's token are not detectable this
  way; for them "humans only" is policy.

### `hotfix`: emergency override

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
  in every repo. Re-running a job does not pick up a change: it reuses the
  workflow version of the original run. Push a commit, or close and reopen. The composite action is also referenced at `@main`, so prompt
  changes in a ci PR only take effect after merge. The reviewer script
  (`scripts/sanity/`) is checked out at the PR head on quonfig/ci's own PRs,
  so reviewer changes are tested before merge.
- `.github/actions/sanity-prompt` exists so the default `prompt.md` ships
  with the workflow: composite actions are downloaded with the whole repo, so
  the caller never has to check out quonfig/ci itself.
