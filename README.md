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

(Later beads add `ssdlc / deps`, `ssdlc / sast`.)

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

## Hotfix override

Adding the `hotfix` label to a PR always overrides the gate: `sanity` passes
without running the AI, and `secrets` reports findings as warnings but passes,
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
