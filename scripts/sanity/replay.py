#!/usr/bin/env python3
"""Replay real PRs through the SSDLC sanity review, several times per model.

Measures, per model variant: verdict consistency across runs, catch rate on
known-bad PRs, false-BLOCK rate on clean PRs, latency and cost per PR. Every
request is built by sanity_review.py, the same code the CI job runs.

Usage (from the monorepo root, so direnv provides QUONFIG_ENCRYPTION_KEY):
  qfg run -w mhw-works/our-config --environment development \\
    --env ANTHROPIC_API_KEY=anthropic.api-key.github-ci -- \\
    python3 ci/scripts/sanity/replay.py --runs 5 \\
      --variants haiku45-temp0,haiku55-medium ...

Inputs: replay-set.tsv next to this file. Diffs and prompts are fetched with
`gh` into --cache (default under $TMPDIR) and never written into this repo:
most of the PRs are in private repos and this repo is public.

Output: samples.jsonl and summary.md in --out.
"""

import argparse
import concurrent.futures as cf
import json
import os
import re
import statistics
import subprocess
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import sanity_review as sr  # noqa: E402

HERE = os.path.dirname(os.path.abspath(__file__))
DEFAULT_PROMPT = os.path.join(HERE, "..", "..", ".github", "actions", "sanity-prompt", "prompt.md")

# $ per million tokens (input, output), from the claude-api skill model table
# cached 2026-10-06. Haiku 5.5 is the <=100K-token prompt rate.
PRICES = {
    "claude-haiku-4-5": (1.00, 5.00),
    "claude-haiku-5-5": (0.10, 0.50),
    "claude-sonnet-5-5": (2.00, 10.00),
    "claude-opus-5-5": (4.00, 20.00),
    "claude-fable-5-1": (10.00, 50.00),
}

# name -> (model, effort, temperature, legacy contract)
VARIANTS = {
    "haiku45-legacy": ("claude-haiku-4-5", None, None, True),
    "haiku45-temp1": ("claude-haiku-4-5", None, None, False),
    "haiku45-temp0": ("claude-haiku-4-5", None, 0.0, False),
    "haiku55-low": ("claude-haiku-5-5", "low", None, False),
    "haiku55-medium": ("claude-haiku-5-5", "medium", None, False),
    "sonnet55-low": ("claude-sonnet-5-5", "low", None, False),
    "sonnet55-medium": ("claude-sonnet-5-5", "medium", None, False),
    "opus55-medium": ("claude-opus-5-5", "medium", None, False),
    "fable51-low": ("claude-fable-5-1", "low", None, False),
}

# A made-up key for the seeded-secret case, assembled at runtime so the secrets
# scanner does not flag this repo.
FAKE_SDK_KEY = "qf_sk_" + "prod_7Hc2mQx9Lw4R" + "t8Vb1Nz6Kp3Ys5Dg0Fj2"

LOCK_RE = re.compile(
    r"^(package-lock\.json|npm-shrinkwrap\.json|pnpm-lock\.yaml|yarn\.lock|go\.sum|poetry\.lock"
    r"|Gemfile\.lock|Package\.resolved|packages\.lock\.json|bun\.lockb)$"
)


def is_generated(path):
    """Mirror of the awk gen() filter in .github/workflows/ssdlc.yml."""
    b = path.rsplit("/", 1)[-1]
    return bool(
        LOCK_RE.match(b) or b.endswith(".lock") or re.search(r"\.min\.(js|css)$", b)
        or re.search(r"\.(js|css)\.map$", b)
    )


def strip_diff(raw):
    out, skipped, skip = [], [], False
    for line in raw.splitlines(keepends=True):
        if line.startswith("diff --git "):
            path = re.sub(r"^diff --git a/.* b/", "", line.rstrip("\n"))
            skip = is_generated(path)
            if skip:
                skipped.append(path)
        if not skip:
            out.append(line)
    return "".join(out), skipped


def gh(*args, attempts=3):
    for i in range(attempts):
        r = subprocess.run(["gh", *args], capture_output=True, text=True)
        if r.returncode == 0:
            return r.stdout
        if "404" in r.stderr:
            break
    raise subprocess.CalledProcessError(r.returncode, ["gh", *args], r.stdout, r.stderr)


def load_mutations():
    with open(os.path.join(HERE, "mutations.json"), encoding="utf-8") as f:
        return json.load(f)


def fetch_case(ref, cache):
    """Fetch (and cache) one PR: stripped diff, skipped files, base-commit prompt.

    A ref like `cli#8~inverted` is a seeded-bug variant of cli#8: the real diff
    with the replacements from mutations.json applied (public repos only).
    """
    if "~" in ref:
        base = fetch_case(ref.split("~")[0], cache)
        mut = load_mutations()[ref]
        diff = base["diff"]
        for old, new in mut["replace"]:
            if diff.count(old) != 1:
                raise SystemExit("mutation %s: expected exactly one match for %r" % (ref, old))
            diff = diff.replace(old, new.replace("{FAKE_SDK_KEY}", FAKE_SDK_KEY))
        return dict(base, ref=ref, diff=diff)
    path = os.path.join(cache, ref.replace("#", "_") + ".json")
    if os.path.exists(path):
        with open(path, encoding="utf-8") as f:
            return json.load(f)
    repo, num = ref.split("#")
    full = "quonfig/" + repo
    meta = json.loads(gh("api", "repos/%s/pulls/%s" % (full, num)))
    raw = gh("pr", "diff", num, "--repo", full)
    diff, skipped = strip_diff(raw)
    base = meta["base"]["sha"]
    try:
        prompt = gh("api", "-H", "Accept: application/vnd.github.raw",
                    "repos/%s/contents/.github/claude-sanity-prompt.md?ref=%s" % (full, base))
        source = "repo@" + base[:7]
    except subprocess.CalledProcessError:
        prompt = ""
    if not prompt.strip():
        with open(DEFAULT_PROMPT, encoding="utf-8") as f:
            prompt = f.read()
        source = "default"
    case = {"ref": ref, "repo": full, "pr": num, "title": meta["title"], "diff": diff,
            "skipped": skipped, "prompt": prompt, "prompt_source": source}
    with open(path, "w", encoding="utf-8") as f:
        json.dump(case, f)
    return case


def cost(model, usage):
    pin, pout = PRICES[model]
    return (usage.get("input_tokens", 0) * pin + usage.get("output_tokens", 0) * pout) / 1e6


def pct(n, d):
    return "n/a" if d == 0 else "%d%%" % round(100.0 * n / d)


def summarize(samples, cases, variants):
    rows = []
    detail = []
    for v in variants:
        model = VARIANTS[v][0]
        vs = [s for s in samples if s["variant"] == v]
        ok = [s for s in vs if s["status"] == "ok"]
        errors = len(vs) - len(ok)
        n = {"BLOCK": 0, "FLAG": 0, "NOBLOCK": 0}
        hit = {"BLOCK": 0, "FLAG": 0, "NOBLOCK": 0}  # BLOCK / not-PASS / BLOCK
        prs = {"BLOCK": 0, "FLAG": 0, "NOBLOCK": 0}
        total = {k: sum(c["expect"] == k for c in cases) for k in n}
        consistent_verdict = consistent_gate = 0
        for c in cases:
            cs = [s["verdict"] for s in ok if s["ref"] == c["ref"]]
            if not cs:
                continue
            consistent_verdict += len(set(cs)) == 1
            consistent_gate += len(set(x == "BLOCK" for x in cs)) == 1
            e = c["expect"]
            h = sum((x != "PASS") if e == "FLAG" else (x == "BLOCK") for x in cs)
            n[e] += len(cs)
            hit[e] += h
            # BLOCK/FLAG: caught on a majority of runs. NOBLOCK: BLOCKed at least once.
            prs[e] += (h > 0) if e == "NOBLOCK" else (h * 2 > len(cs))
            detail.append((v, c["ref"], e, " ".join(x[0] for x in cs)))
        secs = sorted(s["seconds"] for s in ok)
        costs = [cost(model, s["usage"]) for s in ok]
        rows.append([
            v,
            "%d/%d" % (consistent_verdict, len(cases)),
            "%d/%d" % (consistent_gate, len(cases)),
            "%s (%d/%d PRs)" % (pct(hit["BLOCK"], n["BLOCK"]), prs["BLOCK"], total["BLOCK"]),
            "%s (%d/%d PRs)" % (pct(hit["FLAG"], n["FLAG"]), prs["FLAG"], total["FLAG"]),
            "%s (%d/%d PRs)" % (pct(hit["NOBLOCK"], n["NOBLOCK"]), prs["NOBLOCK"], total["NOBLOCK"]),
            "%.1fs / %.1fs" % (statistics.median(secs), secs[int(round(0.9 * (len(secs) - 1)))]) if secs else "n/a",
            "$%.4f" % (sum(costs) / len(costs)) if costs else "n/a",
            str(errors),
        ])
    head = ["variant", "same verdict every run", "same gate every run",
            "catch rate (BLOCK on must-block)", "flag rate (WARN+ on should-flag)",
            "false-BLOCK rate (clean)", "latency p50 / p90", "cost per PR", "AI errors"]
    md = ["| " + " | ".join(head) + " |", "|" + "---|" * len(head)]
    md += ["| " + " | ".join(r) + " |" for r in rows]
    md += ["", "Per-PR verdicts (P/W/B per run):", "",
           "| variant | PR | expect | runs |", "|---|---|---|---|"]
    md += ["| %s | %s | %s | %s |" % d for d in detail]
    return "\n".join(md)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--set", default=os.path.join(HERE, "replay-set.tsv"))
    ap.add_argument("--runs", type=int, default=5)
    # Comma-separated lists, not repeated flags: `qfg run` reorders repeated
    # flags in the child's argv.
    ap.add_argument("--variants", help="comma-separated; one of: " + ", ".join(sorted(VARIANTS)))
    ap.add_argument("--only", help="comma-separated PRs to run, as repo/pr")
    ap.add_argument("--parallel", type=int, default=8)
    ap.add_argument("--cache", default=os.path.join(tempfile.gettempdir(), "sanity-replay-cache"))
    ap.add_argument("--out", default=os.path.join(tempfile.gettempdir(), "sanity-replay-out"))
    ap.add_argument("--fetch-only", action="store_true")
    ap.add_argument("--from-samples", help="comma-separated samples.jsonl files: "
                    "summarize earlier runs without calling the API")
    a = ap.parse_args()
    variants = a.variants.split(",") if a.variants else [
        "haiku45-temp0", "haiku55-medium", "sonnet55-medium", "fable51-low", "opus55-medium"]
    for v in variants:
        if v not in VARIANTS:
            ap.error("unknown variant %s" % v)
    only = a.only.split(",") if a.only else None
    os.makedirs(a.cache, exist_ok=True)
    os.makedirs(a.out, exist_ok=True)

    cases = []
    with open(a.set, encoding="utf-8") as f:
        for line in f:
            if not line.strip() or line.startswith("#"):
                continue
            ref, expect, note = (line.rstrip("\n").split("\t") + ["", ""])[:3]
            if only and ref.replace("#", "/") not in only:
                continue
            c = fetch_case(ref, a.cache)
            c.update(expect=expect, note=note)
            cases.append(c)
            print("%-22s %-7s %5d diff lines, prompt %s" % (
                ref, expect, c["diff"].count("\n"), c["prompt_source"]), file=sys.stderr)
    if a.fetch_only:
        return 0
    if a.from_samples:
        samples = []
        for path in a.from_samples.split(","):
            with open(path, encoding="utf-8") as f:
                samples += [json.loads(l) for l in f if l.strip()]
        refs = set(c["ref"] for c in cases)
        samples = [s for s in samples if s["ref"] in refs and s["variant"] in variants]
        for s in samples:  # expectations come from the current replay-set.tsv
            s["expect"] = next(c["expect"] for c in cases if c["ref"] == s["ref"])
        md = summarize(samples, cases, variants)
        with open(os.path.join(a.out, "summary.md"), "w", encoding="utf-8") as f:
            f.write(md + "\n")
        print(md)
        return 0

    api_key = os.environ.get("ANTHROPIC_API_KEY", "")
    if not api_key:
        print("ANTHROPIC_API_KEY is not set (run under `qfg run`, see --help)", file=sys.stderr)
        return 2

    jobs = []
    for c in cases:
        for v in variants:
            model, effort, temp, legacy = VARIANTS[v]
            system, user = sr.build_messages(c["prompt"], c["diff"], c["skipped"],
                                             c["repo"], c["pr"], legacy=legacy)
            for i in range(a.runs):
                jobs.append((c, v, i, model, effort, temp, legacy, system, user))

    samples_path = os.path.join(a.out, "samples.jsonl")
    samples = []

    def run(job):
        c, v, i, model, effort, temp, legacy, system, user = job
        s = sr.review_once(model, system, user, api_key, effort=effort,
                           temperature=temp, legacy=legacy)
        s.update(ref=c["ref"], expect=c["expect"], variant=v, run=i, model=model)
        return s

    with cf.ThreadPoolExecutor(max_workers=a.parallel) as pool, \
            open(samples_path, "a", encoding="utf-8") as out:
        for n, s in enumerate(pool.map(run, jobs), 1):
            samples.append(s)
            out.write(json.dumps(s) + "\n")
            out.flush()
            print("[%d/%d] %-16s %-22s run %d -> %s %s %.1fs" % (
                n, len(jobs), s["variant"], s["ref"], s["run"], s["verdict"],
                s["status"] if s["status"] != "ok" else "", s["seconds"]), file=sys.stderr)

    md = summarize(samples, cases, variants)
    with open(os.path.join(a.out, "summary.md"), "w", encoding="utf-8") as f:
        f.write(md + "\n")
    print(md)
    return 0


if __name__ == "__main__":
    sys.exit(main())
