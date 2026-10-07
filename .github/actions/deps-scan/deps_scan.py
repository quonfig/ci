#!/usr/bin/env python3
"""SSDLC dependency vulnerability gate (SOC 2, bead qfg-66ko.3).

Runs osv-scanner over every lockfile/manifest in the repo, then applies the
Quonfig policy on top of its JSON output:

  * fail only on HIGH/CRITICAL: highest CVSS score >= 7.0, or a GitHub
    advisory severity of HIGH/CRITICAL (covers advisories with no CVSS);
  * Go: osv-scanner's call analysis (the govulncheck engine) runs by default;
    a vuln whose vulnerable symbols are never called is reported, not failed;
  * dev dependencies are enforced like runtime ones (pnpm/yarn lockfiles do
    not mark them reliably, and test/build tooling runs in CI with secrets);
  * per-repo ignores live in osv-scanner.toml at the repo root as
    [[IgnoredVulns]] entries; every entry MUST carry a non-empty `reason`, and
    an entry past its `ignoreUntil` stops applying;
  * --hotfix (the PR's `hotfix` label) and --report-only (the caller's
    deps_enforce: false) downgrade every failure to a warning.

Needs Python 3.11+ (tomllib). Usage:
  deps_scan.py --osv-bin PATH [--repo DIR] [--hotfix] [--report-only]
  deps_scan.py --osv-json FILE [--repo DIR] ...   # evaluate a saved scan
Exit status: 0 pass, 1 policy failure, 2 tool/config error.
"""

from __future__ import annotations

import argparse
import datetime as dt
import json
import os
import subprocess
import sys
import tempfile
import tomllib
from pathlib import Path

HIGH_SCORE = 7.0
BLOCKING_LABELS = {"HIGH", "CRITICAL"}
IGNORE_FILE = "osv-scanner.toml"

# Manifest names we recognise, for the "found but not scanned" report.
MANIFESTS = {
    "package.json": "npm",
    "go.mod": "Go",
    "Gemfile": "RubyGems",
    "pyproject.toml": "PyPI",
    "requirements.txt": "PyPI",
    "pom.xml": "Maven",
    "build.gradle": "Gradle",
    "build.gradle.kts": "Gradle",
    "Package.swift": "SwiftPM",
    "Cargo.toml": "crates.io",
    "composer.json": "Packagist",
}
SKIP_DIRS = {"node_modules", "vendor", ".git", "dist", "build", ".next"}


class GH:
    """GitHub Actions annotations when running in Actions, plain text otherwise."""

    in_actions = os.environ.get("GITHUB_ACTIONS") == "true"

    @classmethod
    def emit(cls, level: str, msg: str, file: str | None = None) -> None:
        if cls.in_actions:
            loc = f" file={file}," if file else " "
            print(f"::{level}{loc}title=SSDLC deps::{msg}")
        else:
            print(f"[{level}] {file + ': ' if file else ''}{msg}")


def load_ignores(repo: Path, today: dt.date) -> tuple[dict[str, dict], list[str]]:
    """Return ({id: entry}, [config errors]) from the repo's osv-scanner.toml."""
    path = repo / IGNORE_FILE
    if not path.exists():
        return {}, []
    try:
        data = tomllib.loads(path.read_text())
    except tomllib.TOMLDecodeError as e:
        return {}, [f"{IGNORE_FILE} is not valid TOML: {e}"]
    errors: list[str] = []
    unsupported = sorted(set(data) - {"IgnoredVulns"})
    if unsupported:
        errors.append(
            f"{IGNORE_FILE}: only [[IgnoredVulns]] is supported by the SSDLC gate, found {unsupported}"
        )
    ignores: dict[str, dict] = {}
    for i, entry in enumerate(data.get("IgnoredVulns", []), 1):
        vid = str(entry.get("id", "")).strip()
        reason = str(entry.get("reason", "")).strip()
        if not vid:
            errors.append(f"{IGNORE_FILE}: IgnoredVulns entry #{i} has no id")
            continue
        if not reason:
            errors.append(f"{IGNORE_FILE}: IgnoredVulns entry {vid} has no reason (mandatory)")
            continue
        until = entry.get("ignoreUntil")
        if until is not None:
            until_date = until.date() if isinstance(until, dt.datetime) else until
            if not isinstance(until_date, dt.date):
                errors.append(f"{IGNORE_FILE}: {vid} ignoreUntil must be a TOML date or datetime")
                continue
            if until_date < today:
                GH.emit("warning", f"ignore for {vid} expired on {until_date}; it no longer applies")
                continue
        ignores[vid] = {"reason": reason, "until": str(until) if until else "none"}
    return ignores, errors


def run_osv(osv_bin: str, repo: Path, out: Path) -> int:
    # An empty --config stops osv-scanner from honouring nested
    # osv-scanner.toml files, so the reason requirement cannot be sidestepped;
    # the root file's ignores are applied by this script instead.
    empty_cfg = out.parent / "osv-empty.toml"
    empty_cfg.write_text("")
    cmd = [
        osv_bin, "scan", "source", "-r",
        "--config", str(empty_cfg),
        "--all-packages",
        "--format", "json", "--output-file", str(out),
        str(repo),
    ]
    print("+", " ".join(cmd), flush=True)
    return subprocess.run(cmd).returncode


def severity(group: dict, vulns_by_id: dict[str, dict]) -> tuple[float | None, str]:
    score = None
    raw = group.get("max_severity") or ""
    try:
        score = float(raw) if raw else None
    except ValueError:
        score = None
    labels = []
    for vid in group.get("ids", []):
        label = (vulns_by_id.get(vid, {}).get("database_specific") or {}).get("severity")
        if isinstance(label, str):
            labels.append(label.upper())
    order = ["LOW", "MODERATE", "MEDIUM", "HIGH", "CRITICAL"]
    label = max(labels, key=lambda s: order.index(s) if s in order else -1, default="")
    return score, label


def fixed_versions(group: dict, vulns_by_id: dict[str, dict]) -> str:
    fixed: set[str] = set()
    for vid in group.get("ids", []):
        for aff in vulns_by_id.get(vid, {}).get("affected", []) or []:
            for rng in aff.get("ranges", []) or []:
                for ev in rng.get("events", []) or []:
                    if "fixed" in ev:
                        fixed.add(ev["fixed"])
    return ", ".join(sorted(fixed)[:4]) or "no fix yet"


def manifest_dirs(repo: Path) -> dict[Path, list[str]]:
    found: dict[Path, list[str]] = {}
    for root, dirs, files in os.walk(repo):
        dirs[:] = [d for d in dirs if d not in SKIP_DIRS and not d.startswith(".")]
        for f in files:
            if f in MANIFESTS or f.endswith(".csproj"):
                found.setdefault(Path(root), []).append(f)
    return found


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--repo", default=".")
    ap.add_argument("--osv-bin")
    ap.add_argument("--osv-json")
    ap.add_argument("--hotfix", action="store_true")
    ap.add_argument("--report-only", action="store_true")
    ap.add_argument("--summary", default=os.environ.get("GITHUB_STEP_SUMMARY"))
    args = ap.parse_args()
    repo = Path(args.repo).resolve()
    today = dt.datetime.now(dt.timezone.utc).date()

    ignores, cfg_errors = load_ignores(repo, today)
    for e in cfg_errors:
        GH.emit("error", e, IGNORE_FILE)
    if cfg_errors:
        GH.emit("error", f"fix {IGNORE_FILE}: the deps check cannot run with an invalid ignore file")
        return 2

    if args.osv_json:
        report_path = Path(args.osv_json)
    else:
        if not args.osv_bin:
            ap.error("--osv-bin or --osv-json is required")
        tmp = Path(tempfile.mkdtemp(prefix="ssdlc-deps-"))
        report_path = tmp / "osv.json"
        rc = run_osv(args.osv_bin, repo, report_path)
        if rc == 128:
            report_path = None  # no package sources at all
        elif rc not in (0, 1):
            GH.emit("error", f"osv-scanner failed (exit {rc})")
            return 2

    results = []
    if report_path is not None:
        results = json.loads(report_path.read_text()).get("results") or []

    # Which directories yielded at least one package.
    scanned_dirs: set[Path] = set()
    sources = []
    for res in results:
        src = Path(res["source"]["path"])
        n = len(res.get("packages") or [])
        sources.append((src, n))
        if n:
            scanned_dirs.add(src if src.is_dir() else src.parent)

    print("Dependency sources scanned:")
    for src, n in sources:
        print(f"  {src.relative_to(repo) if src.is_relative_to(repo) else src}: {n} packages")
    if not sources:
        print("  (none)")

    unscanned = []
    for d, files in sorted(manifest_dirs(repo).items()):
        if d not in scanned_dirs:
            rel = d.relative_to(repo)
            for f in sorted(files):
                unscanned.append(str(rel / f))
    for f in unscanned:
        GH.emit(
            "warning",
            "manifest found but no packages resolved (no supported lockfile, e.g. Gradle without "
            "dependency locking, Swift without Package.resolved, .NET central package management "
            "without packages.lock.json); these dependencies are NOT scanned",
            f,
        )

    blocking, reported, ignored_hits = [], [], []
    for res in results:
        src = Path(res["source"]["path"])
        rel_src = str(src.relative_to(repo)) if src.is_relative_to(repo) else str(src)
        for pkg in res.get("packages") or []:
            groups = pkg.get("groups") or []
            if not groups:
                continue
            vulns_by_id = {v["id"]: v for v in pkg.get("vulnerabilities") or []}
            p = pkg["package"]
            for g in groups:
                ids = set(g.get("ids", [])) | set(g.get("aliases", []))
                analysis = g.get("experimental_analysis") or {}
                if analysis and all(a.get("unimportant") for a in analysis.values()):
                    continue
                score, label = severity(g, vulns_by_id)
                # Either signal is enough: CVSS >= 7.0, or GitHub rates it HIGH/CRITICAL.
                high = (score is not None and score >= HIGH_SCORE) or label in BLOCKING_LABELS
                if not high:
                    continue
                # Prefer a GHSA id; fall back to any alias if a group has no ids.
                primary = sorted(g.get("ids") or ids or ["UNKNOWN"], key=lambda x: (not x.startswith("GHSA"), x))[0]
                row = {
                    "id": primary,
                    "ids": sorted(ids),
                    "pkg": f"{p['name']}@{p.get('version', '?')}",
                    "eco": p.get("ecosystem", "?"),
                    "sev": f"{score if score is not None else '-'} {label}".strip(),
                    "fixed": fixed_versions(g, vulns_by_id),
                    "file": rel_src,
                    "why": "",
                }
                hit = next((ignores[i] for i in sorted(ids) if i in ignores), None)
                if hit:
                    row["why"] = f"ignored: {hit['reason']} (until {hit['until']})"
                    ignored_hits.append(row)
                    continue
                if analysis and all(a.get("called") is False for a in analysis.values()):
                    row["why"] = "not called (Go call analysis)"
                    reported.append(row)
                else:
                    blocking.append(row)

    def line(r: dict) -> str:
        return f"{r['pkg']} ({r['eco']}): {r['id']} severity {r['sev']}, fixed in {r['fixed']}"

    soft = args.hotfix or args.report_only
    status = "hotfix" if args.hotfix else ("would block" if args.report_only else "BLOCK")
    for r in blocking:
        GH.emit("warning" if soft else "error", line(r), r["file"])
    for r in reported:
        GH.emit("warning", f"{line(r)} [not enforced: {r['why']}]", r["file"])
    for r in ignored_hits:
        GH.emit("notice", f"{line(r)} [{r['why']}]", r["file"])

    if args.summary:
        with open(args.summary, "a") as fh:
            fh.write("### SSDLC deps: HIGH/CRITICAL dependency vulnerabilities\n\n")
            if args.report_only:
                fh.write("Report-only mode (`deps_enforce: false`): findings do not fail the check.\n\n")
            fh.write(f"Sources scanned: {len([s for s in sources if s[1]])}. ")
            fh.write(f"Blocking: {len(blocking)}. Reported only: {len(reported)}. Ignored: {len(ignored_hits)}.\n\n")
            rows = [(r, status) for r in blocking]
            rows += [(r, r["why"]) for r in reported + ignored_hits]
            if rows:
                fh.write("| Status | Package | Advisory | Severity | Fixed in | File |\n|---|---|---|---|---|---|\n")
                for r, st in rows:
                    fh.write(f"| {st} | `{r['pkg']}` | {r['id']} | {r['sev']} | {r['fixed']} | `{r['file']}` |\n")
            if unscanned:
                fh.write("\nNot scanned (no supported lockfile): " + ", ".join(f"`{u}`" for u in unscanned) + "\n")

    print(
        f"\nSummary: {len(blocking)} blocking, {len(reported)} reported-only, "
        f"{len(ignored_hits)} ignored, {len(unscanned)} unscanned manifest(s)."
    )
    if not blocking:
        GH.emit("notice", "no unignored HIGH/CRITICAL vulnerabilities in enforced dependencies")
        return 0
    if args.hotfix:
        GH.emit("warning", f"{len(blocking)} HIGH/CRITICAL finding(s) not enforced because of the hotfix label")
        return 0
    if args.report_only:
        GH.emit("warning", f"{len(blocking)} HIGH/CRITICAL finding(s); report-only mode (deps_enforce: false), not failing")
        return 0
    GH.emit(
        "error",
        f"{len(blocking)} HIGH/CRITICAL dependency vulnerabilit{'y' if len(blocking) == 1 else 'ies'}. "
        f"Upgrade to a fixed version, or add an [[IgnoredVulns]] entry with id, reason and ignoreUntil "
        f"to {IGNORE_FILE}. Add the 'hotfix' label to override.",
    )
    return 1


if __name__ == "__main__":
    sys.exit(main())
