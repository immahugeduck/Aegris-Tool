"""aegris command line.

  aegris scan  <path|owner/repo>     report only, change nothing
  aegris run   <path|owner/repo>     scan -> harden -> AI fix -> re-scan -> PR
  aegris add   <owner/repo>          register for the 30-day review cycle
  aegris remove <owner/repo>
  aegris list
  aegris due                         projects due for review today (used by the workflow)
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import tempfile
from datetime import date, timedelta
from pathlib import Path

from aegris import __version__, fixer, github, hardening, registry, report, scanners
from aegris.findings import SEVERITIES, count_by_severity, diff

DEFAULT_REGISTRY = Path(__file__).resolve().parent.parent / "registry" / "projects.json"


def _token() -> str:
    return os.environ.get("AEGRIS_TOKEN") or os.environ.get("GH_TOKEN") or os.environ.get("GITHUB_TOKEN") or ""


def _log(msg: str) -> None:
    print(f"[aegris] {msg}", file=sys.stderr, flush=True)


def _resolve(target: str, workdir: Path) -> tuple[Path, str | None, str | None]:
    """Return (local path, 'owner/repo' or None, default branch or None)."""
    repo = github.parse_repo(target)
    if repo:
        token = _token()
        if not token:
            raise github.GitHubError("A GitHub repo needs a token: set AEGRIS_TOKEN (see README).")
        dest = workdir / repo.replace("/", "__")
        _log(f"cloning {repo}")
        base = github.clone(repo, dest, token)
        return dest, repo, base
    path = Path(target).expanduser()
    if not path.is_dir():
        raise SystemExit(f"Not a directory or GitHub repo: {target}")
    return path.resolve(), None, None


def _write_outputs(out_dir: Path | None, name: str, body: str, before, after) -> None:
    if not out_dir:
        return
    d = out_dir / name.replace("/", "__")
    d.mkdir(parents=True, exist_ok=True)
    (d / "report.md").write_text(body)
    (d / "findings-before.json").write_text(json.dumps([f.to_dict() for f in before], indent=1))
    (d / "findings-after.json").write_text(json.dumps([f.to_dict() for f in after], indent=1))
    _log(f"report written to {d}")


def cmd_scan(args) -> int:
    with tempfile.TemporaryDirectory(prefix="aegris-") as tmp:
        root, repo, _ = _resolve(args.target, Path(tmp))
        res = scanners.scan(root, hardening.config_checks)
        body = report.render(
            target=repo or str(root), before=res.findings, fixed=[], remaining=res.findings, introduced=[],
            baseline=[], untracked=[], ai_summary="", ai_error="", scanners_ran=res.ran,
            scanners_skipped=res.skipped, cost_usd=None, next_due=None, scan_only=True,
        )
        if args.json:
            print(json.dumps([f.to_dict() for f in res.findings], indent=1))
        else:
            print(body)
        _write_outputs(args.out, repo or root.name, body, res.findings, res.findings)
    worst = [s for s in SEVERITIES if count_by_severity(res.findings)[s]]
    if args.fail_on and worst and SEVERITIES.index(worst[0]) <= SEVERITIES.index(args.fail_on):
        return 1
    return 0


def run_one(target: str, args) -> dict:
    reg_path: Path | None = args.registry
    reg = registry.load(reg_path) if reg_path else None
    with tempfile.TemporaryDirectory(prefix="aegris-") as tmp:
        root, repo, base = _resolve(target, Path(tmp))
        is_git = (root / ".git").exists()
        if not repo and is_git and github.has_changes(root):
            _log("warning: this folder has uncommitted changes; Aegris's edits will be mixed in with them")

        _log("scanning")
        before = scanners.scan(root, hardening.config_checks)
        _log(f"found {len(before.findings)} findings ({', '.join(before.ran)})")

        baseline = [] if args.no_harden else hardening.apply_baseline(root)

        fix = fixer.FixResult(ran=False)
        fixable = [f for f in before.findings if f.tool != "gitleaks-history"]
        if args.no_ai:
            _log("skipping AI fix stage (--no-ai)")
        elif fixable:
            _log(f"fix stage: handing {len(fixable)} findings to Claude Code")
            fix = fixer.run_fixer(root, fixable, model=args.model, max_budget_usd=args.max_budget)
            if fix.error:
                _log(f"fix stage: {fix.error}")

        untracked = []
        if is_git:
            env_files = [f.file for f in before.findings if f.rule == "tracked-env-file"]
            untracked = github.untrack(root, env_files)

        _log("re-scanning to verify")
        after = scanners.scan(root, hardening.config_checks)
        fixed, remaining, introduced = diff(before.findings, after.findings)
        _log(f"fixed {len(fixed)}, still open {len(remaining)}, new {len(introduced)}")

        next_due = None
        if reg is not None and repo:
            next_due = (date.today() + timedelta(days=int(reg["interval_days"]))).isoformat()
        changed = is_git and github.has_changes(root)
        body = report.render(
            target=repo or str(root), before=before.findings, fixed=fixed, remaining=remaining,
            introduced=introduced, baseline=baseline, untracked=untracked, ai_summary=fix.summary,
            ai_error=fix.error, scanners_ran=after.ran, scanners_skipped=after.skipped,
            cost_usd=fix.cost_usd, next_due=next_due,
            diffstat=github.diffstat(root) if changed else "",
        )
        _write_outputs(args.out, repo or root.name, body, before.findings, after.findings)

        result = {"status": "local", "before": len(before.findings), "fixed": len(fixed),
                  "after": len(after.findings), "url": None}
        if repo and not args.no_pr:
            token = _token()
            if changed:
                msg = (f"Aegris security review ({date.today().isoformat()})\n\n"
                       f"Fixed {len(fixed)} of {len(before.findings)} findings; {len(remaining)} still open.")
                github.commit_and_push(root, token, msg, keep_out=untracked)
                result.update(status="pr", url=github.upsert_pr(repo, token, base, body))
            elif after.findings:
                result.update(status="issue", url=github.upsert_issue(repo, token, body))
            else:
                result["status"] = "clean"
            _log(f"{result['status']}: {result['url'] or 'no findings'}")
        elif not repo:
            print(body)
            if changed:
                _log("changes are left uncommitted in the folder - review them with `git diff`")

        if reg is not None and repo:
            registry.record_run(reg, repo, result)
            registry.save(reg_path, reg)
    return result


def cmd_run(args) -> int:
    failures = 0
    for target in args.targets:
        try:
            run_one(target, args)
        except Exception as e:  # noqa: BLE001 - one broken project shouldn't stop the others
            failures += 1
            _log(f"{target}: FAILED - {e}")
            if args.registry and (repo := github.parse_repo(target)):
                reg = registry.load(args.registry)
                entry = reg["projects"].setdefault(repo, {"added": date.today().isoformat(), "paused": False,
                                                          "next_due": date.today().isoformat()})
                entry["last_error"] = f"{date.today().isoformat()}: {e}"[:500]
                registry.save(args.registry, reg)
    return 1 if failures else 0


def cmd_add(args) -> int:
    repo = github.parse_repo(args.repo)
    if not repo:
        raise SystemExit(f"Not a GitHub repo reference: {args.repo}")
    reg = registry.load(args.registry)
    print(f"{repo}: {'added' if registry.add(reg, repo) else 'already registered'}")
    registry.save(args.registry, reg)
    return 0


def cmd_remove(args) -> int:
    reg = registry.load(args.registry)
    repo = github.parse_repo(args.repo) or args.repo
    if reg["projects"].pop(repo, None) is None:
        print(f"{repo}: not registered")
        return 1
    registry.save(args.registry, reg)
    print(f"{repo}: removed")
    return 0


def cmd_list(args) -> int:
    reg = registry.load(args.registry)
    if not reg["projects"]:
        print("No projects registered yet.")
    for repo, e in reg["projects"].items():
        last = e.get("last_result") or {}
        state = "paused" if e.get("paused") else f"next {e.get('next_due', '?')}"
        print(f"{repo:40} last {e.get('last_run', 'never'):10}  {state:16}  "
              f"{last.get('status', '')} {last.get('url') or ''}")
    return 0


def cmd_due(args) -> int:
    for repo in registry.due(registry.load(args.registry)):
        print(repo)
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="aegris", description="Find and fix security problems in a repository.")
    p.add_argument("--version", action="version", version=f"aegris {__version__}")
    sub = p.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("scan", help="report findings without changing anything")
    s.add_argument("target", help="local folder, owner/repo, or GitHub URL")
    s.add_argument("--json", action="store_true", help="print findings as JSON")
    s.add_argument("--out", type=Path, help="also write report files here")
    s.add_argument("--fail-on", choices=SEVERITIES, help="exit 1 if anything this severe or worse is found")
    s.set_defaults(func=cmd_scan)

    r = sub.add_parser("run", help="scan, fix, verify, and open a PR")
    r.add_argument("targets", nargs="+", help="local folders, owner/repo, or GitHub URLs")
    r.add_argument("--no-ai", action="store_true", help="skip the Claude fix stage (baseline + report only)")
    r.add_argument("--no-harden", action="store_true", help="don't add dependabot/.gitignore/SECURITY.md")
    r.add_argument("--no-pr", action="store_true", help="for GitHub repos: don't push or open a PR")
    r.add_argument("--model", default=os.environ.get("AEGRIS_MODEL") or None, help="Claude model for the fix stage")
    r.add_argument("--max-budget", type=float, default=float(os.environ.get("AEGRIS_MAX_BUDGET_USD", "5")),
                   help="max AI spend per project in USD (default 5)")
    r.add_argument("--registry", type=Path, help="record the run here so it's re-reviewed in 30 days")
    r.add_argument("--out", type=Path, help="write report files here")
    r.set_defaults(func=cmd_run)

    for name, fn, helptext in (("add", cmd_add, "register a repo for the 30-day cycle"),
                               ("remove", cmd_remove, "stop reviewing a repo")):
        a = sub.add_parser(name, help=helptext)
        a.add_argument("repo")
        a.add_argument("--registry", type=Path, default=DEFAULT_REGISTRY)
        a.set_defaults(func=fn)
    for name, fn, helptext in (("list", cmd_list, "show registered projects"),
                               ("due", cmd_due, "print projects due for review today")):
        a = sub.add_parser(name, help=helptext)
        a.add_argument("--registry", type=Path, default=DEFAULT_REGISTRY)
        a.set_defaults(func=fn)
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    return args.func(args)
