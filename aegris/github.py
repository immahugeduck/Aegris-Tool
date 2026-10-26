"""Clone a GitHub repo, push the fix branch, and open or update the PR.

The token is passed to git per command as an HTTP header, so it is never
written into the clone's .git/config where the fix stage could read it.
"""

from __future__ import annotations

import base64
import json
import os
import re
import subprocess
from pathlib import Path

BRANCH = "aegris/security"
PR_TITLE = "Aegris: security fixes"
ISSUE_TITLE = "Aegris: security review findings"
BOT_NAME = "Aegris"
BOT_EMAIL = "aegris-bot@users.noreply.github.com"

_REPO_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9-]{0,38}/[A-Za-z0-9._-]{1,100}$")


class GitHubError(RuntimeError):
    pass


def parse_repo(target: str) -> str | None:
    """'owner/repo', 'https://github.com/owner/repo(.git)' or 'git@github.com:owner/repo.git'
    -> 'owner/repo'. Returns None if it isn't a GitHub repo reference."""
    t = target.strip()
    m = re.match(r"^(?:https?://github\.com/|git@github\.com:)([^/]+/[^/#?]+?)(?:\.git)?/?$", t)
    if m:
        t = m.group(1)
    elif "://" in t or t.startswith((".", "/", "~")) or Path(t).exists():
        return None
    return t if _REPO_RE.match(t) and not t.endswith((".", "..")) else None


def _auth_args(token: str) -> list[str]:
    basic = base64.b64encode(f"x-access-token:{token}".encode()).decode()
    return ["-c", f"http.https://github.com/.extraheader=AUTHORIZATION: basic {basic}"]


def _git(args: list[str], cwd: Path | None = None, token: str | None = None) -> str:
    cmd = ["git", *(_auth_args(token) if token else []), *args]
    proc = subprocess.run(cmd, cwd=cwd, capture_output=True, text=True)
    if proc.returncode != 0:
        msg = (proc.stderr or proc.stdout).strip()
        if token:
            msg = msg.replace(token, "***")
        raise GitHubError(f"git {args[0]} failed: {msg[-500:]}")
    return proc.stdout


def _gh(args: list[str], token: str, repo: str) -> str:
    env = dict(os.environ, GH_TOKEN=token)
    proc = subprocess.run(["gh", *args, "--repo", repo], capture_output=True, text=True, env=env)
    if proc.returncode != 0:
        raise GitHubError(f"gh {' '.join(args[:2])} failed: {(proc.stderr or proc.stdout).strip()[-500:]}")
    return proc.stdout


def clone(repo: str, dest: Path, token: str) -> str:
    """Full clone (gitleaks needs history). Returns the default branch name."""
    _git(["clone", "--quiet", f"https://github.com/{repo}.git", str(dest)], token=token)
    head = _git(["symbolic-ref", "--short", "refs/remotes/origin/HEAD"], cwd=dest).strip()
    return head.removeprefix("origin/")


def has_changes(root: Path) -> bool:
    return bool(_git(["status", "--porcelain"], cwd=root).strip())


def untrack(root: Path, paths: list[str]) -> list[str]:
    done = []
    for p in paths:
        try:
            _git(["rm", "--cached", "--quiet", "--", p], cwd=root)
            done.append(p)
        except GitHubError:
            pass
    return done


def diffstat(root: Path) -> str:
    return _git(["status", "--short"], cwd=root).strip()


def commit_and_push(root: Path, token: str, message: str, keep_out: list[str] = ()) -> None:
    _git(["checkout", "-B", BRANCH], cwd=root)
    _git(["add", "-A"], cwd=root)
    if keep_out:
        # `add -A` would re-stage files Aegris just untracked (e.g. .env) if
        # .gitignore doesn't cover them.
        _git(["rm", "--cached", "--quiet", "--ignore-unmatch", "--", *keep_out], cwd=root)
    _git(["-c", f"user.name={BOT_NAME}", "-c", f"user.email={BOT_EMAIL}", "commit", "--quiet", "-m", message], cwd=root)
    # The branch is owned by Aegris and rebuilt from the default branch on every
    # review, so a force push is expected here.
    _git(["push", "--force", "--quiet", "origin", f"HEAD:refs/heads/{BRANCH}"], cwd=root, token=token)


def upsert_pr(repo: str, token: str, base: str, body: str) -> str:
    existing = json.loads(_gh(["pr", "list", "--head", BRANCH, "--state", "open", "--json", "url"], token, repo) or "[]")
    body_file = Path(os.environ.get("RUNNER_TEMP", "/tmp")) / "aegris-pr-body.md"
    body_file.write_text(body)
    if existing:
        url = existing[0]["url"]
        _gh(["pr", "edit", url, "--body-file", str(body_file)], token, repo)
        _gh(["pr", "comment", url, "--body", "Aegris re-reviewed this repository and updated this PR."], token, repo)
        return url
    return _gh(["pr", "create", "--head", BRANCH, "--base", base, "--title", PR_TITLE,
                "--body-file", str(body_file)], token, repo).strip()


def upsert_issue(repo: str, token: str, body: str) -> str:
    """Used when there are open findings but no code changes to propose."""
    existing = json.loads(_gh(["issue", "list", "--state", "open", "--search", f'"{ISSUE_TITLE}" in:title',
                               "--json", "url,title"], token, repo) or "[]")
    existing = [i for i in existing if i["title"] == ISSUE_TITLE]
    body_file = Path(os.environ.get("RUNNER_TEMP", "/tmp")) / "aegris-issue-body.md"
    body_file.write_text(body)
    if existing:
        url = existing[0]["url"]
        _gh(["issue", "edit", url, "--body-file", str(body_file)], token, repo)
        return url
    return _gh(["issue", "create", "--title", ISSUE_TITLE, "--body-file", str(body_file)], token, repo).strip()
