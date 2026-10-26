"""Repository-level checks and the baseline protections Aegris adds itself.

The baseline additions are deterministic (no AI involved): they only add
files or lines that are missing and never rewrite existing content.
"""

from __future__ import annotations

import re
import subprocess
from pathlib import Path

from aegris.findings import Finding

SKIP_DIRS = {".git", "node_modules", "vendor", ".venv", "venv", "dist", "build", ".next", "target", "__pycache__"}

GITIGNORE_LINES = [".env", ".env.*", "!.env.example", "!.env.sample", "*.pem", "*.key", "*.p12", "*.pfx"]
GITIGNORE_HEADER = "# Secrets - added by Aegris"

# manifest file -> dependabot package-ecosystem
ECOSYSTEMS = {
    "package.json": "npm",
    "requirements.txt": "pip",
    "pyproject.toml": "pip",
    "Pipfile": "pip",
    "go.mod": "gomod",
    "Cargo.toml": "cargo",
    "Gemfile": "bundler",
    "composer.json": "composer",
    "pom.xml": "maven",
    "build.gradle": "gradle",
    "build.gradle.kts": "gradle",
    "Dockerfile": "docker",
}

SECURITY_MD = """# Security Policy

## Reporting a vulnerability

Please don't open a public issue for security problems. Report them privately
through this repository's **Security** tab -> **Report a vulnerability**, or
contact the maintainer directly.

You can expect an acknowledgement within a few days. Please include steps to
reproduce and the impact you believe the issue has.

## Automated review

This repository is reviewed by [Aegris](https://github.com/immahugeduck/Aegris-Tool)
roughly every 30 days for leaked secrets, vulnerable dependencies and insecure code.
"""


def _walk(root: Path):
    for path in root.rglob("*"):
        rel = path.relative_to(root)
        if any(part in SKIP_DIRS for part in rel.parts):
            continue
        yield path, rel


def _tracked_files(root: Path) -> list[str]:
    if not (root / ".git").exists():
        return []
    proc = subprocess.run(["git", "-C", str(root), "ls-files"], capture_output=True, text=True)
    return proc.stdout.splitlines() if proc.returncode == 0 else []


# --- checks ---------------------------------------------------------------------

def _jobs_without_permissions(workflow: str) -> list[str]:
    """Job names that set no `permissions:` of their own. A workflow without a
    top-level block is still fine if every job limits itself."""
    lines = workflow.splitlines()
    try:
        start = next(i for i, ln in enumerate(lines) if re.match(r"^jobs:\s*$", ln))
    except StopIteration:
        return []
    jobs: dict[str, bool] = {}
    job_indent = child_indent = None
    current = None
    for ln in lines[start + 1:]:
        if not ln.strip() or ln.lstrip().startswith("#"):
            continue
        indent = len(ln) - len(ln.lstrip())
        if indent == 0:
            break  # next top-level key
        if job_indent is None:
            job_indent = indent
        if indent == job_indent:
            current = ln.strip().rstrip(":")
            jobs[current] = False
            child_indent = None
        elif current is not None:
            child_indent = child_indent or indent
            if indent == child_indent and ln.strip().startswith("permissions:"):
                jobs[current] = True
    return [name for name, has in jobs.items() if not has]


_ENV_FILE = re.compile(r"(^|/)\.env(\.[\w-]+)?$")
_ENV_OK = re.compile(r"\.(example|sample|template|dist|defaults)$")


def config_checks(root: Path) -> list[Finding]:
    out: list[Finding] = []

    for f in _tracked_files(root):
        if _ENV_FILE.search(f) and not _ENV_OK.search(f):
            out.append(Finding(
                tool="aegris", rule="tracked-env-file", severity="high", file=f,
                title="Environment file committed to git",
                detail=".env files usually hold passwords and API keys. This one is tracked by git, "
                       "so everything in it is in the repo history.",
                fix_hint="Remove it from git (git rm --cached), keep a .env.example with placeholder values, "
                         "and rotate any real credentials it contained.",
                needs_human=True,
            ))

    wf_dir = root / ".github" / "workflows"
    if wf_dir.is_dir():
        for wf in sorted(list(wf_dir.glob("*.yml")) + list(wf_dir.glob("*.yaml"))):
            text = wf.read_text(errors="replace")
            rel = str(wf.relative_to(root))
            if not re.search(r"^permissions:", text, re.M) and _jobs_without_permissions(text):
                out.append(Finding(
                    tool="aegris", rule="workflow-default-permissions", severity="medium", file=rel,
                    title="Workflow doesn't limit its GITHUB_TOKEN permissions",
                    detail="Without a top-level `permissions:` block the job token may get broad write access.",
                    fix_hint="Add `permissions: contents: read` at the top level and grant extra scopes only "
                             "to the jobs that need them.",
                ))
            if "pull_request_target" in text and re.search(r"ref:\s*\$\{\{\s*github\.event\.pull_request\.head", text):
                out.append(Finding(
                    tool="aegris", rule="workflow-pwn-request", severity="critical", file=rel,
                    title="pull_request_target checks out untrusted PR code",
                    detail="Code from a stranger's pull request runs with this repo's secrets and write token.",
                    fix_hint="Use the `pull_request` trigger instead, or never check out the PR head in this workflow.",
                ))
            for m in re.finditer(r"run:.*\$\{\{\s*github\.event\.(issue|pull_request|comment|review|head_commit)\.[\w.]*(title|body|message|name|ref)\s*\}\}", text):
                out.append(Finding(
                    tool="aegris", rule="workflow-script-injection", severity="high", file=rel,
                    line=text[: m.start()].count("\n") + 1,
                    title="Untrusted event text inserted directly into a shell command",
                    detail="Anyone who can open an issue/PR can choose this text and run commands in the workflow.",
                    fix_hint="Pass the value through an `env:` variable and reference it as \"$VAR\" in the script.",
                ))
    return out


# --- baseline additions -----------------------------------------------------------

def _ensure_gitignore(root: Path) -> str | None:
    gi = root / ".gitignore"
    existing = gi.read_text().splitlines() if gi.exists() else []
    present = {line.strip() for line in existing}
    missing = [line for line in GITIGNORE_LINES if line not in present]
    # A bare ".env*" or "*.env" pattern already covers .env files.
    if ".env*" in present:
        missing = [m for m in missing if not m.startswith(".env")]
    if not missing:
        return None
    block = ([""] if existing and existing[-1].strip() else []) + [GITIGNORE_HEADER, *missing]
    gi.write_text("\n".join(existing + block) + "\n")
    return f".gitignore: ignore secret files ({', '.join(missing)})"


def detect_ecosystems(root: Path) -> dict[str, set[str]]:
    """Map dependabot ecosystem -> set of directories ('/' = repo root)."""
    found: dict[str, set[str]] = {}
    for path, rel in _walk(root):
        eco = ECOSYSTEMS.get(path.name)
        if eco and path.is_file():
            d = "/" + str(rel.parent).replace("\\", "/")
            found.setdefault(eco, set()).add("/" if d == "/." else d)
    if (root / ".github" / "workflows").is_dir():
        found["github-actions"] = {"/"}
    return found


def _ensure_dependabot(root: Path) -> str | None:
    gh = root / ".github"
    if (gh / "dependabot.yml").exists() or (gh / "dependabot.yaml").exists():
        return None
    ecos = detect_ecosystems(root)
    if not ecos:
        return None
    lines = ["# Added by Aegris: weekly pull requests for dependency security updates.",
             "version: 2", "updates:"]
    for eco in sorted(ecos):
        for d in sorted(ecos[eco]):
            lines += [f'  - package-ecosystem: "{eco}"', f'    directory: "{d}"',
                      "    schedule:", '      interval: "weekly"', "    open-pull-requests-limit: 5"]
    gh.mkdir(exist_ok=True)
    (gh / "dependabot.yml").write_text("\n".join(lines) + "\n")
    return f".github/dependabot.yml: automatic dependency updates for {', '.join(sorted(ecos))}"


def _ensure_security_md(root: Path) -> str | None:
    for candidate in ("SECURITY.md", ".github/SECURITY.md", "docs/SECURITY.md"):
        if (root / candidate).exists():
            return None
    (root / "SECURITY.md").write_text(SECURITY_MD)
    return "SECURITY.md: how to report a vulnerability privately"


def apply_baseline(root: Path) -> list[str]:
    """Add missing baseline protections. Returns a description of each change."""
    changes = []
    for step in (_ensure_gitignore, _ensure_dependabot, _ensure_security_md):
        msg = step(root)
        if msg:
            changes.append(msg)
    return changes
