"""The AI fix stage: hand the findings to Claude Code running headless.

Claude only gets file editing plus a short list of package-manager and test
commands. It never gets git, the GitHub token, or network tools; Aegris itself
does the committing and pushing after re-scanning to verify the result.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path

from aegris.findings import Finding, sort_findings

PROMPT_FILE = Path(__file__).parent / "prompts" / "fix.md"
MAX_FINDINGS_IN_PROMPT = 150

ALLOWED_TOOLS = [
    "Read", "Edit", "Write", "Glob", "Grep",
    # dependency upgrades
    "Bash(npm install:*)", "Bash(npm uninstall:*)", "Bash(npm update:*)", "Bash(npm audit:*)",
    "Bash(npm ls:*)", "Bash(npm view:*)",
    "Bash(pnpm install:*)", "Bash(pnpm update:*)", "Bash(pnpm add:*)",
    "Bash(yarn install:*)", "Bash(yarn add:*)", "Bash(yarn up:*)", "Bash(yarn upgrade:*)",
    "Bash(pip index versions:*)", "Bash(uv lock:*)", "Bash(poetry lock:*)", "Bash(poetry add:*)",
    "Bash(go get:*)", "Bash(go mod tidy:*)", "Bash(cargo update:*)", "Bash(bundle update:*)",
    "Bash(composer update:*)", "Bash(composer require:*)",
    # checking the fix didn't break the build
    "Bash(npm test:*)", "Bash(npm run build:*)", "Bash(npm run lint:*)", "Bash(npm run typecheck:*)",
    "Bash(npx tsc:*)", "Bash(pytest:*)", "Bash(python -m pytest:*)", "Bash(go build:*)",
    "Bash(go test:*)", "Bash(go vet:*)", "Bash(cargo check:*)", "Bash(cargo test:*)",
    "Bash(node --check:*)", "Bash(python -m py_compile:*)", "Bash(python3 -m py_compile:*)",
]

# Only these variables reach the Claude process. In particular the GitHub token
# and the Actions runtime tokens stay out of reach of anything the repo's
# contents might talk the model into doing.
ENV_ALLOWLIST = {
    "PATH", "HOME", "USER", "LANG", "LC_ALL", "TERM", "TMPDIR", "SHELL",
    "ANTHROPIC_API_KEY", "CLAUDE_CODE_OAUTH_TOKEN", "ANTHROPIC_MODEL",
    "HTTPS_PROXY", "HTTP_PROXY", "NO_PROXY", "https_proxy", "http_proxy", "no_proxy",
    "NODE_EXTRA_CA_CERTS", "SSL_CERT_FILE", "REQUESTS_CA_BUNDLE",
    "GOPATH", "GOCACHE", "CARGO_HOME", "RUSTUP_HOME", "PIP_CACHE_DIR", "npm_config_cache",
}


@dataclass
class FixResult:
    ran: bool
    summary: str = ""
    error: str = ""
    cost_usd: float | None = None


def build_prompt(findings: list[Finding]) -> str:
    items = sort_findings(findings)
    shown = items[:MAX_FINDINGS_IN_PROMPT]
    payload = [{k: v for k, v in f.to_dict().items() if v not in ("", 0, False)} for f in shown]
    extra = ""
    if len(items) > len(shown):
        extra = f"\n({len(items) - len(shown)} lower-severity findings omitted; fix the ones listed.)\n"
    return PROMPT_FILE.read_text().replace(
        "{{FINDINGS_JSON}}", json.dumps(payload, indent=1)
    ).replace("{{OMITTED}}", extra)


def credentials_present() -> bool:
    return bool(os.environ.get("ANTHROPIC_API_KEY") or os.environ.get("CLAUDE_CODE_OAUTH_TOKEN"))


def run_fixer(root: Path, findings: list[Finding], model: str | None = None,
              max_budget_usd: float = 5.0, timeout_s: int = 3600) -> FixResult:
    if not findings:
        return FixResult(ran=False, summary="Nothing to fix.")
    exe = shutil.which("claude")
    if not exe:
        return FixResult(ran=False, error="Claude Code CLI not installed (npm i -g @anthropic-ai/claude-code).")
    if not credentials_present():
        return FixResult(ran=False, error="No ANTHROPIC_API_KEY or CLAUDE_CODE_OAUTH_TOKEN set.")

    cmd = [
        exe, "-p",
        "--output-format", "json",
        "--permission-mode", "dontAsk",  # anything not allowed below is refused, not prompted
        "--allowedTools", ",".join(ALLOWED_TOOLS),
        "--setting-sources", "user",  # ignore the target repo's own .claude/ settings and hooks
        "--strict-mcp-config",  # ...and its .mcp.json
        "--no-session-persistence",
        "--max-budget-usd", str(max_budget_usd),
    ]
    if model:
        cmd += ["--model", model]
    env = {k: v for k, v in os.environ.items() if k in ENV_ALLOWLIST and v}

    try:
        proc = subprocess.run(cmd, input=build_prompt(findings), cwd=root, env=env,
                              capture_output=True, text=True, timeout=timeout_s)
    except subprocess.TimeoutExpired:
        return FixResult(ran=True, error=f"Fix stage timed out after {timeout_s // 60} minutes; partial edits kept.")

    try:
        out = json.loads(proc.stdout)
    except json.JSONDecodeError:
        return FixResult(ran=True, error=f"Claude Code exited {proc.returncode}: {(proc.stderr or proc.stdout).strip()[-500:]}")
    error = ""
    if out.get("is_error"):
        error = "; ".join(out.get("errors") or []) or out.get("subtype", "unknown error")
        error += " (any edits made before this point are kept and were re-scanned)"
    return FixResult(
        ran=True,
        summary=(out.get("result") or "").strip(),
        error=error,
        cost_usd=out.get("total_cost_usd"),
    )
