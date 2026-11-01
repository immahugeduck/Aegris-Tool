import json
import os
import stat
import subprocess
from datetime import date

from aegris import fixer, github, hardening, registry
from aegris.findings import Finding, diff


def F(tool="semgrep", rule="r", file="a.py", line=1, **kw):
    return Finding(tool=tool, rule=rule, severity=kw.pop("severity", "high"), title="t", file=file, line=line, **kw)


# --- diff -------------------------------------------------------------------------

def test_diff_ignores_line_shifts_and_counts_duplicates():
    before = [F(line=3), F(line=9), F(rule="other")]
    after = [F(line=5)]  # one of the two moved, the other was fixed
    fixed, remaining, introduced = diff(before, after)
    assert len(fixed) == 2 and len(remaining) == 1 and not introduced
    assert remaining[0].line == 5  # reported at its current location


def test_diff_moved_secret_is_not_a_regression():
    before = [F(tool="gitleaks", rule="stripe", file="s.js")]
    after = [F(tool="gitleaks-history", rule="stripe", file="s.js")]
    fixed, remaining, introduced = diff(before, after)
    assert len(fixed) == 1 and not remaining and not introduced


def test_diff_reports_new_findings():
    _, _, introduced = diff([], [F()])
    assert len(introduced) == 1


# --- registry -----------------------------------------------------------------------

def test_registry_cycle(tmp_path):
    path = tmp_path / "projects.json"
    reg = registry.load(path)
    assert registry.add(reg, "me/app", today=date(2026, 1, 1))
    assert not registry.add(reg, "me/app")
    assert registry.due(reg, today=date(2026, 1, 1)) == ["me/app"]

    registry.record_run(reg, "me/app", {"status": "pr", "before": 4, "after": 1, "url": "u"}, today=date(2026, 1, 1))
    registry.save(path, reg)
    reg = registry.load(path)
    assert reg["projects"]["me/app"]["next_due"] == "2026-01-31"
    assert registry.due(reg, today=date(2026, 1, 30)) == []
    assert registry.due(reg, today=date(2026, 1, 31)) == ["me/app"]

    reg["projects"]["me/app"]["paused"] = True
    assert registry.due(reg, today=date(2026, 3, 1)) == []


def test_registry_history_is_capped():
    reg = registry.load(__import__("pathlib").Path("/nonexistent"))
    for i in range(20):
        registry.record_run(reg, "a/b", {"status": "clean"}, today=date(2026, 1, 1 + i))
    assert len(reg["projects"]["a/b"]["history"]) == 12


# --- parse_repo ---------------------------------------------------------------------

def test_parse_repo_forms(tmp_path):
    assert github.parse_repo("immahugeduck/central-command") == "immahugeduck/central-command"
    assert github.parse_repo("https://github.com/a/b.git") == "a/b"
    assert github.parse_repo("https://github.com/a/b/") == "a/b"
    assert github.parse_repo("git@github.com:a/b.git") == "a/b"
    assert github.parse_repo(str(tmp_path)) is None
    assert github.parse_repo("./x") is None
    assert github.parse_repo("https://gitlab.com/a/b") is None
    assert github.parse_repo("a/b; rm -rf /") is None
    assert github.parse_repo("a/..") is None


# --- hardening ----------------------------------------------------------------------

def _git_repo(path, files):
    for name, content in files.items():
        p = path / name
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(content)
    subprocess.run(["git", "init", "-q"], cwd=path, check=True)
    subprocess.run(["git", "add", "-A"], cwd=path, check=True)


def test_config_checks(tmp_path):
    _git_repo(tmp_path, {
        ".env": "X=1\n",
        ".env.example": "X=\n",
        ".github/workflows/a.yml": "on: issues\njobs:\n  j:\n    steps:\n"
                                   "      - run: echo \"${{ github.event.issue.title }}\"\n",
        ".github/workflows/b.yml": "on: push\npermissions:\n  contents: read\n",
    })
    rules = sorted((f.rule, f.file) for f in hardening.config_checks(tmp_path))
    assert rules == [
        ("tracked-env-file", ".env"),
        ("workflow-default-permissions", ".github/workflows/a.yml"),
        ("workflow-script-injection", ".github/workflows/a.yml"),
    ]


def test_baseline_adds_only_whats_missing(tmp_path):
    (tmp_path / ".gitignore").write_text("node_modules\n.env\n")
    (tmp_path / "web").mkdir()
    (tmp_path / "web" / "package.json").write_text("{}")
    (tmp_path / "node_modules" / "x").mkdir(parents=True)
    (tmp_path / "node_modules" / "x" / "package.json").write_text("{}")
    (tmp_path / "requirements.txt").write_text("")

    changes = hardening.apply_baseline(tmp_path)
    assert len(changes) == 3
    gi = (tmp_path / ".gitignore").read_text().splitlines()
    assert gi[:2] == ["node_modules", ".env"] and gi.count(".env") == 1 and "*.pem" in gi
    dep = (tmp_path / ".github" / "dependabot.yml").read_text()
    assert 'directory: "/web"' in dep and '"pip"' in dep and "node_modules" not in dep
    assert (tmp_path / "SECURITY.md").exists()

    assert hardening.apply_baseline(tmp_path) == []  # idempotent


# --- fixer --------------------------------------------------------------------------

def test_fixer_scrubs_env_and_restricts_tools(tmp_path, monkeypatch):
    """Runs a fake `claude` that records what it was given."""
    record = tmp_path / "record.json"
    fake = tmp_path / "bin" / "claude"
    fake.parent.mkdir()
    fake.write_text(
        "#!/usr/bin/env python3\n"
        "import json, os, sys\n"
        f"json.dump({{'argv': sys.argv[1:], 'env': dict(os.environ), 'stdin': sys.stdin.read()}}, open({str(record)!r}, 'w'))\n"
        "print(json.dumps({'type': 'result', 'is_error': False, 'result': '### What I changed\\n- x', 'total_cost_usd': 0.12}))\n"
    )
    fake.chmod(fake.stat().st_mode | stat.S_IEXEC)
    monkeypatch.setenv("PATH", f"{fake.parent}{os.pathsep}{os.environ['PATH']}")
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-test")
    monkeypatch.setenv("AEGRIS_TOKEN", "ghp_secret")
    monkeypatch.setenv("GITHUB_TOKEN", "ghs_secret")
    monkeypatch.setenv("ACTIONS_RUNTIME_TOKEN", "rt")

    res = fixer.run_fixer(tmp_path, [F(tool="gitleaks", rule="stripe", file="s.js")], max_budget_usd=2)
    assert res.ran and not res.error and res.cost_usd == 0.12 and "What I changed" in res.summary

    rec = json.loads(record.read_text())
    assert rec["env"].get("ANTHROPIC_API_KEY") == "sk-test"
    for leaked in ("AEGRIS_TOKEN", "GITHUB_TOKEN", "ACTIONS_RUNTIME_TOKEN"):
        assert leaked not in rec["env"]
    argv = rec["argv"]
    assert argv[argv.index("--permission-mode") + 1] == "dontAsk"
    assert argv[argv.index("--setting-sources") + 1] == "user"
    assert argv[argv.index("--max-budget-usd") + 1] == "2"
    tools = argv[argv.index("--allowedTools") + 1]
    assert "Bash(git" not in tools and "Bash(curl" not in tools and "WebFetch" not in tools
    assert '"rule": "stripe"' in rec["stdin"] and "{{FINDINGS_JSON}}" not in rec["stdin"]


def test_fixer_without_credentials(monkeypatch, tmp_path):
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    monkeypatch.delenv("CLAUDE_CODE_OAUTH_TOKEN", raising=False)
    res = fixer.run_fixer(tmp_path, [F()])
    assert not res.ran and "ANTHROPIC_API_KEY" in res.error


# --- PR create vs. update ---------------------------------------------------------

def test_upsert_pr_creates_then_updates(tmp_path, monkeypatch):
    log = tmp_path / "gh.log"
    state = tmp_path / "has_pr"
    fake = tmp_path / "bin" / "gh"
    fake.parent.mkdir()
    fake.write_text(
        "#!/usr/bin/env python3\n"
        "import os, sys, json\n"
        f"open({str(log)!r}, 'a').write(' '.join(sys.argv[1:3]) + ' token=' + os.environ.get('GH_TOKEN', '') + '\\n')\n"
        f"has = os.path.exists({str(state)!r})\n"
        "if sys.argv[1:3] == ['pr', 'list']:\n"
        "    print(json.dumps([{'url': 'https://github.com/a/b/pull/7'}] if has else []))\n"
        "elif sys.argv[1:3] == ['pr', 'create']:\n"
        "    print('https://github.com/a/b/pull/7')\n"
    )
    fake.chmod(0o755)
    monkeypatch.setenv("PATH", f"{fake.parent}{os.pathsep}{os.environ['PATH']}")
    monkeypatch.setenv("RUNNER_TEMP", str(tmp_path))

    assert github.upsert_pr("a/b", "tok", "main", "body") == "https://github.com/a/b/pull/7"
    state.write_text("")
    assert github.upsert_pr("a/b", "tok", "main", "body2") == "https://github.com/a/b/pull/7"
    calls = log.read_text().splitlines()
    assert calls == ["pr list token=tok", "pr create token=tok",
                     "pr list token=tok", "pr edit token=tok", "pr comment token=tok"]


def test_commit_keeps_untracked_env_out(tmp_path, monkeypatch):
    """With no .gitignore rule, `git add -A` alone would re-commit the .env."""
    remote = tmp_path / "remote.git"
    subprocess.run(["git", "init", "-q", "--bare", str(remote)], check=True)
    work = tmp_path / "work"
    work.mkdir()
    _git_repo(work, {".env": "SECRET=1\n", "app.py": "x = 1\n"})
    subprocess.run(["git", "-c", "user.name=t", "-c", "user.email=t@t", "commit", "-qm", "init"], cwd=work, check=True)
    subprocess.run(["git", "remote", "add", "origin", str(remote)], cwd=work, check=True)

    untracked = github.untrack(work, [".env"])
    (work / "app.py").write_text("x = 2\n")
    github.commit_and_push(work, "tok", "fix", keep_out=untracked)

    files = subprocess.run(["git", "ls-tree", "-r", "--name-only", github.BRANCH], cwd=remote,
                           capture_output=True, text=True).stdout.split()
    assert files == ["app.py"]
    assert (work / ".env").exists()


def test_job_level_permissions_are_enough():
    every_job = "on: push\njobs:\n  a:\n    runs-on: x\n    permissions:\n      contents: read\n" \
                "  b:\n    runs-on: x\n    permissions: read-all\n"
    assert hardening._jobs_without_permissions(every_job) == []
    one_missing = "on: push\njobs:\n  a:\n    permissions:\n      contents: read\n  b:\n    runs-on: x\n" \
                  "    steps:\n      - with:\n          permissions: nope\n"
    assert hardening._jobs_without_permissions(one_missing) == ["b"]
