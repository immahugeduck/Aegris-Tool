"""Runs the real scanners against a deliberately vulnerable repo built at test
time (so this repo itself never contains vulnerable code or fake secrets).
Skipped when the scanners aren't installed."""

import json
import shutil
import subprocess
import sys

import pytest

needs_scanners = pytest.mark.skipif(
    not (shutil.which("gitleaks") and shutil.which("semgrep")), reason="scanners not installed"
)

# Split so nothing in this file itself looks like a live key to a secret scanner.
FAKE_STRIPE = "sk_" + "live_" + "51HqLyjWDarjtT1zdp7dcXiS0bhJYHXuGbTJSPZ0oCbqX9bWjtV5mEjJ3Qx2MgsQzKk00Y2ZsUQzM"


@pytest.fixture
def vuln_repo(tmp_path):
    (tmp_path / "server.js").write_text(
        'const { exec } = require("child_process");\n'
        f'const key = "{FAKE_STRIPE}";\n'
        "function h(req, db) {\n"
        "  exec(`convert ${req.query.file} out.png`);\n"
        "  db.query(`SELECT * FROM t WHERE name = '${req.query.name}'`);\n"
        "  eval(req.body.code);\n"
        "}\n"
    )
    (tmp_path / "app.py").write_text(
        "import subprocess, yaml\n"
        "def run(cmd, uid, cur):\n"
        "    subprocess.run(cmd, shell=True)\n"
        '    cur.execute(f"SELECT * FROM users WHERE id = {uid}")\n'
        '    yaml.load(open("x"))\n'
    )
    (tmp_path / ".env").write_text("DATABASE_URL=postgres://u:p@h/db\n")
    subprocess.run(["git", "init", "-q"], cwd=tmp_path, check=True)
    subprocess.run(["git", "add", "-A"], cwd=tmp_path, check=True)
    subprocess.run(["git", "-c", "user.name=t", "-c", "user.email=t@t", "commit", "-qm", "init"], cwd=tmp_path, check=True)
    return tmp_path


@needs_scanners
def test_scan_finds_planted_problems(vuln_repo):
    out = subprocess.run([sys.executable, "-m", "aegris", "scan", str(vuln_repo), "--json"],
                         capture_output=True, text=True, timeout=900)
    rules = {f["rule"] for f in json.loads(out.stdout)}
    for expected in ("stripe-access-token", "tracked-env-file", "aegris.js.eval", "aegris.js.child-process-shell",
                     "aegris.js.sql-template", "aegris.py.subprocess-shell", "aegris.py.sql-format",
                     "aegris.py.unsafe-deserialization"):
        assert expected in rules, f"missing {expected}; got {sorted(rules)}"


@needs_scanners
def test_run_without_ai_hardens_and_untracks(vuln_repo, tmp_path_factory):
    out_dir = tmp_path_factory.mktemp("out")
    proc = subprocess.run([sys.executable, "-m", "aegris", "run", str(vuln_repo), "--no-ai", "--out", str(out_dir)],
                          capture_output=True, text=True, timeout=900)
    assert proc.returncode == 0, proc.stderr
    status = subprocess.run(["git", "status", "--short"], cwd=vuln_repo, capture_output=True, text=True).stdout
    assert "D  .env" in status and "SECURITY.md" in status and ".gitignore" in status
    assert (vuln_repo / ".env").exists()  # untracked, not deleted
    report = next(out_dir.glob("*/report.md")).read_text()
    assert "Action needed from you" in report and "Fixed and verified by re-scan | **1**" in report
