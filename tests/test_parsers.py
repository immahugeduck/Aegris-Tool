from pathlib import Path

from aegris.scanners import parse_gitleaks, parse_osv, parse_semgrep

ROOT = Path("/work/repo")


def test_gitleaks_current_file_is_critical_and_relative():
    data = [{"RuleID": "stripe-access-token", "File": "/work/repo/src/pay.js", "StartLine": 3,
             "Description": "Stripe Access Token", "Secret": "REDACTED"}]
    [f] = parse_gitleaks(data, ROOT)
    assert f.tool == "gitleaks"
    assert f.severity == "critical"
    assert f.file == "src/pay.js" and f.line == 3
    assert f.needs_human


def test_gitleaks_history_flags_rotation():
    data = [{"RuleID": "aws-access-token", "File": "config.py", "StartLine": 1, "Commit": "abcdef1234567",
             "Description": "AWS"}]
    [f] = parse_gitleaks(data, ROOT, in_history=True)
    assert f.tool == "gitleaks-history"
    assert "Rotate" in f.fix_hint
    assert "abcdef1234" in f.detail


def test_semgrep_strips_local_rule_path_prefix():
    # Shape taken from a real semgrep 1.182 run.
    data = {"results": [{
        "check_id": "home.user.Aegris-Tool.aegris.rules.aegris.js.eval",
        "path": "server.js",
        "start": {"line": 7, "col": 3},
        "extra": {"message": "eval() runs arbitrary code.", "severity": "ERROR",
                  "metadata": {"cwe": "CWE-95", "fix": "Use JSON.parse"}},
    }, {
        "check_id": "javascript.express.security.audit.xss.direct-response-write",
        "path": "./routes/a.js",
        "start": {"line": 2},
        "extra": {"message": "XSS\nmore", "severity": "WARNING",
                  "metadata": {"cwe": ["CWE-79: XSS"]}},
    }]}
    a, b = parse_semgrep(data, ROOT)
    assert a.rule == "aegris.js.eval" and a.severity == "high" and a.fix_hint == "Use JSON.parse"
    assert b.rule.startswith("javascript.express") and b.severity == "medium"
    assert b.file == "routes/a.js" and b.title == "XSS" and b.detail == "CWE-79: XSS"


def test_osv_groups_aliases_and_finds_fixed_version():
    # Shape per osv-scanner v1 --format json.
    data = {"results": [{
        "source": {"path": "/work/repo/package-lock.json", "type": "lockfile"},
        "packages": [{
            "package": {"name": "lodash", "version": "4.17.15", "ecosystem": "npm"},
            "vulnerabilities": [
                {"id": "GHSA-35jh-r3h4-6jhm", "summary": "Command Injection in lodash",
                 "affected": [{"package": {"name": "lodash"},
                               "ranges": [{"type": "SEMVER", "events": [{"introduced": "0"}, {"fixed": "4.17.21"}]}]}]},
                {"id": "CVE-2021-23337", "summary": "dup", "affected": []},
            ],
            "groups": [{"ids": ["GHSA-35jh-r3h4-6jhm", "CVE-2021-23337"], "max_severity": "7.2"}],
        }],
    }]}
    [f] = parse_osv(data, ROOT)
    assert f.severity == "high"
    assert f.file == "package-lock.json"
    assert f.package == "npm:lodash"
    assert "4.17.21" in f.fix_hint
    assert f.rule == "CVE-2021-23337"  # stable: sorted first id of the group


def test_osv_without_groups_or_fix():
    data = {"results": [{"source": {"path": "requirements.txt"}, "packages": [{
        "package": {"name": "foo", "version": "1.0", "ecosystem": "PyPI"},
        "vulnerabilities": [{"id": "PYSEC-1", "database_specific": {"severity": "CRITICAL"}}],
    }]}]}
    [f] = parse_osv(data, ROOT)
    assert f.severity == "critical"
    assert "No fixed version" in f.fix_hint
