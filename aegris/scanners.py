"""Run the external scanners and convert their output into Findings.

Each scanner is optional: if its binary isn't installed it's reported as
skipped instead of failing the whole run.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import tempfile
from dataclasses import dataclass, field
from pathlib import Path

from aegris.findings import Finding, normalize_severity

RULES_DIR = Path(__file__).parent / "rules"


@dataclass
class ScanResult:
    findings: list[Finding] = field(default_factory=list)
    ran: list[str] = field(default_factory=list)
    skipped: dict[str, str] = field(default_factory=dict)  # tool -> reason


def _rel(path: str, root: Path) -> str:
    p = Path(path)
    if p.is_absolute():
        try:
            return str(p.resolve().relative_to(root.resolve()))
        except ValueError:
            return str(p)
    return str(p).removeprefix("./")


def _last_line(text: str) -> str:
    lines = [ln.strip() for ln in (text or "").splitlines() if ln.strip()]
    return lines[-1][:300] if lines else "no output"


def _run(cmd: list[str], cwd: Path | None = None, timeout: int = 1200, env: dict | None = None) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, cwd=cwd, capture_output=True, text=True, timeout=timeout, env=env)


# --- gitleaks: hard-coded passwords, API keys, tokens ----------------------------

def parse_gitleaks(data: list[dict], root: Path, in_history: bool = False) -> list[Finding]:
    out = []
    for leak in data or []:
        rel = _rel(leak.get("File", ""), root)
        if in_history:
            out.append(Finding(
                tool="gitleaks-history",
                rule=leak.get("RuleID", "secret"),
                severity="high",
                title=f"Secret in git history: {leak.get('Description', leak.get('RuleID'))}",
                file=rel,
                line=int(leak.get("StartLine") or 0),
                detail=f"Committed in {str(leak.get('Commit', ''))[:10]}. It's no longer in the current files, "
                       "but anyone with a copy of the repo history can still read it.",
                fix_hint="Rotate (revoke and re-issue) this credential with its provider. "
                         "Removing it from code does not un-leak it.",
                needs_human=True,
            ))
        else:
            out.append(Finding(
                tool="gitleaks",
                rule=leak.get("RuleID", "secret"),
                severity="critical",
                title=f"Hard-coded secret: {leak.get('Description', leak.get('RuleID'))}",
                file=rel,
                line=int(leak.get("StartLine") or 0),
                detail="A credential is written directly in the source code.",
                fix_hint="Load it from an environment variable instead, add a placeholder to .env.example, "
                         "and rotate the real credential since it has already been exposed.",
                needs_human=True,
            ))
    return out


def run_gitleaks(root: Path, result: ScanResult) -> None:
    exe = shutil.which("gitleaks")
    if not exe:
        result.skipped["gitleaks"] = "not installed"
        return
    with tempfile.TemporaryDirectory() as tmp:
        tree_report = Path(tmp) / "tree.json"
        base = [exe, "detect", "--source", str(root), "--redact", "--exit-code", "0",
                "--no-banner", "--report-format", "json"]
        proc = _run(base + ["--no-git", "--report-path", str(tree_report)])
        if proc.returncode != 0 or not tree_report.exists():
            result.skipped["gitleaks"] = f"failed: {_last_line(proc.stderr)}"
            return
        current = parse_gitleaks(json.loads(tree_report.read_text() or "[]"), root)
        result.findings += current
        result.ran.append("gitleaks")

        if not (root / ".git").exists():
            return
        hist_report = Path(tmp) / "hist.json"
        proc = _run(base + ["--report-path", str(hist_report)])
        if proc.returncode != 0 or not hist_report.exists():
            result.skipped["gitleaks-history"] = f"failed: {_last_line(proc.stderr)}"
            return
        # Only report history leaks that aren't also in the current files;
        # those are already covered above.
        current_keys = {(f.rule, f.file) for f in current}
        seen = set()
        for f in parse_gitleaks(json.loads(hist_report.read_text() or "[]"), root, in_history=True):
            k = (f.rule, f.file)
            if k not in current_keys and k not in seen:
                seen.add(k)
                result.findings.append(f)
        result.ran.append("gitleaks-history")


# --- semgrep: dangerous code patterns (injection, unsafe crypto, ...) -----------

_LOCAL_RULE_PREFIX = re.compile(r".*?\brules\.(aegris\..+)$")


def parse_semgrep(data: dict, root: Path) -> list[Finding]:
    out = []
    for r in data.get("results", []):
        extra = r.get("extra", {})
        meta = extra.get("metadata", {}) or {}
        rule = r.get("check_id", "semgrep")
        m = _LOCAL_RULE_PREFIX.match(rule)
        if m:
            rule = m.group(1)
        cwe = meta.get("cwe")
        if isinstance(cwe, list):
            cwe = ", ".join(cwe[:2])
        out.append(Finding(
            tool="semgrep",
            rule=rule,
            severity=normalize_severity(extra.get("severity", "")),
            title=extra.get("message", rule).strip().split("\n")[0][:200],
            file=_rel(r.get("path", ""), root),
            line=int(r.get("start", {}).get("line") or 0),
            detail=f"{cwe}" if cwe else "",
            fix_hint=meta.get("fix", "") or "",
        ))
    return out


def run_semgrep(root: Path, result: ScanResult) -> None:
    exe = shutil.which("semgrep")
    if not exe:
        result.skipped["semgrep"] = "not installed"
        return
    base = [exe, "scan", "--json", "--metrics=off", "--quiet", "--timeout", "30",
            "--config", str(RULES_DIR)]
    # Semgrep's public ruleset; set AEGRIS_SEMGREP_REGISTRY="" to use only the built-in rules.
    pack = os.environ.get("AEGRIS_SEMGREP_REGISTRY", "p/default")
    # Without this semgrep checks for updates on every run, which stalls for
    # minutes on networks that block semgrep.dev.
    env = dict(os.environ, SEMGREP_ENABLE_VERSION_CHECK="0", SEMGREP_SEND_METRICS="off")
    used_registry = bool(pack)
    proc = _run(base + ["--config", pack, str(root)], env=env) if pack else None
    if proc is None or not proc.stdout.strip() or proc.returncode not in (0, 1):
        # Most likely semgrep.dev was unreachable; fall back to the built-in rules.
        proc = _run(base + [str(root)], env=env)
        used_registry = False
    try:
        data = json.loads(proc.stdout)
    except json.JSONDecodeError:
        result.skipped["semgrep"] = f"failed: {_last_line(proc.stderr)}"
        return
    result.findings += parse_semgrep(data, root)
    result.ran.append("semgrep" if used_registry else "semgrep (built-in rules only)")


# --- osv-scanner: dependencies with published vulnerabilities -------------------

def _fixed_versions(vuln: dict, pkg_name: str) -> list[str]:
    fixed = []
    for aff in vuln.get("affected", []):
        if aff.get("package", {}).get("name") not in (None, pkg_name):
            continue
        for rng in aff.get("ranges", []):
            for ev in rng.get("events", []):
                if "fixed" in ev:
                    fixed.append(ev["fixed"])
    return sorted(set(fixed))


def _osv_severity(group: dict | None, vuln: dict) -> str:
    score = None
    if group and group.get("max_severity"):
        try:
            score = float(group["max_severity"])
        except ValueError:
            pass
    if score is not None:
        if score >= 9:
            return "critical"
        if score >= 7:
            return "high"
        if score >= 4:
            return "medium"
        return "low"
    return normalize_severity((vuln.get("database_specific") or {}).get("severity", "medium"))


def parse_osv(data: dict, root: Path) -> list[Finding]:
    out = []
    for res in data.get("results", []):
        source = _rel(res.get("source", {}).get("path", ""), root)
        for pkg in res.get("packages", []):
            p = pkg.get("package", {})
            name, version, eco = p.get("name", "?"), p.get("version", "?"), p.get("ecosystem", "")
            vulns = {v["id"]: v for v in pkg.get("vulnerabilities", [])}
            groups = pkg.get("groups") or [{"ids": [vid]} for vid in vulns]
            # osv groups aliases of the same bug (GHSA + CVE) - report each group once.
            for g in groups:
                ids = g.get("ids", [])
                primary = next((vulns[i] for i in ids if i in vulns), None)
                if not primary:
                    continue
                fixed = _fixed_versions(primary, name)
                aliases = sorted(set(ids) | set(g.get("aliases", [])))
                out.append(Finding(
                    tool="osv-scanner",
                    rule=sorted(ids)[0],
                    severity=_osv_severity(g, primary),
                    title=f"{name}@{version}: {primary.get('summary') or primary['id']}",
                    file=source,
                    package=f"{eco}:{name}",
                    detail=", ".join(aliases[:4]),
                    fix_hint=(f"Upgrade {name} to {' or '.join(fixed[-2:])} or later." if fixed
                              else f"No fixed version of {name} published yet; consider replacing it."),
                ))
    return out


def run_osv(root: Path, result: ScanResult) -> None:
    exe = shutil.which("osv-scanner")
    if not exe:
        result.skipped["osv-scanner"] = "not installed"
        return
    proc = _run([exe, "--format", "json", "--recursive", str(root)])
    # Exit 0 = clean, 1 = vulns found, 128 = no lockfiles found.
    if proc.returncode == 128:
        result.ran.append("osv-scanner (no lockfiles found)")
        return
    try:
        data = json.loads(proc.stdout)
    except json.JSONDecodeError:
        result.skipped["osv-scanner"] = f"failed (exit {proc.returncode}): {_last_line(proc.stderr)}"
        return
    result.findings += parse_osv(data, root)
    result.ran.append("osv-scanner")


def scan(root: Path, config_checks=None) -> ScanResult:
    """Run every scanner against `root`."""
    root = root.resolve()
    result = ScanResult()
    for runner in (run_gitleaks, run_semgrep, run_osv):
        try:
            runner(root, result)
        except subprocess.TimeoutExpired:
            result.skipped[runner.__name__.removeprefix("run_")] = "timed out"
    if config_checks:
        result.findings += config_checks(root)
        result.ran.append("aegris config checks")
    return result


def scanner_versions() -> dict[str, str]:
    out = {}
    for tool, args in {"gitleaks": ["version"], "semgrep": ["--version"], "osv-scanner": ["--version"]}.items():
        exe = shutil.which(tool)
        if exe:
            try:
                out[tool] = _run([exe, *args], timeout=60).stdout.strip().splitlines()[0]
            except Exception:  # noqa: BLE001 - version is informational only
                out[tool] = "unknown"
    return out
