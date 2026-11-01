"""Turn a run into a Markdown report (used for the PR body and local output)."""

from __future__ import annotations

from aegris.findings import SEVERITIES, Finding, count_by_severity, sort_findings

ICON = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🔵", "info": "⚪"}
MAX_BODY = 60000  # GitHub caps PR/issue bodies at 65,536 characters


def _counts_line(findings: list[Finding]) -> str:
    c = count_by_severity(findings)
    parts = [f"{ICON[s]} {c[s]} {s}" for s in SEVERITIES if c[s]]
    return " · ".join(parts) or "none"


def _table(findings: list[Finding], limit: int = 60) -> str:
    rows = ["| | Finding | Where | Fix |", "|---|---|---|---|"]
    for f in sort_findings(findings)[:limit]:
        where = f"`{f.file}:{f.line}`" if f.line else (f"`{f.file}`" if f.file else "")
        title = f.title.replace("|", "\\|")
        hint = f.fix_hint.replace("|", "\\|")
        rows.append(f"| {ICON[f.severity]} | {title} | {where} | {hint} |")
    if len(findings) > limit:
        rows.append(f"| | …and {len(findings) - limit} more | | |")
    return "\n".join(rows)


def render(*, target: str, before: list[Finding], fixed: list[Finding], remaining: list[Finding],
           introduced: list[Finding], baseline: list[str], untracked: list[str], ai_summary: str,
           ai_error: str, scanners_ran: list[str], scanners_skipped: dict[str, str],
           cost_usd: float | None, next_due: str | None, diffstat: str = "", scan_only: bool = False) -> str:
    out = [f"## 🛡️ Aegris security review: `{target}`", ""]

    out += ["| | |", "|---|---|", f"| Found | {len(before)} ({_counts_line(before)}) |"]
    if not scan_only:
        out += [
            f"| Fixed and verified by re-scan | **{len(fixed)}** |",
            f"| Still open | {len(remaining)} ({_counts_line(remaining)}) |",
        ]
    if introduced:
        out.append(f"| ⚠️ New after fixes | {len(introduced)} — review these carefully |")
    if next_due:
        out.append(f"| Next review | {next_due} |")
    out.append("")

    human = [f for f in remaining + fixed if f.needs_human]
    if human:
        out += ["### ⚠️ Action needed from you", "",
                "These credentials were exposed. Code changes can stop *new* exposure, but anyone who already "
                "has a copy can still use them. Revoke and re-issue each one with its provider:", ""]
        seen = set()
        for f in human:
            k = (f.rule, f.file)
            if k not in seen:
                seen.add(k)
                out.append(f"- [ ] {f.title} — `{f.file}`" + (f" line {f.line}" if f.line else ""))
        out.append("")

    if baseline or untracked:
        out += ["### Baseline protections added", ""]
        out += [f"- {b}" for b in baseline]
        out += [f"- Stopped tracking `{u}` in git (the file is untouched on disk)" for u in untracked]
        out.append("")

    if ai_summary:
        out += [ai_summary, ""]
    if ai_error:
        out += [f"> **Fix stage problem:** {ai_error}", ""]

    if fixed:
        out += ["<details><summary>Fixed findings</summary>", "", _table(fixed), "", "</details>", ""]
    if introduced:
        out += ["### New findings after the fix pass", "", _table(introduced), ""]
    if remaining:
        out += ["### Findings" if scan_only else "### Still open", "", _table(remaining), ""]

    if diffstat:
        out += ["<details><summary>Files changed</summary>", "", "```", diffstat, "```", "</details>", ""]

    meta = f"Scanners: {', '.join(scanners_ran) or 'none'}."
    if scanners_skipped:
        meta += " Skipped: " + ", ".join(f"{k} ({v})" for k, v in scanners_skipped.items()) + "."
    if cost_usd is not None:
        meta += f" AI fix cost (as reported by Claude Code): ${cost_usd:.2f}."
    out += ["---", f"<sub>{meta} Review every change before merging; automated fixes can be wrong.</sub>"]

    body = "\n".join(out)
    if len(body) > MAX_BODY:
        body = body[:MAX_BODY] + "\n\n…(truncated; full report is in the workflow artifacts)"
    return body
