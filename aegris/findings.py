"""The common shape every scanner's output is converted into."""

from __future__ import annotations

from collections import Counter
from dataclasses import asdict, dataclass

SEVERITIES = ["critical", "high", "medium", "low", "info"]


@dataclass
class Finding:
    tool: str  # which scanner reported it
    rule: str  # scanner's rule / advisory id
    severity: str  # one of SEVERITIES
    title: str
    file: str = ""  # path relative to the repo root
    line: int = 0
    detail: str = ""
    fix_hint: str = ""
    package: str = ""  # dependency findings only
    needs_human: bool = False  # can't be fully fixed in code (e.g. a leaked key must be rotated)

    @property
    def key(self) -> str:
        """Identity used to compare scans. Line numbers are left out on
        purpose: edits shift lines, and a moved finding is not a fixed one."""
        return "|".join([self.tool, self.rule, self.file, self.package])

    def to_dict(self) -> dict:
        return asdict(self)


def normalize_severity(raw: str) -> str:
    raw = (raw or "").lower()
    aliases = {
        "error": "high",
        "warning": "medium",
        "moderate": "medium",
        "note": "low",
        "information": "info",
        "unknown": "medium",
    }
    raw = aliases.get(raw, raw)
    return raw if raw in SEVERITIES else "medium"


def sort_findings(findings: list[Finding]) -> list[Finding]:
    return sorted(findings, key=lambda f: (SEVERITIES.index(f.severity), f.file, f.line))


def count_by_severity(findings: list[Finding]) -> dict[str, int]:
    counts = Counter(f.severity for f in findings)
    return {s: counts.get(s, 0) for s in SEVERITIES}


def diff(before: list[Finding], after: list[Finding]) -> tuple[list[Finding], list[Finding], list[Finding]]:
    """Return (fixed, remaining, introduced). Compared as multisets of keys so
    two identical findings in one file count as two."""
    after_left = Counter(f.key for f in after)
    fixed = []
    for f in before:
        if after_left[f.key] > 0:
            after_left[f.key] -= 1
        else:
            fixed.append(f)
    # Remaining findings are taken from the second scan so their file/line
    # point at where the problem is now.
    before_left = Counter(f.key for f in before)
    remaining, introduced = [], []
    for f in after:
        if before_left[f.key] > 0:
            before_left[f.key] -= 1
            remaining.append(f)
        else:
            introduced.append(f)
    # Moving a hard-coded secret out of the code makes it show up as "secret in
    # git history" on the second scan. That's expected, not a regression; the
    # rotation reminder already covers it.
    moved = {(f.rule, f.file) for f in fixed if f.tool == "gitleaks"}
    introduced = [f for f in introduced if not (f.tool == "gitleaks-history" and (f.rule, f.file) in moved)]
    return fixed, remaining, introduced
