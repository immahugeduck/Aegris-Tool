"""The list of projects Aegris has worked on and when each is next due.

Stored as plain JSON in the repo (registry/projects.json) so the history is
visible in git and can be edited by hand.
"""

from __future__ import annotations

import json
from datetime import date, timedelta
from pathlib import Path

DEFAULT_INTERVAL_DAYS = 30


def load(path: Path) -> dict:
    if path.exists():
        data = json.loads(path.read_text())
    else:
        data = {}
    data.setdefault("interval_days", DEFAULT_INTERVAL_DAYS)
    data.setdefault("projects", {})
    return data


def save(path: Path, data: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    data["projects"] = dict(sorted(data["projects"].items(), key=lambda kv: kv[0].lower()))
    path.write_text(json.dumps(data, indent=2) + "\n")


def add(data: dict, repo: str, today: date | None = None) -> bool:
    """Register a project so it's picked up on the next scheduled run. Returns
    False if it was already registered."""
    if repo in data["projects"]:
        return False
    today = today or date.today()
    data["projects"][repo] = {"added": today.isoformat(), "next_due": today.isoformat(), "paused": False}
    return True


def record_run(data: dict, repo: str, result: dict, today: date | None = None) -> None:
    today = today or date.today()
    entry = data["projects"].setdefault(repo, {"added": today.isoformat(), "paused": False})
    entry["last_run"] = today.isoformat()
    entry["next_due"] = (today + timedelta(days=int(data["interval_days"]))).isoformat()
    entry["last_result"] = result
    history = entry.setdefault("history", [])
    history.append({"date": today.isoformat(), **{k: result.get(k) for k in ("status", "before", "after", "url")}})
    del history[:-12]  # keep about a year


def due(data: dict, today: date | None = None) -> list[str]:
    today = today or date.today()
    return [
        repo for repo, entry in data["projects"].items()
        if not entry.get("paused") and date.fromisoformat(entry.get("next_due", "1970-01-01")) <= today
    ]
