"""Rollback bookkeeping: previous commit SHA + the outcome of the last update.

Both files live in `database/` (git-ignored, preserved by updates and by
`uninstall.sh --keep-data`).
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

STATE_FILE_NAME = ".update_previous_sha"
RESULT_FILE_NAME = ".update_last_result.json"
FORCE_MARKER_NAME = ".update_force"


def _state_file(state_dir: Path, name: str = STATE_FILE_NAME) -> Path:
    state_dir.mkdir(parents=True, exist_ok=True)
    return state_dir / name


def save_previous_sha(state_dir: Path, sha: str) -> None:
    sha = (sha or "").strip()
    if not sha:
        return
    _state_file(state_dir).write_text(sha + "\n", encoding="utf-8")


def load_previous_sha(state_dir: Path) -> str | None:
    path = _state_file(state_dir)
    if not path.is_file():
        return None
    value = path.read_text(encoding="utf-8").strip()
    return value or None


def save_last_result(state_dir: Path, result: dict) -> None:
    payload = {**result, "finished_at": datetime.now(timezone.utc).isoformat(timespec="seconds")}
    try:
        _state_file(state_dir, RESULT_FILE_NAME).write_text(
            json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8"
        )
    except OSError:
        pass  # bookkeeping must never fail an update


def load_last_result(state_dir: Path) -> dict | None:
    path = state_dir / RESULT_FILE_NAME
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None


def set_force_marker(state_dir: Path) -> None:
    _state_file(state_dir, FORCE_MARKER_NAME).write_text("1\n", encoding="utf-8")


def pop_force_marker(state_dir: Path) -> bool:
    path = state_dir / FORCE_MARKER_NAME
    if path.is_file():
        path.unlink(missing_ok=True)
        return True
    return False


__all__ = [
    "save_previous_sha",
    "load_previous_sha",
    "save_last_result",
    "load_last_result",
    "set_force_marker",
    "pop_force_marker",
    "STATE_FILE_NAME",
]
