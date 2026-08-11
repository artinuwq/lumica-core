"""Best-effort rollback bookkeeping.

Stores the previous commit SHA before a hard reset so an operator can
manually roll back (`git reset --hard <sha>` + restart). This is not a
schema-migration rollback - see the update/README note in manager.py.
"""

from __future__ import annotations

from pathlib import Path

STATE_FILE_NAME = ".update_previous_sha"


def _state_file(state_dir: Path) -> Path:
    state_dir.mkdir(parents=True, exist_ok=True)
    return state_dir / STATE_FILE_NAME


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


__all__ = ["save_previous_sha", "load_previous_sha", "STATE_FILE_NAME"]
