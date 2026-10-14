"""Pre-update SQLite backups (stdlib only).

Before every update the sqlite files under `database/` are copied with the
sqlite3 online-backup API (safe while the service is running) into
`database/backups/<timestamp>-<sha>/`. The last few backups are kept.
External databases (DATABASE_URL pointing at non-sqlite) are not touched -
those need their own backup tooling.
"""

from __future__ import annotations

import shutil
import sqlite3
from datetime import datetime
from pathlib import Path

BACKUPS_DIR_NAME = "backups"
KEEP_BACKUPS = 5
_DB_SUFFIXES = {".db", ".sqlite3", ".sqlite"}


def _sqlite_files(state_dir: Path) -> list[Path]:
    if not state_dir.is_dir():
        return []
    return sorted(p for p in state_dir.iterdir() if p.is_file() and p.suffix in _DB_SUFFIXES)


def alembic_revision(db_file: Path) -> str | None:
    """Current alembic revision stored in a sqlite file (None if absent)."""
    if not db_file.is_file():
        return None
    try:
        with sqlite3.connect(f"file:{db_file}?mode=ro", uri=True, timeout=5) as conn:
            row = conn.execute("SELECT version_num FROM alembic_version").fetchone()
        return row[0] if row else None
    except sqlite3.Error:
        return None


def create_backup(state_dir: Path, label: str) -> Path | None:
    """Returns the backup directory, or None if there was nothing to back up."""
    files = _sqlite_files(state_dir)
    if not files:
        return None

    stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    target = state_dir / BACKUPS_DIR_NAME / f"{stamp}-{label[:8]}"
    target.mkdir(parents=True, exist_ok=True)

    try:
        for db_file in files:
            src = sqlite3.connect(f"file:{db_file}?mode=ro", uri=True, timeout=30)
            dst = sqlite3.connect(target / db_file.name)
            try:
                src.backup(dst)
            finally:
                dst.close()
                src.close()
    except (sqlite3.Error, OSError):
        shutil.rmtree(target, ignore_errors=True)
        raise

    _prune(state_dir / BACKUPS_DIR_NAME)
    return target


def _prune(backups_dir: Path) -> None:
    entries = sorted(p for p in backups_dir.iterdir() if p.is_dir())
    for old in entries[:-KEEP_BACKUPS]:
        shutil.rmtree(old, ignore_errors=True)


def latest_backup(state_dir: Path) -> Path | None:
    backups_dir = state_dir / BACKUPS_DIR_NAME
    if not backups_dir.is_dir():
        return None
    entries = sorted(p for p in backups_dir.iterdir() if p.is_dir())
    return entries[-1] if entries else None


def schema_changed_since(state_dir: Path, backup_dir: Path) -> bool:
    """True if any live db has a different alembic revision than its backup,
    i.e. a migration ran after the backup was taken."""
    for backup_file in _sqlite_files(backup_dir):
        if alembic_revision(backup_file) != alembic_revision(state_dir / backup_file.name):
            return True
    return False


def restore_backup(state_dir: Path, backup_dir: Path) -> None:
    """Copy backed-up sqlite files back. The service MUST be stopped."""
    for backup_file in _sqlite_files(backup_dir):
        live = state_dir / backup_file.name
        for suffix in ("-wal", "-shm"):
            Path(str(live) + suffix).unlink(missing_ok=True)
        shutil.copy2(backup_file, live)


__all__ = [
    "create_backup",
    "latest_backup",
    "restore_backup",
    "schema_changed_since",
    "alembic_revision",
    "BACKUPS_DIR_NAME",
]
