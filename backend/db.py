import os
import tempfile
from pathlib import Path

from sqlalchemy import create_engine, text
from sqlalchemy.exc import OperationalError
from sqlalchemy.orm import declarative_base, sessionmaker

BASE_DIR = Path(__file__).resolve().parents[1]
DATABASE_DIR = BASE_DIR / "database"
DATABASE_DIR.mkdir(parents=True, exist_ok=True)

# Allow overriding the DB location to quickly swap out a broken/locked file without code changes.
# Defaults to a fresh file name to avoid the previously corrupted app.db.
DATABASE_URL = os.getenv("DATABASE_URL")
if not DATABASE_URL:
    db_filename = os.getenv("DATABASE_FILE", "app_new.db")
    DATABASE_URL = f"sqlite:///{DATABASE_DIR / db_filename}"


def _build_engine(url: str):
    """Create engine; fall back to TEMP if sqlite reports disk I/O errors."""
    is_sqlite = url.lower().startswith("sqlite")
    kwargs = {
        "future": True,
        "connect_args": {"check_same_thread": False} if is_sqlite else {},
    }
    engine = create_engine(url, **kwargs)

    if not is_sqlite:
        return engine, url

    try:
        # Touch the DB with a tiny write to ensure the location is writable.
        with engine.begin() as conn:
            conn.execute(text("CREATE TABLE IF NOT EXISTS __healthcheck (id INTEGER PRIMARY KEY)"))
    except OperationalError as exc:
        # Common on Windows sandboxes when sqlite cannot lock files in the project directory.
        if "disk i/o error" in str(exc).lower() and not os.getenv("DATABASE_URL"):
            temp_db = Path(tempfile.gettempdir()) / "lumica_app.db"
            fallback_url = f"sqlite:///{temp_db}"
            engine = create_engine(fallback_url, **kwargs)
            return engine, fallback_url
        raise

    return engine, url


engine, DATABASE_URL = _build_engine(DATABASE_URL)
SessionLocal = sessionmaker(bind=engine, autocommit=False, autoflush=False, future=True)
Base = declarative_base()
