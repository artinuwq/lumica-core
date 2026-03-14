from __future__ import annotations

import asyncio
import json
import logging
import os
import sqlite3
from pathlib import Path
from typing import Any

LOG = logging.getLogger(__name__)
DATABASE_FILENAME = "DataBase.db"


def resolve_config_path() -> Path:
    override = os.getenv("BOT_CONFIG_FILE")
    path = Path(override) if override else Path(__file__).with_name("bot.json")
    if path.suffix.lower() != ".json":
        raise ValueError("BOT_CONFIG_FILE must point to a JSON file.")
    return path


def load_config() -> dict[str, Any]:
    config_path = resolve_config_path()
    with config_path.open("r", encoding="utf-8") as handle:
        data = json.load(handle)
    if not isinstance(data, dict):
        raise ValueError(f"Config must be a JSON object: {config_path}")
    return data


def resolve_database_path() -> Path:
    return Path(__file__).resolve().with_name(DATABASE_FILENAME)


def connect_db() -> sqlite3.Connection:
    db_path = resolve_database_path()
    db_path.parent.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(db_path)
    connection.row_factory = sqlite3.Row
    return connection


def init_db(connection: sqlite3.Connection) -> None:
    connection.execute(
        """
        CREATE TABLE IF NOT EXISTS bot_storage (
            key TEXT PRIMARY KEY,
            value TEXT NOT NULL,
            updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
        )
        """
    )
    connection.commit()


def set_db_value(connection: sqlite3.Connection, key: str, value: Any) -> None:
    payload = json.dumps(value, ensure_ascii=False)
    connection.execute(
        """
        INSERT INTO bot_storage (key, value, updated_at)
        VALUES (?, ?, CURRENT_TIMESTAMP)
        ON CONFLICT(key) DO UPDATE SET
            value = excluded.value,
            updated_at = CURRENT_TIMESTAMP
        """,
        (key, payload),
    )
    connection.commit()


def get_db_value(connection: sqlite3.Connection, key: str, default: Any = None) -> Any:
    row = connection.execute("SELECT value FROM bot_storage WHERE key = ?", (key,)).fetchone()
    if row is None:
        return default
    try:
        return json.loads(row["value"])
    except json.JSONDecodeError:
        return default


def delete_db_value(connection: sqlite3.Connection, key: str) -> None:
    connection.execute("DELETE FROM bot_storage WHERE key = ?", (key,))
    connection.commit()


def list_db_values(connection: sqlite3.Connection) -> dict[str, Any]:
    rows = connection.execute("SELECT key, value FROM bot_storage ORDER BY key ASC").fetchall()
    result: dict[str, Any] = {}
    for row in rows:
        try:
            result[str(row["key"])] = json.loads(row["value"])
        except json.JSONDecodeError:
            result[str(row["key"])] = row["value"]
    return result


def resolve_token(config: dict[str, Any]) -> tuple[str, str]:
    token_env = str(config.get("token_env") or "BOT_TOKEN")
    token = os.getenv(token_env, "")
    if not token:
        raise RuntimeError(f"Token environment variable is not set: {token_env}")
    return token_env, token


async def start() -> None:
    # Keep heavy third-party imports here so loader imports stay cheap.
    config = load_config()
    config_path = resolve_config_path()
    db_path = resolve_database_path()
    bot_name = str(config.get("name") or Path(__file__).resolve().parent.name)
    interval = float(config.get("interval_seconds", 5))
    iterations = int(config.get("iterations", 0))
    token_env, token = resolve_token(config)
    token_hint = f"{token[:4]}..." if token else "missing"
    connection = connect_db()

    try:
        init_db(connection)
        tick = int(get_db_value(connection, "last_tick", 0) or 0)
        set_db_value(connection, "bot_name", bot_name)
        set_db_value(connection, "config_path", str(config_path))
        set_db_value(connection, "interval_seconds", interval)
        set_db_value(connection, "status", "running")

        LOG.info(
            "bot=%s config=%s db=%s token_env=%s token=%s last_tick=%s",
            bot_name,
            config_path,
            db_path,
            token_env,
            token_hint,
            tick,
        )

        while True:
            tick += 1
            set_db_value(connection, "last_tick", tick)
            LOG.info("[%s] tick=%s state=%s", bot_name, tick, list_db_values(connection))
            if iterations and tick >= iterations:
                set_db_value(connection, "status", "completed")
                LOG.info("[%s] completed test run", bot_name)
                return
            await asyncio.sleep(interval)
    finally:
        connection.close()


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(asctime)s | %(levelname)s | %(name)s | %(message)s")
    asyncio.run(start())
