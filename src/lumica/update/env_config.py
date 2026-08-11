"""Registry of .env settings exposed through `/config` and a dependency-free
.env reader/writer. Deliberately excludes secrets that should never be
echoed back into a chat (TELEGRAM_BOT_TOKEN, SESSION_PEPPER, CSRF_PEPPER).
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlparse

_TRUE_ALIASES = {"1", "true", "yes", "on", "да", "y"}
_FALSE_ALIASES = {"0", "false", "no", "off", "нет", "n"}


@dataclass(frozen=True)
class ConfigSpec:
    key: str
    kind: str  # text | bool | int | url
    description: str
    allow_empty: bool = False
    secret: bool = False


REGISTRY: dict[str, ConfigSpec] = {
    spec.key: spec
    for spec in [
        ConfigSpec("WEBAPP_URL", "url", "URL Telegram mini app, открываемого кнопкой /start"),
        ConfigSpec("ADMIN_TELEGRAM_IDS", "text", "Telegram ID администраторов через запятую", allow_empty=True),
        ConfigSpec("OWNER_TELEGRAM_IDS", "text", "Telegram ID владельцев через запятую", allow_empty=True),
        ConfigSpec("SUPPORT_TELEGRAM_IDS", "text", "Telegram ID саппорта через запятую", allow_empty=True),
        ConfigSpec("FLASK_HOST", "text", "Адрес, на котором слушает веб-сервер"),
        ConfigSpec("FLASK_PORT", "int", "Порт веб-сервера"),
        ConfigSpec("WEB_SERVER", "text", "Бэкенд веб-сервера: waitress или flask"),
        ConfigSpec("WEB_THREADS", "int", "Число потоков waitress"),
        ConfigSpec("SESSION_TTL_DAYS", "int", "Время жизни сессии в днях"),
        ConfigSpec("SESSION_COOKIE_NAME", "text", "Имя cookie сессии"),
        ConfigSpec("DATABASE_URL", "text", "Полный DSN базы данных (переопределяет DATABASE_FILE)", allow_empty=True),
        ConfigSpec("DATABASE_FILE", "text", "Имя файла sqlite внутри database/"),
        ConfigSpec("UPDATE_BRANCH", "text", "Ветка git, используемая /update"),
        ConfigSpec("UPDATE_SERVICE_NAME", "text", "Имя systemd unit, который перезапускает /restart"),
    ]
}

# Never allow these through /config even if someone adds them by hand.
_BLOCKED_KEYS = {"TELEGRAM_BOT_TOKEN", "SESSION_PEPPER", "CSRF_PEPPER", "ROLE_BINDINGS"}


class ConfigError(ValueError):
    pass


def get_spec(key: str) -> ConfigSpec:
    key = (key or "").strip().upper()
    if key in _BLOCKED_KEYS:
        raise ConfigError(f"{key} нельзя читать/менять через /config (секрет)")
    spec = REGISTRY.get(key)
    if not spec:
        raise ConfigError(f"неизвестный ключ настройки: {key}")
    return spec


def validate_value(spec: ConfigSpec, raw_value: str) -> str:
    value = (raw_value or "").strip()
    if not value:
        if spec.allow_empty:
            return ""
        raise ConfigError(f"{spec.key} не может быть пустым")

    if spec.kind == "bool":
        normalized = value.strip().lower()
        if normalized in _TRUE_ALIASES:
            return "true"
        if normalized in _FALSE_ALIASES:
            return "false"
        raise ConfigError(f"{spec.key}: ожидалось булево значение (да/нет/true/false/1/0)")

    if spec.kind == "int":
        try:
            return str(int(value))
        except ValueError as exc:
            raise ConfigError(f"{spec.key}: ожидалось целое число") from exc

    if spec.kind == "url":
        parsed = urlparse(value)
        if not parsed.scheme or not parsed.netloc:
            raise ConfigError(f"{spec.key}: ожидался полный URL (со схемой и хостом)")
        return value

    return value


def read_env_value(env_path: Path, key: str) -> str | None:
    if not env_path.is_file():
        return None
    for line in env_path.read_text(encoding="utf-8").splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        line_key, sep, value = stripped.partition("=")
        if sep == "=" and line_key.strip() == key:
            return value.strip().strip("'\"")
    return None


def write_env_value(env_path: Path, key: str, value: str) -> None:
    """Replace `KEY=...` in place if present, otherwise append it. No
    external libraries - this file is meant to stay readable/editable by
    hand, so we don't rewrite formatting or reorder unrelated lines.
    """
    lines = env_path.read_text(encoding="utf-8").splitlines() if env_path.is_file() else []
    quoted = f'"{value}"' if (" " in value or "" == value) else value
    new_line = f"{key}={quoted}"

    replaced = False
    for index, line in enumerate(lines):
        stripped = line.strip()
        if stripped.startswith("#") or "=" not in stripped:
            continue
        line_key = stripped.split("=", 1)[0].strip()
        if line_key == key:
            lines[index] = new_line
            replaced = True
            break

    if not replaced:
        lines.append(new_line)

    env_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    # keep the live process in sync without requiring a restart
    os.environ[key] = value


def delete_env_value(env_path: Path, key: str) -> bool:
    if not env_path.is_file():
        return False
    lines = env_path.read_text(encoding="utf-8").splitlines()
    kept = []
    removed = False
    for line in lines:
        stripped = line.strip()
        if not stripped.startswith("#") and "=" in stripped and stripped.split("=", 1)[0].strip() == key:
            removed = True
            continue
        kept.append(line)
    if removed:
        env_path.write_text("\n".join(kept) + ("\n" if kept else ""), encoding="utf-8")
        os.environ.pop(key, None)
    return removed


__all__ = [
    "ConfigSpec",
    "ConfigError",
    "REGISTRY",
    "get_spec",
    "validate_value",
    "read_env_value",
    "write_env_value",
    "delete_env_value",
]
