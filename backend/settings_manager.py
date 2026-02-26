import re
from typing import Any

from sqlalchemy.orm import Session

from .db import SessionLocal
from .models import AppSetting

_SETTING_KEY_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")

CLOUD_VISIBILITY_KEY = "cloud.visibility"
CLOUD_UPLOAD_CHUNK_SIZE_MB_KEY = "cloud.upload.chunk_size_mb"
CLOUD_TELEGRAM_SEND_TIMEOUT_SEC_KEY = "cloud.telegram.send.timeout_sec"
CLOUD_TELEGRAM_SEND_RETRIES_KEY = "cloud.telegram.send.retries"
CLOUD_TELEGRAM_SEND_RETRY_DELAY_SEC_KEY = "cloud.telegram.send.retry_delay_sec"


def to_bool(value: Any, default: bool = False) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return bool(value)
    if isinstance(value, str):
        normalized = value.strip().lower()
        if normalized in {"1", "true", "yes", "on"}:
            return True
        if normalized in {"0", "false", "no", "off"}:
            return False
    return default


def to_int(value: Any, default: int, *, min_value: int | None = None, max_value: int | None = None) -> int:
    try:
        out = int(value)
    except (TypeError, ValueError):
        out = int(default)
    if min_value is not None:
        out = max(min_value, out)
    if max_value is not None:
        out = min(max_value, out)
    return out


def normalize_setting_key(raw_key: str) -> str:
    key = str(raw_key or "").strip()
    if not key:
        raise ValueError("setting key is required")
    if not _SETTING_KEY_PATTERN.fullmatch(key):
        raise ValueError(
            "invalid setting key: use letters, numbers, dot, underscore, colon, hyphen; max length is 128"
        )
    return key


class SettingsManager:
    def __init__(self, db: Session):
        self.db = db

    def list_settings(self, prefix: str | None = None) -> list[AppSetting]:
        query = self.db.query(AppSetting)
        if prefix:
            query = query.filter(AppSetting.key.like(f"{prefix}%"))
        return query.order_by(AppSetting.key.asc()).all()

    def get_setting(self, key: str) -> AppSetting | None:
        normalized_key = normalize_setting_key(key)
        return self.db.query(AppSetting).filter(AppSetting.key == normalized_key).first()

    def get_value(self, key: str, default: Any = None) -> Any:
        row = self.get_setting(key)
        return row.value_json if row else default

    def get_values(self, keys: list[str]) -> dict[str, Any]:
        normalized_keys = [normalize_setting_key(item) for item in keys]
        if not normalized_keys:
            return {}
        rows = self.db.query(AppSetting).filter(AppSetting.key.in_(normalized_keys)).all()
        return {row.key: row.value_json for row in rows}

    def set_setting(self, key: str, value: Any, description: str | None = None) -> tuple[AppSetting, bool]:
        normalized_key = normalize_setting_key(key)
        row = self.db.query(AppSetting).filter(AppSetting.key == normalized_key).first()
        created = False
        if not row:
            row = AppSetting(key=normalized_key)
            self.db.add(row)
            created = True

        row.value_json = value
        if description is not None:
            row.description = description.strip() or None

        self.db.flush()
        return row, created

    def delete_setting(self, key: str) -> bool:
        row = self.get_setting(key)
        if not row:
            return False
        self.db.delete(row)
        self.db.flush()
        return True


def get_runtime_setting_value(key: str, default: Any = None) -> Any:
    try:
        with SessionLocal() as db:
            return SettingsManager(db).get_value(key, default=default)
    except Exception:
        return default


def get_runtime_setting_values(keys: list[str]) -> dict[str, Any]:
    try:
        with SessionLocal() as db:
            return SettingsManager(db).get_values(keys)
    except Exception:
        return {}
