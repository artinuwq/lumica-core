import re
from typing import Any

from sqlalchemy.orm import Session

from .models import AppSetting

_SETTING_KEY_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")


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
