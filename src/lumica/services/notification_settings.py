"""Настройки уведомлений клиента (хранятся в User.profile_data["notifications"]).

* Уведомление в день окончания подписки отключить нельзя - клиент выбирает
  только час отправки (MSK): 9:00, 15:00 или 21:00.
* «За 3 дня» - по желанию, по умолчанию выключено; выключено = не отправляем.
* Подтверждение оплаты, отказ в оплате и обновления подписки включены по
  умолчанию. Выключенные не пропадают, а приходят без звука
  (disable_notification): так клиент всё равно увидит сообщение в чате.
"""

from __future__ import annotations

EXPIRY_HOURS = (9, 15, 21)
DEFAULT_EXPIRY_HOUR = 15
SETTINGS_KEY = "notifications"

TOGGLE_DEFAULTS: dict[str, bool] = {
    "remind_3d": False,
    "payment_confirmed": True,
    "payment_rejected": True,
    "subscription_updates": True,
}
# Если категория выключена, сообщение всё равно отправляется, но тихо.
SILENT_WHEN_OFF = frozenset({"payment_confirmed", "payment_rejected", "subscription_updates"})


def get_settings(user) -> dict:
    profile = getattr(user, "profile_data", None)
    raw = profile.get(SETTINGS_KEY) if isinstance(profile, dict) else None
    raw = raw if isinstance(raw, dict) else {}
    hour = raw.get("expiry_hour")
    settings: dict = {"expiry_hour": hour if hour in EXPIRY_HOURS else DEFAULT_EXPIRY_HOUR}
    for key, default in TOGGLE_DEFAULTS.items():
        value = raw.get(key)
        settings[key] = value if isinstance(value, bool) else default
    return settings


def update_settings(user, **changes) -> dict:
    settings = get_settings(user)
    for key, value in changes.items():
        if key == "expiry_hour":
            if value not in EXPIRY_HOURS:
                raise ValueError("Недопустимое время уведомления")
        elif key in TOGGLE_DEFAULTS:
            if not isinstance(value, bool):
                raise ValueError("Значение должно быть true/false")
        else:
            raise ValueError(f"Неизвестная настройка: {key}")
        settings[key] = value
    profile = dict(user.profile_data) if isinstance(user.profile_data, dict) else {}
    profile[SETTINGS_KEY] = settings
    user.profile_data = profile  # новое значение, чтобы SQLAlchemy заметил изменение JSON
    return settings


def is_silent(user, category: str) -> bool:
    """Нужно ли слать сообщение этой категории без звука."""
    return category in SILENT_WHEN_OFF and not get_settings(user).get(category, True)


__all__ = [
    "EXPIRY_HOURS", "DEFAULT_EXPIRY_HOUR", "TOGGLE_DEFAULTS", "SILENT_WHEN_OFF",
    "get_settings", "update_settings", "is_silent",
]
