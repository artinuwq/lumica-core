"""Прямая синхронная отправка сообщений в Telegram + идемпотентность через
NotificationLog. Без очередей и ретраев - для сжатых сроков этого хватает;
если Telegram недоступен, попытка просто не пишется в лог и будет
повторена на следующем цикле планировщика."""

from __future__ import annotations

import logging
import os

import requests

from lumica.domain.models import NotificationLog, User

logger = logging.getLogger(__name__)

TELEGRAM_API_URL = "https://api.telegram.org/bot{token}/sendMessage"
REQUEST_TIMEOUT_SECONDS = 10


def send_raw(telegram_id: str | None, text: str) -> bool:
    token = os.getenv("TELEGRAM_BOT_TOKEN")
    if not token or not telegram_id:
        return False
    try:
        response = requests.post(
            TELEGRAM_API_URL.format(token=token),
            json={"chat_id": telegram_id, "text": text},
            timeout=REQUEST_TIMEOUT_SECONDS,
        )
        return response.ok
    except requests.RequestException:
        logger.exception("Failed to send Telegram message to %s", telegram_id)
        return False


def already_sent(db, user_id: int, key: str) -> bool:
    return db.query(NotificationLog).filter(NotificationLog.user_id == user_id, NotificationLog.key == key).first() is not None


def notify_user(db, user: User, key: str, text: str) -> bool:
    """Отправляет и логирует. Идемпотентно по (user_id, key) - вызывающий
    код сам решает, что включать в key (например дату), чтобы не слать
    повторно за тот же день."""
    if already_sent(db, user.id, key):
        return False
    ok = send_raw(user.telegram_id, text)
    db.add(NotificationLog(user_id=user.id, key=key, success=1 if ok else 0))
    db.flush()
    return ok


def notify_admins(text: str) -> None:
    from lumica.services.roles import load_role_bindings

    bindings = load_role_bindings()
    admin_ids = {tg_id for tg_id, role in bindings.items() if role in ("admin", "owner")}
    for tg_id in admin_ids:
        send_raw(tg_id, text)


__all__ = ["send_raw", "already_sent", "notify_user", "notify_admins"]
