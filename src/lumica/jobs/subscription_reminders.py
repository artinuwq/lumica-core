"""Простое напоминание об истечении подписки: только за 3 дня и в день
истечения (как попросили - без полной настраиваемой системы офсетов).
Идемпотентно через NotificationLog (см. services/notifications.py)."""

from __future__ import annotations

import datetime as dt

from lumica.domain.models import Subscription, User
from lumica.infra.db import SessionLocal
from lumica.services import notifications

REMINDER_OFFSETS_DAYS = (3, 0)


def _message_for(days_left: int, access_until: dt.datetime) -> str:
    date_str = access_until.strftime("%d.%m.%Y")
    if days_left == 0:
        return f"🔴 Ваша подписка истекает сегодня ({date_str}).\nПродлите подписку, чтобы не потерять доступ."
    return f"🟡 Ваша подписка истекает через {days_left} дн. ({date_str}).\nМожно продлить заранее."


def run_subscription_reminders() -> None:
    today = dt.datetime.now(dt.timezone.utc).date()

    with SessionLocal() as db:
        subs = (
            db.query(Subscription)
            .filter(Subscription.status.in_(["active", "expiring"]))
            .filter(Subscription.access_until.isnot(None))
            .all()
        )
        for sub in subs:
            days_left = (sub.access_until.date() - today).days
            if days_left not in REMINDER_OFFSETS_DAYS:
                continue

            user = db.query(User).filter(User.id == sub.user_id).first()
            if not user or not user.telegram_id:
                continue

            key = f"sub_reminder:{sub.id}:{days_left}:{today.isoformat()}"
            notifications.notify_user(db, user, key, _message_for(days_left, sub.access_until))
        db.commit()


__all__ = ["run_subscription_reminders", "REMINDER_OFFSETS_DAYS"]
