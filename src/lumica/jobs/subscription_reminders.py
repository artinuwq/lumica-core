"""Напоминания об окончании подписки.

* В день окончания - всегда (отключить нельзя), в час, который выбрал клиент
  (9:00 / 15:00 / 21:00 MSK; по умолчанию 15:00).
* За 3 дня - только если клиент включил в настройках, в тот же час.
Идемпотентно через NotificationLog: если планировщик проснулся позже нужного
часа, сообщение уйдёт при ближайшем запуске в тот же день.
"""

from __future__ import annotations

import datetime as dt
from zoneinfo import ZoneInfo

from lumica.domain.models import Subscription, User
from lumica.infra.db import SessionLocal
from lumica.services import notifications
from lumica.services.notification_settings import get_settings

MOSCOW = ZoneInfo("Europe/Moscow")
REMINDER_OFFSETS_DAYS = (3, 0)


def _message_for(days_left: int, access_until: dt.datetime) -> str:
    date_str = access_until.strftime("%d.%m.%Y")
    if days_left == 0:
        return f"🔴 Ваша подписка истекает сегодня ({date_str}).\nПродлите подписку, чтобы не потерять доступ."
    return f"🟡 Ваша подписка истекает через {days_left} дн. ({date_str}).\nМожно продлить заранее."


def run_subscription_reminders(now: dt.datetime | None = None) -> None:
    now = now.astimezone(MOSCOW) if now else dt.datetime.now(MOSCOW)
    today = now.date()

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

            settings = get_settings(user)
            if now.hour < settings["expiry_hour"]:
                continue
            if days_left == 3 and not settings["remind_3d"]:
                continue
            # В день оплаты у клиента без группы уже уходит сообщение с кнопками
            # оплаты (payment_due_reminders) - второе такое же не шлём.
            if days_left == 0 and user.group_id is None and sub.billing_day == today.day:
                continue

            key = f"sub_reminder:{sub.id}:{days_left}:{today.isoformat()}"
            category = "remind_3d" if days_left == 3 else "expiry_day"
            notifications.notify_by_preference(db, user, category, _message_for(days_left, sub.access_until), key=key)
        db.commit()


__all__ = ["run_subscription_reminders", "REMINDER_OFFSETS_DAYS"]
