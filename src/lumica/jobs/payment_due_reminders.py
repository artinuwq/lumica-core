"""Monthly payment reminders (in the hour chosen by the payer, 15:00 Moscow by default)."""

from __future__ import annotations

from datetime import datetime
from decimal import Decimal
from zoneinfo import ZoneInfo

from lumica.domain.models import Group, NotificationLog, Subscription, User
from lumica.infra.db import SessionLocal
from lumica.services.notification_settings import get_settings
from lumica.services.notifications import already_sent, send_raw

MOSCOW = ZoneInfo("Europe/Moscow")


def run_payment_due_reminders(now: datetime | None = None) -> None:
    now = now.astimezone(MOSCOW) if now else datetime.now(MOSCOW)
    with SessionLocal() as db:
        subscriptions = (
            db.query(Subscription)
            .filter(Subscription.status.in_(["active", "expiring"]))
            .all()
        )
        processed_groups: set[int] = set()
        for subscription in subscriptions:
            user = db.query(User).filter(User.id == subscription.user_id).first()
            if not user or not user.telegram_id:
                continue
            if user.group_id is not None:
                group_id = user.group_id
                if group_id in processed_groups:
                    continue
                processed_groups.add(group_id)
                group = db.query(Group).filter(Group.id == group_id).first()
                if not group or group.admin_user_id is None:
                    continue
                payer = db.query(User).filter(User.id == group.admin_user_id).first()
                if not payer or not payer.telegram_id:
                    continue
                if now.hour < get_settings(payer)["expiry_hour"]:
                    processed_groups.discard(group_id)
                    continue
                admin_due = db.query(Subscription).filter(
                    Subscription.user_id == payer.id,
                    Subscription.status.in_(["active", "expiring"]),
                    Subscription.billing_day == now.day,
                ).first()
                if not admin_due:
                    continue
                member_ids = [
                    row.id for row in db.query(User.id).filter(User.group_id == group_id).all()
                ]
                due_subscriptions = (
                    db.query(Subscription)
                    .filter(
                        Subscription.user_id.in_(member_ids),
                        Subscription.status.in_(["active", "expiring"]),
                    )
                    .all()
                )
                if not due_subscriptions:
                    continue
                key = f"payment_due:group:{group_id}:{now.date().isoformat()}"
                if already_sent(db, payer.id, key):
                    continue
                amount = Decimal(str(admin_due.price_amount or 0))
                due_lines = []
                for item in due_subscriptions:
                    member = db.query(User).filter(User.id == item.user_id).first()
                    member_name = (member.name or (f"@{member.username}" if member and member.username else None)) if member else None
                    due_lines.append(f"• {member_name or f'Пользователь #{item.user_id}'}")
                text = (
                    f"Сегодня нужно оплатить семейные подписки.\nСумма: {amount}\n\n"
                    + "\n".join(due_lines)
                )
                markup = {"inline_keyboard": [[
                    {"text": "Подтвердить оплату", "callback_data": f"payment:send-group:{group_id}"},
                    {"text": "Реквизиты", "callback_data": f"payment:details-group:{group_id}"},
                ]]}
                sent = send_raw(payer.telegram_id, text, reply_markup=markup)
                db.add(NotificationLog(user_id=payer.id, key=key, success=1 if sent else 0))
                continue
            if subscription.billing_day != now.day:
                continue
            if now.hour < get_settings(user)["expiry_hour"]:
                continue
            key = f"payment_due:{subscription.id}:{now.date().isoformat()}"
            if already_sent(db, user.id, key):
                continue
            amount = subscription.price_amount or "—"
            text = f"Сегодня нужно оплатить подписку.\nСумма: {amount}\n\nПосле перевода пришлите чек."
            markup = {"inline_keyboard": [[
                {"text": "Подтвердить оплату", "callback_data": f"payment:send:{subscription.id}"},
                {"text": "Реквизиты", "callback_data": f"payment:details:{subscription.id}"},
            ]]}
            sent = send_raw(user.telegram_id, text, reply_markup=markup)
            db.add(NotificationLog(user_id=user.id, key=key, success=1 if sent else 0))
        db.commit()
