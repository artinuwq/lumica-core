"""Уведомление клиенту об изменении его подписки (статус, срок, цена, заморозка)."""

from __future__ import annotations

import logging
from decimal import Decimal, InvalidOperation

from lumica.services import notifications

logger = logging.getLogger(__name__)

STATUS_LABELS = {
    "active": "Активна",
    "lifetime": "Бессрочная",
    "paused": "На паузе",
    "expired": "Истекла",
    "canceled": "Отменена",
    "inactive": "Неактивна",
    "expiring": "Скоро закончится",
}


def snapshot(subscription) -> dict | None:
    if subscription is None:
        return None
    return {
        "status": (subscription.status or "").strip().lower(),
        "access_until": subscription.access_until.date().isoformat() if subscription.access_until else None,
        "price": str(subscription.price_amount) if subscription.price_amount is not None else None,
        "frozen": bool(getattr(subscription, "is_frozen", False)),
    }


def _fmt_date(value: str | None, status: str) -> str:
    if status == "lifetime":
        return "Бессрочно"
    if not value:
        return "не указана"
    year, month, day = value.split("-")
    return f"{day}.{month}.{year}"


def _fmt_price(value: str | None) -> str:
    if value is None:
        return "—"
    try:
        text = f"{Decimal(value):f}"
    except InvalidOperation:
        return value
    if "." in text:
        text = text.rstrip("0").rstrip(".")
    return f"{text} ₽"


def describe_changes(before: dict | None, after: dict | None) -> str | None:
    """Текст про изменения или None, если для клиента ничего не изменилось
    (создание подписки и правки заметок/реквизитов уведомлением не считаются)."""
    if not before or not after:
        return None
    lines = []
    if before["status"] != after["status"]:
        old = STATUS_LABELS.get(before["status"], before["status"])
        new = STATUS_LABELS.get(after["status"], after["status"])
        lines.append(f"• Статус: {old} → {new}")
    if before["access_until"] != after["access_until"] or (
        before["status"] != after["status"] and "lifetime" in (before["status"], after["status"])
    ):
        lines.append(
            f"• Дата оплаты до: {_fmt_date(before['access_until'], before['status'])}"
            f" → {_fmt_date(after['access_until'], after['status'])}"
        )
    if before["price"] != after["price"]:
        lines.append(f"• Цена: {_fmt_price(before['price'])} → {_fmt_price(after['price'])}")
    if before["frozen"] != after["frozen"]:
        lines.append("• Подписка заморожена" if after["frozen"] else "• Заморозка снята")
    if not lines:
        return None
    return "🔄 Ваша подписка обновлена\n" + "\n".join(lines)


def notify_subscription_updated(db, user, before: dict | None, after: dict | None) -> bool:
    """Отправляет клиенту сообщение об изменениях. Ошибки доставки не ломают операцию админа."""
    text = describe_changes(before, after)
    if not text or not getattr(user, "telegram_id", None):
        return False
    try:
        return notifications.notify_by_preference(db, user, "subscription_updates", text)
    except Exception:  # noqa: BLE001
        logger.exception("Could not notify user %s about subscription update", user.id)
        return False


__all__ = ["snapshot", "describe_changes", "notify_subscription_updated", "STATUS_LABELS"]
