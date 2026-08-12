"""Платежи (ручной перевод + подтверждение админом, ТЗ п.9). Единственное
место с этой бизнес-логикой - api/routes/payments.py только вызывает эти
функции, как и applications.py / UpdateManager."""

from __future__ import annotations

from datetime import timedelta

from lumica.domain.models import Payment, Subscription
from lumica.services import subscriptions as subscriptions_service

DRAFT_STATUSES = {"draft", "inactive"}


class PaymentError(ValueError):
    pass


def create_payment(db, *, user_id: int, subscription_id: int) -> Payment:
    subscription = (
        db.query(Subscription)
        .filter(Subscription.id == subscription_id, Subscription.user_id == user_id)
        .first()
    )
    if not subscription:
        raise PaymentError("подписка (черновик) не найдена")
    if (subscription.status or "").strip().lower() not in DRAFT_STATUSES:
        raise PaymentError("платёж можно создать только для черновика подписки")

    existing_pending = (
        db.query(Payment)
        .filter(Payment.subscription_id == subscription_id, Payment.status == "pending")
        .first()
    )
    if existing_pending:
        raise PaymentError("по этой подписке уже есть платёж, ожидающий подтверждения")

    amount = subscription.total_price if subscription.total_price is not None else subscription.price_amount
    if amount is None:
        raise PaymentError("у черновика подписки не рассчитана стоимость")

    payment = Payment(user_id=user_id, subscription_id=subscription_id, amount=amount, status="pending")
    db.add(payment)
    db.flush()
    return payment


def confirm_payment(db, payment: Payment, *, staff_user_id: int) -> Subscription:
    """Подтверждает платёж и активирует привязанную подписку. Использует ту
    же логику расчёта, что и self-serve /api/subscription/confirm
    (lumica.services.subscriptions.calculate_subscription_pricing), поэтому
    ручное и самостоятельное подтверждение всегда считают цену одинаково."""
    if payment.status != "pending":
        raise PaymentError(f"нельзя подтвердить платёж в статусе {payment.status}")

    subscription = db.query(Subscription).filter(Subscription.id == payment.subscription_id).first()
    if not subscription:
        raise PaymentError("подписка не найдена")
    if (subscription.status or "").strip().lower() not in DRAFT_STATUSES:
        raise PaymentError(f"подписка уже не в статусе черновика ({subscription.status})")

    payload = subscription.payload if isinstance(subscription.payload, dict) else {}
    plan_payload = {
        "plan_id": payload.get("plan_id"),
        "plan_name": payload.get("plan_name"),
        "duration_months": payload.get("duration_months"),
        "items": payload.get("items"),
        "lifetime": payload.get("lifetime"),
    }

    try:
        plan = subscriptions_service.resolve_plan(db, plan_payload)
        pricing = subscriptions_service.calculate_subscription_pricing(plan, plan_payload)
    except subscriptions_service.PricingError as exc:
        raise PaymentError(str(exc)) from exc

    now = subscriptions_service.utcnow()
    subscription.price_amount = pricing["total"]
    subscription.total_price = pricing["total"]
    if pricing["is_lifetime"]:
        subscription.status = "lifetime"
        subscription.access_until = None
    else:
        subscription.status = "active"
        duration_months = max(pricing["duration_months"], 1)
        subscription.access_until = now + timedelta(days=30 * duration_months)

    payload["confirmed_at"] = now.isoformat()
    payload["status"] = subscription.status
    subscription.payload = payload

    payment.status = "confirmed"
    payment.confirmed_by = staff_user_id
    payment.confirmed_at = now
    return subscription


def reject_payment(db, payment: Payment, *, staff_user_id: int, reason: str | None = None) -> None:
    if payment.status != "pending":
        raise PaymentError(f"нельзя отклонить платёж в статусе {payment.status}")
    payment.status = "rejected"
    payment.confirmed_by = staff_user_id
    payment.confirmed_at = subscriptions_service.utcnow()
    payment.reject_reason = (reason or "").strip() or None


def cancel_payment(db, payment: Payment) -> None:
    if payment.status != "pending":
        raise PaymentError(f"нельзя отменить платёж в статусе {payment.status}")
    payment.status = "cancelled"


__all__ = [
    "PaymentError",
    "create_payment",
    "confirm_payment",
    "reject_payment",
    "cancel_payment",
]
