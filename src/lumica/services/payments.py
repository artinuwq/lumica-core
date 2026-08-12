"""Платежи (ручной перевод + подтверждение админом, ТЗ п.9). Единственное
место с этой бизнес-логикой - api/routes/payments.py только вызывает эти
функции, как и applications.py / UpdateManager.

Платёж может покрывать одну подписку (обычный клиент) или сразу несколько
(групповой платёж - платит только администратор группы за всех участников
разом, одним переводом). Какие подписки покрывает платёж определяется через
Subscription.payment_id."""

from __future__ import annotations

from datetime import timedelta

from lumica.domain.models import Group, Payment, Subscription, User
from lumica.services import groups as groups_service
from lumica.services import subscriptions as subscriptions_service

DRAFT_STATUSES = {"draft", "inactive"}


class PaymentError(ValueError):
    pass


def _draft_subscriptions_or_error(db, subscription_ids: list[int]) -> list[Subscription]:
    if not subscription_ids:
        raise PaymentError("нужно указать хотя бы одну подписку")

    subscriptions = db.query(Subscription).filter(Subscription.id.in_(subscription_ids)).all()
    found_ids = {s.id for s in subscriptions}
    missing = set(subscription_ids) - found_ids
    if missing:
        raise PaymentError(f"подписки не найдены: {sorted(missing)}")

    for subscription in subscriptions:
        if (subscription.status or "").strip().lower() not in DRAFT_STATUSES:
            raise PaymentError(f"подписка {subscription.id} уже не в статусе черновика ({subscription.status})")
        if subscription.payment_id is not None:
            raise PaymentError(f"подписка {subscription.id} уже привязана к другому платежу")

    return subscriptions


def _sum_amount(subscriptions: list[Subscription]):
    total = None
    for subscription in subscriptions:
        amount = subscription.total_price if subscription.total_price is not None else subscription.price_amount
        if amount is None:
            raise PaymentError(f"у подписки {subscription.id} не рассчитана стоимость")
        total = amount if total is None else total + amount
    return total


def create_payment(db, *, user_id: int, subscription_id: int) -> Payment:
    """Обычный (не групповой) платёж - за одну подписку, платит сам клиент."""
    subscriptions = _draft_subscriptions_or_error(db, [subscription_id])
    subscription = subscriptions[0]
    if subscription.user_id != user_id:
        raise PaymentError("эта подписка не принадлежит пользователю")

    amount = _sum_amount(subscriptions)
    payment = Payment(user_id=user_id, amount=amount, status="pending")
    db.add(payment)
    db.flush()
    subscription.payment_id = payment.id
    return payment


def create_group_payment(db, *, admin_user_id: int, group_id: int, subscription_ids: list[int]) -> Payment:
    """Групповой платёж - платит администратор группы разом за подписки
    нескольких участников этой же группы."""
    group = db.query(Group).filter(Group.id == group_id).first()
    if not group:
        raise PaymentError("группа не найдена")
    admin_user = db.query(User).filter(User.id == admin_user_id).first()
    if not admin_user or not groups_service.is_group_admin(admin_user, group):
        raise PaymentError("платить за группу может только администратор этой группы")

    subscriptions = _draft_subscriptions_or_error(db, subscription_ids)
    member_ids = {u.id for u in db.query(User).filter(User.group_id == group_id).all()}
    for subscription in subscriptions:
        if subscription.user_id not in member_ids:
            raise PaymentError(f"подписка {subscription.id} принадлежит пользователю не из этой группы")

    amount = _sum_amount(subscriptions)
    payment = Payment(user_id=admin_user_id, group_id=group_id, amount=amount, status="pending")
    db.add(payment)
    db.flush()
    for subscription in subscriptions:
        subscription.payment_id = payment.id
    return payment


def confirm_payment(db, payment: Payment, *, staff_user_id: int) -> list[Subscription]:
    """Подтверждает платёж и активирует все привязанные к нему подписки
    (одну для обычного платежа, несколько - для группового). Использует ту
    же логику расчёта, что и self-serve /api/subscription/confirm."""
    if payment.status != "pending":
        raise PaymentError(f"нельзя подтвердить платёж в статусе {payment.status}")

    subscriptions = db.query(Subscription).filter(Subscription.payment_id == payment.id).all()
    if not subscriptions:
        raise PaymentError("к этому платежу не привязано ни одной подписки")

    now = subscriptions_service.utcnow()
    activated: list[Subscription] = []
    for subscription in subscriptions:
        if (subscription.status or "").strip().lower() not in DRAFT_STATUSES:
            raise PaymentError(f"подписка {subscription.id} уже не в статусе черновика ({subscription.status})")

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
            raise PaymentError(f"подписка {subscription.id}: {exc}") from exc

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
        activated.append(subscription)

    payment.status = "confirmed"
    payment.confirmed_by = staff_user_id
    payment.confirmed_at = now
    return activated


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
    # освобождаем подписки, чтобы их можно было привязать к новому платежу
    db.query(Subscription).filter(Subscription.payment_id == payment.id).update({Subscription.payment_id: None})


__all__ = [
    "PaymentError",
    "create_payment",
    "create_group_payment",
    "confirm_payment",
    "reject_payment",
    "cancel_payment",
]
