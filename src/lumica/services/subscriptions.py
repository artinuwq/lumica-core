import os
from datetime import datetime, timezone
from decimal import Decimal, InvalidOperation

from lumica.infra.db import SessionLocal
from lumica.domain.models import Panel, PanelInbound, Subscription, SubscriptionPlan, VpnAccount
from lumica.services.panels import PanelRegistry


class PricingError(ValueError):
    """Raised by plan/pricing helpers below. status_code mirrors what the
    HTTP layer should respond with; callers that don't care (e.g. the
    payments service) can just catch ValueError."""

    def __init__(self, message: str, status_code: int = 400):
        super().__init__(message)
        self.status_code = status_code


def plan_meta(plan: SubscriptionPlan) -> dict:
    return plan.meta_json if isinstance(plan.meta_json, dict) else {}


def plan_item_price_map(plan: SubscriptionPlan) -> dict[tuple[str | None, str], Decimal]:
    meta = plan_meta(plan)
    raw_items = []
    for key in ("items", "addons", "options"):
        value = meta.get(key)
        if isinstance(value, list):
            raw_items.extend(value)
    prices: dict[tuple[str | None, str], Decimal] = {}
    for item in raw_items:
        if not isinstance(item, dict):
            continue
        code = str(item.get("code") or "").strip()
        if not code:
            continue
        item_type = str(item.get("item_type") or item.get("type") or "").strip().lower()
        item_type = item_type or None
        raw_price = item.get("price") or item.get("amount") or item.get("cost")
        try:
            price = Decimal(str(raw_price)) if raw_price not in (None, "") else None
        except (InvalidOperation, ValueError):
            price = None
        if price is None:
            continue
        prices[(item_type, code)] = price
        if item_type is not None:
            prices[(None, code)] = price
    return prices


def resolve_plan(db, payload: dict) -> SubscriptionPlan:
    plan_id_raw = payload.get("plan_id") or payload.get("plan") or payload.get("planId")
    plan_name_raw = payload.get("plan_name") or payload.get("planName") or payload.get("plan_code") or payload.get("planCode")

    plan = None
    if plan_id_raw not in (None, ""):
        try:
            plan_id = int(plan_id_raw)
        except (TypeError, ValueError):
            raise PricingError("plan_id must be an integer")
        plan = db.query(SubscriptionPlan).filter(SubscriptionPlan.id == plan_id).first()
    elif plan_name_raw:
        name = str(plan_name_raw).strip()
        if name:
            plan = db.query(SubscriptionPlan).filter(SubscriptionPlan.name == name).first()

    if not plan:
        raise PricingError("Plan not found", 404)
    if not plan.is_active:
        raise PricingError("Plan is inactive")
    return plan


def _int_or_error(value, field: str, *, default: int | None = None, min_value: int | None = None) -> int | None:
    if value in (None, ""):
        return default
    try:
        out = int(value)
    except (TypeError, ValueError):
        raise PricingError(f"{field} must be an integer")
    if min_value is not None and out < min_value:
        raise PricingError(f"{field} must be >= {min_value}")
    return out


def subscription_duration_months(plan: SubscriptionPlan, payload: dict) -> int:
    meta = plan_meta(plan)
    raw_duration = (
        payload.get("duration_months")
        or payload.get("durationMonths")
        or payload.get("months")
        or payload.get("period_months")
        or payload.get("periodMonths")
        or meta.get("duration_months")
        or meta.get("months")
    )
    return _int_or_error(raw_duration, "duration_months", default=1, min_value=0)


def calculate_subscription_pricing(plan: SubscriptionPlan, payload: dict) -> dict:
    """Single source of truth for subscription pricing - used by the
    self-serve draft/confirm endpoints and by the payments flow, so a
    manually-confirmed bank transfer and a self-serve confirm always price
    the same plan the same way."""
    duration_months = subscription_duration_months(plan, payload)
    base_price = plan.base_price or Decimal("0")
    try:
        base_price = Decimal(str(base_price))
    except (InvalidOperation, ValueError):
        base_price = Decimal("0")

    meta = plan_meta(plan)
    is_lifetime = bool(payload.get("lifetime") or meta.get("lifetime"))
    if duration_months == 0 and is_lifetime is False:
        is_lifetime = True

    items_payload = payload.get("items") or payload.get("addons") or []
    if items_payload in (None, ""):
        items_payload = []
    if not isinstance(items_payload, list):
        raise PricingError("items must be a list")

    price_map = plan_item_price_map(plan)
    items = []
    items_total = Decimal("0")
    for raw_item in items_payload:
        if not isinstance(raw_item, dict):
            raise PricingError("items must contain objects")
        code = str(raw_item.get("code") or "").strip()
        if not code:
            raise PricingError("item code is required")
        item_type = str(raw_item.get("item_type") or raw_item.get("type") or "addon").strip().lower() or "addon"
        quantity = _int_or_error(raw_item.get("quantity"), "item quantity", default=1, min_value=1)
        price = price_map.get((item_type, code)) or price_map.get((None, code))
        if price is None:
            raise PricingError(f"Unknown price for item {code}")
        item_total = price * Decimal(quantity)
        items_total += item_total
        items.append(
            {
                "item_type": item_type,
                "code": code,
                "price": price,
                "quantity": quantity,
                "total": item_total,
                "meta": raw_item.get("meta") if isinstance(raw_item.get("meta"), dict) else {},
            }
        )

    total = base_price if is_lifetime else base_price * Decimal(max(duration_months, 1))
    total += items_total
    return {
        "duration_months": duration_months,
        "is_lifetime": is_lifetime,
        "base_price": base_price,
        "items_total": items_total,
        "total": total,
        "items": items,
    }


def utcnow():
    return datetime.now(timezone.utc)


def as_utc(value: datetime | None) -> datetime | None:
    if not value:
        return None
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


def run() -> int:
    changed = 0
    should_disable = os.getenv("DISABLE_CLIENTS_ON_EXPIRE", "true").strip().lower() in {"1", "true", "yes", "on"}
    registry = PanelRegistry() if should_disable else None

    with SessionLocal() as db:
        subs = (
            db.query(Subscription)
            .filter(Subscription.status == "active", Subscription.access_until.isnot(None))
            .all()
        )
        now = utcnow()

        for sub in subs:
            access_until = as_utc(sub.access_until)
            if not access_until or access_until >= now:
                continue

            sub.status = "expired"
            changed += 1

            if should_disable and registry:
                accounts = (
                    db.query(VpnAccount)
                    .filter(VpnAccount.user_id == sub.user_id, VpnAccount.status == "active")
                    .all()
                )
                for account in accounts:
                    if not account.identifier or not account.panel_inbound_ref_id:
                        continue
                    inbound = db.query(PanelInbound).filter(PanelInbound.id == account.panel_inbound_ref_id).first()
                    if not inbound:
                        continue
                    panel = db.query(Panel).filter(Panel.id == inbound.panel_id).first()
                    if not panel:
                        continue
                    try:
                        provider = registry.get_provider(panel.provider)
                        auth_payload = registry.get_auth_payload(db, panel)
                        provider.update_client(
                            panel,
                            account.identifier,
                            {"inbound_id": int(inbound.external_inbound_id), "enable": False},
                            auth_payload,
                        )
                    except Exception:
                        continue

        db.commit()

    return changed


def expire_subscriptions() -> int:
    return run()


if __name__ == "__main__":
    total = run()
    print(f"expired_subscriptions={total}")


__all__ = [
    "PricingError",
    "as_utc",
    "calculate_subscription_pricing",
    "expire_subscriptions",
    "plan_item_price_map",
    "plan_meta",
    "resolve_plan",
    "run",
    "subscription_duration_months",
    "utcnow",
]
