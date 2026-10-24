"""Денежная часть экосистемы: поступления, долг, доход (поступления - расходы).

Правила:
* платящий клиент - тот, у кого последняя подписка со статусом active/expiring/expired
  и ценой больше нуля. Участник группы без своей цены не считается: за него платит
  администратор группы по своей цене;
* каждый платящий платит раз в месяц, поэтому «поступления за месяц» - сумма их цен;
* день платежа - billing_day подписки, а если его нет - день даты окончания;
* долг: дата окончания (до неё оплачено) уже прошла. Сумма = цена × число
  пропущенных платёжных периодов; в день самой даты долга ещё нет;
* расходы вводятся вручную как регулярная месячная сумма.
"""

from __future__ import annotations

import calendar
from collections import defaultdict
from datetime import date, datetime
from decimal import Decimal, InvalidOperation
from zoneinfo import ZoneInfo

from lumica.domain.models import AppSetting, Subscription, User

MOSCOW = ZoneInfo("Europe/Moscow")
EXPENSES_KEY = "finance.monthly_expenses"
BILLABLE_STATUSES = ("active", "expiring", "expired")
MAX_EXPENSES = Decimal("1000000000")
CENT = Decimal("0.01")


def today_msk() -> date:
    return datetime.now(MOSCOW).date()


def _money(value) -> Decimal:
    try:
        return Decimal(str(value if value is not None else 0)).quantize(CENT)
    except InvalidOperation:
        return Decimal("0.00")


def _clamp_day(year: int, month: int, day: int) -> date:
    return date(year, month, min(day, calendar.monthrange(year, month)[1]))


def _add_month(value: date, anchor_day: int | None = None) -> date:
    year, month = (value.year + 1, 1) if value.month == 12 else (value.year, value.month + 1)
    return _clamp_day(year, month, anchor_day or value.day)


def missed_periods(due: date, today: date) -> int:
    """Сколько платёжных дат (due, due+месяц, ...) строго раньше сегодняшнего дня."""
    count, current = 0, due
    while current < today and count < 240:
        count += 1
        current = _add_month(current, due.day)
    return count


def get_monthly_expenses(db) -> Decimal:
    row = db.query(AppSetting).filter(AppSetting.key == EXPENSES_KEY).first()
    value = row.value_json.get("amount") if row and isinstance(row.value_json, dict) else None
    return _money(value)


def set_monthly_expenses(db, amount) -> Decimal:
    try:
        value = Decimal(str(amount).strip().replace(",", ".")).quantize(CENT)
    except (InvalidOperation, ValueError):
        raise ValueError("Сумма расходов должна быть числом") from None
    if not value.is_finite() or value < 0 or value > MAX_EXPENSES:
        raise ValueError("Сумма расходов должна быть от 0 до 1 000 000 000")
    row = db.query(AppSetting).filter(AppSetting.key == EXPENSES_KEY).first()
    payload = {"amount": str(value)}
    if row:
        row.value_json = payload
    else:
        db.add(AppSetting(key=EXPENSES_KEY, value_json=payload, description="Регулярные расходы за месяц"))
    return value


def _payers(db) -> list[dict]:
    latest: dict[int, Subscription] = {}
    for sub in db.query(Subscription).order_by(Subscription.id.asc()).all():
        latest[sub.user_id] = sub
    users = {u.id: u for u in db.query(User).filter(User.id.in_(list(latest) or [0])).all()}
    payers = []
    for user_id, sub in latest.items():
        price = _money(sub.price_amount)
        if price <= 0 or (sub.status or "").lower() not in BILLABLE_STATUSES:
            continue
        due = sub.access_until.date() if sub.access_until else None
        day = sub.billing_day or (due.day if due else None)
        user = users.get(user_id)
        payers.append({
            "user_id": user_id,
            "name": (user.name if user else None) or (f"@{user.username}" if user and user.username else f"#{user_id}"),
            "username": user.username if user else None,
            "price": price,
            "day": day,
            "due": due,
        })
    return payers


def _next_payment(payers: list[dict], today: date) -> dict | None:
    """Ближайший платёжный день (сегодня тоже считается) и сумма ожидаемых за него платежей."""
    best: date | None = None
    for day in {p["day"] for p in payers if p["day"]}:
        candidate = _clamp_day(today.year, today.month, day)
        if candidate < today:
            candidate = _add_month(today.replace(day=1), day)
        if best is None or candidate < best:
            best = candidate
    if best is None:
        return None
    day_group = [p for p in payers if p["day"] and _clamp_day(best.year, best.month, p["day"]) == best]
    return {
        "date": best.isoformat(),
        "day": best.day,
        "amount": str(sum((p["price"] for p in day_group), Decimal("0.00"))),
        "payers": len(day_group),
    }


def compute_summary(db, today: date | None = None) -> dict:
    today = today or today_msk()
    payers = _payers(db)
    expenses = get_monthly_expenses(db)
    receipts = sum((p["price"] for p in payers), Decimal("0.00"))

    by_day: dict[str, dict] = defaultdict(lambda: {"amount": Decimal("0.00"), "payers": 0})
    for payer in payers:
        key = "none" if not payer["day"] else (str(payer["day"]) if payer["day"] in (15, 30) else "other")
        by_day[key]["amount"] += payer["price"]
        by_day[key]["payers"] += 1

    debtors = []
    for payer in payers:
        if payer["due"] and payer["due"] < today:
            periods = missed_periods(payer["due"], today)
            debtors.append({
                "user_id": payer["user_id"],
                "name": payer["name"],
                "username": payer["username"],
                "amount": str(payer["price"] * periods),
                "periods": periods,
                "due_date": payer["due"].isoformat(),
            })
    debtors.sort(key=lambda d: (d["due_date"], -Decimal(d["amount"])))

    return {
        "today": today.isoformat(),
        "month": today.strftime("%Y-%m"),
        "receipts": str(receipts),
        "expenses": str(expenses),
        "income": str(receipts - expenses),
        "payers": len(payers),
        "next_payment": _next_payment(payers, today),
        "by_day": {key: {"amount": str(val["amount"]), "payers": val["payers"]} for key, val in by_day.items()},
        "debt": {
            "amount": str(sum((Decimal(d["amount"]) for d in debtors), Decimal("0.00"))),
            "count": len(debtors),
        },
        "debtors": debtors,
    }


__all__ = ["compute_summary", "get_monthly_expenses", "set_monthly_expenses", "missed_periods", "today_msk"]
