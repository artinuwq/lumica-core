from datetime import date, datetime
from decimal import Decimal

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from lumica.domain.models import Base, Group, Subscription, User
from lumica.services import finance


def _db():
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    return sessionmaker(bind=engine)()


def _client(db, name, price, day, until, status="active", **extra):
    user = User(telegram_id=str(abs(hash(name)) % 10**9), name=name)
    db.add(user)
    db.flush()
    db.add(Subscription(
        user_id=user.id, status=status, price_amount=Decimal(str(price)) if price is not None else None,
        billing_day=day, access_until=until, **extra,
    ))
    db.flush()
    return user


def test_missed_periods_counts_payment_dates_before_today():
    assert finance.missed_periods(date(2026, 10, 15), date(2026, 10, 15)) == 0  # в день даты долга ещё нет
    assert finance.missed_periods(date(2026, 10, 15), date(2026, 10, 17)) == 1
    assert finance.missed_periods(date(2026, 10, 15), date(2026, 11, 15)) == 1
    assert finance.missed_periods(date(2026, 10, 15), date(2026, 11, 16)) == 2
    assert finance.missed_periods(date(2026, 1, 30), date(2026, 3, 31)) == 3  # 30.01, 28.02 (короткий месяц), 30.03


def test_receipts_by_payment_day_and_next_payment_day():
    db = _db()
    _client(db, "A", 300, 15, datetime(2026, 11, 15))
    _client(db, "B", 200, 15, datetime(2026, 11, 15))
    _client(db, "C", 500, 30, datetime(2026, 10, 30))
    _client(db, "D", 100, 7, datetime(2026, 11, 7))
    _client(db, "NoPrice", None, 15, datetime(2026, 11, 15))
    _client(db, "Lifetime", 999, None, None, status="lifetime")
    _client(db, "Paused", 999, 15, datetime(2026, 11, 15), status="paused")
    db.commit()

    summary = finance.compute_summary(db, today=date(2026, 10, 16))
    assert summary["receipts"] == "1100.00" and summary["payers"] == 4
    assert summary["by_day"] == {
        "15": {"amount": "500.00", "payers": 2},
        "30": {"amount": "500.00", "payers": 1},
        "other": {"amount": "100.00", "payers": 1},
    }
    assert summary["next_payment"] == {"date": "2026-10-30", "day": 30, "amount": "500.00", "payers": 1}

    # в сам платёжный день он ещё «следующий»
    assert finance.compute_summary(db, today=date(2026, 10, 15))["next_payment"]["day"] == 15
    # после последнего дня месяца переходим на следующий месяц
    after = finance.compute_summary(db, today=date(2026, 10, 31))["next_payment"]
    assert (after["date"], after["day"]) == ("2026-11-07", 7)


def test_payment_day_falls_back_to_expiry_day_and_is_clamped_in_short_months():
    db = _db()
    _client(db, "NoDay", 100, None, datetime(2026, 12, 20))
    _client(db, "Thirtieth", 400, 30, datetime(2027, 2, 28))
    db.commit()
    summary = finance.compute_summary(db, today=date(2027, 2, 10))
    assert summary["by_day"]["other"] == {"amount": "100.00", "payers": 1}
    assert summary["next_payment"] == {"date": "2027-02-20", "day": 20, "amount": "100.00", "payers": 1}
    nxt = finance.compute_summary(db, today=date(2027, 2, 21))["next_payment"]
    assert nxt["date"] == "2027-02-28" and nxt["amount"] == "400.00"  # 30-е в феврале -> 28-е


def test_debt_lists_overdue_payers_oldest_first_with_periods():
    db = _db()
    _client(db, "Fresh", 300, 15, datetime(2026, 10, 15))      # сегодня 15-е - ещё не должен
    _client(db, "Late", 300, 15, datetime(2026, 10, 12))       # 1 период
    _client(db, "VeryLate", 200, 1, datetime(2026, 8, 1))      # 1.08, 1.09, 1.10 -> 3 периода
    _client(db, "Expired", 100, 5, datetime(2026, 10, 5), status="expired")
    _client(db, "Canceled", 100, 5, datetime(2026, 9, 5), status="canceled")  # отменён - не должен
    db.commit()
    summary = finance.compute_summary(db, today=date(2026, 10, 15))
    assert [(d["name"], d["amount"], d["periods"], d["due_date"]) for d in summary["debtors"]] == [
        ("VeryLate", "600.00", 3, "2026-08-01"),
        ("Expired", "100.00", 1, "2026-10-05"),
        ("Late", "300.00", 1, "2026-10-12"),
    ]
    assert summary["debt"] == {"amount": "1000.00", "count": 3}


def test_group_members_are_paid_for_by_the_admin_and_not_counted_twice():
    db = _db()
    admin = _client(db, "Admin", 500, 15, datetime(2026, 11, 15))
    kid = _client(db, "Kid", None, None, None)
    group = Group(name="G", admin_user_id=admin.id)
    db.add(group)
    db.flush()
    admin.group_id = kid.group_id = group.id
    db.commit()
    summary = finance.compute_summary(db, today=date(2026, 10, 1))
    assert summary["receipts"] == "500.00" and summary["payers"] == 1


def test_income_is_receipts_minus_manual_expenses():
    db = _db()
    _client(db, "A", 1000, 15, datetime(2026, 11, 15))
    db.commit()
    assert finance.compute_summary(db, today=date(2026, 10, 1))["income"] == "1000.00"
    assert finance.set_monthly_expenses(db, "350,5") == Decimal("350.50")
    db.commit()
    summary = finance.compute_summary(db, today=date(2026, 10, 1))
    assert (summary["expenses"], summary["income"]) == ("350.50", "649.50")
    finance.set_monthly_expenses(db, "0")
    db.commit()
    assert finance.compute_summary(db, today=date(2026, 10, 1))["expenses"] == "0.00"
    for bad in ("abc", "-5", "1e12", "nan"):
        with pytest.raises(ValueError):
            finance.set_monthly_expenses(db, bad)


def test_empty_system_gives_zeros_and_no_next_payment():
    summary = finance.compute_summary(_db(), today=date(2026, 10, 1))
    assert summary["receipts"] == summary["income"] == "0.00"
    assert summary["next_payment"] is None and summary["debt"] == {"amount": "0.00", "count": 0}
