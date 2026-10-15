from datetime import datetime
from decimal import Decimal
from zoneinfo import ZoneInfo

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from lumica.domain.models import Base, Group, Subscription, User
from lumica.jobs import payment_due_reminders


def test_family_billing_day_notifies_only_admin(monkeypatch):
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    factory = sessionmaker(bind=engine)
    with factory() as db:
        admin = User(telegram_id="10001", name="Admin")
        member = User(telegram_id="10002", name="Member")
        db.add_all([admin, member])
        db.flush()
        group = Group(name="Family", admin_user_id=admin.id)
        db.add(group)
        db.flush()
        admin.group_id = group.id
        member.group_id = group.id
        db.add_all([
            Subscription(user_id=admin.id, status="active", price_amount=Decimal("100"), billing_day=15),
            Subscription(user_id=member.id, status="active", price_amount=Decimal("50"), billing_day=None),
        ])
        db.commit()

    sent = []
    monkeypatch.setattr(payment_due_reminders, "SessionLocal", factory)
    monkeypatch.setattr(payment_due_reminders, "already_sent", lambda *_args: False)
    monkeypatch.setattr(payment_due_reminders, "send_raw", lambda *args, **_kwargs: sent.append(args) or True)

    payment_due_reminders.run_payment_due_reminders(
        datetime(2026, 10, 15, 15, 30, tzinfo=ZoneInfo("Europe/Moscow"))
    )

    assert len(sent) == 1
    assert sent[0][0] == "10001"
    assert "Сумма: 100" in sent[0][1]
    assert "Member" in sent[0][1]