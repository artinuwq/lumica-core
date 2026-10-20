from decimal import Decimal

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from lumica.domain.models import (
    AuthIdentity, Base, Group, NotificationLog, PaymentRequest, Subscription, SubscriptionVpnAccount,
    User, UserAuditEvent, VpnAccount,
)
from lumica.services import user_deletion


def _db():
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    return sessionmaker(bind=engine)()


def _family(db, admin_first=True):
    users = [User(telegram_id=str(i), name=f"U{i}") for i in (1, 2, 3)]
    db.add_all(users)
    db.flush()
    admin = users[0] if admin_first else users[2]
    group = Group(name="G", admin_user_id=admin.id)
    db.add(group)
    db.flush()
    for user in users:
        user.group_id = group.id
    db.commit()
    return users, group


def _fill(db, user):
    sub = Subscription(user_id=user.id, status="active", price_amount=Decimal("5"))
    account = VpnAccount(user_id=user.id, protocol="vless", meta_json={})
    db.add_all([sub, account])
    db.flush()
    db.add_all([
        SubscriptionVpnAccount(subscription_id=sub.id, vpn_account_id=account.id),
        PaymentRequest(subscription_id=sub.id, subscription_ids=[sub.id], payer_user_id=user.id, amount=Decimal("5")),
        NotificationLog(user_id=user.id, key="k", success=1),
        AuthIdentity(user_id=user.id, provider="telegram", provider_user_id=user.telegram_id),
        UserAuditEvent(actor_user_id=user.id, subject_user_id=user.id, action="x", changes={}),
    ])
    db.commit()


def test_delete_removes_user_and_everything_that_references_it():
    db = _db()
    (admin, member, other), group = _family(db)
    _fill(db, member)
    _fill(db, other)
    member_id = member.id
    summary = user_deletion.delete_user(db, member)
    db.commit()
    assert summary == {"promoted": [], "deleted_groups": []}
    assert db.query(User).filter(User.id == member_id).first() is None
    for model in (Subscription, VpnAccount, NotificationLog, AuthIdentity):
        assert db.query(model).filter(model.user_id == member_id).count() == 0
    assert db.query(PaymentRequest).filter(PaymentRequest.payer_user_id == member_id).count() == 0
    assert db.query(SubscriptionVpnAccount).count() == 1  # связь второго клиента осталась
    event = db.query(UserAuditEvent).filter(UserAuditEvent.actor_user_id.is_(None)).one()
    assert event.subject_user_id is None  # история сохранилась, ссылки на пользователя обнулены
    assert db.query(User).count() == 2


def test_group_admin_deleted_next_added_member_becomes_admin():
    db = _db()
    (admin, member, other), group = _family(db)
    summary = user_deletion.delete_user(db, admin)
    db.commit()
    assert summary["promoted"] == [{"group_id": group.id, "user_id": member.id}]
    refreshed = db.query(Group).one()
    assert refreshed.admin_user_id == member.id
    assert (member.profile_data or {}).get("subscription_type") == "family_admin"
    assert {u.id for u in db.query(User).filter(User.group_id == group.id)} == {member.id, other.id}


def test_last_added_admin_falls_back_to_first_remaining_member():
    db = _db()
    (first, second, newest), group = _family(db, admin_first=False)
    summary = user_deletion.delete_user(db, newest)
    db.commit()
    assert summary["promoted"] == [{"group_id": group.id, "user_id": first.id}]
    assert db.query(Group).one().admin_user_id == first.id


def test_group_without_other_members_is_removed():
    db = _db()
    solo = User(telegram_id="9", name="Solo")
    db.add(solo)
    db.flush()
    group = Group(name="G", admin_user_id=solo.id)
    db.add(group)
    db.flush()
    solo.group_id = group.id
    db.commit()
    summary = user_deletion.delete_user(db, solo)
    db.commit()
    assert summary["deleted_groups"] == [group.id]
    assert db.query(Group).count() == 0 and db.query(User).count() == 0


def test_identity_validation():
    assert user_deletion.normalize_identity({"name": "  Иван  ", "username": "@ivan_01", "telegram_id": " 42 "}) == {
        "name": "Иван", "username": "ivan_01", "telegram_id": "42",
    }
    assert user_deletion.normalize_identity({"name": "", "username": "", "telegram_id": ""}) == {
        "name": None, "username": None, "telegram_id": None,
    }
    assert user_deletion.normalize_identity({}) == {}
    for bad in ({"username": "ab"}, {"username": "bad name!"}, {"telegram_id": "12ab"}):
        with pytest.raises(user_deletion.IdentityError):
            user_deletion.normalize_identity(bad)
