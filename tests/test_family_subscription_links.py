from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from lumica.domain.models import Base, Subscription, SubscriptionVpnAccount, User
from lumica.services.groups import add_member, create_group, remove_member, set_admin
from lumica.services.user_provisioning import create_preprovisioned_user


def _session():
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    return sessionmaker(bind=engine)()


def test_placeholder_user_can_become_family_member_then_personal():
    db = _session()
    admin = create_preprovisioned_user(db, telegram_id="10001", name="Family admin")
    member = create_preprovisioned_user(db, name="Empty seat", allow_placeholder=True)
    group = create_group(db, name="Family", admin_user_id=admin.id)

    add_member(db, group, member.id)
    assert member.group_id == group.id
    assert member.profile_data["subscription_type"] == "family_member"

    remove_member(db, group, member.id)
    assert member.group_id is None
    assert member.profile_data["subscription_type"] == "personal"


def test_subscription_vpn_account_link_is_persisted():
    db = _session()
    user = User(telegram_id="10002", name="Customer")
    db.add(user)
    db.flush()
    subscription = Subscription(user_id=user.id, status="active")
    db.add(subscription)
    db.flush()
    link = SubscriptionVpnAccount(subscription_id=subscription.id, vpn_account_id=15)

    assert link.subscription_id == subscription.id
    assert link.vpn_account_id == 15