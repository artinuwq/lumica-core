from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from lumica.domain.models import Base, MiniAppLaunch, Subscription, User
from tests.test_admin_panel_create import FakeRegistry, _create_test_app


def _factory():
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    return sessionmaker(bind=engine)


def test_admin_users_lists_only_users_added_with_subscription():
    factory = _factory()
    with factory() as db:
        opened_bot_only = User(telegram_id="1", name="Just opened the bot")
        subscribed = User(telegram_id="2", name="Subscribed", username="subscribed")
        draft_only = User(telegram_id="3", name="Draft only")
        family_member = User(
            telegram_id="4", name="Member", profile_data={"subscription_type": "family_member"}
        )
        placeholder = User(name="Empty seat")
        db.add_all([opened_bot_only, subscribed, draft_only, family_member, placeholder])
        db.flush()
        db.add(MiniAppLaunch(user_id=opened_bot_only.id, url="https://app.example", status="opened"))
        db.add(Subscription(user_id=subscribed.id, status="active"))
        db.add(Subscription(user_id=draft_only.id, status="draft"))
        db.add(Subscription(user_id=placeholder.id, status="active"))
        db.commit()

    app = _create_test_app(factory, FakeRegistry())
    response = app.test_client().get("/api/admin/users")

    assert response.status_code == 200
    users = response.get_json()["users"]
    assert {u["name"] for u in users} == {
        "Just opened the bot",
        "Subscribed",
        "Member",
        "Empty seat",
    }
    by_name = {u["name"]: u for u in users}
    assert by_name["Subscribed"]["subscription_type"] == "personal"
    assert by_name["Subscribed"]["subscription_status"] == "active"
    assert by_name["Member"]["subscription_type"] == "family_member"


def test_known_users_still_include_everyone_who_opened_the_bot():
    factory = _factory()
    with factory() as db:
        user = User(telegram_id="1", name="Just opened the bot")
        db.add(user)
        db.flush()
        db.add(MiniAppLaunch(user_id=user.id, url="https://app.example", status="opened"))
        db.commit()

    app = _create_test_app(factory, FakeRegistry())
    response = app.test_client().get("/api/admin/users/known")

    assert [u["name"] for u in response.get_json()["users"]] == ["Just opened the bot"]


def test_known_users_cover_everyone_who_opened_the_app_or_the_bot():
    from lumica.domain.models import Application, AuthIdentity

    factory = _factory()
    with factory() as db:
        opened_app = User(telegram_id="1", name="Opened app", profile_data={"last_seen": "2026-10-01T10:00:00+00:00"})
        has_identity = User(telegram_id="2", name="Has identity")
        wrote_bot = User(telegram_id="3", name="Wrote bot")
        never_came = User(telegram_id="4", name="Pre-created by admin")
        placeholder = User(name="Empty seat")
        db.add_all([opened_app, has_identity, wrote_bot, never_came, placeholder])
        db.flush()
        db.add(AuthIdentity(user_id=has_identity.id, provider="telegram", provider_user_id="2"))
        db.add(Application(user_id=wrote_bot.id, full_name="Ivan Ivanov"))
        db.commit()

    app = _create_test_app(factory, FakeRegistry())
    response = app.test_client().get("/api/admin/users/known")

    assert response.status_code == 200
    by_name = {u["name"]: u for u in response.get_json()["users"]}
    assert set(by_name) == {"Opened app", "Has identity", "Wrote bot"}
    assert by_name["Opened app"]["source"] == "app"
    assert by_name["Has identity"]["source"] == "app"
    assert by_name["Wrote bot"]["source"] == "bot"


def test_admin_users_works_when_nobody_has_a_subscription_yet():
    factory = _factory()
    with factory() as db:
        db.add(User(telegram_id="1", name="Lonely", profile_data={"subscription_type": "personal"}))
        db.commit()

    app = _create_test_app(factory, FakeRegistry())
    response = app.test_client().get("/api/admin/users")

    assert response.status_code == 200
    assert [u["name"] for u in response.get_json()["users"]] == ["Lonely"]


def test_user_overview_exposes_group_membership_and_administered_groups():
    from datetime import datetime, timezone
    from decimal import Decimal

    from lumica.api.helpers import build_auth_helpers
    from lumica.domain.models import Group, VpnAccount

    def _as_utc(value):
        if value is None:
            return None
        return value if value.tzinfo else value.replace(tzinfo=timezone.utc)

    helpers = build_auth_helpers(
        {
            "User": User,
            "Subscription": Subscription,
            "VpnAccount": VpnAccount,
            "_as_utc": _as_utc,
            "utcnow": lambda: datetime.now(timezone.utc),
            "_latest_subscription": lambda db, user_id: (
                db.query(Subscription).filter(Subscription.user_id == user_id).order_by(Subscription.id.desc()).first()
            ),
            "_extract_connections_limit": lambda _user: None,
        }
    )
    serialize = helpers["_serialize_admin_user_overview"]

    factory = _factory()
    with factory() as db:
        owner = User(telegram_id="10", name="Family Owner")
        db.add(owner)
        db.flush()
        group = Group(name="Семья", admin_user_id=owner.id)
        db.add(group)
        db.flush()
        member = User(telegram_id="11", name="Kid", group_id=group.id)
        db.add(member)
        db.flush()
        db.add(Subscription(user_id=member.id, status="paused"))
        db.add(Subscription(
            user_id=owner.id, status="active", access_until=datetime(2030, 5, 14),
            price_amount=Decimal("300"), billing_day=14,
        ))
        db.commit()

        member_overview = serialize(db, member)
        assert member_overview["group"]["admin_name"] == "Family Owner"
        assert member_overview["group"]["is_admin"] is False
        assert member_overview["group"]["admin_subscription"] == {
            "status": "active", "access_until": "2030-05-14T00:00:00", "price_amount": "300.00", "billing_day": 14,
        }
        assert member_overview["administered_groups"] == []

        owner_overview = serialize(db, owner)
        assert owner_overview["group"] is None
        listed = owner_overview["administered_groups"][0]["members"]
        assert [(m["name"], m["subscription_status"]) for m in listed] == [("Kid", "paused")]


def test_extending_sets_billing_day_only_when_missing_and_not_for_group_members():
    from datetime import datetime, timezone
    from decimal import Decimal, InvalidOperation

    from lumica.api.helpers import build_admin_helpers
    from lumica.domain.models import Group

    def _as_utc(value):
        if value is None:
            return None
        return value if value.tzinfo else value.replace(tzinfo=timezone.utc)

    helpers = build_admin_helpers(
        {
            "User": User,
            "Subscription": Subscription,
            "Decimal": Decimal,
            "InvalidOperation": InvalidOperation,
            "datetime": datetime,
            "timezone": timezone,
            "_as_utc": _as_utc,
            "utcnow": lambda: datetime.now(timezone.utc),
            "jsonify": lambda *a, **k: (a, k),
            "add_calendar_month": lambda base, months: base.replace(year=base.year + (base.month + months - 1) // 12, month=(base.month + months - 1) % 12 + 1),
        }
    )
    apply_payload = helpers["_apply_admin_subscription_payload"]

    factory = _factory()
    with factory() as db:
        owner = User(telegram_id="1", name="Owner")
        db.add(owner)
        db.flush()
        group = Group(name="G", admin_user_id=owner.id)
        db.add(group)
        db.flush()
        owner.group_id = group.id
        member = User(telegram_id="2", name="Member", group_id=group.id)
        solo = User(telegram_id="3", name="Solo")
        with_day = User(telegram_id="4", name="WithDay")
        db.add_all([member, solo, with_day])
        db.flush()
        db.add(Subscription(user_id=with_day.id, status="active", billing_day=7))
        db.commit()

        for user in (solo, member, owner, with_day):
            assert apply_payload(db, user, {"access_until": "2030-01-15T23:59:59"}) is None
        db.commit()

        def day(user):
            return db.query(Subscription).filter(Subscription.user_id == user.id).first().billing_day

        assert day(solo) == 15
        assert day(owner) == 15
        assert day(member) is None
        assert day(with_day) == 7


def test_users_list_exposes_data_for_filters():
    from datetime import datetime
    from decimal import Decimal

    from lumica.domain.models import Group, Panel, VpnAccount

    factory = _factory()
    with factory() as db:
        panel_de = Panel(id="p-de", name="Germany", provider="3xui", auth_type="token", auth_secret_ref="x",
                         base_url="https://h", region="de")
        owner = User(telegram_id="1", name="Owner")
        kid = User(telegram_id="2", name="Kid")
        solo = User(telegram_id="3", name="Solo")
        db.add_all([panel_de, owner, kid, solo])
        db.flush()
        group = Group(name="G", admin_user_id=owner.id)
        db.add(group)
        db.flush()
        owner.group_id = kid.group_id = group.id
        db.add_all([
            Subscription(user_id=owner.id, status="active", price_amount=Decimal("300"), billing_day=15,
                         access_until=datetime(2030, 5, 14), is_frozen=True),
            Subscription(user_id=kid.id, status="paused"),
            Subscription(user_id=solo.id, status="active"),
            VpnAccount(user_id=owner.id, protocol="vless", status="active", meta_json={"panel_id": "p-de"}),
            VpnAccount(user_id=solo.id, protocol="vless", status="active", meta_json={"panel_id": "missing"}),
        ])
        db.commit()
    response = _create_test_app(factory, FakeRegistry()).test_client().get("/api/admin/users")
    by_name = {u["name"]: u for u in response.get_json()["users"]}
    assert by_name["Owner"]["is_group_admin"] is True and by_name["Kid"]["is_group_admin"] is False
    assert by_name["Owner"]["price_amount"] == "300.00" and by_name["Owner"]["billing_day"] == 15
    assert by_name["Owner"]["access_until"] == "2030-05-14T00:00:00" and by_name["Owner"]["is_frozen"] is True
    assert by_name["Owner"]["servers"] == [{"id": "p-de", "code": "De", "name": "Germany"}]
    assert by_name["Solo"]["servers"] == [] and by_name["Kid"]["servers"] == []
