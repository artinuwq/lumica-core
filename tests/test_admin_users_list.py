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
