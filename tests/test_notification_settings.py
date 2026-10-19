import asyncio
from datetime import datetime, timezone
from decimal import Decimal
from types import SimpleNamespace
from unittest.mock import AsyncMock
from zoneinfo import ZoneInfo

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from lumica.bot import settings as bot_settings
from lumica.domain.models import Base, Group, Panel, Subscription, SubscriptionVpnAccount, User, VpnAccount
from lumica.jobs import payment_due_reminders, subscription_reminders
from lumica.services import notifications, notification_settings, subscription_links, subscription_updates

MSK = ZoneInfo("Europe/Moscow")


def _factory():
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    return sessionmaker(bind=engine)


# ------------------------------------------------------------- настройки

def test_defaults_and_validation():
    user = SimpleNamespace(profile_data=None)
    assert notification_settings.get_settings(user) == {
        "expiry_hour": 15, "remind_3d": False, "payment_confirmed": True,
        "payment_rejected": True, "subscription_updates": True,
    }
    notification_settings.update_settings(user, expiry_hour=21, remind_3d=True)
    assert notification_settings.get_settings(user)["expiry_hour"] == 21
    assert user.profile_data["notifications"]["remind_3d"] is True
    with pytest.raises(ValueError):
        notification_settings.update_settings(user, expiry_hour=10)
    with pytest.raises(ValueError):
        notification_settings.update_settings(user, remind_3d="yes")
    with pytest.raises(ValueError):
        notification_settings.update_settings(user, unknown=True)


def test_update_keeps_other_profile_fields():
    user = SimpleNamespace(profile_data={"region": "fl"})
    notification_settings.update_settings(user, payment_rejected=False)
    assert user.profile_data["region"] == "fl"
    assert notification_settings.is_silent(user, "payment_rejected") is True
    assert notification_settings.is_silent(user, "payment_confirmed") is False
    assert notification_settings.is_silent(user, "expiry_day") is False  # нельзя заглушить


def test_disabled_categories_are_sent_silently_and_3d_is_skipped(monkeypatch):
    sent = []
    monkeypatch.setattr(notifications, "send_raw", lambda tid, text, **kw: sent.append(kw) or True)
    factory = _factory()
    with factory() as db:
        user = User(telegram_id="1", name="A")
        db.add(user)
        db.flush()
        assert notifications.notify_by_preference(db, user, "payment_confirmed", "x") is True
        assert sent[-1]["silent"] is False
        notification_settings.update_settings(user, payment_confirmed=False)
        assert notifications.notify_by_preference(db, user, "payment_confirmed", "x") is True
        assert sent[-1]["silent"] is True  # без звука, но сообщение не теряется
        before = len(sent)
        assert notifications.notify_by_preference(db, user, "remind_3d", "x") is False
        assert len(sent) == before  # «за 3 дня» выключено - не отправляем вовсе


# ----------------------------------------------------- напоминания по времени

def _expiring_user(db, *, days_from_now, hour=None, remind_3d=None, billing_day=None, today=None):
    today = today or datetime(2026, 10, 20, tzinfo=MSK)
    user = User(telegram_id="77", name="Client")
    db.add(user)
    db.flush()
    if hour is not None or remind_3d is not None:
        changes = {}
        if hour is not None:
            changes["expiry_hour"] = hour
        if remind_3d is not None:
            changes["remind_3d"] = remind_3d
        notification_settings.update_settings(user, **changes)
    until = datetime(2026, 10, 20 + days_from_now, 23, 59)
    db.add(Subscription(user_id=user.id, status="active", access_until=until, billing_day=billing_day))
    db.commit()
    return user


def _run_reminders(monkeypatch, factory, hour):
    sent = []
    monkeypatch.setattr(subscription_reminders, "SessionLocal", factory)
    monkeypatch.setattr(notifications, "send_raw", lambda tid, text, **kw: sent.append(text) or True)
    subscription_reminders.run_subscription_reminders(datetime(2026, 10, 20, hour, 5, tzinfo=MSK))
    return sent


def test_day_of_reminder_goes_out_at_chosen_hour_only(monkeypatch):
    factory = _factory()
    with factory() as db:
        _expiring_user(db, days_from_now=0, hour=21)
    assert _run_reminders(monkeypatch, factory, 15) == []
    assert _run_reminders(monkeypatch, factory, 9) == []
    late = _run_reminders(monkeypatch, factory, 21)
    assert len(late) == 1 and "истекает сегодня" in late[0]
    assert _run_reminders(monkeypatch, factory, 22) == []  # уже отправлено, повтора нет


def test_day_of_reminder_default_hour_is_15(monkeypatch):
    factory = _factory()
    with factory() as db:
        _expiring_user(db, days_from_now=0)
    assert _run_reminders(monkeypatch, factory, 14) == []
    assert len(_run_reminders(monkeypatch, factory, 15)) == 1


def test_three_day_reminder_only_when_enabled(monkeypatch):
    factory = _factory()
    with factory() as db:
        _expiring_user(db, days_from_now=3)
    assert _run_reminders(monkeypatch, factory, 21) == []
    factory2 = _factory()
    with factory2() as db:
        _expiring_user(db, days_from_now=3, remind_3d=True, hour=9)
    sent = _run_reminders(monkeypatch, factory2, 9)
    assert len(sent) == 1 and "через 3 дн." in sent[0]


def test_day_of_reminder_not_duplicated_by_payment_due_message(monkeypatch):
    factory = _factory()
    with factory() as db:
        _expiring_user(db, days_from_now=0, billing_day=20)
    assert _run_reminders(monkeypatch, factory, 18) == []


def test_payment_due_reminder_respects_chosen_hour(monkeypatch):
    factory = _factory()
    with factory() as db:
        _expiring_user(db, days_from_now=5, billing_day=20, hour=21)
    sent = []
    monkeypatch.setattr(payment_due_reminders, "SessionLocal", factory)
    monkeypatch.setattr(payment_due_reminders, "send_raw", lambda *a, **k: sent.append(a) or True)
    payment_due_reminders.run_payment_due_reminders(datetime(2026, 10, 20, 15, 30, tzinfo=MSK))
    assert sent == []
    payment_due_reminders.run_payment_due_reminders(datetime(2026, 10, 20, 21, 10, tzinfo=MSK))
    assert len(sent) == 1


# ------------------------------------------------------ обновления подписки

def _snap(**over):
    base = {"status": "active", "access_until": "2026-10-18", "price": "500.00", "frozen": False}
    base.update(over)
    return base


def test_subscription_update_text_lists_only_real_changes():
    text = subscription_updates.describe_changes(
        _snap(), _snap(status="paused", access_until="2026-11-18", price="700.00", frozen=True)
    )
    assert text.startswith("🔄 Ваша подписка обновлена")
    assert "Статус: Активна → На паузе" in text
    assert "Дата оплаты до: 18.10.2026 → 18.11.2026" in text
    assert "Цена: 500 ₽ → 700 ₽" in text and "Подписка заморожена" in text
    assert subscription_updates.describe_changes(_snap(), _snap()) is None
    assert subscription_updates.describe_changes(None, _snap()) is None  # создание - не обновление
    assert "Заморозка снята" in subscription_updates.describe_changes(_snap(frozen=True), _snap())


def test_update_notification_is_sent_silently_when_user_disabled_it(monkeypatch):
    sent = []
    monkeypatch.setattr(notifications, "send_raw", lambda tid, text, **kw: sent.append(kw["silent"]) or True)
    factory = _factory()
    with factory() as db:
        user = User(telegram_id="5", name="A")
        db.add(user)
        db.flush()
        assert subscription_updates.notify_subscription_updated(db, user, _snap(), _snap(price="1")) is True
        notification_settings.update_settings(user, subscription_updates=False)
        subscription_updates.notify_subscription_updated(db, user, _snap(), _snap(price="2"))
    assert sent == [False, True]


# ------------------------------------------------------------ экран в боте

def test_settings_screen_has_warning_and_toggles_work():
    text, markup = bot_settings.render_settings(notification_settings.get_settings(SimpleNamespace(profile_data=None)))
    assert "нельзя отключить" in text and "Настоятельно не рекомендуем" in text
    rows = [[b.text for b in row] for row in markup.inline_keyboard]
    assert rows[0] == ["9:00", "✅ 15:00", "21:00"]
    assert rows[-1] == ["Меню"] and len(rows) == 6

    factory = _factory()
    with factory() as db:
        db.add(User(telegram_id="9", name="Z"))
        db.commit()
    bot_settings.SessionLocal = factory

    def press(data):
        message = SimpleNamespace(edit_text=AsyncMock(), answer=AsyncMock())
        query = SimpleNamespace(from_user=SimpleNamespace(id=9), data=data, message=message, answer=AsyncMock())
        asyncio.run(bot_settings.change_setting(query))
        return message

    message = press("settings:hour:21")
    assert message.edit_text.await_args.args[0].count("21:00") >= 1
    press("settings:toggle:remind_3d")
    press("settings:toggle:payment_rejected")
    with factory() as db:
        user = db.query(User).one()
        assert notification_settings.get_settings(user) == {
            "expiry_hour": 21, "remind_3d": True, "payment_confirmed": True,
            "payment_rejected": False, "subscription_updates": True,
        }
    bad = press("settings:hour:10")
    bad.edit_text.assert_not_awaited()


# ------------------------------------------------------------ ссылки подписки

@pytest.fixture
def clean_env(monkeypatch):
    for name in ("PANEL_PUBLIC_BASE_URL", "PANEL_SUBSCRIPTION_BASE_URL", "PANEL_SUBSCRIPTION_URL_TEMPLATE",
                 "PANEL_BASE_URL", "PUBLIC_VPN_HOST", "PANEL_SUBSCRIPTION_PORT"):
        monkeypatch.delenv(name, raising=False)
    subscription_links._probe_cache.clear()


def test_links_built_from_panel_base_url_and_public_host_like_mini_app(clean_env, monkeypatch):
    monkeypatch.setenv("PANEL_BASE_URL", "https://panel.example:2053/panel/api")
    monkeypatch.setenv("PUBLIC_VPN_HOST", "vpn.example")
    monkeypatch.setenv("PANEL_SUBSCRIPTION_PORT", "2096")
    urls = subscription_links.build_subscription_urls("abc")
    assert "https://panel.example:2053/sub/abc" in urls
    assert "https://vpn.example:2096/subcrp/abc" in urls
    assert subscription_links.build_subscription_urls("") == []


def test_pick_prefers_working_candidate_and_falls_back_to_first(clean_env, monkeypatch):
    monkeypatch.setattr(subscription_links, "probe_url", lambda url, timeout=0: url.endswith("/subcrp/abc"))
    assert subscription_links.pick_subscription_url(["https://h/sub/abc", "https://h/subcrp/abc"]) == "https://h/subcrp/abc"
    subscription_links._probe_cache.clear()
    monkeypatch.setattr(subscription_links, "probe_url", lambda url, timeout=0: False)
    assert subscription_links.pick_subscription_url(["https://h/sub/abc", "https://h/subcrp/abc"]) == "https://h/sub/abc"
    assert subscription_links.pick_subscription_url([]) is None


def test_bot_finds_link_using_panel_root_when_no_env_is_configured(clean_env, monkeypatch):
    """Регрессия: клиент видел «ссылка не выдана», хотя админ видел её в mini app."""
    from lumica.bot import menus

    monkeypatch.setattr(subscription_links, "probe_url", lambda url, timeout=0: "/sub/abc" in url)
    factory = _factory()
    with factory() as db:
        panel = Panel(id="p1", name="FI", provider="3xui", auth_type="token", auth_secret_ref="x", base_url="https://fi.example:2053/panel/api")
        user = User(telegram_id="3", name="Client")
        db.add_all([panel, user])
        db.flush()
        sub = Subscription(user_id=user.id, status="active", access_until=datetime(2030, 1, 1), price_amount=Decimal("500"))
        account = VpnAccount(user_id=user.id, protocol="vless", status="active",
                             meta_json={"panel_id": "p1", "sub_id": "abc"})
        db.add_all([sub, account])
        db.flush()
        db.add(SubscriptionVpnAccount(subscription_id=sub.id, vpn_account_id=account.id))
        db.commit()
        texts = menus.collect_subscription_messages(db, user)
    assert "https://fi.example:2053/sub/abc" in texts[0]
    assert "Ссылка на подписку пока не выдана" not in texts[0]
