import asyncio
from decimal import Decimal
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from lumica.bot import menus, onboarding, registration, welcome
from lumica.domain.models import (
    AppSetting, Application, Base, Group, Subscription, User, VpnAccount,
)


def _factory():
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    return sessionmaker(bind=engine)


def _wire(monkeypatch, factory):
    for module in (menus, registration, welcome, onboarding):
        monkeypatch.setattr(module, "SessionLocal", factory)
    monkeypatch.setattr(menus, "is_authorized", lambda *a, **k: False)
    monkeypatch.setattr(onboarding, "is_authorized", lambda *a, **k: False)


def _buttons(markup):
    return [[button.text for button in row] for row in markup.inline_keyboard]


def _bot():
    bot = MagicMock()
    bot.edit_message_text = AsyncMock()
    bot.send_message = AsyncMock()
    return bot


def _tg_user(user_id=500, username="newbie", first="Ivan", last="Petrov"):
    return SimpleNamespace(id=user_id, username=username, first_name=first, last_name=last, full_name=f"{first} {last}")


def _query(user_id=500, data="menu:register", message_id=77, **user):
    message = SimpleNamespace(
        chat=SimpleNamespace(id=user_id), message_id=message_id, edit_text=AsyncMock(), answer=AsyncMock()
    )
    return SimpleNamespace(
        from_user=_tg_user(user_id, **user), data=data, message=message, answer=AsyncMock()
    ), message


def _text_message(text, user_id=500, chat_type="private"):
    return SimpleNamespace(
        from_user=_tg_user(user_id), chat=SimpleNamespace(id=user_id, type=chat_type), text=text,
        delete=AsyncMock(), answer=AsyncMock(),
    )


# --------------------------------------------------------------- состояние и меню

def test_client_state_found_applicant_or_new():
    factory = _factory()
    with factory() as db:
        with_sub = User(telegram_id="1", name="WithSub")
        accounts_only = User(telegram_id="2", name="Accounts")
        member = User(telegram_id="3", name="Member")
        applicant = User(telegram_id="4", name="Applicant")
        rejected = User(telegram_id="5", name="Rejected")
        bare = User(telegram_id="6", name="Bare")
        db.add_all([with_sub, accounts_only, member, applicant, rejected, bare])
        db.flush()
        group = Group(name="G", admin_user_id=with_sub.id)
        db.add(group)
        db.flush()
        member.group_id = group.id
        db.add_all([
            Subscription(user_id=with_sub.id, status="active", price_amount=Decimal("1")),
            VpnAccount(user_id=accounts_only.id, protocol="vless", status="active", meta_json={}),
            Application(user_id=applicant.id, full_name="A", status="new"),
            Application(user_id=rejected.id, full_name="R", status="rejected"),
        ])
        db.commit()
        states = {tg: menus.client_state(db, tg) for tg in (1, 2, 3, 4, 5, 6, 999)}
    assert states == {
        1: "active", 2: "active", 3: "active", 4: "applicant", 5: "new", 6: "new", 999: "new",
    }


def test_menu_layouts_per_state():
    assert _buttons(menus.user_menu("active")) == [
        ["📋 Подписка", "💳 Оплатить"], ["🖥 Статус серверов", "🌐 Центр Lumica"], ["⚙️ Настройки"],
    ]
    new = menus.user_menu("new")
    assert _buttons(new) == [["📝 Регистрация"], ["⚙️ Настройки", "🌐 Центр Lumica"]]
    assert new.inline_keyboard[0][0].callback_data == "menu:register"
    applicant = menus.user_menu("applicant")
    assert _buttons(applicant) == [["📨 Статус заявки"], ["⚙️ Настройки", "🌐 Центр Lumica"]]
    assert "Статус серверов" not in str(_buttons(new)) + str(_buttons(applicant))
    assert menus.main_menu_content(False, "new")[0] == menus.GREETINGS["new"]


# ------------------------------------------------------------------- приветствие

def test_welcome_texts_and_buttons():
    found = welcome.welcome_text("active")
    assert found.startswith("Привет! Это официальный (насколько возможно) бот Lumica")
    assert "Подписка найдена" in found and "Подписка не найдена" not in found
    for section in ("📋 Подписка", "💳 Оплатить", "🖥 Статус серверов", "⚙️ Настройки", "Центр Lumica"):
        assert section in found
    missing = welcome.welcome_text("new")
    assert "Подписка не найдена" in missing and "мы добавим связь" in missing
    assert _buttons(welcome.welcome_keyboard("active")) == [["Меню"]]
    assert _buttons(welcome.welcome_keyboard("new")) == [["📝 Регистрация", "Меню"]]
    assert welcome.welcome_keyboard("new").inline_keyboard[0][1].callback_data == "menu:back"


def test_backfill_marks_existing_users_once(monkeypatch):
    factory = _factory()
    monkeypatch.setattr(welcome, "SessionLocal", factory)
    with factory() as db:
        db.add_all([User(telegram_id="1", name="Old"), User(telegram_id="2", name="Older"), User(name="NoTg")])
        db.commit()
    assert welcome.backfill_existing_users() == 2
    assert welcome.is_welcomed("1") and welcome.is_welcomed("2") and not welcome.is_welcomed("3")
    with factory() as db:
        db.add(User(telegram_id="3", name="Brand new"))
        db.commit()
    assert welcome.backfill_existing_users() == 0      # повторно ничего не отмечаем
    assert not welcome.is_welcomed("3")                # новичок получит приветствие


def _start(monkeypatch, factory, tg_user):
    message = SimpleNamespace(from_user=tg_user, answer=AsyncMock())
    asyncio.run(onboarding.cmd_start(message))
    return message


def test_first_start_shows_welcome_then_regular_menu(monkeypatch):
    factory = _factory()
    _wire(monkeypatch, factory)
    first = _start(monkeypatch, factory, _tg_user())
    text = first.answer.await_args.args[0]
    assert text == welcome.welcome_text("new")
    assert _buttons(first.answer.await_args.kwargs["reply_markup"]) == [["📝 Регистрация", "Меню"]]
    second = _start(monkeypatch, factory, _tg_user())
    assert second.answer.await_args.args[0] == menus.GREETINGS["new"]
    assert _buttons(second.answer.await_args.kwargs["reply_markup"])[0] == ["📝 Регистрация"]


def test_admin_start_skips_welcome(monkeypatch):
    factory = _factory()
    _wire(monkeypatch, factory)
    monkeypatch.setattr(onboarding, "is_authorized", lambda *a, **k: True)
    message = _start(monkeypatch, factory, _tg_user(user_id=1))
    assert message.answer.await_args.args[0] == menus.ADMIN_GREETING


def test_client_with_subscription_gets_welcome_with_found_status_once(monkeypatch):
    factory = _factory()
    _wire(monkeypatch, factory)
    with factory() as db:
        user = User(telegram_id="500", name="Client")
        db.add(user)
        db.flush()
        db.add(Subscription(user_id=user.id, status="active"))
        db.commit()
    first = _start(monkeypatch, factory, _tg_user())
    assert "Подписка найдена" in first.answer.await_args.args[0]
    assert _buttons(first.answer.await_args.kwargs["reply_markup"]) == [["Меню"]]
    second = _start(monkeypatch, factory, _tg_user())
    assert second.answer.await_args.args[0] == menus.USER_GREETING


# -------------------------------------------------------------------- регистрация

def test_full_registration_flow_in_one_edited_message(monkeypatch):
    factory = _factory()
    _wire(monkeypatch, factory)
    notified = []
    monkeypatch.setattr(registration.notifications, "notify_admins", lambda text: notified.append(text))
    bot = _bot()

    async def scenario():
        query, _ = _query()
        await registration.start_registration(query, bot)
        first = bot.edit_message_text.await_args
        name_msg = _text_message("Иван Иванов")
        await registration.collect_text(name_msg, bot)
        second = bot.edit_message_text.await_args
        extra_msg = _text_message("Нужен прокси <b> и сервер NL")
        await registration.collect_text(extra_msg, bot)
        third = bot.edit_message_text.await_args
        done_query, _ = _query(data="reg:done")
        await registration.finish_registration(done_query, bot)
        return first, second, third, name_msg, extra_msg, bot.edit_message_text.await_args

    first, second, third, name_msg, extra_msg, final = asyncio.run(scenario())
    assert first.args[0] == "Регистрация | Новая заявка\n\nУкажите ФИО или хотя бы имя"
    assert _buttons(first.kwargs["reply_markup"]) == [["Отмена"]]
    assert (first.kwargs["chat_id"], first.kwargs["message_id"]) == (500, 77)
    assert second.args[0].startswith("Регистрация | Заявка\nФИО: Иван Иванов")
    assert "будет передано без изменений" in second.args[0]
    assert _buttons(second.kwargs["reply_markup"]) == [["Пропустить", "Отмена"]]
    assert third.args[0] == (
        "Регистрация | Готовая заявка\nФИО: Иван Иванов\nДополнительная информация: Нужен прокси &lt;b&gt; и сервер NL"
    )
    assert _buttons(third.kwargs["reply_markup"]) == [["Отмена", "Готово"]]
    name_msg.delete.assert_awaited_once()
    extra_msg.delete.assert_awaited_once()          # сообщения клиента удаляются
    assert final.args[0].startswith("✅ Заявка №1 отправлена")
    assert _buttons(final.kwargs["reply_markup"]) == [["Меню"]]
    with factory() as db:
        application = db.query(Application).one()
        assert (application.full_name, application.extra_info, application.status) == (
            "Иван Иванов", "Нужен прокси <b> и сервер NL", "new",
        )
        user = db.query(User).one()
        assert (user.telegram_id, user.status) == ("500", "unverified")
        assert menus.client_state(db, 500) == "applicant"
    assert registration.load_draft(500) is None
    assert len(notified) == 1 and "Иван Иванов" in notified[0] and "№1" in notified[0]


def test_skip_extra_gives_dash(monkeypatch):
    factory = _factory()
    _wire(monkeypatch, factory)
    bot = _bot()

    async def scenario():
        query, _ = _query()
        await registration.start_registration(query, bot)
        await registration.collect_text(_text_message("Анна"), bot)
        skip, _ = _query(data="reg:skip")
        await registration.skip_extra(skip, bot)

    asyncio.run(scenario())
    assert bot.edit_message_text.await_args.args[0].endswith("Дополнительная информация: —")


def test_draft_survives_bot_restart(monkeypatch):
    factory = _factory()
    _wire(monkeypatch, factory)
    asyncio.run(registration.start_registration(_query()[0], _bot()))   # процесс №1
    bot2 = _bot()                                                       # процесс №2: память пуста
    asyncio.run(registration.collect_text(_text_message("Мария"), bot2))
    assert bot2.edit_message_text.await_args.args[0].startswith("Регистрация | Заявка\nФИО: Мария")
    assert registration.load_draft(500).step == "extra"


def test_cancel_returns_menu_in_same_message(monkeypatch):
    factory = _factory()
    _wire(monkeypatch, factory)
    bot = _bot()
    asyncio.run(registration.start_registration(_query()[0], bot))
    cancel, message = _query(data="reg:cancel")
    asyncio.run(registration.cancel_registration(cancel))
    assert registration.load_draft(500) is None
    assert message.edit_text.await_args.args[0] == menus.GREETINGS["new"]
    assert _buttons(message.edit_text.await_args.kwargs["reply_markup"])[0] == ["📝 Регистрация"]
    with factory() as db:
        assert db.query(Application).count() == 0


def test_applicant_and_active_clients_cannot_register_again(monkeypatch):
    factory = _factory()
    _wire(monkeypatch, factory)
    with factory() as db:
        applicant = User(telegram_id="500", name="A")
        active = User(telegram_id="501", name="B")
        db.add_all([applicant, active])
        db.flush()
        db.add_all([Application(user_id=applicant.id, full_name="A", status="new"), Subscription(user_id=active.id, status="active")])
        db.commit()
    for tg_id in (500, 501):
        query, _ = _query(user_id=tg_id)
        asyncio.run(registration.start_registration(query, _bot()))
        assert query.answer.await_args.kwargs.get("show_alert") is True
        assert registration.load_draft(tg_id) is None


def test_only_private_non_command_text_goes_to_the_draft(monkeypatch):
    factory = _factory()
    _wire(monkeypatch, factory)
    assert registration._has_registration_draft(_text_message("привет")) is False   # черновика нет
    asyncio.run(registration.start_registration(_query()[0], _bot()))
    assert registration._has_registration_draft(_text_message("привет")) is True
    assert registration._has_registration_draft(_text_message("/menu")) is False
    assert registration._has_registration_draft(_text_message("привет", chat_type="supergroup")) is False


def test_application_status_page(monkeypatch):
    factory = _factory()
    _wire(monkeypatch, factory)
    with factory() as db:
        user = User(telegram_id="500", name="A")
        db.add(user)
        db.flush()
        db.add(Application(user_id=user.id, full_name="Иван", extra_info="прокси", status="new"))
        db.commit()
    query, message = _query(data="menu:appstatus")
    asyncio.run(menus.application_status_menu(query))
    text = message.edit_text.await_args.args[0]
    assert text == (
        "Регистрация | Заявка №1\n\nФИО: Иван\nДополнительная информация: прокси\n\nСтатус: на рассмотрении ⏳"
    )
    markup = message.edit_text.await_args.kwargs["reply_markup"]
    assert _buttons(markup) == [["Меню"]] and markup.inline_keyboard[0][0].callback_data == "menu:back"
