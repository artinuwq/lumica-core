import asyncio
import json
from datetime import datetime, timedelta, timezone
from decimal import Decimal
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from lumica.bot import chatops, menus, payments
from lumica.domain.models import (
    AppSetting, Base, Group, PaymentRequest, Subscription, SubscriptionVpnAccount, User, VpnAccount,
)
from lumica.update.manifest import UpdateResult, UpdateStatus


def _factory():
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    return sessionmaker(bind=engine)


def _buttons(markup):
    return [[button.text for button in row] for row in markup.inline_keyboard]


# ----------------------------------------------------------------- меню

def test_user_and_admin_menus_have_requested_layout(monkeypatch):
    monkeypatch.delenv("WEBAPP_URL", raising=False)
    assert _buttons(menus.user_menu()) == [
        ["📋 Подписка", "💳 Оплатить"], ["🖥 Статус серверов", "🌐 Центр Lumica"], ["⚙️ Настройки"],
    ]
    assert menus.USER_GREETING.startswith("Здравствуйте! Добро пожаловать в инфраструктуру Lumica.")
    admin = menus.admin_menu()
    assert _buttons(admin) == [["Открыть mini app"], ["Подписка"], ["Настройки"]]
    assert admin.inline_keyboard[0][0].web_app.url == "https://lumica.duckdns.org/"


def test_webapp_url_env_override_ignores_placeholder(monkeypatch):
    monkeypatch.setenv("WEBAPP_URL", "https://example.com")
    assert menus.webapp_url() == "https://lumica.duckdns.org/"
    monkeypatch.setenv("WEBAPP_URL", "https://my.host/app")
    assert menus.webapp_url() == "https://my.host/app"


def test_subscription_message_quotes_links_and_pluralizes():
    sub = SimpleNamespace(
        status="active", access_until=datetime(2026, 11, 18), price_amount=Decimal("500.00"), id=1, user_id=1
    )
    one = menus.format_subscription_message(sub, [("De", "https://h/sub/a")])
    assert one.startswith("Ваша подписка\n\nДата оплаты до: 18.11.2026\nЦена: 500 ₽")
    assert 'Сервер "De":\n<blockquote><code>https://h/sub/a</code></blockquote>' in one
    two = menus.format_subscription_message(sub, [("De", "https://h/sub/a"), ("Fl", "https://h/sub/b")])
    assert 'Сервер "De":' in two and 'Сервер "Fl":' in two and two.count("<code>") == 2
    lifetime = SimpleNamespace(status="lifetime", access_until=None, price_amount=None, id=2, user_id=1)
    assert "Дата оплаты до: Бессрочно" in menus.format_subscription_message(lifetime, [])


def test_group_admin_gets_separate_message_for_each_member(monkeypatch):
    monkeypatch.setenv("PANEL_SUBSCRIPTION_BASE_URL", "https://panel.example")
    factory = _factory()
    with factory() as db:
        admin = User(telegram_id="1", name="Owner")
        kid = User(telegram_id="2", name="Kid")
        lonely = User(telegram_id="3", name="NoSub")
        db.add_all([admin, kid, lonely])
        db.flush()
        group = Group(name="G", admin_user_id=admin.id)
        db.add(group)
        db.flush()
        for person in (admin, kid, lonely):
            person.group_id = group.id
        own = Subscription(user_id=admin.id, status="active", price_amount=Decimal("300"))
        kids = Subscription(user_id=kid.id, status="active", price_amount=Decimal("100"))
        db.add_all([own, kids])
        db.flush()
        account = VpnAccount(user_id=kid.id, protocol="vless", meta_json={"sub_id": "abc"})
        db.add(account)
        db.flush()
        db.add(SubscriptionVpnAccount(subscription_id=kids.id, vpn_account_id=account.id))
        db.commit()
        texts = menus.collect_subscription_messages(db, admin)
        member_view = menus.collect_subscription_messages(db, kid)
    assert len(texts) == 3
    assert "Дата оплаты до" in texts[0]
    assert texts[1].startswith("Подписка участника группы\n👤 Kid") and "https://panel.example/sub/abc" in texts[1]
    assert "Дата оплаты" not in texts[1] and "Цена" not in texts[1]  # у участника только ссылки
    assert texts[2] == "👤 NoSub\nПодписки нет."
    assert len(member_view) == 1 and "только администратор" in member_view[0]


# ----------------------------------------------------------------- оплата

def _bot():
    bot = MagicMock()
    bot.send_message = AsyncMock(side_effect=lambda *a, **k: SimpleNamespace(message_id=100))
    bot.copy_message = AsyncMock(return_value=SimpleNamespace(message_id=500))
    bot.edit_message_text = AsyncMock()
    bot.edit_message_reply_markup = AsyncMock()
    bot.delete_message = AsyncMock()
    return bot


def _query(user_id, data, message=None):
    return SimpleNamespace(
        from_user=SimpleNamespace(id=user_id, full_name="Ivan", username="ivan"),
        data=data,
        message=message,
        answer=AsyncMock(),
    )


def _payment_db(monkeypatch, *, details="Карта 1234"):
    factory = _factory()
    with factory() as db:
        user = User(telegram_id="42", name="Ivan")
        db.add(user)
        db.flush()
        db.add(Subscription(
            user_id=user.id, status="active", price_amount=Decimal("500"),
            access_until=datetime(2030, 10, 18), billing_details=details,
        ))
        db.add(AppSetting(
            key="telegram.operator_workspace",
            value_json={"chat_id": "-100", "topics": {"Заявки и Оплата": 7}},
        ))
        db.commit()
    monkeypatch.setattr(payments, "SessionLocal", factory)
    payments._TASKS.clear()
    return factory


def _receipt_message(user_id=42, *, text=None, photo=True, chat_type="private"):
    answers = []
    message = SimpleNamespace(
        from_user=SimpleNamespace(id=user_id, full_name="Ivan", username="ivan"),
        chat=SimpleNamespace(id=user_id, type=chat_type), message_id=900, text=text,
        photo=[SimpleNamespace(file_id="F")] if photo else None, document=None,
        answer=AsyncMock(side_effect=lambda *a, **k: answers.append(a[0])),
    )
    return message, answers


def test_pay_twice_creates_single_request(monkeypatch):
    _payment_db(monkeypatch)
    bot = _bot()

    async def scenario():
        first, second = _query(42, "menu:pay"), _query(42, "menu:pay")
        await asyncio.gather(payments.pay_menu(first, bot), payments.pay_menu(second, bot))
        return first, second

    first, second = asyncio.run(scenario())
    assert bot.send_message.await_count == 1
    text = bot.send_message.await_args.args[1]
    assert "Ваши реквизиты для оплаты:" in text and "<blockquote>Карта 1234</blockquote>" in text
    assert _buttons(bot.send_message.await_args.kwargs["reply_markup"]) == [["Отменить"]]
    alerts = [c for q in (first, second) for c in q.answer.await_args_list if c.kwargs.get("show_alert")]
    assert len(alerts) == 1 and "уже создана" in alerts[0].args[0]
    pending = payments.load_pending(42)
    assert pending and pending.message_id == 100 and pending.subscription_ids == [1]


def test_request_survives_bot_restart_receipt_still_accepted(monkeypatch):
    """Клиент нажал «Оплатить», бот перезапустился (новый цикл событий и пустая память), чек принимается."""
    factory = _payment_db(monkeypatch)
    asyncio.run(payments.pay_menu(_query(42, "menu:pay"), _bot()))   # процесс №1
    payments._TASKS.clear()                                          # память процесса №1 потеряна
    bot2 = _bot()
    message, answers = _receipt_message()
    asyncio.run(payments.receive_receipt(message, bot2))             # процесс №2
    assert answers == ["Оплата принята на рассмотрение администратором, ожидайте результата"]
    assert bot2.copy_message.await_args.kwargs["message_thread_id"] == 7
    assert payments.load_pending(42) is None
    with factory() as db:
        assert db.query(PaymentRequest).one().status == "pending"


def test_cancel_works_after_bot_restart(monkeypatch):
    _payment_db(monkeypatch)
    monkeypatch.setattr(payments, "CANCELLED_MESSAGE_LIFETIME_SECONDS", 0.01)
    asyncio.run(payments.pay_menu(_query(42, "menu:pay"), _bot()))
    payments._TASKS.clear()
    bot2 = _bot()
    message = SimpleNamespace(chat=SimpleNamespace(id=42), message_id=100, edit_text=AsyncMock())

    async def scenario():
        await payments.cancel_receipt(_query(42, "payment:cancel", message), bot2)
        await asyncio.sleep(0.1)

    asyncio.run(scenario())
    assert message.edit_text.await_args.args[0] == "Заявка на оплату успешно отменена\nСпасибо за честность"
    assert _buttons(message.edit_text.await_args.kwargs["reply_markup"]) == [["Меню"]]
    bot2.delete_message.assert_awaited_once_with(42, 100)
    assert payments.load_pending(42) is None


def test_timeout_timer_is_restored_after_restart_and_expires_the_request(monkeypatch):
    _payment_db(monkeypatch)
    monkeypatch.setattr(payments, "PAYMENT_TIMEOUT_SECONDS", 0.3)
    asyncio.run(payments.pay_menu(_query(42, "menu:pay"), _bot()))   # таймер процесса №1 исчез вместе с ним
    payments._TASKS.clear()
    assert payments.load_pending(42) is not None
    bot2 = _bot()

    async def scenario():
        await payments.resume_pending_requests(bot2)
        await asyncio.sleep(0.6)

    asyncio.run(scenario())
    args = bot2.edit_message_text.await_args
    assert "отменена автоматической системой" in args.args[0] and "создайте заявку заново" in args.args[0]
    assert (args.kwargs["chat_id"], args.kwargs["message_id"]) == (42, 100)
    assert _buttons(args.kwargs["reply_markup"]) == [["Меню"]]
    assert payments.load_pending(42) is None


def test_request_that_expired_while_bot_was_down_is_closed_on_start(monkeypatch):
    _payment_db(monkeypatch)
    asyncio.run(payments.pay_menu(_query(42, "menu:pay"), _bot()))
    payments._TASKS.clear()
    pending = payments.load_pending(42)
    pending.expires_at = datetime.now(timezone.utc) - timedelta(minutes=5)
    payments.save_pending(pending)
    bot2 = _bot()

    async def scenario():
        await payments.resume_pending_requests(bot2)
        await asyncio.sleep(0.1)

    asyncio.run(scenario())
    assert "отменена автоматической системой" in bot2.edit_message_text.await_args.args[0]
    assert payments.load_pending(42) is None


def test_receipt_after_expiry_is_refused_even_before_the_timer_fires(monkeypatch):
    _payment_db(monkeypatch)
    asyncio.run(payments.pay_menu(_query(42, "menu:pay"), _bot()))
    payments._TASKS.clear()
    pending = payments.load_pending(42)
    pending.expires_at = datetime.now(timezone.utc) - timedelta(seconds=1)
    payments.save_pending(pending)
    bot2 = _bot()
    message, answers = _receipt_message()
    asyncio.run(payments.receive_receipt(message, bot2))
    assert answers == ["Заявка на оплату уже закрыта. Создайте новую через меню."]
    bot2.copy_message.assert_not_awaited()
    assert payments.load_pending(42) is None


def test_only_private_non_command_messages_of_a_waiting_client_are_taken(monkeypatch):
    _payment_db(monkeypatch)
    stranger, _ = _receipt_message(user_id=7)
    assert payments._has_pending_payment(stranger) is False          # заявки нет
    asyncio.run(payments.pay_menu(_query(42, "menu:pay"), _bot()))
    photo, _ = _receipt_message()
    command, _ = _receipt_message(text="/menu", photo=False)
    group, _ = _receipt_message(chat_type="supergroup")
    assert payments._has_pending_payment(photo) is True
    assert payments._has_pending_payment(command) is False           # /menu остаётся командой
    assert payments._has_pending_payment(group) is False
    asyncio.run(asyncio.sleep(0))


def test_cancel_edits_message_and_deletes_it_later(monkeypatch):
    _payment_db(monkeypatch)
    monkeypatch.setattr(payments, "CANCELLED_MESSAGE_LIFETIME_SECONDS", 0.01)
    bot = _bot()
    message = SimpleNamespace(chat=SimpleNamespace(id=42), message_id=100, edit_text=AsyncMock())

    async def scenario():
        await payments.pay_menu(_query(42, "menu:pay"), bot)
        await payments.cancel_receipt(_query(42, "payment:cancel", message), bot)
        await asyncio.sleep(0.1)

    asyncio.run(scenario())
    assert message.edit_text.await_args.args[0] == "Заявка на оплату успешно отменена\nСпасибо за честность"
    assert _buttons(message.edit_text.await_args.kwargs["reply_markup"]) == [["Меню"]]
    bot.delete_message.assert_awaited_once_with(42, 100)
    assert payments.load_pending(42) is None


def test_request_expires_after_timeout(monkeypatch):
    _payment_db(monkeypatch)
    monkeypatch.setattr(payments, "PAYMENT_TIMEOUT_SECONDS", 0.05)
    bot = _bot()

    async def scenario():
        await payments.pay_menu(_query(42, "menu:pay"), bot)
        await asyncio.sleep(0.3)

    asyncio.run(scenario())
    bot.edit_message_text.assert_awaited_once()
    args = bot.edit_message_text.await_args
    assert "отменена автоматической системой" in args.args[0]
    assert _buttons(args.kwargs["reply_markup"]) == [["Меню"]]
    assert payments.load_pending(42) is None


def test_receipt_cancels_the_timeout_timer(monkeypatch):
    _payment_db(monkeypatch)
    monkeypatch.setattr(payments, "PAYMENT_TIMEOUT_SECONDS", 0.4)
    bot = _bot()
    message, answers = _receipt_message()

    async def scenario():
        await payments.pay_menu(_query(42, "menu:pay"), bot)
        await payments.receive_receipt(message, bot)
        await asyncio.sleep(0.9)

    asyncio.run(scenario())
    bot.edit_message_text.assert_not_awaited()   # «заявка отменена» после принятого чека не приходит
    assert answers == ["Оплата принята на рассмотрение администратором, ожидайте результата"]


def test_missing_details_do_not_start_request(monkeypatch):
    _payment_db(monkeypatch, details=None)
    bot = _bot()
    asyncio.run(payments.pay_menu(_query(42, "menu:pay"), bot))
    sent = bot.send_message.await_args
    assert sent.args[1] == "Реквизиты для вас пока не настроены. Напишите в рабочий аккаунт"
    assert sent.args[1].count("http") == 0
    buttons = sent.kwargs["reply_markup"].inline_keyboard[0]
    assert [b.text for b in buttons] == ["Меню", "Аккаунт"]
    assert buttons[0].callback_data == "menu:main" and buttons[1].url.startswith("https://t.me/")
    assert payments.load_pending(42) is None


def _send_receipt(factory_monkeypatch):
    bot = _bot()
    message, answers = _receipt_message()

    async def scenario():
        await payments.pay_menu(_query(42, "menu:pay"), bot)
        await payments.receive_receipt(message, bot)

    asyncio.run(scenario())
    return bot, answers, None


def test_receipt_goes_to_admin_topic_with_buttons_and_user_is_told(monkeypatch):
    factory = _payment_db(monkeypatch)
    bot, answers, _ = _send_receipt(monkeypatch)
    kwargs = bot.copy_message.await_args.kwargs
    assert kwargs["message_thread_id"] == 7
    assert _buttons(kwargs["reply_markup"]) == [["Подтвердить", "Отклонить"]]
    assert "Оплата #1" in kwargs["caption"] and "Ivan" in kwargs["caption"]
    assert answers == ["Оплата принята на рассмотрение администратором, ожидайте результата"]
    assert payments.load_pending(42) is None
    bot.edit_message_reply_markup.assert_awaited_once()  # кнопка «Отменить» убрана
    with factory() as db:
        item = db.query(PaymentRequest).one()
        assert (item.status, item.operator_message_id) == ("pending", 500)


def _operator_message():
    return SimpleNamespace(
        text=None, caption="Оплата #1\nСтатус: ожидает подтверждения",
        edit_caption=AsyncMock(), edit_text=AsyncMock(),
    )


def test_admin_confirm_then_extend_shows_before_after_and_notifies_user(monkeypatch):
    factory = _payment_db(monkeypatch)
    _send_receipt(monkeypatch)
    monkeypatch.setattr(payments, "is_authorized", lambda *a, **k: True)
    bot = _bot()

    async def scenario():
        confirm_msg = _operator_message()
        await payments.confirm_payment(_query(1, "payment:confirm:1", confirm_msg))
        extend_msg = SimpleNamespace(
            text=None, caption=confirm_msg.edit_caption.await_args.kwargs["caption"],
            edit_caption=AsyncMock(), edit_text=AsyncMock(),
        )
        again = _query(1, "payment:extend:1", extend_msg)
        await payments.extend_payment(again, bot)
        repeat = _query(1, "payment:extend:1", extend_msg)
        await payments.extend_payment(repeat, bot)
        return confirm_msg, extend_msg, repeat

    confirm_msg, extend_msg, repeat = asyncio.run(scenario())
    assert _buttons(confirm_msg.edit_caption.await_args.kwargs["reply_markup"]) == [
        ["Продлить на 1 месяц"], ["Открыть", "Пропустить"],
    ]
    caption = extend_msg.edit_caption.await_args.kwargs["caption"]
    assert 'Выбранное действие: "Продлить на месяц"' in caption
    assert "Было: 18.10.2030" in caption and "Стало: 18.11.2030" in caption
    assert extend_msg.edit_caption.await_args.kwargs["reply_markup"] is None
    assert "Следующая оплата: 18.11.2030" in bot.send_message.await_args.args[1]
    assert repeat.answer.await_args.kwargs.get("show_alert") is True  # второй клик не продлевает ещё раз
    with factory() as db:
        assert db.query(Subscription).one().access_until.date().isoformat() == "2030-11-18"
        assert db.query(PaymentRequest).one().status == "extended"


def test_admin_skip_and_reject(monkeypatch):
    factory = _payment_db(monkeypatch)
    _send_receipt(monkeypatch)
    monkeypatch.setattr(payments, "is_authorized", lambda *a, **k: True)
    bot = _bot()

    async def skip_flow():
        msg = _operator_message()
        await payments.confirm_payment(_query(1, "payment:confirm:1", msg))
        skip_msg = SimpleNamespace(text=None, caption=msg.edit_caption.await_args.kwargs["caption"],
                                   edit_caption=AsyncMock(), edit_text=AsyncMock())
        await payments.skip_payment(_query(1, "payment:skip:1", skip_msg))
        return skip_msg

    skip_msg = asyncio.run(skip_flow())
    assert 'Выбранное действие: "Пропуск"' in skip_msg.edit_caption.await_args.kwargs["caption"]
    with factory() as db:
        assert db.query(PaymentRequest).one().status == "skipped"
        assert db.query(Subscription).one().access_until.date().isoformat() == "2030-10-18"

    with factory() as db:  # новая заявка -> отклонение
        db.add(PaymentRequest(subscription_id=1, subscription_ids=[1], payer_user_id=1, amount=Decimal("1")))
        db.commit()
    reject_msg = _operator_message()
    asyncio.run(payments.reject_payment(_query(1, "payment:reject:2", reject_msg), bot))
    sent = bot.send_message.await_args
    assert sent.args[0] == "42" and "Оплата не засчитана" in sent.args[1] and "рабочий аккаунт" in sent.args[1]
    assert reject_msg.edit_caption.await_args.kwargs["reply_markup"] is None


def test_non_admin_cannot_review_payment(monkeypatch):
    _payment_db(monkeypatch)
    monkeypatch.setattr(payments, "is_authorized", lambda *a, **k: False)
    query = _query(5, "payment:confirm:1", _operator_message())
    asyncio.run(payments.confirm_payment(query))
    assert query.answer.await_args.kwargs.get("show_alert") is True


# ----------------------------------------------------------- /status, /update

def _status(**over):
    base = dict(
        branch="main", local_sha="a9", remote_sha="49", up_to_date=False, dirty=False, message="m",
        local_version="a9f75b3 (2026-10-17)", remote_version="497267a (2026-10-17)", remote_subject="Fix login",
    )
    base.update(over)
    return UpdateStatus(**base)


LAST = {"kind": "update", "success": True, "finished_at": "2026-10-18T20:39:48+00:00"}


def test_status_text_when_up_to_date_and_when_update_needed():
    ok = chatops.render_status_text(_status(up_to_date=True), LAST)
    assert ok == (
        "ℹ️ На данный момент установлена актуальная версия\n"
        "Последняя операция: update, 2026-10-18 23:39:48"
    )
    need = chatops.render_status_text(_status(), LAST)
    assert need == (
        "⛔️ Требуется обновление\n\n"
        "Сейчас: a9f75b3 (2026-10-17)\nПоследняя: 497267a (2026-10-17)\n\n"
        "Описание обновления: Fix login\n\n"
        "Последняя операция: update, 2026-10-18 23:39:48"
    )
    assert chatops.render_status_text(_status(local_sha="", message="ошибка сети: x"), None) == "⚠️ ошибка сети: x"


class FakeManager:
    def __init__(self, state_dir, *, result):
        self.state_dir = state_dir
        self.repo_dir = state_dir
        self._result = result
        self.service = SimpleNamespace(unit_exists=lambda unit: True, update_unit="lumica-update")

    def check(self):
        return _status()

    def apply_background(self, force=False):
        return UpdateResult(True, "started", started=True)

    def last_result(self):
        return self._result()


def test_update_edits_one_message_and_posts_server_event(monkeypatch, tmp_path):
    finished = {
        "kind": "update", "success": True, "previous_sha": "a9", "current_sha": "49",
        "finished_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
    }
    calls = {"n": 0}

    def last_result():
        calls["n"] += 1
        return finished if calls["n"] > 1 else None

    manager = FakeManager(tmp_path, result=last_result)
    monkeypatch.setattr(chatops, "UpdateManager", lambda: manager)
    monkeypatch.setattr(chatops, "is_authorized", lambda *a, **k: True)
    monkeypatch.setattr(chatops, "NOTICE_POLL_SECONDS", 0.01)
    monkeypatch.setattr(
        chatops.update_provider, "describe",
        lambda repo, sha: {"a9": "a9f75b3 (2026-10-17)", "49": "497267a (2026-10-17)"}[sha],
    )
    events = []
    monkeypatch.setattr(chatops, "post_to_topic", lambda topic, text: events.append((topic, text)) or True)

    progress = SimpleNamespace(chat=SimpleNamespace(id=42), message_id=77, edit_text=AsyncMock())
    message = SimpleNamespace(
        from_user=SimpleNamespace(id=42, full_name="Ivan", username="ivan"),
        answer=AsyncMock(return_value=progress),
    )
    bot = _bot()

    async def scenario():
        await chatops.cmd_update(message, bot)
        await asyncio.sleep(0.2)

    asyncio.run(scenario())
    assert message.answer.await_args.args[0] == "⏳ Проверяю и применяю обновление..."
    assert message.answer.await_count == 1  # новых сообщений не плодим
    progress.edit_text.assert_awaited_once_with("⏳ Обновление запущено в фоне")
    final = bot.edit_message_text.await_args
    assert final.args[0] == "✅ Обновление успешно завершено\na9f75b3 (2026-10-17) -> 497267a (2026-10-17)"
    assert (final.kwargs["chat_id"], final.kwargs["message_id"]) == (42, 77)
    assert len(events) == 1 and events[0][0] == "🔴 События серверов"
    for expected in ("Запущено обновление", "Ivan", "main", "a9f75b3", "497267a", "Fix login"):
        assert expected in events[0][1]
    assert not (tmp_path / chatops.NOTICE_FILE_NAME).exists()


def test_new_bot_process_finishes_update_message_after_restart(monkeypatch, tmp_path):
    finished = {
        "kind": "update", "success": False, "message": "новая версия не запустилась",
        "finished_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
    }
    manager = FakeManager(tmp_path, result=lambda: finished)
    monkeypatch.setattr(chatops, "UpdateManager", lambda: manager)
    (tmp_path / chatops.NOTICE_FILE_NAME).write_text(json.dumps({
        "chat_id": 42, "message_id": 77, "started_at": "2020-01-01T00:00:00+00:00",
    }))
    bot = _bot()
    asyncio.run(chatops.resume_update_notice(bot))
    assert bot.edit_message_text.await_args.args[0] == "❌ Обновление не удалось\nновая версия не запустилась"
    assert not (tmp_path / chatops.NOTICE_FILE_NAME).exists()


# --------------------------------------------- /menu, состояние серверов, прокси-ссылки

def test_server_condition_thresholds():
    assert menus.server_condition("green", 49.9, 79.9) == ("🟢", "отличное")
    assert menus.server_condition("green", 50.0, 10.0) == ("🟡", "среднее")  # CPU не ниже 50%
    assert menus.server_condition("green", 10.0, 80.0) == ("🟡", "среднее")  # RAM не ниже 80%
    assert menus.server_condition("red", 1.0, 1.0) == ("🔴", "недоступен")
    assert menus.server_condition("green", None, 30.0) == ("🟢", "доступен")


def _menu_message():
    answers = []
    message = SimpleNamespace(
        from_user=SimpleNamespace(id=42, full_name="Ivan", username="ivan"),
        answer=AsyncMock(side_effect=lambda *a, **k: answers.append((a, k))),
    )
    return message, answers


def _page_query(user_id=42):
    message = SimpleNamespace(edit_text=AsyncMock(), answer=AsyncMock())
    query = SimpleNamespace(
        from_user=SimpleNamespace(id=user_id, full_name="Ivan", username="ivan"),
        data="x", message=message, answer=AsyncMock(),
    )
    return query, message


def test_server_status_is_a_page_that_replaces_the_message(monkeypatch):
    from lumica.domain.models import Panel

    factory = _factory()
    with factory() as db:
        db.add_all([
            Panel(id="a", name="Финляндия", provider="3xui", auth_type="token", auth_secret_ref="x",
                  base_url="https://h", health_status="green"),
            Panel(id="b", name="Германия", provider="3xui", auth_type="token", auth_secret_ref="x",
                  base_url="https://h", health_status="green"),
            Panel(id="c", name="Нидерланды", provider="3xui", auth_type="token", auth_secret_ref="x",
                  base_url="https://h", health_status="red"),
            Panel(id="d", name="Выключен", provider="3xui", auth_type="token", auth_secret_ref="x",
                  base_url="https://h", is_active=0, health_status="green"),
            AppSetting(key=menus.PANEL_MONITOR_STATE_KEY, value_json={
                "a": {"cpu": 12.0, "mem": 40.0}, "b": {"cpu": 71.0, "mem": 30.0}, "c": {"cpu": 1.0, "mem": 1.0},
            }),
            User(telegram_id="42", name="Ivan"),
        ])
        db.flush()
        db.add(Subscription(user_id=db.query(User).filter(User.telegram_id == "42").one().id, status="active"))
        db.commit()
    monkeypatch.setattr(menus, "SessionLocal", factory)
    monkeypatch.setattr(menus, "is_authorized", lambda *a, **k: False)

    query, message = _page_query()
    asyncio.run(menus.status_menu(query))
    text = message.edit_text.await_args.args[0]
    assert text.startswith("🌍 Состояние серверов")
    assert "🟢 Финляндия - отличное" in text
    assert "🟡 Германия - среднее" in text
    assert "🔴 Нидерланды - недоступен" in text
    assert "Выключен" not in text
    markup = message.edit_text.await_args.kwargs["reply_markup"]
    assert _buttons(markup) == [["Меню"]] and markup.inline_keyboard[0][0].callback_data == "menu:back"
    message.answer.assert_not_awaited()  # то же сообщение, новых нет

    # [Меню] возвращает главное меню тем же сообщением
    back_query, back_message = _page_query()
    asyncio.run(menus.back_to_menu(back_query))
    assert back_message.edit_text.await_args.args[0] == menus.USER_GREETING
    assert _buttons(back_message.edit_text.await_args.kwargs["reply_markup"])[0] == ["📋 Подписка", "💳 Оплатить"]


def test_help_center_is_a_placeholder_page_with_back_button(monkeypatch):
    factory = _factory()
    with factory() as db:
        user = User(telegram_id="42", name="Ivan")
        db.add(user)
        db.flush()
        db.add(Subscription(user_id=user.id, status="active"))
        db.commit()
    monkeypatch.setattr(menus, "SessionLocal", factory)
    monkeypatch.setattr(menus, "is_authorized", lambda *a, **k: False)
    query, message = _page_query()
    asyncio.run(menus.help_menu(query))
    assert message.edit_text.await_args.args[0] == "Здесь будет справка."
    markup = message.edit_text.await_args.kwargs["reply_markup"]
    assert _buttons(markup) == [["Назад"]] and markup.inline_keyboard[0][0].callback_data == "menu:back"
    back_query, back_message = _page_query()
    asyncio.run(menus.back_to_menu(back_query))
    assert back_message.edit_text.await_args.args[0] == menus.USER_GREETING


def test_admin_menu_unchanged_and_has_no_server_block(monkeypatch):
    message, answers = _menu_message()
    asyncio.run(menus.answer_main_menu(message, is_admin=True))
    assert answers[0][0][0] == menus.ADMIN_GREETING
    assert _buttons(answers[0][1]["reply_markup"]) == [["Открыть mini app"], ["Подписка"], ["Настройки"]]


def test_menu_command_shows_menu_again(monkeypatch):
    factory = _factory()
    with factory() as db:
        user = User(telegram_id="42", name="Ivan")
        db.add(user)
        db.flush()
        db.add(Subscription(user_id=user.id, status="active"))
        db.commit()
    monkeypatch.setattr(menus, "SessionLocal", factory)
    monkeypatch.setattr(menus, "is_authorized", lambda *a, **k: False)
    message, answers = _menu_message()
    asyncio.run(menus.cmd_menu(message))
    assert answers[0][0][0] == menus.USER_GREETING
    assert _buttons(answers[0][1]["reply_markup"])[0] == ["📋 Подписка", "💳 Оплатить"]

    stranger, stranger_answers = _menu_message()
    stranger.from_user.id = 999
    asyncio.run(menus.cmd_menu(stranger))
    # незнакомому /menu показывает меню с кнопкой регистрации, а не тупик
    assert stranger_answers[0][0][0] == menus.GREETINGS["new"]
    assert _buttons(stranger_answers[0][1]["reply_markup"])[0] == ["📝 Регистрация"]


def test_subscription_message_ends_with_proxy_links_quote():
    sub = SimpleNamespace(
        status="active", access_until=datetime(2100, 5, 14), price_amount=Decimal("8"), id=1, user_id=1,
        notes="tg://proxy?server=a&port=1\nsocks5://u:p@h:1080",
    )
    text = menus.format_subscription_message(sub, [("De", "https://h/sub/a")])
    assert text.index('Сервер "De":') < text.index("Прокси-ссылки:")
    assert text.endswith("<blockquote>tg://proxy?server=a&amp;port=1\nsocks5://u:p@h:1080</blockquote>")
    member = menus.format_subscription_message(sub, [], owner_name="Kid")
    assert "Прокси-ссылки:" in member and "Ссылка на подписку пока не выдана" not in member
    no_notes = SimpleNamespace(**{**sub.__dict__, "notes": None})
    assert "Прокси-ссылки" not in menus.format_subscription_message(no_notes, [("De", "https://h")])
