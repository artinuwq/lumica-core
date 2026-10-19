import asyncio
import json
from datetime import datetime, timezone
from decimal import Decimal
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock

from aiogram.fsm.context import FSMContext
from aiogram.fsm.storage.base import StorageKey
from aiogram.fsm.storage.memory import MemoryStorage
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
        ["Подписка", "Оплатить"], ["Рабочий аккаунт", "Статус серверов"], ["Настройки"],
    ]
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
    one = menus.format_subscription_message(sub, ["https://h/sub/a"])
    assert "Дата оплаты до: 18.11.2026" in one and "Цена: 500 ₽" in one
    assert "Ваша личная подписка:" in one
    assert "<blockquote><code>https://h/sub/a</code></blockquote>" in one
    two = menus.format_subscription_message(sub, ["https://h/sub/a", "https://h/sub/b"])
    assert "Ваши личные подписки:" in two and two.count("<code>") == 2
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
    assert texts[1].startswith("👤 Kid") and "https://panel.example/sub/abc" in texts[1]
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


def _state(user_id):
    return FSMContext(MemoryStorage(), StorageKey(bot_id=1, chat_id=user_id, user_id=user_id))


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
    payments._PENDING.clear()
    return factory


def test_pay_twice_creates_single_request(monkeypatch):
    _payment_db(monkeypatch)
    bot, state = _bot(), _state(42)

    async def scenario():
        first, second = _query(42, "menu:pay"), _query(42, "menu:pay")
        await asyncio.gather(
            payments.pay_menu(first, state, bot), payments.pay_menu(second, state, bot)
        )
        await asyncio.sleep(0)
        payments._release_pending(42)
        return first, second

    first, second = asyncio.run(scenario())
    assert bot.send_message.await_count == 1
    text = bot.send_message.await_args.args[1]
    assert "Ваши реквизиты для оплаты:" in text and "<blockquote>Карта 1234</blockquote>" in text
    assert _buttons(bot.send_message.await_args.kwargs["reply_markup"]) == [["Отменить"]]
    alerts = [c for q in (first, second) for c in q.answer.await_args_list if c.kwargs.get("show_alert")]
    assert len(alerts) == 1 and "уже создана" in alerts[0].args[0]


def test_cancel_edits_message_and_deletes_it_later(monkeypatch):
    _payment_db(monkeypatch)
    monkeypatch.setattr(payments, "CANCELLED_MESSAGE_LIFETIME_SECONDS", 0.01)
    bot, state = _bot(), _state(42)
    message = SimpleNamespace(
        chat=SimpleNamespace(id=42), message_id=100, edit_text=AsyncMock()
    )

    async def scenario():
        await payments.pay_menu(_query(42, "menu:pay"), state, bot)
        await payments.cancel_receipt(_query(42, "payment:cancel", message), state, bot)
        await asyncio.sleep(0.1)

    asyncio.run(scenario())
    message.edit_text.assert_awaited_once()
    assert message.edit_text.await_args.args[0] == "Заявка на оплату успешно отменена\nСпасибо за честность"
    assert _buttons(message.edit_text.await_args.kwargs["reply_markup"]) == [["Меню"]]
    bot.delete_message.assert_awaited_once_with(42, 100)
    assert 42 not in payments._PENDING


def test_request_expires_after_timeout(monkeypatch):
    _payment_db(monkeypatch)
    monkeypatch.setattr(payments, "PAYMENT_TIMEOUT_SECONDS", 0.05)
    bot, state = _bot(), _state(42)

    async def scenario():
        await payments.pay_menu(_query(42, "menu:pay"), state, bot)
        await asyncio.sleep(0.2)
        return await state.get_state()

    assert asyncio.run(scenario()) is None
    bot.edit_message_text.assert_awaited_once()
    args = bot.edit_message_text.await_args
    assert "отменена автоматической системой" in args.args[0]
    assert "создайте заявку заново" in args.args[0]
    assert _buttons(args.kwargs["reply_markup"]) == [["Меню"]]
    assert 42 not in payments._PENDING


def test_missing_details_do_not_start_request(monkeypatch):
    _payment_db(monkeypatch, details=None)
    bot, state = _bot(), _state(42)
    asyncio.run(payments.pay_menu(_query(42, "menu:pay"), state, bot))
    assert "Реквизиты пока не настроены" in bot.send_message.await_args.args[1]
    assert 42 not in payments._PENDING


def _send_receipt(factory_monkeypatch):
    bot, state = _bot(), _state(42)
    answers = []
    photo_message = SimpleNamespace(
        from_user=SimpleNamespace(id=42, full_name="Ivan", username="ivan"),
        chat=SimpleNamespace(id=42), message_id=900,
        photo=[SimpleNamespace(file_id="F")], document=None,
        answer=AsyncMock(side_effect=lambda *a, **k: answers.append(a[0])),
    )

    async def scenario():
        await payments.pay_menu(_query(42, "menu:pay"), state, bot)
        await payments.receive_receipt(photo_message, state, bot)
        return await state.get_state()

    return bot, answers, asyncio.run(scenario())


def test_receipt_goes_to_admin_topic_with_buttons_and_user_is_told(monkeypatch):
    factory = _payment_db(monkeypatch)
    bot, answers, state_after = _send_receipt(monkeypatch)
    kwargs = bot.copy_message.await_args.kwargs
    assert kwargs["message_thread_id"] == 7
    assert _buttons(kwargs["reply_markup"]) == [["Подтвердить", "Отклонить"]]
    assert "Оплата #1" in kwargs["caption"] and "Ivan" in kwargs["caption"]
    assert answers == ["Оплата принята на рассмотрение администратором, ожидайте результата"]
    assert state_after is None and 42 not in payments._PENDING
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
