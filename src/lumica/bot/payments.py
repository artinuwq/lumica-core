"""Оплата подписки через бота.

Клиент: «Оплатить» -> реквизиты + просьба прислать чек (одна активная заявка на
человека, автоотмена через 15 минут) -> чек уходит в тему «Заявки и Оплата»
операторской группы с кнопками. Администратор: [Подтвердить] [Отклонить] ->
после подтверждения [Продлить на 1 месяц] / [Открыть] / [Пропустить].
"""

from __future__ import annotations

import asyncio
import html
import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from decimal import Decimal

from aiogram import Bot, Router, types
from aiogram.exceptions import TelegramAPIError
from aiogram.fsm.context import FSMContext
from aiogram.fsm.state import State, StatesGroup
from aiogram.types import CallbackQuery, InlineKeyboardButton, InlineKeyboardMarkup

from lumica.domain.models import AppSetting, Group, PaymentRequest, Subscription, User
from lumica.infra.db import SessionLocal
from lumica.services.notification_settings import is_silent
from lumica.services.payments import add_calendar_month
from lumica.services.roles import is_authorized, load_role_bindings

from .menus import NO_DETAILS_TEXT, menu_button, no_details_keyboard, support_url
from .workspace import MOSCOW, WORKSPACE_KEY

logger = logging.getLogger(__name__)
router = Router(name="payments")

PAYMENT_TIMEOUT_SECONDS = 15 * 60
CANCELLED_MESSAGE_LIFETIME_SECONDS = 60
PAYABLE_STATUSES = ("active", "expiring", "expired")

CANCELLED_TEXT = "Заявка на оплату успешно отменена\nСпасибо за честность"
EXPIRED_TEXT = (
    "Данная заявка отменена автоматической системой.\n"
    "Если вы оплатили, но забыли скинуть чек, создайте заявку заново."
)
RECEIPT_ACCEPTED_TEXT = "Оплата принята на рассмотрение администратором, ожидайте результата"


class PaymentReceipt(StatesGroup):
    waiting_for_file = State()


@dataclass
class PendingPayment:
    chat_id: int
    subscription_ids: list[int]
    message_id: int | None = None
    task: asyncio.Task | None = field(default=None, repr=False)


# Активные заявки по telegram_id плательщика. Хранится в памяти процесса, как и FSM.
_PENDING: dict[int, PendingPayment] = {}


def _parse_payment_target(data: str) -> tuple[int, bool] | None:
    parts = (data or "").split(":")
    if len(parts) == 3 and parts[0] == "payment" and parts[1] in {"send", "send-group"}:
        try:
            return int(parts[2]), parts[1] == "send-group"
        except ValueError:
            return None
    return None


def _cancel_keyboard() -> InlineKeyboardMarkup:
    return InlineKeyboardMarkup(inline_keyboard=[[InlineKeyboardButton(text="Отменить", callback_data="payment:cancel")]])


def _review_keyboard(request_id: int) -> InlineKeyboardMarkup:
    return InlineKeyboardMarkup(inline_keyboard=[[
        InlineKeyboardButton(text="Подтвердить", callback_data=f"payment:confirm:{request_id}"),
        InlineKeyboardButton(text="Отклонить", callback_data=f"payment:reject:{request_id}"),
    ]])


def _action_keyboard(request_id: int) -> InlineKeyboardMarkup:
    return InlineKeyboardMarkup(inline_keyboard=[
        [InlineKeyboardButton(text="Продлить на 1 месяц", callback_data=f"payment:extend:{request_id}")],
        [
            InlineKeyboardButton(text="Открыть", callback_data=f"payment:open:{request_id}"),
            InlineKeyboardButton(text="Пропустить", callback_data=f"payment:skip:{request_id}"),
        ],
    ])


def _display_name(user: User | None) -> str:
    if not user:
        return "—"
    return user.name or (f"@{user.username}" if user.username else f"id{user.telegram_id}")


def _fmt_date(value: datetime | None) -> str:
    return value.strftime("%d.%m.%Y") if value else "не указано"


def _is_admin(telegram_id: int) -> bool:
    return is_authorized(telegram_id, "admin", load_role_bindings())


# ------------------------------------------------------- заявка клиента

def _release_pending(telegram_id: int) -> PendingPayment | None:
    pending = _PENDING.pop(telegram_id, None)
    task = pending.task if pending else None
    if task and task is not asyncio.current_task():
        task.cancel()
    return pending


async def _delete_later(bot: Bot, chat_id: int, message_id: int, delay: float) -> None:
    try:
        await asyncio.sleep(delay)
        await bot.delete_message(chat_id, message_id)
    except (TelegramAPIError, asyncio.CancelledError):
        pass


async def _expire_request(bot: Bot, telegram_id: int, state: FSMContext, pending: PendingPayment) -> None:
    try:
        await asyncio.sleep(PAYMENT_TIMEOUT_SECONDS)
    except asyncio.CancelledError:
        return
    if _PENDING.get(telegram_id) is not pending:
        return
    _PENDING.pop(telegram_id, None)
    try:
        await state.clear()
    except Exception:  # noqa: BLE001 - автоотмена не должна падать из-за хранилища FSM
        logger.exception("Could not clear FSM state for %s", telegram_id)
    if pending.message_id:
        try:
            await bot.edit_message_text(
                EXPIRED_TEXT, chat_id=pending.chat_id, message_id=pending.message_id, reply_markup=menu_button()
            )
        except TelegramAPIError:
            await bot.send_message(pending.chat_id, EXPIRED_TEXT, reply_markup=menu_button())


async def begin_payment_request(
    query: CallbackQuery, state: FSMContext, bot: Bot, *, subscription_ids: list[int], details: str | None
) -> None:
    """Создаёт ровно одну активную заявку на человека."""
    telegram_id = query.from_user.id
    existing = _PENDING.get(telegram_id)
    if existing:
        if await state.get_state() == PaymentReceipt.waiting_for_file.state:
            await query.answer("Заявка на оплату уже создана. Отправьте чек в ответ на неё.", show_alert=True)
            return
        _release_pending(telegram_id)  # состояние сброшено (например, /start) - заявка протухла

    if not details:
        await query.answer()
        await bot.send_message(query.from_user.id, NO_DETAILS_TEXT, reply_markup=no_details_keyboard())
        return

    # Занимаем слот до первого await, чтобы двойное нажатие не создало две заявки.
    pending = PendingPayment(chat_id=query.from_user.id, subscription_ids=list(subscription_ids))
    _PENDING[telegram_id] = pending
    await query.answer()
    try:
        await state.set_state(PaymentReceipt.waiting_for_file)
        await state.update_data(subscription_ids=list(subscription_ids))
        sent = await bot.send_message(
            pending.chat_id,
            "Ваши реквизиты для оплаты:\n"
            f"<blockquote>{html.escape(details)}</blockquote>\n\n"
            "Пожалуйста, отправьте скрин перевода, а лучше скрин чека в следующем сообщении "
            "для подтверждения оплаты.",
            parse_mode="HTML",
            reply_markup=_cancel_keyboard(),
        )
    except Exception:
        _release_pending(telegram_id)
        await state.clear()
        raise
    pending.message_id = sent.message_id
    pending.task = asyncio.create_task(_expire_request(bot, telegram_id, state, pending))


def _payable_subscriptions(db, user: User) -> tuple[list[Subscription], str | None, str | None]:
    """(подписки к оплате, реквизиты, ошибка для пользователя)."""
    group = db.query(Group).filter(Group.id == user.group_id).first() if user.group_id else None
    if group and group.admin_user_id != user.id:
        return [], None, "Оплату семейной подписки вносит администратор группы."
    if group:
        member_ids = [row.id for row in db.query(User.id).filter(User.group_id == group.id).all()]
        subscriptions = db.query(Subscription).filter(
            Subscription.user_id.in_(member_ids), Subscription.status.in_(PAYABLE_STATUSES)
        ).order_by(Subscription.id.asc()).all()
        own = db.query(Subscription).filter(Subscription.user_id == user.id).order_by(Subscription.id.desc()).first()
        details = next(
            (item.billing_details for item in db.query(Subscription).filter(Subscription.user_id == user.id)
             .order_by(Subscription.id.desc()).all() if item.billing_details),
            None,
        ) if own else None
    else:
        subscriptions = db.query(Subscription).filter(
            Subscription.user_id == user.id, Subscription.status.in_(PAYABLE_STATUSES)
        ).order_by(Subscription.id.desc()).limit(1).all()
        details = subscriptions[0].billing_details if subscriptions else None
    if not subscriptions:
        return [], None, "Подписки к оплате не найдены."
    return subscriptions, details, None


@router.callback_query(lambda query: query.data == "menu:pay")
async def pay_menu(query: CallbackQuery, state: FSMContext, bot: Bot) -> None:
    if not query.from_user:
        return
    with SessionLocal() as db:
        user = db.query(User).filter(User.telegram_id == str(query.from_user.id)).first()
        if not user:
            await query.answer("Вы ещё не зарегистрированы. Отправьте /start.", show_alert=True)
            return
        subscriptions, details, error = _payable_subscriptions(db, user)
        subscription_ids = [item.id for item in subscriptions]
    if error:
        await query.answer(error, show_alert=True)
        return
    await begin_payment_request(query, state, bot, subscription_ids=subscription_ids, details=details)


@router.callback_query(lambda query: (query.data or "").startswith(("payment:send:", "payment:send-group:")))
async def request_receipt(query: CallbackQuery, state: FSMContext, bot: Bot) -> None:
    """Кнопка «Подтвердить оплату» из напоминания об оплате."""
    if not query.from_user or not query.data:
        return
    target = _parse_payment_target(query.data)
    if not target:
        await query.answer("Некорректная подписка", show_alert=True)
        return
    target_id, is_group_payment = target
    with SessionLocal() as db:
        user = db.query(User).filter(User.telegram_id == str(query.from_user.id)).first()
        if not user:
            await query.answer("Подписки к оплате не найдены", show_alert=True)
            return
        subscriptions, details, error = _payable_subscriptions(db, user)
        if error:
            await query.answer(error, show_alert=True)
            return
        if is_group_payment:
            group = db.query(Group).filter(Group.id == target_id).first()
            if not group or group.admin_user_id != user.id:
                await query.answer("Оплатить семейную подписку может только администратор группы", show_alert=True)
                return
        elif target_id not in {item.id for item in subscriptions}:
            await query.answer("Подписки к оплате не найдены", show_alert=True)
            return
        subscription_ids = [item.id for item in subscriptions]
    await begin_payment_request(query, state, bot, subscription_ids=subscription_ids, details=details)


@router.callback_query(lambda query: query.data == "payment:cancel")
async def cancel_receipt(query: CallbackQuery, state: FSMContext, bot: Bot) -> None:
    await state.clear()
    if query.from_user:
        _release_pending(query.from_user.id)
    await query.answer()
    message = query.message
    if not message:
        return
    try:
        await message.edit_text(CANCELLED_TEXT, reply_markup=menu_button())
    except TelegramAPIError:
        return
    asyncio.create_task(_delete_later(bot, message.chat.id, message.message_id, CANCELLED_MESSAGE_LIFETIME_SECONDS))


@router.callback_query(lambda query: (query.data or "").startswith("payment:details:"))
async def payment_details(query: CallbackQuery) -> None:
    if not query.from_user or not query.data:
        return
    try:
        subscription_id = int(query.data.rsplit(":", 1)[1])
    except ValueError:
        await query.answer("Некорректная подписка", show_alert=True)
        return
    with SessionLocal() as db:
        user = db.query(User).filter(User.telegram_id == str(query.from_user.id)).first()
        subscription = db.query(Subscription).filter(
            Subscription.id == subscription_id, Subscription.user_id == user.id
        ).first() if user else None
        details = subscription.billing_details if subscription else None
    await query.answer()
    if query.message:
        await _send_details(query.message, details)


@router.callback_query(lambda query: (query.data or "").startswith("payment:details-group:"))
async def group_payment_details(query: CallbackQuery) -> None:
    if not query.from_user or not query.data:
        return
    try:
        group_id = int(query.data.rsplit(":", 1)[1])
    except ValueError:
        await query.answer("Некорректная группа", show_alert=True)
        return
    with SessionLocal() as db:
        payer = db.query(User).filter(User.telegram_id == str(query.from_user.id)).first()
        group = db.query(Group).filter(Group.id == group_id).first()
        if not payer or not group or group.admin_user_id != payer.id:
            await query.answer("Реквизиты доступны администратору группы", show_alert=True)
            return
        admin_subscription = db.query(Subscription).filter(
            Subscription.user_id == payer.id, Subscription.billing_details.isnot(None)
        ).order_by(Subscription.id.desc()).first()
        details = admin_subscription.billing_details if admin_subscription else None
    await query.answer()
    if query.message:
        await _send_details(query.message, details)


async def _send_details(message: types.Message, details: str | None) -> None:
    if not details:
        await message.answer(NO_DETAILS_TEXT, reply_markup=no_details_keyboard())
        return
    await message.answer(
        f"Ваши реквизиты для оплаты:\n<blockquote>{html.escape(details)}</blockquote>", parse_mode="HTML"
    )


# ------------------------------------------------------ получение чека

@router.message(PaymentReceipt.waiting_for_file)
async def receive_receipt(message: types.Message, state: FSMContext, bot: Bot) -> None:
    if not message.from_user:
        return
    telegram_id = message.from_user.id
    pending = _PENDING.get(telegram_id)
    if pending is None:
        await state.clear()
        await message.answer(
            "Заявка на оплату уже закрыта. Создайте новую через меню.", reply_markup=menu_button()
        )
        return
    file_id = message.photo[-1].file_id if message.photo else (message.document.file_id if message.document else None)
    if not file_id:
        await message.answer("Нужно отправить фото или документ с чеком. Для отмены нажмите «Отменить» в сообщении выше.")
        return
    data = await state.get_data()
    subscription_ids = data.get("subscription_ids") or pending.subscription_ids
    try:
        subscription_ids = sorted({int(value) for value in subscription_ids})
    except (TypeError, ValueError):
        subscription_ids = []

    with SessionLocal() as db:
        user = db.query(User).filter(User.telegram_id == str(telegram_id)).first()
        subscriptions = db.query(Subscription).filter(Subscription.id.in_(subscription_ids)).all() if subscription_ids else []
        group = db.query(Group).filter(Group.id == user.group_id).first() if user and user.group_id else None
        owns_all = bool(user and subscriptions and len(subscriptions) == len(subscription_ids))
        if owns_all and group:
            owns_all = group.admin_user_id == user.id and all(
                member.group_id == group.id
                for item in subscriptions
                for member in [db.query(User).filter(User.id == item.user_id).first()]
                if member
            )
        elif owns_all:
            owns_all = len(subscriptions) == 1 and subscriptions[0].user_id == user.id
        workspace = db.query(AppSetting).filter(AppSetting.key == WORKSPACE_KEY).first()
        config = workspace.value_json if workspace and isinstance(workspace.value_json, dict) else {}
        if not owns_all or not config.get("chat_id") or not config.get("topics", {}).get("Заявки и Оплата"):
            await state.clear()
            _release_pending(telegram_id)
            await message.answer("Не удалось передать чек. Обратитесь в рабочий аккаунт.", reply_markup=menu_button())
            return
        if group:
            payer_subscription = db.query(Subscription).filter(
                Subscription.user_id == user.id, Subscription.status.in_(PAYABLE_STATUSES)
            ).order_by(Subscription.id.desc()).first()
            amount = Decimal(str(payer_subscription.price_amount or 0)) if payer_subscription else Decimal("0")
        else:
            amount = Decimal(str(subscriptions[0].price_amount or 0))
        owner_names = []
        for item in subscriptions:
            owner = db.query(User).filter(User.id == item.user_id).first()
            owner_names.append(_display_name(owner))
        item = PaymentRequest(
            subscription_id=subscriptions[0].id,
            subscription_ids=subscription_ids,
            payer_user_id=user.id,
            amount=amount,
            receipt_file_id=file_id,
        )
        db.add(item)
        db.flush()
        request_id = item.id
        chat_id = config["chat_id"]
        thread_id = config["topics"]["Заявки и Оплата"]
        db.commit()

    caption = (
        f"Оплата #{request_id}\n"
        f"От: {message.from_user.full_name} (@{message.from_user.username or '—'})\n"
        f"Сумма: {amount:f} ₽\n"
        f"Подписки: {', '.join(owner_names)[:500]}\n"
        f"Отправлено: {datetime.now(MOSCOW):%d.%m.%Y %H:%M} MSK\n"
        "Статус: ожидает подтверждения"
    )
    try:
        copied = await bot.copy_message(
            chat_id,
            message.chat.id,
            message.message_id,
            message_thread_id=thread_id,
            caption=caption,
            reply_markup=_review_keyboard(request_id),
        )
    except Exception:  # noqa: BLE001 - любая ошибка доставки = заявку не потеряем, но пометим
        logger.exception("Could not deliver receipt for payment request %s", request_id)
        with SessionLocal() as db:
            row = db.query(PaymentRequest).filter(PaymentRequest.id == request_id).first()
            if row and row.status == "pending":
                row.status = "delivery_failed"
                db.commit()
        await state.clear()
        _release_pending(telegram_id)
        await message.answer(
            "Не удалось передать чек администратору. Попробуйте позже или напишите в рабочий аккаунт.",
            reply_markup=menu_button(),
        )
        return
    with SessionLocal() as db:
        row = db.query(PaymentRequest).filter(PaymentRequest.id == request_id).first()
        if row:
            row.operator_chat_id = str(chat_id)
            row.operator_message_id = copied.message_id
            db.commit()

    await state.clear()
    finished = _release_pending(telegram_id)
    if finished and finished.message_id:
        try:  # чек уже отправлен - отменять заявку поздно
            await bot.edit_message_reply_markup(chat_id=finished.chat_id, message_id=finished.message_id, reply_markup=None)
        except TelegramAPIError:
            pass
    await message.answer(RECEIPT_ACCEPTED_TEXT)


# ------------------------------------------------- решения администратора

async def _edit_operator_message(query: CallbackQuery, text: str, reply_markup: InlineKeyboardMarkup | None) -> None:
    message = query.message
    if not message:
        return
    try:
        if message.text is not None:
            await message.edit_text(text, reply_markup=reply_markup)
        else:
            await message.edit_caption(caption=text[:1024], reply_markup=reply_markup)
    except TelegramAPIError:
        logger.exception("Could not edit operator message for %s", query.data)


def _current_text(query: CallbackQuery) -> str:
    message = query.message
    return (message.caption or message.text or "Оплата") if message else "Оплата"


def _request_id(query: CallbackQuery) -> int | None:
    try:
        return int((query.data or "").rsplit(":", 1)[1])
    except (ValueError, IndexError):
        return None


async def _admin_gate(query: CallbackQuery) -> int | None:
    if not query.from_user or not query.data:
        return None
    if not _is_admin(query.from_user.id):
        await query.answer("Только для администраторов", show_alert=True)
        return None
    request_id = _request_id(query)
    if request_id is None:
        await query.answer("Некорректная заявка", show_alert=True)
    return request_id


def _admin_name(db, telegram_id: int) -> tuple[User | None, str]:
    admin = db.query(User).filter(User.telegram_id == str(telegram_id)).first()
    return admin, _display_name(admin) if admin else "администратор"


@router.callback_query(lambda query: (query.data or "").startswith("payment:confirm:"))
async def confirm_payment(query: CallbackQuery) -> None:
    request_id = await _admin_gate(query)
    if request_id is None:
        return
    with SessionLocal() as db:
        item = db.query(PaymentRequest).filter(PaymentRequest.id == request_id).first()
        if not item or item.status != "pending":
            await query.answer("Заявка уже обработана", show_alert=True)
            return
        admin, admin_name = _admin_name(db, query.from_user.id)
        item.status = "confirmed"
        item.reviewed_by = admin.id if admin else None
        item.reviewed_at = datetime.now(timezone.utc)
        db.commit()
    await query.answer("Оплата подтверждена")
    await _edit_operator_message(
        query,
        _current_text(query).replace("Статус: ожидает подтверждения", "Статус: подтверждена")
        + f"\n\n✅ Подтвердил: {admin_name}\nВыберите действие:",
        _action_keyboard(request_id),
    )


@router.callback_query(lambda query: (query.data or "").startswith(("payment:reject:", "payment:decline:")))
async def reject_payment(query: CallbackQuery, bot: Bot) -> None:
    request_id = await _admin_gate(query)
    if request_id is None:
        return
    with SessionLocal() as db:
        item = db.query(PaymentRequest).filter(PaymentRequest.id == request_id).first()
        if not item or item.status != "pending":
            await query.answer("Заявка уже обработана", show_alert=True)
            return
        payer = db.query(User).filter(User.id == item.payer_user_id).first()
        admin, admin_name = _admin_name(db, query.from_user.id)
        item.status = "rejected"
        item.reviewed_by = admin.id if admin else None
        item.reviewed_at = datetime.now(timezone.utc)
        telegram_id = payer.telegram_id if payer else None
        silent = bool(payer and is_silent(payer, "payment_rejected"))
        db.commit()
    if telegram_id:
        try:
            await bot.send_message(
                telegram_id,
                "Оплата не засчитана. Если вы не знаете почему, обратитесь на рабочий аккаунт: " + support_url(),
                reply_markup=menu_button(),
                disable_notification=silent,
            )
        except TelegramAPIError:
            logger.exception("Could not notify payer about rejected payment %s", request_id)
    await query.answer("Оплата отклонена")
    await _edit_operator_message(
        query,
        _current_text(query).replace("Статус: ожидает подтверждения", "Статус: отклонена")
        + f"\n\n❌ Отклонил: {admin_name}\nИзменено: {datetime.now(MOSCOW):%d.%m.%Y %H:%M:%S} MSK",
        None,
    )


@router.callback_query(lambda query: (query.data or "").startswith("payment:extend:"))
async def extend_payment(query: CallbackQuery, bot: Bot) -> None:
    request_id = await _admin_gate(query)
    if request_id is None:
        return
    changes: list[tuple[str, datetime | None, datetime]] = []
    with SessionLocal() as db:
        item = db.query(PaymentRequest).filter(PaymentRequest.id == request_id).first()
        if not item or item.status != "confirmed":
            await query.answer("Заявка уже обработана", show_alert=True)
            return
        ids = item.subscription_ids if isinstance(item.subscription_ids, list) else [item.subscription_id]
        subscriptions = db.query(Subscription).filter(Subscription.id.in_(ids)).all()
        payer = db.query(User).filter(User.id == item.payer_user_id).first()
        if not subscriptions or len(subscriptions) != len(ids) or not payer:
            await query.answer("Связанные данные не найдены", show_alert=True)
            return
        now = datetime.now(timezone.utc)
        for subscription in subscriptions:
            old_until = subscription.access_until
            aware = old_until.replace(tzinfo=timezone.utc) if old_until and old_until.tzinfo is None else old_until
            base = aware if aware and aware > now else now
            subscription.access_until = add_calendar_month(base)
            subscription.status = "active"
            owner = db.query(User).filter(User.id == subscription.user_id).first()
            changes.append((_display_name(owner), old_until, subscription.access_until))
        item.status = "extended"
        next_payment = max(new for _, _, new in changes)
        payer_telegram_id = payer.telegram_id
        silent = is_silent(payer, "payment_confirmed")
        db.commit()
    if payer_telegram_id:
        try:
            await bot.send_message(
                payer_telegram_id,
                "Администратор подтвердил вашу оплату, спасибо большое 💜\n\n"
                f"Следующая оплата: {next_payment:%d.%m.%Y}",
                reply_markup=menu_button(),
                disable_notification=silent,
            )
        except TelegramAPIError:
            logger.exception("Could not notify payer about extended payment %s", request_id)
    if len(changes) == 1:
        diff = f"Было: {_fmt_date(changes[0][1])}\nСтало: {_fmt_date(changes[0][2])}"
    else:
        diff = "\n".join(f"{name}: было {_fmt_date(old)} -> стало {_fmt_date(new)}" for name, old, new in changes)
    base_text = _current_text(query).split("\nВыберите действие:")[0].rstrip()
    await query.answer("Подписка продлена")
    await _edit_operator_message(
        query, f'{base_text}\n\nВыбранное действие: "Продлить на месяц"\n{diff}', None
    )


@router.callback_query(lambda query: (query.data or "").startswith("payment:skip:"))
async def skip_payment(query: CallbackQuery) -> None:
    request_id = await _admin_gate(query)
    if request_id is None:
        return
    with SessionLocal() as db:
        item = db.query(PaymentRequest).filter(PaymentRequest.id == request_id).first()
        if not item or item.status != "confirmed":
            await query.answer("Заявка уже обработана", show_alert=True)
            return
        item.status = "skipped"
        db.commit()
    base_text = _current_text(query).split("\nВыберите действие:")[0].rstrip()
    await query.answer("Пропущено")
    await _edit_operator_message(query, f'{base_text}\n\nВыбранное действие: "Пропуск"', None)


@router.callback_query(lambda query: (query.data or "").startswith("payment:open:"))
async def open_payment_user(query: CallbackQuery) -> None:
    """Заглушка: позже здесь откроется карточка пользователя в mini app."""
    if not query.from_user or not _is_admin(query.from_user.id):
        await query.answer("Только для администраторов", show_alert=True)
        return
    await query.answer("Скоро: откроется карточка пользователя в mini app")


__all__ = ["router", "PaymentReceipt", "begin_payment_request", "_parse_payment_target"]
