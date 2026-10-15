"""Operator forum setup and the compact customer bot menu."""

from __future__ import annotations

import os
from datetime import datetime, timezone
from decimal import Decimal
from zoneinfo import ZoneInfo

from aiogram import Bot, Router, types
from aiogram.filters import Command
from aiogram.fsm.context import FSMContext
from aiogram.fsm.state import State, StatesGroup
from aiogram.types import CallbackQuery, InlineKeyboardButton, InlineKeyboardMarkup

from lumica.domain.models import AppSetting, Group, PaymentRequest, Subscription, User
from lumica.infra.db import SessionLocal
from lumica.services.payments import add_calendar_month
from lumica.services.roles import is_authorized, load_role_bindings

router = Router(name="workspace")
WORKSPACE_KEY = "telegram.operator_workspace"
TOPICS = ("🔴 События серверов", "👥 События пользователей", "📊 Мониторинг", "Заявки и Оплата")
MOSCOW = ZoneInfo("Europe/Moscow")


class PaymentReceipt(StatesGroup):
    waiting_for_file = State()


def user_menu() -> InlineKeyboardMarkup:
    return InlineKeyboardMarkup(inline_keyboard=[
        [InlineKeyboardButton(text="Подписка", callback_data="menu:subscription")],
        [
            InlineKeyboardButton(text="Рабочий аккаунт", url=os.getenv("SUPPORT_URL", "https://t.me/NovenWrk")),
            InlineKeyboardButton(text="Статус серверов", callback_data="menu:status"),
        ],
    ])


def _parse_payment_target(data: str) -> tuple[int, bool] | None:
    parts = (data or "").split(":")
    if len(parts) == 3 and parts[0] == "payment" and parts[1] in {"send", "send-group"}:
        try:
            return int(parts[2]), parts[1] == "send-group"
        except ValueError:
            return None
    return None


def _subscription_message(subscription: Subscription, title: str, *, hide_billing: bool = False) -> str:
    lines = [title, f"Статус: {subscription.status or '—'}"]
    if hide_billing:
        lines.append("Дату оплаты и стоимость семейной подписки видит только администратор группы.")
    else:
        until = subscription.access_until.strftime("%d.%m.%Y") if subscription.access_until else "не указано"
        lines.extend((f"До: {until}", f"Оплата: {subscription.price_amount or '—'}"))
    return "\n".join(lines)


@router.message(Command("setup_group"))
async def setup_group(message: types.Message, bot: Bot) -> None:
    if not message.from_user or not is_authorized(message.from_user.id, "admin", load_role_bindings()):
        await message.answer("Эта команда доступна администраторам.")
        return
    if message.chat.type != "supergroup" or not getattr(message.chat, "is_forum", False):
        await message.answer("Создайте супергруппу, включите темы, добавьте бота администратором и выполните /setup_group здесь.")
        return
    me = await bot.get_me()
    member = await bot.get_chat_member(message.chat.id, me.id)
    if member.status not in {"administrator", "creator"} or not getattr(member, "can_manage_topics", False):
        await message.answer("Боту нужно право «Управление темами».")
        return
    with SessionLocal() as db:
        row = db.query(AppSetting).filter(AppSetting.key == WORKSPACE_KEY).first()
        value = row.value_json if row and isinstance(row.value_json, dict) else {}
        topics = value.get("topics") if str(value.get("chat_id")) == str(message.chat.id) else {}
        topics = topics if isinstance(topics, dict) else {}
        for title in TOPICS:
            if title not in topics:
                topic = await bot.create_forum_topic(message.chat.id, name=title)
                topics[title] = topic.message_thread_id
        value = {"chat_id": str(message.chat.id), "topics": topics}
        if row:
            row.value_json = value
        else:
            db.add(AppSetting(key=WORKSPACE_KEY, value_json=value, description="Операторская супергруппа Telegram"))
        db.commit()
    await message.answer("Готово: темы созданы, настройки сохранены.")


@router.callback_query(lambda query: query.data == "menu:subscription")
async def subscription_menu(query: CallbackQuery) -> None:
    if not query.from_user:
        return
    with SessionLocal() as db:
        user = db.query(User).filter(User.telegram_id == str(query.from_user.id)).first()
        group = db.query(Group).filter(Group.id == user.group_id).first() if user and user.group_id else None
        is_group_admin = bool(group and group.admin_user_id == user.id)
        if is_group_admin:
            user_ids = [row.id for row in db.query(User.id).filter(User.group_id == group.id).all()]
            subscriptions = (
                db.query(Subscription)
                .filter(Subscription.user_id.in_(user_ids))
                .order_by(Subscription.user_id.asc(), Subscription.id.asc())
                .all()
            )
        else:
            subscriptions = (
                db.query(Subscription)
                .filter(Subscription.user_id == user.id)
                .order_by(Subscription.id.asc())
                .all()
                if user else []
            )
        if not subscriptions:
            messages = ["Подписок пока нет."]
        else:
            messages = []
            for item in subscriptions:
                owner = user if item.user_id == user.id else db.query(User).filter(User.id == item.user_id).first()
                owner_name = (owner.name or (f"@{owner.username}" if owner.username else None)) if owner else None
                title = f"Подписка №{item.id}"
                if is_group_admin:
                    title += f" · {owner_name or f'Пользователь #{item.user_id}'}"
                messages.append(_subscription_message(item, title, hide_billing=bool(group and not is_group_admin)))
    await query.answer()
    if query.message:
        for text in messages:
            await query.message.answer(text)


@router.callback_query(lambda query: query.data == "menu:status")
async def status_menu(query: CallbackQuery) -> None:
    await query.answer("Статус серверов доступен в Mini App.", show_alert=True)


@router.callback_query(lambda query: (query.data or "").startswith(("payment:send:", "payment:send-group:")))
async def request_receipt(query: CallbackQuery, state: FSMContext) -> None:
    if not query.from_user or not query.data:
        return
    target = _parse_payment_target(query.data)
    if not target:
        await query.answer("Некорректная подписка", show_alert=True)
        return
    target_id, is_group_payment = target
    with SessionLocal() as db:
        user = db.query(User).filter(User.telegram_id == str(query.from_user.id)).first()
        subscription_ids = []
        if is_group_payment:
            group = db.query(Group).filter(Group.id == target_id).first()
            if not user or not group or group.admin_user_id != user.id:
                await query.answer("Оплатить семейную подписку может только администратор группы", show_alert=True)
                return
            admin_due = db.query(Subscription).filter(
                Subscription.user_id == user.id,
                Subscription.status.in_(["active", "expiring"]),
                Subscription.billing_day == datetime.now(MOSCOW).day,
            ).first()
            if not admin_due:
                await query.answer("Сегодня не день оплаты семейной подписки", show_alert=True)
                return
            member_ids = [row.id for row in db.query(User.id).filter(User.group_id == group.id).all()]
            due_subscriptions = db.query(Subscription).filter(
                Subscription.user_id.in_(member_ids),
                Subscription.status.in_(["active", "expiring"]),
            ).all()
            subscription_ids = [item.id for item in due_subscriptions]
        else:
            subscription = db.query(Subscription).filter(
                Subscription.id == target_id,
                Subscription.user_id == user.id if user else False,
            ).first()
            group = db.query(Group).filter(Group.id == user.group_id).first() if user and user.group_id else None
            if group:
                await query.answer("Оплатить семейную подписку может только администратор группы", show_alert=True)
                return
            subscription_ids = [subscription.id] if subscription else []
    if not subscription_ids:
        await query.answer("Подписки к оплате не найдены", show_alert=True)
        return
    await state.set_state(PaymentReceipt.waiting_for_file)
    await state.update_data(subscription_ids=subscription_ids)
    await query.answer()
    if query.message:
        keyboard = InlineKeyboardMarkup(inline_keyboard=[[
            InlineKeyboardButton(text="Отмена", callback_data="payment:cancel"),
        ]])
        await query.message.answer("Пришлите фото перевода или документ с чеком.", reply_markup=keyboard)


@router.callback_query(lambda query: query.data == "payment:cancel")
async def cancel_receipt(query: CallbackQuery, state: FSMContext) -> None:
    await state.clear()
    await query.answer("Отправка чека отменена")
    if query.message:
        await query.message.edit_reply_markup(reply_markup=None)


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
        subscription = db.query(Subscription).filter(Subscription.id == subscription_id, Subscription.user_id == user.id).first() if user else None
        details = subscription.billing_details if subscription else None
    await query.answer()
    if query.message:
        await query.message.answer(details or "Реквизиты пока не настроены. Напишите в рабочий аккаунт.")


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
            Subscription.user_id == payer.id,
            Subscription.billing_day.isnot(None),
        ).order_by(Subscription.id.desc()).first()
        details = admin_subscription.billing_details if admin_subscription else None
    await query.answer()
    if query.message:
        await query.message.answer(details or "Реквизиты пока не настроены. Напишите в рабочий аккаунт.")


@router.message(PaymentReceipt.waiting_for_file)
async def receive_receipt(message: types.Message, state: FSMContext, bot: Bot) -> None:
    if not message.from_user:
        return
    file_id = message.photo[-1].file_id if message.photo else (message.document.file_id if message.document else None)
    if not file_id:
        await message.answer("Нужно отправить фото или документ. Для отмены используйте /start.")
        return
    data = await state.get_data()
    await state.clear()
    subscription_ids = data.get("subscription_ids") or ([data.get("subscription_id")] if data.get("subscription_id") else [])
    try:
        subscription_ids = list({int(value) for value in subscription_ids})
    except (TypeError, ValueError):
        subscription_ids = []
    with SessionLocal() as db:
        user = db.query(User).filter(User.telegram_id == str(message.from_user.id)).first()
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
            await message.answer("Не удалось передать чек. Обратитесь в рабочий аккаунт.")
            return
        if group:
            payer_subscription = db.query(Subscription).filter(
                Subscription.user_id == user.id,
                Subscription.status.in_(["active", "expiring"]),
                Subscription.billing_day == datetime.now(MOSCOW).day,
            ).order_by(Subscription.id.desc()).first()
            amount = Decimal(str(payer_subscription.price_amount or 0)) if payer_subscription else Decimal("0")
        else:
            amount = Decimal(str(subscriptions[0].price_amount or 0))
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
    keyboard = InlineKeyboardMarkup(inline_keyboard=[[
        InlineKeyboardButton(text="Подтвердить", callback_data=f"payment:confirm:{request_id}"),
        InlineKeyboardButton(text="Отказать", callback_data=f"payment:reject:{request_id}"),
    ]])
    try:
        await bot.copy_message(chat_id, message.chat.id, message.message_id, message_thread_id=thread_id)
        note = await bot.send_message(
            chat_id,
            f"Оплата #{request_id}\nОт: {message.from_user.full_name} (@{message.from_user.username or '—'})"
            f"\nОтправлено: {message.date:%d.%m.%Y %H:%M} UTC\nСтатус: ожидает подтверждения",
            message_thread_id=thread_id,
            reply_markup=keyboard,
        )
    except Exception:
        with SessionLocal() as db:
            item = db.query(PaymentRequest).filter(PaymentRequest.id == request_id).first()
            if item and item.status == "pending":
                item.status = "delivery_failed"
                db.commit()
        await message.answer("Не удалось передать чек администратору. Попробуйте позже или напишите в рабочий аккаунт.")
        return
    with SessionLocal() as db:
        item = db.query(PaymentRequest).filter(PaymentRequest.id == request_id).first()
        if item:
            item.operator_chat_id = str(chat_id)
            item.operator_message_id = note.message_id
            db.commit()
    await message.answer("Чек передан администратору. Ждём подтверждения.")


@router.callback_query(lambda query: (query.data or "").startswith("payment:confirm:"))
async def confirm_payment(query: CallbackQuery, bot: Bot) -> None:
    if not query.from_user or not query.data:
        return
    if not is_authorized(query.from_user.id, "admin", load_role_bindings()):
        await query.answer("Только для администраторов", show_alert=True)
        return
    try:
        request_id = int(query.data.rsplit(":", 1)[1])
    except ValueError:
        await query.answer("Некорректная заявка", show_alert=True)
        return
    with SessionLocal() as db:
        item = db.query(PaymentRequest).filter(PaymentRequest.id == request_id).first()
        if not item or item.status != "pending":
            await query.answer("Заявка уже обработана", show_alert=True)
            return
        subscription_ids = item.subscription_ids if isinstance(item.subscription_ids, list) else [item.subscription_id]
        subscriptions = db.query(Subscription).filter(Subscription.id.in_(subscription_ids)).all()
        user = db.query(User).filter(User.id == item.payer_user_id).first()
        if not subscriptions or len(subscriptions) != len(subscription_ids) or not user:
            await query.answer("Связанные данные не найдены", show_alert=True)
            return
        now = datetime.now(timezone.utc)
        for subscription in subscriptions:
            access_until = subscription.access_until
            if access_until and access_until.tzinfo is None:
                access_until = access_until.replace(tzinfo=timezone.utc)
            base = access_until if access_until and access_until > now else now
            subscription.access_until = add_calendar_month(base)
            subscription.status = "active"
        item.status = "confirmed"
        admin = db.query(User).filter(User.telegram_id == str(query.from_user.id)).first()
        item.reviewed_by = admin.id if admin else None
        item.reviewed_at = now
        admin_name = admin.name or (f"@{admin.username}" if admin and admin.username else None) if admin else None
        next_payment = max((item.access_until for item in subscriptions if item.access_until), default=now)
        db.commit()
        telegram_id = user.telegram_id
    if telegram_id:
        await bot.send_message(telegram_id, "Администратор подтвердил вашу оплату, спасибо большое 💜\n\nСледующая оплата: " + next_payment.strftime("%d.%m.%Y"))
    await query.answer("Оплата подтверждена")
    if query.message:
        await query.message.edit_text(
            (query.message.text or "Оплата")
            + f"\n\n✅ Подтверждено: {admin_name or 'администратор'}"
            + f"\nИзменено: {datetime.now(MOSCOW):%d.%m.%Y %H:%M:%S} MSK"
        )


@router.callback_query(lambda query: (query.data or "").startswith("payment:reject:"))
async def reject_payment(query: CallbackQuery, bot: Bot) -> None:
    if not query.from_user or not query.data:
        return
    if not is_authorized(query.from_user.id, "admin", load_role_bindings()):
        await query.answer("Только для администраторов", show_alert=True)
        return
    try:
        request_id = int(query.data.rsplit(":", 1)[1])
    except ValueError:
        await query.answer("Некорректная заявка", show_alert=True)
        return
    with SessionLocal() as db:
        item = db.query(PaymentRequest).filter(PaymentRequest.id == request_id).first()
        if not item or item.status != "pending":
            await query.answer("Заявка уже обработана", show_alert=True)
            return
        user = db.query(User).filter(User.id == item.payer_user_id).first()
        admin = db.query(User).filter(User.telegram_id == str(query.from_user.id)).first()
        item.status = "rejected"
        item.reviewed_by = admin.id if admin else None
        item.reviewed_at = datetime.now(timezone.utc)
        telegram_id = user.telegram_id if user else None
        admin_name = admin.name or (f"@{admin.username}" if admin and admin.username else None) if admin else None
        db.commit()
    if telegram_id:
        await bot.send_message(
            telegram_id,
            "Извините, администратор отклонил вашу оплату. Напишите на рабочий аккаунт для уточнений: @NovenWrk",
        )
    await query.answer("Оплата отклонена")
    if query.message:
        await query.message.edit_text(
            (query.message.text or "Оплата")
            + f"\n\n❌ Отклонено: {admin_name or 'администратор'}"
            + f"\nИзменено: {datetime.now(MOSCOW):%d.%m.%Y %H:%M:%S} MSK"
        )
