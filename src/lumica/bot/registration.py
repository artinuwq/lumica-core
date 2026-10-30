"""Регистрация (заявка) в боте: имя -> что ещё нужно -> проверка -> «Готово».

Одно сообщение бота редактируется по ходу дела, а сообщения клиента удаляются, чтобы чат
не разрастался. Черновик хранится в БД, поэтому перезапуск бота его не теряет."""

from __future__ import annotations

import asyncio
import html
import logging
from dataclasses import dataclass

from aiogram import Bot, Router, types
from aiogram.exceptions import TelegramAPIError
from aiogram.types import CallbackQuery, InlineKeyboardButton, InlineKeyboardMarkup

from lumica.domain.models import AppSetting, Application, User
from lumica.infra.db import SessionLocal
from lumica.services import applications as application_service
from lumica.services import notifications

from .menus import (
    APPLICATION_OPEN_STATUSES, STATE_ACTIVE, STATE_APPLICANT, client_state, page_back_keyboard,
    show_main_menu_in_place,
)
from .onboarding import _display_name, _find_or_link_user

logger = logging.getLogger(__name__)
router = Router(name="registration")

DRAFT_PREFIX = "registration.draft:"
STEP_NAME, STEP_EXTRA, STEP_CONFIRM = "name", "extra", "confirm"
MAX_NAME = 120
MAX_EXTRA = 1000


@dataclass
class Draft:
    telegram_id: int
    chat_id: int
    message_id: int
    step: str = STEP_NAME
    full_name: str = ""
    extra: str = ""


def _key(telegram_id: int) -> str:
    return f"{DRAFT_PREFIX}{telegram_id}"


def load_draft(telegram_id: int) -> Draft | None:
    with SessionLocal() as db:
        row = db.query(AppSetting).filter(AppSetting.key == _key(telegram_id)).first()
        value = row.value_json if row and isinstance(row.value_json, dict) else None
    if not value:
        return None
    try:
        return Draft(
            telegram_id=telegram_id, chat_id=int(value["chat_id"]), message_id=int(value["message_id"]),
            step=str(value.get("step") or STEP_NAME), full_name=str(value.get("full_name") or ""),
            extra=str(value.get("extra") or ""),
        )
    except (KeyError, TypeError, ValueError):
        return None


def save_draft(draft: Draft) -> None:
    payload = {
        "chat_id": draft.chat_id, "message_id": draft.message_id, "step": draft.step,
        "full_name": draft.full_name, "extra": draft.extra,
    }
    with SessionLocal() as db:
        row = db.query(AppSetting).filter(AppSetting.key == _key(draft.telegram_id)).first()
        if row:
            row.value_json = payload
        else:
            db.add(AppSetting(key=_key(draft.telegram_id), value_json=payload, description="Черновик заявки"))
        db.commit()


def drop_draft(telegram_id: int) -> None:
    with SessionLocal() as db:
        row = db.query(AppSetting).filter(AppSetting.key == _key(telegram_id)).first()
        if row:
            db.delete(row)
            db.commit()


# ------------------------------------------------------------------ тексты и кнопки

def _btn(text: str, data: str) -> InlineKeyboardButton:
    return InlineKeyboardButton(text=text, callback_data=data)


def text_name() -> str:
    return "Регистрация | Новая заявка\n\nУкажите ФИО или хотя бы имя"


def text_extra(full_name: str) -> str:
    return (
        f"Регистрация | Заявка\nФИО: {html.escape(full_name)}\n\n"
        "Укажите, требуется ли ещё что-то кроме VPN. Внимание: ваше сообщение будет передано без изменений. "
        "Здесь можно написать, нужен ли прокси, какой-то конкретный сервер и т. п."
    )


def text_ready(full_name: str, extra: str) -> str:
    return (
        "Регистрация | Готовая заявка\n"
        f"ФИО: {html.escape(full_name)}\n"
        f"Дополнительная информация: {html.escape(extra) if extra else '—'}"
    )


def keyboard_for(step: str) -> InlineKeyboardMarkup:
    if step == STEP_NAME:
        return InlineKeyboardMarkup(inline_keyboard=[[_btn("Отмена", "reg:cancel")]])
    if step == STEP_EXTRA:
        return InlineKeyboardMarkup(inline_keyboard=[[_btn("Пропустить", "reg:skip"), _btn("Отмена", "reg:cancel")]])
    return InlineKeyboardMarkup(inline_keyboard=[[_btn("Отмена", "reg:cancel"), _btn("Готово", "reg:done")]])


def text_for(draft: Draft) -> str:
    if draft.step == STEP_NAME:
        return text_name()
    if draft.step == STEP_EXTRA:
        return text_extra(draft.full_name)
    return text_ready(draft.full_name, draft.extra)


async def _render(bot: Bot, draft: Draft) -> None:
    try:
        await bot.edit_message_text(
            text_for(draft), chat_id=draft.chat_id, message_id=draft.message_id,
            reply_markup=keyboard_for(draft.step), parse_mode="HTML",
        )
    except TelegramAPIError as exc:
        if "not modified" not in str(exc).lower():
            logger.warning("Could not edit registration message: %s", exc)


# ------------------------------------------------------------------ обработчики

@router.callback_query(lambda query: query.data == "menu:register")
async def start_registration(query: CallbackQuery, bot: Bot) -> None:
    if not query.from_user or not query.message:
        return
    with SessionLocal() as db:
        state = client_state(db, query.from_user.id)
    if state == STATE_ACTIVE:
        await query.answer("Подписка уже найдена, регистрация не нужна.", show_alert=True)
        return
    if state == STATE_APPLICANT:
        await query.answer("Заявка уже подана. Статус можно посмотреть в меню.", show_alert=True)
        return
    draft = Draft(
        telegram_id=query.from_user.id, chat_id=query.message.chat.id, message_id=query.message.message_id,
    )
    save_draft(draft)
    await query.answer()
    await _render(bot, draft)


@router.callback_query(lambda query: query.data == "reg:cancel")
async def cancel_registration(query: CallbackQuery) -> None:
    if query.from_user:
        drop_draft(query.from_user.id)
    await query.answer()
    await show_main_menu_in_place(query)


@router.callback_query(lambda query: query.data == "reg:skip")
async def skip_extra(query: CallbackQuery, bot: Bot) -> None:
    draft = load_draft(query.from_user.id) if query.from_user else None
    if draft is None or draft.step != STEP_EXTRA:
        await query.answer("Эта заявка уже закрыта. Откройте меню.", show_alert=True)
        return
    draft.step, draft.extra = STEP_CONFIRM, ""
    save_draft(draft)
    await query.answer()
    await _render(bot, draft)


def _has_registration_draft(message: types.Message) -> bool:
    if not message.from_user or getattr(getattr(message, "chat", None), "type", "private") != "private":
        return False
    if (message.text or "").startswith("/"):
        return False
    return load_draft(message.from_user.id) is not None


@router.message(_has_registration_draft)
async def collect_text(message: types.Message, bot: Bot) -> None:
    draft = load_draft(message.from_user.id)
    if draft is None:
        return
    text = (message.text or "").strip()
    try:
        await message.delete()  # сообщение клиента убираем, чат остаётся чистым
    except TelegramAPIError:
        pass
    if not text or draft.step == STEP_CONFIRM:
        return  # фото, стикеры и текст на шаге подтверждения игнорируем
    if draft.step == STEP_NAME:
        draft.full_name = text[:MAX_NAME]
        draft.step = STEP_EXTRA
    else:
        draft.extra = text[:MAX_EXTRA]
        draft.step = STEP_CONFIRM
    save_draft(draft)
    await _render(bot, draft)


@router.callback_query(lambda query: query.data == "reg:done")
async def finish_registration(query: CallbackQuery, bot: Bot) -> None:
    if not query.from_user:
        return
    draft = load_draft(query.from_user.id)
    if draft is None or draft.step != STEP_CONFIRM or not draft.full_name:
        await query.answer("Эта заявка уже закрыта. Откройте меню.", show_alert=True)
        return
    tg_user = query.from_user
    user = _find_or_link_user(tg_user)
    with SessionLocal() as db:
        if user is None:
            user = User(
                telegram_id=str(tg_user.id), username=tg_user.username,
                name=_display_name(tg_user) or None, status="unverified",
            )
            db.add(user)
            db.flush()
        else:
            user = db.query(User).filter(User.id == user.id).first()
        existing = (
            db.query(Application)
            .filter(Application.user_id == user.id, Application.status.in_(APPLICATION_OPEN_STATUSES))
            .first()
        )
        application = existing or application_service.create_application(
            db, user_id=user.id, full_name=draft.full_name, extra_info=draft.extra or None
        )
        db.commit()
        application_id = application.id
    drop_draft(tg_user.id)
    await query.answer("Заявка отправлена")
    try:
        await bot.edit_message_text(
            f"✅ Заявка №{application_id} отправлена\n\nМы сообщим о решении здесь, в боте. "
            "Статус заявки всегда можно посмотреть в меню.",
            chat_id=draft.chat_id, message_id=draft.message_id,
            reply_markup=page_back_keyboard("Меню"),
        )
    except TelegramAPIError:
        logger.warning("Could not confirm application %s to the user", application_id)
    if existing is None:
        username = f"@{tg_user.username}" if tg_user.username else "без username"
        note = (
            f"🆕 Новая заявка №{application_id}\nФИО: {draft.full_name}\nTelegram: {username}, ID {tg_user.id}\n"
            f"Сообщение: {draft.extra or '—'}\n\nОткройте «Админ → Заявки» в mini app."
        )
        try:
            await asyncio.to_thread(notifications.notify_admins, note)
        except Exception:  # noqa: BLE001 - заявка уже сохранена, уведомление вторично
            logger.exception("Could not notify admins about application %s", application_id)


__all__ = ["router", "load_draft", "save_draft", "drop_draft", "Draft"]
