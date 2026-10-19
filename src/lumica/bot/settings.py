"""Настройки уведомлений клиента: кнопка «Настройки» в меню бота."""

from __future__ import annotations

import logging

from aiogram import Router
from aiogram.exceptions import TelegramAPIError
from aiogram.types import CallbackQuery, InlineKeyboardButton, InlineKeyboardMarkup

from lumica.domain.models import User
from lumica.infra.db import SessionLocal
from lumica.services.notification_settings import EXPIRY_HOURS, TOGGLE_DEFAULTS, get_settings, update_settings

logger = logging.getLogger(__name__)
router = Router(name="settings")

TOGGLE_TITLES = {
    "remind_3d": "За 3 дня до окончания",
    "payment_confirmed": "Подтверждение оплаты",
    "payment_rejected": "Отказ в оплате",
    "subscription_updates": "Обновления подписки",
}
WARNING = (
    "⚠️ Настоятельно не рекомендуем отключать уведомления об оплате и обновлениях подписки: "
    "так легко пропустить важное."
)


def _mark(enabled: bool) -> str:
    return "✅" if enabled else "✖️"


def render_settings(settings: dict) -> tuple[str, InlineKeyboardMarkup]:
    hour = settings["expiry_hour"]
    lines = [
        "⚙️ Настройки уведомлений",
        "",
        f"🔔 В день окончания подписки: {hour}:00 (МСК). Это уведомление нельзя отключить, "
        "можно выбрать только время.",
    ]
    for key, title in TOGGLE_TITLES.items():
        state = "включено" if settings[key] else "выключено"
        lines.append(f"{_mark(settings[key])} {title}: {state}")
    lines += [
        "",
        "Выключенные уведомления об оплате и обновлениях подписки приходят без звука. "
        "Напоминание за 3 дня при выключении не отправляется.",
        "",
        WARNING,
    ]
    time_row = [
        InlineKeyboardButton(
            text=f"{'✅ ' if value == hour else ''}{value}:00", callback_data=f"settings:hour:{value}"
        )
        for value in EXPIRY_HOURS
    ]
    rows = [time_row] + [
        [InlineKeyboardButton(text=f"{_mark(settings[key])} {title}", callback_data=f"settings:toggle:{key}")]
        for key, title in TOGGLE_TITLES.items()
    ]
    rows.append([InlineKeyboardButton(text="Меню", callback_data="menu:main")])
    return "\n".join(lines), InlineKeyboardMarkup(inline_keyboard=rows)


async def _show(query: CallbackQuery, settings: dict, *, edit: bool) -> None:
    text, markup = render_settings(settings)
    if not query.message:
        return
    if edit:
        try:
            await query.message.edit_text(text, reply_markup=markup)
        except TelegramAPIError as exc:
            if "not modified" not in str(exc).lower():
                logger.warning("Could not edit settings message: %s", exc)
    else:
        await query.message.answer(text, reply_markup=markup)


@router.callback_query(lambda query: query.data == "menu:settings")
async def open_settings(query: CallbackQuery) -> None:
    if not query.from_user:
        return
    with SessionLocal() as db:
        user = db.query(User).filter(User.telegram_id == str(query.from_user.id)).first()
        settings = get_settings(user) if user else None
    if settings is None:
        await query.answer("Сначала отправьте /start, чтобы оставить заявку.", show_alert=True)
        return
    await query.answer()
    await _show(query, settings, edit=False)


@router.callback_query(lambda query: (query.data or "").startswith("settings:"))
async def change_setting(query: CallbackQuery) -> None:
    if not query.from_user or not query.data:
        return
    parts = query.data.split(":")
    with SessionLocal() as db:
        user = db.query(User).filter(User.telegram_id == str(query.from_user.id)).first()
        if not user:
            await query.answer("Пользователь не найден", show_alert=True)
            return
        try:
            if len(parts) == 3 and parts[1] == "hour":
                settings = update_settings(user, expiry_hour=int(parts[2]))
            elif len(parts) == 3 and parts[1] == "toggle" and parts[2] in TOGGLE_DEFAULTS:
                settings = update_settings(user, **{parts[2]: not get_settings(user)[parts[2]]})
            else:
                await query.answer("Неизвестная настройка", show_alert=True)
                return
        except ValueError:
            await query.answer("Недопустимое значение", show_alert=True)
            return
        db.commit()
    await query.answer("Сохранено")
    await _show(query, settings, edit=True)


__all__ = ["router", "render_settings"]
