"""Настройки уведомлений клиента: кнопка «Настройки» в меню бота.

Главный экран - список настроек. Нажатие открывает отдельный экран со статусом
настройки и кнопками «Назад» / «Включить|Выключить» (сообщение редактируется
на месте, новых сообщений не плодим).
"""

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

WARNING = (
    "⚠️ Настоятельно не рекомендуем отключать это уведомление: так легко пропустить важное."
)
SILENT_NOTE = "Если выключить, сообщение всё равно придёт, но без звука."

SECTION_DAY = "day"
SECTION_BEFORE = "before"
SECTION_PAYMENT = "payment"
SECTION_UPDATES = "updates"

MAIN_BUTTONS = (
    (SECTION_DAY, "Уведомление в день оплаты"),
    (SECTION_BEFORE, "Уведомление до"),
    (SECTION_PAYMENT, "Статус оплаты"),
    (SECTION_UPDATES, "Обновление подписки"),
)
# Какая настройка на каком экране.
SECTION_OF_KEY = {
    "remind_3d": SECTION_BEFORE,
    "payment_confirmed": SECTION_PAYMENT,
    "payment_rejected": SECTION_PAYMENT,
    "subscription_updates": SECTION_UPDATES,
}


def _state(enabled: bool) -> str:
    return "включено ✅" if enabled else "выключено ✖️"


def _back() -> list[InlineKeyboardButton]:
    return [InlineKeyboardButton(text="Назад", callback_data="settings:main")]


def render_main() -> tuple[str, InlineKeyboardMarkup]:
    rows = [[InlineKeyboardButton(text=title, callback_data=f"settings:open:{section}")] for section, title in MAIN_BUTTONS]
    rows.append([InlineKeyboardButton(text="Меню", callback_data="menu:main")])
    return "⚙️ Настройки уведомлений\n\nВыберите, что настроить.", InlineKeyboardMarkup(inline_keyboard=rows)


def _toggle_button(key: str, enabled: bool, label: str) -> InlineKeyboardButton:
    return InlineKeyboardButton(text=("Выключить" if enabled else "Включить") + label, callback_data=f"settings:toggle:{key}")


def render_section(section: str, settings: dict) -> tuple[str, InlineKeyboardMarkup]:
    if section == SECTION_DAY:
        hour = settings["expiry_hour"]
        text = (
            f"Уведомление в день оплаты: {hour}:00 (МСК)\n\n"
            "Это уведомление нельзя отключить, можно выбрать только время."
        )
        times = [
            InlineKeyboardButton(
                text=f"{'✅ ' if value == hour else ''}{value}:00", callback_data=f"settings:hour:{value}"
            )
            for value in EXPIRY_HOURS
        ]
        return text, InlineKeyboardMarkup(inline_keyboard=[_back(), times])

    if section == SECTION_BEFORE:
        enabled = settings["remind_3d"]
        text = (
            f"Уведомление до оплаты: {_state(enabled)}\n\n"
            "Если включить, напомним за 3 дня до срока оплаты, чтобы можно было оплатить заранее. "
            "Время отправки то же, что в уведомлении в день оплаты. Если выключено, не отправляем."
        )
        return text, InlineKeyboardMarkup(inline_keyboard=[_back() + [_toggle_button("remind_3d", enabled, "")]])

    if section == SECTION_PAYMENT:
        confirmed, rejected = settings["payment_confirmed"], settings["payment_rejected"]
        text = (
            "Уведомления о статусе оплаты\n\n"
            f"При подтверждении: {_state(confirmed)}\n"
            f"При отказе: {_state(rejected)}\n\n"
            f"{SILENT_NOTE}\n\n{WARNING}"
        )
        return text, InlineKeyboardMarkup(inline_keyboard=[
            _back(),
            [_toggle_button("payment_confirmed", confirmed, " при подтверждении")],
            [_toggle_button("payment_rejected", rejected, " при отказе")],
        ])

    if section == SECTION_UPDATES:
        enabled = settings["subscription_updates"]
        text = (
            f"Уведомление об обновлении подписки: {_state(enabled)}\n\n"
            f"{SILENT_NOTE}\n\n{WARNING}"
        )
        return text, InlineKeyboardMarkup(inline_keyboard=[
            _back() + [_toggle_button("subscription_updates", enabled, "")]
        ])

    return render_main()


async def _show(query: CallbackQuery, text: str, markup: InlineKeyboardMarkup, *, edit: bool) -> None:
    if not query.message:
        return
    if not edit:
        await query.message.answer(text, reply_markup=markup)
        return
    try:
        await query.message.edit_text(text, reply_markup=markup)
    except TelegramAPIError as exc:
        if "not modified" not in str(exc).lower():
            logger.warning("Could not edit settings message: %s", exc)


@router.callback_query(lambda query: query.data == "menu:settings")
async def open_settings(query: CallbackQuery) -> None:
    if not query.from_user:
        return
    with SessionLocal() as db:
        exists = db.query(User.id).filter(User.telegram_id == str(query.from_user.id)).first() is not None
    if not exists:
        await query.answer("Сначала отправьте /start, чтобы оставить заявку.", show_alert=True)
        return
    await query.answer()
    text, markup = render_main()
    await _show(query, text, markup, edit=False)


@router.callback_query(lambda query: (query.data or "").startswith("settings:"))
async def settings_action(query: CallbackQuery) -> None:
    if not query.from_user or not query.data:
        return
    parts = query.data.split(":")
    action = parts[1] if len(parts) > 1 else ""
    with SessionLocal() as db:
        user = db.query(User).filter(User.telegram_id == str(query.from_user.id)).first()
        if not user:
            await query.answer("Пользователь не найден", show_alert=True)
            return
        if action == "main":
            text, markup = render_main()
            await query.answer()
            await _show(query, text, markup, edit=True)
            return
        section = None
        try:
            if action == "open" and len(parts) == 3 and parts[2] in {key for key, _ in MAIN_BUTTONS}:
                section = parts[2]
            elif action == "hour" and len(parts) == 3:
                update_settings(user, expiry_hour=int(parts[2]))
                section = SECTION_DAY
            elif action == "toggle" and len(parts) == 3 and parts[2] in TOGGLE_DEFAULTS:
                update_settings(user, **{parts[2]: not get_settings(user)[parts[2]]})
                section = SECTION_OF_KEY[parts[2]]
        except ValueError:
            section = None
        if section is None:
            await query.answer("Неизвестная настройка", show_alert=True)
            return
        db.commit()
        settings = get_settings(user)
    await query.answer("Сохранено" if action in {"hour", "toggle"} else None)
    text, markup = render_section(section, settings)
    await _show(query, text, markup, edit=True)


__all__ = ["router", "render_main", "render_section"]
