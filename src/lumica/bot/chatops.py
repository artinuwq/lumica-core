"""Chat-ops remote control: /status, /update, /restart, /config, /ping.

Thin wrapper over lumica.update.UpdateManager + lumica.update.env_config -
no update/config logic is duplicated here, matching the HTTP API in
lumica/api/routes/update.py.
"""

from __future__ import annotations

from aiogram import Router, types
from aiogram.filters import Command
from aiogram.types import CallbackQuery, InlineKeyboardButton, InlineKeyboardMarkup

from lumica.infra.settings import ENV_FILE
from lumica.services.roles import is_authorized, load_role_bindings
from lumica.update import UpdateManager
from lumica.update.env_config import (
    REGISTRY,
    ConfigError,
    delete_env_value,
    get_spec,
    read_env_value,
    validate_value,
    write_env_value,
)

router = Router(name="chatops")

_RESTART_CONFIRM_PREFIX = "chatops:restart:"


def _require_admin(message: types.Message) -> bool:
    telegram_id = message.from_user.id if message.from_user else None
    if telegram_id is None:
        return False
    return is_authorized(telegram_id, "admin", load_role_bindings())


async def _deny(message: types.Message) -> None:
    await message.answer("⛔ Эта команда доступна только администраторам.")


@router.message(Command("ping"))
async def cmd_ping(message: types.Message) -> None:
    await message.answer("pong")


@router.message(Command("status"))
async def cmd_status(message: types.Message) -> None:
    if not _require_admin(message):
        await _deny(message)
        return
    status = UpdateManager().check()
    await message.answer(f"ℹ️ {status.message}")


@router.message(Command("update"))
async def cmd_update(message: types.Message) -> None:
    if not _require_admin(message):
        await _deny(message)
        return
    await message.answer("⏳ Проверяю и применяю обновление...")
    result = UpdateManager().apply()
    icon = "✅" if result.success else "❌"
    await message.answer(f"{icon} {result.message}")


@router.message(Command("restart"))
async def cmd_restart(message: types.Message) -> None:
    if not _require_admin(message):
        await _deny(message)
        return
    keyboard = InlineKeyboardMarkup(
        inline_keyboard=[
            [
                InlineKeyboardButton(text="Да, перезапустить", callback_data=f"{_RESTART_CONFIRM_PREFIX}yes"),
                InlineKeyboardButton(text="Отмена", callback_data=f"{_RESTART_CONFIRM_PREFIX}no"),
            ]
        ]
    )
    await message.answer("⚠️ Перезапустить сервис сейчас?", reply_markup=keyboard)


@router.callback_query(lambda c: c.data and c.data.startswith(_RESTART_CONFIRM_PREFIX))
async def cb_restart_confirm(callback: CallbackQuery) -> None:
    telegram_id = callback.from_user.id if callback.from_user else None
    if telegram_id is None or not is_authorized(telegram_id, "admin", load_role_bindings()):
        await callback.answer("Только для администраторов", show_alert=True)
        return

    choice = callback.data.removeprefix(_RESTART_CONFIRM_PREFIX)
    if choice != "yes":
        await callback.answer("Отменено")
        if callback.message:
            await callback.message.edit_text("Перезапуск отменён.")
        return

    await callback.answer("Перезапускаю...")
    if callback.message:
        await callback.message.edit_text("⏳ Перезапускаю сервис...")
    restarted, restart_message = UpdateManager().restart_service()
    icon = "✅" if restarted else "❌"
    if callback.message:
        await callback.message.answer(f"{icon} {restart_message}")


@router.message(Command("config"))
async def cmd_config(message: types.Message) -> None:
    if not _require_admin(message):
        await _deny(message)
        return

    parts = (message.text or "").split(maxsplit=3)
    # /config                       -> list keys
    # /config get KEY                -> read one
    # /config set KEY VALUE          -> write one
    # /config clear KEY              -> delete one
    if len(parts) == 1:
        lines = [f"• {spec.key} ({spec.kind}) - {spec.description}" for spec in REGISTRY.values()]
        await message.answer("Доступные настройки:\n" + "\n".join(lines))
        return

    action = parts[1].lower()

    if action == "get" and len(parts) >= 3:
        try:
            spec = get_spec(parts[2])
        except ConfigError as exc:
            await message.answer(f"❌ {exc}")
            return
        value = read_env_value(ENV_FILE, spec.key)
        await message.answer(f"{spec.key} = {value if value is not None else '(не задано)'}")
        return

    if action == "set" and len(parts) == 4:
        try:
            spec = get_spec(parts[2])
            value = validate_value(spec, parts[3])
        except ConfigError as exc:
            await message.answer(f"❌ {exc}")
            return
        write_env_value(ENV_FILE, spec.key, value)
        await message.answer(f"✅ {spec.key} обновлён")
        return

    if action == "clear" and len(parts) >= 3:
        try:
            spec = get_spec(parts[2])
        except ConfigError as exc:
            await message.answer(f"❌ {exc}")
            return
        removed = delete_env_value(ENV_FILE, spec.key)
        await message.answer("✅ значение очищено" if removed else "ключ и так не был задан")
        return

    await message.answer(
        "Использование:\n"
        "/config - список настроек\n"
        "/config get KEY\n"
        "/config set KEY VALUE\n"
        "/config clear KEY"
    )


__all__ = ["router"]
