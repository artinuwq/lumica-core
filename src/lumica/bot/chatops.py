"""Chat-ops remote control: /status, /update, /restart, /config, /ping.

Thin wrapper over lumica.update.UpdateManager + lumica.update.env_config -
no update/config logic is duplicated here, matching the HTTP API in
lumica/api/routes/update.py.
"""

from __future__ import annotations

import asyncio
import json
import logging
from datetime import datetime, timedelta, timezone
from zoneinfo import ZoneInfo

from aiogram import Bot, Router, types
from aiogram.exceptions import TelegramAPIError
from aiogram.filters import Command
from aiogram.types import CallbackQuery, InlineKeyboardButton, InlineKeyboardMarkup

from lumica.infra.settings import ENV_FILE
from lumica.services.roles import is_authorized, load_role_bindings
from lumica.services.operator_events import SERVER_EVENTS_TOPIC, post_to_topic
from lumica.update import UpdateManager, provider as update_provider
from lumica.update.manifest import UpdateStatus
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
logger = logging.getLogger(__name__)

MOSCOW = ZoneInfo("Europe/Moscow")
NOTICE_FILE_NAME = ".update_notice.json"
NOTICE_WAIT_SECONDS = 20 * 60
NOTICE_POLL_SECONDS = 3

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


def _format_operation_time(raw) -> str:
    try:
        moment = datetime.fromisoformat(str(raw))
    except (TypeError, ValueError):
        return str(raw or "—")
    if moment.tzinfo is None:
        moment = moment.replace(tzinfo=timezone.utc)
    return moment.astimezone(MOSCOW).strftime("%Y-%m-%d %H:%M:%S")


def _last_operation_line(last: dict | None) -> str:
    if not last:
        return ""
    line = f"Последняя операция: {last.get('kind') or 'update'}, {_format_operation_time(last.get('finished_at'))}"
    return line if last.get("success") else line + " ❌"


def render_status_text(status: UpdateStatus, last: dict | None) -> str:
    last_line = _last_operation_line(last)
    if not status.local_sha:  # git/сеть недоступны - показываем причину как есть
        text = f"⚠️ {status.message}"
        return text + (f"\n\n{last_line}" if last_line else "")
    if status.up_to_date:
        text = "ℹ️ На данный момент установлена актуальная версия"
        if status.dirty:
            text += "\n⚠️ Есть локальные изменения отслеживаемых файлов"
        return text + (f"\n{last_line}" if last_line else "")
    parts = [
        "⛔️ Требуется обновление",
        f"Сейчас: {status.local_version}\nПоследняя: {status.remote_version}",
    ]
    if status.remote_subject:
        parts.append(f"Описание обновления: {status.remote_subject}")
    if status.dirty:
        parts.append("⚠️ Есть локальные изменения отслеживаемых файлов, обновление может не примениться.")
    if last_line:
        parts.append(last_line)
    return "\n\n".join(parts)


@router.message(Command("status"))
async def cmd_status(message: types.Message) -> None:
    if not _require_admin(message):
        await _deny(message)
        return
    manager = UpdateManager()
    status = await asyncio.to_thread(manager.check)
    await message.answer(render_status_text(status, manager.last_result()))


# --- /update: одно сообщение, которое обновляется по ходу дела -----------------

def _notice_path(manager: UpdateManager):
    return manager.state_dir / NOTICE_FILE_NAME


def _save_notice(manager: UpdateManager, notice: dict) -> None:
    try:
        manager.state_dir.mkdir(parents=True, exist_ok=True)
        _notice_path(manager).write_text(json.dumps(notice, ensure_ascii=False), encoding="utf-8")
    except OSError:
        logger.exception("Could not save update notice")


def _load_notice(manager: UpdateManager) -> dict | None:
    try:
        data = json.loads(_notice_path(manager).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    return data if isinstance(data, dict) and data.get("chat_id") and data.get("message_id") else None


def _clear_notice(manager: UpdateManager) -> None:
    try:
        _notice_path(manager).unlink(missing_ok=True)
    except OSError:
        pass


async def _edit_notice(bot: Bot, notice: dict, text: str) -> None:
    try:
        await bot.edit_message_text(text, chat_id=notice["chat_id"], message_id=notice["message_id"])
    except TelegramAPIError as exc:
        if "not modified" not in str(exc).lower():
            logger.warning("Could not edit update message: %s", exc)


def _finished_after(result: dict, started_at: str) -> bool:
    try:
        finished = datetime.fromisoformat(str(result.get("finished_at")))
        started = datetime.fromisoformat(str(started_at))
    except (TypeError, ValueError):
        return False
    if finished.tzinfo is None:
        finished = finished.replace(tzinfo=timezone.utc)
    if started.tzinfo is None:
        started = started.replace(tzinfo=timezone.utc)
    return finished >= started - timedelta(seconds=2)


def final_update_text(manager: UpdateManager, result: dict, notice: dict) -> str:
    if result.get("success"):
        previous = result.get("previous_sha")
        current = result.get("current_sha")
        before = update_provider.describe(manager.repo_dir, previous) if previous else notice.get("from_version")
        after = update_provider.describe(manager.repo_dir, current) if current else notice.get("to_version")
        return f"✅ Обновление успешно завершено\n{before} -> {after}"
    return f"❌ Обновление не удалось\n{result.get('message') or 'причина неизвестна'}"


async def _watch_update(bot: Bot, manager: UpdateManager, notice: dict) -> None:
    """Ждёт итог обновления и дописывает его в то же сообщение."""
    waited = 0
    while waited < NOTICE_WAIT_SECONDS:
        result = await asyncio.to_thread(manager.last_result)
        if result and result.get("kind") == "update" and _finished_after(result, notice.get("started_at", "")):
            text = await asyncio.to_thread(final_update_text, manager, result, notice)
            await _edit_notice(bot, notice, text)
            _clear_notice(manager)
            return
        await asyncio.sleep(NOTICE_POLL_SECONDS)
        waited += NOTICE_POLL_SECONDS
    await _edit_notice(bot, notice, "⚠️ Итог обновления не получен. Проверьте /status")
    _clear_notice(manager)


async def resume_update_notice(bot: Bot) -> None:
    """При старте бота: если его перезапустило обновление, показываем итог в старом сообщении."""
    manager = UpdateManager()
    notice = _load_notice(manager)
    if notice:
        await _watch_update(bot, manager, notice)


def _update_event_text(message: types.Message, status: UpdateStatus) -> str:
    user = message.from_user
    who = f"{user.full_name} (@{user.username or '—'}, ID {user.id})" if user else "—"
    lines = [
        "🔄 Запущено обновление",
        f"Кто: {who}",
        f"Ветка: {status.branch}",
        f"Было: {status.local_version}",
        f"Станет: {status.remote_version}",
    ]
    if status.remote_subject:
        lines.append(f"Описание: {status.remote_subject}")
    lines.append(f"Когда: {datetime.now(MOSCOW):%d.%m.%Y %H:%M:%S} MSK")
    return "\n".join(lines)


@router.message(Command("update"))
async def cmd_update(message: types.Message, bot: Bot) -> None:
    if not _require_admin(message):
        await _deny(message)
        return
    progress = await message.answer("⏳ Проверяю и применяю обновление...")
    notice = {
        "chat_id": progress.chat.id,
        "message_id": progress.message_id,
        "started_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
    }
    manager = UpdateManager()
    status = await asyncio.to_thread(manager.check)
    if not status.local_sha:
        await progress.edit_text(render_status_text(status, manager.last_result()))
        return
    if status.up_to_date:
        await progress.edit_text(render_status_text(status, manager.last_result()))
        return
    notice.update(from_version=status.local_version, to_version=status.remote_version)
    event_text = _update_event_text(message, status)
    # Рестарт убьёт этот процесс: запоминаем сообщение, чтобы новый бот дописал итог.
    _save_notice(manager, notice)
    background = manager.service.unit_exists(manager.service.update_unit)
    if not background:  # без отдельного юнита обновление идёт в этом процессе
        await asyncio.to_thread(post_to_topic, SERVER_EVENTS_TOPIC, event_text)
    result = await asyncio.to_thread(manager.apply_background)
    if not result.started:
        _clear_notice(manager)
        if result.success and not result.noop:
            await progress.edit_text(
                "✅ Обновление успешно завершено\n"
                f"{status.local_version} -> {status.remote_version}"
            )
        elif result.success:
            await progress.edit_text("ℹ️ На данный момент установлена актуальная версия")
        else:
            await progress.edit_text(f"❌ Обновление не удалось\n{result.message}")
        return
    await asyncio.to_thread(post_to_topic, SERVER_EVENTS_TOPIC, event_text)
    await progress.edit_text("⏳ Обновление запущено в фоне")
    asyncio.create_task(_watch_update(bot, manager, notice))


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


__all__ = ["router", "resume_update_notice", "render_status_text", "final_update_text"]
