"""Operator forum setup (/setup_group). Меню клиента - menus.py, оплата - payments.py."""

from __future__ import annotations

from zoneinfo import ZoneInfo

from aiogram import Bot, Router, types
from aiogram.filters import Command

from lumica.domain.models import AppSetting
from lumica.infra.db import SessionLocal
from lumica.services.roles import is_authorized, load_role_bindings

router = Router(name="workspace")
WORKSPACE_KEY = "telegram.operator_workspace"
TOPICS = ("🔴 События серверов", "👥 События пользователей", "📊 Мониторинг", "Заявки и Оплата")
MOSCOW = ZoneInfo("Europe/Moscow")


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
