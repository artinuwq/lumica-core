"""Первое знакомство с ботом: приветствие вместо обычного меню (только при самом первом /start)."""

from __future__ import annotations

from aiogram.types import InlineKeyboardButton, InlineKeyboardMarkup

from lumica.domain.models import AppSetting, User
from lumica.infra.db import SessionLocal

from .menus import STATE_ACTIVE, STATE_APPLICANT, STATE_NEW

WELCOMED_PREFIX = "bot.welcomed:"
BACKFILL_KEY = "bot.welcome_backfill_done"

_INTRO = "Привет! Это официальный (насколько возможно) бот Lumica 💜"
_SECTIONS = (
    "Что здесь есть:\n"
    "📋 Подписка — до какого числа она действует, а если вы администратор группы, то и кто в ней.\n"
    "💳 Оплатить — можно заранее, можно день в день: мы не кусаемся.\n"
    "🖥 Статус серверов — состояние серверов. Бот живёт отдельно от VPN-серверов, поэтому отвечает, "
    "даже если они недоступны.\n"
    "⚙️ Настройки — уведомления и всё остальное.\n\n"
    "Не очень разбираетесь? Загляните в «🌐 Центр Lumica»: там справка со всем, что может пригодиться."
)
_OUTRO = "Добро пожаловать! Здесь тихо, быстро и без лишних вопросов 🚀"

_FOUND = "🔎 Подписка найдена ✅ Вы с нами, всё под рукой."
_NOT_FOUND = (
    "🔎 Подписка не найдена 😔\n"
    "Простите! Если вы уже пользуетесь Lumica, оставьте заявку через «Регистрацию»: мы добавим связь. "
    "Подписка и оплата появятся в меню сразу после этого."
)
_APPLICANT = "🔎 Подписка пока не найдена, но ваша заявка уже у нас ✨ Статус можно посмотреть в меню."


def welcome_text(state: str) -> str:
    status = {STATE_ACTIVE: _FOUND, STATE_APPLICANT: _APPLICANT}.get(state, _NOT_FOUND)
    return f"{_INTRO}\n\n{status}\n\n{_SECTIONS}\n\n{_OUTRO}"


def welcome_keyboard(state: str) -> InlineKeyboardMarkup:
    menu = InlineKeyboardButton(text="Меню", callback_data="menu:back")
    if state == STATE_NEW:
        return InlineKeyboardMarkup(inline_keyboard=[[
            InlineKeyboardButton(text="📝 Регистрация", callback_data="menu:register"), menu,
        ]])
    return InlineKeyboardMarkup(inline_keyboard=[[menu]])


def is_welcomed(telegram_id) -> bool:
    with SessionLocal() as db:
        return db.query(AppSetting.key).filter(AppSetting.key == f"{WELCOMED_PREFIX}{telegram_id}").first() is not None


def mark_welcomed(telegram_id) -> None:
    key = f"{WELCOMED_PREFIX}{telegram_id}"
    with SessionLocal() as db:
        if db.query(AppSetting.key).filter(AppSetting.key == key).first() is None:
            db.add(AppSetting(key=key, value_json={"welcomed": True}, description="Бот поприветствовал пользователя"))
            db.commit()


def backfill_existing_users() -> int:
    """Один раз при запуске: тех, кто уже есть в системе, считаем знакомыми, чтобы приветствие
    получали только новые люди, а не все существующие клиенты после обновления."""
    with SessionLocal() as db:
        if db.query(AppSetting.key).filter(AppSetting.key == BACKFILL_KEY).first() is not None:
            return 0
        known = {key for (key,) in db.query(AppSetting.key).filter(AppSetting.key.like(f"{WELCOMED_PREFIX}%")).all()}
        added = 0
        for (telegram_id,) in db.query(User.telegram_id).filter(User.telegram_id.isnot(None)).all():
            key = f"{WELCOMED_PREFIX}{telegram_id}"
            if key not in known:
                db.add(AppSetting(key=key, value_json={"welcomed": True, "backfill": True}, description="Уже был в системе"))
                added += 1
        db.add(AppSetting(key=BACKFILL_KEY, value_json={"done": True}, description="Приветствие: существующие пользователи отмечены"))
        db.commit()
        return added


__all__ = [
    "welcome_text", "welcome_keyboard", "is_welcomed", "mark_welcomed", "backfill_existing_users",
]
