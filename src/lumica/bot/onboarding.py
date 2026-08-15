"""Заявка для незарегистрированных пользователей: /start -> если юзера нет
в системе - короткий FSM-опрос (ФИО, нужен ли прокси кнопками Да/Нет) ->
создаётся Application. Если пользователь уже есть (в т.ч. заранее созданный
админом вручную - см. services/user_provisioning.py) - обычное приветствие."""

from __future__ import annotations

import os

from aiogram import Router, types
from aiogram.filters import CommandStart
from aiogram.fsm.context import FSMContext
from aiogram.fsm.state import State, StatesGroup
from aiogram.types import CallbackQuery, InlineKeyboardButton, InlineKeyboardMarkup, WebAppInfo

from lumica.domain.models import User
from lumica.infra.db import SessionLocal
from lumica.services import applications as application_service
from lumica.services import notifications
from lumica.services import user_provisioning

router = Router(name="onboarding")

_PROXY_CALLBACK_PREFIX = "app_proxy:"


class ApplicationForm(StatesGroup):
    full_name = State()
    needs_proxy = State()


def _webapp_keyboard() -> InlineKeyboardMarkup:
    webapp_url = os.getenv("WEBAPP_URL", "https://example.com")
    return InlineKeyboardMarkup(
        inline_keyboard=[[InlineKeyboardButton(text="Открыть mini app", web_app=WebAppInfo(url=webapp_url))]]
    )


def _proxy_keyboard() -> InlineKeyboardMarkup:
    return InlineKeyboardMarkup(
        inline_keyboard=[
            [
                InlineKeyboardButton(text="Да", callback_data=f"{_PROXY_CALLBACK_PREFIX}yes"),
                InlineKeyboardButton(text="Нет", callback_data=f"{_PROXY_CALLBACK_PREFIX}no"),
            ]
        ]
    )


def _display_name(tg_user: types.User) -> str:
    return " ".join(filter(None, [tg_user.first_name, tg_user.last_name])).strip()


def _find_or_link_user(tg_user: types.User) -> User | None:
    """Синхронный поиск: уже зарегистрирован по telegram_id, либо
    предсозданная админом запись по username - тогда линкуем и считаем
    существующим пользователем."""
    telegram_id = str(tg_user.id)
    with SessionLocal() as db:
        user = user_provisioning.find_by_telegram_id(db, telegram_id)
        if user:
            return user

        if tg_user.username:
            preprovisioned = user_provisioning.find_preprovisioned_by_username(db, tg_user.username)
            if preprovisioned:
                user_provisioning.link_telegram_identity(
                    db,
                    preprovisioned,
                    telegram_id=telegram_id,
                    username=tg_user.username,
                    name=_display_name(tg_user),
                )
                db.commit()
                db.refresh(preprovisioned)
                return preprovisioned
    return None


@router.message(CommandStart())
async def cmd_start(message: types.Message, state: FSMContext) -> None:
    await state.clear()
    if not message.from_user:
        return

    user = _find_or_link_user(message.from_user)
    if user:
        await message.answer(
            "Добро пожаловать в экосистему Lumica Services! \n"
            "Вы можете открыть Mini app по кнопке ниже.\n\n"
            "Команды:\n"
            "/subscription - ваша подписка\n"
            "/ping, /status, /update, /restart, /config (для администраторов)",
            reply_markup=_webapp_keyboard(),
        )
        return

    await state.set_state(ApplicationForm.full_name)
    await message.answer(
        "Здравствуйте! Похоже, вы обращаетесь впервые.\n\n"
        "Чтобы начать пользоваться Lumica, нужно оставить заявку.\n\n"
        "Укажите ваше полное ФИО:"
    )


@router.message(ApplicationForm.full_name)
async def application_collect_full_name(message: types.Message, state: FSMContext) -> None:
    full_name = (message.text or "").strip()
    if len(full_name.split()) < 2:
        await message.answer("Пожалуйста, укажите полностью имя и фамилию.")
        return

    await state.update_data(full_name=full_name)
    await state.set_state(ApplicationForm.needs_proxy)
    await message.answer(
        "Нужен ли вам прокси для Telegram?\n\n"
        "Прокси используется вместо VPN внутри самого Telegram. "
        "Если не уверены - выберите «Нет», это можно будет включить позже.",
        reply_markup=_proxy_keyboard(),
    )


@router.callback_query(ApplicationForm.needs_proxy, lambda c: (c.data or "").startswith(_PROXY_CALLBACK_PREFIX))
async def application_collect_proxy_choice(callback: CallbackQuery, state: FSMContext) -> None:
    if not callback.from_user or not callback.data:
        await callback.answer()
        return

    needs_proxy = callback.data.removeprefix(_PROXY_CALLBACK_PREFIX) == "yes"
    data = await state.get_data()
    full_name = (data.get("full_name") or "").strip()
    await state.clear()

    if not full_name:
        await callback.answer("Начните заново: /start", show_alert=True)
        return

    tg_user = callback.from_user
    telegram_id = str(tg_user.id)

    with SessionLocal() as db:
        user = user_provisioning.find_by_telegram_id(db, telegram_id)
        if not user:
            user = User(
                telegram_id=telegram_id,
                username=tg_user.username,
                name=_display_name(tg_user) or tg_user.username,
                role="user",
                status="unverified",
            )
            db.add(user)
            db.flush()

        application = application_service.create_application(
            db, user_id=user.id, full_name=full_name, needs_proxy=needs_proxy
        )
        db.commit()
        application_id = application.id

        proxy_text = "да" if needs_proxy else "нет"
        notifications.notify_admins(f"🆕 Новая заявка №{application_id}\nФИО: {full_name}\nПрокси: {proxy_text}")

    await callback.answer("Заявка отправлена")
    proxy_text = "да" if needs_proxy else "нет"
    if callback.message:
        await callback.message.edit_text(
            f"✅ Заявка №{application_id} принята.\n\nФИО: {full_name}\nПрокси: {proxy_text}\n\n"
            "Мы свяжемся с вами после рассмотрения."
        )


__all__ = ["router", "ApplicationForm"]
