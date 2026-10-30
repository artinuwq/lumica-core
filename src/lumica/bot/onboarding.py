"""/start: первое знакомство (приветствие) и обычное меню для тех, кто уже знаком боту.

Регистрация (заявка) живёт в registration.py и запускается кнопкой «Регистрация» в меню,
а не навязывается при входе."""

from __future__ import annotations

from aiogram import Router, types
from aiogram.filters import CommandStart

from lumica.domain.models import User
from lumica.infra.db import SessionLocal
from lumica.services import user_provisioning
from lumica.services.roles import is_authorized, load_role_bindings, role_allows

from .menus import answer_main_menu, client_state
from .welcome import is_welcomed, mark_welcomed, welcome_keyboard, welcome_text

router = Router(name="onboarding")


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


def _has_admin_mini_app_access(user: User, telegram_id: int) -> bool:
    if role_allows(user.role, "admin"):
        return True
    return is_authorized(telegram_id, "admin", load_role_bindings())


@router.message(CommandStart())
async def cmd_start(message: types.Message) -> None:
    if not message.from_user:
        return
    tg_user = message.from_user
    user = _find_or_link_user(tg_user)
    is_admin = _has_admin_mini_app_access(user, tg_user.id) if user else is_authorized(
        tg_user.id, "admin", load_role_bindings()
    )
    if is_admin:
        await answer_main_menu(message, is_admin=True)
        return
    with SessionLocal() as db:
        state = client_state(db, tg_user.id)
    if is_welcomed(tg_user.id):
        await answer_main_menu(message, is_admin=False, state=state)
        return
    mark_welcomed(tg_user.id)  # приветствие показываем один раз - при самом первом входе
    await message.answer(welcome_text(state), reply_markup=welcome_keyboard(state))


__all__ = ["router"]
