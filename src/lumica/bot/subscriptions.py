"""`/subscription` - то же, что кнопка «Подписка» в меню (см. menus.py)."""

from __future__ import annotations

from aiogram import Router, types
from aiogram.filters import Command

from .menus import send_subscription_info

router = Router(name="subscriptions")


@router.message(Command("subscription"))
async def cmd_subscription(message: types.Message) -> None:
    if message.from_user:
        await send_subscription_info(message, message.from_user)


__all__ = ["router"]
