import asyncio
import os

from aiogram import Bot, Dispatcher

from .chatops import resume_update_notice, router as chatops_router
from .menus import router as menus_router
from .onboarding import router as onboarding_router
from .payments import router as payments_router
from .subscriptions import router as subscriptions_router
from .workspace import router as workspace_router


def register_handlers(dp: Dispatcher) -> None:
    # onboarding owns /start (registration + application FSM for new users)
    dp.include_router(onboarding_router)
    dp.include_router(subscriptions_router)
    dp.include_router(chatops_router)
    dp.include_router(workspace_router)
    dp.include_router(menus_router)
    dp.include_router(payments_router)


async def start_bot():
    token = os.getenv("TELEGRAM_BOT_TOKEN", "")
    if not token:
        raise RuntimeError("TELEGRAM_BOT_TOKEN is not set")

    bot = Bot(token=token)
    dp = Dispatcher()
    register_handlers(dp)
    # Если бот перезапущен самим обновлением - дописываем итог в сообщение /update.
    resume_task = asyncio.create_task(resume_update_notice(bot))
    try:
        await dp.start_polling(bot)
    finally:
        resume_task.cancel()


if __name__ == "__main__":
    asyncio.run(start_bot())
