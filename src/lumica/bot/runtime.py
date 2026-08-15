import asyncio
import os

from aiogram import Bot, Dispatcher

from .chatops import router as chatops_router
from .onboarding import router as onboarding_router
from .subscriptions import router as subscriptions_router


def register_handlers(dp: Dispatcher) -> None:
    # onboarding owns /start (registration + application FSM for new users)
    dp.include_router(onboarding_router)
    dp.include_router(subscriptions_router)
    dp.include_router(chatops_router)


async def start_bot():
    token = os.getenv("TELEGRAM_BOT_TOKEN", "")
    if not token:
        raise RuntimeError("TELEGRAM_BOT_TOKEN is not set")

    bot = Bot(token=token)
    dp = Dispatcher()
    register_handlers(dp)
    await dp.start_polling(bot)


if __name__ == "__main__":
    asyncio.run(start_bot())
