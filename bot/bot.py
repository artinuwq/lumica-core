import asyncio
import os

from aiogram import Bot, Dispatcher, types
from aiogram.filters import CommandStart
from aiogram.types import InlineKeyboardButton, InlineKeyboardMarkup, WebAppInfo


def build_keyboard():
    webapp_url = os.getenv("WEBAPP_URL", "https://example.com")
    return InlineKeyboardMarkup(
        inline_keyboard=[[InlineKeyboardButton(text="Открыть mini app", web_app=WebAppInfo(url=webapp_url))]]
    )


async def handle_start(message: types.Message) -> None:
    await message.answer(
        "Добро пожаловать! Откройте mini app для управления сервисом.",
        reply_markup=build_keyboard(),
    )


def register_handlers(dp: Dispatcher) -> None:
    dp.message(CommandStart())(handle_start)


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
