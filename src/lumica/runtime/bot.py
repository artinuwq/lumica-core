import asyncio

from lumica.bot import start_bot
from lumica.infra import ENV_FILE, load_dotenv
from lumica.infra.logging_setup import setup_logging


async def run_bot() -> None:
    await start_bot()


def main() -> None:
    load_dotenv(ENV_FILE)
    setup_logging()
    asyncio.run(run_bot())

