import asyncio
import os
import sys
import threading
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from main import ENV_FILE, load_dotenv  # noqa: E402
from backend.app import create_app  # noqa: E402
from bot.bot import start_bot  # noqa: E402


def run_web() -> None:
    app = create_app()
    host = os.getenv("FLASK_HOST", "0.0.0.0")
    port = int(os.getenv("FLASK_PORT", "8000"))
    app.run(host=host, port=port, use_reloader=False)


async def main() -> None:
    load_dotenv(ENV_FILE)
    web_thread = threading.Thread(target=run_web, daemon=True)
    web_thread.start()
    await start_bot()


if __name__ == "__main__":
    asyncio.run(main())
