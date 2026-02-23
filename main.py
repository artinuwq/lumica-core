import argparse
import asyncio
import os
import threading
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent
ENV_FILE = BASE_DIR / ".env"


def load_dotenv(path: Path) -> None:
    if not path.is_file():
        return

    for line in path.read_text().splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue

        key, sep, value = stripped.partition("=")
        if sep != "=":
            continue

        key = key.strip()
        value = value.strip().strip('\'"')
        os.environ.setdefault(key, value)


load_dotenv(ENV_FILE)

from backend.app import create_app  # noqa: E402
from bot.bot import start_bot  # noqa: E402


def run_api():
    app = create_app()
    host = os.getenv("FLASK_HOST", "0.0.0.0")
    port = int(os.getenv("FLASK_PORT", "8000"))
    app.run(host=host, port=port, use_reloader=False)


async def run_both():
    flask_thread = threading.Thread(target=run_api, daemon=True)
    flask_thread.start()
    await start_bot()


def main():
    parser = argparse.ArgumentParser(description="Lumica core services")
    parser.add_argument(
        "service",
        nargs="?",
        choices=["api", "bot", "all"],
        default="all",
        help="Service to run (default: all)",
    )
    args = parser.parse_args()

    if args.service == "api":
        run_api()
    elif args.service == "bot":
        asyncio.run(start_bot())
    else:
        asyncio.run(run_both())


if __name__ == "__main__":
    main()
