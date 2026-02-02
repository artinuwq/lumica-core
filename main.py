import argparse
import asyncio
import os

from backend.app import create_app
from bot.bot import start_bot


def main():
    parser = argparse.ArgumentParser(description="Lumica core services")
    parser.add_argument("service", choices=["api", "bot"], help="Service to run")
    args = parser.parse_args()

    if args.service == "api":
        app = create_app()
        host = os.getenv("FLASK_HOST", "0.0.0.0")
        port = int(os.getenv("FLASK_PORT", "8000"))
        app.run(host=host, port=port)
    else:
        asyncio.run(start_bot())


if __name__ == "__main__":
    main()
