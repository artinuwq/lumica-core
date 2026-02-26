import asyncio
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from scripts.env_loader import ENV_FILE, load_dotenv  # noqa: E402

# Load environment before importing modules that may depend on it.
load_dotenv(ENV_FILE)

from bot.bot import start_bot  # noqa: E402


def main() -> None:
    asyncio.run(start_bot())


if __name__ == "__main__":
    main()
