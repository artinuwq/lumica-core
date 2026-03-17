import asyncio
import sys
import threading
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
for path in (ROOT, SRC):
    raw = str(path)
    if raw not in sys.path:
        sys.path.insert(0, raw)

from lumica.bot import start_bot  # noqa: E402
from lumica.infra import ENV_FILE, load_dotenv  # noqa: E402
from lumica.jobs import run_scheduler_forever  # noqa: E402
from lumica.infra.db import ensure_db_schema  # noqa: E402

# Load environment before importing modules that read it at import time.
load_dotenv(ENV_FILE)

from lumica.runtime.external_bots import main as run_external_bots  # noqa: E402
from lumica.runtime.web import run_web_server  # noqa: E402


def run_web() -> None:
    run_web_server()


async def main() -> None:
    # Ensure migrations applied before any workers start
    ensure_db_schema()

    web_thread = threading.Thread(target=run_web, daemon=True)
    scheduler_thread = threading.Thread(target=run_scheduler_forever, daemon=True)
    external_bots_thread = threading.Thread(target=run_external_bots, daemon=True)
    web_thread.start()
    scheduler_thread.start()
    external_bots_thread.start()
    await start_bot()


if __name__ == "__main__":
    asyncio.run(main())
