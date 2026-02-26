import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from scripts.env_loader import ENV_FILE, load_dotenv  # noqa: E402
from backend.app import create_app  # noqa: E402


def main() -> None:
    load_dotenv(ENV_FILE)
    app = create_app()
    host = os.getenv("FLASK_HOST", "0.0.0.0")
    port = int(os.getenv("FLASK_PORT", "8000"))
    app.run(host=host, port=port, use_reloader=False)


if __name__ == "__main__":
    main()
