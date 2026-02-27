import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from scripts.env_loader import ENV_FILE, load_dotenv  # noqa: E402

# Load environment before importing modules that read it at import time.
load_dotenv(ENV_FILE)

from backend.app import create_app  # noqa: E402


def main() -> None:
    app = create_app()
    host = os.getenv("FLASK_HOST", "0.0.0.0")
    port = int(os.getenv("FLASK_PORT", "8000"))
    server = os.getenv("WEB_SERVER", "waitress").strip().lower()

    if server == "flask":
        app.run(host=host, port=port, use_reloader=False)
        return

    if server == "waitress":
        try:
            from waitress import serve
        except ImportError:
            print(
                "waitress is not installed, falling back to Flask dev server. "
                "Install with: pip install waitress",
                file=sys.stderr,
            )
            app.run(host=host, port=port, use_reloader=False)
            return

        threads = int(os.getenv("WEB_THREADS", "8"))
        serve(app, host=host, port=port, threads=threads)
        return

    raise ValueError(f"Unsupported WEB_SERVER={server!r}. Use 'waitress' or 'flask'.")


if __name__ == "__main__":
    main()
