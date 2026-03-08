import os
import sys
import threading

from lumica.api import create_app
from lumica.infra import ENV_FILE, load_dotenv
from lumica.jobs import run_scheduler_forever


def _run_server(app) -> None:
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


def run_web_server() -> None:
    load_dotenv(ENV_FILE)
    app = create_app()
    _run_server(app)


def main() -> None:
    load_dotenv(ENV_FILE)
    app = create_app()
    scheduler_thread = threading.Thread(target=run_scheduler_forever, daemon=True)
    scheduler_thread.start()
    _run_server(app)

