import os
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
ENV_FILE = ROOT / ".env"


def load_dotenv(path: Path = ENV_FILE) -> None:
    if not path.is_file():
        return

    for line in path.read_text(encoding="utf-8").splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue

        key, sep, value = stripped.partition("=")
        if sep != "=":
            continue

        key = key.strip()
        value = value.strip().strip("'\"")
        os.environ.setdefault(key, value)
