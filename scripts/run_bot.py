import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
for path in (ROOT, SRC):
    raw = str(path)
    if raw not in sys.path:
        sys.path.insert(0, raw)

from lumica.runtime.bot import main  # noqa: E402


if __name__ == "__main__":
    main()
