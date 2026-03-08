import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
for path in (ROOT, SRC):
    raw = str(path)
    if raw not in sys.path:
        sys.path.insert(0, raw)

from lumica.jobs.scheduler import run_scheduler_forever  # noqa: E402


__all__ = ["run_scheduler_forever"]
