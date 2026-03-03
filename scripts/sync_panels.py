import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from scripts.env_loader import ENV_FILE, load_dotenv  # noqa: E402

load_dotenv(ENV_FILE)

from backend.app import _bootstrap_multi_panel_state, _ensure_schema_compatibility  # noqa: E402
from backend.db import Base, SessionLocal, engine  # noqa: E402
from backend.panels import PanelRegistry, sync_all_panels  # noqa: E402
from backend.panels.service import sync_group_members_from_inbounds  # noqa: E402


def main() -> int:
    Base.metadata.create_all(bind=engine)
    _ensure_schema_compatibility()

    registry = PanelRegistry()
    with SessionLocal() as db:
        _bootstrap_multi_panel_state(db)
        result = sync_all_panels(db, registry)
        sync_group_members_from_inbounds(db)
        db.commit()
    print(json.dumps(result, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

