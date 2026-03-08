import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
for path in (ROOT, SRC):
    raw = str(path)
    if raw not in sys.path:
        sys.path.insert(0, raw)

from lumica.infra import ENV_FILE, SessionLocal, bootstrap_runtime, load_dotenv  # noqa: E402
from lumica.services.panels import PanelRegistry, sync_all_panels, sync_group_members_from_inbounds  # noqa: E402

load_dotenv(ENV_FILE)


def main() -> int:
    bootstrap_runtime(with_multi_panel_state=True)

    registry = PanelRegistry()
    with SessionLocal() as db:
        result = sync_all_panels(db, registry)
        sync_group_members_from_inbounds(db)
        db.commit()
    print(json.dumps(result, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
