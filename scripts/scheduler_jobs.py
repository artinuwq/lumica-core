import os
import time

from backend.app import _bootstrap_multi_panel_state, _ensure_schema_compatibility
from backend.db import Base, SessionLocal, engine
from backend.expire_subscriptions import run as expire_subscriptions_run
from backend.panels import PanelRegistry, sync_all_panels
from backend.panels.service import sync_group_members_from_inbounds


def run_scheduler_forever() -> None:
    enabled = os.getenv("ENABLE_BACKGROUND_JOBS", "true").strip().lower() in {"1", "true", "yes", "on"}
    if not enabled:
        return

    sync_interval = max(30, int(os.getenv("PANEL_SYNC_INTERVAL_SEC", "300")))
    expire_interval = max(60, int(os.getenv("EXPIRE_SUBSCRIPTIONS_INTERVAL_SEC", "3600")))
    registry = PanelRegistry()
    next_sync = 0.0
    next_expire = 0.0

    Base.metadata.create_all(bind=engine)
    _ensure_schema_compatibility()

    while True:
        now = time.time()
        if now >= next_sync:
            try:
                with SessionLocal() as db:
                    _bootstrap_multi_panel_state(db)
                    sync_all_panels(db, registry)
                    sync_group_members_from_inbounds(db)
                    db.commit()
            except Exception:
                pass
            next_sync = now + sync_interval

        if now >= next_expire:
            try:
                expire_subscriptions_run()
            except Exception:
                pass
            next_expire = now + expire_interval

        time.sleep(3)

