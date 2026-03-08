"""Background scheduler loop."""

import os
import time

from lumica.infra.bootstrap import _bootstrap_multi_panel_state
from lumica.infra.bootstrap import bootstrap_runtime
from lumica.infra.db import SessionLocal
from lumica.jobs.expire_subscriptions import run_expire_subscriptions
from lumica.services.panels import PanelRegistry, sync_all_panels, sync_group_members_from_inbounds


def run_scheduler_forever() -> None:
    enabled = os.getenv("ENABLE_BACKGROUND_JOBS", "true").strip().lower() in {"1", "true", "yes", "on"}
    if not enabled:
        return

    sync_interval = max(30, int(os.getenv("PANEL_SYNC_INTERVAL_SEC", "300")))
    expire_interval = max(60, int(os.getenv("EXPIRE_SUBSCRIPTIONS_INTERVAL_SEC", "3600")))
    registry = PanelRegistry()
    next_sync = 0.0
    next_expire = 0.0

    bootstrap_runtime(with_multi_panel_state=True)

    while True:
        now = time.time()
        if now >= next_sync:
            try:
                with SessionLocal() as db:
                    _bootstrap_multi_panel_state(db)
                    result = sync_all_panels(db, registry)
                    if result.get("ok"):
                        sync_group_members_from_inbounds(db)
                    db.commit()
            except Exception:
                pass
            next_sync = now + sync_interval

        if now >= next_expire:
            try:
                run_expire_subscriptions()
            except Exception:
                pass
            next_expire = now + expire_interval

        time.sleep(3)


__all__ = ["run_scheduler_forever"]
