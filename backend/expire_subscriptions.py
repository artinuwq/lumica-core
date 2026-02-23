import os
from datetime import datetime, timezone

from .db import SessionLocal
from .models import Subscription, VpnAccount
from .xui_api import XUIClient


def utcnow():
    return datetime.now(timezone.utc)


def as_utc(value: datetime | None) -> datetime | None:
    if not value:
        return None
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


def run() -> int:
    changed = 0
    should_disable = os.getenv("DISABLE_CLIENTS_ON_EXPIRE", "true").strip().lower() in {"1", "true", "yes", "on"}
    xui = XUIClient() if should_disable else None

    with SessionLocal() as db:
        subs = (
            db.query(Subscription)
            .filter(Subscription.status == "active", Subscription.access_until.isnot(None))
            .all()
        )
        now = utcnow()

        for sub in subs:
            access_until = as_utc(sub.access_until)
            if not access_until or access_until >= now:
                continue

            sub.status = "expired"
            changed += 1

            if xui:
                accounts = (
                    db.query(VpnAccount)
                    .filter(VpnAccount.user_id == sub.user_id, VpnAccount.status == "active")
                    .all()
                )
                for account in accounts:
                    if account.panel_inbound_id and account.identifier:
                        xui.disable_client(account.panel_inbound_id, account.identifier)

        db.commit()

    return changed


if __name__ == "__main__":
    total = run()
    print(f"expired_subscriptions={total}")
