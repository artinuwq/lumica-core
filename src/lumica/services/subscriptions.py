import os
from datetime import datetime, timezone

from lumica.infra.db import SessionLocal
from lumica.domain.models import Panel, PanelInbound, Subscription, VpnAccount
from lumica.services.panels import PanelRegistry


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
    registry = PanelRegistry() if should_disable else None

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

            if should_disable and registry:
                accounts = (
                    db.query(VpnAccount)
                    .filter(VpnAccount.user_id == sub.user_id, VpnAccount.status == "active")
                    .all()
                )
                for account in accounts:
                    if not account.identifier or not account.panel_inbound_ref_id:
                        continue
                    inbound = db.query(PanelInbound).filter(PanelInbound.id == account.panel_inbound_ref_id).first()
                    if not inbound:
                        continue
                    panel = db.query(Panel).filter(Panel.id == inbound.panel_id).first()
                    if not panel:
                        continue
                    try:
                        provider = registry.get_provider(panel.provider)
                        auth_payload = registry.get_auth_payload(db, panel)
                        provider.update_client(
                            panel,
                            account.identifier,
                            {"inbound_id": int(inbound.external_inbound_id), "enable": False},
                            auth_payload,
                        )
                    except Exception:
                        continue

        db.commit()

    return changed


def expire_subscriptions() -> int:
    return run()


if __name__ == "__main__":
    total = run()
    print(f"expired_subscriptions={total}")


__all__ = ["as_utc", "expire_subscriptions", "run", "utcnow"]
