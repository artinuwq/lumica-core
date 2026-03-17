from datetime import datetime, timezone
from decimal import Decimal

from sqlalchemy import text

from lumica.infra.db import Base, SessionLocal, engine
from lumica.domain.models import (
    InboundGroupMember,
    PanelTemplate,
    Region,
    SubscriptionPlan,
    UserConnection,
    VpnAccount,
)
from lumica.services.panels import ensure_default_groups, protocol_to_group_key, sync_group_members_from_inbounds
from lumica.services.settings import SettingsManager


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _ensure_schema_compatibility() -> None:
    with engine.begin() as conn:
        cols = {row[1] for row in conn.exec_driver_sql("PRAGMA table_info(users)").fetchall()}
        if "role" not in cols:
            conn.execute(text("ALTER TABLE users ADD COLUMN role VARCHAR NOT NULL DEFAULT 'user'"))

        inbound_cols = {row[1] for row in conn.exec_driver_sql("PRAGMA table_info(inbounds)").fetchall()}
        if "show_in_app" not in inbound_cols:
            conn.execute(text("ALTER TABLE inbounds ADD COLUMN show_in_app INTEGER NOT NULL DEFAULT 1"))

        vpn_cols = {row[1] for row in conn.exec_driver_sql("PRAGMA table_info(vpn_accounts)").fetchall()}
        if "panel_inbound_ref_id" not in vpn_cols:
            conn.execute(text("ALTER TABLE vpn_accounts ADD COLUMN panel_inbound_ref_id INTEGER"))

        pending_cols = {row[1] for row in conn.exec_driver_sql("PRAGMA table_info(pending_bindings)").fetchall()}
        if "panel_inbound_ref_id" not in pending_cols:
            conn.execute(text("ALTER TABLE pending_bindings ADD COLUMN panel_inbound_ref_id INTEGER"))


def _bootstrap_multi_panel_state(db) -> None:
    manager = SettingsManager(db)
    schema_version = manager.get_value("schema.multi_panel.version", default=0)

    groups = ensure_default_groups(db)
    sync_group_members_from_inbounds(db)

    # Seed user_connections from active bindings.
    group_by_key = {item.key: item.id for item in groups.values()}
    existing_user_connections = {
        (row.user_id, row.group_id): row
        for row in db.query(UserConnection).all()
    }
    active_accounts = (
        db.query(VpnAccount)
        .filter(VpnAccount.status == "active")
        .order_by(VpnAccount.user_id.asc(), VpnAccount.id.desc())
        .all()
    )

    for account in active_accounts:
        group_key = protocol_to_group_key(account.protocol)
        if not group_key:
            continue
        group_id = group_by_key.get(group_key)
        if not group_id:
            continue
        pair = (account.user_id, group_id)
        if pair in existing_user_connections:
            continue

        inbound_ref_id = account.panel_inbound_ref_id
        if not inbound_ref_id:
            continue
        selected_member_id = None
        if inbound_ref_id:
            member = (
                db.query(InboundGroupMember)
                .filter(
                    InboundGroupMember.group_id == group_id,
                    InboundGroupMember.panel_inbound_id == int(inbound_ref_id),
                )
                .first()
            )
            if member:
                selected_member_id = member.id

        row = UserConnection(
            user_id=account.user_id,
            group_id=group_id,
            selected_member_id=selected_member_id,
            selection_strategy="manual",
        )
        db.add(row)
        db.flush()
        existing_user_connections[pair] = row

    if str(schema_version) != "2":
        manager.set_setting(
            "schema.multi_panel.version",
            2,
            description="Multi-panel schema/data bootstrap version (legacy compatibility removed)",
        )


def _seed_constructor_data(db) -> None:
    if not db.query(SubscriptionPlan.id).first():
        db.add_all(
            [
                SubscriptionPlan(
                    name="Starter",
                    is_active=1,
                    base_price=Decimal("9.99"),
                    meta_json={
                        "duration_months": 1,
                        "items": [
                            {
                                "code": "extra_connection",
                                "item_type": "addon",
                                "price": "2.00",
                                "title": "Extra connection",
                            }
                        ],
                    },
                )
            ]
        )

    if not db.query(Region.id).first():
        db.add_all(
            [
                Region(code="EU", name="Europe", is_active=1),
                Region(code="RU", name="Russia", is_active=1),
                Region(code="US", name="United States", is_active=1),
            ]
        )

    if not db.query(PanelTemplate.id).first():
        db.add_all(
            [
                PanelTemplate(
                    name="VLESS Default",
                    protocol="vless",
                    settings={},
                    apply_mode="only_auto",
                ),
                PanelTemplate(
                    name="Mixed Default",
                    protocol="mixed",
                    settings={},
                    apply_mode="only_auto",
                ),
            ]
        )


def bootstrap_runtime(*, with_multi_panel_state: bool = True) -> None:
    Base.metadata.create_all(bind=engine)
    _ensure_schema_compatibility()
    if not with_multi_panel_state:
        return
    with SessionLocal() as db:
        _bootstrap_multi_panel_state(db)
        _seed_constructor_data(db)
        db.commit()


__all__ = [
    "_bootstrap_multi_panel_state",
    "_ensure_schema_compatibility",
    "_seed_constructor_data",
    "bootstrap_runtime",
]
