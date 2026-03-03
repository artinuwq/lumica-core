from __future__ import annotations

import json
from datetime import datetime, timezone

from ..models import InboundGroup, InboundGroupMember, Panel, PanelInbound
from .registry import PanelRegistry
from .xui_provider import _extract_clients_from_settings


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def protocol_to_group_key(protocol: str | None) -> str | None:
    value = (protocol or "").strip().lower()
    if value == "vless":
        return "vless"
    if value in {"mixed", "http", "socks", "socks5"}:
        return "socks5"
    return None


def extract_clients_from_panel_inbound(inbound: PanelInbound | None) -> list[dict]:
    if not inbound:
        return []
    return _extract_clients_from_settings(inbound.protocol, inbound.settings)


def _safe_dict(value) -> dict:
    if isinstance(value, dict):
        return value
    if isinstance(value, str):
        try:
            parsed = json.loads(value)
        except ValueError:
            return {}
        return parsed if isinstance(parsed, dict) else {}
    return {}


def ensure_default_groups(db) -> dict[str, InboundGroup]:
    expected = {
        "vless": "VLESS",
        "socks5": "SOCKS5",
    }
    out: dict[str, InboundGroup] = {}
    for key, title in expected.items():
        row = db.query(InboundGroup).filter(InboundGroup.key == key).first()
        if not row:
            row = InboundGroup(key=key, title=title, visible=1, sort=100 if key == "vless" else 200)
            db.add(row)
            db.flush()
        out[key] = row
    return out


def _upsert_panel_inbound(db, panel: Panel, item: dict) -> PanelInbound | None:
    external_id_raw = item.get("id")
    if external_id_raw in (None, ""):
        return None
    external_id = str(external_id_raw)
    row = (
        db.query(PanelInbound)
        .filter(
            PanelInbound.panel_id == panel.id,
            PanelInbound.external_inbound_id == external_id,
        )
        .first()
    )
    if not row:
        row = PanelInbound(
            panel_id=panel.id,
            external_inbound_id=external_id,
            show_in_app=1,
        )
        db.add(row)

    row.protocol = item.get("protocol")
    row.port = item.get("port")
    row.remark = item.get("remark")
    row.listen = item.get("listen")
    row.enabled = 1 if item.get("enable", True) else 0
    row.stream_settings = _safe_dict(item.get("streamSettings"))
    row.settings = _safe_dict(item.get("settings"))
    row.last_sync_at = utcnow()
    return row


def sync_single_panel(db, registry: PanelRegistry, panel: Panel) -> dict:
    provider = registry.get_provider(panel.provider)
    auth = registry.get_auth_payload(db, panel)
    items = provider.list_inbounds(panel, auth)
    seen_external_ids: set[str] = set()
    upserted = 0

    for item in items:
        row = _upsert_panel_inbound(db, panel, item)
        if not row:
            continue
        seen_external_ids.add(row.external_inbound_id)
        upserted += 1

    stale_rows = (
        db.query(PanelInbound)
        .filter(PanelInbound.panel_id == panel.id)
        .all()
    )
    stale_count = 0
    for stale in stale_rows:
        if stale.external_inbound_id in seen_external_ids:
            continue
        stale.enabled = 0
        stale.last_sync_at = utcnow()
        stale_count += 1

    ensure_default_groups(db)
    return {"ok": True, "upserted": upserted, "stale_disabled": stale_count}


def sync_all_panels(db, registry: PanelRegistry) -> dict:
    panels = registry.get_active_panels(db)
    result_rows: list[dict] = []
    total_upserted = 0
    total_stale = 0

    for panel in panels:
        try:
            row = sync_single_panel(db, registry, panel)
            panel.health_status = "green"
            panel.last_ok_at = utcnow()
            panel.error_message = None
            total_upserted += int(row.get("upserted", 0))
            total_stale += int(row.get("stale_disabled", 0))
            result_rows.append({"panel_id": panel.id, "ok": True, **row})
        except Exception as exc:
            registry.invalidate_panel(panel.id)
            panel.health_status = "red"
            panel.error_message = str(exc)[:500]
            result_rows.append({"panel_id": panel.id, "ok": False, "error": str(exc)})

    db.flush()
    return {
        "ok": True,
        "panels": result_rows,
        "upserted": total_upserted,
        "stale_disabled": total_stale,
    }


def sync_group_members_from_inbounds(db) -> int:
    groups = ensure_default_groups(db)
    group_by_key = {key: row.id for key, row in groups.items()}
    rows = db.query(PanelInbound).all()
    added = 0
    for inbound in rows:
        key = protocol_to_group_key(inbound.protocol)
        group_id = group_by_key.get(key or "")
        if not group_id:
            continue
        existing = (
            db.query(InboundGroupMember)
            .filter(
                InboundGroupMember.group_id == group_id,
                InboundGroupMember.panel_inbound_id == inbound.id,
            )
            .first()
        )
        if existing:
            continue
        db.add(
            InboundGroupMember(
                group_id=group_id,
                panel_inbound_id=inbound.id,
                label=inbound.remark,
                priority=100,
                is_active=1,
            )
        )
        added += 1
    return added
