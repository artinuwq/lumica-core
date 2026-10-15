from __future__ import annotations

import json
from typing import Any

from lumica.domain.models import Panel, PanelInbound
from lumica.integrations.xui_client import XUIClient
from .provider import PanelProvider


def _extract_clients_from_settings(protocol: str | None, settings: Any) -> list[dict]:
    payload = settings if isinstance(settings, dict) else {}
    protocol_raw = (protocol or "").strip().lower()
    normalized_protocol = "mixed" if protocol_raw in {"mixed", "http", "socks", "socks5"} else protocol_raw

    def _as_list(value):
        if isinstance(value, list):
            return value
        if isinstance(value, dict):
            return [value]
        if isinstance(value, str):
            try:
                parsed = json.loads(value)
            except ValueError:
                return []
            if isinstance(parsed, list):
                return parsed
            if isinstance(parsed, dict):
                return [parsed]
        return []

    source = [*_as_list(payload.get("clients")), *_as_list(payload.get("accounts"))]
    clients: list[dict] = []
    for item in source:
        if not isinstance(item, dict):
            continue
        identifier = item.get("id") or item.get("email") or item.get("username") or item.get("user")
        identifier = str(identifier).strip() if identifier is not None else ""
        if not identifier:
            continue
        label = item.get("email") or item.get("remark") or item.get("username") or item.get("user") or identifier
        secret = item.get("password") or item.get("pass")
        sub_id = item.get("subId") or item.get("subid")
        clients.append(
            {
                "identifier": identifier,
                "label": str(label),
                "secret": secret if isinstance(secret, str) else None,
                "sub_id": str(sub_id) if sub_id is not None else None,
                "protocol": normalized_protocol,
                "raw": item,
            }
        )
    return clients


def _api_object(payload: Any) -> Any:
    if isinstance(payload, dict):
        if "obj" in payload:
            return payload.get("obj")
        if "data" in payload:
            return payload.get("data")
    return payload


class XuiProvider(PanelProvider):
    provider_name = "3xui"

    def _client(self, panel: Panel, auth: dict) -> XUIClient:
        username = str(auth.get("username") or auth.get("login") or "").strip() or None
        password = str(auth.get("password") or "").strip() or None
        token = str(auth.get("token") or auth.get("api_token") or "").strip() or None
        if panel.auth_type == "api_token":
            if not token:
                raise RuntimeError("API token is required for this panel")
            return XUIClient(
                base_url=panel.base_url,
                token=token,
                token_header=str(auth.get("token_header") or "Authorization"),
                token_prefix=str(auth.get("token_prefix") or "Bearer"),
            )
        return XUIClient(base_url=panel.base_url, username=username, password=password)

    def health_check(self, panel: Panel, auth: dict) -> dict:
        client = self._client(panel, auth)
        inbounds = client.get_inbounds()
        return {
            "ok": True,
            "version": None,
            "inbounds_count": len(inbounds),
        }

    def monitoring_snapshot(self, panel: Panel, auth: dict) -> dict[str, Any]:
        client = self._client(panel, auth)
        try:
            status = _api_object(client.get_status())
        except Exception:
            status = None
        snapshot: dict[str, Any] = {"status": status}
        xray = status.get("xray") if isinstance(status, dict) else None
        snapshot["xray_version"] = xray.get("version") if isinstance(xray, dict) else None
        snapshot["panel_version"] = status.get("panelVersion") if isinstance(status, dict) else None
        for key, getter in (
            ("online_clients", client.get_online_clients),
            ("update_status", client.get_update_status),
            ("xray_observatory", client.get_xray_observatory),
        ):
            try:
                snapshot[key] = _api_object(getter())
            except Exception:
                snapshot[key] = None
        return snapshot

    def list_inbounds(self, panel: Panel, auth: dict) -> list[dict]:
        return self._client(panel, auth).get_inbounds()

    def list_clients(self, panel: Panel, inbound: PanelInbound, auth: dict) -> list[dict]:
        return _extract_clients_from_settings(inbound.protocol, inbound.settings)

    def create_client(self, panel: Panel, inbound: PanelInbound, payload: dict, auth: dict) -> dict:
        inbound_id = int(inbound.external_inbound_id)
        return self._client(panel, auth).add_client(inbound_id, payload)

    def update_client(self, panel: Panel, client_id: str, payload: dict, auth: dict) -> dict:
        inbound_id = payload.get("inbound_id")
        if inbound_id is None:
            raise RuntimeError("inbound_id is required for XUI update_client")
        enabled = bool(payload.get("enabled", False))
        ok = self._client(panel, auth).set_client_enabled(int(inbound_id), str(client_id), enabled)
        return {"ok": bool(ok)}

    def delete_client(self, panel: Panel, client_id: str, auth: dict) -> dict:
        # 3x-ui delete/disable requires inbound id, so client_id is encoded as "<inbound_id>:<identifier>".
        raw = str(client_id or "").strip()
        if ":" not in raw:
            raise RuntimeError("client_id must be '<inbound_id>:<identifier>' for XUI delete_client")
        inbound_part, identifier = raw.split(":", 1)
        ok = self._client(panel, auth).disable_client(int(inbound_part), identifier)
        return {"ok": bool(ok)}

