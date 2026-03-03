from __future__ import annotations

import json
from typing import Any

from ..models import Panel, PanelInbound
from ..xui_api import XUIClient
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


class XuiProvider(PanelProvider):
    provider_name = "3xui"

    def _client(self, panel: Panel, auth: dict) -> XUIClient:
        username = str(auth.get("username") or auth.get("login") or "").strip() or None
        password = str(auth.get("password") or "").strip() or None
        return XUIClient(base_url=panel.base_url, username=username, password=password)

    def health_check(self, panel: Panel, auth: dict) -> dict:
        client = self._client(panel, auth)
        inbounds = client.get_inbounds()
        return {
            "ok": True,
            "version": None,
            "inbounds_count": len(inbounds),
        }

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
        ok = self._client(panel, auth).disable_client(int(inbound_id), str(client_id))
        return {"ok": bool(ok)}

    def delete_client(self, panel: Panel, client_id: str, auth: dict) -> dict:
        # 3x-ui delete/disable requires inbound id, so client_id is encoded as "<inbound_id>:<identifier>".
        raw = str(client_id or "").strip()
        if ":" not in raw:
            raise RuntimeError("client_id must be '<inbound_id>:<identifier>' for XUI delete_client")
        inbound_part, identifier = raw.split(":", 1)
        ok = self._client(panel, auth).disable_client(int(inbound_part), identifier)
        return {"ok": bool(ok)}

