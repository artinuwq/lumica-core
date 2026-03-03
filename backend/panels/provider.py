from __future__ import annotations

from typing import Protocol

from ..models import Panel, PanelInbound


class PanelProvider(Protocol):
    provider_name: str

    def health_check(self, panel: Panel, auth: dict) -> dict:
        ...

    def list_inbounds(self, panel: Panel, auth: dict) -> list[dict]:
        ...

    def list_clients(self, panel: Panel, inbound: PanelInbound, auth: dict) -> list[dict]:
        ...

    def create_client(self, panel: Panel, inbound: PanelInbound, payload: dict, auth: dict) -> dict:
        ...

    def update_client(self, panel: Panel, client_id: str, payload: dict, auth: dict) -> dict:
        ...

    def delete_client(self, panel: Panel, client_id: str, auth: dict) -> dict:
        ...

