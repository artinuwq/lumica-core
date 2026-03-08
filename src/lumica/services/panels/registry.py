from __future__ import annotations

import base64
import hashlib
import json
import os
from datetime import datetime, timedelta, timezone
from typing import Any

from lumica.domain.models import Panel, PanelSecret
from .provider import PanelProvider
from .xui_provider import XuiProvider


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _as_utc(value: datetime | None) -> datetime | None:
    if not value:
        return None
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


def _xor_stream_crypt(raw: bytes, key_material: bytes, nonce: bytes) -> bytes:
    out = bytearray()
    counter = 0
    while len(out) < len(raw):
        block = hashlib.sha256(key_material + nonce + counter.to_bytes(4, "big")).digest()
        for item in block:
            if len(out) >= len(raw):
                break
            out.append(item)
        counter += 1
    return bytes(a ^ b for a, b in zip(raw, out))


def _key_material() -> bytes:
    raw = os.getenv("PANEL_SECRET_KEY", "").strip()
    if not raw:
        raw = os.getenv("SESSION_PEPPER", "lumica-default-panel-secret")
    return hashlib.sha256(raw.encode("utf-8")).digest()


def encrypt_payload(payload: dict[str, Any]) -> str:
    serialized = json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    nonce = os.urandom(16)
    encrypted = _xor_stream_crypt(serialized, _key_material(), nonce)
    return base64.urlsafe_b64encode(nonce + encrypted).decode("ascii")


def decrypt_payload(ciphertext: str) -> dict[str, Any]:
    blob = base64.urlsafe_b64decode((ciphertext or "").encode("ascii"))
    if len(blob) < 16:
        raise ValueError("Invalid secret payload")
    nonce = blob[:16]
    encrypted = blob[16:]
    decoded = _xor_stream_crypt(encrypted, _key_material(), nonce).decode("utf-8")
    payload = json.loads(decoded)
    return payload if isinstance(payload, dict) else {}


class _MarzbanProviderStub(PanelProvider):
    provider_name = "marzban"

    def _unsupported(self, *_args, **_kwargs):
        raise RuntimeError("Marzban provider is not implemented yet")

    health_check = _unsupported
    list_inbounds = _unsupported
    list_clients = _unsupported
    create_client = _unsupported
    update_client = _unsupported
    delete_client = _unsupported


class PanelRegistry:
    def __init__(self):
        self._providers: dict[str, PanelProvider] = {
            "3xui": XuiProvider(),
            "xui": XuiProvider(),
            "marzban": _MarzbanProviderStub(),
        }
        self._auth_cache: dict[str, tuple[datetime, dict[str, Any]]] = {}
        self._cache_ttl = int(os.getenv("PANEL_SESSION_TTL_SEC", "900"))

    def get_provider(self, provider_name: str) -> PanelProvider:
        key = str(provider_name or "").strip().lower()
        provider = self._providers.get(key)
        if not provider:
            raise RuntimeError(f"Unsupported panel provider: {provider_name}")
        return provider

    def get_active_panels(self, db) -> list[Panel]:
        return (
            db.query(Panel)
            .filter(Panel.is_active == 1)
            .order_by(Panel.created_at.asc())
            .all()
        )

    def invalidate_panel(self, panel_id: str) -> None:
        self._auth_cache.pop(str(panel_id), None)

    def get_auth_payload(self, db, panel: Panel) -> dict[str, Any]:
        panel_key = str(panel.id)
        cached = self._auth_cache.get(panel_key)
        now = _utcnow()
        if cached:
            expires_at, payload = cached
            if _as_utc(expires_at) and _as_utc(expires_at) > now:
                return payload

        secret = db.query(PanelSecret).filter(PanelSecret.id == panel.auth_secret_ref).first()
        if not secret:
            raise RuntimeError("Panel secret not found")
        payload = decrypt_payload(secret.ciphertext)
        self._auth_cache[panel_key] = (now + timedelta(seconds=max(self._cache_ttl, 30)), payload)
        return payload

    def health_check(self, db, panel: Panel) -> dict:
        provider = self.get_provider(panel.provider)
        try:
            auth = self.get_auth_payload(db, panel)
            payload = provider.health_check(panel, auth)
            panel.health_status = "green"
            panel.last_ok_at = _utcnow()
            panel.error_message = None
            return {"ok": True, **(payload if isinstance(payload, dict) else {})}
        except Exception as exc:
            self.invalidate_panel(panel.id)
            panel.health_status = "red"
            panel.error_message = str(exc)[:500]
            return {"ok": False, "error": str(exc)}
