from __future__ import annotations

import base64
import hashlib
import json
import os
from datetime import datetime, timedelta, timezone
from typing import Any

from cryptography.fernet import Fernet, InvalidToken

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


def _fernet(raw: str) -> Fernet:
    key = base64.urlsafe_b64encode(hashlib.sha256(raw.encode("utf-8")).digest())
    return Fernet(key)


def _configured_secret_keys() -> list[str]:
    keys = [
        os.getenv("PANEL_SECRET_KEY", "").strip(),
        os.getenv("SESSION_PEPPER", "").strip(),
    ]
    return list(dict.fromkeys(key for key in keys if key))


def encrypt_payload(payload: dict[str, Any]) -> str:
    keys = _configured_secret_keys()
    if not keys:
        raise RuntimeError("PANEL_SECRET_KEY must be configured before storing panel credentials")
    serialized = json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    return "fernet:" + _fernet(keys[0]).encrypt(serialized).decode("ascii")


def decrypt_payload(ciphertext: str) -> dict[str, Any]:
    raw = (ciphertext or "").strip()
    if raw.startswith("fernet:"):
        token = raw.removeprefix("fernet:").encode("ascii")
        for key in _configured_secret_keys():
            try:
                payload = json.loads(_fernet(key).decrypt(token).decode("utf-8"))
                return payload if isinstance(payload, dict) else {}
            except (InvalidToken, UnicodeDecodeError, json.JSONDecodeError):
                continue
        raise ValueError("Unable to decrypt panel credentials with configured keys")

    # Existing installations used this unauthenticated format; keep it read-only
    # during migration while all newly stored credentials use Fernet.
    try:
        blob = base64.urlsafe_b64decode(raw.encode("ascii"))
    except (ValueError, UnicodeEncodeError) as exc:
        raise ValueError("Invalid secret payload") from exc
    if len(blob) < 16:
        raise ValueError("Invalid secret payload")
    nonce, encrypted = blob[:16], blob[16:]
    legacy_keys = [*_configured_secret_keys(), "lumica-default-panel-secret"]
    for key in dict.fromkeys(legacy_keys):
        decoded = _xor_stream_crypt(encrypted, hashlib.sha256(key.encode("utf-8")).digest(), nonce)
        try:
            payload = json.loads(decoded.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            continue
        return payload if isinstance(payload, dict) else {}
    raise ValueError("Unable to decrypt legacy panel credentials")


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
