import base64
import hashlib
import json

from lumica.services.panels.registry import _xor_stream_crypt, decrypt_payload, encrypt_payload


def test_new_panel_secret_uses_fernet(monkeypatch):
    monkeypatch.setenv("PANEL_SECRET_KEY", "panel-key")
    monkeypatch.setenv("SESSION_PEPPER", "session-key")
    payload = {"token": "private-token"}

    ciphertext = encrypt_payload(payload)

    assert ciphertext.startswith("fernet:")
    assert decrypt_payload(ciphertext) == payload


def test_legacy_panel_ciphertext_remains_readable_after_key_upgrade(monkeypatch):
    monkeypatch.delenv("PANEL_SECRET_KEY", raising=False)
    monkeypatch.setenv("SESSION_PEPPER", "old-session-key")
    payload = {"username": "old-panel", "password": "legacy-secret"}
    serialized = json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    nonce = b"0123456789abcdef"
    encrypted = _xor_stream_crypt(serialized, hashlib.sha256(b"old-session-key").digest(), nonce)
    legacy_ciphertext = base64.urlsafe_b64encode(nonce + encrypted).decode("ascii")

    monkeypatch.setenv("PANEL_SECRET_KEY", "new-panel-key")
    assert decrypt_payload(legacy_ciphertext) == payload