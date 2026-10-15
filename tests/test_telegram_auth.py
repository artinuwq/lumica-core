import hashlib
import hmac
import importlib
import json
import time
from urllib.parse import urlencode

from lumica.integrations import telegram_auth


def _signed_init_data(bot_token: str) -> tuple[str, dict]:
    user = {"id": 123456789, "first_name": "Test", "username": "tester"}
    fields = {
        "auth_date": str(int(time.time())),
        "query_id": "test-query",
        "user": json.dumps(user, separators=(",", ":")),
    }
    check_string = "\n".join(f"{key}={fields[key]}" for key in sorted(fields))
    secret_key = hmac.new(b"WebAppData", bot_token.encode(), hashlib.sha256).digest()
    fields["hash"] = hmac.new(secret_key, check_string.encode(), hashlib.sha256).hexdigest()
    return urlencode(fields), user


def test_init_data_uses_token_loaded_after_module_import(monkeypatch):
    monkeypatch.delenv("TELEGRAM_BOT_TOKEN", raising=False)
    importlib.reload(telegram_auth)
    token = "123456789:abcdefghijklmnopqrstuvwxyzABCDE"
    init_data, expected_user = _signed_init_data(token)

    monkeypatch.setenv("TELEGRAM_BOT_TOKEN", token)

    assert telegram_auth.validate_init_data(init_data) == expected_user