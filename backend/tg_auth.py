import hashlib
import hmac
import json
import os
from urllib.parse import parse_qsl

BOT_TOKEN = os.getenv("TELEGRAM_BOT_TOKEN", "")


def validate_init_data(init_data: str):
    if not BOT_TOKEN:
        return None

    data = dict(parse_qsl(init_data, keep_blank_values=True))
    got_hash = data.pop("hash", "")
    if not got_hash:
        return None

    data_check_string = "\n".join(f"{k}={data[k]}" for k in sorted(data.keys()))
    secret_key = hmac.new(b"WebAppData", BOT_TOKEN.encode(), hashlib.sha256).digest()
    calc_hash = hmac.new(secret_key, data_check_string.encode(), hashlib.sha256).hexdigest()

    if not hmac.compare_digest(calc_hash, got_hash):
        return None

    return json.loads(data["user"]) if "user" in data else None
