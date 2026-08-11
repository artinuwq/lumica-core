"""Shared Telegram-id -> role resolution.

Used by both the HTTP API (session-based auth) and the Telegram chat-ops
bot (telegram_id-based auth) so the two never drift out of sync.
"""

from __future__ import annotations

import json
import os

ROLE_PRIORITY = {"user": 10, "support": 20, "admin": 30, "owner": 40}

_LEGACY_ENV_ROLES = {
    "OWNER_TELEGRAM_IDS": "owner",
    "ADMIN_TELEGRAM_IDS": "admin",
    "SUPPORT_TELEGRAM_IDS": "support",
}


def normalize_role(role: str | None) -> str:
    if not role:
        return "user"
    value = str(role).strip().lower()
    return value if value in ROLE_PRIORITY else "user"


def role_allows(current_role: str | None, required_role: str | None) -> bool:
    if not required_role:
        return True
    current = normalize_role(current_role)
    required = normalize_role(required_role)
    return ROLE_PRIORITY[current] >= ROLE_PRIORITY[required]


def to_id_list(value) -> list[str]:
    if value is None:
        return []
    if isinstance(value, (int, float)):
        return [str(int(value))]
    if isinstance(value, str):
        raw = value.strip()
        if not raw:
            return []
        if "," in raw:
            return [part.strip() for part in raw.split(",") if part.strip()]
        return [raw]
    if isinstance(value, list):
        out: list[str] = []
        for item in value:
            out.extend(to_id_list(item))
        return out
    return []


def load_role_bindings() -> dict[str, str]:
    """Parse ROLE_BINDINGS (+ legacy *_TELEGRAM_IDS envs) into {telegram_id: role}."""
    bindings: dict[str, str] = {}
    raw = os.getenv("ROLE_BINDINGS", "").strip()

    def set_role(tg_id: str, role: str) -> None:
        if tg_id:
            bindings[str(tg_id)] = normalize_role(role)

    if raw:
        parsed = None
        if raw.startswith("{") or raw.startswith("["):
            try:
                parsed = json.loads(raw)
            except ValueError:
                parsed = None

        if isinstance(parsed, dict):
            for role, ids in parsed.items():
                for tg_id in to_id_list(ids):
                    set_role(tg_id, role)
        elif isinstance(parsed, list):
            for item in parsed:
                if isinstance(item, dict):
                    tg_id = item.get("telegram_id") or item.get("id")
                    role = item.get("role")
                    if tg_id and role:
                        set_role(str(tg_id), str(role))
                elif isinstance(item, str) and ":" in item:
                    tg_id, role = item.split(":", 1)
                    set_role(tg_id.strip(), role.strip())
        else:
            # csv-style: "123:owner,456:admin"
            for token in raw.split(","):
                token = token.strip()
                if not token or ":" not in token:
                    continue
                tg_id, role = token.split(":", 1)
                set_role(tg_id.strip(), role.strip())

    for env_name, role in _LEGACY_ENV_ROLES.items():
        for tg_id in to_id_list(os.getenv(env_name, "")):
            set_role(tg_id, role)

    return bindings


def resolve_role(telegram_id: int | str, bindings: dict[str, str] | None = None) -> str:
    bindings = bindings if bindings is not None else load_role_bindings()
    return normalize_role(bindings.get(str(telegram_id)))


def is_authorized(telegram_id: int | str, required_role: str, bindings: dict[str, str] | None = None) -> bool:
    """True if telegram_id satisfies required_role.

    Unlike the generic "empty roster = allow everyone" dev-mode fallback,
    chat-ops here DENIES by default when no roles are configured at all.
    This app moves money (paid subscriptions) and ships /update and /restart
    as chat commands, so an unconfigured ROLE_BINDINGS/ADMIN_TELEGRAM_IDS
    must not silently grant every Telegram user admin power. Configure
    ADMIN_TELEGRAM_IDS or OWNER_TELEGRAM_IDS (or ROLE_BINDINGS) explicitly -
    install.sh does this for you via --admin-id.
    """
    bindings = bindings if bindings is not None else load_role_bindings()
    if not bindings:
        return False
    return role_allows(resolve_role(telegram_id, bindings), required_role)


__all__ = [
    "ROLE_PRIORITY",
    "normalize_role",
    "role_allows",
    "to_id_list",
    "load_role_bindings",
    "resolve_role",
    "is_authorized",
]
