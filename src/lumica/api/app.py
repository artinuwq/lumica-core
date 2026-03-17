import hashlib
import hmac
import json
import mimetypes
import os
import secrets
import socket
import base64
from types import SimpleNamespace
from decimal import Decimal, InvalidOperation
from datetime import datetime, timedelta, timezone
from pathlib import Path
from uuid import uuid4
from urllib.parse import parse_qsl, quote, unquote, urlencode, urlparse

import psutil
import requests
from flask import Flask, Response, jsonify, make_response, render_template, request, stream_with_context
from sqlalchemy import text
from sqlalchemy.exc import SQLAlchemyError

from lumica.infra.bootstrap import _bootstrap_multi_panel_state, _ensure_schema_compatibility
from lumica.integrations.telegram_storage import (
    TelegramStorageError,
    cloud_chunk_size_bytes,
    delete_telegram_message,
    iter_telegram_file_bytes,
    send_chunk_to_telegram,
)
from lumica.infra.db import Base, SessionLocal, engine, ensure_db_schema
from lumica.domain.models import (
    AppSetting,
    AuthSession,
    CloudChunk,
    CloudFile,
    CloudNode,
    InboundGroup,
    InboundGroupMember,
    Panel,
    PanelInbound,
    PanelSecret,
    PendingBinding,
    Subscription,
    User,
    UserConnection,
    UserVerification,
    VerificationCode,
    VpnAccount,
)
from lumica.services.panels import PanelRegistry, extract_clients_from_panel_inbound, protocol_to_group_key
from lumica.services.panels.registry import encrypt_payload
from lumica.services.panels import ensure_default_groups, sync_group_members_from_inbounds
from lumica.services.settings import (
    CLOUD_VISIBILITY_KEY,
    SettingsManager,
    to_bool,
)
from lumica.integrations.telegram_auth import validate_init_data
from .routes import (
    register_admin_routes,
    register_auth_routes,
    register_cloud_routes,
    register_status_routes,
    register_vpn_routes,
)
from .helpers import (
    build_admin_helpers,
    build_auth_helpers,
    build_cloud_helpers,
    build_vpn_helpers,
)


# src/lumica/api/app.py -> project root is 3 levels above
BASE_DIR = Path(__file__).resolve().parents[3]
FRONTEND_DIR = BASE_DIR / "frontend"
ROLE_PRIORITY = {"user": 10, "support": 20, "admin": 30, "owner": 40}


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _as_utc(value: datetime | None) -> datetime | None:
    if not value:
        return None
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


def _env_bool(name: str, default: bool = False) -> bool:
    value = os.getenv(name)
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


def _token_hash(raw_token: str) -> str:
    pepper = os.getenv("SESSION_PEPPER", "")
    return hashlib.sha256(f"{raw_token}:{pepper}".encode("utf-8")).hexdigest()


def _csrf_hash(raw_token: str) -> str:
    pepper = os.getenv("CSRF_PEPPER", os.getenv("SESSION_PEPPER", ""))
    return hashlib.sha256(f"{raw_token}:{pepper}".encode("utf-8")).hexdigest()


def _safe_json(value):
    if isinstance(value, dict):
        return value
    if isinstance(value, str):
        try:
            parsed = json.loads(value)
            return parsed if isinstance(parsed, dict) else {}
        except ValueError:
            return {}
    return {}


def _normalize_role(role: str | None) -> str:
    if not role:
        return "user"
    value = str(role).strip().lower()
    return value if value in ROLE_PRIORITY else "user"


def _role_allows(current_role: str | None, required_role: str | None) -> bool:
    if not required_role:
        return True
    current = _normalize_role(current_role)
    required = _normalize_role(required_role)
    return ROLE_PRIORITY[current] >= ROLE_PRIORITY[required]


def _to_id_list(value) -> list[str]:
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
        out = []
        for item in value:
            out.extend(_to_id_list(item))
        return out
    return []


def _load_role_bindings() -> dict[str, str]:
    bindings: dict[str, str] = {}
    raw = os.getenv("ROLE_BINDINGS", "").strip()

    def set_role(tg_id: str, role: str):
        if tg_id:
            bindings[str(tg_id)] = _normalize_role(role)

    if raw:
        parsed = None
        if raw.startswith("{") or raw.startswith("["):
            try:
                parsed = json.loads(raw)
            except ValueError:
                parsed = None

        if isinstance(parsed, dict):
            for role, ids in parsed.items():
                for tg_id in _to_id_list(ids):
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

    # optional legacy env compatibility
    legacy = {
        "OWNER_TELEGRAM_IDS": "owner",
        "ADMIN_TELEGRAM_IDS": "admin",
        "SUPPORT_TELEGRAM_IDS": "support",
    }
    for env_name, role in legacy.items():
        for tg_id in _to_id_list(os.getenv(env_name, "")):
            set_role(tg_id, role)

    return bindings


def _serialize_app_setting(row: AppSetting) -> dict:
    return {
        "id": row.id,
        "key": row.key,
        "value": row.value_json,
        "description": row.description,
        "created_at": row.created_at.isoformat() if row.created_at else None,
        "updated_at": row.updated_at.isoformat() if row.updated_at else None,
    }


def _normalize_panel_provider(raw_value: str | None) -> str:
    value = str(raw_value or "").strip().lower()
    if value in {"3xui", "xui", "3x-ui"}:
        return "3xui"
    if value == "marzban":
        return "marzban"
    return "3xui"


def create_app():
    app = Flask(
        __name__,
        template_folder=str(FRONTEND_DIR),
        static_folder=str(FRONTEND_DIR),
        static_url_path="/static",
    )
    # Allow template updates without restarting the process.
    app.config["TEMPLATES_AUTO_RELOAD"] = True
    app.jinja_env.auto_reload = True

    ensure_db_schema()
    _ensure_schema_compatibility()
    with SessionLocal() as db:
        _bootstrap_multi_panel_state(db)
        db.commit()

    session_cookie_name = os.getenv("SESSION_COOKIE_NAME", "session")
    session_ttl_days = int(os.getenv("SESSION_TTL_DAYS", "7"))
    role_bindings = _load_role_bindings()
    panel_registry = PanelRegistry()
    csrf_exempt_paths = {"/api/tg/auth"}
    csrf_protected_methods = {"POST", "PUT", "PATCH", "DELETE"}
    CLOUD_NODE_TYPE_FOLDER = "folder"
    CLOUD_NODE_TYPE_FILE = "file"

    route_deps = {**globals(), **locals()}
    route_deps.update(build_admin_helpers(route_deps))
    route_deps.update(build_vpn_helpers(route_deps))
    route_deps.update(build_auth_helpers(route_deps))
    route_deps.update(build_cloud_helpers(route_deps))

    _verify_csrf_request = route_deps["_verify_csrf_request"]

    @app.before_request
    def _enforce_csrf_protection():
        return _verify_csrf_request()

    @app.get("/")
    def index():
        response = make_response(render_template("index.html"))
        response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
        response.headers["Pragma"] = "no-cache"
        response.headers["Expires"] = "0"
        return response

    @app.get("/health")
    def health():
        return {"ok": True}

    register_cloud_routes(app, route_deps)
    register_status_routes(app, route_deps)
    register_admin_routes(app, route_deps)
    register_auth_routes(app, route_deps)
    register_vpn_routes(app, route_deps)

    return app


if __name__ == "__main__":
    app = create_app()
    host = os.getenv("FLASK_HOST", "0.0.0.0")
    port = int(os.getenv("FLASK_PORT", "8000"))
    app.run(host=host, port=port)
