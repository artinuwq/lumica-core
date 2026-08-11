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

from lumica.infra.bootstrap import _bootstrap_multi_panel_state, _ensure_schema_compatibility, _seed_constructor_data
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
    AuthIdentity,
    AuthSession,
    CloudChunk,
    CloudFile,
    CloudNode,
    InboundGroup,
    InboundGroupMember,
    Panel,
    PanelInbound,
    PanelSecret,
    PanelTemplate,
    PendingBinding,
    Region,
    Subscription,
    SubscriptionPlan,
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
from lumica.services.roles import ROLE_PRIORITY, load_role_bindings, normalize_role, role_allows
from .routes import (
    register_admin_routes,
    register_application_routes,
    register_auth_routes,
    register_cloud_routes,
    register_status_routes,
    register_update_routes,
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


# Backward-compatible local aliases: role logic now lives in
# lumica.services.roles so the HTTP API and the Telegram chat-ops bot share
# one implementation instead of two copies drifting apart.
_normalize_role = normalize_role
_role_allows = role_allows
_load_role_bindings = load_role_bindings


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
        _seed_constructor_data(db)
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
    register_update_routes(app, route_deps)
    register_application_routes(app, route_deps)

    return app


if __name__ == "__main__":
    app = create_app()
    host = os.getenv("FLASK_HOST", "0.0.0.0")
    port = int(os.getenv("FLASK_PORT", "8000"))
    app.run(host=host, port=port)
