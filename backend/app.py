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

from .cloud_storage import (
    TelegramStorageError,
    cloud_chunk_size_bytes,
    delete_telegram_message,
    iter_telegram_file_bytes,
    send_chunk_to_telegram,
)
from .db import Base, SessionLocal, engine
from .models import (
    AppSetting,
    AuthSession,
    CloudChunk,
    CloudFile,
    CloudNode,
    Inbound,
    InboundGroup,
    InboundGroupMember,
    Panel,
    PanelInbound,
    PanelSecret,
    PendingBinding,
    Subscription,
    User,
    UserConnection,
    VpnAccount,
)
from .panels import PanelRegistry, extract_clients_from_panel_inbound, protocol_to_group_key
from .panels.registry import encrypt_payload
from .panels.service import ensure_default_groups, sync_group_members_from_inbounds
from .settings_manager import (
    CLOUD_VISIBILITY_KEY,
    SettingsManager,
    to_bool,
)
from .tg_auth import validate_init_data
from .xui_api import XUIClient


BASE_DIR = Path(__file__).resolve().parents[1]
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


def _ensure_schema_compatibility() -> None:
    with engine.begin() as conn:
        cols = {row[1] for row in conn.exec_driver_sql("PRAGMA table_info(users)").fetchall()}
        if "role" not in cols:
            conn.execute(text("ALTER TABLE users ADD COLUMN role VARCHAR NOT NULL DEFAULT 'user'"))

        inbound_cols = {row[1] for row in conn.exec_driver_sql("PRAGMA table_info(inbounds)").fetchall()}
        if "show_in_app" not in inbound_cols:
            conn.execute(text("ALTER TABLE inbounds ADD COLUMN show_in_app INTEGER NOT NULL DEFAULT 1"))

        vpn_cols = {row[1] for row in conn.exec_driver_sql("PRAGMA table_info(vpn_accounts)").fetchall()}
        if "panel_inbound_ref_id" not in vpn_cols:
            conn.execute(text("ALTER TABLE vpn_accounts ADD COLUMN panel_inbound_ref_id INTEGER"))

        pending_cols = {row[1] for row in conn.exec_driver_sql("PRAGMA table_info(pending_bindings)").fetchall()}
        if "panel_inbound_ref_id" not in pending_cols:
            conn.execute(text("ALTER TABLE pending_bindings ADD COLUMN panel_inbound_ref_id INTEGER"))


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


def _bootstrap_multi_panel_state(db) -> None:
    manager = SettingsManager(db)
    schema_version = manager.get_value("schema.multi_panel.version", default=0)

    # Ensure at least one panel entry exists, based on current env single-panel setup.
    default_panel = db.query(Panel).filter(Panel.is_default == 1).order_by(Panel.created_at.asc()).first()
    if not default_panel:
        default_panel = db.query(Panel).order_by(Panel.created_at.asc()).first()
    if not default_panel:
        provider = _normalize_panel_provider(os.getenv("PANEL_PROVIDER", "3xui"))
        auth_type = os.getenv("PANEL_AUTH_TYPE", "login_password").strip().lower() or "login_password"
        secret_payload = {
            "username": os.getenv("PANEL_USER", "").strip(),
            "password": os.getenv("PANEL_PASS", "").strip(),
            "token": os.getenv("PANEL_TOKEN", "").strip(),
        }
        secret = PanelSecret(
            id=str(uuid4()),
            provider=provider,
            auth_type=auth_type,
            ciphertext=encrypt_payload(secret_payload),
        )
        db.add(secret)
        db.flush()

        default_panel = Panel(
            id=str(uuid4()),
            name=os.getenv("PANEL_DEFAULT_NAME", "Default Panel").strip() or "Default Panel",
            provider=provider,
            base_url=(os.getenv("PANEL_BASE_URL", "http://127.0.0.1:2053/panel/api").strip() or "http://127.0.0.1:2053/panel/api"),
            auth_type=auth_type,
            auth_secret_ref=secret.id,
            is_active=1,
            is_default=1,
            region=(os.getenv("PANEL_DEFAULT_REGION", "").strip() or None),
            health_status="unknown",
        )
        db.add(default_panel)
        db.flush()
    elif not default_panel.is_default:
        default_panel.is_default = 1

    # Legacy inbounds backfill to canonical panel_inbounds.
    legacy_inbounds = db.query(Inbound).all()
    legacy_map: dict[int, int] = {}
    for old in legacy_inbounds:
        external_id = str(old.panel_inbound_id)
        row = (
            db.query(PanelInbound)
            .filter(
                PanelInbound.panel_id == default_panel.id,
                PanelInbound.external_inbound_id == external_id,
            )
            .first()
        )
        if not row:
            row = PanelInbound(
                panel_id=default_panel.id,
                external_inbound_id=external_id,
                show_in_app=1,
            )
            db.add(row)
            db.flush()

        row.protocol = old.protocol
        row.port = old.port
        row.remark = old.remark
        row.listen = old.listen
        row.enabled = 1 if old.enable else 0
        row.show_in_app = 1 if getattr(old, "show_in_app", 1) else 0
        row.stream_settings = old.stream_settings if isinstance(old.stream_settings, dict) else {}
        row.settings = old.settings if isinstance(old.settings, dict) else {}
        row.last_sync_at = utcnow()
        legacy_map[int(old.panel_inbound_id)] = int(row.id)

    # Backfill refs in vpn_accounts.
    accounts = (
        db.query(VpnAccount)
        .filter(VpnAccount.panel_inbound_ref_id.is_(None), VpnAccount.panel_inbound_id.isnot(None))
        .all()
    )
    for account in accounts:
        ref_id = legacy_map.get(int(account.panel_inbound_id))
        if ref_id:
            account.panel_inbound_ref_id = int(ref_id)

    # Backfill refs in pending_bindings.
    pending_rows = (
        db.query(PendingBinding)
        .filter(PendingBinding.panel_inbound_ref_id.is_(None), PendingBinding.panel_inbound_id.isnot(None))
        .all()
    )
    for row in pending_rows:
        ref_id = legacy_map.get(int(row.panel_inbound_id))
        if ref_id:
            row.panel_inbound_ref_id = int(ref_id)

    groups = ensure_default_groups(db)
    sync_group_members_from_inbounds(db)

    # Seed user_connections from active bindings.
    group_by_key = {item.key: item.id for item in groups.values()}
    existing_user_connections = {
        (row.user_id, row.group_id): row
        for row in db.query(UserConnection).all()
    }
    active_accounts = (
        db.query(VpnAccount)
        .filter(VpnAccount.status == "active")
        .order_by(VpnAccount.user_id.asc(), VpnAccount.id.desc())
        .all()
    )

    for account in active_accounts:
        group_key = protocol_to_group_key(account.protocol)
        if not group_key:
            continue
        group_id = group_by_key.get(group_key)
        if not group_id:
            continue
        pair = (account.user_id, group_id)
        if pair in existing_user_connections:
            continue

        inbound_ref_id = account.panel_inbound_ref_id
        if not inbound_ref_id and account.panel_inbound_id is not None:
            inbound_ref_id = legacy_map.get(int(account.panel_inbound_id))
        selected_member_id = None
        if inbound_ref_id:
            member = (
                db.query(InboundGroupMember)
                .filter(
                    InboundGroupMember.group_id == group_id,
                    InboundGroupMember.panel_inbound_id == int(inbound_ref_id),
                )
                .first()
            )
            if member:
                selected_member_id = member.id

        row = UserConnection(
            user_id=account.user_id,
            group_id=group_id,
            selected_member_id=selected_member_id,
            selection_strategy="manual",
        )
        db.add(row)
        db.flush()
        existing_user_connections[pair] = row

    if str(schema_version) != "1":
        manager.set_setting(
            "schema.multi_panel.version",
            1,
            description="Multi-panel schema/data bootstrap version",
        )


def create_app():
    app = Flask(
        __name__,
        template_folder=str(FRONTEND_DIR),
        static_folder=str(FRONTEND_DIR),
    )
    # Allow template updates without restarting the process.
    app.config["TEMPLATES_AUTO_RELOAD"] = True
    app.jinja_env.auto_reload = True

    Base.metadata.create_all(bind=engine)
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

    def _active_subscription(db, user_id: int) -> Subscription | None:
        sub = (
            db.query(Subscription)
            .filter(Subscription.user_id == user_id)
            .order_by(Subscription.id.desc())
            .first()
        )
        if not sub:
            return None
        status = (sub.status or "").strip().lower()
        if status == "lifetime":
            # Lifetime subscriptions must not have an expiration timestamp.
            if sub.access_until is not None:
                sub.access_until = None
                db.commit()
            return sub
        if status != "active":
            return None
        access_until = _as_utc(sub.access_until)
        if access_until and access_until < utcnow():
            sub.status = "expired"
            db.commit()
            return None
        return sub

    def _latest_subscription(db, user_id: int) -> Subscription | None:
        return (
            db.query(Subscription)
            .filter(Subscription.user_id == user_id)
            .order_by(Subscription.id.desc())
            .first()
        )

    def _extract_connections_limit(user: User) -> int | None:
        profile = user.profile_data if isinstance(user.profile_data, dict) else {}
        raw = profile.get("connections_limit")
        if raw is None:
            raw = profile.get("connection_limit")
        try:
            limit = int(raw) if raw is not None else None
        except (ValueError, TypeError):
            return None
        if limit is None or limit < 0:
            return None
        return limit

    def _serialize_admin_user_overview(db, user: User) -> dict:
        # Keep active/expired status in sync when needed.
        _active_subscription(db, user.id)
        subscription = _latest_subscription(db, user.id)

        accounts = (
            db.query(VpnAccount)
            .filter(VpnAccount.user_id == user.id)
            .order_by(VpnAccount.updated_at.desc(), VpnAccount.id.desc())
            .all()
        )
        active_connections = [a for a in accounts if (a.status or "").lower() == "active"]
        connections_limit = _extract_connections_limit(user)
        available_connections = (
            max(connections_limit - len(active_connections), 0)
            if connections_limit is not None
            else None
        )

        return {
            "user": {
                "id": user.id,
                "telegram_id": user.telegram_id,
                "username": user.username,
                "name": user.name,
                "role": user.role,
            },
            "subscription": None
            if not subscription
            else {
                "id": subscription.id,
                "status": subscription.status,
                "access_until": subscription.access_until.isoformat() if subscription.access_until else None,
                "price_amount": str(subscription.price_amount) if subscription.price_amount is not None else None,
            },
            "connections": {
                "active": len(active_connections),
                "total": len(accounts),
                "limit": connections_limit,
                "available": available_connections,
            },
        }

    def _auth_context(require_role: str | None = None):
        raw_token = request.cookies.get(session_cookie_name)
        if not raw_token:
            return None, (jsonify({"ok": False, "error": "Unauthorized"}), 401)

        token_hash = _token_hash(raw_token)
        with SessionLocal() as db:
            auth_session = db.query(AuthSession).filter(AuthSession.session_token == token_hash).first()
            if not auth_session:
                return None, (jsonify({"ok": False, "error": "Unauthorized"}), 401)
            expires_at = _as_utc(auth_session.expires_at)
            if not expires_at or expires_at < utcnow():
                db.delete(auth_session)
                db.commit()
                return None, (jsonify({"ok": False, "error": "Session expired"}), 401)

            user = db.query(User).filter(User.id == auth_session.user_id).first()
            if not user:
                return None, (jsonify({"ok": False, "error": "Unauthorized"}), 401)
            if not _role_allows(user.role, require_role):
                return None, (jsonify({"ok": False, "error": "Forbidden"}), 403)

            return {
                "user_id": user.id,
                "role": user.role,
                "telegram_id": user.telegram_id,
                "username": user.username,
                "name": user.name,
            }, None

    def _session_csrf_hash(auth_session: AuthSession) -> str:
        session_data = _safe_json(auth_session.init_data)
        value = session_data.get("csrf_hash")
        return value if isinstance(value, str) else ""

    def _verify_csrf_request():
        if request.method not in csrf_protected_methods:
            return None
        if request.path in csrf_exempt_paths:
            return None

        raw_token = request.cookies.get(session_cookie_name)
        if not raw_token:
            return jsonify({"ok": False, "error": "Unauthorized"}), 401

        token_hash = _token_hash(raw_token)
        request_csrf_token = request.headers.get("X-CSRF-Token", "")
        if not request_csrf_token:
            return jsonify({"ok": False, "error": "CSRF token missing"}), 403

        with SessionLocal() as db:
            auth_session = db.query(AuthSession).filter(AuthSession.session_token == token_hash).first()
            if not auth_session:
                return jsonify({"ok": False, "error": "Unauthorized"}), 401

            expires_at = _as_utc(auth_session.expires_at)
            if not expires_at or expires_at < utcnow():
                db.delete(auth_session)
                db.commit()
                return jsonify({"ok": False, "error": "Session expired"}), 401

            stored_csrf_hash = _session_csrf_hash(auth_session)
            if not stored_csrf_hash:
                return jsonify({"ok": False, "error": "CSRF token is not initialized"}), 403

        if not hmac.compare_digest(_csrf_hash(request_csrf_token), stored_csrf_hash):
            return jsonify({"ok": False, "error": "Invalid CSRF token"}), 403
        return None

    @app.before_request
    def _enforce_csrf_protection():
        return _verify_csrf_request()

    def _new_session(db, user: User, init_data: str):
        raw_token = secrets.token_urlsafe(32)
        raw_csrf_token = secrets.token_urlsafe(32)
        expires_at = utcnow() + timedelta(days=session_ttl_days)
        token_hash = _token_hash(raw_token)
        csrf_hash = _csrf_hash(raw_csrf_token)
        try:
            parsed_init_data = dict(parse_qsl(init_data, keep_blank_values=True)) if init_data else {}
        except ValueError:
            parsed_init_data = {}
        auth_date = None
        raw_auth_date = parsed_init_data.get("auth_date")
        if raw_auth_date is not None:
            try:
                auth_date = int(raw_auth_date)
            except (ValueError, TypeError):
                auth_date = None
        init_data_sha256 = hashlib.sha256(init_data.encode("utf-8")).hexdigest() if init_data else ""
        session_meta = {
            "csrf_hash": csrf_hash,
            "telegram_id": str(user.telegram_id or ""),
            "username": str(user.username or ""),
            "auth_date": auth_date,
            "init_data_sha256": init_data_sha256,
        }

        db.query(AuthSession).filter(AuthSession.expires_at < utcnow()).delete()
        db.add(
            AuthSession(
                user_id=user.id,
                init_data=session_meta,
                session_token=token_hash,
                expires_at=expires_at,
            )
        )
        db.commit()
        return raw_token, raw_csrf_token

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

    def check_port(host: str, port: int, timeout: float = 1.0):
        try:
            with socket.create_connection((host, port), timeout=timeout):
                return True
        except OSError:
            return False

    def _panel_host_port() -> tuple[str, int]:
        base = os.getenv("PANEL_BASE_URL", "http://127.0.0.1:2053/panel/api")
        parsed = urlparse(base)
        host = parsed.hostname or "127.0.0.1"
        if parsed.port:
            return host, parsed.port
        return host, 443 if parsed.scheme == "https" else 80

    def _default_panel(db) -> Panel | None:
        return panel_registry.get_default_panel(db)

    def _panel_by_inbound_ref(db, inbound_ref_id: int | None) -> tuple[PanelInbound | None, Panel | None]:
        if not inbound_ref_id:
            return None, None
        inbound_row = db.query(PanelInbound).filter(PanelInbound.id == int(inbound_ref_id)).first()
        if not inbound_row:
            return None, None
        panel = db.query(Panel).filter(Panel.id == inbound_row.panel_id).first()
        return inbound_row, panel

    def _panel_inbound_by_legacy_id(db, panel_inbound_id: int | None) -> tuple[PanelInbound | None, Panel | None]:
        if panel_inbound_id is None:
            return None, None
        default = _default_panel(db)
        if not default:
            return None, None
        row = (
            db.query(PanelInbound)
            .filter(
                PanelInbound.panel_id == default.id,
                PanelInbound.external_inbound_id == str(panel_inbound_id),
            )
            .first()
        )
        return row, default

    def _resolve_panel_inbound_ref_id(
        db,
        *,
        panel_inbound_id: int | None = None,
        panel_id: str | None = None,
        external_inbound_id: str | None = None,
    ) -> int | None:
        if panel_id and external_inbound_id:
            row = (
                db.query(PanelInbound.id)
                .filter(
                    PanelInbound.panel_id == panel_id,
                    PanelInbound.external_inbound_id == str(external_inbound_id),
                )
                .first()
            )
            return int(row.id) if row else None
        if panel_inbound_id is None:
            return None
        row, _panel = _panel_inbound_by_legacy_id(db, panel_inbound_id)
        return int(row.id) if row else None

    def _panel_inbound_snapshot(inbound_row: PanelInbound) -> SimpleNamespace:
        panel_inbound_id = None
        try:
            panel_inbound_id = int(inbound_row.external_inbound_id)
        except (TypeError, ValueError):
            panel_inbound_id = None
        return SimpleNamespace(
            id=inbound_row.id,
            panel_inbound_id=panel_inbound_id,
            external_inbound_id=inbound_row.external_inbound_id,
            protocol=inbound_row.protocol,
            port=inbound_row.port,
            remark=inbound_row.remark,
            listen=inbound_row.listen,
            enable=inbound_row.enabled,
            show_in_app=inbound_row.show_in_app,
            stream_settings=inbound_row.stream_settings if isinstance(inbound_row.stream_settings, dict) else {},
            settings=inbound_row.settings if isinstance(inbound_row.settings, dict) else {},
            panel_id=inbound_row.panel_id,
        )

    def _resolve_account_inbound(db, account: VpnAccount):
        inbound_row = None
        panel = None
        if account.panel_inbound_ref_id:
            inbound_row, panel = _panel_by_inbound_ref(db, account.panel_inbound_ref_id)
        if not inbound_row and account.panel_inbound_id is not None:
            inbound_row, panel = _panel_inbound_by_legacy_id(db, account.panel_inbound_id)
        if inbound_row:
            return _panel_inbound_snapshot(inbound_row), inbound_row, panel
        if account.panel_inbound_id is None:
            return None, None, None
        legacy = db.query(Inbound).filter(Inbound.panel_inbound_id == account.panel_inbound_id).first()
        return legacy, None, None

    def _protocol_variants(protocol: str) -> set[str]:
        value = (protocol or "").strip().lower()
        if value == "https_mixed":
            return {"http", "mixed", "socks", "socks5"}
        if value == "mixed":
            return {"mixed", "socks", "socks5"}
        if value == "http":
            return {"http"}
        return {value}

    def _inbound_for_protocol(db, protocol: str) -> Inbound | None:
        variants = _protocol_variants(protocol)
        panel_row = (
            db.query(PanelInbound)
            .join(Panel, Panel.id == PanelInbound.panel_id)
            .filter(
                PanelInbound.protocol.in_(variants),
                PanelInbound.enabled == 1,
                PanelInbound.port.isnot(None),
                Panel.is_active == 1,
            )
            .order_by(PanelInbound.updated_at.desc(), PanelInbound.id.desc())
            .first()
        )
        if panel_row:
            return _panel_inbound_snapshot(panel_row)

        return (
            db.query(Inbound)
            .filter(
                Inbound.protocol.in_(variants),
                Inbound.enable == 1,
                Inbound.port.isnot(None),
            )
            .order_by(Inbound.updated_at.desc(), Inbound.id.desc())
            .first()
        )

    def _is_inbound_visible(inbound: Inbound | None) -> bool:
        if not inbound:
            return False
        return bool(inbound.enable) and bool(getattr(inbound, "show_in_app", 1))

    def _latest_visible_account_for_protocol(db, user_id: int, protocol: str) -> tuple[VpnAccount | None, Inbound | None]:
        rows = _visible_accounts_for_protocol(db, user_id, protocol)
        return rows[0] if rows else (None, None)

    def _visible_accounts_for_protocol(db, user_id: int, protocol: str) -> list[tuple[VpnAccount, Inbound]]:
        variants = _protocol_variants(protocol)
        protocol_value = (protocol or "").strip().lower()
        if protocol_value == "vless":
            account_protocols = {"vless"}
        else:
            account_protocols = {"mixed", "http", "socks", "socks5"}
        accounts = (
            db.query(VpnAccount)
            .filter(
                VpnAccount.user_id == user_id,
                VpnAccount.protocol.in_(account_protocols),
                VpnAccount.status == "active",
            )
            .order_by(VpnAccount.id.desc())
            .all()
        )
        out: list[tuple[VpnAccount, Inbound]] = []
        for account in accounts:
            inbound, inbound_row, _panel = _resolve_account_inbound(db, account)
            if not inbound:
                continue
            if inbound_row and not account.panel_inbound_ref_id:
                account.panel_inbound_ref_id = inbound_row.id
            if not inbound.port:
                continue
            inbound_protocol = (inbound.protocol or "").strip().lower()
            if inbound_protocol not in variants:
                continue
            if not _is_inbound_visible(inbound):
                continue
            out.append((account, inbound))
        return out

    def _protocol_visible_in_app(db, protocol: str) -> bool:
        variants = _protocol_variants(protocol)
        panel_row = (
            db.query(PanelInbound.id)
            .join(Panel, Panel.id == PanelInbound.panel_id)
            .filter(
                PanelInbound.protocol.in_(variants),
                PanelInbound.enabled == 1,
                PanelInbound.show_in_app == 1,
                PanelInbound.port.isnot(None),
                Panel.is_active == 1,
            )
            .order_by(PanelInbound.updated_at.desc(), PanelInbound.id.desc())
            .first()
        )
        if panel_row:
            return True
        row = (
            db.query(Inbound.id)
            .filter(
                Inbound.protocol.in_(variants),
                Inbound.enable == 1,
                Inbound.show_in_app == 1,
                Inbound.port.isnot(None),
            )
            .order_by(Inbound.updated_at.desc(), Inbound.id.desc())
            .first()
        )
        return bool(row)

    def _service_status(inbound: Inbound | None) -> dict:
        if not inbound:
            return {
                "ok": False,
                "configured": False,
                "port": None,
                "error": "Inbound not synced. Run /api/admin/sync-inbounds.",
            }
        panel_inbound_id = getattr(inbound, "panel_inbound_id", None)
        if panel_inbound_id is None:
            panel_inbound_id = getattr(inbound, "external_inbound_id", None)
        return {
            "ok": check_port("127.0.0.1", int(inbound.port)),
            "configured": True,
            "port": int(inbound.port),
            "panel_inbound_id": panel_inbound_id,
            "panel_id": getattr(inbound, "panel_id", None),
        }

    def _extract_clients_from_inbound(inbound: Inbound | None) -> list[dict]:
        if not inbound:
            return []
        settings = inbound.settings if isinstance(inbound.settings, dict) else {}
        protocol_raw = (inbound.protocol or "").strip().lower()
        protocol = "mixed" if protocol_raw in {"mixed", "http", "socks", "socks5"} else protocol_raw

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

        raw_clients = _as_list(settings.get("clients"))
        raw_accounts = _as_list(settings.get("accounts"))
        source_items = [*raw_clients, *raw_accounts]
        if not source_items:
            return []

        out: list[dict] = []
        for client in source_items:
            if not isinstance(client, dict):
                continue
            identifier = (
                client.get("id")
                or client.get("email")
                or client.get("username")
                or client.get("user")
            )
            identifier = str(identifier).strip() if identifier is not None else ""
            if not identifier:
                continue

            label = (
                client.get("email")
                or client.get("remark")
                or client.get("username")
                or client.get("user")
                or identifier
            )
            secret = client.get("password") or client.get("pass")
            sub_id = client.get("subId") or client.get("subid")
            out.append(
                {
                    "identifier": identifier,
                    "label": str(label),
                    "secret": secret if isinstance(secret, str) else None,
                    "sub_id": str(sub_id) if sub_id is not None else None,
                    "protocol": protocol,
                    "raw": client,
                }
            )
        return out

    def _sync_single_inbound_from_panel(db, panel_item: dict, panel: Panel | None = None):
        panel_id_raw = panel_item.get("id")
        if panel_id_raw is None:
            raise ValueError("panel inbound item has no id")
        external_inbound_id = str(panel_id_raw)

        target_panel = panel or _default_panel(db)
        if not target_panel:
            raise RuntimeError("No panel configured")

        panel_inbound = (
            db.query(PanelInbound)
            .filter(
                PanelInbound.panel_id == target_panel.id,
                PanelInbound.external_inbound_id == external_inbound_id,
            )
            .first()
        )
        if not panel_inbound:
            panel_inbound = PanelInbound(
                panel_id=target_panel.id,
                external_inbound_id=external_inbound_id,
                show_in_app=1,
            )
            db.add(panel_inbound)
            db.flush()

        panel_inbound.protocol = panel_item.get("protocol")
        panel_inbound.port = panel_item.get("port")
        panel_inbound.remark = panel_item.get("remark")
        panel_inbound.listen = panel_item.get("listen")
        panel_inbound.enabled = 1 if panel_item.get("enable", True) else 0
        panel_inbound.stream_settings = _safe_json(panel_item.get("streamSettings"))
        panel_inbound.settings = _safe_json(panel_item.get("settings"))
        panel_inbound.last_sync_at = utcnow()

        # Keep legacy inbounds in sync for default panel compatibility.
        if target_panel.is_default:
            try:
                legacy_panel_inbound_id = int(external_inbound_id)
            except (TypeError, ValueError):
                legacy_panel_inbound_id = None
            if legacy_panel_inbound_id is not None:
                legacy = db.query(Inbound).filter(Inbound.panel_inbound_id == legacy_panel_inbound_id).first()
                if not legacy:
                    legacy = Inbound(panel_inbound_id=legacy_panel_inbound_id)
                    legacy.show_in_app = 1
                    db.add(legacy)
                legacy.protocol = panel_inbound.protocol
                legacy.port = panel_inbound.port
                legacy.remark = panel_inbound.remark
                legacy.listen = panel_inbound.listen
                legacy.enable = panel_inbound.enabled
                legacy.stream_settings = panel_inbound.stream_settings
                legacy.settings = panel_inbound.settings
                legacy.show_in_app = panel_inbound.show_in_app

        return panel_inbound

    def _generate_panel_sub_id(length: int = 16) -> str:
        alphabet = "abcdefghijklmnopqrstuvwxyz0123456789"
        return "".join(secrets.choice(alphabet) for _ in range(max(8, length)))

    def _decode_subscription_payload(raw_text: str) -> str:
        text = (raw_text or "").strip()
        if not text:
            return ""
        if "://" in text:
            return text

        compact = "".join(text.split())
        if not compact:
            return ""
        pad = len(compact) % 4
        if pad:
            compact += "=" * (4 - pad)

        for decoder in (base64.b64decode, base64.urlsafe_b64decode):
            try:
                decoded = decoder(compact.encode("utf-8"))
            except Exception:
                continue
            as_text = decoded.decode("utf-8", errors="ignore").strip()
            if "://" in as_text:
                return as_text
        return text

    def _load_subscription_links(subscription_url: str, *, quiet: bool = False) -> list[str]:
        url = str(subscription_url or "").strip()
        if not url:
            return []
        parsed = urlparse(url)
        if parsed.scheme not in {"http", "https"}:
            return []

        try:
            response = requests.get(url, timeout=8)
            response.raise_for_status()
            payload = _decode_subscription_payload(response.text or "")
        except Exception as exc:
            if not quiet:
                app.logger.warning("subscription fetch failed for %s: %s", url, exc)
            return []

        links: list[str] = []
        for line in payload.splitlines():
            item = line.strip()
            if not item or "://" not in item:
                continue
            links.append(item)
        return links

    def _vless_identifier_from_url(link: str) -> str:
        value = str(link or "").strip()
        if not value.lower().startswith("vless://"):
            return ""
        rest = value[len("vless://") :]
        userinfo = rest.split("@", 1)[0] if "@" in rest else ""
        return unquote(userinfo).strip().lower()

    def _pick_vless_from_subscription(links: list[str], identifier: str | None) -> str | None:
        if not links:
            return None
        wanted = str(identifier or "").strip().lower()
        vless_links = [item for item in links if str(item).strip().lower().startswith("vless://")]
        if not vless_links:
            return None
        if wanted:
            for link in vless_links:
                if _vless_identifier_from_url(link) == wanted:
                    return link
        return vless_links[0]

    def _normalize_vless_client_name(label: str | None, identifier: str | None) -> str:
        value = str(label or "").strip()
        if not value:
            value = str(identifier or "").strip()
        if not value:
            return "client"

        low = value.lower()
        for suffix in ("-main", "_main", " main"):
            if low.endswith(suffix):
                value = value[: len(value) - len(suffix)].strip(" -_")
                break

        return value or "client"

    def _apply_vless_display_name(link: str | None, label: str | None, identifier: str | None) -> str | None:
        value = str(link or "").strip()
        if not value:
            return None
        if not value.lower().startswith("vless://"):
            return value

        client_name = _normalize_vless_client_name(label, identifier)
        display_name = f"Lumica - {client_name}"
        base = value.split("#", 1)[0]
        return f"{base}#{quote(display_name, safe='')}"

    def _build_subscription_urls(sub_id: str | None, explicit_url: str | None = None) -> list[str]:
        sid = str(sub_id or "").strip()
        sid_quoted = quote(sid) if sid else ""
        urls: list[str] = []

        def _append_url(raw: str | None):
            value = str(raw or "").strip()
            if not value:
                return
            parsed_value = urlparse(value)
            if parsed_value.scheme not in {"http", "https"}:
                return
            if value not in urls:
                urls.append(value)

        _append_url(explicit_url)

        public_base = os.getenv("PANEL_PUBLIC_BASE_URL", "").strip().rstrip("/")
        subscription_base = os.getenv("PANEL_SUBSCRIPTION_BASE_URL", "").strip().rstrip("/")
        tpl = os.getenv("PANEL_SUBSCRIPTION_URL_TEMPLATE", "").strip()
        if tpl:
            for base_url in (subscription_base, public_base, ""):
                try:
                    _append_url(tpl.format(sub_id=sid, base_url=base_url))
                except Exception as exc:
                    app.logger.warning("invalid PANEL_SUBSCRIPTION_URL_TEMPLATE: %s", exc)
                    break

        if sid:
            for base_url in (subscription_base, public_base):
                if not base_url:
                    continue
                _append_url(f"{base_url}/sub/{sid_quoted}")
                _append_url(f"{base_url}/subcrp/{sid_quoted}")

            panel_base = os.getenv("PANEL_BASE_URL", "").strip()
            parsed_base = urlparse(panel_base)
            if parsed_base.scheme in {"http", "https"} and parsed_base.netloc:
                root = f"{parsed_base.scheme}://{parsed_base.netloc}"
                _append_url(f"{root}/sub/{sid_quoted}")
                _append_url(f"{root}/subcrp/{sid_quoted}")

            public_host = os.getenv("PUBLIC_VPN_HOST", "").strip()
            sub_port = os.getenv("PANEL_SUBSCRIPTION_PORT", "").strip()
            if public_host and sub_port:
                _append_url(f"http://{public_host}:{sub_port}/sub/{sid_quoted}")
                _append_url(f"http://{public_host}:{sub_port}/subcrp/{sid_quoted}")
                _append_url(f"https://{public_host}:{sub_port}/sub/{sid_quoted}")
                _append_url(f"https://{public_host}:{sub_port}/subcrp/{sid_quoted}")

        return urls

    def _normalize_account_protocol(raw_protocol: str | None) -> str:
        value = (raw_protocol or "").strip().lower()
        return {
            "vless": "vless",
            "mixed": "mixed",
            "http": "mixed",
            "socks": "mixed",
            "socks5": "mixed",
        }.get(value, value)

    def _upsert_vpn_account(
        db,
        *,
        user_id: int,
        panel_inbound_id: int | None,
        panel_inbound_ref_id: int | None = None,
        protocol: str,
        identifier: str,
        label: str | None = None,
        secret: str | None = None,
        sub_id: str | None = None,
    ) -> VpnAccount:
        normalized_protocol = _normalize_account_protocol(protocol)
        if normalized_protocol not in {"vless", "mixed"}:
            raise ValueError("protocol must be vless or mixed")

        query = (
            db.query(VpnAccount)
            .filter(
                VpnAccount.user_id == int(user_id),
                VpnAccount.protocol == normalized_protocol,
                VpnAccount.identifier == identifier,
            )
        )
        if panel_inbound_ref_id:
            query = query.filter(VpnAccount.panel_inbound_ref_id == int(panel_inbound_ref_id))
        else:
            if panel_inbound_id is None:
                query = query.filter(VpnAccount.panel_inbound_id.is_(None))
            else:
                query = query.filter(VpnAccount.panel_inbound_id == int(panel_inbound_id))
        account = query.order_by(VpnAccount.id.desc()).first()
        if not account:
            account = VpnAccount(user_id=int(user_id), protocol=normalized_protocol)
            db.add(account)

        meta = account.meta_json if isinstance(account.meta_json, dict) else {}
        if sub_id:
            meta["sub_id"] = str(sub_id)

        account.panel_inbound_id = int(panel_inbound_id) if panel_inbound_id is not None else None
        account.panel_inbound_ref_id = int(panel_inbound_ref_id) if panel_inbound_ref_id else None
        account.identifier = identifier
        account.label = label or identifier
        account.secret = secret if normalized_protocol == "mixed" else None
        account.meta_json = meta
        account.status = "active"
        return account

    def _serialize_pending_binding(db, row: PendingBinding) -> dict:
        panel_inbound = None
        panel = None
        if row.panel_inbound_ref_id:
            panel_inbound, panel = _panel_by_inbound_ref(db, row.panel_inbound_ref_id)
        if not panel_inbound and row.panel_inbound_id is not None:
            panel_inbound, panel = _panel_inbound_by_legacy_id(db, row.panel_inbound_id)
        inbound = db.query(Inbound).filter(Inbound.panel_inbound_id == row.panel_inbound_id).first()
        panel_inbound_id_value = row.panel_inbound_id
        if panel_inbound and panel_inbound_id_value is None:
            try:
                panel_inbound_id_value = int(panel_inbound.external_inbound_id)
            except (TypeError, ValueError):
                panel_inbound_id_value = None
        meta = row.meta_json if isinstance(row.meta_json, dict) else {}
        return {
            "id": row.id,
            "telegram_id": row.telegram_id,
            "status": row.status,
            "protocol": row.protocol,
            "panel_inbound_id": panel_inbound_id_value,
            "panel_inbound_ref_id": row.panel_inbound_ref_id,
            "panel_id": panel.id if panel else None,
            "inbound_remark": panel_inbound.remark if panel_inbound else (inbound.remark if inbound else None),
            "inbound_port": panel_inbound.port if panel_inbound else (inbound.port if inbound else None),
            "identifier": row.identifier,
            "label": row.label,
            "sub_id": meta.get("sub_id"),
            "created_at": row.created_at.isoformat() if row.created_at else None,
            "applied_at": row.applied_at.isoformat() if row.applied_at else None,
            "applied_user_id": row.applied_user_id,
        }

    def _apply_pending_bindings_for_user(db, user: User) -> int:
        if not user or not user.telegram_id:
            return 0

        pending_rows = (
            db.query(PendingBinding)
            .filter(
                PendingBinding.telegram_id == str(user.telegram_id),
                PendingBinding.status == "pending",
            )
            .order_by(PendingBinding.id.asc())
            .all()
        )
        if not pending_rows:
            return 0

        applied = 0
        for row in pending_rows:
            panel_inbound = None
            if row.panel_inbound_ref_id:
                panel_inbound, _panel = _panel_by_inbound_ref(db, row.panel_inbound_ref_id)
            if not panel_inbound and row.panel_inbound_id is not None:
                panel_inbound, _panel = _panel_inbound_by_legacy_id(db, row.panel_inbound_id)

            inbound = db.query(Inbound).filter(Inbound.panel_inbound_id == row.panel_inbound_id).first()
            if not panel_inbound and not inbound:
                # Keep as pending so it can be retried after inbound sync/fix.
                continue

            sub_id = None
            if isinstance(row.meta_json, dict):
                sub_id = row.meta_json.get("sub_id")

            legacy_panel_inbound_id: int | None = row.panel_inbound_id
            if legacy_panel_inbound_id is None and panel_inbound:
                try:
                    legacy_panel_inbound_id = int(panel_inbound.external_inbound_id)
                except (TypeError, ValueError):
                    legacy_panel_inbound_id = None

            try:
                _upsert_vpn_account(
                    db,
                    user_id=user.id,
                    panel_inbound_id=legacy_panel_inbound_id,
                    panel_inbound_ref_id=(panel_inbound.id if panel_inbound else row.panel_inbound_ref_id),
                    protocol=row.protocol,
                    identifier=row.identifier,
                    label=row.label,
                    secret=row.secret,
                    sub_id=sub_id,
                )
            except ValueError:
                # Invalid protocol should not block remaining rows.
                continue

            row.status = "applied"
            row.applied_user_id = user.id
            row.applied_at = utcnow()
            applied += 1

        return applied

    def _normalize_selection_strategy(raw_value: str | None) -> str:
        value = str(raw_value or "").strip().lower()
        allowed = {"manual", "region_first", "least_loaded", "priority_order"}
        return value if value in allowed else "priority_order"

    def _load_default_selection_strategy(db) -> str:
        value = SettingsManager(db).get_value("vpn.selection.default_strategy", default="priority_order")
        return _normalize_selection_strategy(str(value or "priority_order"))

    def _group_by_key(db, group_key: str) -> InboundGroup | None:
        return db.query(InboundGroup).filter(InboundGroup.key == group_key).first()

    def _ensure_user_connection(db, user_id: int, group_key: str) -> UserConnection | None:
        group = _group_by_key(db, group_key)
        if not group:
            return None
        row = (
            db.query(UserConnection)
            .filter(UserConnection.user_id == int(user_id), UserConnection.group_id == int(group.id))
            .first()
        )
        if row:
            return row
        row = UserConnection(
            user_id=int(user_id),
            group_id=int(group.id),
            selected_member_id=None,
            selection_strategy=_load_default_selection_strategy(db),
        )
        db.add(row)
        db.flush()
        return row

    def _resolve_account_member(db, account: VpnAccount, group_key: str):
        group = _group_by_key(db, group_key)
        if not group:
            return None, None, None
        inbound_snapshot, panel_inbound, panel = _resolve_account_inbound(db, account)
        if not inbound_snapshot:
            return None, None, None
        if not panel_inbound and account.panel_inbound_ref_id:
            panel_inbound = db.query(PanelInbound).filter(PanelInbound.id == account.panel_inbound_ref_id).first()
        if not panel_inbound and account.panel_inbound_id is not None:
            panel_inbound, panel = _panel_inbound_by_legacy_id(db, account.panel_inbound_id)
        if not panel_inbound:
            return inbound_snapshot, None, panel

        member = (
            db.query(InboundGroupMember)
            .filter(
                InboundGroupMember.group_id == group.id,
                InboundGroupMember.panel_inbound_id == panel_inbound.id,
            )
            .first()
        )
        if not member:
            member = InboundGroupMember(
                group_id=group.id,
                panel_inbound_id=panel_inbound.id,
                label=panel_inbound.remark,
                priority=100,
                is_active=1,
            )
            db.add(member)
            db.flush()
        if not panel:
            panel = db.query(Panel).filter(Panel.id == panel_inbound.panel_id).first()
        return inbound_snapshot, member, panel

    def _account_candidates_for_protocol(db, user_id: int, protocol: str) -> list[dict]:
        rows = _visible_accounts_for_protocol(db, user_id, protocol)
        group_key = protocol_to_group_key(protocol)
        out: list[dict] = []
        for account, inbound in rows:
            member = None
            panel = None
            inbound_snapshot = inbound
            if group_key:
                resolved_inbound, resolved_member, resolved_panel = _resolve_account_member(db, account, group_key)
                if resolved_inbound:
                    inbound_snapshot = resolved_inbound
                member = resolved_member
                panel = resolved_panel

            out.append(
                {
                    "account": account,
                    "inbound": inbound_snapshot,
                    "member_id": member.id if member else None,
                    "priority": member.priority if member else 999999,
                    "region": panel.region if panel else None,
                    "panel_id": panel.id if panel else None,
                    "panel_name": panel.name if panel else None,
                }
            )
        return out

    def _pick_candidate_by_strategy(db, candidates: list[dict], strategy: str, user: User | None = None) -> dict | None:
        if not candidates:
            return None
        normalized = _normalize_selection_strategy(strategy)

        if normalized == "least_loaded":
            load_by_ref: dict[int, int] = {}
            ref_ids = [int(item["account"].panel_inbound_ref_id) for item in candidates if item["account"].panel_inbound_ref_id]
            if ref_ids:
                rows = (
                    db.query(VpnAccount.panel_inbound_ref_id, text("COUNT(*)"))
                    .filter(VpnAccount.panel_inbound_ref_id.in_(ref_ids), VpnAccount.status == "active")
                    .group_by(VpnAccount.panel_inbound_ref_id)
                    .all()
                )
                load_by_ref = {int(ref_id): int(cnt) for ref_id, cnt in rows if ref_id is not None}

            return sorted(
                candidates,
                key=lambda item: (
                    load_by_ref.get(int(item["account"].panel_inbound_ref_id or 0), 0),
                    int(item.get("priority") or 999999),
                    int(item["account"].id),
                ),
            )[0]

        if normalized == "region_first":
            user_region = None
            profile = user.profile_data if user and isinstance(user.profile_data, dict) else {}
            if profile:
                user_region = str(profile.get("region") or "").strip().lower() or None
            return sorted(
                candidates,
                key=lambda item: (
                    0 if user_region and str(item.get("region") or "").strip().lower() == user_region else 1,
                    int(item.get("priority") or 999999),
                    int(item["account"].id),
                ),
            )[0]

        # manual and priority_order share deterministic fallback ordering.
        return sorted(
            candidates,
            key=lambda item: (int(item.get("priority") or 999999), int(item["account"].id)),
        )[0]

    def _resolve_selected_candidate(db, user_id: int, protocol: str) -> tuple[list[dict], dict | None, str, int | None]:
        group_key = protocol_to_group_key(protocol)
        candidates = _account_candidates_for_protocol(db, user_id, protocol)
        if not group_key:
            return candidates, (candidates[0] if candidates else None), "priority_order", None

        user = db.query(User).filter(User.id == int(user_id)).first()
        user_conn = _ensure_user_connection(db, user_id, group_key)
        strategy = _normalize_selection_strategy(user_conn.selection_strategy if user_conn else _load_default_selection_strategy(db))
        selected = None
        if user_conn and user_conn.selected_member_id:
            selected = next((item for item in candidates if item.get("member_id") == user_conn.selected_member_id), None)
        if not selected:
            selected = _pick_candidate_by_strategy(db, candidates, strategy, user=user)

        selected_member_id = selected.get("member_id") if selected else None
        if user_conn:
            # Keep persisted selection stable if manual selection was not explicitly set.
            if user_conn.selected_member_id is None and selected_member_id is not None:
                user_conn.selected_member_id = selected_member_id

        if selected:
            candidates = [selected, *[item for item in candidates if item is not selected]]
        return candidates, selected, strategy, selected_member_id

    CLOUD_NODE_TYPE_FOLDER = "folder"
    CLOUD_NODE_TYPE_FILE = "file"

    def _cloud_visibility_enabled(db) -> bool:
        raw = SettingsManager(db).get_value(
            CLOUD_VISIBILITY_KEY,
            default=os.getenv("CLOUD_VISIBILITY", "true"),
        )
        return to_bool(raw, default=True)

    def _sanitize_cloud_name(raw_name: str | None) -> str:
        value = (raw_name or "").replace("\\", "/").strip()
        value = value.split("/")[-1].strip()
        if not value or value in {".", ".."}:
            return ""
        return value[:255]

    def _normalize_cloud_path(raw_path: str | None) -> str:
        value = (raw_path or "/").replace("\\", "/").strip()
        if not value:
            return "/"
        if not value.startswith("/"):
            value = f"/{value}"
        parts: list[str] = []
        for part in value.split("/"):
            part = part.strip()
            if not part or part == ".":
                continue
            if part == "..":
                raise ValueError("Path traversal is not allowed")
            safe = _sanitize_cloud_name(part)
            if not safe:
                raise ValueError("Invalid path segment")
            parts.append(safe)
        if not parts:
            return "/"
        return "/" + "/".join(parts)

    def _cloud_path_parts(path: str) -> list[str]:
        if path == "/":
            return []
        return [part for part in path.strip("/").split("/") if part]

    def _cloud_join_path(parent_path: str, child_name: str) -> str:
        if parent_path == "/":
            return f"/{child_name}"
        return f"{parent_path}/{child_name}"

    def _cloud_split_parent_path(path: str) -> tuple[str, str]:
        parts = _cloud_path_parts(path)
        if not parts:
            raise ValueError("Path must not be root")
        name = parts[-1]
        parent_parts = parts[:-1]
        parent_path = "/" + "/".join(parent_parts) if parent_parts else "/"
        return parent_path, name

    def _find_cloud_child(
        db,
        *,
        owner_user_id: int,
        parent_id: int | None,
        name: str,
    ) -> CloudNode | None:
        query = db.query(CloudNode).filter(
            CloudNode.owner_user_id == owner_user_id,
            CloudNode.name == name,
        )
        if parent_id is None:
            query = query.filter(CloudNode.parent_id.is_(None))
        else:
            query = query.filter(CloudNode.parent_id == parent_id)
        return query.first()

    def _resolve_cloud_folder(
        db,
        *,
        owner_user_id: int,
        path: str,
        create_missing: bool = False,
    ) -> CloudNode | None:
        if path == "/":
            return None

        parent_id: int | None = None
        current: CloudNode | None = None
        for part in _cloud_path_parts(path):
            child = _find_cloud_child(db, owner_user_id=owner_user_id, parent_id=parent_id, name=part)
            if child and child.node_type != CLOUD_NODE_TYPE_FOLDER:
                return None
            if not child:
                if not create_missing:
                    return None
                child = CloudNode(
                    owner_user_id=owner_user_id,
                    parent_id=parent_id,
                    node_type=CLOUD_NODE_TYPE_FOLDER,
                    name=part,
                )
                db.add(child)
                db.flush()
            current = child
            parent_id = child.id
        return current

    def _cloud_unique_child_name(
        db,
        *,
        owner_user_id: int,
        parent_id: int | None,
        desired_name: str,
    ) -> str:
        safe_name = _sanitize_cloud_name(desired_name)
        if not safe_name:
            safe_name = f"file-{utcnow().strftime('%Y%m%d-%H%M%S')}.bin"

        stem = Path(safe_name).stem
        suffix = Path(safe_name).suffix
        candidate = safe_name
        idx = 1
        while _find_cloud_child(db, owner_user_id=owner_user_id, parent_id=parent_id, name=candidate):
            candidate = f"{stem} ({idx}){suffix}"
            idx += 1
        return candidate

    def _cloud_node_to_payload(node: CloudNode, *, parent_path: str) -> dict:
        return {
            "node_id": node.id,
            "type": node.node_type,
            "name": node.name,
            "path": _cloud_join_path(parent_path, node.name),
            "created_at": node.created_at.isoformat() if node.created_at else None,
            "updated_at": node.updated_at.isoformat() if node.updated_at else None,
        }

    @app.get("/api/cloud/list")
    def cloud_list():
        auth, err = _auth_context()
        if err:
            return err

        try:
            current_path = _normalize_cloud_path(request.args.get("path", "/"))
        except ValueError as exc:
            return jsonify({"ok": False, "error": str(exc)}), 400

        with SessionLocal() as db:
            if not _cloud_visibility_enabled(db):
                return jsonify({"ok": False, "error": "Cloud feature is disabled"}), 403

            folder = _resolve_cloud_folder(db, owner_user_id=auth["user_id"], path=current_path)
            if current_path != "/" and not folder:
                return jsonify({"ok": False, "error": "Folder not found"}), 404

            parent_id = folder.id if folder else None
            query = db.query(CloudNode).filter(CloudNode.owner_user_id == auth["user_id"])
            if parent_id is None:
                query = query.filter(CloudNode.parent_id.is_(None))
            else:
                query = query.filter(CloudNode.parent_id == parent_id)
            nodes = query.all()

            file_node_ids = [node.id for node in nodes if node.node_type == CLOUD_NODE_TYPE_FILE]
            files_by_node_id: dict[int, CloudFile] = {}
            if file_node_ids:
                file_rows = (
                    db.query(CloudFile)
                    .filter(
                        CloudFile.owner_user_id == auth["user_id"],
                        CloudFile.node_id.in_(file_node_ids),
                    )
                    .all()
                )
                files_by_node_id = {row.node_id: row for row in file_rows}

            folders: list[dict] = []
            files: list[dict] = []
            for node in nodes:
                payload = _cloud_node_to_payload(node, parent_path=current_path)
                if node.node_type == CLOUD_NODE_TYPE_FOLDER:
                    folders.append(payload)
                    continue

                file_row = files_by_node_id.get(node.id)
                payload["file"] = None
                if file_row:
                    payload["file"] = {
                        "file_id": file_row.id,
                        "original_name": file_row.original_name,
                        "extension": file_row.extension,
                        "mime_type": file_row.mime_type,
                        "size_bytes": file_row.size_bytes,
                        "chunk_size_bytes": file_row.chunk_size_bytes,
                        "chunk_count": file_row.chunk_count,
                        "checksum_sha256": file_row.checksum_sha256,
                        "status": file_row.status,
                        "error_text": file_row.error_text,
                        "created_at": file_row.created_at.isoformat() if file_row.created_at else None,
                        "updated_at": file_row.updated_at.isoformat() if file_row.updated_at else None,
                    }
                files.append(payload)

            folders.sort(key=lambda item: item["name"].lower())
            files.sort(key=lambda item: item["name"].lower())

            return jsonify(
                {
                    "ok": True,
                    "path": current_path,
                    "folders": folders,
                    "files": files,
                }
            )

    @app.post("/api/cloud/mkdir")
    def cloud_mkdir():
        auth, err = _auth_context()
        if err:
            return err

        body = request.get_json(silent=True) or {}
        create_parents = bool(body.get("create_parents"))

        target_path_raw = body.get("path")
        if target_path_raw:
            try:
                target_path = _normalize_cloud_path(str(target_path_raw))
            except ValueError as exc:
                return jsonify({"ok": False, "error": str(exc)}), 400
        else:
            try:
                parent_path = _normalize_cloud_path(body.get("parent_path", "/"))
            except ValueError as exc:
                return jsonify({"ok": False, "error": str(exc)}), 400
            name = _sanitize_cloud_name(body.get("name"))
            if not name:
                return jsonify({"ok": False, "error": "name is required"}), 400
            target_path = _cloud_join_path(parent_path, name)

        if target_path == "/":
            return jsonify({"ok": False, "error": "Cannot create root folder"}), 400

        try:
            parent_path, folder_name = _cloud_split_parent_path(target_path)
        except ValueError as exc:
            return jsonify({"ok": False, "error": str(exc)}), 400

        with SessionLocal() as db:
            if not _cloud_visibility_enabled(db):
                return jsonify({"ok": False, "error": "Cloud feature is disabled"}), 403

            parent_folder = _resolve_cloud_folder(
                db,
                owner_user_id=auth["user_id"],
                path=parent_path,
                create_missing=create_parents,
            )
            if parent_path != "/" and not parent_folder:
                return jsonify({"ok": False, "error": "Parent folder not found"}), 404

            parent_id = parent_folder.id if parent_folder else None
            existing = _find_cloud_child(
                db,
                owner_user_id=auth["user_id"],
                parent_id=parent_id,
                name=folder_name,
            )
            if existing:
                if existing.node_type != CLOUD_NODE_TYPE_FOLDER:
                    return jsonify({"ok": False, "error": "A file with the same name already exists"}), 409
                return jsonify(
                    {
                        "ok": True,
                        "existing": True,
                        "folder": _cloud_node_to_payload(existing, parent_path=parent_path),
                    }
                )

            folder = CloudNode(
                owner_user_id=auth["user_id"],
                parent_id=parent_id,
                node_type=CLOUD_NODE_TYPE_FOLDER,
                name=folder_name,
            )
            db.add(folder)
            db.commit()
            db.refresh(folder)
            return jsonify(
                {
                    "ok": True,
                    "existing": False,
                    "folder": _cloud_node_to_payload(folder, parent_path=parent_path),
                }
            )

    @app.post("/api/cloud/upload")
    def cloud_upload():
        auth, err = _auth_context()
        if err:
            return err

        file_storage = request.files.get("file")
        if not file_storage:
            return jsonify({"ok": False, "error": "file is required"}), 400

        try:
            target_path = _normalize_cloud_path(request.form.get("path", "/"))
        except ValueError as exc:
            return jsonify({"ok": False, "error": str(exc)}), 400

        source_name = _sanitize_cloud_name(file_storage.filename or "")
        if not source_name:
            source_name = f"file-{utcnow().strftime('%Y%m%d-%H%M%S')}.bin"

        chunk_size = cloud_chunk_size_bytes()
        min_split_chunk_size = 512 * 1024
        try:
            min_split_chunk_kb = int(os.getenv("CLOUD_MIN_SPLIT_CHUNK_KB", "512"))
            min_split_chunk_size = max(64 * 1024, min_split_chunk_kb * 1024)
        except (TypeError, ValueError):
            min_split_chunk_size = 512 * 1024
        uploaded_total = 0
        uploaded_chunks = 0
        rolling_hash = hashlib.sha256()

        with SessionLocal() as db:
            if not _cloud_visibility_enabled(db):
                return jsonify({"ok": False, "error": "Cloud feature is disabled"}), 403

            folder = _resolve_cloud_folder(db, owner_user_id=auth["user_id"], path=target_path)
            if target_path != "/" and not folder:
                return jsonify({"ok": False, "error": "Target folder not found"}), 404

            parent_id = folder.id if folder else None
            final_name = _cloud_unique_child_name(
                db,
                owner_user_id=auth["user_id"],
                parent_id=parent_id,
                desired_name=source_name,
            )
            mime_type = file_storage.mimetype or mimetypes.guess_type(final_name)[0] or "application/octet-stream"
            suffix = Path(final_name).suffix

            node = CloudNode(
                owner_user_id=auth["user_id"],
                parent_id=parent_id,
                node_type=CLOUD_NODE_TYPE_FILE,
                name=final_name,
            )
            db.add(node)
            db.flush()

            cloud_file = CloudFile(
                node_id=node.id,
                owner_user_id=auth["user_id"],
                original_name=final_name,
                extension=suffix[1:].lower() if suffix.startswith(".") else None,
                mime_type=mime_type,
                size_bytes=0,
                chunk_size_bytes=0,
                chunk_count=0,
                status="uploading",
            )
            db.add(cloud_file)
            db.commit()
            db.refresh(node)
            db.refresh(cloud_file)

            try:
                while True:
                    chunk = file_storage.stream.read(chunk_size)
                    if not chunk:
                        break

                    rolling_hash.update(chunk)
                    pending_parts: list[bytes] = [chunk]
                    while pending_parts:
                        part = pending_parts.pop(0)
                        next_chunk_index = uploaded_chunks + 1
                        chunk_hash = hashlib.sha256(part).hexdigest()
                        part_name = f"{final_name}.part{next_chunk_index:06d}"
                        caption = f"cloud uid={auth['user_id']} file={cloud_file.id} chunk={next_chunk_index}"

                        try:
                            tg_meta = send_chunk_to_telegram(part, filename=part_name, caption=caption)
                        except TelegramStorageError as exc:
                            err_text = str(exc).lower()
                            is_timeout = ("timeout" in err_text) or ("timed out" in err_text)
                            can_split = len(part) > min_split_chunk_size
                            if is_timeout and can_split:
                                split_at = len(part) // 2
                                first = part[:split_at]
                                second = part[split_at:]
                                if first and second:
                                    pending_parts = [first, second, *pending_parts]
                                    continue
                            raise

                        uploaded_chunks = next_chunk_index
                        uploaded_total += len(part)
                        db.add(
                            CloudChunk(
                                file_id=cloud_file.id,
                                owner_user_id=auth["user_id"],
                                chunk_index=uploaded_chunks,
                                size_bytes=len(part),
                                checksum_sha256=chunk_hash,
                                tg_chat_id=tg_meta["chat_id"],
                                tg_message_id=tg_meta["message_id"],
                                tg_file_id=tg_meta["file_id"],
                                tg_file_unique_id=tg_meta["file_unique_id"] or None,
                                status="uploaded",
                            )
                        )
                        cloud_file.size_bytes = uploaded_total
                        cloud_file.chunk_size_bytes = chunk_size
                        cloud_file.chunk_count = uploaded_chunks
                        db.commit()

                cloud_file.status = "ready"
                cloud_file.error_text = None
                cloud_file.size_bytes = uploaded_total
                cloud_file.chunk_size_bytes = chunk_size if uploaded_chunks else 0
                cloud_file.chunk_count = uploaded_chunks
                cloud_file.checksum_sha256 = rolling_hash.hexdigest()
                db.commit()

                return jsonify(
                    {
                        "ok": True,
                        "path": _cloud_join_path(target_path, final_name),
                        "node_id": node.id,
                        "file": {
                            "file_id": cloud_file.id,
                            "name": final_name,
                            "mime_type": cloud_file.mime_type,
                            "size_bytes": cloud_file.size_bytes,
                            "chunk_size_bytes": cloud_file.chunk_size_bytes,
                            "chunk_count": cloud_file.chunk_count,
                            "checksum_sha256": cloud_file.checksum_sha256,
                            "status": cloud_file.status,
                        },
                    }
                )
            except TelegramStorageError as exc:
                db.rollback()
                failed = (
                    db.query(CloudFile)
                    .filter(
                        CloudFile.id == cloud_file.id,
                        CloudFile.owner_user_id == auth["user_id"],
                    )
                    .first()
                )
                if failed:
                    failed.status = "failed"
                    failed.error_text = str(exc)[:500]
                    failed.size_bytes = uploaded_total
                    failed.chunk_size_bytes = chunk_size if uploaded_chunks else 0
                    failed.chunk_count = uploaded_chunks
                    failed.checksum_sha256 = rolling_hash.hexdigest() if uploaded_total else None
                    db.commit()
                return jsonify({"ok": False, "error": f"Telegram storage error: {exc}"}), 502
            except Exception as exc:
                app.logger.exception("Cloud upload failed")
                db.rollback()
                failed = (
                    db.query(CloudFile)
                    .filter(
                        CloudFile.id == cloud_file.id,
                        CloudFile.owner_user_id == auth["user_id"],
                    )
                    .first()
                )
                if failed:
                    failed.status = "failed"
                    failed.error_text = str(exc)[:500]
                    failed.size_bytes = uploaded_total
                    failed.chunk_size_bytes = chunk_size if uploaded_chunks else 0
                    failed.chunk_count = uploaded_chunks
                    failed.checksum_sha256 = rolling_hash.hexdigest() if uploaded_total else None
                    db.commit()
                detail = str(exc).strip() or "unknown error"
                return jsonify({"ok": False, "error": f"Upload failed: {detail[:300]}"}), 500

    @app.get("/api/cloud/files/<int:file_id>/download")
    def cloud_download(file_id: int):
        auth, err = _auth_context()
        if err:
            return err
        inline_raw = str(request.args.get("inline", "")).strip().lower()
        inline_mode = inline_raw in {"1", "true", "yes", "on"}

        with SessionLocal() as db:
            if not _cloud_visibility_enabled(db):
                return jsonify({"ok": False, "error": "Cloud feature is disabled"}), 403

            cloud_file = (
                db.query(CloudFile)
                .filter(
                    CloudFile.id == file_id,
                    CloudFile.owner_user_id == auth["user_id"],
                )
                .first()
            )
            if not cloud_file:
                return jsonify({"ok": False, "error": "File not found"}), 404
            if cloud_file.status != "ready":
                return jsonify({"ok": False, "error": "File is not ready for download"}), 409

            chunks = (
                db.query(CloudChunk)
                .filter(
                    CloudChunk.file_id == cloud_file.id,
                    CloudChunk.owner_user_id == auth["user_id"],
                )
                .order_by(CloudChunk.chunk_index.asc())
                .all()
            )
            if len(chunks) != int(cloud_file.chunk_count or 0):
                return jsonify({"ok": False, "error": "File chunks are incomplete"}), 409

            file_name = cloud_file.original_name or f"file-{cloud_file.id}.bin"
            mime_type = cloud_file.mime_type or "application/octet-stream"
            size_bytes = int(cloud_file.size_bytes or 0)
            tg_file_ids = [str(chunk.tg_file_id) for chunk in chunks]

        def _stream():
            for tg_file_id in tg_file_ids:
                for piece in iter_telegram_file_bytes(tg_file_id):
                    yield piece

        response = Response(stream_with_context(_stream()), mimetype=mime_type)
        disposition = "inline" if inline_mode else "attachment"
        response.headers["Content-Disposition"] = f"{disposition}; filename*=UTF-8''{quote(file_name)}"
        response.headers["Cache-Control"] = "no-store"
        response.headers["X-Cloud-File-Id"] = str(file_id)
        if size_bytes >= 0:
            response.headers["Content-Length"] = str(size_bytes)
        return response

    @app.delete("/api/cloud/nodes/<int:node_id>")
    def cloud_delete_node(node_id: int):
        auth, err = _auth_context()
        if err:
            return err

        message_ids: list[int] = []

        with SessionLocal() as db:
            if not _cloud_visibility_enabled(db):
                return jsonify({"ok": False, "error": "Cloud feature is disabled"}), 403

            node = (
                db.query(CloudNode)
                .filter(
                    CloudNode.id == node_id,
                    CloudNode.owner_user_id == auth["user_id"],
                )
                .first()
            )
            if not node:
                return jsonify({"ok": False, "error": "Node not found"}), 404

            if node.node_type == CLOUD_NODE_TYPE_FOLDER:
                has_children = (
                    db.query(CloudNode.id)
                    .filter(
                        CloudNode.owner_user_id == auth["user_id"],
                        CloudNode.parent_id == node.id,
                    )
                    .first()
                )
                if has_children:
                    return jsonify({"ok": False, "error": "Folder is not empty"}), 409

            if node.node_type == CLOUD_NODE_TYPE_FILE and node.file:
                message_ids = [chunk.tg_message_id for chunk in node.file.chunks if chunk.tg_message_id]

            db.delete(node)
            db.commit()

        for message_id in message_ids:
            delete_telegram_message(message_id)

        return jsonify({"ok": True, "deleted_node_id": node_id})

    def system_stats():
        vm = psutil.virtual_memory()
        du = psutil.disk_usage("/")
        return {
            "cpu_pct": psutil.cpu_percent(interval=0.05),
            "ram_used_pct": round(vm.percent, 1),
            "disk_used_pct": round(du.percent, 1),
            "uptime_s": int(psutil.boot_time() and (datetime.utcnow().timestamp() - psutil.boot_time())),
        }

    def _panels_status_payload(db, *, refresh: bool = False) -> tuple[list[dict], dict]:
        now = utcnow()
        rows = db.query(Panel).order_by(Panel.is_default.desc(), Panel.created_at.asc()).all()
        out: list[dict] = []
        healthy = 0
        degraded = 0
        down = 0

        for panel in rows:
            if refresh:
                panel_registry.health_check(db, panel)

            last_ok = _as_utc(panel.last_ok_at)
            age_sec = (now - last_ok).total_seconds() if last_ok else None
            color = (panel.health_status or "unknown").strip().lower()
            if age_sec is not None:
                if age_sec < 600:
                    color = "green"
                elif age_sec < 1800 and color != "red":
                    color = "yellow"
                elif age_sec >= 1800:
                    color = "red"
            if color not in {"green", "yellow", "red"}:
                color = "unknown"

            if color == "green":
                healthy += 1
            elif color == "yellow":
                degraded += 1
            elif color == "red":
                down += 1

            out.append(
                {
                    "id": panel.id,
                    "name": panel.name,
                    "provider": panel.provider,
                    "base_url": panel.base_url,
                    "region": panel.region,
                    "is_active": bool(panel.is_active),
                    "is_default": bool(panel.is_default),
                    "health_status": color,
                    "last_ok_at": panel.last_ok_at.isoformat() if panel.last_ok_at else None,
                    "error_message": panel.error_message,
                }
            )

        summary = {
            "healthy_count": healthy,
            "degraded_count": degraded,
            "down_count": down,
            "total_count": len(out),
        }
        return out, summary

    @app.get("/api/status")
    def status_public():
        panel_host, panel_port = _panel_host_port()
        with SessionLocal() as db:
            vless_inbound = _inbound_for_protocol(db, "vless")
            http_inbound = _inbound_for_protocol(db, "http")
            mixed_inbound = _inbound_for_protocol(db, "mixed")
            vless_visible = _protocol_visible_in_app(db, "vless")
            http_visible = _protocol_visible_in_app(db, "http")
            mixed_visible = _protocol_visible_in_app(db, "mixed")
            panels_payload, panel_summary = _panels_status_payload(db, refresh=False)

        vless_status = _service_status(vless_inbound)
        http_status = _service_status(http_inbound)
        mixed_status = _service_status(mixed_inbound)
        vless_status["visible_in_app"] = vless_visible
        http_status["visible_in_app"] = http_visible
        mixed_status["visible_in_app"] = mixed_visible
        https_mixed_status = {
            "ok": bool(http_status.get("ok")) or bool(mixed_status.get("ok")),
            "configured": bool(http_status.get("configured")) or bool(mixed_status.get("configured")),
            "port": http_status.get("port") or mixed_status.get("port"),
            "panel_inbound_id": http_status.get("panel_inbound_id") or mixed_status.get("panel_inbound_id"),
            "visible_in_app": http_visible or mixed_visible,
            "error": None,
        }

        return jsonify(
            {
                "ok": True,
                "panel": {"ok": check_port(panel_host, panel_port), "host": panel_host, "port": panel_port},
                "services": {
                    "vless": vless_status,
                    "http": http_status,
                    "mixed": mixed_status,
                    "https_mixed": https_mixed_status,
                },
                "panels": panels_payload,
                "panels_summary": panel_summary,
                "timestamp": datetime.utcnow().isoformat(),
            }
        )

    @app.get("/api/admin/status")
    def status_admin():
        auth, err = _auth_context(require_role="admin")
        if err:
            return err

        panel_host, panel_port = _panel_host_port()
        with SessionLocal() as db:
            vless_inbound = _inbound_for_protocol(db, "vless")
            http_inbound = _inbound_for_protocol(db, "http")
            mixed_inbound = _inbound_for_protocol(db, "mixed")
            vless_visible = _protocol_visible_in_app(db, "vless")
            http_visible = _protocol_visible_in_app(db, "http")
            mixed_visible = _protocol_visible_in_app(db, "mixed")
            panels_payload, panel_summary = _panels_status_payload(db, refresh=True)
            db.commit()

        vless_status = _service_status(vless_inbound)
        http_status = _service_status(http_inbound)
        mixed_status = _service_status(mixed_inbound)
        vless_status["visible_in_app"] = vless_visible
        http_status["visible_in_app"] = http_visible
        mixed_status["visible_in_app"] = mixed_visible
        https_mixed_status = {
            "ok": bool(http_status.get("ok")) or bool(mixed_status.get("ok")),
            "configured": bool(http_status.get("configured")) or bool(mixed_status.get("configured")),
            "port": http_status.get("port") or mixed_status.get("port"),
            "panel_inbound_id": http_status.get("panel_inbound_id") or mixed_status.get("panel_inbound_id"),
            "visible_in_app": http_visible or mixed_visible,
            "error": None,
        }

        return jsonify(
            {
                "ok": True,
                "admin": auth,
                "panel": {"ok": check_port(panel_host, panel_port), "host": panel_host, "port": panel_port},
                "services": {
                    "vless": vless_status,
                    "http": http_status,
                    "mixed": mixed_status,
                    "https_mixed": https_mixed_status,
                },
                "panels": panels_payload,
                "panels_summary": panel_summary,
                "system": system_stats(),
                "timestamp": datetime.utcnow().isoformat(),
            }
        )

    @app.post("/api/admin/sync-inbounds")
    def sync_inbounds():
        _, err = _auth_context(require_role="admin")
        if err:
            return err

        with SessionLocal() as db:
            panels = panel_registry.get_active_panels(db)
            if not panels:
                return jsonify({"ok": False, "error": "No active panels configured"}), 400

            upserted = 0
            stale_disabled = 0
            results: list[dict] = []
            for panel in panels:
                try:
                    provider = panel_registry.get_provider(panel.provider)
                    auth_payload = panel_registry.get_auth_payload(db, panel)
                    items = provider.list_inbounds(panel, auth_payload)

                    seen: set[str] = set()
                    for item in items:
                        row = _sync_single_inbound_from_panel(db, item, panel=panel)
                        upserted += 1
                        seen.add(row.external_inbound_id)

                    stale_rows = (
                        db.query(PanelInbound)
                        .filter(PanelInbound.panel_id == panel.id)
                        .all()
                    )
                    local_stale = 0
                    for stale in stale_rows:
                        if stale.external_inbound_id in seen:
                            continue
                        stale.enabled = 0
                        stale.last_sync_at = utcnow()
                        local_stale += 1
                    stale_disabled += local_stale

                    panel.health_status = "green"
                    panel.last_ok_at = utcnow()
                    panel.error_message = None
                    results.append(
                        {
                            "panel_id": panel.id,
                            "name": panel.name,
                            "ok": True,
                            "upserted": len(seen),
                            "stale_disabled": local_stale,
                        }
                    )
                except Exception as exc:
                    panel_registry.invalidate_panel(panel.id)
                    panel.health_status = "red"
                    panel.error_message = str(exc)[:500]
                    results.append({"panel_id": panel.id, "name": panel.name, "ok": False, "error": str(exc)})

            sync_group_members_from_inbounds(db)
            db.commit()

        return jsonify(
            {
                "ok": True,
                "count": upserted,
                "stale_disabled": stale_disabled,
                "panels": results,
            }
        )

    @app.get("/api/admin/inbounds")
    def list_inbounds():
        _, err = _auth_context(require_role="admin")
        if err:
            return err

        with SessionLocal() as db:
            rows = (
                db.query(PanelInbound, Panel)
                .join(Panel, Panel.id == PanelInbound.panel_id)
                .order_by(Panel.name.asc(), PanelInbound.id.asc())
                .all()
            )
            if rows:
                inbounds: list[dict] = []
                for inbound, panel in rows:
                    panel_inbound_id = None
                    try:
                        panel_inbound_id = int(inbound.external_inbound_id)
                    except (TypeError, ValueError):
                        panel_inbound_id = None
                    inbounds.append(
                        {
                            "id": inbound.id,
                            "panel_inbound_ref_id": inbound.id,
                            "panel_id": panel.id,
                            "panel_name": panel.name,
                            "region": panel.region,
                            "external_inbound_id": inbound.external_inbound_id,
                            "panel_inbound_id": panel_inbound_id,
                            "protocol": inbound.protocol,
                            "port": inbound.port,
                            "remark": inbound.remark,
                            "listen": inbound.listen,
                            "enable": bool(inbound.enabled),
                            "show_in_app": bool(inbound.show_in_app),
                            "updated_at": inbound.updated_at.isoformat() if inbound.updated_at else None,
                            "last_sync_at": inbound.last_sync_at.isoformat() if inbound.last_sync_at else None,
                        }
                    )
                return jsonify({"ok": True, "inbounds": inbounds})

            legacy_rows = db.query(Inbound).order_by(Inbound.panel_inbound_id.asc()).all()
            return jsonify(
                {
                    "ok": True,
                    "inbounds": [
                        {
                            "id": r.id,
                            "panel_inbound_id": r.panel_inbound_id,
                            "protocol": r.protocol,
                            "port": r.port,
                            "remark": r.remark,
                            "listen": r.listen,
                            "enable": bool(r.enable),
                            "show_in_app": bool(getattr(r, "show_in_app", 1)),
                            "updated_at": r.updated_at.isoformat() if r.updated_at else None,
                        }
                        for r in legacy_rows
                    ],
                }
            )

    @app.get("/api/admin/settings")
    def admin_settings_list():
        _, err = _auth_context(require_role="admin")
        if err:
            return err

        prefix = (request.args.get("prefix") or "").strip() or None
        with SessionLocal() as db:
            settings = SettingsManager(db).list_settings(prefix=prefix)
            return jsonify({"ok": True, "settings": [_serialize_app_setting(item) for item in settings]})

    @app.get("/api/admin/settings/<setting_key>")
    def admin_settings_get(setting_key: str):
        _, err = _auth_context(require_role="admin")
        if err:
            return err

        with SessionLocal() as db:
            manager = SettingsManager(db)
            try:
                item = manager.get_setting(setting_key)
            except ValueError as exc:
                return jsonify({"ok": False, "error": str(exc)}), 400

            if not item:
                return jsonify({"ok": False, "error": "Setting not found"}), 404
            return jsonify({"ok": True, "setting": _serialize_app_setting(item)})

    @app.post("/api/admin/settings/<setting_key>")
    def admin_settings_upsert(setting_key: str):
        _, err = _auth_context(require_role="admin")
        if err:
            return err

        body = request.get_json(silent=True) or {}
        if "value" not in body:
            return jsonify({"ok": False, "error": "value is required"}), 400

        description = body.get("description")
        if description is not None and not isinstance(description, str):
            return jsonify({"ok": False, "error": "description must be a string"}), 400

        with SessionLocal() as db:
            manager = SettingsManager(db)
            try:
                item, created = manager.set_setting(
                    setting_key,
                    body.get("value"),
                    description=description,
                )
            except ValueError as exc:
                return jsonify({"ok": False, "error": str(exc)}), 400

            db.commit()
            return jsonify({"ok": True, "created": created, "setting": _serialize_app_setting(item)})

    @app.post("/api/admin/settings/<setting_key>/delete")
    def admin_settings_delete(setting_key: str):
        _, err = _auth_context(require_role="admin")
        if err:
            return err

        with SessionLocal() as db:
            manager = SettingsManager(db)
            try:
                deleted = manager.delete_setting(setting_key)
            except ValueError as exc:
                return jsonify({"ok": False, "error": str(exc)}), 400

            if not deleted:
                return jsonify({"ok": False, "error": "Setting not found"}), 404
            db.commit()
            return jsonify({"ok": True, "deleted": True})

    @app.post("/api/admin/inbounds/<int:panel_inbound_id>/visibility")
    def admin_inbound_visibility(panel_inbound_id: int):
        _, err = _auth_context(require_role="admin")
        if err:
            return err

        body = request.get_json(silent=True) or {}
        if "show_in_app" not in body:
            return jsonify({"ok": False, "error": "show_in_app is required"}), 400

        with SessionLocal() as db:
            inbound_ref = _resolve_panel_inbound_ref_id(db, panel_inbound_id=panel_inbound_id)
            panel_inbound = db.query(PanelInbound).filter(PanelInbound.id == inbound_ref).first() if inbound_ref else None
            inbound = db.query(Inbound).filter(Inbound.panel_inbound_id == panel_inbound_id).first()
            if not panel_inbound and not inbound:
                return jsonify({"ok": False, "error": "Inbound not found"}), 404

            next_visibility = 1 if body.get("show_in_app") else 0
            if panel_inbound:
                panel_inbound.show_in_app = next_visibility
            if inbound:
                inbound.show_in_app = next_visibility
            db.commit()

            protocol = panel_inbound.protocol if panel_inbound else inbound.protocol
            remark = panel_inbound.remark if panel_inbound else inbound.remark
            port = panel_inbound.port if panel_inbound else inbound.port
            enabled = bool(panel_inbound.enabled) if panel_inbound else bool(inbound.enable)
            return jsonify(
                {
                    "ok": True,
                    "inbound": {
                        "panel_inbound_id": panel_inbound_id,
                        "panel_inbound_ref_id": panel_inbound.id if panel_inbound else None,
                        "protocol": protocol,
                        "remark": remark,
                        "port": port,
                        "enable": enabled,
                        "show_in_app": bool(next_visibility),
                    },
                }
            )

    @app.get("/api/admin/users")
    def admin_users():
        _, err = _auth_context(require_role="admin")
        if err:
            return err

        with SessionLocal() as db:
            rows = db.query(User).order_by(User.id.asc()).all()
            return jsonify(
                {
                    "ok": True,
                    "users": [
                        {
                            "id": u.id,
                            "telegram_id": u.telegram_id,
                            "username": u.username,
                            "name": u.name,
                            "role": u.role,
                        }
                        for u in rows
                    ],
                }
            )

    @app.get("/api/admin/users/<int:user_id>/bindings")
    def admin_user_bindings(user_id: int):
        _, err = _auth_context(require_role="admin")
        if err:
            return err

        with SessionLocal() as db:
            user = db.query(User).filter(User.id == user_id).first()
            if not user:
                return jsonify({"ok": False, "error": "User not found"}), 404

            accounts = (
                db.query(VpnAccount)
                .filter(VpnAccount.user_id == user_id)
                .order_by(VpnAccount.updated_at.desc(), VpnAccount.id.desc())
                .all()
            )

            inbound_ids = {a.panel_inbound_id for a in accounts if a.panel_inbound_id is not None}
            inbounds_by_panel_id: dict[int, Inbound] = {}
            if inbound_ids:
                rows = db.query(Inbound).filter(Inbound.panel_inbound_id.in_(inbound_ids)).all()
                inbounds_by_panel_id = {row.panel_inbound_id: row for row in rows}

            inbound_ref_ids = {a.panel_inbound_ref_id for a in accounts if a.panel_inbound_ref_id is not None}
            panel_inbounds_by_ref: dict[int, PanelInbound] = {}
            panels_by_id: dict[str, Panel] = {}
            if inbound_ref_ids:
                rows = db.query(PanelInbound).filter(PanelInbound.id.in_(inbound_ref_ids)).all()
                panel_inbounds_by_ref = {row.id: row for row in rows}
                panel_ids = {row.panel_id for row in rows}
                if panel_ids:
                    panel_rows = db.query(Panel).filter(Panel.id.in_(panel_ids)).all()
                    panels_by_id = {row.id: row for row in panel_rows}

            return jsonify(
                {
                    "ok": True,
                    "user": {
                        "id": user.id,
                        "telegram_id": user.telegram_id,
                        "username": user.username,
                        "name": user.name,
                        "role": user.role,
                    },
                    "bindings": [
                        {
                            "id": a.id,
                            "protocol": a.protocol,
                            "panel_inbound_id": (
                                a.panel_inbound_id
                                if a.panel_inbound_id is not None
                                else (
                                    int(panel_inbounds_by_ref[a.panel_inbound_ref_id].external_inbound_id)
                                    if (
                                        a.panel_inbound_ref_id in panel_inbounds_by_ref
                                        and str(panel_inbounds_by_ref[a.panel_inbound_ref_id].external_inbound_id).isdigit()
                                    )
                                    else None
                                )
                            ),
                            "panel_inbound_ref_id": a.panel_inbound_ref_id,
                            "panel_id": (
                                panel_inbounds_by_ref[a.panel_inbound_ref_id].panel_id
                                if a.panel_inbound_ref_id in panel_inbounds_by_ref
                                else None
                            ),
                            "panel_name": (
                                panels_by_id[panel_inbounds_by_ref[a.panel_inbound_ref_id].panel_id].name
                                if (
                                    a.panel_inbound_ref_id in panel_inbounds_by_ref
                                    and panel_inbounds_by_ref[a.panel_inbound_ref_id].panel_id in panels_by_id
                                )
                                else None
                            ),
                            "inbound_remark": (
                                panel_inbounds_by_ref[a.panel_inbound_ref_id].remark
                                if a.panel_inbound_ref_id in panel_inbounds_by_ref
                                else (
                                    inbounds_by_panel_id[a.panel_inbound_id].remark
                                    if a.panel_inbound_id in inbounds_by_panel_id
                                    else None
                                )
                            ),
                            "inbound_port": (
                                panel_inbounds_by_ref[a.panel_inbound_ref_id].port
                                if a.panel_inbound_ref_id in panel_inbounds_by_ref
                                else (
                                    inbounds_by_panel_id[a.panel_inbound_id].port
                                    if a.panel_inbound_id in inbounds_by_panel_id
                                    else None
                                )
                            ),
                            "external_inbound_id": (
                                panel_inbounds_by_ref[a.panel_inbound_ref_id].external_inbound_id
                                if a.panel_inbound_ref_id in panel_inbounds_by_ref
                                else None
                            ),
                            "identifier": a.identifier,
                            "label": a.label,
                            "status": a.status,
                            "sub_id": (
                                (a.meta_json or {}).get("sub_id")
                                if isinstance(a.meta_json, dict)
                                else None
                            ),
                            "updated_at": a.updated_at.isoformat() if a.updated_at else None,
                        }
                        for a in accounts
                    ],
                }
            )

    @app.get("/api/admin/users/<int:user_id>/overview")
    def admin_user_overview(user_id: int):
        _, err = _auth_context(require_role="admin")
        if err:
            return err

        with SessionLocal() as db:
            user = db.query(User).filter(User.id == user_id).first()
            if not user:
                return jsonify({"ok": False, "error": "User not found"}), 404
            return jsonify({"ok": True, "overview": _serialize_admin_user_overview(db, user)})

    def _get_or_create_user_by_telegram_id(db, telegram_id: str) -> tuple[User, bool]:
        user = db.query(User).filter(User.telegram_id == telegram_id).first()
        if user:
            return user, False

        user = User(
            telegram_id=telegram_id,
            role=role_bindings.get(telegram_id, "user"),
        )
        db.add(user)
        db.flush()
        return user, True

    def _apply_admin_subscription_payload(db, user: User, body: dict):
        touches_subscription = any(
            key in body for key in ("extend_months", "status", "price_amount", "access_until")
        )
        sub = _latest_subscription(db, user.id)
        if touches_subscription and not sub:
            sub = Subscription(user_id=user.id, status="active")
            db.add(sub)
            db.flush()

        if sub and "extend_months" in body and str(body.get("extend_months")).strip() != "":
            try:
                months = int(body.get("extend_months"))
            except (TypeError, ValueError):
                return jsonify({"ok": False, "error": "extend_months must be an integer"}), 400
            if months <= 0:
                return jsonify({"ok": False, "error": "extend_months must be > 0"}), 400

            now = utcnow()
            current_until = _as_utc(sub.access_until)
            base = current_until if current_until and current_until > now else now
            sub.access_until = base + timedelta(days=30 * months)
            sub.status = "active"

        if sub and "status" in body and body.get("status") not in (None, ""):
            status = str(body.get("status")).strip().lower()
            allowed_statuses = {"active", "lifetime", "expired", "paused", "canceled", "inactive"}
            if status not in allowed_statuses:
                return jsonify({"ok": False, "error": "invalid subscription status"}), 400
            sub.status = status

        if sub and "price_amount" in body:
            raw_price = body.get("price_amount")
            if raw_price in (None, ""):
                sub.price_amount = None
            else:
                try:
                    sub.price_amount = Decimal(str(raw_price))
                except (InvalidOperation, ValueError):
                    return jsonify({"ok": False, "error": "price_amount must be a number"}), 400

        if sub and "access_until" in body:
            raw_access_until = body.get("access_until")
            if raw_access_until in (None, ""):
                sub.access_until = None
            else:
                try:
                    parsed = datetime.fromisoformat(str(raw_access_until).replace("Z", "+00:00"))
                except ValueError:
                    return jsonify({"ok": False, "error": "access_until must be ISO datetime"}), 400
                sub.access_until = parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)

        if sub and (sub.status or "").strip().lower() == "lifetime":
            sub.access_until = None

        if "connections_limit" in body:
            raw_limit = body.get("connections_limit")
            profile = user.profile_data if isinstance(user.profile_data, dict) else {}
            if raw_limit in (None, ""):
                profile.pop("connections_limit", None)
            else:
                try:
                    limit = int(raw_limit)
                except (TypeError, ValueError):
                    return jsonify({"ok": False, "error": "connections_limit must be an integer"}), 400
                if limit < 0:
                    return jsonify({"ok": False, "error": "connections_limit must be >= 0"}), 400
                profile["connections_limit"] = limit
            user.profile_data = profile

        return None

    @app.post("/api/admin/users/<int:user_id>/subscription")
    def admin_user_subscription_update(user_id: int):
        _, err = _auth_context(require_role="admin")
        if err:
            return err

        body = request.get_json(silent=True) or {}

        with SessionLocal() as db:
            user = db.query(User).filter(User.id == user_id).first()
            if not user:
                return jsonify({"ok": False, "error": "User not found"}), 404

            payload_err = _apply_admin_subscription_payload(db, user, body)
            if payload_err:
                return payload_err

            db.commit()
            db.refresh(user)
            return jsonify({"ok": True, "overview": _serialize_admin_user_overview(db, user)})

    @app.get("/api/admin/users/by-telegram/<telegram_id>/overview")
    def admin_user_overview_by_telegram(telegram_id: str):
        _, err = _auth_context(require_role="admin")
        if err:
            return err

        telegram_id = str(telegram_id or "").strip()
        if not telegram_id.isdigit():
            return jsonify({"ok": False, "error": "telegram_id must be numeric"}), 400

        with SessionLocal() as db:
            user = db.query(User).filter(User.telegram_id == telegram_id).first()
            if not user:
                return jsonify({"ok": True, "exists": False, "overview": None})
            return jsonify({"ok": True, "exists": True, "overview": _serialize_admin_user_overview(db, user)})

    @app.post("/api/admin/users/by-telegram/subscription")
    def admin_user_subscription_update_by_telegram():
        _, err = _auth_context(require_role="admin")
        if err:
            return err

        body = request.get_json(silent=True) or {}
        telegram_id = str(body.get("telegram_id") or "").strip()
        if not telegram_id or not telegram_id.isdigit():
            return jsonify({"ok": False, "error": "telegram_id must be numeric"}), 400

        with SessionLocal() as db:
            user, created_user = _get_or_create_user_by_telegram_id(db, telegram_id)
            payload_err = _apply_admin_subscription_payload(db, user, body)
            if payload_err:
                return payload_err

            db.commit()
            db.refresh(user)
            return jsonify(
                {
                    "ok": True,
                    "created_user": created_user,
                    "user_id": user.id,
                    "overview": _serialize_admin_user_overview(db, user),
                }
            )

    @app.get("/api/admin/inbounds/<int:panel_inbound_id>/clients")
    def admin_inbound_clients(panel_inbound_id: int):
        _, err = _auth_context(require_role="admin")
        if err:
            return err

        with SessionLocal() as db:
            inbound_ref = _resolve_panel_inbound_ref_id(db, panel_inbound_id=panel_inbound_id)
            panel_inbound = db.query(PanelInbound).filter(PanelInbound.id == inbound_ref).first() if inbound_ref else None
            inbound = db.query(Inbound).filter(Inbound.panel_inbound_id == panel_inbound_id).first()
            if not panel_inbound and not inbound:
                return jsonify({"ok": False, "error": "Inbound not found"}), 404
            clients = extract_clients_from_panel_inbound(panel_inbound) if panel_inbound else _extract_clients_from_inbound(inbound)
            protocol = panel_inbound.protocol if panel_inbound else inbound.protocol
            return jsonify(
                {
                    "ok": True,
                    "panel_inbound_id": panel_inbound_id,
                    "panel_inbound_ref_id": panel_inbound.id if panel_inbound else None,
                    "protocol": protocol,
                    "clients": clients,
                }
            )

    @app.post("/api/admin/inbounds/<int:panel_inbound_id>/clients")
    def admin_inbound_clients_create(panel_inbound_id: int):
        _, err = _auth_context(require_role="admin")
        if err:
            return err

        body = request.get_json(silent=True) or {}
        label = str(body.get("label") or body.get("email") or "").strip()
        if not label:
            return jsonify({"ok": False, "error": "label is required"}), 400
        label = label[:64]

        def _as_non_negative_int(value, default=0):
            if value in (None, ""):
                return default
            try:
                out = int(value)
            except (TypeError, ValueError):
                raise ValueError("must be an integer")
            if out < 0:
                raise ValueError("must be >= 0")
            return out

        try:
            limit_ip = _as_non_negative_int(body.get("limit_ip"), default=0)
            total_gb = _as_non_negative_int(body.get("total_gb"), default=0)
            expiry_days = _as_non_negative_int(body.get("expiry_days"), default=0)
        except ValueError as exc:
            return jsonify({"ok": False, "error": str(exc)}), 400

        flow = str(body.get("flow") or "xtls-rprx-vision").strip() or "xtls-rprx-vision"
        client_id = str(uuid4())
        sub_id = str(body.get("sub_id") or _generate_panel_sub_id()).strip()[:32] or _generate_panel_sub_id()
        expiry_time_ms = 0
        if expiry_days > 0:
            expiry_time_ms = int((utcnow() + timedelta(days=expiry_days)).timestamp() * 1000)
        total_bytes = int(total_gb) * 1024 * 1024 * 1024

        with SessionLocal() as db:
            inbound_ref = _resolve_panel_inbound_ref_id(db, panel_inbound_id=panel_inbound_id)
            panel_inbound = db.query(PanelInbound).filter(PanelInbound.id == inbound_ref).first() if inbound_ref else None
            inbound = db.query(Inbound).filter(Inbound.panel_inbound_id == panel_inbound_id).first()
            if not panel_inbound and not inbound:
                return jsonify({"ok": False, "error": "Inbound not found"}), 404

            effective_protocol = str((panel_inbound.protocol if panel_inbound else inbound.protocol) or "").strip().lower()
            if effective_protocol != "vless":
                return jsonify({"ok": False, "error": "Adding new clients is currently supported only for VLESS inbounds"}), 400

            existing = extract_clients_from_panel_inbound(panel_inbound) if panel_inbound else _extract_clients_from_inbound(inbound)
            existing_labels = {str(item.get("label") or "").strip().lower() for item in existing}
            if label.lower() in existing_labels:
                return jsonify({"ok": False, "error": "Client with this label already exists"}), 409

            client_payload = {
                "id": client_id,
                "email": label,
                "flow": flow,
                "limitIp": limit_ip,
                "totalGB": total_bytes,
                "expiryTime": expiry_time_ms,
                "enable": True,
                "tgId": 0,
                "subId": sub_id,
                "reset": 0,
            }

            panel_result = None
            refresh_warning = None
            if panel_inbound:
                panel = db.query(Panel).filter(Panel.id == panel_inbound.panel_id).first()
                if not panel:
                    return jsonify({"ok": False, "error": "Panel not found for inbound"}), 404
                try:
                    provider = panel_registry.get_provider(panel.provider)
                    auth_payload = panel_registry.get_auth_payload(db, panel)
                    panel_result = provider.create_client(panel, panel_inbound, client_payload, auth_payload)
                except Exception as exc:
                    app.logger.exception("add inbound client failed")
                    return jsonify({"ok": False, "error": str(exc)}), 502

                try:
                    provider = panel_registry.get_provider(panel.provider)
                    auth_payload = panel_registry.get_auth_payload(db, panel)
                    panel_items = provider.list_inbounds(panel, auth_payload)
                    panel_item = next(
                        (item for item in panel_items if str(item.get("id")) == str(panel_inbound.external_inbound_id)),
                        None,
                    )
                    if panel_item:
                        panel_inbound = _sync_single_inbound_from_panel(db, panel_item, panel=panel)
                        db.commit()
                    else:
                        refresh_warning = "Client created in panel, but inbound was not found during refresh."
                except Exception as exc:
                    refresh_warning = f"Client created in panel, but local refresh failed: {exc}"
                    app.logger.warning("refresh inbound after add-client failed: %s", exc)
            else:
                try:
                    panel_result = XUIClient().add_client(panel_inbound_id, client_payload)
                except Exception as exc:
                    app.logger.exception("add inbound client failed")
                    return jsonify({"ok": False, "error": str(exc)}), 502

                try:
                    panel_items = XUIClient().get_inbounds()
                    panel_item = next((item for item in panel_items if str(item.get("id")) == str(panel_inbound_id)), None)
                    if panel_item:
                        _sync_single_inbound_from_panel(db, panel_item)
                        db.commit()
                        inbound = db.query(Inbound).filter(Inbound.panel_inbound_id == panel_inbound_id).first() or inbound
                    else:
                        refresh_warning = "Client created in panel, but inbound was not found during refresh."
                except Exception as exc:
                    refresh_warning = f"Client created in panel, but local refresh failed: {exc}"
                    app.logger.warning("refresh inbound after add-client failed: %s", exc)

            clients = (
                extract_clients_from_panel_inbound(panel_inbound)
                if panel_inbound
                else _extract_clients_from_inbound(inbound)
            )
            created = next((item for item in clients if str(item.get("identifier")) == client_id), None)
            if not created:
                created = {
                    "identifier": client_id,
                    "label": label,
                    "sub_id": sub_id,
                    "protocol": effective_protocol,
                }
                clients = [created, *clients]

            return jsonify(
                {
                    "ok": True,
                    "panel_inbound_id": panel_inbound_id,
                    "panel_inbound_ref_id": panel_inbound.id if panel_inbound else inbound_ref,
                    "protocol": effective_protocol,
                    "created_client": created,
                    "clients": clients,
                    "panel_result": panel_result,
                    "warning": refresh_warning,
                }
            )

    @app.post("/api/admin/bind-client")
    def admin_bind_client():
        _, err = _auth_context(require_role="admin")
        if err:
            return err

        body = request.get_json(silent=True) or {}
        user_id = body.get("user_id")
        panel_inbound_id = body.get("panel_inbound_id")
        panel_inbound_ref_id_raw = body.get("panel_inbound_ref_id")
        identifier = (body.get("client_identifier") or "").strip()
        protocol = _normalize_account_protocol(body.get("protocol"))
        label = body.get("label")
        secret = body.get("secret")
        sub_id = body.get("sub_id")

        if not user_id or (not panel_inbound_id and not panel_inbound_ref_id_raw) or not identifier:
            return jsonify({"ok": False, "error": "user_id, panel_inbound_id|panel_inbound_ref_id, client_identifier are required"}), 400
        if protocol not in {"vless", "mixed"}:
            return jsonify({"ok": False, "error": "protocol must be vless or mixed"}), 400

        with SessionLocal() as db:
            user = db.query(User).filter(User.id == int(user_id)).first()
            if not user:
                return jsonify({"ok": False, "error": "User not found"}), 404

            panel_inbound_ref_id = None
            panel_inbound = None
            if panel_inbound_ref_id_raw not in (None, ""):
                try:
                    panel_inbound_ref_id = int(panel_inbound_ref_id_raw)
                except (TypeError, ValueError):
                    return jsonify({"ok": False, "error": "panel_inbound_ref_id must be an integer"}), 400
                panel_inbound = db.query(PanelInbound).filter(PanelInbound.id == panel_inbound_ref_id).first()
                if not panel_inbound:
                    return jsonify({"ok": False, "error": "Panel inbound not found"}), 404
                if panel_inbound_id in (None, ""):
                    try:
                        panel_inbound_id = int(panel_inbound.external_inbound_id)
                    except (TypeError, ValueError):
                        panel_inbound_id = None
            else:
                panel_inbound_ref_id = _resolve_panel_inbound_ref_id(db, panel_inbound_id=int(panel_inbound_id))
                panel_inbound = db.query(PanelInbound).filter(PanelInbound.id == panel_inbound_ref_id).first() if panel_inbound_ref_id else None
            inbound = db.query(Inbound).filter(Inbound.panel_inbound_id == int(panel_inbound_id)).first() if panel_inbound_id not in (None, "") else None
            if not panel_inbound and not inbound:
                return jsonify({"ok": False, "error": "Inbound not found"}), 404

            account = _upsert_vpn_account(
                db,
                user_id=user.id,
                panel_inbound_id=(int(panel_inbound_id) if panel_inbound_id not in (None, "") else None),
                panel_inbound_ref_id=panel_inbound_ref_id,
                protocol=protocol,
                identifier=identifier,
                label=label,
                secret=secret,
                sub_id=sub_id,
            )
            db.commit()

            return jsonify(
                {
                    "ok": True,
                    "account": {
                        "id": account.id,
                        "user_id": account.user_id,
                        "protocol": account.protocol,
                        "panel_inbound_id": account.panel_inbound_id,
                        "panel_inbound_ref_id": account.panel_inbound_ref_id,
                        "identifier": account.identifier,
                        "label": account.label,
                        "status": account.status,
                    },
                }
            )

    @app.get("/api/admin/pending-bindings")
    def admin_pending_bindings():
        _, err = _auth_context(require_role="admin")
        if err:
            return err

        telegram_id = (request.args.get("telegram_id") or "").strip()
        status = (request.args.get("status") or "").strip().lower()
        limit_raw = request.args.get("limit")
        try:
            limit = int(limit_raw) if limit_raw not in (None, "") else 200
        except (TypeError, ValueError):
            return jsonify({"ok": False, "error": "limit must be an integer"}), 400
        limit = max(1, min(limit, 500))

        with SessionLocal() as db:
            query = db.query(PendingBinding).order_by(PendingBinding.id.desc())
            if telegram_id:
                query = query.filter(PendingBinding.telegram_id == telegram_id)
            if status:
                query = query.filter(PendingBinding.status == status)

            rows = query.limit(limit).all()
            return jsonify(
                {
                    "ok": True,
                    "pending_bindings": [_serialize_pending_binding(db, row) for row in rows],
                }
            )

    @app.post("/api/admin/pending-bindings")
    def admin_pending_bindings_create():
        _, err = _auth_context(require_role="admin")
        if err:
            return err

        body = request.get_json(silent=True) or {}
        telegram_id = str(body.get("telegram_id") or "").strip()
        panel_inbound_id = body.get("panel_inbound_id")
        identifier = str(body.get("client_identifier") or "").strip()
        protocol = _normalize_account_protocol(body.get("protocol"))
        label = body.get("label")
        secret = body.get("secret")
        sub_id = body.get("sub_id")

        if not telegram_id or not telegram_id.isdigit():
            return jsonify({"ok": False, "error": "telegram_id must be numeric"}), 400
        if not panel_inbound_id or not identifier:
            return jsonify({"ok": False, "error": "panel_inbound_id and client_identifier are required"}), 400
        if protocol not in {"vless", "mixed"}:
            return jsonify({"ok": False, "error": "protocol must be vless or mixed"}), 400
        try:
            panel_inbound_id = int(panel_inbound_id)
        except (TypeError, ValueError):
            return jsonify({"ok": False, "error": "panel_inbound_id must be an integer"}), 400

        with SessionLocal() as db:
            panel_inbound_ref_id = _resolve_panel_inbound_ref_id(db, panel_inbound_id=panel_inbound_id)
            panel_inbound = db.query(PanelInbound).filter(PanelInbound.id == panel_inbound_ref_id).first() if panel_inbound_ref_id else None
            inbound = db.query(Inbound).filter(Inbound.panel_inbound_id == panel_inbound_id).first()
            if not panel_inbound and not inbound:
                return jsonify({"ok": False, "error": "Inbound not found"}), 404

            existing = (
                db.query(PendingBinding)
                .filter(
                    PendingBinding.telegram_id == telegram_id,
                    PendingBinding.protocol == protocol,
                    PendingBinding.panel_inbound_id == panel_inbound_id,
                    PendingBinding.identifier == identifier,
                    PendingBinding.status == "pending",
                )
                .order_by(PendingBinding.id.desc())
                .first()
            )
            if existing:
                meta = existing.meta_json if isinstance(existing.meta_json, dict) else {}
                if sub_id:
                    meta["sub_id"] = str(sub_id)
                existing.label = label or existing.label or identifier
                existing.secret = secret if protocol == "mixed" else None
                existing.meta_json = meta
                if panel_inbound_ref_id:
                    existing.panel_inbound_ref_id = panel_inbound_ref_id
                db.commit()
                return jsonify(
                    {
                        "ok": True,
                        "deduplicated": True,
                        "pending_binding": _serialize_pending_binding(db, existing),
                    }
                )

            row = PendingBinding(
                telegram_id=telegram_id,
                protocol=protocol,
                panel_inbound_id=panel_inbound_id,
                panel_inbound_ref_id=panel_inbound_ref_id,
                identifier=identifier,
                label=label or identifier,
                secret=secret if protocol == "mixed" else None,
                meta_json={"sub_id": str(sub_id)} if sub_id else {},
                status="pending",
            )
            db.add(row)
            db.commit()
            return jsonify({"ok": True, "pending_binding": _serialize_pending_binding(db, row)})

    @app.post("/api/admin/pending-bindings/<int:pending_id>/cancel")
    def admin_pending_binding_cancel(pending_id: int):
        _, err = _auth_context(require_role="admin")
        if err:
            return err

        with SessionLocal() as db:
            row = db.query(PendingBinding).filter(PendingBinding.id == pending_id).first()
            if not row:
                return jsonify({"ok": False, "error": "Pending binding not found"}), 404
            if row.status != "pending":
                return jsonify({"ok": False, "error": "Only pending bindings can be canceled"}), 400

            row.status = "canceled"
            db.commit()
            return jsonify({"ok": True, "pending_binding": _serialize_pending_binding(db, row)})

    @app.post("/api/admin/unbind-client")
    def admin_unbind_client():
        _, err = _auth_context(require_role="admin")
        if err:
            return err

        body = request.get_json(silent=True) or {}
        binding_id = body.get("binding_id")
        if not binding_id:
            return jsonify({"ok": False, "error": "binding_id is required"}), 400

        with SessionLocal() as db:
            account = db.query(VpnAccount).filter(VpnAccount.id == int(binding_id)).first()
            if not account:
                return jsonify({"ok": False, "error": "Binding not found"}), 404

            deleted = {
                "id": account.id,
                "user_id": account.user_id,
                "protocol": account.protocol,
                "panel_inbound_id": account.panel_inbound_id,
                "identifier": account.identifier,
                "label": account.label,
            }
            db.delete(account)
            db.commit()

            return jsonify({"ok": True, "deleted": deleted})

    @app.post("/api/tg/auth")
    def tg_auth():
        body = request.get_json(silent=True) or {}
        init_data = body.get("initData", "")

        try:
            user_data = validate_init_data(init_data)
        except Exception:
            app.logger.exception("tg_auth validation failed")
            return jsonify({"ok": False, "error": "Server error validating initData"}), 500

        if not user_data:
            return jsonify({"ok": False, "error": "Invalid initData"}), 401

        try:
            with SessionLocal() as db:
                telegram_id = str(user_data.get("id", ""))
                user = db.query(User).filter(User.telegram_id == telegram_id).first()
                if not user:
                    user = User(telegram_id=telegram_id)
                    db.add(user)
                    db.flush()

                user.username = user_data.get("username")
                first_name = user_data.get("first_name")
                last_name = user_data.get("last_name")
                name = " ".join(filter(None, [first_name, last_name])).strip()
                user.name = name or user.username
                if telegram_id in role_bindings:
                    user.role = role_bindings[telegram_id]
                elif not user.role:
                    user.role = "user"

                now = utcnow()
                old_profile = user.profile_data or {}
                last_seen_raw = old_profile.get("last_seen")
                last_seen = None
                if isinstance(last_seen_raw, str):
                    try:
                        last_seen = datetime.fromisoformat(last_seen_raw)
                        if last_seen.tzinfo is None:
                            last_seen = last_seen.replace(tzinfo=timezone.utc)
                    except ValueError:
                        last_seen = None

                cooldown_minutes = int(os.getenv("ANIMATION_COOLDOWN_MINUTES", "720"))
                show_long_intro = last_seen is None or now - last_seen > timedelta(minutes=cooldown_minutes)

                merged_profile = {
                    **old_profile,
                    **user_data,
                    "last_seen": now.isoformat(),
                    "visit_count": int(old_profile.get("visit_count", 0)) + 1,
                }
                user.profile_data = merged_profile
                applied_pending_bindings = _apply_pending_bindings_for_user(db, user)
                db.commit()

                raw_session_token, raw_csrf_token = _new_session(db, user, init_data)
        except SQLAlchemyError:
            app.logger.exception("tg_auth: database error")
            return jsonify({"ok": False, "error": "Database error, please try again later"}), 500

        response = make_response(
            jsonify(
                {
                    "ok": True,
                    "user": user_data,
                    "first_visit": last_seen is None,
                    "show_long_intro": show_long_intro,
                    "applied_pending_bindings": applied_pending_bindings,
                    "csrf_token": raw_csrf_token,
                }
            )
        )
        cookie_secure = _env_bool("COOKIE_SECURE", True)
        same_site = os.getenv("COOKIE_SAMESITE", "Lax").strip().capitalize()
        if same_site not in {"Lax", "Strict", "None"}:
            same_site = "Lax"
        response.set_cookie(
            session_cookie_name,
            raw_session_token,
            httponly=True,
            secure=cookie_secure,
            samesite=same_site,
            max_age=session_ttl_days * 24 * 60 * 60,
            path="/",
        )
        return response

    @app.post("/api/auth/logout")
    def logout():
        raw_token = request.cookies.get(session_cookie_name)
        if raw_token:
            token_hash = _token_hash(raw_token)
            with SessionLocal() as db:
                db.query(AuthSession).filter(AuthSession.session_token == token_hash).delete()
                db.commit()

        response = make_response(jsonify({"ok": True}))
        response.delete_cookie(session_cookie_name, path="/")
        return response

    @app.get("/api/me")
    def me():
        auth, err = _auth_context()
        if err:
            return err

        with SessionLocal() as db:
            user = db.query(User).filter(User.id == auth["user_id"]).first()
            if not user:
                return jsonify({"ok": False, "error": "Unauthorized"}), 401

            sub = _active_subscription(db, user.id)
            cloud_enabled = _cloud_visibility_enabled(db)
            return jsonify(
                {
                    "ok": True,
                    "user": {
                        "id": user.id,
                        "telegram_id": user.telegram_id,
                        "username": user.username,
                        "name": user.name,
                        "role": user.role,
                    },
                    "subscription": None
                    if not sub
                    else {
                        "status": sub.status,
                        "access_until": sub.access_until.isoformat() if sub.access_until else None,
                        "price_amount": str(sub.price_amount) if sub.price_amount is not None else None,
                    },
                    "features": {
                        "cloud_enabled": cloud_enabled,
                    },
                }
            )

    @app.get("/api/vpn/config")
    def vpn_config():
        auth, err = _auth_context()
        if err:
            return err

        host = os.getenv("PUBLIC_VPN_HOST") or request.host.split(":")[0]
        subscription_cache: dict[str, list[str]] = {}

        with SessionLocal() as db:
            sub = _active_subscription(db, auth["user_id"])
            if not sub:
                return jsonify({"ok": False, "error": "Active subscription required"}), 403

            candidates, selected, strategy, selected_member_id = _resolve_selected_candidate(db, auth["user_id"], "vless")
            if not candidates:
                return jsonify({"ok": False, "error": "Visible VLESS account not found"}), 404

            connections: list[dict] = []
            servers: list[dict] = []
            for item in candidates:
                account = item["account"]
                inbound = item["inbound"]
                port = int(inbound.port)
                meta = account.meta_json or {}
                subscription_url = meta.get("sub_url")
                subscription_urls = _build_subscription_urls(meta.get("sub_id"), subscription_url)

                vless_url = meta.get("vless_url")
                if not vless_url and subscription_urls:
                    for candidate_url in subscription_urls:
                        cached_links = subscription_cache.get(candidate_url)
                        if cached_links is None:
                            cached_links = _load_subscription_links(candidate_url, quiet=True)
                            subscription_cache[candidate_url] = cached_links
                        if not cached_links:
                            continue
                        picked = _pick_vless_from_subscription(cached_links, account.identifier)
                        if not picked:
                            continue
                        vless_url = picked
                        subscription_url = candidate_url
                        break
                    if not vless_url and subscription_urls:
                        subscription_url = subscription_urls[0]
                if not vless_url and account.identifier:
                    query_params = {
                        "type": meta.get("type", "tcp"),
                        "security": meta.get("security", "reality"),
                        "flow": meta.get("flow", "xtls-rprx-vision"),
                        "sni": meta.get("sni", host),
                        "fp": meta.get("fp", "chrome"),
                    }
                    if meta.get("pbk"):
                        query_params["pbk"] = meta.get("pbk")
                    if meta.get("sid"):
                        query_params["sid"] = meta.get("sid")
                    q = urlencode({k: v for k, v in query_params.items() if v})
                    label = quote(account.label or "lumica")
                    vless_url = f"vless://{account.identifier}@{host}:{port}?{q}#{label}"
                if vless_url:
                    vless_url = _apply_vless_display_name(vless_url, account.label, account.identifier)

                panel_inbound_id = account.panel_inbound_id
                if panel_inbound_id is None:
                    try:
                        panel_inbound_id = int(getattr(inbound, "external_inbound_id", ""))
                    except (TypeError, ValueError):
                        panel_inbound_id = None

                connections.append(
                    {
                        "account_id": account.id,
                        "label": account.label or account.identifier or f"vless-{account.id}",
                        "identifier": account.identifier,
                        "panel_inbound_id": panel_inbound_id,
                        "panel_inbound_ref_id": account.panel_inbound_ref_id,
                        "inbound_remark": inbound.remark,
                        "panel_id": item.get("panel_id"),
                        "panel_name": item.get("panel_name"),
                        "region": item.get("region"),
                        "member_id": item.get("member_id"),
                        "selected": bool(selected and selected.get("account").id == account.id),
                        "host": host,
                        "port": port,
                        "sub_id": meta.get("sub_id"),
                        "subscription_url": subscription_url,
                        "vless_url": vless_url,
                    }
                )
                servers.append(
                    {
                        "member_id": item.get("member_id"),
                        "label": account.label or account.identifier or f"vless-{account.id}",
                        "panel_id": item.get("panel_id"),
                        "panel_name": item.get("panel_name"),
                        "region": item.get("region"),
                        "selected": bool(selected and selected.get("account").id == account.id),
                    }
                )

            first = connections[0]
            db.commit()

            return jsonify(
                {
                    "ok": True,
                    "protocol": "vless",
                    "group_key": "vless",
                    "selected_member_id": selected_member_id,
                    "applied_strategy": strategy,
                    "host": first.get("host"),
                    "port": first.get("port"),
                    "identifier": first.get("identifier"),
                    "sub_id": first.get("sub_id"),
                    "subscription_url": first.get("subscription_url"),
                    "vless_url": first.get("vless_url"),
                    "servers": servers,
                    "connections": connections,
                    "total": len(connections),
                }
            )

    @app.get("/api/vpn/mixed")
    def vpn_mixed():
        auth, err = _auth_context()
        if err:
            return err

        host = os.getenv("PUBLIC_VPN_HOST") or request.host.split(":")[0]

        with SessionLocal() as db:
            sub = _active_subscription(db, auth["user_id"])
            if not sub:
                return jsonify({"ok": False, "error": "Active subscription required"}), 403

            candidates, selected, strategy, selected_member_id = _resolve_selected_candidate(db, auth["user_id"], "mixed")
            if not candidates:
                return jsonify({"ok": False, "error": "Visible MIXED account not found"}), 404

            connections: list[dict] = []
            servers: list[dict] = []
            for item in candidates:
                account = item["account"]
                inbound = item["inbound"]
                port = int(inbound.port)
                username = account.identifier
                password = account.secret
                if not username or not password:
                    continue

                socks_url = f"socks5://{username}:{password}@{host}:{port}"
                http_url = f"http://{username}:{password}@{host}:{port}"
                panel_inbound_id = account.panel_inbound_id
                if panel_inbound_id is None:
                    try:
                        panel_inbound_id = int(getattr(inbound, "external_inbound_id", ""))
                    except (TypeError, ValueError):
                        panel_inbound_id = None
                connections.append(
                    {
                        "account_id": account.id,
                        "label": account.label or account.identifier or f"mixed-{account.id}",
                        "identifier": account.identifier,
                        "panel_inbound_id": panel_inbound_id,
                        "panel_inbound_ref_id": account.panel_inbound_ref_id,
                        "inbound_remark": inbound.remark,
                        "panel_id": item.get("panel_id"),
                        "panel_name": item.get("panel_name"),
                        "region": item.get("region"),
                        "member_id": item.get("member_id"),
                        "selected": bool(selected and selected.get("account").id == account.id),
                        "host": host,
                        "port": port,
                        "username": username,
                        "password": password,
                        "urls": [socks_url, http_url],
                    }
                )
                servers.append(
                    {
                        "member_id": item.get("member_id"),
                        "label": account.label or account.identifier or f"mixed-{account.id}",
                        "panel_id": item.get("panel_id"),
                        "panel_name": item.get("panel_name"),
                        "region": item.get("region"),
                        "selected": bool(selected and selected.get("account").id == account.id),
                    }
                )

            if not connections:
                return jsonify({"ok": False, "error": "Visible MIXED accounts have no credentials"}), 409

            first = connections[0]
            db.commit()

            return jsonify(
                {
                    "ok": True,
                    "protocol": "mixed",
                    "group_key": "socks5",
                    "selected_member_id": selected_member_id,
                    "applied_strategy": strategy,
                    "host": first.get("host"),
                    "port": first.get("port"),
                    "username": first.get("username"),
                    "password": first.get("password"),
                    "urls": first.get("urls"),
                    "servers": servers,
                    "connections": connections,
                    "total": len(connections),
                }
            )

    @app.get("/api/vpn/http")
    def vpn_http():
        auth, err = _auth_context()
        if err:
            return err

        host = os.getenv("PUBLIC_VPN_HOST") or request.host.split(":")[0]

        with SessionLocal() as db:
            sub = _active_subscription(db, auth["user_id"])
            if not sub:
                return jsonify({"ok": False, "error": "Active subscription required"}), 403

            candidates, selected, strategy, selected_member_id = _resolve_selected_candidate(db, auth["user_id"], "http")
            if not candidates:
                return jsonify({"ok": False, "error": "Visible HTTP account not found"}), 404

            connections: list[dict] = []
            servers: list[dict] = []
            for item in candidates:
                account = item["account"]
                inbound = item["inbound"]
                port = int(inbound.port)
                username = account.identifier
                password = account.secret
                if not username or not password:
                    continue

                http_url = f"http://{username}:{password}@{host}:{port}"
                panel_inbound_id = account.panel_inbound_id
                if panel_inbound_id is None:
                    try:
                        panel_inbound_id = int(getattr(inbound, "external_inbound_id", ""))
                    except (TypeError, ValueError):
                        panel_inbound_id = None
                connections.append(
                    {
                        "account_id": account.id,
                        "label": account.label or account.identifier or f"http-{account.id}",
                        "identifier": account.identifier,
                        "panel_inbound_id": panel_inbound_id,
                        "panel_inbound_ref_id": account.panel_inbound_ref_id,
                        "inbound_remark": inbound.remark,
                        "panel_id": item.get("panel_id"),
                        "panel_name": item.get("panel_name"),
                        "region": item.get("region"),
                        "member_id": item.get("member_id"),
                        "selected": bool(selected and selected.get("account").id == account.id),
                        "host": host,
                        "port": port,
                        "username": username,
                        "password": password,
                        "urls": [http_url],
                    }
                )
                servers.append(
                    {
                        "member_id": item.get("member_id"),
                        "label": account.label or account.identifier or f"http-{account.id}",
                        "panel_id": item.get("panel_id"),
                        "panel_name": item.get("panel_name"),
                        "region": item.get("region"),
                        "selected": bool(selected and selected.get("account").id == account.id),
                    }
                )

            if not connections:
                return jsonify({"ok": False, "error": "Visible HTTP accounts have no credentials"}), 409

            first = connections[0]
            db.commit()
            return jsonify(
                {
                    "ok": True,
                    "protocol": "http",
                    "group_key": "socks5",
                    "selected_member_id": selected_member_id,
                    "applied_strategy": strategy,
                    "host": first.get("host"),
                    "port": first.get("port"),
                    "username": first.get("username"),
                    "password": first.get("password"),
                    "urls": first.get("urls"),
                    "servers": servers,
                    "connections": connections,
                    "total": len(connections),
                }
            )

    def _serialize_panel(panel: Panel) -> dict:
        return {
            "id": panel.id,
            "name": panel.name,
            "provider": panel.provider,
            "base_url": panel.base_url,
            "auth_type": panel.auth_type,
            "auth_secret_ref": panel.auth_secret_ref,
            "is_active": bool(panel.is_active),
            "is_default": bool(panel.is_default),
            "region": panel.region,
            "health_status": panel.health_status,
            "last_ok_at": panel.last_ok_at.isoformat() if panel.last_ok_at else None,
            "error_message": panel.error_message,
            "created_at": panel.created_at.isoformat() if panel.created_at else None,
            "updated_at": panel.updated_at.isoformat() if panel.updated_at else None,
        }

    @app.get("/api/admin/panels")
    def admin_panels_list():
        _, err = _auth_context(require_role="admin")
        if err:
            return err
        with SessionLocal() as db:
            rows = db.query(Panel).order_by(Panel.is_default.desc(), Panel.created_at.asc()).all()
            return jsonify({"ok": True, "panels": [_serialize_panel(row) for row in rows]})

    @app.post("/api/admin/panels/test-connection")
    def admin_panels_test_connection():
        _, err = _auth_context(require_role="admin")
        if err:
            return err
        body = request.get_json(silent=True) or {}
        provider = _normalize_panel_provider(body.get("provider"))
        base_url = str(body.get("base_url") or "").strip()
        auth_type = str(body.get("auth_type") or "login_password").strip().lower() or "login_password"
        if not base_url:
            return jsonify({"ok": False, "error": "base_url is required"}), 400
        auth_payload = {
            "username": str(body.get("username") or body.get("login") or "").strip(),
            "password": str(body.get("password") or "").strip(),
            "token": str(body.get("token") or "").strip(),
        }
        panel_stub = Panel(
            id=str(uuid4()),
            name=str(body.get("name") or "Panel").strip() or "Panel",
            provider=provider,
            base_url=base_url,
            auth_type=auth_type,
            auth_secret_ref=str(uuid4()),
            is_active=1,
            is_default=0,
        )
        try:
            result = panel_registry.get_provider(provider).health_check(panel_stub, auth_payload)
            return jsonify({"ok": True, "result": result})
        except Exception as exc:
            return jsonify({"ok": False, "error": str(exc)}), 502

    @app.post("/api/admin/panels")
    def admin_panels_create():
        _, err = _auth_context(require_role="admin")
        if err:
            return err
        body = request.get_json(silent=True) or {}
        name = str(body.get("name") or "").strip()
        base_url = str(body.get("base_url") or "").strip()
        provider = _normalize_panel_provider(body.get("provider"))
        auth_type = str(body.get("auth_type") or "login_password").strip().lower() or "login_password"
        if not name:
            return jsonify({"ok": False, "error": "name is required"}), 400
        if not base_url:
            return jsonify({"ok": False, "error": "base_url is required"}), 400

        secret_payload = {
            "username": str(body.get("username") or body.get("login") or "").strip(),
            "password": str(body.get("password") or "").strip(),
            "token": str(body.get("token") or "").strip(),
        }
        with SessionLocal() as db:
            secret = PanelSecret(
                id=str(uuid4()),
                provider=provider,
                auth_type=auth_type,
                ciphertext=encrypt_payload(secret_payload),
            )
            db.add(secret)
            db.flush()

            row = Panel(
                id=str(uuid4()),
                name=name[:120],
                provider=provider,
                base_url=base_url[:512],
                auth_type=auth_type,
                auth_secret_ref=secret.id,
                is_active=1 if body.get("is_active", True) else 0,
                is_default=1 if body.get("is_default") else 0,
                region=(str(body.get("region") or "").strip()[:16] or None),
                health_status="unknown",
            )
            if row.is_default:
                db.query(Panel).update({"is_default": 0})
            db.add(row)
            db.commit()
            return jsonify({"ok": True, "panel": _serialize_panel(row)})

    @app.post("/api/admin/panels/<panel_id>")
    def admin_panels_update(panel_id: str):
        _, err = _auth_context(require_role="admin")
        if err:
            return err
        body = request.get_json(silent=True) or {}
        with SessionLocal() as db:
            row = db.query(Panel).filter(Panel.id == panel_id).first()
            if not row:
                return jsonify({"ok": False, "error": "Panel not found"}), 404
            if "name" in body:
                row.name = str(body.get("name") or "").strip()[:120] or row.name
            if "base_url" in body:
                base_url = str(body.get("base_url") or "").strip()
                if base_url:
                    row.base_url = base_url[:512]
            if "provider" in body:
                row.provider = _normalize_panel_provider(body.get("provider"))
            if "region" in body:
                row.region = str(body.get("region") or "").strip()[:16] or None
            if "auth_type" in body:
                row.auth_type = str(body.get("auth_type") or "").strip().lower() or row.auth_type
            db.commit()
            return jsonify({"ok": True, "panel": _serialize_panel(row)})

    @app.post("/api/admin/panels/<panel_id>/rotate-secret")
    def admin_panels_rotate_secret(panel_id: str):
        _, err = _auth_context(require_role="admin")
        if err:
            return err
        body = request.get_json(silent=True) or {}
        with SessionLocal() as db:
            panel = db.query(Panel).filter(Panel.id == panel_id).first()
            if not panel:
                return jsonify({"ok": False, "error": "Panel not found"}), 404
            secret = db.query(PanelSecret).filter(PanelSecret.id == panel.auth_secret_ref).first()
            if not secret:
                return jsonify({"ok": False, "error": "Panel secret not found"}), 404

            payload = {
                "username": str(body.get("username") or body.get("login") or "").strip(),
                "password": str(body.get("password") or "").strip(),
                "token": str(body.get("token") or "").strip(),
            }
            secret.auth_type = str(body.get("auth_type") or panel.auth_type).strip().lower() or panel.auth_type
            secret.ciphertext = encrypt_payload(payload)
            panel.auth_type = secret.auth_type
            panel_registry.invalidate_panel(panel.id)
            db.commit()
            return jsonify({"ok": True, "panel": _serialize_panel(panel)})

    @app.post("/api/admin/panels/<panel_id>/activate")
    def admin_panels_activate(panel_id: str):
        _, err = _auth_context(require_role="admin")
        if err:
            return err
        body = request.get_json(silent=True) or {}
        is_active = 1 if body.get("is_active", True) else 0
        with SessionLocal() as db:
            panel = db.query(Panel).filter(Panel.id == panel_id).first()
            if not panel:
                return jsonify({"ok": False, "error": "Panel not found"}), 404
            panel.is_active = is_active
            db.commit()
            return jsonify({"ok": True, "panel": _serialize_panel(panel)})

    @app.post("/api/admin/panels/<panel_id>/set-default")
    def admin_panels_set_default(panel_id: str):
        _, err = _auth_context(require_role="admin")
        if err:
            return err
        with SessionLocal() as db:
            panel = db.query(Panel).filter(Panel.id == panel_id).first()
            if not panel:
                return jsonify({"ok": False, "error": "Panel not found"}), 404
            db.query(Panel).update({"is_default": 0})
            panel.is_default = 1
            db.commit()
            return jsonify({"ok": True, "panel": _serialize_panel(panel)})

    @app.post("/api/admin/panels/<panel_id>/sync-inbounds")
    def admin_panel_sync_inbounds(panel_id: str):
        _, err = _auth_context(require_role="admin")
        if err:
            return err
        with SessionLocal() as db:
            panel = db.query(Panel).filter(Panel.id == panel_id, Panel.is_active == 1).first()
            if not panel:
                return jsonify({"ok": False, "error": "Panel not found or inactive"}), 404
            try:
                provider = panel_registry.get_provider(panel.provider)
                auth_payload = panel_registry.get_auth_payload(db, panel)
                items = provider.list_inbounds(panel, auth_payload)
                seen: set[str] = set()
                for item in items:
                    row = _sync_single_inbound_from_panel(db, item, panel=panel)
                    seen.add(row.external_inbound_id)
                stale_rows = db.query(PanelInbound).filter(PanelInbound.panel_id == panel.id).all()
                stale_disabled = 0
                for stale in stale_rows:
                    if stale.external_inbound_id in seen:
                        continue
                    stale.enabled = 0
                    stale.last_sync_at = utcnow()
                    stale_disabled += 1
                panel.health_status = "green"
                panel.last_ok_at = utcnow()
                panel.error_message = None
                sync_group_members_from_inbounds(db)
                db.commit()
                return jsonify({"ok": True, "upserted": len(seen), "stale_disabled": stale_disabled})
            except Exception as exc:
                panel_registry.invalidate_panel(panel.id)
                panel.health_status = "red"
                panel.error_message = str(exc)[:500]
                db.commit()
                return jsonify({"ok": False, "error": str(exc)}), 502

    @app.get("/api/admin/panel-inbounds")
    def admin_panel_inbounds_list():
        _, err = _auth_context(require_role="admin")
        if err:
            return err
        with SessionLocal() as db:
            rows = (
                db.query(PanelInbound, Panel)
                .join(Panel, Panel.id == PanelInbound.panel_id)
                .order_by(Panel.name.asc(), PanelInbound.id.asc())
                .all()
            )
            payload = []
            for inbound, panel in rows:
                payload.append(
                    {
                        "id": inbound.id,
                        "panel_id": panel.id,
                        "panel_name": panel.name,
                        "provider": panel.provider,
                        "region": panel.region,
                        "external_inbound_id": inbound.external_inbound_id,
                        "protocol": inbound.protocol,
                        "port": inbound.port,
                        "remark": inbound.remark,
                        "listen": inbound.listen,
                        "enabled": bool(inbound.enabled),
                        "show_in_app": bool(inbound.show_in_app),
                        "last_sync_at": inbound.last_sync_at.isoformat() if inbound.last_sync_at else None,
                        "updated_at": inbound.updated_at.isoformat() if inbound.updated_at else None,
                    }
                )
            return jsonify({"ok": True, "inbounds": payload})

    @app.post("/api/admin/panel-inbounds/<int:panel_inbound_ref_id>/visibility")
    def admin_panel_inbound_visibility(panel_inbound_ref_id: int):
        _, err = _auth_context(require_role="admin")
        if err:
            return err
        body = request.get_json(silent=True) or {}
        if "show_in_app" not in body:
            return jsonify({"ok": False, "error": "show_in_app is required"}), 400
        with SessionLocal() as db:
            inbound = db.query(PanelInbound).filter(PanelInbound.id == panel_inbound_ref_id).first()
            if not inbound:
                return jsonify({"ok": False, "error": "Panel inbound not found"}), 404
            inbound.show_in_app = 1 if body.get("show_in_app") else 0
            panel = db.query(Panel).filter(Panel.id == inbound.panel_id).first()
            if panel and panel.is_default:
                try:
                    legacy_id = int(inbound.external_inbound_id)
                except (TypeError, ValueError):
                    legacy_id = None
                if legacy_id is not None:
                    legacy = db.query(Inbound).filter(Inbound.panel_inbound_id == legacy_id).first()
                    if legacy:
                        legacy.show_in_app = inbound.show_in_app
            db.commit()
            return jsonify(
                {
                    "ok": True,
                    "inbound": {
                        "id": inbound.id,
                        "show_in_app": bool(inbound.show_in_app),
                    },
                }
            )

    @app.get("/api/admin/panel-inbounds/<int:panel_inbound_ref_id>/clients")
    def admin_panel_inbound_clients(panel_inbound_ref_id: int):
        _, err = _auth_context(require_role="admin")
        if err:
            return err
        with SessionLocal() as db:
            inbound = db.query(PanelInbound).filter(PanelInbound.id == panel_inbound_ref_id).first()
            if not inbound:
                return jsonify({"ok": False, "error": "Panel inbound not found"}), 404
            clients = extract_clients_from_panel_inbound(inbound)
            return jsonify(
                {
                    "ok": True,
                    "panel_inbound_ref_id": inbound.id,
                    "external_inbound_id": inbound.external_inbound_id,
                    "protocol": inbound.protocol,
                    "clients": clients,
                }
            )

    @app.post("/api/admin/panel-inbounds/<int:panel_inbound_ref_id>/clients")
    def admin_panel_inbound_clients_create(panel_inbound_ref_id: int):
        _, err = _auth_context(require_role="admin")
        if err:
            return err
        body = request.get_json(silent=True) or {}
        label = str(body.get("label") or body.get("email") or "").strip()
        if not label:
            return jsonify({"ok": False, "error": "label is required"}), 400
        with SessionLocal() as db:
            inbound = db.query(PanelInbound).filter(PanelInbound.id == panel_inbound_ref_id).first()
            if not inbound:
                return jsonify({"ok": False, "error": "Panel inbound not found"}), 404
            panel = db.query(Panel).filter(Panel.id == inbound.panel_id).first()
            if not panel:
                return jsonify({"ok": False, "error": "Panel not found"}), 404
            protocol = str(inbound.protocol or "").strip().lower()
            if protocol != "vless":
                return jsonify({"ok": False, "error": "Only VLESS panel inbounds support add client"}), 400
            existing = extract_clients_from_panel_inbound(inbound)
            existing_labels = {str(item.get("label") or "").strip().lower() for item in existing}
            if label.lower() in existing_labels:
                return jsonify({"ok": False, "error": "Client with this label already exists"}), 409
            client_id = str(uuid4())
            client_payload = {
                "id": client_id,
                "email": label[:64],
                "flow": str(body.get("flow") or "xtls-rprx-vision").strip() or "xtls-rprx-vision",
                "limitIp": int(body.get("limit_ip") or 0),
                "totalGB": int(body.get("total_gb") or 0) * 1024 * 1024 * 1024,
                "expiryTime": 0,
                "enable": True,
                "tgId": 0,
                "subId": str(body.get("sub_id") or _generate_panel_sub_id()).strip()[:32] or _generate_panel_sub_id(),
                "reset": 0,
            }
            try:
                provider = panel_registry.get_provider(panel.provider)
                auth_payload = panel_registry.get_auth_payload(db, panel)
                panel_result = provider.create_client(panel, inbound, client_payload, auth_payload)
                items = provider.list_inbounds(panel, auth_payload)
                panel_item = next((item for item in items if str(item.get("id")) == str(inbound.external_inbound_id)), None)
                if panel_item:
                    inbound = _sync_single_inbound_from_panel(db, panel_item, panel=panel)
                clients = extract_clients_from_panel_inbound(inbound)
                db.commit()
                return jsonify(
                    {
                        "ok": True,
                        "panel_inbound_ref_id": inbound.id,
                        "created_client": next((item for item in clients if item.get("identifier") == client_id), None),
                        "clients": clients,
                        "panel_result": panel_result,
                    }
                )
            except Exception as exc:
                return jsonify({"ok": False, "error": str(exc)}), 502

    @app.get("/api/admin/inbound-groups")
    def admin_inbound_groups_list():
        _, err = _auth_context(require_role="admin")
        if err:
            return err
        with SessionLocal() as db:
            groups = db.query(InboundGroup).order_by(InboundGroup.sort.asc(), InboundGroup.id.asc()).all()
            payload = []
            for group in groups:
                members = (
                    db.query(InboundGroupMember, PanelInbound, Panel)
                    .join(PanelInbound, PanelInbound.id == InboundGroupMember.panel_inbound_id)
                    .join(Panel, Panel.id == PanelInbound.panel_id)
                    .filter(InboundGroupMember.group_id == group.id)
                    .order_by(InboundGroupMember.priority.asc(), InboundGroupMember.id.asc())
                    .all()
                )
                payload.append(
                    {
                        "id": group.id,
                        "key": group.key,
                        "title": group.title,
                        "visible": bool(group.visible),
                        "sort": group.sort,
                        "members": [
                            {
                                "id": member.id,
                                "panel_inbound_id": member.panel_inbound_id,
                                "external_inbound_id": inbound.external_inbound_id,
                                "panel_id": panel.id,
                                "panel_name": panel.name,
                                "label": member.label,
                                "priority": member.priority,
                                "is_active": bool(member.is_active),
                            }
                            for member, inbound, panel in members
                        ],
                    }
                )
            return jsonify({"ok": True, "groups": payload})

    @app.post("/api/admin/inbound-groups")
    def admin_inbound_groups_create():
        _, err = _auth_context(require_role="admin")
        if err:
            return err
        body = request.get_json(silent=True) or {}
        key = str(body.get("key") or "").strip().lower()
        title = str(body.get("title") or "").strip()
        if not key or not title:
            return jsonify({"ok": False, "error": "key and title are required"}), 400
        with SessionLocal() as db:
            existing = db.query(InboundGroup).filter(InboundGroup.key == key).first()
            if existing:
                return jsonify({"ok": False, "error": "Group key already exists"}), 409
            row = InboundGroup(
                key=key[:32],
                title=title[:64],
                visible=1 if body.get("visible", True) else 0,
                sort=int(body.get("sort") or 100),
            )
            db.add(row)
            db.commit()
            return jsonify({"ok": True, "group": {"id": row.id, "key": row.key, "title": row.title}})

    @app.post("/api/admin/inbound-groups/<int:group_id>")
    def admin_inbound_groups_update(group_id: int):
        _, err = _auth_context(require_role="admin")
        if err:
            return err
        body = request.get_json(silent=True) or {}
        with SessionLocal() as db:
            row = db.query(InboundGroup).filter(InboundGroup.id == group_id).first()
            if not row:
                return jsonify({"ok": False, "error": "Group not found"}), 404
            if "title" in body:
                title = str(body.get("title") or "").strip()
                if title:
                    row.title = title[:64]
            if "visible" in body:
                row.visible = 1 if body.get("visible") else 0
            if "sort" in body:
                row.sort = int(body.get("sort") or row.sort)
            db.commit()
            return jsonify({"ok": True})

    @app.post("/api/admin/inbound-groups/<int:group_id>/members/upsert")
    def admin_inbound_group_members_upsert(group_id: int):
        _, err = _auth_context(require_role="admin")
        if err:
            return err
        body = request.get_json(silent=True) or {}
        panel_inbound_id = body.get("panel_inbound_id")
        if not panel_inbound_id:
            return jsonify({"ok": False, "error": "panel_inbound_id is required"}), 400
        with SessionLocal() as db:
            group = db.query(InboundGroup).filter(InboundGroup.id == group_id).first()
            if not group:
                return jsonify({"ok": False, "error": "Group not found"}), 404
            inbound = db.query(PanelInbound).filter(PanelInbound.id == int(panel_inbound_id)).first()
            if not inbound:
                return jsonify({"ok": False, "error": "Panel inbound not found"}), 404
            row = (
                db.query(InboundGroupMember)
                .filter(
                    InboundGroupMember.group_id == group.id,
                    InboundGroupMember.panel_inbound_id == inbound.id,
                )
                .first()
            )
            if not row:
                row = InboundGroupMember(group_id=group.id, panel_inbound_id=inbound.id)
                db.add(row)
            row.label = str(body.get("label") or inbound.remark or "").strip()[:120] or None
            row.priority = int(body.get("priority") or 100)
            row.is_active = 1 if body.get("is_active", True) else 0
            db.commit()
            return jsonify({"ok": True, "member_id": row.id})

    @app.post("/api/admin/inbound-groups/<int:group_id>/members/<int:member_id>/delete")
    def admin_inbound_group_members_delete(group_id: int, member_id: int):
        _, err = _auth_context(require_role="admin")
        if err:
            return err
        with SessionLocal() as db:
            row = (
                db.query(InboundGroupMember)
                .filter(InboundGroupMember.id == member_id, InboundGroupMember.group_id == group_id)
                .first()
            )
            if not row:
                return jsonify({"ok": False, "error": "Group member not found"}), 404
            db.delete(row)
            db.commit()
            return jsonify({"ok": True, "deleted": True})

    @app.post("/api/vpn/select-server")
    def vpn_select_server():
        auth, err = _auth_context()
        if err:
            return err
        body = request.get_json(silent=True) or {}
        group_key = str(body.get("group_key") or "").strip().lower()
        member_id_raw = body.get("member_id")
        strategy_raw = body.get("strategy")
        strategy = (
            _normalize_selection_strategy(strategy_raw)
            if strategy_raw not in (None, "")
            else "manual"
        )
        if group_key not in {"vless", "socks5"}:
            return jsonify({"ok": False, "error": "group_key must be vless or socks5"}), 400
        try:
            member_id = int(member_id_raw)
        except (TypeError, ValueError):
            return jsonify({"ok": False, "error": "member_id must be an integer"}), 400

        with SessionLocal() as db:
            user_conn = _ensure_user_connection(db, auth["user_id"], group_key)
            if not user_conn:
                return jsonify({"ok": False, "error": "Group not found"}), 404
            member = (
                db.query(InboundGroupMember)
                .filter(
                    InboundGroupMember.id == member_id,
                    InboundGroupMember.group_id == user_conn.group_id,
                    InboundGroupMember.is_active == 1,
                )
                .first()
            )
            if not member:
                return jsonify({"ok": False, "error": "Group member not found or inactive"}), 404
            user_conn.selected_member_id = member.id
            user_conn.selection_strategy = strategy
            db.commit()
            return jsonify(
                {
                    "ok": True,
                    "selected_member_id": member.id,
                    "applied_strategy": user_conn.selection_strategy,
                }
            )

    return app


if __name__ == "__main__":
    app = create_app()
    host = os.getenv("FLASK_HOST", "0.0.0.0")
    port = int(os.getenv("FLASK_PORT", "8000"))
    app.run(host=host, port=port)
