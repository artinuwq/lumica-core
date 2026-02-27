import hashlib
import hmac
import json
import mimetypes
import os
import secrets
import socket
from decimal import Decimal, InvalidOperation
from datetime import datetime, timedelta, timezone
from pathlib import Path
from urllib.parse import quote, urlencode, urlparse

import psutil
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
    PendingBinding,
    Subscription,
    User,
    VpnAccount,
)
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

    session_cookie_name = os.getenv("SESSION_COOKIE_NAME", "session")
    session_ttl_days = int(os.getenv("SESSION_TTL_DAYS", "7"))
    role_bindings = _load_role_bindings()
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

        db.query(AuthSession).filter(AuthSession.expires_at < utcnow()).delete()
        db.add(
            AuthSession(
                user_id=user.id,
                init_data={"raw": init_data[:4096], "csrf_hash": csrf_hash},
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
            if account.panel_inbound_id is None:
                continue
            inbound = db.query(Inbound).filter(Inbound.panel_inbound_id == account.panel_inbound_id).first()
            if not inbound or not inbound.port:
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
        return {
            "ok": check_port("127.0.0.1", int(inbound.port)),
            "configured": True,
            "port": int(inbound.port),
            "panel_inbound_id": inbound.panel_inbound_id,
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
        panel_inbound_id: int,
        protocol: str,
        identifier: str,
        label: str | None = None,
        secret: str | None = None,
        sub_id: str | None = None,
    ) -> VpnAccount:
        normalized_protocol = _normalize_account_protocol(protocol)
        if normalized_protocol not in {"vless", "mixed"}:
            raise ValueError("protocol must be vless or mixed")

        account = (
            db.query(VpnAccount)
            .filter(
                VpnAccount.user_id == int(user_id),
                VpnAccount.protocol == normalized_protocol,
                VpnAccount.panel_inbound_id == int(panel_inbound_id),
                VpnAccount.identifier == identifier,
            )
            .order_by(VpnAccount.id.desc())
            .first()
        )
        if not account:
            account = VpnAccount(user_id=int(user_id), protocol=normalized_protocol)
            db.add(account)

        meta = account.meta_json if isinstance(account.meta_json, dict) else {}
        if sub_id:
            meta["sub_id"] = str(sub_id)

        account.panel_inbound_id = int(panel_inbound_id)
        account.identifier = identifier
        account.label = label or identifier
        account.secret = secret if normalized_protocol == "mixed" else None
        account.meta_json = meta
        account.status = "active"
        return account

    def _serialize_pending_binding(db, row: PendingBinding) -> dict:
        inbound = db.query(Inbound).filter(Inbound.panel_inbound_id == row.panel_inbound_id).first()
        meta = row.meta_json if isinstance(row.meta_json, dict) else {}
        return {
            "id": row.id,
            "telegram_id": row.telegram_id,
            "status": row.status,
            "protocol": row.protocol,
            "panel_inbound_id": row.panel_inbound_id,
            "inbound_remark": inbound.remark if inbound else None,
            "inbound_port": inbound.port if inbound else None,
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
            inbound = db.query(Inbound).filter(Inbound.panel_inbound_id == row.panel_inbound_id).first()
            if not inbound:
                # Keep as pending so it can be retried after inbound sync/fix.
                continue

            sub_id = None
            if isinstance(row.meta_json, dict):
                sub_id = row.meta_json.get("sub_id")

            try:
                _upsert_vpn_account(
                    db,
                    user_id=user.id,
                    panel_inbound_id=row.panel_inbound_id,
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
                "system": system_stats(),
                "timestamp": datetime.utcnow().isoformat(),
            }
        )

    @app.post("/api/admin/sync-inbounds")
    def sync_inbounds():
        _, err = _auth_context(require_role="admin")
        if err:
            return err

        try:
            items = XUIClient().get_inbounds()
        except Exception as exc:
            app.logger.exception("sync inbounds failed")
            return jsonify({"ok": False, "error": str(exc)}), 500

        upserted = 0
        with SessionLocal() as db:
            for item in items:
                panel_id = item.get("id")
                if panel_id is None:
                    continue

                inbound = db.query(Inbound).filter(Inbound.panel_inbound_id == panel_id).first()
                if not inbound:
                    inbound = Inbound(panel_inbound_id=panel_id)
                    inbound.show_in_app = 1
                    db.add(inbound)

                inbound.protocol = item.get("protocol")
                inbound.port = item.get("port")
                inbound.remark = item.get("remark")
                inbound.listen = item.get("listen")
                inbound.enable = 1 if item.get("enable", True) else 0
                inbound.stream_settings = _safe_json(item.get("streamSettings"))
                inbound.settings = _safe_json(item.get("settings"))
                upserted += 1

            db.commit()

        return jsonify({"ok": True, "count": upserted})

    @app.get("/api/admin/inbounds")
    def list_inbounds():
        _, err = _auth_context(require_role="admin")
        if err:
            return err

        with SessionLocal() as db:
            rows = db.query(Inbound).order_by(Inbound.panel_inbound_id.asc()).all()
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
                        for r in rows
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
            inbound = db.query(Inbound).filter(Inbound.panel_inbound_id == panel_inbound_id).first()
            if not inbound:
                return jsonify({"ok": False, "error": "Inbound not found"}), 404

            inbound.show_in_app = 1 if body.get("show_in_app") else 0
            db.commit()

            return jsonify(
                {
                    "ok": True,
                    "inbound": {
                        "panel_inbound_id": inbound.panel_inbound_id,
                        "protocol": inbound.protocol,
                        "remark": inbound.remark,
                        "port": inbound.port,
                        "enable": bool(inbound.enable),
                        "show_in_app": bool(inbound.show_in_app),
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
                            "panel_inbound_id": a.panel_inbound_id,
                            "inbound_remark": (
                                inbounds_by_panel_id[a.panel_inbound_id].remark
                                if a.panel_inbound_id in inbounds_by_panel_id
                                else None
                            ),
                            "inbound_port": (
                                inbounds_by_panel_id[a.panel_inbound_id].port
                                if a.panel_inbound_id in inbounds_by_panel_id
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

            db.commit()
            db.refresh(user)
            return jsonify({"ok": True, "overview": _serialize_admin_user_overview(db, user)})

    @app.get("/api/admin/inbounds/<int:panel_inbound_id>/clients")
    def admin_inbound_clients(panel_inbound_id: int):
        _, err = _auth_context(require_role="admin")
        if err:
            return err

        with SessionLocal() as db:
            inbound = db.query(Inbound).filter(Inbound.panel_inbound_id == panel_inbound_id).first()
            if not inbound:
                return jsonify({"ok": False, "error": "Inbound not found"}), 404
            clients = _extract_clients_from_inbound(inbound)
            return jsonify(
                {
                    "ok": True,
                    "panel_inbound_id": panel_inbound_id,
                    "protocol": inbound.protocol,
                    "clients": clients,
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
        identifier = (body.get("client_identifier") or "").strip()
        protocol = _normalize_account_protocol(body.get("protocol"))
        label = body.get("label")
        secret = body.get("secret")
        sub_id = body.get("sub_id")

        if not user_id or not panel_inbound_id or not identifier:
            return jsonify({"ok": False, "error": "user_id, panel_inbound_id, client_identifier are required"}), 400
        if protocol not in {"vless", "mixed"}:
            return jsonify({"ok": False, "error": "protocol must be vless or mixed"}), 400

        with SessionLocal() as db:
            user = db.query(User).filter(User.id == int(user_id)).first()
            if not user:
                return jsonify({"ok": False, "error": "User not found"}), 404

            inbound = db.query(Inbound).filter(Inbound.panel_inbound_id == int(panel_inbound_id)).first()
            if not inbound:
                return jsonify({"ok": False, "error": "Inbound not found"}), 404

            account = _upsert_vpn_account(
                db,
                user_id=user.id,
                panel_inbound_id=int(panel_inbound_id),
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
            inbound = db.query(Inbound).filter(Inbound.panel_inbound_id == panel_inbound_id).first()
            if not inbound:
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

        with SessionLocal() as db:
            sub = _active_subscription(db, auth["user_id"])
            if not sub:
                return jsonify({"ok": False, "error": "Active subscription required"}), 403

            rows = _visible_accounts_for_protocol(db, auth["user_id"], "vless")
            if not rows:
                return jsonify({"ok": False, "error": "Visible VLESS account not found"}), 404

            connections: list[dict] = []
            for account, inbound in rows:
                port = int(inbound.port)
                meta = account.meta_json or {}
                subscription_url = meta.get("sub_url")
                if not subscription_url and meta.get("sub_id"):
                    tpl = os.getenv("PANEL_SUBSCRIPTION_URL_TEMPLATE", "")
                    public_base = os.getenv("PANEL_PUBLIC_BASE_URL", "").rstrip("/")
                    if tpl:
                        subscription_url = tpl.format(sub_id=meta.get("sub_id"), base_url=public_base)

                vless_url = meta.get("vless_url")
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

                connections.append(
                    {
                        "account_id": account.id,
                        "label": account.label or account.identifier or f"vless-{account.id}",
                        "identifier": account.identifier,
                        "panel_inbound_id": account.panel_inbound_id,
                        "inbound_remark": inbound.remark,
                        "host": host,
                        "port": port,
                        "sub_id": meta.get("sub_id"),
                        "subscription_url": subscription_url,
                        "vless_url": vless_url,
                    }
                )

            first = connections[0]

            return jsonify(
                {
                    "ok": True,
                    "protocol": "vless",
                    "host": first.get("host"),
                    "port": first.get("port"),
                    "identifier": first.get("identifier"),
                    "sub_id": first.get("sub_id"),
                    "subscription_url": first.get("subscription_url"),
                    "vless_url": first.get("vless_url"),
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

            rows = _visible_accounts_for_protocol(db, auth["user_id"], "mixed")
            if not rows:
                return jsonify({"ok": False, "error": "Visible MIXED account not found"}), 404

            connections: list[dict] = []
            for account, inbound in rows:
                port = int(inbound.port)
                username = account.identifier
                password = account.secret
                if not username or not password:
                    continue

                socks_url = f"socks5://{username}:{password}@{host}:{port}"
                http_url = f"http://{username}:{password}@{host}:{port}"
                connections.append(
                    {
                        "account_id": account.id,
                        "label": account.label or account.identifier or f"mixed-{account.id}",
                        "identifier": account.identifier,
                        "panel_inbound_id": account.panel_inbound_id,
                        "inbound_remark": inbound.remark,
                        "host": host,
                        "port": port,
                        "username": username,
                        "password": password,
                        "urls": [socks_url, http_url],
                    }
                )

            if not connections:
                return jsonify({"ok": False, "error": "Visible MIXED accounts have no credentials"}), 409

            first = connections[0]

            return jsonify(
                {
                    "ok": True,
                    "protocol": "mixed",
                    "host": first.get("host"),
                    "port": first.get("port"),
                    "username": first.get("username"),
                    "password": first.get("password"),
                    "urls": first.get("urls"),
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

            rows = _visible_accounts_for_protocol(db, auth["user_id"], "http")
            if not rows:
                return jsonify({"ok": False, "error": "Visible HTTP account not found"}), 404

            connections: list[dict] = []
            for account, inbound in rows:
                port = int(inbound.port)
                username = account.identifier
                password = account.secret
                if not username or not password:
                    continue

                http_url = f"http://{username}:{password}@{host}:{port}"
                connections.append(
                    {
                        "account_id": account.id,
                        "label": account.label or account.identifier or f"http-{account.id}",
                        "identifier": account.identifier,
                        "panel_inbound_id": account.panel_inbound_id,
                        "inbound_remark": inbound.remark,
                        "host": host,
                        "port": port,
                        "username": username,
                        "password": password,
                        "urls": [http_url],
                    }
                )

            if not connections:
                return jsonify({"ok": False, "error": "Visible HTTP accounts have no credentials"}), 409

            first = connections[0]
            return jsonify(
                {
                    "ok": True,
                    "protocol": "http",
                    "host": first.get("host"),
                    "port": first.get("port"),
                    "username": first.get("username"),
                    "password": first.get("password"),
                    "urls": first.get("urls"),
                    "connections": connections,
                    "total": len(connections),
                }
            )

    return app


if __name__ == "__main__":
    app = create_app()
    host = os.getenv("FLASK_HOST", "0.0.0.0")
    port = int(os.getenv("FLASK_PORT", "8000"))
    app.run(host=host, port=port)
