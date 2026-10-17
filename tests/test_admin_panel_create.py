import json
from datetime import datetime, timezone
from uuid import uuid4

from flask import Flask, jsonify, request
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from lumica.api.routes.admin import register_admin_routes
from lumica.domain.models import (
    Base,
    InboundGroup,
    InboundGroupMember,
    MiniAppLaunch,
    Panel,
    PanelInbound,
    PanelSecret,
    User,
    VpnAccount,
)


class FakeProvider:
    def __init__(self):
        self.should_fail = True

    def health_check(self, _panel, auth):
        assert auth.get("token") == "private-token"
        if self.should_fail:
            raise RuntimeError("panel is unavailable")
        return {"ok": True, "inbounds_count": 1}


class FakeRegistry:
    def __init__(self):
        self.provider = FakeProvider()

    def get_provider(self, _name):
        return self.provider

    def get_auth_payload(self, _db, _panel):
        return {}


def _serialize_panel(panel):
    return {
        "id": panel.id,
        "name": panel.name,
        "provider": panel.provider,
        "base_url": panel.base_url,
        "auth_type": panel.auth_type,
        "region": panel.region,
        "health_status": panel.health_status,
    }


def _create_test_app(factory, registry):
    app = Flask(__name__)
    register_admin_routes(app, {
        "_auth_context": lambda **_kwargs: ({"user_id": 1}, None),
        "request": request,
        "jsonify": jsonify,
        "_normalize_panel_provider": lambda value: value or "3xui",
        "panel_registry": registry,
        "Panel": Panel,
        "PanelSecret": PanelSecret,
        "User": User,
        "SessionLocal": factory,
        "encrypt_payload": lambda _payload: "encrypted-secret",
        "uuid4": uuid4,
        "utcnow": lambda: datetime.now(timezone.utc),
        "_serialize_panel": _serialize_panel,
    })
    return app


def test_panel_is_saved_only_after_successful_health_check():
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    factory = sessionmaker(bind=engine)
    registry = FakeRegistry()
    app = _create_test_app(factory, registry)
    client = app.test_client()
    payload = {
        "name": "de-1",
        "provider": "3xui",
        "base_url": "https://panel.example:2053/panel/api",
        "region": "de",
        "auth_type": "api_token",
        "token": "private-token",
    }

    failed = client.post("/api/admin/panels", json=payload)
    assert failed.status_code == 502
    with factory() as db:
        assert db.query(Panel).count() == 0
        assert db.query(PanelSecret).count() == 0

    registry.provider.should_fail = False
    saved = client.post("/api/admin/panels", json=payload)
    assert saved.status_code == 200
    response_text = json.dumps(saved.get_json())
    assert "private-token" not in response_text
    assert "auth_secret_ref" not in response_text
    with factory() as db:
        assert db.query(Panel).count() == 1
        assert db.query(PanelSecret).count() == 1


def test_known_user_search_only_returns_mini_app_launches():
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    factory = sessionmaker(bind=engine)
    with factory() as db:
        known = User(telegram_id="10001", name="Known")
        placeholder = User(name="Empty seat")
        db.add_all([known, placeholder])
        db.flush()
        db.add(MiniAppLaunch(user_id=known.id, url="https://app.example", status="opened"))
        db.commit()

    app = _create_test_app(factory, FakeRegistry())
    response = app.test_client().get("/api/admin/users/known")

    assert response.status_code == 200
    assert [user["name"] for user in response.get_json()["users"]] == ["Known"]
class FakeBindProvider:
    """Fake panel provider for bind-route tests."""

    def __init__(self, clients_by_email=None, list_clients=None):
        self.clients_by_email = clients_by_email or {}
        self.list_clients = list_clients or []
        self.created = None
        self.updated = None
        self.get_called = False

    def get_panel_client(self, _panel, _auth, email):
        self.get_called = True
        client = self.clients_by_email.get(email)
        if client is None:
            return None
        return dict(client)

    def create_panel_client(self, _panel, _auth, client, inbound_ids):
        self.created = {"client": client, "inbound_ids": inbound_ids}
        email = client.get("email")
        self.clients_by_email[email] = {
            "email": email,
            "subId": client.get("subId"),
            "inboundIds": inbound_ids,
            "enable": True,
        }
        return {"ok": True}

    def list_panel_clients(self, _panel, _auth):
        return [
            {
                "email": c.get("email"),
                "sub_id": c.get("subId"),
                "inbound_ids": c.get("inboundIds", []),
                "enable": True,
            }
            for c in self.list_clients
        ]

    def update_panel_client(self, _panel, _auth, email, client, inbound_ids=None):
        self.updated = {"email": email, "client": client, "inbound_ids": inbound_ids}
        if email in self.clients_by_email:
            self.clients_by_email[email].update(client)
        return {"ok": True}


def _mock_upsert_panel_client_account(db, *, user_id, panel, client):
    account = VpnAccount(
        user_id=int(user_id),
        protocol="vless",
        panel_inbound_ref_id=None,
        panel_inbound_id=None,
        identifier=str(client.get("email") or ""),
        label=str(client.get("comment") or client.get("email") or ""),
        secret=None,
        status="active",
    )
    db.add(account)
    db.flush()
    return account


def _mock_serialize_panel_client_account(_db, account):
    return {
        "id": account.id,
        "user_id": account.user_id,
        "protocol": account.protocol,
        "identifier": account.identifier,
        "label": account.label,
        "status": account.status,
    }


def _create_bind_test_app(factory, registry, extra_deps=None):
    deps = {
        "_auth_context": lambda **_kwargs: ({"user_id": 1}, None),
        "request": request,
        "jsonify": jsonify,
        "_normalize_panel_provider": lambda value: value or "3xui",
        "panel_registry": registry,
        "Panel": Panel,
        "PanelSecret": PanelSecret,
        "User": User,
        "VpnAccount": VpnAccount,
        "SessionLocal": factory,
        "encrypt_payload": lambda _payload: "encrypted-secret",
        "uuid4": uuid4,
        "utcnow": lambda: datetime.now(timezone.utc),
        "_serialize_panel": lambda p: {"id": p.id, "name": p.name},
        "_upsert_panel_client_account": _mock_upsert_panel_client_account,
        "_serialize_panel_client_account": _mock_serialize_panel_client_account,
    }
    if extra_deps:
        deps.update(extra_deps)
    app = Flask(__name__)
    register_admin_routes(app, deps)
    return app


def _seed_bind_data(db):
    """Seed a panel, inbound, user, and an existing VpnAccount binding."""
    secret = PanelSecret(id="secret-1", provider="3xui", auth_type="api_token", ciphertext="enc")
    panel = Panel(
        id="panel-1",
        name="Test Panel",
        provider="3xui",
        base_url="https://panel.example.test/panel/api",
        auth_type="api_token",
        auth_secret_ref=secret.id,
        is_active=1,
        health_status="green",
    )
    db.add_all([secret, panel])
    db.flush()

    inbound = PanelInbound(
        panel_id=panel.id,
        external_inbound_id="101",
        protocol="vless",
        port=443,
        enabled=1,
        show_in_app=1,
    )
    db.add(inbound)
    db.flush()

    user = User(id=1, telegram_id="10001", name="Test User")
    user2 = User(id=2, telegram_id="10002", name="Another User")
    db.add_all([user, user2])
    db.flush()

    existing = VpnAccount(
        user_id=1,
        protocol="vless",
        panel_inbound_id=101,
        panel_inbound_ref_id=inbound.id,
        identifier="client-1@test.com",
        status="active",
    )
    db.add(existing)
    db.commit()

    return panel, inbound, user


def test_bind_client_get_panel_client_handles_list_obj():
    """get_panel_client must unwrap obj when it is a list (3x-ui returns [client])."""
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    factory = sessionmaker(bind=engine)

    provider = FakeBindProvider(
        clients_by_email={
            "ok@example.com": {
                "email": "ok@example.com",
                "subId": "sub-123",
                "inboundIds": [101],
            }
        }
    )
    registry = FakeRegistry()
    registry.provider = provider

    with factory() as db:
        _seed_bind_data(db)

    app = _create_bind_test_app(factory, registry)
    client = app.test_client()

    resp = client.post(
        "/api/admin/users/1/panel-client",
        json={"panel_id": "panel-1", "email": "ok@example.com"},
    )
    assert resp.status_code == 200, resp.get_json()
    data = resp.get_json()
    assert data["ok"] is True
    assert provider.get_called is True


def test_bind_client_returns_409_when_already_bound_to_another_user():
    """Duplicate binding (same identifier, different user_id) returns 409."""
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    factory = sessionmaker(bind=engine)

    provider = FakeBindProvider(
        clients_by_email={
            "client-1@test.com": {
                "email": "client-1@test.com",
                "subId": "sub-123",
                "inboundIds": [101],
            }
        }
    )
    registry = FakeRegistry()
    registry.provider = provider

    app = _create_bind_test_app(factory, registry)

    with factory() as db:
        _seed_bind_data(db)

    client = app.test_client()
    resp = client.post(
        "/api/admin/users/2/panel-client",
        json={"panel_id": "panel-1", "email": "client-1@test.com"},
    )
    assert resp.status_code == 409, resp.get_json()
    data = resp.get_json()
    assert data["ok"] is False
    assert "already bound" in data["error"].lower()


def test_bind_client_creates_missing_panel_client_when_inbound_ids_provided():
    """When client is not in panel, bind route creates it then binds."""
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    factory = sessionmaker(bind=engine)

    provider = FakeBindProvider(clients_by_email={})
    registry = FakeRegistry()
    registry.provider = provider

    app = _create_bind_test_app(factory, registry)

    with factory() as db:
        _seed_bind_data(db)

    client = app.test_client()
    resp = client.post(
        "/api/admin/users/2/panel-client",
        json={
            "panel_id": "panel-1",
            "email": "new-client@example.com",
            "inbound_ids": [101],
            "sub_id": "new-sub",
        },
    )
    assert resp.status_code == 200, resp.get_json()
    data = resp.get_json()
    assert data["ok"] is True
    assert provider.created is not None
    assert provider.created["client"]["email"] == "new-client@example.com"
    assert provider.created["inbound_ids"] == [101]


def test_bind_client_returns_404_when_client_not_found_and_no_inbound_ids():
    """When client is not in panel and no inbound_ids given, return 404."""
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    factory = sessionmaker(bind=engine)

    provider = FakeBindProvider(clients_by_email={})
    registry = FakeRegistry()
    registry.provider = provider

    app = _create_bind_test_app(factory, registry)

    with factory() as db:
        _seed_bind_data(db)

    client = app.test_client()
    resp = client.post(
        "/api/admin/users/2/panel-client",
        json={"panel_id": "panel-1", "email": "missing@example.com"},
    )
    assert resp.status_code == 404, resp.get_json()
    data = resp.get_json()
    assert data["ok"] is False
    assert "not found" in data["error"].lower()


def test_bind_client_binds_existing_user_without_duplicate():
    """Binding a client to the same user that already owns it succeeds."""
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    factory = sessionmaker(bind=engine)

    provider = FakeBindProvider(
        clients_by_email={
            "client-1@test.com": {
                "email": "client-1@test.com",
                "subId": "sub-123",
                "inboundIds": [101],
            }
        }
    )
    registry = FakeRegistry()
    registry.provider = provider

    app = _create_bind_test_app(factory, registry)

    with factory() as db:
        _seed_bind_data(db)

    client = app.test_client()
    resp = client.post(
        "/api/admin/users/1/panel-client",
        json={"panel_id": "panel-1", "email": "client-1@test.com"},
    )
    assert resp.status_code == 200, resp.get_json()
    data = resp.get_json()
    assert data["ok"] is True