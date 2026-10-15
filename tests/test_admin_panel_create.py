import json
from datetime import datetime, timezone
from uuid import uuid4

from flask import Flask, jsonify, request
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from lumica.api.routes.admin import register_admin_routes
from lumica.domain.models import Base, MiniAppLaunch, Panel, PanelSecret, User


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