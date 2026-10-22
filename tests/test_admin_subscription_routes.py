"""Регрессия: POST /api/admin/users/<id>/subscription отвечал 500 (NameError в маршруте).

Запускаем настоящее приложение (create_app) во временной БД в отдельном процессе:
имена из хелперов подмешиваются в маршруты только при реальной сборке приложения,
поэтому тестовая обвязка с заглушками такую ошибку не ловит.
"""

import json
import subprocess
import sys
import textwrap
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

SCRIPT = textwrap.dedent(
    """
    import json, os, sys, tempfile
    tmp = tempfile.mkdtemp()
    os.environ.update(DATABASE_URL=f"sqlite:///{tmp}/t.db", MIGRATE_ON_START="0",
                      ENABLE_BACKGROUND_JOBS="false", ENV="prod")
    sys.path.insert(0, "src")
    from datetime import datetime, timedelta, timezone
    from lumica.api import create_app
    from lumica.api.app import _token_hash
    from lumica.domain.models import AuthSession, Group, Subscription, User
    from lumica.infra.db import SessionLocal
    app = create_app()
    app.before_request_funcs[None] = []  # CSRF здесь не проверяем
    with SessionLocal() as db:
        admin = User(telegram_id="1", name="Admin", role="admin")
        client = User(telegram_id="2", name="Client")
        db.add_all([admin, client]); db.flush()
        db.add(AuthSession(user_id=admin.id, session_token=_token_hash("tok"),
                           expires_at=datetime.now(timezone.utc) + timedelta(days=1), init_data="{}"))
        db.add(Subscription(user_id=client.id, status="active", access_until=datetime(2030, 10, 18),
                            price_amount=500, billing_day=7))
        db.flush()
        other = User(telegram_id="3", name="Other")
        db.add(other); db.flush()
        group = Group(name="Fam", admin_user_id=client.id)
        db.add(group); db.flush()
        client.group_id = group.id; other.group_id = group.id
        db.commit(); cid = client.id; oid = other.id; aid = admin.id
    c = app.test_client(); c.set_cookie("session", "tok")
    out = {}
    for name, payload in {
        "details": {"billing_details": "card", "price_amount": "700"},
        "extend_months": {"extend_months": 1},
        "date": {"status": "active", "access_until": "2030-11-18T23:55:00", "billing_day": 18},
    }.items():
        out[name] = c.post(f"/api/admin/users/{cid}/subscription", json=payload).status_code
    out["manual_extend"] = c.post(f"/api/admin/users/{cid}/manual-extend", json={"confirmed": True, "months": 1}).status_code
    out["freeze"] = c.post(f"/api/admin/users/{cid}/freeze", json={"frozen": True}).status_code
    out["overview"] = c.get(f"/api/admin/users/{cid}/overview").status_code
    import requests as _requests
    sent_to = []
    class _Resp:
        status_code = 200
        def json(self): return {"ok": True}
    def _fake_post(url, json=None, timeout=None):
        sent_to.append((json or {}).get("chat_id")); return _Resp()
    _requests.post = _fake_post
    os.environ["TELEGRAM_BOT_TOKEN"] = "t"
    import lumica.services.broadcasts as _b
    _b.SEND_INTERVAL_SECONDS = 0
    out["broadcast"] = c.post("/api/admin/broadcasts", json={"type": "ad", "text": "**Hi**", "user_ids": [cid, oid]}).get_json()
    out["broadcast_sent_to"] = sorted(x for x in sent_to if x)
    out["broadcast_bad_type"] = c.post("/api/admin/broadcasts", json={"type": "x", "text": "a", "user_ids": [cid]}).status_code
    out["broadcast_no_users"] = c.post("/api/admin/broadcasts", json={"type": "ad", "text": "a", "user_ids": []}).status_code
    out["identity"] = c.post(f"/api/admin/users/{cid}/identity",
                             json={"name": "New Name", "username": "@new_user", "telegram_id": "555"}).status_code
    out["identity_duplicate"] = c.post(f"/api/admin/users/{cid}/identity", json={"telegram_id": "1"}).status_code
    out["identity_bad_username"] = c.post(f"/api/admin/users/{cid}/identity", json={"username": "a"}).status_code
    out["delete_self"] = c.delete(f"/api/admin/users/{aid}").status_code
    out["delete_client"] = c.delete(f"/api/admin/users/{cid}").status_code
    with SessionLocal() as db:
        out["client_gone"] = db.query(User).filter(User.id == cid).first() is None
        out["new_group_admin"] = db.query(Group).one().admin_user_id == oid
    print("RESULT" + json.dumps(out))
    """
)


def test_admin_subscription_endpoints_do_not_crash_in_the_real_app():
    done = subprocess.run(
        [sys.executable, "-c", SCRIPT], cwd=ROOT, capture_output=True, text=True, timeout=120,
        env={**__import__("os").environ, "PYTHONPATH": str(ROOT / "src")},
    )
    line = next((row for row in done.stdout.splitlines() if row.startswith("RESULT")), None)
    assert line, done.stderr[-2000:]
    assert json.loads(line[len("RESULT"):]) == {
        "details": 200, "extend_months": 200, "date": 200, "manual_extend": 200, "freeze": 200, "overview": 200,
        "broadcast": {"ok": True, "total": 2, "sent": 2, "failed": [], "log_posted": False},
        "broadcast_sent_to": ["2", "3"], "broadcast_bad_type": 400, "broadcast_no_users": 400,
        "identity": 200, "identity_duplicate": 409, "identity_bad_username": 400,
        "delete_self": 400, "delete_client": 200, "client_gone": True, "new_group_admin": True,
    }
