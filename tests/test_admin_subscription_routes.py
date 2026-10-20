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
    from lumica.domain.models import AuthSession, Subscription, User
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
        db.commit(); cid = client.id
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
    }
