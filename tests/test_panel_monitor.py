from datetime import datetime, timezone

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from lumica.domain.models import AppSetting, Base, Panel, PanelSecret
from lumica.jobs import panel_monitor
from lumica.jobs.panel_monitor import _format_snapshot, _observatory_unhealthy


class FakeProvider:
    def __init__(self):
        self.checks = 0

    def health_check(self, _panel, _auth):
        self.checks += 1
        if self.checks == 1:
            raise RuntimeError("panel unavailable")
        return {"ok": True}

    def monitoring_snapshot(self, _panel, _auth):
        return {"status": {"cpu": 24}, "online_clients": []}


class FakeRegistry:
    def __init__(self):
        self.provider = FakeProvider()

    def get_auth_payload(self, _db, _panel):
        return {}

    def get_provider(self, _provider):
        return self.provider

    def invalidate_panel(self, _panel_id):
        pass


def test_monitor_updates_same_post_and_emits_down_recovery(monkeypatch):
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    factory = sessionmaker(bind=engine)
    with factory() as db:
        db.add(PanelSecret(id="secret-1", provider="3xui", auth_type="api_token", ciphertext="hidden"))
        db.add(Panel(
            id="panel-1",
            name="DE-01",
            provider="3xui",
            base_url="https://panel.example",
            auth_type="api_token",
            auth_secret_ref="secret-1",
            is_active=1,
            health_status="green",
        ))
        db.add(AppSetting(
            key=panel_monitor.WORKSPACE_KEY,
            value_json={"chat_id": "-1001", "topics": {"📊 Мониторинг": 10, "🔴 События серверов": 11}},
        ))
        db.add(AppSetting(
            key=panel_monitor.STATE_KEY,
            value_json={"panel-1": {"message_id": 77, "health_status": "green"}},
        ))
        db.commit()

    posts = []
    events = []
    monkeypatch.setattr(panel_monitor, "SessionLocal", factory)
    monkeypatch.setattr(
        panel_monitor,
        "_topic_message",
        lambda chat_id, thread_id, text, message_id=None: posts.append((thread_id, text, message_id)) or message_id or 77,
    )
    monkeypatch.setattr(
        panel_monitor,
        "_telegram_call",
        lambda method, payload: events.append((method, payload)) or {"ok": True},
    )
    registry = FakeRegistry()
    now = datetime(2026, 10, 15, 12, 0, tzinfo=timezone.utc)

    assert panel_monitor.run_panel_monitoring(registry, now) == 1
    with factory() as db:
        stored = db.query(AppSetting).filter(AppSetting.key == panel_monitor.STATE_KEY).first()
        assert stored.value_json["panel-1"]["health_status"] == "red"
    assert panel_monitor.run_panel_monitoring(registry, now) == 1

    assert len(posts) == 2
    assert posts[0][2] == 77 and posts[1][2] == 77
    assert "Offline" in posts[0][1]
    assert "CPU 24%" in posts[1][1]
    assert [payload["message_thread_id"] for _method, payload in events] == [11, 11]
    assert "недоступен" in events[0][1]["text"]
    assert "восстановился" in events[1][1]["text"]


def test_documented_status_payload_formats_all_available_metrics():
    gib = 1024 ** 3
    panel = Panel(name="DE-01", health_status="green")
    text = _format_snapshot(panel, {
        "status": {
            "cpu": 24,
            "mem": {"current": 62, "total": 100},
            "swap": {"current": 46, "total": 100},
            "disk": {"current": 90 * gib, "total": 100 * gib},
            "netIO": {"up": 1_550_000, "down": 6_025_000},
            "uptime": 86400,
            "xray": {"state": "running", "version": "25.10.31"},
            "panelVersion": "v3.x.x",
            "tcpCount": 8,
            "udpCount": 10,
        },
        "online_clients": [f"client-{index}" for index in range(18)],
        "xray_version": "25.10.31",
        "panel_version": "v3.x.x",
    }, datetime(2026, 10, 15, 12, 0, tzinfo=timezone.utc))

    assert "CPU 24%" in text
    assert "Диск 90%" in text
    assert "RAM 62% · SWAP 46%" in text
    assert "Свободно на диске: 10.0 GB" in text
    assert "Подключения: 18 · Пользователи online: 18" in text
    assert "Xray: running 25.10.31 · Панель: v3.x.x" in text
    assert "↑ 12.4 Мбит/с · ↓ 48.2 Мбит/с" in text


def test_observatory_health_detection_is_optional_and_tolerant():
    assert _observatory_unhealthy({"outbounds": [{"alive": False}]}) is True
    assert _observatory_unhealthy({"outbounds": [{"alive": True}]}) is False
    assert _observatory_unhealthy({}) is None


def test_critical_metric_events_are_deduplicated_and_recovered(monkeypatch):
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    factory = sessionmaker(bind=engine)
    gib = 1024 ** 3
    critical = {
        "status": {
            "cpu": 24,
            "mem": {"current": 96, "total": 100},
            "disk": {"current": 95 * gib, "total": 100 * gib},
            "xray": {"state": "error", "version": "25.10.31"},
            "panelVersion": "v3",
            "tcpCount": 2,
            "udpCount": 1,
        },
        "online_clients": ["alice"],
        "xray_observatory": {"outbounds": [{"alive": False}]},
        "update_status": {"state": "failed", "runId": "run-1", "exitCode": 1},
    }
    healthy = {
        "status": {
            "cpu": 10,
            "mem": {"current": 50, "total": 100},
            "disk": {"current": 60 * gib, "total": 100 * gib},
            "xray": {"state": "running", "version": "25.10.31"},
            "panelVersion": "v3",
            "tcpCount": 2,
            "udpCount": 1,
        },
        "online_clients": ["alice"],
        "xray_observatory": {"outbounds": [{"alive": True}]},
        "update_status": {"state": "success", "runId": "run-2", "exitCode": 0},
    }
    with factory() as db:
        db.add(PanelSecret(id="secret-2", provider="3xui", auth_type="api_token", ciphertext="hidden"))
        db.add(Panel(
            id="panel-2",
            name="DE-02",
            provider="3xui",
            base_url="https://panel.example",
            auth_type="api_token",
            auth_secret_ref="secret-2",
            is_active=1,
            health_status="green",
        ))
        db.add(AppSetting(
            key=panel_monitor.WORKSPACE_KEY,
            value_json={"chat_id": "-1002", "topics": {"📊 Мониторинг": 20, "🔴 События серверов": 21}},
        ))
        db.add(AppSetting(
            key=panel_monitor.STATE_KEY,
            value_json={"panel-2": {
                "message_id": 88,
                "health_status": "green",
                "alerts": {
                    "xray_down": False,
                    "disk_critical": False,
                    "ram_critical": False,
                    "proxy_unavailable": False,
                },
                "update": {"run_id": "old", "state": "success"},
            }},
        ))
        db.commit()

    class SequenceProvider:
        def __init__(self):
            self.snapshots = [critical, critical, healthy]

        def health_check(self, _panel, _auth):
            return {"ok": True}

        def monitoring_snapshot(self, _panel, _auth):
            return self.snapshots.pop(0)

    class SequenceRegistry(FakeRegistry):
        def __init__(self):
            self.provider = SequenceProvider()

    sent_events = []
    monkeypatch.setattr(panel_monitor, "SessionLocal", factory)
    monkeypatch.setattr(panel_monitor, "_topic_message", lambda _chat, _thread, _text, message_id=None: message_id or 88)
    monkeypatch.setattr(
        panel_monitor,
        "_telegram_call",
        lambda method, payload: sent_events.append(payload["text"]) or {"ok": True},
    )
    registry = SequenceRegistry()
    now = datetime(2026, 10, 15, 12, 0, tzinfo=timezone.utc)

    panel_monitor.run_panel_monitoring(registry, now)
    panel_monitor.run_panel_monitoring(registry, now)
    assert len(sent_events) == 5
    panel_monitor.run_panel_monitoring(registry, now)
    assert len(sent_events) == 10
    assert sum("диск" in text.lower() for text in sent_events) == 2
    assert sum("RAM" in text for text in sent_events) == 2
    assert sum("Xray" in text for text in sent_events) == 2
    assert sum("прокси" in text.lower() for text in sent_events) == 2
    assert sum("обновление панели" in text.lower() for text in sent_events) == 2