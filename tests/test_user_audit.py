from unittest.mock import Mock

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from lumica.domain.models import AppSetting, Base, User, UserAuditEvent
from lumica.services import user_audit


def test_record_user_event_persists_and_publishes(monkeypatch):
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    factory = sessionmaker(bind=engine)
    with factory() as db:
        actor = User(telegram_id="10001", name="Admin")
        subject = User(telegram_id="10002", name="Client")
        db.add_all([actor, subject])
        db.flush()
        db.add(AppSetting(
            key=user_audit.WORKSPACE_KEY,
            value_json={"chat_id": "-100123", "topics": {"👥 События пользователей": 44}},
        ))
        db.commit()

        sent = []
        response = Mock()
        monkeypatch.setenv("TELEGRAM_BOT_TOKEN", "test-token")
        monkeypatch.setattr(user_audit.requests, "post", lambda *args, **kwargs: sent.append((args, kwargs)) or response)
        event = user_audit.record_user_event(
            db,
            actor_user_id=actor.id,
            subject_user_id=subject.id,
            action="subscription_updated",
            changes={"billing_day": 15, "billing_details": "4111 1111 1111 1111"},
        )
        db.commit()

        assert db.query(UserAuditEvent).filter(UserAuditEvent.id == event.id).count() == 1
        assert len(sent) == 1
        payload = sent[0][1]["json"]
        assert payload["message_thread_id"] == 44
        assert "Admin" in payload["text"]
        assert "Client" in payload["text"]
        assert "billing_day" in payload["text"]
        assert "4111 1111 1111 1111" not in payload["text"]