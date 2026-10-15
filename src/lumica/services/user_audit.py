from __future__ import annotations

import json
import logging
import os
from datetime import datetime
from zoneinfo import ZoneInfo

import requests

from lumica.domain.models import AppSetting, User, UserAuditEvent

logger = logging.getLogger(__name__)
MOSCOW = ZoneInfo("Europe/Moscow")
WORKSPACE_KEY = "telegram.operator_workspace"
SENSITIVE_KEYS = {"billing_details", "notes", "password", "token", "api_token", "secret", "receipt_file_id"}


def _redact_changes(value):
    if isinstance(value, dict):
        return {
            key: "изменено" if str(key).strip().lower() in SENSITIVE_KEYS else _redact_changes(item)
            for key, item in value.items()
        }
    if isinstance(value, list):
        return [_redact_changes(item) for item in value]
    return value


def record_user_event(db, *, actor_user_id: int | None, subject_user_id: int | None, action: str, changes: dict) -> UserAuditEvent:
    event = UserAuditEvent(
        actor_user_id=actor_user_id,
        subject_user_id=subject_user_id,
        action=action,
        changes=changes,
    )
    db.add(event)
    db.flush()

    workspace = db.query(AppSetting).filter(AppSetting.key == WORKSPACE_KEY).first()
    config = workspace.value_json if workspace and isinstance(workspace.value_json, dict) else {}
    topics = config.get("topics") if isinstance(config.get("topics"), dict) else {}
    chat_id = config.get("chat_id")
    thread_id = topics.get("👥 События пользователей")
    token = os.getenv("TELEGRAM_BOT_TOKEN")
    if not chat_id or not thread_id or not token:
        return event

    actor = db.query(User).filter(User.id == actor_user_id).first() if actor_user_id else None
    subject = db.query(User).filter(User.id == subject_user_id).first() if subject_user_id else None
    actor_name = actor.name or (f"@{actor.username}" if actor and actor.username else None) if actor else None
    subject_name = subject.name or (f"@{subject.username}" if subject and subject.username else None) if subject else None
    change_text = json.dumps(_redact_changes(changes), ensure_ascii=False, default=str)
    text = (
        f"Действие: {action}\n"
        f"Кто: {actor_name or 'Системный администратор'} (ID {actor.telegram_id if actor else '—'})\n"
        f"Над кем: {subject_name or '—'} (ID {subject.telegram_id if subject else '—'})\n"
        f"Изменения: {change_text[:2400]}\n"
        f"Когда: {datetime.now(MOSCOW):%d.%m.%Y %H:%M:%S} MSK"
    )
    try:
        response = requests.post(
            f"https://api.telegram.org/bot{token}/sendMessage",
            json={"chat_id": str(chat_id), "message_thread_id": int(thread_id), "text": text},
            timeout=8,
        )
        response.raise_for_status()
    except requests.RequestException:
        logger.exception("Could not publish user audit event %s", event.id)
    return event


__all__ = ["record_user_event"]