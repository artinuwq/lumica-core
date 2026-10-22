"""Публикация событий в темы операторской супергруппы (см. /setup_group)."""

from __future__ import annotations

import logging
import os

import requests

from lumica.domain.models import AppSetting
from lumica.infra.db import SessionLocal

logger = logging.getLogger(__name__)

WORKSPACE_KEY = "telegram.operator_workspace"
SERVER_EVENTS_TOPIC = "🔴 События серверов"
USER_EVENTS_TOPIC = "👥 События пользователей"


def post_to_topic(topic_title: str, text: str, *, parse_mode: str | None = None) -> bool:
    """Синхронно отправляет текст в тему операторской группы. Возвращает False,
    если группа не настроена или Telegram недоступен: событие - вспомогательное,
    оно не должно ломать основную операцию."""
    token = os.getenv("TELEGRAM_BOT_TOKEN")
    if not token:
        return False
    with SessionLocal() as db:
        row = db.query(AppSetting).filter(AppSetting.key == WORKSPACE_KEY).first()
        config = row.value_json if row and isinstance(row.value_json, dict) else {}
    topics = config.get("topics") if isinstance(config.get("topics"), dict) else {}
    chat_id, thread_id = config.get("chat_id"), topics.get(topic_title)
    if not chat_id or not thread_id:
        return False
    payload = {"chat_id": str(chat_id), "message_thread_id": int(thread_id), "text": text}
    if parse_mode:
        payload["parse_mode"] = parse_mode
    try:
        response = requests.post(
            f"https://api.telegram.org/bot{token}/sendMessage",
            json=payload,
            timeout=8,
        )
        response.raise_for_status()
        return True
    except requests.RequestException:
        logger.exception("Could not publish event to topic %s", topic_title)
        return False


__all__ = ["post_to_topic", "SERVER_EVENTS_TOPIC", "USER_EVENTS_TOPIC"]
