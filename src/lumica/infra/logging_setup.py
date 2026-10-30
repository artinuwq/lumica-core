"""Единая настройка логов для фоновых процессов (бот и планировщик).

Без неё сообщения logger.* уровня INFO теряются, а ошибки выводятся без времени и
имени источника. Уровень задаётся LOG_LEVEL (по умолчанию INFO)."""

from __future__ import annotations

import logging
import os

_FORMAT = "%(asctime)s %(levelname)s %(name)s: %(message)s"


def setup_logging() -> None:
    level_name = os.getenv("LOG_LEVEL", "INFO").strip().upper()
    level = getattr(logging, level_name, logging.INFO)
    root = logging.getLogger()
    if not root.handlers:
        logging.basicConfig(level=level, format=_FORMAT)
    else:
        root.setLevel(level)


__all__ = ["setup_logging"]
