"""
Renders a NotificationTemplate + a context dict into a channel-agnostic
RenderedMessage. Channel adapters (TelegramChannel, later EmailChannel...)
turn RenderedMessage into whatever their API needs.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass

from lumica.notifications.domain.enums import NotificationType
from lumica.notifications.templates.registry import (
    NotificationTemplate,
    StaticTemplateRegistry,
    TemplateRegistry,
)

logger = logging.getLogger(__name__)

_MISSING_PLACEHOLDER = "—"


class _SafeDict(dict):
    """dict subclass so `str.format_map` never raises on a missing key —
    a template/context mismatch should degrade the message, not crash
    delivery (ARCHITECTURE.md §12)."""

    def __missing__(self, key: str) -> str:
        logger.warning("Template variable %r missing from context", key)
        return _MISSING_PLACEHOLDER


@dataclass(frozen=True)
class RenderedButton:
    text: str
    target: str  # still symbolic here; resolved to a real URL by the channel


@dataclass(frozen=True)
class RenderedMessage:
    title: str
    body: str
    buttons: tuple[RenderedButton, ...]


class TemplateRenderer:
    def __init__(self, registry: TemplateRegistry | None = None) -> None:
        self._registry = registry or StaticTemplateRegistry()

    def render(self, type_: NotificationType, context: dict) -> RenderedMessage:
        tpl: NotificationTemplate = self._registry.get(type_)
        safe_ctx = _SafeDict(context)
        return RenderedMessage(
            title=tpl.title.format_map(safe_ctx),
            body=tpl.body.format_map(safe_ctx),
            buttons=tuple(
                RenderedButton(
                    text=btn.text.format_map(safe_ctx),
                    target=btn.target.format_map(safe_ctx),
                )
                for btn in tpl.buttons
            ),
        )
