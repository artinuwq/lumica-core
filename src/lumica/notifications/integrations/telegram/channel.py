"""
The one concrete DeliveryChannelPort for MVP. Nothing outside this file
knows about aiogram/Telegram Bot API types — NotificationService only sees
the DeliveryChannelPort Protocol and DeliveryResult.
"""

from __future__ import annotations

import logging

from lumica.notifications.domain.enums import DeliveryChannel
from lumica.notifications.integrations.telegram.deep_link import DeepLinkResolver
from lumica.notifications.integrations.telegram.errors import classify
from lumica.notifications.services.channel_dispatcher import DeliveryResult
from lumica.notifications.services.data_gateway import DataGateway
from lumica.notifications.templates.renderer import RenderedMessage

logger = logging.getLogger(__name__)


class TelegramChannel:
    """Implements DeliveryChannelPort. `bot` is expected to be an aiogram
    `Bot` instance (or any object exposing an equivalent async
    `send_message(chat_id, text, reply_markup=...)`); kept untyped here to
    avoid a hard dependency of this design doc/module on aiogram being
    importable in isolation.
    """

    channel = DeliveryChannel.TELEGRAM

    def __init__(self, bot, gateway: DataGateway, deep_links: DeepLinkResolver) -> None:
        self._bot = bot
        self._gateway = gateway
        self._deep_links = deep_links

    async def send(self, recipient_user_id: int, message: RenderedMessage) -> DeliveryResult:
        user = await self._gateway.get_user(recipient_user_id)

        if not user.telegram_reachable:
            # Known-blocked user: don't even try, don't burn a retry slot,
            # don't spam admins about it again (ARCHITECTURE.md §10).
            return DeliveryResult(
                success=False,
                retryable=False,
                error_code="USER_BLOCKED_BOT",
                error_message="User previously marked unreachable.",
            )

        if user.telegram_chat_id is None:
            return DeliveryResult(
                success=False,
                retryable=False,
                error_code="NO_TELEGRAM_CHAT",
                error_message="User has no linked Telegram chat.",
            )

        text = f"<b>{_escape(message.title)}</b>\n\n{_escape(message.body)}"
        keyboard = self._build_keyboard(message)

        try:
            sent = await self._bot.send_message(
                chat_id=user.telegram_chat_id,
                text=text,
                parse_mode="HTML",
                reply_markup=keyboard,
                disable_web_page_preview=True,
            )
        except Exception as exc:  # noqa: BLE001 - deliberately broad, classified below
            classified = classify(exc)
            logger.warning(
                "Telegram send failed for user_id=%s: %s (%s)",
                recipient_user_id,
                classified.error_code,
                classified.message,
            )
            return DeliveryResult(
                success=False,
                retryable=classified.retryable,
                error_code=classified.error_code,
                error_message=classified.message,
            )

        message_id = getattr(sent, "message_id", None)
        return DeliveryResult(success=True, provider_message_id=str(message_id))

    def _build_keyboard(self, message: RenderedMessage):
        if not message.buttons:
            return None
        # aiogram-style inline keyboard; swap for whatever the real bot
        # client's markup type is.
        from aiogram.types import InlineKeyboardButton, InlineKeyboardMarkup

        rows = [
            [InlineKeyboardButton(text=btn.text, url=self._deep_links.resolve(btn.target))]
            for btn in message.buttons
        ]
        return InlineKeyboardMarkup(inline_keyboard=rows)


def _escape(text: str) -> str:
    return text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
