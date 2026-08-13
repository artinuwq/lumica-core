"""
Notification -> ChannelDispatcher -> concrete channel -> Telegram (etc).

NotificationService never imports a Telegram client type directly — only
this Protocol. Adding EMAIL/WEB/PUSH later is "implement DeliveryChannelPort,
register it in the dispatcher" and nothing else changes.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional, Protocol

from lumica.notifications.domain.enums import DeliveryChannel
from lumica.notifications.templates.renderer import RenderedMessage


@dataclass(frozen=True)
class DeliveryResult:
    success: bool
    retryable: bool = False
    error_code: Optional[str] = None
    error_message: Optional[str] = None
    provider_message_id: Optional[str] = None


class DeliveryChannelPort(Protocol):
    channel: DeliveryChannel

    async def send(self, recipient_user_id: int, message: RenderedMessage) -> DeliveryResult: ...


class ChannelDispatcher:
    def __init__(self) -> None:
        self._channels: dict[DeliveryChannel, DeliveryChannelPort] = {}

    def register(self, port: DeliveryChannelPort) -> None:
        self._channels[port.channel] = port

    def get(self, channel: DeliveryChannel) -> DeliveryChannelPort:
        try:
            return self._channels[channel]
        except KeyError as exc:
            raise LookupError(f"No channel registered for {channel!r}") from exc

    async def send(
        self, channel: DeliveryChannel, recipient_user_id: int, message: RenderedMessage
    ) -> DeliveryResult:
        return await self.get(channel).send(recipient_user_id, message)
