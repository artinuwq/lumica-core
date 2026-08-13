"""
The one entrypoint business code (and jobs) talk to.

    await notification_service.handle_event(PaymentConfirmed(...))

does: rules -> per-spec preference check -> per-spec recipient resolution ->
idempotent create (one Notification row per resolved recipient). Delivery
itself happens asynchronously via `process_pending()`, called by
jobs/delivery_processor_job.py — handle_event() never blocks on Telegram.
"""

from __future__ import annotations

import datetime as dt
import logging

from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from lumica.notifications.config.settings import NotificationSettings
from lumica.notifications.domain import events as ev
from lumica.notifications.domain.enums import (
    DeliveryChannel,
    DeliveryStatus,
    NotificationStatus,
    NotificationType,
)
from lumica.notifications.domain.models import Notification, NotificationDelivery
from lumica.notifications.services.channel_dispatcher import ChannelDispatcher
from lumica.notifications.services.data_gateway import DataGateway
from lumica.notifications.services.preferences_service import PreferenceService
from lumica.notifications.services.recipient_resolver import RecipientResolver
from lumica.notifications.services.rules import NotificationSpec, RuleEngine
from lumica.notifications.templates.renderer import TemplateRenderer

logger = logging.getLogger(__name__)


class NotificationService:
    def __init__(
        self,
        session: AsyncSession,
        gateway: DataGateway,
        dispatcher: ChannelDispatcher,
        settings: NotificationSettings | None = None,
        renderer: TemplateRenderer | None = None,
    ) -> None:
        self._session = session
        self._gateway = gateway
        self._dispatcher = dispatcher
        self._settings = settings or NotificationSettings()
        self._renderer = renderer or TemplateRenderer()
        self._rules = RuleEngine(gateway)
        self._resolver = RecipientResolver(gateway)
        self._preferences = PreferenceService(session)

    # ------------------------------------------------------------------ CREATE

    async def handle_event(self, event: ev.Event) -> list[Notification]:
        """Business/job entrypoint. Returns the Notification rows actually
        created (excludes ones skipped by dedup or preference)."""
        specs = await self._rules.build_specs(event)
        created: list[Notification] = []
        for spec in specs:
            created.extend(await self._create_from_spec(spec))
        return created

    async def notify_admins_directly(
        self, type_: NotificationType, context: dict, dedup_key: str
    ) -> list[Notification]:
        """Escape hatch for admin notifications that aren't modeled as a
        business Event (e.g. called straight from a job). Still goes through
        the same create/dedup path."""
        from lumica.notifications.domain.enums import RecipientType

        spec = NotificationSpec(
            type=type_,
            recipient_type=RecipientType.SUPER_ADMIN,
            resolver_hint={"role": "super_admin"},
            context=context,
            dedup_key=dedup_key,
        )
        return await self._create_from_spec(spec)

    async def create_from_spec(self, spec: NotificationSpec) -> list[Notification]:
        """Public wrapper — used by jobs (subscription reminders, VPN/server
        health) that build NotificationSpec directly instead of through an
        Event, because their "event" is really a scheduled/derived check
        rather than something another service raised."""
        return await self._create_from_spec(spec)

    async def _create_from_spec(self, spec: NotificationSpec) -> list[Notification]:
        recipient_ids = await self._resolver.resolve(spec)
        results: list[Notification] = []
        for recipient_id in recipient_ids:
            if not await self._preferences.is_enabled(recipient_id, spec.type):
                continue
            notif = await self._insert_notification(spec, recipient_id)
            if notif is not None:
                results.append(notif)
        return results

    async def _insert_notification(
        self, spec: NotificationSpec, recipient_id: int
    ) -> Notification | None:
        """Idempotent insert. Relies on the DB unique constraint on
        dedup_key as the source of truth (ARCHITECTURE.md §8) — this is safe
        under concurrent callers/workers, unlike a check-then-insert.

        When a single spec resolves to more than one recipient (e.g. ADMIN
        fan-out), the dedup_key is suffixed per recipient so each admin gets
        their own row while still being idempotent per (spec, recipient).
        """
        dedup_key = spec.dedup_key
        if spec.recipient_type.value in ("admin", "super_admin"):
            dedup_key = f"{dedup_key}:{recipient_id}"

        notif = Notification(
            type=spec.type,
            priority=spec.priority or spec.type.default_priority,
            recipient_type=spec.recipient_type,
            recipient_id=recipient_id,
            status=NotificationStatus.PENDING,
            dedup_key=dedup_key,
            context=spec.context,
            related_entity_type=spec.related_entity_type,
            related_entity_id=spec.related_entity_id,
        )
        self._session.add(notif)
        try:
            await self._session.flush()  # trigger the unique constraint now
        except IntegrityError:
            await self._session.rollback()
            logger.debug("Duplicate notification suppressed: dedup_key=%s", dedup_key)
            return None
        return notif

    # ------------------------------------------------------------------ DELIVER

    async def process_pending(self, limit: int | None = None) -> int:
        """Claim a batch of due PENDING notifications and attempt delivery.
        Safe to run from multiple worker processes concurrently — claiming
        uses SELECT ... FOR UPDATE SKIP LOCKED (infra/locks.py).
        """
        from lumica.notifications.infra.locks import claim_pending_notifications

        batch_size = limit or self._settings.delivery_batch_size
        notifications = await claim_pending_notifications(self._session, batch_size)
        sent = 0
        for notif in notifications:
            if await self._deliver_one(notif):
                sent += 1
        return sent

    async def _deliver_one(self, notif: Notification) -> bool:
        channel = DeliveryChannel.TELEGRAM  # only channel wired up for MVP
        attempt_number = len(notif.deliveries) + 1

        message = self._renderer.render(notif.type, notif.context)
        result = await self._dispatcher.send(channel, notif.recipient_id, message)

        delivery = NotificationDelivery(
            notification_id=notif.id,
            channel=channel,
            attempt_number=attempt_number,
            attempted_at=dt.datetime.now(dt.timezone.utc),
        )

        if result.success:
            delivery.status = DeliveryStatus.SENT
            delivery.provider_message_id = result.provider_message_id
            notif.status = NotificationStatus.SENT
            self._session.add(delivery)
            await self._session.flush()
            return True

        delivery.status = DeliveryStatus.FAILED
        delivery.error_code = result.error_code
        delivery.error_message = result.error_message
        self._session.add(delivery)

        if result.retryable and attempt_number < self._settings.retry.max_attempts:
            delay = self._settings.retry.delay_for_attempt(attempt_number)
            delivery.next_retry_at = dt.datetime.now(dt.timezone.utc) + dt.timedelta(
                seconds=delay
            )
            notif.status = NotificationStatus.PROCESSING  # retry worker will pick it up
        else:
            notif.status = NotificationStatus.FAILED
            await self._session.flush()
            if result.error_code != "USER_BLOCKED_BOT":
                # Don't spam admins per-blocked-user; do alert on exhausted
                # retries / unexpected permanent failures.
                await self.notify_admins_directly(
                    NotificationType.NOTIFICATION_DELIVERY_FAILED,
                    context={"name": str(notif.recipient_id)},
                    dedup_key=f"delivery_failed:{notif.id}",
                )

        await self._session.flush()
        return False

    async def process_retries(self, limit: int | None = None) -> int:
        """Re-attempt FAILED deliveries whose next_retry_at has arrived, for
        notifications still in PROCESSING. Same SKIP LOCKED claim pattern.
        """
        from lumica.notifications.infra.locks import claim_retryable_notifications

        batch_size = limit or self._settings.delivery_batch_size
        notifications = await claim_retryable_notifications(self._session, batch_size)
        sent = 0
        for notif in notifications:
            if await self._deliver_one(notif):
                sent += 1
        return sent
