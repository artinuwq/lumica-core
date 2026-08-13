"""
Three small, independently-schedulable jobs that keep the delivery pipeline
moving. All are safe to run from multiple worker processes concurrently
(claiming uses SELECT ... FOR UPDATE SKIP LOCKED — see infra/locks.py) and
are meant to be triggered often and cheaply (e.g. every 10-30s for delivery
processing, every few minutes for retries, every few minutes for the stale
sweeper) by whatever scheduler the rest of Lumica already runs
(APScheduler/cron/celery-beat).
"""

from __future__ import annotations

import logging

from lumica.notifications.config.settings import NotificationSettings
from lumica.notifications.infra.locks import claim_stale_processing
from lumica.notifications.services.notification_service import NotificationService

logger = logging.getLogger(__name__)


class DeliveryProcessorJob:
    """Sends PENDING notifications that are due (not_before <= now)."""

    def __init__(self, notification_service: NotificationService) -> None:
        self._notifications = notification_service

    async def run(self) -> int:
        sent = await self._notifications.process_pending()
        if sent:
            logger.info("delivery_processor_job sent %d notification(s)", sent)
        return sent


class RetryJob:
    """Re-attempts FAILED deliveries whose backoff window has elapsed."""

    def __init__(self, notification_service: NotificationService) -> None:
        self._notifications = notification_service

    async def run(self) -> int:
        sent = await self._notifications.process_retries()
        if sent:
            logger.info("retry_job sent %d notification(s)", sent)
        return sent


class StaleProcessingSweeperJob:
    """Resets notifications that have been stuck in PROCESSING past the
    configured timeout (a worker crashed mid-send) back to PENDING, so the
    delivery worker will retry them — bounded by the normal retry budget."""

    def __init__(self, session, settings: NotificationSettings) -> None:
        self._session = session
        self._settings = settings

    async def run(self) -> int:
        rows = await claim_stale_processing(
            self._session,
            timeout_seconds=self._settings.processing_timeout_seconds,
            limit=self._settings.delivery_batch_size,
        )
        if rows:
            logger.warning("stale_processing_sweeper reset %d stuck notification(s)", len(rows))
        return len(rows)
