"""
Concurrency-safe row claiming for background workers.

Every job that pulls rows to act on uses `SELECT ... FOR UPDATE SKIP LOCKED`
so that N worker processes running the same job never grab the same
Notification/Delivery — no external lock service needed for MVP
(ARCHITECTURE.md §11).
"""

from __future__ import annotations

import datetime as dt

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from lumica.notifications.domain.enums import DeliveryStatus, NotificationStatus
from lumica.notifications.domain.models import Notification, NotificationDelivery


async def claim_pending_notifications(
    session: AsyncSession, limit: int
) -> list[Notification]:
    """Claim due PENDING notifications and flip them to PROCESSING in the
    same transaction, so a concurrent caller's SKIP LOCKED pass won't see
    them even after this one commits/flushes."""
    now = dt.datetime.now(dt.timezone.utc)
    stmt = (
        select(Notification)
        .where(
            Notification.status == NotificationStatus.PENDING,
            Notification.not_before <= now,
        )
        .order_by(Notification.priority.desc(), Notification.created_at)
        .limit(limit)
        .with_for_update(skip_locked=True)
    )
    result = await session.execute(stmt)
    rows = list(result.scalars().all())
    for row in rows:
        row.status = NotificationStatus.PROCESSING
    await session.flush()
    return rows


async def claim_retryable_notifications(
    session: AsyncSession, limit: int
) -> list[Notification]:
    """Claim notifications still PROCESSING whose most recent delivery
    attempt is FAILED with next_retry_at due."""
    now = dt.datetime.now(dt.timezone.utc)
    stmt = (
        select(Notification)
        .join(NotificationDelivery, NotificationDelivery.notification_id == Notification.id)
        .where(
            Notification.status == NotificationStatus.PROCESSING,
            NotificationDelivery.status == DeliveryStatus.FAILED,
            NotificationDelivery.next_retry_at <= now,
        )
        .distinct()
        .order_by(Notification.priority.desc())
        .limit(limit)
        .with_for_update(skip_locked=True, of=Notification)
    )
    result = await session.execute(stmt)
    return list(result.scalars().all())


async def claim_stale_processing(
    session: AsyncSession, timeout_seconds: int, limit: int
) -> list[Notification]:
    """Notifications stuck in PROCESSING past the timeout — assumed to
    belong to a crashed worker. Reset to PENDING so the delivery worker
    retries them; still bounded by max_attempts since prior delivery rows
    remain on the notification and count toward the budget."""
    cutoff = dt.datetime.now(dt.timezone.utc) - dt.timedelta(seconds=timeout_seconds)
    stmt = (
        select(Notification)
        .where(
            Notification.status == NotificationStatus.PROCESSING,
            Notification.updated_at <= cutoff,
        )
        .limit(limit)
        .with_for_update(skip_locked=True)
    )
    result = await session.execute(stmt)
    rows = list(result.scalars().all())
    for row in rows:
        # Record the timeout as a delivery attempt so it still counts
        # against the retry budget and shows up in history honestly.
        last_attempt = len(row.deliveries) + 1
        row.deliveries.append(
            NotificationDelivery(
                notification_id=row.id,
                channel="telegram",
                status=DeliveryStatus.FAILED,
                attempt_number=last_attempt,
                error_code="WORKER_TIMEOUT",
                error_message="Notification stuck in PROCESSING past timeout; worker likely crashed.",
                attempted_at=dt.datetime.now(dt.timezone.utc),
            )
        )
        row.status = NotificationStatus.PENDING
    await session.flush()
    return rows
