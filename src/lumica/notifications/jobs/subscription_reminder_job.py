"""
Periodic job (e.g. every hour, driven by whatever scheduler the rest of
Lumica already uses — APScheduler/cron/celery-beat) that turns "subscription
X expires in N days" into a SubscriptionExpiring event.

Group subscriptions (Subscription.owner_type == GROUP) are checked exactly
the same way as personal ones — the job never queries per-member dates,
because members don't have their own subscription (spec §7, §15). The
group-vs-personal branching happens later, in recipient_resolver, not here.

Intervals are entirely config-driven (spec §7: "не хардкодить 7, 3, 1").
"""

from __future__ import annotations

import datetime as dt
import logging

from lumica.notifications.config.settings import NotificationSettings
from lumica.notifications.domain import events as ev
from lumica.notifications.services.data_gateway import DataGateway
from lumica.notifications.services.notification_service import NotificationService

logger = logging.getLogger(__name__)


class SubscriptionReminderJob:
    def __init__(
        self,
        notification_service: NotificationService,
        gateway: DataGateway,
        settings: NotificationSettings,
    ) -> None:
        self._notifications = notification_service
        self._gateway = gateway
        self._settings = settings

    async def run(self, today: dt.date | None = None) -> int:
        cfg = self._settings.subscription_reminders
        if not cfg.enabled:
            return 0

        today = today or dt.datetime.now(dt.timezone.utc).date()
        created_count = 0

        for days_left in cfg.intervals_days:
            target_date = today + dt.timedelta(days=days_left)
            subs = await self._gateway.list_active_subscriptions_expiring_on(target_date)
            for sub in subs:
                created = await self._notifications.handle_event(
                    ev.SubscriptionExpiring(
                        subscription_id=sub.id,
                        days_left=days_left,
                        expires_at=sub.expires_at,
                    )
                )
                created_count += len(created)

        if cfg.notify_on_expiry:
            expired = await self._gateway.list_active_subscriptions_expired_on(today)
            for sub in expired:
                created = await self._notifications.handle_event(
                    ev.SubscriptionExpired(subscription_id=sub.id, expired_at=today)
                )
                created_count += len(created)

        logger.info("subscription_reminder_job created %d notification(s)", created_count)
        return created_count
