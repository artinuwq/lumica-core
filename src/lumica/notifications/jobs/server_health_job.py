"""
Called by whatever already pings/health-checks VPN servers (out of scope
here) with a raw per-check result. Only real UP<->DOWN transitions — gated
by a configurable consecutive-failure threshold — produce a notification
(spec §6 SERVER: "1 failed check -> ничего, N failed checks -> SERVER_UNAVAILABLE").

These are admin-facing by default (recipient_type=ADMIN), so they go through
`NotificationService.create_from_spec` directly rather than
`handle_event(ServerHealthChanged(...))` — see rules.py's note on why raw
health signals aren't handled 1:1 by the RuleEngine.
"""

from __future__ import annotations

from lumica.notifications.config.settings import NotificationSettings
from lumica.notifications.domain.enums import NotificationType, RecipientType
from lumica.notifications.services.health_state_tracker import HealthStateTracker, Transition
from lumica.notifications.services.notification_service import NotificationService
from lumica.notifications.services.rules import NotificationSpec


class ServerHealthJob:
    def __init__(
        self,
        notification_service: NotificationService,
        tracker: HealthStateTracker,
        settings: NotificationSettings,
    ) -> None:
        self._notifications = notification_service
        self._tracker = tracker
        self._settings = settings

    async def record_check(self, server_id: int, server_name: str, is_healthy: bool) -> None:
        cfg = self._settings.server_health
        result = await self._tracker.record_check(
            state_key=f"server:{server_id}",
            is_healthy=is_healthy,
            failure_threshold=cfg.failure_threshold,
            recovery_threshold=cfg.recovery_threshold,
        )

        # `changed_at` comes from the (row-locked) state machine itself, not
        # a freshly-read clock, so it's identical across any callers racing
        # on the same transition — the dedup_key stays a true idempotency
        # key rather than a wall-clock guess (ARCHITECTURE.md §8 note).
        incident_marker = result.changed_at.isoformat()

        if result.transition == Transition.BECAME_DOWN:
            await self._notifications.create_from_spec(
                NotificationSpec(
                    type=NotificationType.SERVER_UNAVAILABLE,
                    recipient_type=RecipientType.ADMIN,
                    resolver_hint={"role": "admin"},
                    context={"server": server_name},
                    dedup_key=f"server:{server_id}:unavailable:{incident_marker}",
                    related_entity_type="server",
                    related_entity_id=server_id,
                )
            )
        elif result.transition == Transition.BECAME_UP:
            await self._notifications.create_from_spec(
                NotificationSpec(
                    type=NotificationType.SERVER_RECOVERED,
                    recipient_type=RecipientType.ADMIN,
                    resolver_hint={"role": "admin"},
                    context={"server": server_name},
                    dedup_key=f"server:{server_id}:recovered:{incident_marker}",
                    related_entity_type="server",
                    related_entity_id=server_id,
                )
            )
