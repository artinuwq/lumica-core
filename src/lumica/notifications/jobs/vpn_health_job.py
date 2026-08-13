"""
Same flap-suppression pattern as ServerHealthJob, but per VPN account and
always notifying the account owner directly — the owner might be a group
member, and that's fine, because this is a personal/technical notification,
not a subscription one (spec §5, §15).

If the VPN account belongs to a group AND that group has opted in via
`group_notification_settings.notify_admin_on_member_vpn_issues`, the job
also raises a separate VPN_MEMBER_ISSUE_DIGEST notification to the group
admin — a second, independently-resolved, independently-deduped
notification, never an implicit fan-out of the member's own message.
"""

from __future__ import annotations

from lumica.notifications.domain.enums import NotificationType, RecipientType
from lumica.notifications.services.data_gateway import DataGateway
from lumica.notifications.services.health_state_tracker import HealthStateTracker, Transition
from lumica.notifications.services.notification_service import NotificationService
from lumica.notifications.services.preferences_service import PreferenceService
from lumica.notifications.services.rules import NotificationSpec


class VpnHealthJob:
    def __init__(
        self,
        notification_service: NotificationService,
        gateway: DataGateway,
        tracker: HealthStateTracker,
        preferences: PreferenceService,
    ) -> None:
        self._notifications = notification_service
        self._gateway = gateway
        self._tracker = tracker
        self._preferences = preferences

    async def record_check(self, vpn_account_id: int, is_healthy: bool) -> None:
        # A single bad check is enough for VPN (unlike servers, spec doesn't
        # ask for a threshold here) — failure_threshold/recovery_threshold
        # default to 1 in HealthStateTracker.
        result = await self._tracker.record_check(
            state_key=f"vpn:{vpn_account_id}", is_healthy=is_healthy
        )
        if result.transition == Transition.NONE:
            return

        vpn = await self._gateway.get_vpn_account(vpn_account_id)
        incident_marker = result.changed_at.isoformat()

        if result.transition == Transition.BECAME_DOWN:
            await self._notifications.create_from_spec(
                NotificationSpec(
                    type=NotificationType.VPN_UNAVAILABLE,
                    recipient_type=RecipientType.USER,
                    resolver_hint={"user_id": vpn.owner_user_id},
                    context={"vpn_account_id": vpn_account_id},
                    dedup_key=f"vpn:{vpn_account_id}:unavailable:{incident_marker}",
                    related_entity_type="vpn_account",
                    related_entity_id=vpn_account_id,
                )
            )
            await self._maybe_notify_group_admin(vpn, incident_marker)
        elif result.transition == Transition.BECAME_UP:
            await self._notifications.create_from_spec(
                NotificationSpec(
                    type=NotificationType.VPN_RECOVERED,
                    recipient_type=RecipientType.USER,
                    resolver_hint={"user_id": vpn.owner_user_id},
                    context={},
                    dedup_key=f"vpn:{vpn_account_id}:recovered:{incident_marker}",
                    related_entity_type="vpn_account",
                    related_entity_id=vpn_account_id,
                )
            )

    async def _maybe_notify_group_admin(self, vpn, incident_marker: str) -> None:
        if vpn.group_id is None:
            return
        if not await self._preferences.notify_admin_on_member_vpn_issues(vpn.group_id):
            return

        owner = await self._gateway.get_user(vpn.owner_user_id)
        await self._notifications.create_from_spec(
            NotificationSpec(
                type=NotificationType.VPN_MEMBER_ISSUE_DIGEST,
                recipient_type=RecipientType.GROUP_ADMIN,
                resolver_hint={"group_id": vpn.group_id},
                context={"name": owner.display_name},
                dedup_key=f"vpn:{vpn.id}:member_issue_digest:{incident_marker}",
                related_entity_type="vpn_account",
                related_entity_id=vpn.id,
            )
        )
