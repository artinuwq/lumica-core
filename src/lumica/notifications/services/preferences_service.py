"""
Whether a given (user, notification_type) pair should actually be created.

Mandatory types never look at the database — see NotificationType.is_mutable
and ARCHITECTURE.md §6/§14. This is called once per (recipient, spec) right
before a Notification row would be created, so a disabled preference results
in the notification simply never existing (not a "created then cancelled"
row) — cheaper and simpler for the common case.
"""

from __future__ import annotations

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from lumica.notifications.domain.enums import NotificationType
from lumica.notifications.domain.models import GroupNotificationSettings, NotificationPreference


class PreferenceService:
    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def is_enabled(self, user_id: int, type_: NotificationType) -> bool:
        if not type_.is_mutable:
            return True

        row = await self._session.get(NotificationPreference, (user_id, type_))
        if row is None:
            return True  # default: enabled until the user explicitly mutes it
        return row.enabled

    async def set_enabled(self, user_id: int, type_: NotificationType, enabled: bool) -> None:
        if not type_.is_mutable:
            raise ValueError(f"{type_} is mandatory and cannot be muted")

        row = await self._session.get(NotificationPreference, (user_id, type_))
        if row is None:
            row = NotificationPreference(
                user_id=user_id, notification_type=type_, enabled=enabled
            )
            self._session.add(row)
        else:
            row.enabled = enabled
        await self._session.flush()

    async def group_settings(self, group_id: int) -> GroupNotificationSettings:
        row = await self._session.get(GroupNotificationSettings, group_id)
        if row is None:
            # Defaults match the model's column defaults; not persisted until
            # an admin actually changes something.
            return GroupNotificationSettings(group_id=group_id)
        return row

    async def notify_admin_on_member_vpn_issues(self, group_id: int) -> bool:
        settings = await self.group_settings(group_id)
        return settings.notify_admin_on_member_vpn_issues
