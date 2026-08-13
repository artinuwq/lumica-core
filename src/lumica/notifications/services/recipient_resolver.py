"""
Turns a NotificationSpec's `resolver_hint` into concrete `user.id`s.

This is THE single place that knows "a group subscription resolves to
group.admin_id, never to the members" (spec §5, §15, §18). Every rule in
rules.py goes through this — none of them special-case groups themselves.
"""

from __future__ import annotations

from lumica.notifications.services.data_gateway import DataGateway, OwnerType
from lumica.notifications.services.rules import NotificationSpec


class RecipientResolver:
    def __init__(self, gateway: DataGateway) -> None:
        self._gw = gateway

    async def resolve(self, spec: NotificationSpec) -> list[int]:
        hint = spec.resolver_hint

        if "user_id" in hint:
            return [hint["user_id"]]

        if "subscription_id" in hint:
            return await self._resolve_subscription_owner(hint["subscription_id"])

        if "vpn_account_id" in hint:
            vpn = await self._gw.get_vpn_account(hint["vpn_account_id"])
            return [vpn.owner_user_id]

        if hint.get("role") == "admin":
            return list(await self._gw.get_admin_user_ids())

        if hint.get("role") == "super_admin":
            ids = list(await self._gw.get_super_admin_user_ids())
            # Fall back to regular admins if no super-admin is configured,
            # so critical system notifications are never silently dropped.
            return ids or list(await self._gw.get_admin_user_ids())

        if "group_id" in hint:
            group = await self._gw.get_group(hint["group_id"])
            return [group.admin_user_id]

        raise ValueError(f"Cannot resolve recipient from hint: {hint!r}")

    async def _resolve_subscription_owner(self, subscription_id: int) -> list[int]:
        """The one function in the whole system that decides "does this
        subscription notification go to a person or to a group admin".
        """
        sub = await self._gw.get_subscription(subscription_id)
        if sub.owner_type == OwnerType.GROUP:
            group = await self._gw.get_group(sub.owner_id)
            return [group.admin_user_id]  # never fan out to members
        return [sub.owner_id]
