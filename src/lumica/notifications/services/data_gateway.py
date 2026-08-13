"""
Everything the notification system needs to know about the rest of Lumica
(users, groups, subscriptions, vpn accounts, admins), expressed as a
Protocol instead of direct imports of those domain models.

Why: this module should be droppable into `src/lumica/notifications/`
without creating an import cycle with `src/lumica/domain` and without this
document having to guess the exact shape of those (unseen) models. The real
integration provides one concrete class (e.g. `SqlAlchemyDataGateway`) that
implements this Protocol against the actual `users` / `groups` /
`subscriptions` / `vpn_accounts` tables.

Only read access is needed here — the notification system never mutates
business entities.
"""

from __future__ import annotations

import datetime as dt
from dataclasses import dataclass
from typing import Optional, Protocol


class OwnerType:
    USER = "user"
    GROUP = "group"


@dataclass(frozen=True)
class SubscriptionInfo:
    id: int
    owner_type: str  # OwnerType.USER | OwnerType.GROUP
    owner_id: int  # user_id if USER, group_id if GROUP
    expires_at: dt.date
    status: str


@dataclass(frozen=True)
class GroupInfo:
    id: int
    name: str
    admin_user_id: int
    member_user_ids: tuple[int, ...]


@dataclass(frozen=True)
class VpnAccountInfo:
    id: int
    owner_user_id: int
    group_id: Optional[int]  # set if this VPN belongs to a group member
    server_name: str


@dataclass(frozen=True)
class UserInfo:
    id: int
    display_name: str
    telegram_chat_id: Optional[int]
    telegram_reachable: bool  # False once we've seen a permanent "blocked bot" error


class DataGateway(Protocol):
    async def get_subscription(self, subscription_id: int) -> SubscriptionInfo: ...

    async def get_group(self, group_id: int) -> GroupInfo: ...

    async def get_group_by_subscription(self, subscription_id: int) -> Optional[GroupInfo]:
        """Convenience: None if the subscription is not group-owned."""
        ...

    async def get_vpn_account(self, vpn_account_id: int) -> VpnAccountInfo: ...

    async def get_user(self, user_id: int) -> UserInfo: ...

    async def get_admin_user_ids(self) -> tuple[int, ...]: ...

    async def get_super_admin_user_ids(self) -> tuple[int, ...]: ...

    # --- bulk lookups used by scheduler jobs (jobs/subscription_reminder_job.py) ---

    async def list_active_subscriptions_expiring_on(
        self, target_date: dt.date
    ) -> tuple[SubscriptionInfo, ...]:
        """All active subscriptions (personal AND group) whose expires_at ==
        target_date. The job computes target_date = today + N for each
        configured interval; this method does the actual DB filtering so the
        job never has to know the subscription table's schema."""
        ...

    async def list_active_subscriptions_expired_on(
        self, target_date: dt.date
    ) -> tuple[SubscriptionInfo, ...]:
        """Subscriptions whose expires_at == target_date and which have not
        yet been marked expired (i.e. haven't had SUBSCRIPTION_EXPIRED
        raised for them). Used for the "expired today" checkpoint."""
        ...
