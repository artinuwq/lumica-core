"""
Tests for the parts of the notification system that don't need a database:
rule -> spec construction, recipient resolution (the group-vs-personal
subscription behavior is the single most important thing to get right per
spec §15), and template rendering.

Run with `pytest` once this module is dropped into a lumica-core checkout
with its normal dependencies installed. A fake DataGateway stands in for the
real SQLAlchemy-backed one so these tests need no database at all.
"""

from __future__ import annotations

import datetime as dt

import pytest

from lumica.notifications.domain import events as ev
from lumica.notifications.domain.enums import NotificationType
from lumica.notifications.services.data_gateway import (
    GroupInfo,
    OwnerType,
    SubscriptionInfo,
    UserInfo,
    VpnAccountInfo,
)
from lumica.notifications.services.recipient_resolver import RecipientResolver
from lumica.notifications.services.rules import RuleEngine
from lumica.notifications.templates.renderer import TemplateRenderer


class FakeGateway:
    """Minimal in-memory stand-in for the real DataGateway, satisfying the
    Protocol duck-typed (no DB)."""

    def __init__(self):
        self.users = {
            1: UserInfo(1, "Ivan", telegram_chat_id=111, telegram_reachable=True),  # group admin
            2: UserInfo(2, "Maria", telegram_chat_id=222, telegram_reachable=True),  # member
            3: UserInfo(3, "Solo", telegram_chat_id=333, telegram_reachable=True),  # personal owner
        }
        self.groups = {
            15: GroupInfo(15, "Family", admin_user_id=1, member_user_ids=(2,)),
        }
        self.subscriptions = {
            200: SubscriptionInfo(200, OwnerType.GROUP, 15, dt.date(2026, 9, 15), "active"),
            300: SubscriptionInfo(300, OwnerType.USER, 3, dt.date(2026, 9, 20), "active"),
        }
        self.vpn_accounts = {
            44: VpnAccountInfo(44, owner_user_id=2, group_id=15, server_name="fra-1"),
        }
        self.admin_ids = (1,)
        self.super_admin_ids = ()

    async def get_subscription(self, subscription_id):
        return self.subscriptions[subscription_id]

    async def get_group(self, group_id):
        return self.groups[group_id]

    async def get_group_by_subscription(self, subscription_id):
        sub = self.subscriptions[subscription_id]
        if sub.owner_type == OwnerType.GROUP:
            return self.groups[sub.owner_id]
        return None

    async def get_vpn_account(self, vpn_account_id):
        return self.vpn_accounts[vpn_account_id]

    async def get_user(self, user_id):
        return self.users[user_id]

    async def get_admin_user_ids(self):
        return self.admin_ids

    async def get_super_admin_user_ids(self):
        return self.super_admin_ids


@pytest.fixture
def gateway():
    return FakeGateway()


@pytest.mark.asyncio
async def test_group_subscription_expiring_notifies_admin_only(gateway):
    """The single most load-bearing behavior in the spec: a group's shared
    subscription reminder goes to group.admin_id, never to members."""
    rules = RuleEngine(gateway)
    resolver = RecipientResolver(gateway)

    specs = await rules.build_specs(
        ev.SubscriptionExpiring(
            subscription_id=200, days_left=3, expires_at=dt.date(2026, 9, 15)
        )
    )
    assert len(specs) == 1

    recipients = await resolver.resolve(specs[0])
    assert recipients == [1]  # Ivan, the group admin
    assert 2 not in recipients  # Maria (member) never gets it


@pytest.mark.asyncio
async def test_personal_subscription_expiring_notifies_owner(gateway):
    rules = RuleEngine(gateway)
    resolver = RecipientResolver(gateway)

    specs = await rules.build_specs(
        ev.SubscriptionExpiring(
            subscription_id=300, days_left=3, expires_at=dt.date(2026, 9, 20)
        )
    )
    recipients = await resolver.resolve(specs[0])
    assert recipients == [3]  # Solo, the personal owner


@pytest.mark.asyncio
async def test_vpn_issue_notifies_member_directly_even_in_a_group(gateway):
    """VPN notifications are always personal/technical — the group admin is
    NOT the implicit recipient, even though this VPN belongs to a group
    member (spec §5, §15)."""
    resolver = RecipientResolver(gateway)

    # VPN_UNAVAILABLE specs are built by jobs/vpn_health_job.py rather than
    # RuleEngine, but they use the same resolver_hint shape.
    from lumica.notifications.domain.enums import RecipientType
    from lumica.notifications.services.rules import NotificationSpec

    spec = NotificationSpec(
        type=NotificationType.VPN_UNAVAILABLE,
        recipient_type=RecipientType.USER,
        resolver_hint={"user_id": gateway.vpn_accounts[44].owner_user_id},
        context={},
        dedup_key="vpn:44:unavailable:x",
    )
    recipients = await resolver.resolve(spec)
    assert recipients == [2]  # Maria, not Ivan


@pytest.mark.asyncio
async def test_dedup_key_distinguishes_reminder_checkpoints(gateway):
    rules = RuleEngine(gateway)

    specs_3d = await rules.build_specs(
        ev.SubscriptionExpiring(subscription_id=300, days_left=3, expires_at=dt.date(2026, 9, 20))
    )
    specs_1d = await rules.build_specs(
        ev.SubscriptionExpiring(subscription_id=300, days_left=1, expires_at=dt.date(2026, 9, 20))
    )
    assert specs_3d[0].dedup_key != specs_1d[0].dedup_key
    assert specs_3d[0].dedup_key == "subscription:300:expiring:3"


@pytest.mark.asyncio
async def test_dedup_key_stable_across_repeated_calls(gateway):
    """Same logical event, called twice (simulating scheduler double-run),
    must yield the identical dedup_key so the DB unique constraint catches
    the duplicate."""
    rules = RuleEngine(gateway)
    event = ev.SubscriptionExpiring(subscription_id=200, days_left=7, expires_at=dt.date(2026, 9, 15))

    specs_a = await rules.build_specs(event)
    specs_b = await rules.build_specs(event)
    assert specs_a[0].dedup_key == specs_b[0].dedup_key


def test_template_renderer_degrades_missing_variable_gracefully():
    renderer = TemplateRenderer()
    rendered = renderer.render(
        NotificationType.SUBSCRIPTION_EXPIRING,
        context={"date": "2026-09-15", "days_left": 3},  # group_name deliberately missing
    )
    assert "2026-09-15" in rendered.body
    assert "—" in rendered.body  # safe placeholder for the missing {group_name}
    assert rendered.buttons[0].text == "Продлить подписку"


def test_template_renderer_renders_group_subscription_prefix():
    renderer = TemplateRenderer()
    rendered = renderer.render(
        NotificationType.SUBSCRIPTION_EXPIRING,
        context={
            "date": "2026-09-15",
            "days_left": 3,
            "group_name": "группы «Family» в ",
        },
    )
    assert "группы «Family» в Lumica" in rendered.body
