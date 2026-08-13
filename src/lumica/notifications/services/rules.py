"""
Event -> NotificationSpec(s).

This is the single place that decides:
  * which NotificationType(s) an event produces,
  * what context/template-variables they carry,
  * the dedup_key,
  * a recipient *hint* (resolved to concrete user id(s) by RecipientResolver).

It deliberately does NOT resolve concrete Telegram user ids itself — see
recipient_resolver.py. Keeping resolution separate is what lets group vs.
individual subscription logic live in exactly one place (recipient_resolver)
instead of being re-implemented per event type here.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Optional

from lumica.notifications.domain import events as ev
from lumica.notifications.domain.enums import NotificationType, RecipientType
from lumica.notifications.services.data_gateway import DataGateway, OwnerType


@dataclass(frozen=True)
class NotificationSpec:
    type: NotificationType
    recipient_type: RecipientType
    # Resolver input: enough info to find the concrete user(s). Kept generic
    # (not just "one user id") because ADMIN/SUPER_ADMIN specs fan out.
    resolver_hint: dict[str, Any]
    context: dict[str, Any]
    dedup_key: str
    related_entity_type: Optional[str] = None
    related_entity_id: Optional[int] = None
    priority: Optional[str] = None  # overrides NotificationType.default_priority if set


def _group_name_prefix(group_name: Optional[str]) -> str:
    """`{group_name}Lumica` template convenience: '' for personal subs,
    'группы «X» в ' for group subs, so one template string serves both."""
    return f"группы «{group_name}» в " if group_name else ""


class RuleEngine:
    def __init__(self, gateway: DataGateway) -> None:
        self._gw = gateway

    async def build_specs(self, event: ev.Event) -> list[NotificationSpec]:
        handler = self._HANDLERS.get(type(event))
        if handler is None:
            return []
        return await handler(self, event)

    # ---------------------------------------------------------------- APPLICATION

    async def _application_created(self, e: ev.ApplicationCreated) -> list[NotificationSpec]:
        applicant = await self._gw.get_user(e.applicant_user_id)
        return [
            NotificationSpec(
                type=NotificationType.APPLICATION_CREATED,
                recipient_type=RecipientType.ADMIN,
                resolver_hint={"role": "admin"},
                context={"name": applicant.display_name, "application_id": e.application_id},
                dedup_key=f"application:{e.application_id}:created:admins",
                related_entity_type="application",
                related_entity_id=e.application_id,
            )
        ]

    async def _application_approved(self, e: ev.ApplicationApproved) -> list[NotificationSpec]:
        return [
            NotificationSpec(
                type=NotificationType.APPLICATION_APPROVED,
                recipient_type=RecipientType.USER,
                resolver_hint={"user_id": e.applicant_user_id},
                context={"application_id": e.application_id},
                dedup_key=f"application:{e.application_id}:approved",
                related_entity_type="application",
                related_entity_id=e.application_id,
            )
        ]

    async def _application_rejected(self, e: ev.ApplicationRejected) -> list[NotificationSpec]:
        return [
            NotificationSpec(
                type=NotificationType.APPLICATION_REJECTED,
                recipient_type=RecipientType.USER,
                resolver_hint={"user_id": e.applicant_user_id},
                context={"application_id": e.application_id, "reason": e.reason or "—"},
                dedup_key=f"application:{e.application_id}:rejected",
                related_entity_type="application",
                related_entity_id=e.application_id,
            )
        ]

    async def _application_need_info(
        self, e: ev.ApplicationNeedInformation
    ) -> list[NotificationSpec]:
        return [
            NotificationSpec(
                type=NotificationType.APPLICATION_NEED_INFORMATION,
                recipient_type=RecipientType.USER,
                resolver_hint={"user_id": e.applicant_user_id},
                context={
                    "application_id": e.application_id,
                    "requested_info": e.requested_info,
                },
                # includes occurred_at so a second, distinct info request can
                # still notify rather than being deduped against the first.
                dedup_key=(
                    f"application:{e.application_id}:need_info:"
                    f"{e.occurred_at.isoformat()}"
                ),
                related_entity_type="application",
                related_entity_id=e.application_id,
            )
        ]

    # ---------------------------------------------------------------- PAYMENT
    # Payment always concerns a subscription. If that subscription is
    # group-owned, the payer/recipient is the group admin (spec §6, §15) —
    # resolved centrally in recipient_resolver, not decided here.

    async def _payment_context(self, subscription_id: int) -> tuple[dict, Optional[str]]:
        sub = await self._gw.get_subscription(subscription_id)
        group_name = None
        if sub.owner_type == OwnerType.GROUP:
            group = await self._gw.get_group(sub.owner_id)
            group_name = group.name
        return (
            {"date": sub.expires_at.isoformat(), "group_name": _group_name_prefix(group_name)},
            group_name,
        )

    async def _payment_reported(self, e: ev.PaymentReported) -> list[NotificationSpec]:
        ctx, _ = await self._payment_context(e.subscription_id)
        ctx["amount"] = e.amount
        return [
            NotificationSpec(
                type=NotificationType.PAYMENT_REPORTED,
                recipient_type=RecipientType.ADMIN,
                resolver_hint={"role": "admin"},
                context={**ctx, "payment_id": e.payment_id},
                dedup_key=f"payment:{e.payment_id}:reported:admins",
                related_entity_type="payment",
                related_entity_id=e.payment_id,
            ),
            NotificationSpec(
                type=NotificationType.PAYMENT_REPORTED,
                recipient_type=RecipientType.USER,
                resolver_hint={"subscription_id": e.subscription_id},
                context={**ctx, "payment_id": e.payment_id},
                dedup_key=f"payment:{e.payment_id}:reported:payer",
                related_entity_type="payment",
                related_entity_id=e.payment_id,
            ),
        ]

    async def _payment_confirmed(self, e: ev.PaymentConfirmed) -> list[NotificationSpec]:
        ctx, _ = await self._payment_context(e.subscription_id)
        ctx["amount"] = e.amount
        return [
            NotificationSpec(
                type=NotificationType.PAYMENT_CONFIRMED,
                recipient_type=RecipientType.USER,
                resolver_hint={"subscription_id": e.subscription_id},
                context={**ctx, "payment_id": e.payment_id},
                dedup_key=f"payment:{e.payment_id}:confirmed",
                related_entity_type="payment",
                related_entity_id=e.payment_id,
            )
        ]

    async def _payment_rejected(self, e: ev.PaymentRejected) -> list[NotificationSpec]:
        ctx, _ = await self._payment_context(e.subscription_id)
        ctx["amount"] = ""
        ctx["reason"] = e.reason or "не указана"
        return [
            NotificationSpec(
                type=NotificationType.PAYMENT_REJECTED,
                recipient_type=RecipientType.USER,
                resolver_hint={"subscription_id": e.subscription_id},
                context={**ctx, "payment_id": e.payment_id},
                dedup_key=f"payment:{e.payment_id}:rejected",
                related_entity_type="payment",
                related_entity_id=e.payment_id,
            )
        ]

    # ---------------------------------------------------------------- SUBSCRIPTION
    # These fire once per subscription (personal or group) — never once per
    # group member. See ARCHITECTURE.md §5 / spec §15.

    async def _subscription_expiring(self, e: ev.SubscriptionExpiring) -> list[NotificationSpec]:
        sub = await self._gw.get_subscription(e.subscription_id)
        group_name = None
        if sub.owner_type == OwnerType.GROUP:
            group_name = (await self._gw.get_group(sub.owner_id)).name
        return [
            NotificationSpec(
                type=NotificationType.SUBSCRIPTION_EXPIRING,
                recipient_type=RecipientType.USER,
                resolver_hint={"subscription_id": e.subscription_id},
                context={
                    "date": e.expires_at.isoformat(),
                    "days_left": e.days_left,
                    "group_name": _group_name_prefix(group_name),
                    "subscription_id": e.subscription_id,
                },
                # days_left in the key: reminder for "3 days" and "1 day"
                # are distinct logical notifications, but re-running the
                # scheduler for the SAME checkpoint is a no-op (spec §8).
                dedup_key=f"subscription:{e.subscription_id}:expiring:{e.days_left}",
                related_entity_type="subscription",
                related_entity_id=e.subscription_id,
            )
        ]

    async def _subscription_expired(self, e: ev.SubscriptionExpired) -> list[NotificationSpec]:
        sub = await self._gw.get_subscription(e.subscription_id)
        group_name = None
        if sub.owner_type == OwnerType.GROUP:
            group_name = (await self._gw.get_group(sub.owner_id)).name
        return [
            NotificationSpec(
                type=NotificationType.SUBSCRIPTION_EXPIRED,
                recipient_type=RecipientType.USER,
                resolver_hint={"subscription_id": e.subscription_id},
                context={
                    "date": e.expired_at.isoformat(),
                    "group_name": _group_name_prefix(group_name),
                    "subscription_id": e.subscription_id,
                },
                dedup_key=f"subscription:{e.subscription_id}:expired",
                related_entity_type="subscription",
                related_entity_id=e.subscription_id,
            )
        ]

    async def _subscription_renewed(self, e: ev.SubscriptionRenewed) -> list[NotificationSpec]:
        sub = await self._gw.get_subscription(e.subscription_id)
        group_name = None
        if sub.owner_type == OwnerType.GROUP:
            group_name = (await self._gw.get_group(sub.owner_id)).name
        return [
            NotificationSpec(
                type=NotificationType.SUBSCRIPTION_RENEWED,
                recipient_type=RecipientType.USER,
                resolver_hint={"subscription_id": e.subscription_id},
                context={
                    "date": e.new_expires_at.isoformat(),
                    "group_name": _group_name_prefix(group_name),
                },
                dedup_key=(
                    f"subscription:{e.subscription_id}:renewed:"
                    f"{e.new_expires_at.isoformat()}"
                ),
                related_entity_type="subscription",
                related_entity_id=e.subscription_id,
            )
        ]

    async def _subscription_cancelled(
        self, e: ev.SubscriptionCancelled
    ) -> list[NotificationSpec]:
        sub = await self._gw.get_subscription(e.subscription_id)
        group_name = None
        if sub.owner_type == OwnerType.GROUP:
            group_name = (await self._gw.get_group(sub.owner_id)).name
        return [
            NotificationSpec(
                type=NotificationType.SUBSCRIPTION_CANCELLED,
                recipient_type=RecipientType.USER,
                resolver_hint={"subscription_id": e.subscription_id},
                context={"group_name": _group_name_prefix(group_name)},
                dedup_key=f"subscription:{e.subscription_id}:cancelled:{e.occurred_at.date()}",
                related_entity_type="subscription",
                related_entity_id=e.subscription_id,
            )
        ]

    # ---------------------------------------------------------------- VPN
    # Always personal — goes to the VPN account owner, even if that owner is
    # a group member (spec §15). VPNHealthChanged is handled by the health
    # job's state machine, not here (raw signals aren't 1:1 with notifications).

    async def _vpn_created(self, e: ev.VPNCreated) -> list[NotificationSpec]:
        return [
            NotificationSpec(
                type=NotificationType.VPN_CREATED,
                recipient_type=RecipientType.USER,
                resolver_hint={"vpn_account_id": e.vpn_account_id},
                context={},
                dedup_key=f"vpn:{e.vpn_account_id}:created",
                related_entity_type="vpn_account",
                related_entity_id=e.vpn_account_id,
            )
        ]

    async def _vpn_disabled(self, e: ev.VPNDisabled) -> list[NotificationSpec]:
        return [
            NotificationSpec(
                type=NotificationType.VPN_DISABLED,
                recipient_type=RecipientType.USER,
                resolver_hint={"vpn_account_id": e.vpn_account_id},
                context={"vpn_account_id": e.vpn_account_id},
                dedup_key=f"vpn:{e.vpn_account_id}:disabled:{e.occurred_at.date()}",
                related_entity_type="vpn_account",
                related_entity_id=e.vpn_account_id,
            )
        ]

    async def _vpn_blacklisted(self, e: ev.VPNBlacklisted) -> list[NotificationSpec]:
        return [
            NotificationSpec(
                type=NotificationType.VPN_BLACKLISTED,
                recipient_type=RecipientType.USER,
                resolver_hint={"vpn_account_id": e.vpn_account_id},
                context={},
                dedup_key=f"vpn:{e.vpn_account_id}:blacklisted",
                related_entity_type="vpn_account",
                related_entity_id=e.vpn_account_id,
            )
        ]

    async def _vpn_server_changed(self, e: ev.VPNServerChanged) -> list[NotificationSpec]:
        return [
            NotificationSpec(
                type=NotificationType.VPN_SERVER_CHANGED,
                recipient_type=RecipientType.USER,
                resolver_hint={"vpn_account_id": e.vpn_account_id},
                context={"server": e.new_server_name},
                dedup_key=(
                    f"vpn:{e.vpn_account_id}:server_changed:"
                    f"{e.occurred_at.isoformat()}"
                ),
                related_entity_type="vpn_account",
                related_entity_id=e.vpn_account_id,
            )
        ]

    # ---------------------------------------------------------------- SUPPORT

    async def _ticket_created(self, e: ev.SupportTicketCreated) -> list[NotificationSpec]:
        return [
            NotificationSpec(
                type=NotificationType.SUPPORT_TICKET_CREATED,
                recipient_type=RecipientType.USER,
                resolver_hint={"user_id": e.user_id},
                context={"ticket_id": e.ticket_id},
                dedup_key=f"support:{e.ticket_id}:created",
                related_entity_type="support_ticket",
                related_entity_id=e.ticket_id,
            ),
            NotificationSpec(
                type=NotificationType.SUPPORT_TICKET_CREATED,
                recipient_type=RecipientType.ADMIN,
                resolver_hint={"role": "admin"},
                context={"ticket_id": e.ticket_id},
                dedup_key=f"support:{e.ticket_id}:created:admins",
                related_entity_type="support_ticket",
                related_entity_id=e.ticket_id,
            ),
        ]

    async def _ticket_updated(self, e: ev.SupportTicketUpdated) -> list[NotificationSpec]:
        return [
            NotificationSpec(
                type=NotificationType.SUPPORT_TICKET_UPDATED,
                recipient_type=RecipientType.USER,
                resolver_hint={"user_id": e.user_id},
                context={"ticket_id": e.ticket_id},
                dedup_key=f"support:{e.ticket_id}:updated:{e.occurred_at.isoformat()}",
                related_entity_type="support_ticket",
                related_entity_id=e.ticket_id,
            )
        ]

    async def _ticket_closed(self, e: ev.SupportTicketClosed) -> list[NotificationSpec]:
        return [
            NotificationSpec(
                type=NotificationType.SUPPORT_TICKET_CLOSED,
                recipient_type=RecipientType.USER,
                resolver_hint={"user_id": e.user_id},
                context={"ticket_id": e.ticket_id},
                dedup_key=f"support:{e.ticket_id}:closed",
                related_entity_type="support_ticket",
                related_entity_id=e.ticket_id,
            )
        ]

    # ---------------------------------------------------------------- SYSTEM

    async def _system_error(self, e: ev.SystemErrorRaised) -> list[NotificationSpec]:
        return [
            NotificationSpec(
                type=NotificationType.SYSTEM_ERROR,
                recipient_type=RecipientType.SUPER_ADMIN,
                resolver_hint={"role": "super_admin"},
                context={"name": e.component, "amount": e.message},
                dedup_key=f"system:error:{e.component}:{e.occurred_at.isoformat()}",
            )
        ]

    async def _background_job_failed(self, e: ev.BackgroundJobFailed) -> list[NotificationSpec]:
        return [
            NotificationSpec(
                type=NotificationType.BACKGROUND_JOB_FAILED,
                recipient_type=RecipientType.SUPER_ADMIN,
                resolver_hint={"role": "super_admin"},
                context={"name": e.job_name},
                dedup_key=f"job:{e.job_name}:failed:{e.occurred_at.isoformat()}",
            )
        ]

    _HANDLERS: dict[type, Any] = {}


# Registered after class body so methods exist as bound-callable references.
RuleEngine._HANDLERS = {
    ev.ApplicationCreated: RuleEngine._application_created,
    ev.ApplicationApproved: RuleEngine._application_approved,
    ev.ApplicationRejected: RuleEngine._application_rejected,
    ev.ApplicationNeedInformation: RuleEngine._application_need_info,
    ev.PaymentReported: RuleEngine._payment_reported,
    ev.PaymentConfirmed: RuleEngine._payment_confirmed,
    ev.PaymentRejected: RuleEngine._payment_rejected,
    ev.SubscriptionExpiring: RuleEngine._subscription_expiring,
    ev.SubscriptionExpired: RuleEngine._subscription_expired,
    ev.SubscriptionRenewed: RuleEngine._subscription_renewed,
    ev.SubscriptionCancelled: RuleEngine._subscription_cancelled,
    ev.VPNCreated: RuleEngine._vpn_created,
    ev.VPNDisabled: RuleEngine._vpn_disabled,
    ev.VPNBlacklisted: RuleEngine._vpn_blacklisted,
    ev.VPNServerChanged: RuleEngine._vpn_server_changed,
    ev.SupportTicketCreated: RuleEngine._ticket_created,
    ev.SupportTicketUpdated: RuleEngine._ticket_updated,
    ev.SupportTicketClosed: RuleEngine._ticket_closed,
    ev.SystemErrorRaised: RuleEngine._system_error,
    ev.BackgroundJobFailed: RuleEngine._background_job_failed,
    # ev.VPNHealthChanged / ev.ServerHealthChanged are intentionally absent —
    # they're consumed by jobs/server_health_job.py and the VPN-health
    # equivalent, which own the flap-suppression state machine and emit
    # VPN_UNAVAILABLE/VPN_RECOVERED/SERVER_UNAVAILABLE/SERVER_RECOVERED specs
    # directly (see ARCHITECTURE.md §9).
}
