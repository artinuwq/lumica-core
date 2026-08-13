"""
Business events. These are what `subscription_service`, `payment_service`,
`vpn_service`, `application_service`, `support_service` etc. raise. They are
plain, non-persisted dataclasses — the *only* contract between business logic
and the notification system.

A business service does e.g.:

    from lumica.notifications.domain.events import PaymentConfirmed
    from lumica.notifications.services.notification_service import NotificationService

    await notification_service.handle_event(
        PaymentConfirmed(payment_id=p.id, subscription_id=p.subscription_id, amount=p.amount)
    )

and nothing else. It never imports Telegram, never picks a recipient, never
touches a template.
"""

from __future__ import annotations

import datetime as dt
from dataclasses import dataclass, field


@dataclass(frozen=True, kw_only=True)
class Event:
    """Base class. `occurred_at` defaults to "now" so callers don't have to
    think about it, but can override for backfills/tests."""

    occurred_at: dt.datetime = field(default_factory=lambda: dt.datetime.now(dt.timezone.utc))


# --- APPLICATION ---


@dataclass(frozen=True, kw_only=True)
class ApplicationCreated(Event):
    application_id: int
    applicant_user_id: int


@dataclass(frozen=True, kw_only=True)
class ApplicationApproved(Event):
    application_id: int
    applicant_user_id: int


@dataclass(frozen=True, kw_only=True)
class ApplicationRejected(Event):
    application_id: int
    applicant_user_id: int
    reason: str | None = None


@dataclass(frozen=True, kw_only=True)
class ApplicationNeedInformation(Event):
    application_id: int
    applicant_user_id: int
    requested_info: str


# --- PAYMENT ---


@dataclass(frozen=True, kw_only=True)
class PaymentReported(Event):
    payment_id: int
    subscription_id: int
    amount: str


@dataclass(frozen=True, kw_only=True)
class PaymentConfirmed(Event):
    payment_id: int
    subscription_id: int
    amount: str


@dataclass(frozen=True, kw_only=True)
class PaymentRejected(Event):
    payment_id: int
    subscription_id: int
    reason: str | None = None


# --- SUBSCRIPTION ---
# Note: SUBSCRIPTION_EXPIRING is NOT raised ad-hoc by business code — it is
# produced exclusively by the subscription reminder job, which is the only
# thing that knows about configured reminder intervals (ARCHITECTURE.md §7 /
# spec §7). It's still modeled as an Event so it flows through the same
# handle_event() pipeline as everything else.


@dataclass(frozen=True, kw_only=True)
class SubscriptionExpiring(Event):
    subscription_id: int
    days_left: int
    expires_at: dt.date


@dataclass(frozen=True, kw_only=True)
class SubscriptionExpired(Event):
    subscription_id: int
    expired_at: dt.date


@dataclass(frozen=True, kw_only=True)
class SubscriptionRenewed(Event):
    subscription_id: int
    new_expires_at: dt.date


@dataclass(frozen=True, kw_only=True)
class SubscriptionCancelled(Event):
    subscription_id: int
    reason: str | None = None


# --- VPN ---


@dataclass(frozen=True, kw_only=True)
class VPNCreated(Event):
    vpn_account_id: int


@dataclass(frozen=True, kw_only=True)
class VPNDisabled(Event):
    vpn_account_id: int
    reason: str | None = None


@dataclass(frozen=True, kw_only=True)
class VPNHealthChanged(Event):
    """Raw health signal. The rule layer + ChannelState decide whether this
    actually represents a state *transition* worth notifying about — see
    ARCHITECTURE.md §9. `is_healthy=False` repeated many times in a row does
    NOT produce repeated notifications.
    """

    vpn_account_id: int
    is_healthy: bool


@dataclass(frozen=True, kw_only=True)
class VPNBlacklisted(Event):
    vpn_account_id: int


@dataclass(frozen=True, kw_only=True)
class VPNServerChanged(Event):
    vpn_account_id: int
    new_server_name: str


# --- SERVER (admin-facing) ---


@dataclass(frozen=True, kw_only=True)
class ServerHealthChanged(Event):
    """Raw health-check signal, e.g. from a periodic ping job. Same flap
    suppression treatment as VPNHealthChanged, plus a minimum consecutive
    failure threshold before it's treated as "really down"."""

    server_id: int
    is_healthy: bool


# --- SUPPORT ---


@dataclass(frozen=True, kw_only=True)
class SupportTicketCreated(Event):
    ticket_id: int
    user_id: int


@dataclass(frozen=True, kw_only=True)
class SupportTicketUpdated(Event):
    ticket_id: int
    user_id: int


@dataclass(frozen=True, kw_only=True)
class SupportTicketClosed(Event):
    ticket_id: int
    user_id: int


# --- SYSTEM (admin-facing) ---


@dataclass(frozen=True, kw_only=True)
class SystemErrorRaised(Event):
    component: str
    message: str


@dataclass(frozen=True, kw_only=True)
class BackgroundJobFailed(Event):
    job_name: str
    message: str
