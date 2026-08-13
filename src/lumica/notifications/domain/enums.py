"""
Closed catalogs for the notification system.

Nothing outside this module should define a new NotificationType,
RecipientType, DeliveryChannel, etc. ad-hoc — the whole point of a
centralized catalog is that business code can only ever pick from a known,
reviewed set of notification types instead of inventing free-text ones.
"""

from __future__ import annotations

import enum


class Priority(str, enum.Enum):
    INFO = "info"
    WARNING = "warning"
    CRITICAL = "critical"


class RecipientType(str, enum.Enum):
    """Conceptual recipient role. Always resolved to a concrete user id
    before a Notification row is created — see services/recipient_resolver.py.
    """

    USER = "user"
    GROUP_ADMIN = "group_admin"
    ADMIN = "admin"
    SUPER_ADMIN = "super_admin"


class DeliveryChannel(str, enum.Enum):
    TELEGRAM = "telegram"
    # Reserved for future use — do not implement yet (see ARCHITECTURE.md §15).
    EMAIL = "email"
    WEB = "web"
    PUSH = "push"


class NotificationStatus(str, enum.Enum):
    PENDING = "pending"
    PROCESSING = "processing"
    SENT = "sent"
    FAILED = "failed"
    CANCELLED = "cancelled"


class DeliveryStatus(str, enum.Enum):
    PENDING = "pending"
    SENT = "sent"
    FAILED = "failed"


class ChannelHealthStatus(str, enum.Enum):
    """Used by channel_state for VPN/server flap suppression (ARCHITECTURE.md §9)."""

    UP = "up"
    DOWN = "down"


class NotificationType(str, enum.Enum):
    # --- APPLICATION ---
    APPLICATION_CREATED = "application_created"
    APPLICATION_APPROVED = "application_approved"
    APPLICATION_REJECTED = "application_rejected"
    APPLICATION_NEED_INFORMATION = "application_need_information"

    # --- PAYMENT ---
    PAYMENT_INSTRUCTIONS = "payment_instructions"
    PAYMENT_REPORTED = "payment_reported"
    PAYMENT_CONFIRMED = "payment_confirmed"
    PAYMENT_REJECTED = "payment_rejected"

    # --- SUBSCRIPTION ---
    SUBSCRIPTION_EXPIRING = "subscription_expiring"
    SUBSCRIPTION_EXPIRED = "subscription_expired"
    SUBSCRIPTION_RENEWED = "subscription_renewed"
    SUBSCRIPTION_CANCELLED = "subscription_cancelled"

    # --- VPN ---
    VPN_CREATED = "vpn_created"
    VPN_DISABLED = "vpn_disabled"
    VPN_UNAVAILABLE = "vpn_unavailable"
    VPN_RECOVERED = "vpn_recovered"
    VPN_BLACKLISTED = "vpn_blacklisted"
    VPN_SERVER_CHANGED = "vpn_server_changed"
    # Optional digest sent to the group admin about a member's VPN issue,
    # gated by group_notification_settings.notify_admin_on_member_vpn_issues.
    VPN_MEMBER_ISSUE_DIGEST = "vpn_member_issue_digest"

    # --- SERVER (admin-facing) ---
    SERVER_UNAVAILABLE = "server_unavailable"
    SERVER_RECOVERED = "server_recovered"

    # --- SUPPORT ---
    SUPPORT_TICKET_CREATED = "support_ticket_created"
    SUPPORT_TICKET_UPDATED = "support_ticket_updated"
    SUPPORT_TICKET_CLOSED = "support_ticket_closed"

    # --- SYSTEM (admin-facing) ---
    SYSTEM_ERROR = "system_error"
    BACKGROUND_JOB_FAILED = "background_job_failed"
    NOTIFICATION_DELIVERY_FAILED = "notification_delivery_failed"

    @property
    def default_priority(self) -> Priority:
        return _DEFAULT_PRIORITY[self]

    @property
    def is_mutable(self) -> bool:
        """Can a regular user opt out of this type? See ARCHITECTURE.md §6."""
        return self in _MUTABLE_TYPES


# Types a user is allowed to mute. Everything else is mandatory:
# subscription/payment lifecycle, VPN outage/recovery, security-relevant, and
# all admin/system types are never muteable by a regular user.
_MUTABLE_TYPES: frozenset[NotificationType] = frozenset(
    {
        NotificationType.APPLICATION_CREATED,
        NotificationType.APPLICATION_APPROVED,
        NotificationType.SUPPORT_TICKET_UPDATED,
        NotificationType.VPN_SERVER_CHANGED,
    }
)

_DEFAULT_PRIORITY: dict[NotificationType, Priority] = {
    NotificationType.APPLICATION_CREATED: Priority.INFO,
    NotificationType.APPLICATION_APPROVED: Priority.INFO,
    NotificationType.APPLICATION_REJECTED: Priority.WARNING,
    NotificationType.APPLICATION_NEED_INFORMATION: Priority.WARNING,
    NotificationType.PAYMENT_INSTRUCTIONS: Priority.INFO,
    NotificationType.PAYMENT_REPORTED: Priority.WARNING,
    NotificationType.PAYMENT_CONFIRMED: Priority.INFO,
    NotificationType.PAYMENT_REJECTED: Priority.WARNING,
    NotificationType.SUBSCRIPTION_EXPIRING: Priority.WARNING,
    NotificationType.SUBSCRIPTION_EXPIRED: Priority.WARNING,
    NotificationType.SUBSCRIPTION_RENEWED: Priority.INFO,
    NotificationType.SUBSCRIPTION_CANCELLED: Priority.WARNING,
    NotificationType.VPN_CREATED: Priority.INFO,
    NotificationType.VPN_DISABLED: Priority.CRITICAL,
    NotificationType.VPN_UNAVAILABLE: Priority.CRITICAL,
    NotificationType.VPN_RECOVERED: Priority.INFO,
    NotificationType.VPN_BLACKLISTED: Priority.CRITICAL,
    NotificationType.VPN_SERVER_CHANGED: Priority.INFO,
    NotificationType.VPN_MEMBER_ISSUE_DIGEST: Priority.WARNING,
    NotificationType.SERVER_UNAVAILABLE: Priority.CRITICAL,
    NotificationType.SERVER_RECOVERED: Priority.INFO,
    NotificationType.SUPPORT_TICKET_CREATED: Priority.INFO,
    NotificationType.SUPPORT_TICKET_UPDATED: Priority.INFO,
    NotificationType.SUPPORT_TICKET_CLOSED: Priority.INFO,
    NotificationType.SYSTEM_ERROR: Priority.CRITICAL,
    NotificationType.BACKGROUND_JOB_FAILED: Priority.CRITICAL,
    NotificationType.NOTIFICATION_DELIVERY_FAILED: Priority.WARNING,
}
