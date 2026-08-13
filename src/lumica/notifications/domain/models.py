"""
ORM models for the notification subsystem.

Integration note
-----------------
This module defines its own `Base` for portability. In the real lumica-core
tree, delete the `Base = declarative_base()` line below and instead do:

    from lumica.domain.base import Base

so these tables live in the same metadata/migration chain as `users`,
`groups`, `subscriptions`, etc. Everything else (columns, indexes, relations)
is written against plain `sqlalchemy.ForeignKey("users.id")` style string
references, so it does not require importing those models directly and
does not create an import cycle.
"""

from __future__ import annotations

import datetime as dt
from typing import Any, Optional

from sqlalchemy import (
    BigInteger,
    Boolean,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
    func,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship

from lumica.notifications.domain.enums import (
    ChannelHealthStatus,
    DeliveryChannel,
    DeliveryStatus,
    NotificationStatus,
    NotificationType,
    Priority,
    RecipientType,
)


class Base(DeclarativeBase):
    pass


class Notification(Base):
    """'What needs to be communicated to a specific recipient.'

    One Notification == one logical message for one resolved recipient. It
    may end up with several `NotificationDelivery` rows if retries happen,
    but it is never re-created for the same logical occurrence — that's what
    `dedup_key` guarantees.
    """

    __tablename__ = "notification"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True)

    type: Mapped[NotificationType] = mapped_column(
        String(64), nullable=False, index=True
    )
    priority: Mapped[Priority] = mapped_column(String(16), nullable=False)

    recipient_type: Mapped[RecipientType] = mapped_column(String(32), nullable=False)
    recipient_id: Mapped[int] = mapped_column(BigInteger, nullable=False, index=True)

    status: Mapped[NotificationStatus] = mapped_column(
        String(16), nullable=False, default=NotificationStatus.PENDING
    )

    # Idempotency key — see ARCHITECTURE.md §8. This unique constraint is the
    # actual anti-duplication mechanism; everything else is best-effort.
    dedup_key: Mapped[str] = mapped_column(String(255), nullable=False, unique=True)

    # Template variables + any extra payload the rule wanted to carry along.
    context: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False, default=dict)

    # For admin drill-down and for rate-limit / state lookups, e.g.
    # ("subscription", 200) or ("vpn_account", 44).
    related_entity_type: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    related_entity_id: Mapped[Optional[int]] = mapped_column(BigInteger, nullable=True)

    # Delivery must not be attempted before this timestamp. Defaults to "now"
    # for immediate sends; scheduler-created reminders can set this ahead.
    not_before: Mapped[dt.datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )

    cancelled_reason: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)

    created_at: Mapped[dt.datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
    updated_at: Mapped[dt.datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
        onupdate=func.now(),
    )

    deliveries: Mapped[list["NotificationDelivery"]] = relationship(
        back_populates="notification",
        cascade="all, delete-orphan",
        order_by="NotificationDelivery.attempt_number",
    )

    __table_args__ = (
        Index("ix_notification_status_not_before", "status", "not_before"),
        Index(
            "ix_notification_recipient_type_created",
            "recipient_id",
            "type",
            "created_at",
        ),
        Index(
            "ix_notification_related_entity",
            "related_entity_type",
            "related_entity_id",
        ),
    )


class NotificationDelivery(Base):
    """One attempt to push a Notification through one channel.

    Deliberately has its OWN status, separate from Notification.status — see
    ARCHITECTURE.md §9 ("Do not mix Notification status and delivery attempt
    status").
    """

    __tablename__ = "notification_delivery"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    notification_id: Mapped[int] = mapped_column(
        BigInteger, ForeignKey("notification.id", ondelete="CASCADE"), nullable=False
    )

    channel: Mapped[DeliveryChannel] = mapped_column(String(16), nullable=False)
    status: Mapped[DeliveryStatus] = mapped_column(
        String(16), nullable=False, default=DeliveryStatus.PENDING
    )
    attempt_number: Mapped[int] = mapped_column(Integer, nullable=False, default=1)

    error_code: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    error_message: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    provider_message_id: Mapped[Optional[str]] = mapped_column(String(128), nullable=True)

    attempted_at: Mapped[Optional[dt.datetime]] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    next_retry_at: Mapped[Optional[dt.datetime]] = mapped_column(
        DateTime(timezone=True), nullable=True
    )

    created_at: Mapped[dt.datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )

    notification: Mapped["Notification"] = relationship(back_populates="deliveries")

    __table_args__ = (
        Index("ix_delivery_notification_id", "notification_id"),
        Index("ix_delivery_status_next_retry", "status", "next_retry_at"),
    )


class NotificationPreference(Base):
    """Per-user opt-out for MUTABLE notification types only. Mandatory types
    (see NotificationType.is_mutable) never get a row here and are always on.
    """

    __tablename__ = "notification_preference"

    user_id: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    notification_type: Mapped[NotificationType] = mapped_column(
        String(64), primary_key=True
    )
    enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)

    updated_at: Mapped[dt.datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
        onupdate=func.now(),
    )


class GroupNotificationSettings(Base):
    """Group-admin-controlled settings. Payment/subscription notifications
    for the group are NOT controlled here — those are mandatory and always
    go to group.admin_id (ARCHITECTURE.md §3.4).
    """

    __tablename__ = "group_notification_settings"

    group_id: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    notify_admin_on_member_vpn_issues: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=False
    )
    notify_admin_on_group_events: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=True
    )

    updated_at: Mapped[dt.datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
        onupdate=func.now(),
    )


class ChannelState(Base):
    """Flap-suppression state machine for VPN/server health notifications.
    See ARCHITECTURE.md §9. `state_key` examples: 'vpn:44', 'server:7'.
    """

    __tablename__ = "notification_channel_state"

    state_key: Mapped[str] = mapped_column(String(128), primary_key=True)
    status: Mapped[ChannelHealthStatus] = mapped_column(String(8), nullable=False)
    consecutive_failures: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    changed_at: Mapped[dt.datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )

    __table_args__ = (UniqueConstraint("state_key", name="uq_channel_state_key"),)
