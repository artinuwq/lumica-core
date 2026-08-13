"""create notification system tables

Revision ID: 20260813_0001
Revises:
Create Date: 2026-08-13

Integration note: set `down_revision` below to whatever the current head
revision is in the real lumica-core alembic history before applying.
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision = "20260813_0001"
down_revision = None  # TODO: set to current head revision in lumica-core
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "notification",
        sa.Column("id", sa.BigInteger(), primary_key=True, autoincrement=True),
        sa.Column("type", sa.String(64), nullable=False),
        sa.Column("priority", sa.String(16), nullable=False),
        sa.Column("recipient_type", sa.String(32), nullable=False),
        sa.Column("recipient_id", sa.BigInteger(), nullable=False),
        sa.Column("status", sa.String(16), nullable=False, server_default="pending"),
        sa.Column("dedup_key", sa.String(255), nullable=False),
        sa.Column(
            "context", postgresql.JSONB(astext_type=sa.Text()), nullable=False, server_default="{}"
        ),
        sa.Column("related_entity_type", sa.String(64), nullable=True),
        sa.Column("related_entity_id", sa.BigInteger(), nullable=True),
        sa.Column("not_before", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("cancelled_reason", sa.String(255), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.UniqueConstraint("dedup_key", name="uq_notification_dedup_key"),
    )
    op.create_index("ix_notification_type", "notification", ["type"])
    op.create_index("ix_notification_recipient_id", "notification", ["recipient_id"])
    op.create_index(
        "ix_notification_status_not_before", "notification", ["status", "not_before"]
    )
    op.create_index(
        "ix_notification_recipient_type_created",
        "notification",
        ["recipient_id", "type", "created_at"],
    )
    op.create_index(
        "ix_notification_related_entity",
        "notification",
        ["related_entity_type", "related_entity_id"],
    )

    op.create_table(
        "notification_delivery",
        sa.Column("id", sa.BigInteger(), primary_key=True, autoincrement=True),
        sa.Column(
            "notification_id",
            sa.BigInteger(),
            sa.ForeignKey("notification.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("channel", sa.String(16), nullable=False),
        sa.Column("status", sa.String(16), nullable=False, server_default="pending"),
        sa.Column("attempt_number", sa.Integer(), nullable=False, server_default="1"),
        sa.Column("error_code", sa.String(64), nullable=True),
        sa.Column("error_message", sa.Text(), nullable=True),
        sa.Column("provider_message_id", sa.String(128), nullable=True),
        sa.Column("attempted_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("next_retry_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
    )
    op.create_index("ix_delivery_notification_id", "notification_delivery", ["notification_id"])
    op.create_index(
        "ix_delivery_status_next_retry", "notification_delivery", ["status", "next_retry_at"]
    )

    op.create_table(
        "notification_preference",
        sa.Column("user_id", sa.BigInteger(), nullable=False),
        sa.Column("notification_type", sa.String(64), nullable=False),
        sa.Column("enabled", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.PrimaryKeyConstraint("user_id", "notification_type"),
    )

    op.create_table(
        "group_notification_settings",
        sa.Column("group_id", sa.BigInteger(), primary_key=True),
        sa.Column(
            "notify_admin_on_member_vpn_issues", sa.Boolean(), nullable=False, server_default=sa.false()
        ),
        sa.Column("notify_admin_on_group_events", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
    )

    op.create_table(
        "notification_channel_state",
        sa.Column("state_key", sa.String(128), primary_key=True),
        sa.Column("status", sa.String(8), nullable=False),
        sa.Column("consecutive_failures", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("changed_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
    )


def downgrade() -> None:
    op.drop_table("notification_channel_state")
    op.drop_table("group_notification_settings")
    op.drop_table("notification_preference")
    op.drop_index("ix_delivery_status_next_retry", table_name="notification_delivery")
    op.drop_index("ix_delivery_notification_id", table_name="notification_delivery")
    op.drop_table("notification_delivery")
    op.drop_index("ix_notification_related_entity", table_name="notification")
    op.drop_index("ix_notification_recipient_type_created", table_name="notification")
    op.drop_index("ix_notification_status_not_before", table_name="notification")
    op.drop_index("ix_notification_recipient_id", table_name="notification")
    op.drop_index("ix_notification_type", table_name="notification")
    op.drop_table("notification")
