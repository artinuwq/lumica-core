"""Add notification_log table (simple reminder idempotency)

Revision ID: 20260814_0001
Revises: 20260813_0001
Create Date: 2026-08-14

"""
from __future__ import annotations

from alembic import op
import sqlalchemy as sa
from sqlalchemy import inspect

# revision identifiers, used by Alembic.
revision = "20260814_0001"
down_revision = "20260813_0001"
branch_labels = None
depends_on = None


def upgrade() -> None:
    conn = op.get_bind()
    inspector = inspect(conn)
    if "notification_log" in set(inspector.get_table_names()):
        return

    op.create_table(
        "notification_log",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("user_id", sa.Integer(), sa.ForeignKey("users.id", ondelete="CASCADE"), nullable=False),
        sa.Column("key", sa.String(), nullable=False),
        sa.Column("success", sa.Integer(), nullable=False, server_default="1"),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.UniqueConstraint("user_id", "key", name="uq_notification_log_user_key"),
    )
    op.create_index("ix_notification_log_user_id", "notification_log", ["user_id"])


def downgrade() -> None:
    op.drop_index("ix_notification_log_user_id", table_name="notification_log")
    op.drop_table("notification_log")
