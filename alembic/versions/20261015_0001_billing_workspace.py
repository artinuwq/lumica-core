"""Add monthly billing state and payment requests.

Revision ID: 20261015_0001
Revises: 20260814_0001
"""

from alembic import op
import sqlalchemy as sa
from sqlalchemy import inspect

revision = "20261015_0001"
down_revision = "20260814_0001"
branch_labels = None
depends_on = None


def upgrade() -> None:
    conn = op.get_bind()
    inspector = inspect(conn)
    subscription_columns = {column["name"] for column in inspector.get_columns("subscriptions")}
    for column in (
        sa.Column("billing_day", sa.Integer(), nullable=True),
        sa.Column("billing_details", sa.Text(), nullable=True),
        sa.Column("is_frozen", sa.Boolean(), nullable=False, server_default=sa.false()),
    ):
        if column.name not in subscription_columns:
            op.add_column("subscriptions", column)

    tables = set(inspector.get_table_names())
    if "payment_requests" not in tables:
        op.create_table(
            "payment_requests",
            sa.Column("id", sa.Integer(), primary_key=True),
            sa.Column("subscription_id", sa.Integer(), sa.ForeignKey("subscriptions.id", ondelete="CASCADE"), nullable=False),
            sa.Column("subscription_ids", sa.JSON(), nullable=True),
            sa.Column("payer_user_id", sa.Integer(), sa.ForeignKey("users.id", ondelete="CASCADE"), nullable=False),
            sa.Column("amount", sa.Numeric(10, 2), nullable=True),
            sa.Column("status", sa.String(20), nullable=False, server_default="pending"),
            sa.Column("receipt_file_id", sa.String(256), nullable=True),
            sa.Column("operator_chat_id", sa.String(64), nullable=True),
            sa.Column("operator_message_id", sa.Integer(), nullable=True),
            sa.Column("reviewed_by", sa.Integer(), sa.ForeignKey("users.id", ondelete="SET NULL"), nullable=True),
            sa.Column("reviewed_at", sa.DateTime(timezone=True), nullable=True),
            sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        )
    indexes = {index["name"] for index in inspect(conn).get_indexes("payment_requests")}
    if "ix_payment_requests_status" not in indexes:
        op.create_index("ix_payment_requests_status", "payment_requests", ["status"])


def downgrade() -> None:
    conn = op.get_bind()
    inspector = inspect(conn)
    if "payment_requests" in set(inspector.get_table_names()):
        indexes = {index["name"] for index in inspect(conn).get_indexes("payment_requests")}
        if "ix_payment_requests_status" in indexes:
            op.drop_index("ix_payment_requests_status", table_name="payment_requests")
        op.drop_table("payment_requests")
    subscription_columns = {column["name"] for column in inspect(conn).get_columns("subscriptions")}
    for name in ("is_frozen", "billing_details", "billing_day"):
        if name in subscription_columns:
            op.drop_column("subscriptions", name)
