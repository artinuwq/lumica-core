"""Add groups, group-payments; migrate payments away from single subscription_id

Revision ID: 20260811_0300
Revises: 20260811_0200
Create Date: 2026-08-12 03:00:00

Payments used to hold a single subscription_id (one payment <-> one
subscription). To support group payments (one payment covering several
members' subscriptions at once), the link is inverted: subscriptions now
carry payment_id, payments no longer carry subscription_id. Existing data is
backfilled before the old column is dropped, so no payment loses its
subscription link.
"""
from __future__ import annotations

from alembic import op
import sqlalchemy as sa
from sqlalchemy import inspect

# revision identifiers, used by Alembic.
revision = "20260811_0300"
down_revision = "20260811_0200"
branch_labels = None
depends_on = None


def upgrade() -> None:
    conn = op.get_bind()
    inspector = inspect(conn)
    existing_tables = set(inspector.get_table_names())

    if "groups" not in existing_tables:
        op.create_table(
            "groups",
            sa.Column("id", sa.Integer(), primary_key=True),
            sa.Column("name", sa.String(), nullable=True),
            sa.Column(
                "admin_user_id",
                sa.Integer(),
                sa.ForeignKey("users.id", ondelete="SET NULL", use_alter=True, name="fk_groups_admin_user_id"),
                nullable=True,
            ),
            sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        )

    user_columns = {c["name"] for c in inspector.get_columns("users")}
    if "group_id" not in user_columns:
        with op.batch_alter_table("users") as batch:
            batch.add_column(
                sa.Column(
                    "group_id",
                    sa.Integer(),
                    sa.ForeignKey("groups.id", ondelete="SET NULL", name="fk_users_group_id"),
                    nullable=True,
                )
            )
        op.create_index("ix_users_group_id", "users", ["group_id"])

    subscription_columns = {c["name"] for c in inspector.get_columns("subscriptions")}
    if "payment_id" not in subscription_columns:
        with op.batch_alter_table("subscriptions") as batch:
            batch.add_column(
                sa.Column(
                    "payment_id",
                    sa.Integer(),
                    sa.ForeignKey("payments.id", ondelete="SET NULL", name="fk_subscriptions_payment_id"),
                    nullable=True,
                )
            )
        op.create_index("ix_subscriptions_payment_id", "subscriptions", ["payment_id"])

    payment_columns = {c["name"] for c in inspector.get_columns("payments")}
    if "subscription_id" in payment_columns:
        # Backfill: every existing payment.subscription_id becomes that
        # subscription's payment_id before the old column is dropped.
        conn.execute(
            sa.text(
                "UPDATE subscriptions "
                "SET payment_id = ("
                "  SELECT payments.id FROM payments WHERE payments.subscription_id = subscriptions.id"
                ") "
                "WHERE id IN (SELECT subscription_id FROM payments WHERE subscription_id IS NOT NULL)"
            )
        )
        with op.batch_alter_table("payments") as batch:
            batch.drop_column("subscription_id")

    if "group_id" not in payment_columns:
        with op.batch_alter_table("payments") as batch:
            batch.add_column(
                sa.Column(
                    "group_id",
                    sa.Integer(),
                    sa.ForeignKey("groups.id", ondelete="SET NULL", name="fk_payments_group_id"),
                    nullable=True,
                )
            )
        op.create_index("ix_payments_group_id", "payments", ["group_id"])


def downgrade() -> None:
    with op.batch_alter_table("payments") as batch:
        batch.drop_index("ix_payments_group_id")
        batch.drop_column("group_id")
        batch.add_column(
            sa.Column(
                "subscription_id",
                sa.Integer(),
                sa.ForeignKey("subscriptions.id", ondelete="CASCADE", name="fk_payments_subscription_id"),
                nullable=True,
            )
        )

    op.execute(
        "UPDATE payments SET subscription_id = ("
        "  SELECT subscriptions.id FROM subscriptions WHERE subscriptions.payment_id = payments.id LIMIT 1"
        ")"
    )

    with op.batch_alter_table("subscriptions") as batch:
        batch.drop_index("ix_subscriptions_payment_id")
        batch.drop_column("payment_id")
    with op.batch_alter_table("users") as batch:
        batch.drop_index("ix_users_group_id")
        batch.drop_column("group_id")
    op.drop_table("groups")
