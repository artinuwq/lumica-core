"""Link subscriptions to their server-side VPN accounts.

Revision ID: 20261015_0003
Revises: 20261015_0002
"""

from alembic import op
import sqlalchemy as sa
from sqlalchemy import inspect

revision = "20261015_0003"
down_revision = "20261015_0002"
branch_labels = None
depends_on = None


def upgrade() -> None:
    conn = op.get_bind()
    if "subscription_vpn_accounts" not in set(inspect(conn).get_table_names()):
        op.create_table(
            "subscription_vpn_accounts",
            sa.Column("id", sa.Integer(), primary_key=True),
            sa.Column("subscription_id", sa.Integer(), sa.ForeignKey("subscriptions.id", ondelete="CASCADE"), nullable=False),
            sa.Column("vpn_account_id", sa.Integer(), sa.ForeignKey("vpn_accounts.id", ondelete="CASCADE"), nullable=False),
            sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
            sa.UniqueConstraint("subscription_id", "vpn_account_id", name="uq_subscription_vpn_account"),
        )
    indexes = {index["name"] for index in inspect(conn).get_indexes("subscription_vpn_accounts")}
    if "ix_subscription_vpn_accounts_vpn_account_id" not in indexes:
        op.create_index("ix_subscription_vpn_accounts_vpn_account_id", "subscription_vpn_accounts", ["vpn_account_id"])


def downgrade() -> None:
    conn = op.get_bind()
    if "subscription_vpn_accounts" in set(inspect(conn).get_table_names()):
        indexes = {index["name"] for index in inspect(conn).get_indexes("subscription_vpn_accounts")}
        if "ix_subscription_vpn_accounts_vpn_account_id" in indexes:
            op.drop_index("ix_subscription_vpn_accounts_vpn_account_id", table_name="subscription_vpn_accounts")
        op.drop_table("subscription_vpn_accounts")