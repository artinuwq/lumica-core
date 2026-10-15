"""Allow one receipt request to cover multiple family subscriptions.

Revision ID: 20261015_0002
Revises: 20261015_0001
"""

from alembic import op
import sqlalchemy as sa
from sqlalchemy import inspect

revision = "20261015_0002"
down_revision = "20261015_0001"
branch_labels = None
depends_on = None


def upgrade() -> None:
    conn = op.get_bind()
    tables = set(inspect(conn).get_table_names())
    if "payment_requests" in tables:
        columns = {column["name"] for column in inspect(conn).get_columns("payment_requests")}
        if "subscription_ids" not in columns:
            op.add_column("payment_requests", sa.Column("subscription_ids", sa.JSON(), nullable=True))


def downgrade() -> None:
    conn = op.get_bind()
    if "payment_requests" in set(inspect(conn).get_table_names()):
        columns = {column["name"] for column in inspect(conn).get_columns("payment_requests")}
        if "subscription_ids" in columns:
            op.drop_column("payment_requests", "subscription_ids")