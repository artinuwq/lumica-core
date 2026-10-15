"""Persist admin actions for the user-events topic.

Revision ID: 20261015_0004
Revises: 20261015_0003
"""

from alembic import op
import sqlalchemy as sa
from sqlalchemy import inspect

revision = "20261015_0004"
down_revision = "20261015_0003"
branch_labels = None
depends_on = None


def upgrade() -> None:
    conn = op.get_bind()
    if "user_audit_events" in set(inspect(conn).get_table_names()):
        return
    op.create_table(
        "user_audit_events",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("actor_user_id", sa.Integer(), sa.ForeignKey("users.id", ondelete="SET NULL"), nullable=True),
        sa.Column("subject_user_id", sa.Integer(), sa.ForeignKey("users.id", ondelete="SET NULL"), nullable=True),
        sa.Column("action", sa.String(64), nullable=False),
        sa.Column("changes", sa.JSON(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
    )
    op.create_index("ix_user_audit_events_subject_created", "user_audit_events", ["subject_user_id", "created_at"])


def downgrade() -> None:
    conn = op.get_bind()
    if "user_audit_events" not in set(inspect(conn).get_table_names()):
        return
    indexes = {index["name"] for index in inspect(conn).get_indexes("user_audit_events")}
    if "ix_user_audit_events_subject_created" in indexes:
        op.drop_index("ix_user_audit_events_subject_created", table_name="user_audit_events")
    op.drop_table("user_audit_events")