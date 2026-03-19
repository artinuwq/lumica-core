"""Add auth identities and phone contact

Revision ID: 20260319_1215
Revises: 20260316_2352
Create Date: 2026-03-19 12:15:00

"""
from __future__ import annotations

from alembic import op
import sqlalchemy as sa
from sqlalchemy import inspect

# revision identifiers, used by Alembic.
revision = "20260319_1215"
down_revision = "20260316_2352"
branch_labels = None
depends_on = None


def upgrade() -> None:
    conn = op.get_bind()
    inspector = inspect(conn)
    existing_tables = set(inspector.get_table_names())

    def _column_names(table: str) -> set[str]:
        if table not in existing_tables:
            return set()
        return {col["name"] for col in inspector.get_columns(table)}

    if "users" in existing_tables:
        cols = _column_names("users")
        with op.batch_alter_table("users") as batch:
            if "phone" not in cols:
                batch.add_column(sa.Column("phone", sa.String(), nullable=True))
            if "telegram_id" in cols:
                batch.alter_column("telegram_id", existing_type=sa.String(), nullable=True)

    if "auth_identities" not in existing_tables:
        op.create_table(
            "auth_identities",
            sa.Column("id", sa.Integer(), primary_key=True),
            sa.Column("user_id", sa.Integer(), sa.ForeignKey("users.id", ondelete="CASCADE"), nullable=False),
            sa.Column("provider", sa.String(), nullable=False),
            sa.Column("provider_user_id", sa.String(), nullable=False),
            sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
            sa.UniqueConstraint("provider", "provider_user_id", name="uq_auth_identities_provider_user_id"),
        )


def downgrade() -> None:
    conn = op.get_bind()
    inspector = inspect(conn)
    existing_tables = set(inspector.get_table_names())

    if "auth_identities" in existing_tables:
        op.drop_table("auth_identities")

    if "users" in existing_tables:
        with op.batch_alter_table("users") as batch:
            batch.alter_column("telegram_id", existing_type=sa.String(), nullable=False)
            batch.drop_column("phone")
