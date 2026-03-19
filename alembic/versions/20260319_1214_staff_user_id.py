"""Add staff.user_id and backfill via auth identities

Revision ID: 20260319_1214
Revises: 20260316_2352
Create Date: 2026-03-19 12:14:00

"""
from __future__ import annotations

from alembic import op
import sqlalchemy as sa
from sqlalchemy import inspect

# revision identifiers, used by Alembic.
revision = "20260319_1214"
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

    def _column_type(table: str, column: str) -> sa.types.TypeEngine:
        for col in inspector.get_columns(table):
            if col["name"] == column:
                return col["type"]
        return sa.String()

    if "staff" in existing_tables:
        staff_cols = _column_names("staff")
        if "user_id" not in staff_cols:
            with op.batch_alter_table("staff") as batch:
                batch.add_column(sa.Column("user_id", sa.Integer(), nullable=True))

        if "telegram_id" in staff_cols:
            telegram_type = _column_type("staff", "telegram_id")
            with op.batch_alter_table("staff") as batch:
                batch.alter_column("telegram_id", existing_type=telegram_type, nullable=True)

        if "users" in existing_tables:
            fks = {fk["name"] for fk in inspector.get_foreign_keys("staff")}
            if "fk_staff_user_id" not in fks and "user_id" in _column_names("staff"):
                with op.batch_alter_table("staff") as batch:
                    batch.create_foreign_key(
                        "fk_staff_user_id",
                        "users",
                        ["user_id"],
                        ["id"],
                        ondelete="SET NULL",
                    )

    if {"staff", "auth_identities"}.issubset(existing_tables):
        staff_cols = _column_names("staff")
        auth_cols = _column_names("auth_identities")
        if {"telegram_id", "user_id"}.issubset(staff_cols) and {"provider", "provider_user_id", "user_id"}.issubset(auth_cols):
            op.execute(
                sa.text(
                    """
                    UPDATE staff
                    SET user_id = (
                        SELECT ai.user_id
                        FROM auth_identities ai
                        WHERE ai.provider = 'telegram'
                          AND ai.provider_user_id = staff.telegram_id
                        LIMIT 1
                    )
                    WHERE staff.user_id IS NULL
                      AND staff.telegram_id IS NOT NULL
                    """
                )
            )


def downgrade() -> None:
    conn = op.get_bind()
    inspector = inspect(conn)
    existing_tables = set(inspector.get_table_names())

    def _column_names(table: str) -> set[str]:
        if table not in existing_tables:
            return set()
        return {col["name"] for col in inspector.get_columns(table)}

    def _column_type(table: str, column: str) -> sa.types.TypeEngine:
        for col in inspector.get_columns(table):
            if col["name"] == column:
                return col["type"]
        return sa.String()

    if "staff" in existing_tables:
        staff_cols = _column_names("staff")
        fks = {fk["name"] for fk in inspector.get_foreign_keys("staff")}
        telegram_type = _column_type("staff", "telegram_id")

        with op.batch_alter_table("staff") as batch:
            if "fk_staff_user_id" in fks:
                batch.drop_constraint("fk_staff_user_id", type_="foreignkey")
            if "user_id" in staff_cols:
                batch.drop_column("user_id")
            if "telegram_id" in staff_cols:
                batch.alter_column("telegram_id", existing_type=telegram_type, nullable=False)
