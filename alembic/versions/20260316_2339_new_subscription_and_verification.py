"""Add verification, subscription builder, regions, templates

Revision ID: 20260316_2339
Revises: 
Create Date: 2026-03-16 23:39:00

"""
from __future__ import annotations

from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision = "20260316_2339"
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    # Existing tables: add columns
    with op.batch_alter_table("users") as batch:
        batch.add_column(sa.Column("status", sa.String(), nullable=False, server_default="verified"))

    with op.batch_alter_table("subscriptions") as batch:
        batch.add_column(sa.Column("total_price", sa.Numeric(10, 2), nullable=True))
        batch.add_column(sa.Column("payload", sa.JSON(), nullable=True))

    with op.batch_alter_table("vpn_accounts") as batch:
        batch.add_column(sa.Column("purpose", sa.String(), nullable=True))

    with op.batch_alter_table("panels") as batch:
        batch.add_column(sa.Column("region_id", sa.Integer(), nullable=True))

    with op.batch_alter_table("panel_inbounds") as batch:
        batch.add_column(sa.Column("tag", sa.String(4), nullable=True))

    with op.batch_alter_table("user_connections") as batch:
        batch.add_column(sa.Column("purpose", sa.String(32), nullable=True))

    # New tables
    op.create_table(
        "verification_codes",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("code", sa.String(8), nullable=False, unique=True),
        sa.Column("status", sa.String(), nullable=False, server_default="active"),
        sa.Column("issued_by", sa.Integer(), sa.ForeignKey("users.id", ondelete="SET NULL"), nullable=True),
        sa.Column("used_by", sa.Integer(), sa.ForeignKey("users.id", ondelete="SET NULL"), nullable=True),
        sa.Column("used_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
    )

    op.create_table(
        "user_verifications",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("user_id", sa.Integer(), sa.ForeignKey("users.id", ondelete="CASCADE"), nullable=False),
        sa.Column("method", sa.String(), nullable=False),
        sa.Column("code_id", sa.Integer(), sa.ForeignKey("verification_codes.id", ondelete="SET NULL"), nullable=True),
        sa.Column("approved_by", sa.Integer(), sa.ForeignKey("users.id", ondelete="SET NULL"), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
    )

    op.create_table(
        "subscription_plans",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("name", sa.String(), nullable=False),
        sa.Column("is_active", sa.Integer(), nullable=False, server_default="1"),
        sa.Column("base_price", sa.Numeric(10, 2), nullable=True),
        sa.Column("meta", sa.JSON(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
    )

    op.create_table(
        "subscription_items",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("subscription_id", sa.Integer(), sa.ForeignKey("subscriptions.id", ondelete="CASCADE"), nullable=False),
        sa.Column("item_type", sa.String(), nullable=False),
        sa.Column("code", sa.String(), nullable=False),
        sa.Column("price", sa.Numeric(10, 2), nullable=True),
        sa.Column("quantity", sa.Integer(), nullable=False, server_default="1"),
        sa.Column("meta", sa.JSON(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
    )

    op.create_table(
        "regions",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("code", sa.String(16), nullable=False, unique=True),
        sa.Column("name", sa.String(64), nullable=False),
        sa.Column("is_active", sa.Integer(), nullable=False, server_default="1"),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
    )

    op.create_table(
        "panel_templates",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("name", sa.String(120), nullable=False),
        sa.Column("protocol", sa.String(32), nullable=False),
        sa.Column("settings", sa.JSON(), nullable=True),
        sa.Column("apply_mode", sa.String(16), nullable=False, server_default="only_auto"),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
    )

    op.create_table(
        "panel_template_links",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("panel_id", sa.String(36), sa.ForeignKey("panels.id", ondelete="CASCADE"), nullable=False),
        sa.Column("template_id", sa.Integer(), sa.ForeignKey("panel_templates.id", ondelete="CASCADE"), nullable=False),
        sa.Column("mode", sa.String(32), nullable=False, server_default="bind_existing"),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
    )

    # Add FK from panels.region_id to regions.id
    with op.batch_alter_table("panels") as batch:
        batch.create_foreign_key("fk_panels_region_id", "regions", ["region_id"], ["id"], ondelete="SET NULL")



def downgrade() -> None:
    with op.batch_alter_table("panels") as batch:
        batch.drop_constraint("fk_panels_region_id", type_="foreignkey")

    op.drop_table("panel_template_links")
    op.drop_table("panel_templates")
    op.drop_table("regions")
    op.drop_table("subscription_items")
    op.drop_table("subscription_plans")
    op.drop_table("user_verifications")
    op.drop_table("verification_codes")

    with op.batch_alter_table("user_connections") as batch:
        batch.drop_column("purpose")

    with op.batch_alter_table("panel_inbounds") as batch:
        batch.drop_column("tag")

    with op.batch_alter_table("panels") as batch:
        batch.drop_column("region_id")

    with op.batch_alter_table("vpn_accounts") as batch:
        batch.drop_column("purpose")

    with op.batch_alter_table("subscriptions") as batch:
        batch.drop_column("payload")
        batch.drop_column("total_price")

    with op.batch_alter_table("users") as batch:
        batch.drop_column("status")
