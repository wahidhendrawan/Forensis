"""Add tenant isolation, normalized roles, OIDC identities, and structured audit logs.

Revision ID: 20260802_0001
Revises: 20260531_0001
Create Date: 2026-08-02
"""

from alembic import op
import sqlalchemy as sa


revision = "20260802_0001"
down_revision = "20260531_0001"
branch_labels = None
depends_on = None


TENANT_TABLES = (
    "analysis_history",
    "dfir_case",
    "artifact",
    "analysis_job",
    "finding",
    "rule_match",
    "timeline_event",
)


def _add_tenant_column(table_name: str) -> None:
    """Add and backfill a tenant column in a way SQLite can execute."""
    with op.batch_alter_table(table_name) as batch:
        batch.add_column(sa.Column("tenant_id", sa.String(length=64), nullable=True))
    op.execute(sa.text(f"UPDATE {table_name} SET tenant_id = 'default' WHERE tenant_id IS NULL"))
    with op.batch_alter_table(table_name) as batch:
        batch.alter_column(
            "tenant_id",
            existing_type=sa.String(length=64),
            nullable=False,
            server_default="default",
        )
        batch.create_index(f"ix_{table_name}_tenant_id", ["tenant_id"])


def upgrade() -> None:
    # User identity and authorization fields. `role` remains during transition
    # so current templates and local-login flows stay compatible.
    with op.batch_alter_table("users") as batch:
        batch.add_column(sa.Column("tenant_id", sa.String(length=64), nullable=True))
        batch.add_column(sa.Column("roles", sa.JSON(), nullable=True))
        batch.add_column(sa.Column("email", sa.String(length=255), nullable=True))
        batch.add_column(sa.Column("auth_provider", sa.String(length=32), nullable=True))
        batch.add_column(sa.Column("oidc_issuer", sa.String(length=512), nullable=True))
        batch.add_column(sa.Column("oidc_subject", sa.String(length=255), nullable=True))

    op.execute(sa.text("UPDATE users SET tenant_id = 'default' WHERE tenant_id IS NULL"))
    op.execute(sa.text("UPDATE users SET auth_provider = 'local' WHERE auth_provider IS NULL"))
    # JSON is stored as text on SQLite. An empty array deliberately lets the
    # model fall back to the legacy `role` value until a user is edited/logs in.
    op.execute(sa.text("UPDATE users SET roles = '[]' WHERE roles IS NULL"))

    with op.batch_alter_table("users") as batch:
        batch.alter_column("tenant_id", existing_type=sa.String(length=64), nullable=False, server_default="default")
        batch.alter_column("roles", existing_type=sa.JSON(), nullable=False, server_default="[]")
        batch.alter_column("auth_provider", existing_type=sa.String(length=32), nullable=False, server_default="local")
        batch.create_index("ix_user_tenant_id", ["tenant_id"])
        batch.create_index("ix_user_tenant_username", ["tenant_id", "username"])
        batch.create_unique_constraint("uq_user_oidc_identity", ["oidc_issuer", "oidc_subject"])

    for table_name in TENANT_TABLES:
        _add_tenant_column(table_name)

    op.create_table(
        "audit_log",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("ts", sa.DateTime(), nullable=False, server_default=sa.text("CURRENT_TIMESTAMP")),
        sa.Column("actor_sub", sa.String(length=255), nullable=False),
        sa.Column("actor_email", sa.String(length=255), nullable=True),
        sa.Column("tenant_id", sa.String(length=64), nullable=False, server_default="default"),
        sa.Column("action", sa.String(length=100), nullable=False),
        sa.Column("resource_type", sa.String(length=50), nullable=True),
        sa.Column("resource_id", sa.String(length=255), nullable=True),
        sa.Column("status", sa.String(length=20), nullable=False),
        sa.Column("ip_address", sa.String(length=45), nullable=True),
        sa.Column("user_agent", sa.Text(), nullable=True),
        sa.Column("metadata_json", sa.JSON(), nullable=False, server_default="{}"),
    )
    # Single-column indexes (match model index=True)
    op.create_index("ix_audit_log_tenant_id", "audit_log", ["tenant_id"])
    op.create_index("ix_audit_log_ts", "audit_log", ["ts"])
    # Composite indexes for common query patterns
    op.create_index("idx_audit_tenant_ts", "audit_log", ["tenant_id", "ts"])
    op.create_index("idx_audit_actor_ts", "audit_log", ["actor_sub", "ts"])
    op.create_index("idx_audit_action_ts", "audit_log", ["action", "ts"])


def downgrade() -> None:
    op.drop_index("idx_audit_action_ts", table_name="audit_log")
    op.drop_index("idx_audit_actor_ts", table_name="audit_log")
    op.drop_index("idx_audit_tenant_ts", table_name="audit_log")
    op.drop_index("ix_audit_log_ts", table_name="audit_log")
    op.drop_index("ix_audit_log_tenant_id", table_name="audit_log")
    op.drop_table("audit_log")

    for table_name in reversed(TENANT_TABLES):
        with op.batch_alter_table(table_name) as batch:
            batch.drop_index(f"ix_{table_name}_tenant_id")
            batch.drop_column("tenant_id")

    with op.batch_alter_table("users") as batch:
        batch.drop_constraint("uq_user_oidc_identity", type_="unique")
        batch.drop_index("ix_user_tenant_username")
        batch.drop_index("ix_user_tenant_id")
        batch.drop_column("oidc_subject")
        batch.drop_column("oidc_issuer")
        batch.drop_column("auth_provider")
        batch.drop_column("email")
        batch.drop_column("roles")
        batch.drop_column("tenant_id")
