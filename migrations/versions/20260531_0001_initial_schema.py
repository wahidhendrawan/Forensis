"""initial forensis schema

Revision ID: 20260531_0001
Revises: None
Create Date: 2026-05-31 13:20:00
"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = "20260531_0001"
down_revision: Union[str, None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "group",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("name", sa.String(length=100), nullable=False),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("name"),
    )

    op.create_table(
        "user",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("username", sa.String(length=150), nullable=False),
        sa.Column("password_hash", sa.String(length=200), nullable=False),
        sa.Column("role", sa.String(length=50), nullable=False),
        sa.Column("group_id", sa.Integer(), nullable=True),
        sa.Column("mfa_secret", sa.String(length=32), nullable=True),
        sa.Column("mfa_enabled", sa.Boolean(), nullable=True),
        sa.ForeignKeyConstraint(["group_id"], ["group.id"]),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("username"),
    )

    op.create_table(
        "analysis_history",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("type", sa.String(length=50), nullable=False),
        sa.Column("timestamp", sa.DateTime(), nullable=False),
        sa.Column("user_id", sa.Integer(), nullable=True),
        sa.Column("results_json", sa.Text(), nullable=True),
        sa.Column("filename", sa.String(length=255), nullable=True),
        sa.ForeignKeyConstraint(["user_id"], ["user.id"]),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(op.f("ix_analysis_history_timestamp"), "analysis_history", ["timestamp"], unique=False)
    op.create_index(op.f("ix_analysis_history_user_id"), "analysis_history", ["user_id"], unique=False)

    op.create_table(
        "system_setting",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("key", sa.String(length=120), nullable=False),
        sa.Column("value", sa.Text(), nullable=True),
        sa.Column("updated_at", sa.DateTime(), nullable=False),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(op.f("ix_system_setting_key"), "system_setting", ["key"], unique=True)

    op.create_table(
        "dfir_case",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("case_key", sa.String(length=64), nullable=False),
        sa.Column("title", sa.String(length=255), nullable=False),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column("status", sa.String(length=32), nullable=False),
        sa.Column("severity", sa.String(length=16), nullable=False),
        sa.Column("owner_user_id", sa.Integer(), nullable=True),
        sa.Column("schema_version", sa.String(length=32), nullable=False),
        sa.Column("metadata_json", sa.Text(), nullable=True),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.Column("updated_at", sa.DateTime(), nullable=False),
        sa.ForeignKeyConstraint(["owner_user_id"], ["user.id"]),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(op.f("ix_dfir_case_case_key"), "dfir_case", ["case_key"], unique=True)
    op.create_index(op.f("ix_dfir_case_created_at"), "dfir_case", ["created_at"], unique=False)
    op.create_index(op.f("ix_dfir_case_owner_user_id"), "dfir_case", ["owner_user_id"], unique=False)
    op.create_index(op.f("ix_dfir_case_severity"), "dfir_case", ["severity"], unique=False)
    op.create_index(op.f("ix_dfir_case_status"), "dfir_case", ["status"], unique=False)

    op.create_table(
        "artifact",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("case_id", sa.Integer(), nullable=True),
        sa.Column("uploaded_by_user_id", sa.Integer(), nullable=True),
        sa.Column("artifact_type", sa.String(length=32), nullable=False),
        sa.Column("filename", sa.String(length=255), nullable=False),
        sa.Column("storage_backend", sa.String(length=32), nullable=False),
        sa.Column("storage_path", sa.String(length=1024), nullable=True),
        sa.Column("mime_type", sa.String(length=255), nullable=True),
        sa.Column("size_bytes", sa.Integer(), nullable=True),
        sa.Column("sha256", sa.String(length=64), nullable=True),
        sa.Column("metadata_json", sa.Text(), nullable=True),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.ForeignKeyConstraint(["case_id"], ["dfir_case.id"]),
        sa.ForeignKeyConstraint(["uploaded_by_user_id"], ["user.id"]),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(op.f("ix_artifact_artifact_type"), "artifact", ["artifact_type"], unique=False)
    op.create_index(op.f("ix_artifact_case_id"), "artifact", ["case_id"], unique=False)
    op.create_index(op.f("ix_artifact_created_at"), "artifact", ["created_at"], unique=False)
    op.create_index(op.f("ix_artifact_sha256"), "artifact", ["sha256"], unique=False)
    op.create_index(op.f("ix_artifact_uploaded_by_user_id"), "artifact", ["uploaded_by_user_id"], unique=False)

    op.create_table(
        "analysis_job",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("case_id", sa.Integer(), nullable=True),
        sa.Column("artifact_id", sa.Integer(), nullable=True),
        sa.Column("history_id", sa.Integer(), nullable=True),
        sa.Column("submitted_by_user_id", sa.Integer(), nullable=True),
        sa.Column("job_type", sa.String(length=32), nullable=False),
        sa.Column("queue_name", sa.String(length=64), nullable=False),
        sa.Column("state", sa.String(length=16), nullable=False),
        sa.Column("stage", sa.String(length=32), nullable=False),
        sa.Column("progress", sa.Integer(), nullable=False),
        sa.Column("task_id", sa.String(length=128), nullable=True),
        sa.Column("error_message", sa.Text(), nullable=True),
        sa.Column("result_summary_json", sa.Text(), nullable=True),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.Column("updated_at", sa.DateTime(), nullable=False),
        sa.Column("started_at", sa.DateTime(), nullable=True),
        sa.Column("finished_at", sa.DateTime(), nullable=True),
        sa.ForeignKeyConstraint(["artifact_id"], ["artifact.id"]),
        sa.ForeignKeyConstraint(["case_id"], ["dfir_case.id"]),
        sa.ForeignKeyConstraint(["history_id"], ["analysis_history.id"]),
        sa.ForeignKeyConstraint(["submitted_by_user_id"], ["user.id"]),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("task_id"),
    )
    op.create_index(op.f("ix_analysis_job_artifact_id"), "analysis_job", ["artifact_id"], unique=False)
    op.create_index(op.f("ix_analysis_job_case_id"), "analysis_job", ["case_id"], unique=False)
    op.create_index(op.f("ix_analysis_job_created_at"), "analysis_job", ["created_at"], unique=False)
    op.create_index(op.f("ix_analysis_job_history_id"), "analysis_job", ["history_id"], unique=False)
    op.create_index(op.f("ix_analysis_job_job_type"), "analysis_job", ["job_type"], unique=False)
    op.create_index(op.f("ix_analysis_job_stage"), "analysis_job", ["stage"], unique=False)
    op.create_index(op.f("ix_analysis_job_state"), "analysis_job", ["state"], unique=False)
    op.create_index(op.f("ix_analysis_job_submitted_by_user_id"), "analysis_job", ["submitted_by_user_id"], unique=False)
    op.create_index(op.f("ix_analysis_job_task_id"), "analysis_job", ["task_id"], unique=True)

    op.create_table(
        "finding",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("case_id", sa.Integer(), nullable=True),
        sa.Column("analysis_job_id", sa.Integer(), nullable=True),
        sa.Column("source_type", sa.String(length=32), nullable=False),
        sa.Column("category", sa.String(length=64), nullable=True),
        sa.Column("severity", sa.String(length=16), nullable=False),
        sa.Column("indicator", sa.String(length=255), nullable=True),
        sa.Column("title", sa.String(length=255), nullable=False),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column("score", sa.Integer(), nullable=False),
        sa.Column("event_ref", sa.String(length=255), nullable=True),
        sa.Column("raw_json", sa.Text(), nullable=True),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.ForeignKeyConstraint(["analysis_job_id"], ["analysis_job.id"]),
        sa.ForeignKeyConstraint(["case_id"], ["dfir_case.id"]),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(op.f("ix_finding_analysis_job_id"), "finding", ["analysis_job_id"], unique=False)
    op.create_index(op.f("ix_finding_case_id"), "finding", ["case_id"], unique=False)
    op.create_index(op.f("ix_finding_category"), "finding", ["category"], unique=False)
    op.create_index(op.f("ix_finding_created_at"), "finding", ["created_at"], unique=False)
    op.create_index(op.f("ix_finding_indicator"), "finding", ["indicator"], unique=False)
    op.create_index(op.f("ix_finding_severity"), "finding", ["severity"], unique=False)
    op.create_index(op.f("ix_finding_source_type"), "finding", ["source_type"], unique=False)

    op.create_table(
        "timeline_event",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("case_id", sa.Integer(), nullable=True),
        sa.Column("analysis_job_id", sa.Integer(), nullable=True),
        sa.Column("event_type", sa.String(length=64), nullable=False),
        sa.Column("source", sa.String(length=64), nullable=True),
        sa.Column("title", sa.String(length=255), nullable=False),
        sa.Column("event_ts", sa.DateTime(), nullable=True),
        sa.Column("details_json", sa.Text(), nullable=True),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.ForeignKeyConstraint(["analysis_job_id"], ["analysis_job.id"]),
        sa.ForeignKeyConstraint(["case_id"], ["dfir_case.id"]),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(op.f("ix_timeline_event_analysis_job_id"), "timeline_event", ["analysis_job_id"], unique=False)
    op.create_index(op.f("ix_timeline_event_case_id"), "timeline_event", ["case_id"], unique=False)
    op.create_index(op.f("ix_timeline_event_created_at"), "timeline_event", ["created_at"], unique=False)
    op.create_index(op.f("ix_timeline_event_event_ts"), "timeline_event", ["event_ts"], unique=False)
    op.create_index(op.f("ix_timeline_event_event_type"), "timeline_event", ["event_type"], unique=False)
    op.create_index(op.f("ix_timeline_event_source"), "timeline_event", ["source"], unique=False)

    op.create_table(
        "rule_match",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("case_id", sa.Integer(), nullable=True),
        sa.Column("analysis_job_id", sa.Integer(), nullable=True),
        sa.Column("finding_id", sa.Integer(), nullable=True),
        sa.Column("rule_engine", sa.String(length=32), nullable=False),
        sa.Column("rule_id", sa.String(length=255), nullable=True),
        sa.Column("rule_title", sa.String(length=255), nullable=False),
        sa.Column("rule_level", sa.String(length=32), nullable=True),
        sa.Column("event_index", sa.Integer(), nullable=True),
        sa.Column("match_json", sa.Text(), nullable=True),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.ForeignKeyConstraint(["analysis_job_id"], ["analysis_job.id"]),
        sa.ForeignKeyConstraint(["case_id"], ["dfir_case.id"]),
        sa.ForeignKeyConstraint(["finding_id"], ["finding.id"]),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(op.f("ix_rule_match_analysis_job_id"), "rule_match", ["analysis_job_id"], unique=False)
    op.create_index(op.f("ix_rule_match_case_id"), "rule_match", ["case_id"], unique=False)
    op.create_index(op.f("ix_rule_match_created_at"), "rule_match", ["created_at"], unique=False)
    op.create_index(op.f("ix_rule_match_finding_id"), "rule_match", ["finding_id"], unique=False)
    op.create_index(op.f("ix_rule_match_rule_engine"), "rule_match", ["rule_engine"], unique=False)
    op.create_index(op.f("ix_rule_match_rule_id"), "rule_match", ["rule_id"], unique=False)


def downgrade() -> None:
    op.drop_index(op.f("ix_rule_match_rule_id"), table_name="rule_match")
    op.drop_index(op.f("ix_rule_match_rule_engine"), table_name="rule_match")
    op.drop_index(op.f("ix_rule_match_finding_id"), table_name="rule_match")
    op.drop_index(op.f("ix_rule_match_created_at"), table_name="rule_match")
    op.drop_index(op.f("ix_rule_match_case_id"), table_name="rule_match")
    op.drop_index(op.f("ix_rule_match_analysis_job_id"), table_name="rule_match")
    op.drop_table("rule_match")

    op.drop_index(op.f("ix_timeline_event_source"), table_name="timeline_event")
    op.drop_index(op.f("ix_timeline_event_event_type"), table_name="timeline_event")
    op.drop_index(op.f("ix_timeline_event_event_ts"), table_name="timeline_event")
    op.drop_index(op.f("ix_timeline_event_created_at"), table_name="timeline_event")
    op.drop_index(op.f("ix_timeline_event_case_id"), table_name="timeline_event")
    op.drop_index(op.f("ix_timeline_event_analysis_job_id"), table_name="timeline_event")
    op.drop_table("timeline_event")

    op.drop_index(op.f("ix_finding_source_type"), table_name="finding")
    op.drop_index(op.f("ix_finding_severity"), table_name="finding")
    op.drop_index(op.f("ix_finding_indicator"), table_name="finding")
    op.drop_index(op.f("ix_finding_created_at"), table_name="finding")
    op.drop_index(op.f("ix_finding_category"), table_name="finding")
    op.drop_index(op.f("ix_finding_case_id"), table_name="finding")
    op.drop_index(op.f("ix_finding_analysis_job_id"), table_name="finding")
    op.drop_table("finding")

    op.drop_index(op.f("ix_analysis_job_task_id"), table_name="analysis_job")
    op.drop_index(op.f("ix_analysis_job_submitted_by_user_id"), table_name="analysis_job")
    op.drop_index(op.f("ix_analysis_job_state"), table_name="analysis_job")
    op.drop_index(op.f("ix_analysis_job_stage"), table_name="analysis_job")
    op.drop_index(op.f("ix_analysis_job_job_type"), table_name="analysis_job")
    op.drop_index(op.f("ix_analysis_job_history_id"), table_name="analysis_job")
    op.drop_index(op.f("ix_analysis_job_created_at"), table_name="analysis_job")
    op.drop_index(op.f("ix_analysis_job_case_id"), table_name="analysis_job")
    op.drop_index(op.f("ix_analysis_job_artifact_id"), table_name="analysis_job")
    op.drop_table("analysis_job")

    op.drop_index(op.f("ix_artifact_uploaded_by_user_id"), table_name="artifact")
    op.drop_index(op.f("ix_artifact_sha256"), table_name="artifact")
    op.drop_index(op.f("ix_artifact_created_at"), table_name="artifact")
    op.drop_index(op.f("ix_artifact_case_id"), table_name="artifact")
    op.drop_index(op.f("ix_artifact_artifact_type"), table_name="artifact")
    op.drop_table("artifact")

    op.drop_index(op.f("ix_dfir_case_status"), table_name="dfir_case")
    op.drop_index(op.f("ix_dfir_case_severity"), table_name="dfir_case")
    op.drop_index(op.f("ix_dfir_case_owner_user_id"), table_name="dfir_case")
    op.drop_index(op.f("ix_dfir_case_created_at"), table_name="dfir_case")
    op.drop_index(op.f("ix_dfir_case_case_key"), table_name="dfir_case")
    op.drop_table("dfir_case")

    op.drop_index(op.f("ix_system_setting_key"), table_name="system_setting")
    op.drop_table("system_setting")

    op.drop_index(op.f("ix_analysis_history_user_id"), table_name="analysis_history")
    op.drop_index(op.f("ix_analysis_history_timestamp"), table_name="analysis_history")
    op.drop_table("analysis_history")

    op.drop_table("user")
    op.drop_table("group")
