from __future__ import annotations

import os
from logging.config import fileConfig

from alembic import context
from sqlalchemy import engine_from_config, pool

from forensis.models import db
# Import model modules so metadata is fully populated for autogenerate/check.
from forensis import models as _models  # noqa: F401

IGNORED_RUNTIME_INDEXES = {
    "ix_analysis_history_type_ts",
    "ix_analysis_history_user_ts",
    "ix_analysis_job_case_state",
    "ix_analysis_job_state_updated",
    "ix_artifact_case_created",
    "ix_finding_case_severity_created",
    "ix_rule_match_case_engine_created",
    "ix_timeline_case_ts",
}


config = context.config

if config.config_file_name is not None:
    fileConfig(config.config_file_name)


def _include_object(obj, name, type_, reflected, compare_to):  # noqa: ANN001
    if type_ == "index" and name in IGNORED_RUNTIME_INDEXES:
        return False
    return True


def _database_url() -> str:
    env_url = (os.getenv("FORENSIS_DB_URI", "") or "").strip()
    if env_url:
        return env_url
    return config.get_main_option("sqlalchemy.url")


def _configure_opts(url: str):
    return {
        "url": url,
        "target_metadata": db.metadata,
        "compare_type": True,
        "compare_server_default": True,
        "render_as_batch": url.startswith("sqlite"),
        "include_object": _include_object,
    }


def run_migrations_offline() -> None:
    url = _database_url()
    context.configure(**_configure_opts(url), literal_binds=True, dialect_opts={"paramstyle": "named"})

    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    section = config.get_section(config.config_ini_section) or {}
    section["sqlalchemy.url"] = _database_url()

    connectable = engine_from_config(section, prefix="sqlalchemy.", poolclass=pool.NullPool)

    with connectable.connect() as connection:
        context.configure(connection=connection, **_configure_opts(section["sqlalchemy.url"]))

        with context.begin_transaction():
            context.run_migrations()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
