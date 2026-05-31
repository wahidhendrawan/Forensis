#!/usr/bin/env python3
"""
Copy Forensis data from SQLite to PostgreSQL.

Usage:
  python scripts/migrate_sqlite_to_postgres.py \
    --sqlite-path instance/forensis.db \
    --postgres-uri postgresql+psycopg://forensis:forensis_change_me@localhost:5432/forensis
"""

import argparse
from typing import Dict, List

from sqlalchemy import MetaData, Table, create_engine, delete, insert, select

TABLE_ORDER = [
    "group",
    "user",
    "system_setting",
    "analysis_history",
    "dfir_case",
    "artifact",
    "analysis_job",
    "finding",
    "rule_match",
    "timeline_event",
]


def _chunks(items: List[Dict], size: int):
    for idx in range(0, len(items), size):
        yield items[idx : idx + size]


def _load_source_rows(src_conn, table: Table):
    result = src_conn.execute(select(table))
    return [dict(row._mapping) for row in result]


def _truncate_destination(dst_conn, table: Table):
    # PostgreSQL identity reset + cascade; fallback to normal delete if unsupported.
    try:
        dst_conn.exec_driver_sql(f'TRUNCATE TABLE "{table.name}" RESTART IDENTITY CASCADE')
        return
    except Exception:
        pass
    dst_conn.execute(delete(table))


def _copy_table(src_conn, dst_conn, src_table: Table, dst_table: Table, batch_size: int):
    rows = _load_source_rows(src_conn, src_table)
    _truncate_destination(dst_conn, dst_table)
    if not rows:
        return 0
    for chunk in _chunks(rows, batch_size):
        dst_conn.execute(insert(dst_table), chunk)
    return len(rows)


def _repair_postgres_sequences(dst_conn, dst_meta: MetaData):
    for table_name in TABLE_ORDER:
        table = dst_meta.tables.get(table_name)
        if table is None:
            continue
        if "id" not in table.columns:
            continue
        try:
            dst_conn.exec_driver_sql(
                f"""
                SELECT setval(
                    pg_get_serial_sequence('"{table_name}"', 'id'),
                    COALESCE((SELECT MAX(id) FROM "{table_name}"), 0) + 1,
                    false
                )
                """
            )
        except Exception:
            # Skip if table does not use serial sequence for id.
            continue


def main():
    parser = argparse.ArgumentParser(description="Migrate Forensis SQLite data to PostgreSQL")
    parser.add_argument("--sqlite-path", default="instance/forensis.db", help="Path to source SQLite database file")
    parser.add_argument("--postgres-uri", required=True, help="Target PostgreSQL SQLAlchemy URI")
    parser.add_argument("--batch-size", type=int, default=1000, help="Insert batch size")
    args = parser.parse_args()

    src_engine = create_engine(f"sqlite:///{args.sqlite_path}")
    dst_engine = create_engine(args.postgres_uri)

    src_meta = MetaData()
    dst_meta = MetaData()
    src_meta.reflect(bind=src_engine)
    dst_meta.reflect(bind=dst_engine)

    copied = {}

    with src_engine.connect() as src_conn, dst_engine.begin() as dst_conn:
        for table_name in TABLE_ORDER:
            src_table = src_meta.tables.get(table_name)
            dst_table = dst_meta.tables.get(table_name)
            if src_table is None:
                copied[table_name] = 0
                continue
            if dst_table is None:
                raise RuntimeError(
                    f"Destination table '{table_name}' not found. "
                    "Run Forensis once with FORENSIS_DB_URI pointed to PostgreSQL to initialize schema."
                )
            row_count = _copy_table(src_conn, dst_conn, src_table, dst_table, max(1, int(args.batch_size)))
            copied[table_name] = row_count
        _repair_postgres_sequences(dst_conn, dst_meta)

    total = sum(copied.values())
    print("Migration completed.")
    for name in TABLE_ORDER:
        print(f"- {name}: {copied.get(name, 0)} row(s)")
    print(f"Total rows copied: {total}")


if __name__ == "__main__":
    main()
