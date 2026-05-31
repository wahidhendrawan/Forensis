import json
import os
import re
import threading
import time
from datetime import datetime, timezone
from typing import Any, Dict, List

try:
    import requests
except ImportError:  # fail-safe if dependencies not installed
    requests = None  # type: ignore


def _get_env(name: str, default: str = "") -> str:
    return os.getenv(name, default)


def _env_bool(name: str, default: bool) -> bool:
    raw = (_get_env(name, "") or "").strip().lower()
    if not raw:
        return bool(default)
    return raw in {"1", "true", "yes", "on"}


ELASTIC_URL = _get_env("FORENSIS_ELASTIC_URL") or _get_env("ELASTICSEARCH_URL")
OPENSEARCH_URL = _get_env("FORENSIS_OPENSEARCH_URL") or ELASTIC_URL
OPENSEARCH_INDEX = (_get_env("FORENSIS_OPENSEARCH_INDEX", "forensis-events") or "forensis-events").strip()
OPENSEARCH_USERNAME = _get_env("FORENSIS_OPENSEARCH_USERNAME")
OPENSEARCH_PASSWORD = _get_env("FORENSIS_OPENSEARCH_PASSWORD")
OPENSEARCH_VERIFY_TLS = _env_bool("FORENSIS_OPENSEARCH_VERIFY_TLS", False)

LOKI_URL = _get_env("FORENSIS_LOKI_URL")
LOKI_LABELS = _get_env("FORENSIS_LOKI_LABELS", 'app="forensis"')

CLICKHOUSE_URL = _get_env("FORENSIS_CLICKHOUSE_URL", "")
CLICKHOUSE_DB = _get_env("FORENSIS_CLICKHOUSE_DB", "forensis")
CLICKHOUSE_TABLE = _get_env("FORENSIS_CLICKHOUSE_TABLE", "events")
CLICKHOUSE_USERNAME = _get_env("FORENSIS_CLICKHOUSE_USERNAME", "")
CLICKHOUSE_PASSWORD = _get_env("FORENSIS_CLICKHOUSE_PASSWORD", "")
CLICKHOUSE_TIMEOUT = max(1, int(_get_env("FORENSIS_CLICKHOUSE_TIMEOUT", "4") or "4"))

_SANITIZE_RE = re.compile(r"[^a-zA-Z0-9_]")
_CLICKHOUSE_LOCK = threading.Lock()
_CLICKHOUSE_READY = False


def _safe_identifier(value: str, fallback: str) -> str:
    text = _SANITIZE_RE.sub("_", (value or "").strip())
    return text or fallback


def _safe_requests_post(url: str, *, timeout: int = 3, **kwargs):
    if requests is None:
        return None
    try:
        return requests.post(url, timeout=timeout, **kwargs)
    except Exception:
        # Do not break the UI if backend is unreachable.
        return None


def _auth_tuple(username: str, password: str):
    if username or password:
        return (username, password)
    return None


def send_to_opensearch(events: List[Dict[str, Any]], source_type: str):
    if not OPENSEARCH_URL or not events:
        return

    base = OPENSEARCH_URL.rstrip("/")
    index = _safe_identifier(OPENSEARCH_INDEX, "forensis_events")
    url = f"{base}/_bulk"

    now = datetime.now(timezone.utc).isoformat()
    bulk_data = []
    for ev in events:
        if not isinstance(ev, dict):
            continue
        doc = {
            "source_type": source_type,
            "ingested_at": now,
            **ev,
        }
        bulk_data.append(json.dumps({"index": {"_index": index}}))
        bulk_data.append(json.dumps(doc, default=str))

    if not bulk_data:
        return

    bulk_payload = "\n".join(bulk_data) + "\n"
    _safe_requests_post(
        url,
        timeout=4,
        data=bulk_payload,
        headers={"Content-Type": "application/x-ndjson"},
        auth=_auth_tuple(OPENSEARCH_USERNAME, OPENSEARCH_PASSWORD),
        verify=OPENSEARCH_VERIFY_TLS,
    )


def send_to_elasticsearch(events: List[Dict[str, Any]], source_type: str):
    # Backward-compatible alias.
    send_to_opensearch(events, source_type)


def _parse_loki_labels(raw: str) -> Dict[str, str]:
    labels: Dict[str, str] = {}
    if not raw:
        return labels
    parts = [p.strip() for p in raw.split(",") if p.strip()]
    for p in parts:
        if "=" not in p:
            continue
        k, v = p.split("=", 1)
        k = k.strip().strip("{} ")
        v = v.strip().strip('" ')
        labels[k] = v
    return labels


def send_to_loki(events: List[Dict[str, Any]], source_type: str):
    if not LOKI_URL or not events:
        return

    base_labels = _parse_loki_labels(LOKI_LABELS)
    base_labels.setdefault("source_type", source_type)

    values = []
    for ev in events:
        if not isinstance(ev, dict):
            continue
        ts_ns = str(int(time.time() * 1e9))
        message = str(ev.get("raw")) or str(ev.get("message")) or json.dumps(ev, default=str)
        values.append([ts_ns, message])

    if not values:
        return

    payload = {
        "streams": [
            {
                "stream": base_labels,
                "values": values,
            }
        ]
    }

    url = LOKI_URL.rstrip("/") + "/loki/api/v1/push"
    _safe_requests_post(url, timeout=4, data=json.dumps(payload), headers={"Content-Type": "application/json"})


def _clickhouse_http_post(query: str, data: str = ""):
    if not CLICKHOUSE_URL or requests is None:
        return None
    url = CLICKHOUSE_URL.rstrip("/") + "/"
    return _safe_requests_post(
        url,
        timeout=CLICKHOUSE_TIMEOUT,
        params={"query": query},
        data=data,
        auth=_auth_tuple(CLICKHOUSE_USERNAME, CLICKHOUSE_PASSWORD),
    )


def _ensure_clickhouse_schema():
    global _CLICKHOUSE_READY
    if _CLICKHOUSE_READY or not CLICKHOUSE_URL:
        return

    with _CLICKHOUSE_LOCK:
        if _CLICKHOUSE_READY:
            return

        db_name = _safe_identifier(CLICKHOUSE_DB, "forensis")
        table_name = _safe_identifier(CLICKHOUSE_TABLE, "events")

        create_db = f"CREATE DATABASE IF NOT EXISTS {db_name}"
        _clickhouse_http_post(create_db)

        create_table = f"""
        CREATE TABLE IF NOT EXISTS {db_name}.{table_name}
        (
            ingested_at DateTime,
            source_type LowCardinality(String),
            source_ip String,
            destination_ip String,
            indicator String,
            severity LowCardinality(String),
            message String,
            event_json String
        )
        ENGINE = MergeTree
        ORDER BY (ingested_at, source_type)
        """
        _clickhouse_http_post(" ".join(create_table.split()))
        _CLICKHOUSE_READY = True


def _event_to_clickhouse_row(source_type: str, event: Dict[str, Any]) -> Dict[str, Any]:
    source_ip = str(event.get("src_ip") or event.get("ip") or "")
    destination_ip = str(event.get("dst_ip") or event.get("host") or "")
    indicator = str(event.get("indicator") or "")
    severity = str(event.get("severity") or "unknown")
    message = str(event.get("message") or event.get("raw") or "")[:4000]
    return {
        "ingested_at": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S"),
        "source_type": source_type,
        "source_ip": source_ip,
        "destination_ip": destination_ip,
        "indicator": indicator,
        "severity": severity,
        "message": message,
        "event_json": json.dumps(event, default=str),
    }


def send_to_clickhouse(events: List[Dict[str, Any]], source_type: str):
    if not CLICKHOUSE_URL or not events:
        return

    _ensure_clickhouse_schema()

    db_name = _safe_identifier(CLICKHOUSE_DB, "forensis")
    table_name = _safe_identifier(CLICKHOUSE_TABLE, "events")
    query = f"INSERT INTO {db_name}.{table_name} FORMAT JSONEachRow"

    rows = []
    for event in events:
        if isinstance(event, dict):
            rows.append(json.dumps(_event_to_clickhouse_row(source_type, event), default=str))

    if not rows:
        return

    payload = "\n".join(rows) + "\n"
    _clickhouse_http_post(query=query, data=payload)


def ship_events(events: List[Dict[str, Any]], source_type: str):
    # Helper to send events to configured sinks.
    if not events:
        return
    send_to_opensearch(events, source_type)
    send_to_loki(events, source_type)
    send_to_clickhouse(events, source_type)
