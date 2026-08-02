from __future__ import annotations

import os
import re
from datetime import datetime, timedelta
from typing import Any, Dict, Optional

try:
    import requests
except ImportError:
    requests = None  # type: ignore

from forensis.models import AnalysisHistory

_CLICKHOUSE_SANITIZE_RE = re.compile(r"[^a-zA-Z0-9_]")
CLICKHOUSE_URL = (os.getenv("FORENSIS_CLICKHOUSE_URL", "") or "").strip()
CLICKHOUSE_DB = _CLICKHOUSE_SANITIZE_RE.sub("_", (os.getenv("FORENSIS_CLICKHOUSE_DB", "forensis") or "forensis").strip())
CLICKHOUSE_TABLE = _CLICKHOUSE_SANITIZE_RE.sub("_", (os.getenv("FORENSIS_CLICKHOUSE_TABLE", "events") or "events").strip())
CLICKHOUSE_USERNAME = (os.getenv("FORENSIS_CLICKHOUSE_USERNAME", "") or "").strip()
CLICKHOUSE_PASSWORD = (os.getenv("FORENSIS_CLICKHOUSE_PASSWORD", "") or "").strip()


def _auth_tuple():
    return (CLICKHOUSE_USERNAME, CLICKHOUSE_PASSWORD) if CLICKHOUSE_USERNAME or CLICKHOUSE_PASSWORD else None


def _clickhouse_query(query: str) -> Dict[str, Any]:
    if not CLICKHOUSE_URL or requests is None:
        return {"ok": False, "items": []}
    try:
        response = requests.post(
            CLICKHOUSE_URL.rstrip("/") + "/",
            timeout=5,
            params={"query": " ".join(query.strip().split())},
            auth=_auth_tuple(),
        )
        if response.status_code != 200:
            return {"ok": False, "items": [], "error": f"status_{response.status_code}"}
        payload = response.json()
        return {"ok": True, "items": payload.get("data", []) if isinstance(payload, dict) else []}
    except Exception as exc:
        return {"ok": False, "items": [], "error": str(exc)}


def _clickhouse_literal(value: str) -> str:
    return str(value or "").replace("\\", "\\\\").replace("'", "\\'")


def clickhouse_overview(since_minutes: int = 1440, tenant_id: Optional[str] = None) -> Dict[str, Any]:
    if not CLICKHOUSE_URL:
        return {"enabled": False, "backend": "clickhouse", "source_counts": [], "severity_counts": [], "timeline": []}

    minutes = max(5, int(since_minutes or 1440))
    table = f"{CLICKHOUSE_DB}.{CLICKHOUSE_TABLE}"
    tenant_filter = f" AND tenant_id = '{_clickhouse_literal(tenant_id)}'" if tenant_id else ""
    where = f"ingested_at >= now() - INTERVAL {minutes} MINUTE{tenant_filter}"

    source = _clickhouse_query(f"SELECT source_type, count() AS c FROM {table} WHERE {where} GROUP BY source_type ORDER BY c DESC FORMAT JSON")
    severity = _clickhouse_query(f"SELECT severity, count() AS c FROM {table} WHERE {where} GROUP BY severity ORDER BY c DESC FORMAT JSON")
    timeline = _clickhouse_query(f"SELECT toStartOfHour(ingested_at) AS hour_bucket, count() AS c FROM {table} WHERE {where} GROUP BY hour_bucket ORDER BY hour_bucket ASC FORMAT JSON")
    return {
        "enabled": True,
        "backend": "clickhouse",
        "source_counts": source.get("items", []),
        "severity_counts": severity.get("items", []),
        "timeline": timeline.get("items", []),
        "errors": [error for error in (source.get("error"), severity.get("error"), timeline.get("error")) if error],
    }


def history_overview_fallback(current_user, since_minutes: int = 1440) -> Dict[str, Any]:
    cutoff = datetime.utcnow() - timedelta(minutes=max(5, int(since_minutes or 1440)))
    query = AnalysisHistory.query.filter(AnalysisHistory.timestamp >= cutoff)
    if not current_user.has_role("super_admin"):
        query = query.filter(AnalysisHistory.tenant_id == current_user.tenant_id)
    if not current_user.has_role("admin", "super_admin"):
        query = query.filter(AnalysisHistory.user_id == current_user.id)

    source_counts: Dict[str, int] = {}
    severity_counts: Dict[str, int] = {}
    timeline_counts: Dict[str, int] = {}
    for record in query.order_by(AnalysisHistory.timestamp.desc()).limit(300).all():
        source_key = str(record.type or "unknown")
        source_counts[source_key] = source_counts.get(source_key, 0) + 1
        if record.timestamp:
            hour_key = record.timestamp.replace(minute=0, second=0, microsecond=0).isoformat()
            timeline_counts[hour_key] = timeline_counts.get(hour_key, 0) + 1
        results = record.get_results()
        for item in results.get("anomalies", []) if isinstance(results, dict) else []:
            if isinstance(item, dict):
                severity = str(item.get("severity") or "unknown").lower()
                severity_counts[severity] = severity_counts.get(severity, 0) + 1

    return {
        "enabled": True,
        "backend": "history_fallback",
        "source_counts": [{"source_type": key, "c": value} for key, value in sorted(source_counts.items(), key=lambda pair: pair[1], reverse=True)],
        "severity_counts": [{"severity": key, "c": value} for key, value in sorted(severity_counts.items(), key=lambda pair: pair[1], reverse=True)],
        "timeline": [{"hour_bucket": key, "c": timeline_counts[key]} for key in sorted(timeline_counts)],
        "errors": [],
    }
