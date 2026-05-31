from __future__ import annotations

import json
import os
import re
from datetime import datetime, timedelta
from typing import Any, Dict, List

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
    if CLICKHOUSE_USERNAME or CLICKHOUSE_PASSWORD:
        return (CLICKHOUSE_USERNAME, CLICKHOUSE_PASSWORD)
    return None


def _clickhouse_query(query: str) -> Dict[str, Any]:
    if not CLICKHOUSE_URL or requests is None:
        return {"ok": False, "items": []}

    url = CLICKHOUSE_URL.rstrip("/") + "/"
    sql = " ".join(query.strip().split())
    try:
        resp = requests.post(
            url,
            timeout=5,
            params={"query": sql},
            auth=_auth_tuple(),
        )
        if resp.status_code != 200:
            return {"ok": False, "items": [], "error": f"status_{resp.status_code}"}
        payload = resp.json()
        return {"ok": True, "items": payload.get("data", []) if isinstance(payload, dict) else []}
    except Exception as exc:
        return {"ok": False, "items": [], "error": str(exc)}


def clickhouse_overview(since_minutes: int = 1440) -> Dict[str, Any]:
    if not CLICKHOUSE_URL:
        return {"enabled": False, "backend": "clickhouse", "source_counts": [], "severity_counts": [], "timeline": []}

    minutes = max(5, int(since_minutes or 1440))
    table = f"{CLICKHOUSE_DB}.{CLICKHOUSE_TABLE}"

    source_q = f"""
    SELECT source_type, count() AS c
    FROM {table}
    WHERE ingested_at >= now() - INTERVAL {minutes} MINUTE
    GROUP BY source_type
    ORDER BY c DESC
    FORMAT JSON
    """

    severity_q = f"""
    SELECT severity, count() AS c
    FROM {table}
    WHERE ingested_at >= now() - INTERVAL {minutes} MINUTE
    GROUP BY severity
    ORDER BY c DESC
    FORMAT JSON
    """

    timeline_q = f"""
    SELECT toStartOfHour(ingested_at) AS hour_bucket, count() AS c
    FROM {table}
    WHERE ingested_at >= now() - INTERVAL {minutes} MINUTE
    GROUP BY hour_bucket
    ORDER BY hour_bucket ASC
    FORMAT JSON
    """

    source = _clickhouse_query(source_q)
    severity = _clickhouse_query(severity_q)
    timeline = _clickhouse_query(timeline_q)

    return {
        "enabled": True,
        "backend": "clickhouse",
        "source_counts": source.get("items", []),
        "severity_counts": severity.get("items", []),
        "timeline": timeline.get("items", []),
        "errors": [
            e
            for e in [source.get("error"), severity.get("error"), timeline.get("error")]
            if e
        ],
    }


def history_overview_fallback(current_user, since_minutes: int = 1440) -> Dict[str, Any]:
    minutes = max(5, int(since_minutes or 1440))
    cutoff = datetime.utcnow() - timedelta(minutes=minutes)

    q = AnalysisHistory.query.filter(AnalysisHistory.timestamp >= cutoff).order_by(AnalysisHistory.timestamp.desc())
    if getattr(current_user, "role", "") != "admin":
        q = q.filter_by(user_id=current_user.id)

    source_counts: Dict[str, int] = {}
    severity_counts: Dict[str, int] = {}
    timeline_counts: Dict[str, int] = {}

    for rec in q.limit(300).all():
        source_key = str(rec.type or "unknown")
        source_counts[source_key] = source_counts.get(source_key, 0) + 1

        ts = rec.timestamp
        if ts:
            hour_key = ts.replace(minute=0, second=0, microsecond=0).isoformat()
            timeline_counts[hour_key] = timeline_counts.get(hour_key, 0) + 1

        data = rec.get_results() if hasattr(rec, "get_results") else {}
        anomalies = data.get("anomalies") if isinstance(data, dict) else []
        for item in anomalies or []:
            if not isinstance(item, dict):
                continue
            sev = str(item.get("severity") or "unknown").lower()
            severity_counts[sev] = severity_counts.get(sev, 0) + 1

    source_items = [{"source_type": k, "c": v} for k, v in sorted(source_counts.items(), key=lambda x: x[1], reverse=True)]
    severity_items = [{"severity": k, "c": v} for k, v in sorted(severity_counts.items(), key=lambda x: x[1], reverse=True)]
    timeline_items = [{"hour_bucket": k, "c": timeline_counts[k]} for k in sorted(timeline_counts.keys())]

    return {
        "enabled": True,
        "backend": "history_fallback",
        "source_counts": source_items,
        "severity_counts": severity_items,
        "timeline": timeline_items,
        "errors": [],
    }
