from __future__ import annotations

import json
import os
from datetime import datetime, timedelta
from typing import Any, Dict, List

try:
    import requests
except ImportError:
    requests = None  # type: ignore

from forensis.models import AnalysisHistory


def _env_int(name: str, default: int, min_value: int, max_value: int) -> int:
    raw = (os.getenv(name, "") or "").strip()
    try:
        value = int(raw) if raw else int(default)
    except (TypeError, ValueError):
        value = int(default)
    return max(min_value, min(max_value, value))


def _env_bool(name: str, default: bool) -> bool:
    raw = (os.getenv(name, "") or "").strip().lower()
    if not raw:
        return bool(default)
    return raw in {"1", "true", "yes", "on"}


OPENSEARCH_URL = (os.getenv("FORENSIS_OPENSEARCH_URL", "") or os.getenv("FORENSIS_ELASTIC_URL", "")).strip()
OPENSEARCH_INDEX = (os.getenv("FORENSIS_OPENSEARCH_INDEX", "forensis-events") or "forensis-events").strip()
OPENSEARCH_USERNAME = (os.getenv("FORENSIS_OPENSEARCH_USERNAME", "") or "").strip()
OPENSEARCH_PASSWORD = (os.getenv("FORENSIS_OPENSEARCH_PASSWORD", "") or "").strip()
OPENSEARCH_VERIFY_TLS = _env_bool("FORENSIS_OPENSEARCH_VERIFY_TLS", False)


def _os_auth():
    if OPENSEARCH_USERNAME or OPENSEARCH_PASSWORD:
        return (OPENSEARCH_USERNAME, OPENSEARCH_PASSWORD)
    return None


def _source_type_match(history_type: str, requested: str) -> bool:
    if not requested:
        return True
    req = requested.strip().lower()
    text = (history_type or "").strip().lower()
    if req == "memory":
        return text.startswith("memory")
    return text == req


def _event_matches_query(event: Dict[str, Any], query_text: str) -> bool:
    if not query_text:
        return True
    try:
        haystack = json.dumps(event, default=str).lower()
    except Exception:
        haystack = str(event).lower()
    return query_text in haystack


def search_events_opensearch(query: str, source_type: str, since_minutes: int, limit: int) -> Dict[str, Any]:
    if not OPENSEARCH_URL or requests is None:
        return {"backend": "disabled", "items": [], "count": 0}

    safe_limit = _env_int("FORENSIS_SEARCH_MAX_LIMIT", limit or 100, min_value=1, max_value=500)
    safe_minutes = max(1, int(since_minutes or 60))

    must_clause: List[Dict[str, Any]] = []
    filter_clause: List[Dict[str, Any]] = [
        {"range": {"ingested_at": {"gte": f"now-{safe_minutes}m", "lte": "now"}}}
    ]

    query_text = (query or "").strip()
    if query_text:
        must_clause.append(
            {
                "query_string": {
                    "query": query_text,
                    "default_operator": "AND",
                    "lenient": True,
                }
            }
        )

    source_text = (source_type or "").strip().lower()
    if source_text:
        filter_clause.append({"term": {"source_type.keyword": source_text}})

    body = {
        "size": safe_limit,
        "sort": [{"ingested_at": {"order": "desc", "unmapped_type": "date"}}],
        "query": {
            "bool": {
                "must": must_clause or [{"match_all": {}}],
                "filter": filter_clause,
            }
        },
    }

    url = f"{OPENSEARCH_URL.rstrip('/')}/{OPENSEARCH_INDEX}/_search"
    try:
        resp = requests.post(
            url,
            timeout=5,
            json=body,
            auth=_os_auth(),
            verify=OPENSEARCH_VERIFY_TLS,
            headers={"Content-Type": "application/json"},
        )
        if resp.status_code != 200:
            return {"backend": "opensearch", "items": [], "count": 0, "error": f"status_{resp.status_code}"}
        payload = resp.json()
    except Exception as exc:
        return {"backend": "opensearch", "items": [], "count": 0, "error": str(exc)}

    hits = ((payload or {}).get("hits") or {}).get("hits") or []
    items = []
    for hit in hits:
        src = (hit or {}).get("_source") or {}
        items.append(
            {
                "source_type": src.get("source_type"),
                "ingested_at": src.get("ingested_at"),
                "event": src,
            }
        )

    return {
        "backend": "opensearch",
        "items": items,
        "count": len(items),
    }


def search_events_history_fallback(current_user, query: str, source_type: str, since_minutes: int, limit: int) -> Dict[str, Any]:
    safe_limit = _env_int("FORENSIS_SEARCH_MAX_LIMIT", limit or 100, min_value=1, max_value=500)
    safe_minutes = max(1, int(since_minutes or 60))

    cutoff = datetime.utcnow() - timedelta(minutes=safe_minutes)
    q = AnalysisHistory.query.filter(AnalysisHistory.timestamp >= cutoff).order_by(AnalysisHistory.timestamp.desc())
    if getattr(current_user, "role", "") != "admin":
        q = q.filter_by(user_id=current_user.id)

    query_text = (query or "").strip().lower()
    requested_source = (source_type or "").strip().lower()

    out: List[Dict[str, Any]] = []
    for rec in q.limit(300).all():
        if not _source_type_match(rec.type, requested_source):
            continue

        data = rec.get_results() if hasattr(rec, "get_results") else {}
        events = data.get("events") if isinstance(data, dict) else []
        anomalies = data.get("anomalies") if isinstance(data, dict) else []

        for ev in (events or []):
            if not isinstance(ev, dict):
                continue
            if not _event_matches_query(ev, query_text):
                continue
            out.append(
                {
                    "history_id": rec.id,
                    "source_type": rec.type,
                    "ingested_at": rec.timestamp.isoformat() if rec.timestamp else None,
                    "event": ev,
                }
            )
            if len(out) >= safe_limit:
                return {"backend": "history_fallback", "items": out, "count": len(out)}

        for an in (anomalies or []):
            if not isinstance(an, dict):
                continue
            if not _event_matches_query(an, query_text):
                continue
            out.append(
                {
                    "history_id": rec.id,
                    "source_type": rec.type,
                    "ingested_at": rec.timestamp.isoformat() if rec.timestamp else None,
                    "event": an,
                }
            )
            if len(out) >= safe_limit:
                return {"backend": "history_fallback", "items": out, "count": len(out)}

    return {"backend": "history_fallback", "items": out, "count": len(out)}
