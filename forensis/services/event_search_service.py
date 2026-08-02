from __future__ import annotations

import json
import os
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional

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
    return bool(default) if not raw else raw in {"1", "true", "yes", "on"}


OPENSEARCH_URL = (os.getenv("FORENSIS_OPENSEARCH_URL", "") or os.getenv("FORENSIS_ELASTIC_URL", "")).strip()
OPENSEARCH_INDEX = (os.getenv("FORENSIS_OPENSEARCH_INDEX", "forensis-events") or "forensis-events").strip()
OPENSEARCH_USERNAME = (os.getenv("FORENSIS_OPENSEARCH_USERNAME", "") or "").strip()
OPENSEARCH_PASSWORD = (os.getenv("FORENSIS_OPENSEARCH_PASSWORD", "") or "").strip()
OPENSEARCH_VERIFY_TLS = _env_bool("FORENSIS_OPENSEARCH_VERIFY_TLS", False)


def _os_auth():
    return (OPENSEARCH_USERNAME, OPENSEARCH_PASSWORD) if OPENSEARCH_USERNAME or OPENSEARCH_PASSWORD else None


def _source_type_match(history_type: str, requested: str) -> bool:
    if not requested:
        return True
    requested = requested.strip().lower()
    history_type = (history_type or "").strip().lower()
    return history_type.startswith("memory") if requested == "memory" else history_type == requested


def _event_matches_query(event: Dict[str, Any], query_text: str) -> bool:
    if not query_text:
        return True
    try:
        return query_text in json.dumps(event, default=str).lower()
    except Exception:
        return query_text in str(event).lower()


def search_events_opensearch(
    query: str,
    source_type: str,
    since_minutes: int,
    limit: int,
    tenant_id: Optional[str] = None,
) -> Dict[str, Any]:
    if not OPENSEARCH_URL or requests is None:
        return {"backend": "disabled", "items": [], "count": 0}

    safe_limit = _env_int("FORENSIS_SEARCH_MAX_LIMIT", limit or 100, min_value=1, max_value=500)
    safe_minutes = max(1, int(since_minutes or 60))
    must_clause: List[Dict[str, Any]] = []
    filter_clause: List[Dict[str, Any]] = [
        {"range": {"ingested_at": {"gte": f"now-{safe_minutes}m", "lte": "now"}}}
    ]
    if tenant_id:
        filter_clause.append({"term": {"tenant_id.keyword": tenant_id}})

    query_text = (query or "").strip()
    if query_text:
        must_clause.append({"query_string": {"query": query_text, "default_operator": "AND", "lenient": True}})
    source_text = (source_type or "").strip().lower()
    if source_text:
        filter_clause.append({"term": {"source_type.keyword": source_text}})

    body = {
        "size": safe_limit,
        "sort": [{"ingested_at": {"order": "desc", "unmapped_type": "date"}}],
        "query": {"bool": {"must": must_clause or [{"match_all": {}}], "filter": filter_clause}},
    }
    try:
        response = requests.post(
            f"{OPENSEARCH_URL.rstrip('/')}/{OPENSEARCH_INDEX}/_search",
            timeout=5,
            json=body,
            auth=_os_auth(),
            verify=OPENSEARCH_VERIFY_TLS,
            headers={"Content-Type": "application/json"},
        )
        if response.status_code != 200:
            return {"backend": "opensearch", "items": [], "count": 0, "error": f"status_{response.status_code}"}
        payload = response.json()
    except Exception as exc:
        return {"backend": "opensearch", "items": [], "count": 0, "error": str(exc)}

    items = []
    for hit in ((payload or {}).get("hits") or {}).get("hits") or []:
        source = (hit or {}).get("_source") or {}
        items.append({"source_type": source.get("source_type"), "ingested_at": source.get("ingested_at"), "event": source})
    return {"backend": "opensearch", "items": items, "count": len(items)}


def search_events_history_fallback(current_user, query: str, source_type: str, since_minutes: int, limit: int) -> Dict[str, Any]:
    safe_limit = _env_int("FORENSIS_SEARCH_MAX_LIMIT", limit or 100, min_value=1, max_value=500)
    cutoff = datetime.utcnow() - timedelta(minutes=max(1, int(since_minutes or 60)))
    history_query = AnalysisHistory.query.filter(AnalysisHistory.timestamp >= cutoff)
    if not current_user.has_role("super_admin"):
        history_query = history_query.filter(AnalysisHistory.tenant_id == current_user.tenant_id)
    if not current_user.has_role("admin", "super_admin"):
        history_query = history_query.filter(AnalysisHistory.user_id == current_user.id)

    query_text = (query or "").strip().lower()
    requested_source = (source_type or "").strip().lower()
    output: List[Dict[str, Any]] = []
    for record in history_query.order_by(AnalysisHistory.timestamp.desc()).limit(300).all():
        if not _source_type_match(record.type, requested_source):
            continue
        results = record.get_results()
        for event in list(results.get("events") or []) + list(results.get("anomalies") or []) if isinstance(results, dict) else []:
            if not isinstance(event, dict) or not _event_matches_query(event, query_text):
                continue
            output.append(
                {
                    "history_id": record.id,
                    "source_type": record.type,
                    "ingested_at": record.timestamp.isoformat() if record.timestamp else None,
                    "event": event,
                }
            )
            if len(output) >= safe_limit:
                return {"backend": "history_fallback", "items": output, "count": len(output)}
    return {"backend": "history_fallback", "items": output, "count": len(output)}
