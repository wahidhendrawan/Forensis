import os
import json
import time
from typing import List, Dict, Any

try:
    import requests
except ImportError:  # fail-safe if dependencies not installed
    requests = None  # type: ignore


def _get_env(name: str, default: str = "") -> str:
    return os.getenv(name, default)


ELASTIC_URL = _get_env("FORENSIS_ELASTIC_URL") or _get_env("ELASTICSEARCH_URL")
ELASTIC_INDEX = _get_env("FORENSIS_ELASTIC_INDEX", "forensis-events")
LOKI_URL = _get_env("FORENSIS_LOKI_URL")
LOKI_LABELS = _get_env("FORENSIS_LOKI_LABELS", 'app="forensis"')


def _safe_requests_post(url: str, **kwargs):
    if requests is None:
        return
    try:
        requests.post(url, timeout=3, **kwargs)
    except Exception:
        # Do not break the UI if backend is unreachable
        return


def send_to_elasticsearch(events: List[Dict[str, Any]], source_type: str):
    # Simple integration: send each event as a single document into Elasticsearch.
    if not ELASTIC_URL or not events:
        return

    base = ELASTIC_URL.rstrip("/")
    index = ELASTIC_INDEX.strip("/") or "forensis-events"
    url = f"{base}/{index}/_doc"

    for ev in events:
        doc = {"source_type": source_type, **ev}
        _safe_requests_post(url, json=doc)


def _parse_loki_labels(raw: str) -> Dict[str, str]:
    # Parse simple Loki labels string: app="forensis",env="lab" into a dict.
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
    # Simple Loki push API integration.
    if not LOKI_URL or not events:
        return

    base_labels = _parse_loki_labels(LOKI_LABELS)
    base_labels.setdefault("source_type", source_type)

    values = []
    for ev in events:
        # Loki timestamp in nanoseconds as string
        ts_ns = str(int(time.time() * 1e9))
        message = (
            str(ev.get("raw"))
            or str(ev.get("message"))
            or json.dumps(ev, default=str)
        )
        values.append([ts_ns, message])

    payload = {
        "streams": [
            {
                "stream": base_labels,
                "values": values,
            }
        ]
    }

    url = LOKI_URL.rstrip("/") + "/loki/api/v1/push"
    headers = {"Content-Type": "application/json"}
    _safe_requests_post(url, data=json.dumps(payload), headers=headers)


def ship_events(events: List[Dict[str, Any]], source_type: str):
    # Helper to send events to both Elasticsearch and Loki (if configured).
    if not events:
        return
    send_to_elasticsearch(events, source_type)
    send_to_loki(events, source_type)
