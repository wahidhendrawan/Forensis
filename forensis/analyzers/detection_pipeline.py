from collections import Counter
from typing import Dict, List


SEVERITY_WEIGHT = {
    "critical": 5,
    "high": 3,
    "medium": 2,
    "low": 1,
}

TI_SEVERITY = {
    "critical": "critical",
    "high": "high",
    "medium": "medium",
    "low": "low",
}


def _calc_threat_score(severity_counts: Counter):
    return sum(SEVERITY_WEIGHT.get(str(sev).lower(), 1) * int(count) for sev, count in severity_counts.items())


def _event_text(event: Dict):
    parts = []
    for key in ("message", "raw", "path", "request", "uri", "process", "host", "ip", "src_ip", "dst_ip"):
        val = event.get(key)
        if val is not None:
            parts.append(str(val))
    return " | ".join(parts)


def _append_unique_anomaly(anomalies: List[Dict], seen: set, item: Dict):
    reason = str(item.get("reason", "")).strip()
    severity = str(item.get("severity", "medium")).lower()
    indicator = str(item.get("indicator", "")).strip()
    evt = item.get("event") or {}
    evt_text = str(evt.get("raw") or evt.get("message") or evt.get("source") or "")[:300]
    key = (reason, severity, indicator, evt_text)
    if key in seen:
        return False
    seen.add(key)
    anomalies.append(item)
    return True


def enrich_analysis_results(
    results: Dict,
    analysis_type: str,
    yara_engine=None,
    threat_intel_engine=None,
    entity_profile_engine=None,
    raw_blob: str = None,
):
    if not isinstance(results, dict):
        return results

    summary = results.setdefault("summary", {})
    events = results.get("events", []) or []
    anomalies = results.setdefault("anomalies", [])
    preexisting_signal_hits = 0
    for key in ("malicious_pattern_hits", "suspicious_hits", "anomaly_count"):
        try:
            preexisting_signal_hits = max(preexisting_signal_hits, int(summary.get(key) or 0))
        except (TypeError, ValueError):
            continue
    anomaly_seen = set()
    for a in anomalies:
        reason = str(a.get("reason", "")).strip()
        severity = str(a.get("severity", "medium")).lower()
        indicator = str(a.get("indicator", "")).strip()
        evt = a.get("event") or {}
        evt_text = str(evt.get("raw") or evt.get("message") or evt.get("source") or "")[:300]
        anomaly_seen.add((reason, severity, indicator, evt_text))

    severity_counts = Counter()
    for sev, count in (summary.get("severity_counts", {}) or {}).items():
        try:
            severity_counts[str(sev).lower()] += int(count)
        except (TypeError, ValueError):
            continue

    # 1) Threat Intel enrichment with cache + scoring.
    ti_data = {"hit_count": 0, "total_score": 0, "top_indicators": [], "severity_counts": {}}
    if threat_intel_engine:
        try:
            ti_data = threat_intel_engine.enrich_events(events, analysis_type)
        except Exception:
            ti_data = {"hit_count": 0, "total_score": 0, "top_indicators": [], "severity_counts": {}}

    for hit in ti_data.get("hits", []) or []:
        sev = TI_SEVERITY.get(str(hit.get("severity", "medium")).lower(), "medium")
        item = {
            "reason": f"Threat intel match: {hit.get('name')} ({hit.get('indicator_type')}={hit.get('indicator_value')})",
            "severity": sev,
            "category": "threat_intel",
            "indicator": "threat_intel_match",
            "event": events[hit.get("event_index", 0)] if events else {"source": "threat_intel"},
        }
        if _append_unique_anomaly(anomalies, anomaly_seen, item):
            severity_counts[sev] += 1

    # 2) Entity baseline / allowlist deviation.
    baseline_data = {"anomalies": [], "suppressed": 0, "count": 0}
    if entity_profile_engine:
        try:
            baseline_data = entity_profile_engine.evaluate_events(events, analysis_type)
        except Exception:
            baseline_data = {"anomalies": [], "suppressed": 0, "count": 0}

    for item in baseline_data.get("anomalies", []) or []:
        sev = str(item.get("severity", "low")).lower()
        if _append_unique_anomaly(anomalies, anomaly_seen, item):
            severity_counts[sev] += 1

    # 3) YARA scanning.
    yara_hits = []
    if yara_engine:
        scan_blob = raw_blob or "\n".join(_event_text(e) for e in events[:3000])
        try:
            yara_hits = yara_engine.scan_text(scan_blob, source=analysis_type, max_hits=120)
        except Exception:
            yara_hits = []

    for hit in yara_hits:
        meta = hit.get("meta", {}) or {}
        sev = str(meta.get("severity", "high")).lower()
        if sev not in {"critical", "high", "medium", "low"}:
            sev = "high"
        reason = f"YARA match: {hit.get('rule')}"
        item = {
            "reason": reason,
            "severity": sev,
            "category": "yara_detection",
            "indicator": "yara_match",
            "event": {
                "source": "yara",
                "message": ", ".join(s.get("sample", "") for s in (hit.get("strings") or [])[:2])[:400],
                "raw": f"rule={hit.get('rule')} file={hit.get('rule_file')}",
            },
        }
        if _append_unique_anomaly(anomalies, anomaly_seen, item):
            severity_counts[sev] += 1

    # 4) Final normalized summary fields.
    engine_anomaly_count = len(anomalies)
    combined_signal_hits = max(preexisting_signal_hits, engine_anomaly_count)

    summary["severity_counts"] = dict(severity_counts)
    summary["anomaly_count"] = engine_anomaly_count
    summary["engine_anomaly_count"] = engine_anomaly_count
    summary["malicious_pattern_hits"] = combined_signal_hits
    summary["detected_signal_hits"] = combined_signal_hits
    if preexisting_signal_hits:
        summary["parser_signal_hits"] = preexisting_signal_hits
    summary["threat_score"] = _calc_threat_score(severity_counts)

    summary["threat_intel_hits"] = int(ti_data.get("hit_count", 0))
    summary["threat_intel_score"] = int(ti_data.get("total_score", 0))
    summary["ti_top_indicators"] = ti_data.get("top_indicators", []) or []
    summary["ti_severity_counts"] = ti_data.get("severity_counts", {}) or {}

    if yara_engine:
        ysum = yara_engine.match_summary(yara_hits)
        summary["yara_hits"] = int(ysum.get("total_hits", 0))
        summary["yara_top_rules"] = ysum.get("top_rules", []) or []
        summary["yara_engine_available"] = bool(ysum.get("engine_available"))
        summary["yara_loaded_rule_files"] = int(ysum.get("loaded_rule_files", 0))
    else:
        summary["yara_hits"] = 0
        summary["yara_top_rules"] = []
        summary["yara_engine_available"] = False
        summary["yara_loaded_rule_files"] = 0

    summary["baseline_deviation_hits"] = int(baseline_data.get("count", 0))
    summary["allowlist_suppressed"] = int(baseline_data.get("suppressed", 0))
    return results
