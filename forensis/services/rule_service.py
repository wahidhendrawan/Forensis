from typing import Dict, List, Optional, Tuple
import time


def _flow_to_event(flow: dict):
    if not isinstance(flow, dict):
        return None
    return {
        "source": "pcap_flow",
        "src_ip": flow.get("src"),
        "dst_ip": flow.get("dst"),
        "src_port": flow.get("sport"),
        "dst_port": flow.get("dport"),
        "proto": flow.get("proto"),
        "packets": flow.get("packets"),
        "bytes": flow.get("bytes"),
        "duration": flow.get("duration"),
        "avg_payload": flow.get("avg_payload"),
        "first_seen": flow.get("first_seen"),
        "last_seen": flow.get("last_seen"),
    }


def _event_key(evt: dict):
    if not isinstance(evt, dict):
        return None
    return (
        str(evt.get("source") or ""),
        str(evt.get("ip") or evt.get("src_ip") or ""),
        str(evt.get("host") or evt.get("dst_ip") or ""),
        str(evt.get("src_port") or ""),
        str(evt.get("dst_port") or ""),
        str(evt.get("proto") or ""),
        str(evt.get("indicator") or ""),
        str(evt.get("message") or evt.get("raw") or "")[:160],
    )


def _append_unique_event(bucket: list, seen: set, evt: dict):
    key = _event_key(evt)
    if key is None or key in seen:
        return False
    seen.add(key)
    bucket.append(evt)
    return True


def sigma_limits_for_type(
    analysis_type: str,
    default_max_events: int,
    max_matches: int,
    max_events_logs: int,
    max_events_network: int,
    max_events_memory: int,
) -> Tuple[int, int]:
    text = str(analysis_type or "").lower()
    if "network" in text:
        return max_events_network, max_matches
    if "memory" in text:
        return max_events_memory, max_matches
    if "log" in text:
        return max_events_logs, max_matches
    return default_max_events, max_matches


def select_sigma_candidate_events(results: dict, analysis_type: str, limit: int) -> List[Dict]:
    if not isinstance(results, dict) or limit <= 0:
        return []
    selected = []
    seen = set()
    events = results.get("events") or []
    anomalies = results.get("anomalies") or []
    flows = results.get("flows") or []
    text = str(analysis_type or "").lower()

    if "network" in text:
        for anomaly in anomalies:
            if not isinstance(anomaly, dict):
                continue
            evt = anomaly.get("event")
            if isinstance(evt, dict):
                _append_unique_event(selected, seen, evt)
                if len(selected) >= limit:
                    return selected
            flow_evt = _flow_to_event(anomaly.get("flow"))
            if flow_evt and _append_unique_event(selected, seen, flow_evt):
                if len(selected) >= limit:
                    return selected

        for flow in flows:
            flow_evt = _flow_to_event(flow)
            if flow_evt and _append_unique_event(selected, seen, flow_evt):
                if len(selected) >= limit:
                    return selected

    for evt in events:
        if isinstance(evt, dict) and _append_unique_event(selected, seen, evt):
            if len(selected) >= limit:
                return selected
    return selected


def compact_network_results(results: dict, events_limit: int, anomalies_limit: int):
    if not isinstance(results, dict):
        return results
    summary = results.setdefault("summary", {})
    if not isinstance(summary, dict):
        summary = {}
        results["summary"] = summary

    all_events = results.get("events") or []
    all_anomalies = results.get("anomalies") or []
    summary["event_count_total"] = len(all_events)
    summary["anomaly_count_total"] = len(all_anomalies)

    kept_events = select_sigma_candidate_events(results, "network", events_limit)
    if len(kept_events) < events_limit:
        seen = {_event_key(evt) for evt in kept_events if isinstance(evt, dict)}
        for evt in all_events:
            if not isinstance(evt, dict):
                continue
            if _append_unique_event(kept_events, seen, evt) and len(kept_events) >= events_limit:
                break

    results["events"] = kept_events[:events_limit]
    results["events_truncated"] = len(all_events) > len(results["events"])

    if len(all_anomalies) > anomalies_limit:
        results["anomalies"] = all_anomalies[:anomalies_limit]
        results["anomalies_truncated"] = True
    else:
        results["anomalies_truncated"] = False
    return results


def resolve_sigma_matches(
    results: dict,
    analysis_type: str,
    sigma_engine,
    *,
    default_max_events: int,
    max_matches: int,
    max_events_logs: int,
    max_events_network: int,
    max_events_memory: int,
    force_recompute: bool = False,
) -> List[Dict]:
    if not isinstance(results, dict):
        return []

    existing = results.get("sigma_matches")
    if isinstance(existing, list) and not force_recompute:
        return existing

    max_events, max_rules_matches = sigma_limits_for_type(
        analysis_type,
        default_max_events=default_max_events,
        max_matches=max_matches,
        max_events_logs=max_events_logs,
        max_events_network=max_events_network,
        max_events_memory=max_events_memory,
    )
    candidates = select_sigma_candidate_events(results, analysis_type, max_events)
    if not candidates:
        results["sigma_matches"] = []
        return []

    started = time.monotonic()
    matches = sigma_engine.correlate_events(candidates, max_events=max_events, max_matches=max_rules_matches)
    elapsed = time.monotonic() - started

    summary = results.setdefault("summary", {})
    if not isinstance(summary, dict):
        summary = {}
        results["summary"] = summary
    summary["sigma_event_sampled"] = len(candidates)
    summary["sigma_match_count"] = len(matches)
    summary["sigma_correlation_seconds"] = round(elapsed, 3)
    summary["sigma_max_events"] = max_events
    summary["sigma_max_matches"] = max_rules_matches
    summary["sigma_matches_limited"] = len(matches) >= max_rules_matches
    results["sigma_matches"] = matches
    return matches


def extract_result_summary(results: Optional[dict]):
    if not isinstance(results, dict):
        return {}
    summary = results.get("summary")
    if not isinstance(summary, dict):
        summary = {}
    return {
        "event_count": len(results.get("events") or []),
        "anomaly_count": len(results.get("anomalies") or []),
        "threat_score": int(summary.get("threat_score") or 0),
        "sigma_match_count": int(summary.get("sigma_match_count") or len(results.get("sigma_matches") or [])),
        "severity_counts": summary.get("severity_counts") or {},
    }

