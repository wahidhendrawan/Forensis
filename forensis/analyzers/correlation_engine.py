from collections import Counter, defaultdict
from datetime import timedelta
from typing import Dict, List


def _norm_type(analysis_type: str):
    text = (analysis_type or "").lower()
    if "log" in text:
        return "logs"
    if "network" in text:
        return "network"
    if "memory" in text:
        return "memory"
    return text or "unknown"


def _extract_identities(results: Dict):
    identities = set()
    for evt in (results.get("events") or [])[:1500]:
        for key in ("ip", "src_ip", "dst_ip", "host"):
            val = str(evt.get(key, "")).strip()
            if not val:
                continue
            if val.lower() in {"unknown", "-", "none"}:
                continue
            identities.add(val)
    for top in (results.get("summary", {}) or {}).get("top_sources", [])[:20]:
        if isinstance(top, (list, tuple)) and top and str(top[0]).strip():
            identities.add(str(top[0]).strip())
    return identities


def _extract_indicators(results: Dict):
    indicators = []
    summary = results.get("summary", {}) or {}

    for item in (summary.get("top_indicators") or [])[:10]:
        if isinstance(item, (list, tuple)) and item:
            indicators.append(str(item[0]))

    for item in (summary.get("yara_top_rules") or [])[:10]:
        if isinstance(item, (list, tuple)) and item:
            indicators.append(f"yara:{item[0]}")

    for item in (summary.get("ti_top_indicators") or [])[:10]:
        if isinstance(item, (list, tuple)) and item:
            indicators.append(f"ti:{item[0]}")

    for anomaly in (results.get("anomalies") or [])[:20]:
        ind = anomaly.get("indicator") or anomaly.get("reason")
        if ind:
            indicators.append(str(ind)[:160])
    return indicators


def correlate_recent_analyses(analysis_records: List, window_minutes: int = 60):
    observations = []
    for rec in analysis_records:
        try:
            results = rec.get_results() or {}
        except Exception:
            continue
        analysis_type = _norm_type(getattr(rec, "type", "unknown"))
        ts = getattr(rec, "timestamp", None)
        if ts is None:
            continue

        identities = _extract_identities(results)
        if not identities:
            continue
        indicators = _extract_indicators(results)
        threat_score = int((results.get("summary", {}) or {}).get("threat_score") or 0)
        ti_score = int((results.get("summary", {}) or {}).get("threat_intel_score") or 0)

        for identity in identities:
            observations.append(
                {
                    "identity": identity,
                    "timestamp": ts,
                    "source": analysis_type,
                    "indicators": indicators,
                    "risk_score": threat_score + ti_score,
                    "analysis_id": getattr(rec, "id", None),
                }
            )

    by_identity = defaultdict(list)
    for obs in observations:
        by_identity[obs["identity"]].append(obs)

    findings = []
    window_delta = timedelta(minutes=max(5, int(window_minutes)))

    for identity, obs_list in by_identity.items():
        obs_list.sort(key=lambda o: o["timestamp"])
        n = len(obs_list)
        for i in range(n):
            base = obs_list[i]
            sources = {base["source"]}
            indicators = set(base["indicators"])
            score = int(base["risk_score"])
            start = base["timestamp"]
            end = base["timestamp"]
            related = {base["analysis_id"]}

            for j in range(i + 1, n):
                cur = obs_list[j]
                if cur["timestamp"] - start > window_delta:
                    break
                sources.add(cur["source"])
                indicators.update(cur["indicators"])
                score += int(cur["risk_score"])
                end = cur["timestamp"]
                related.add(cur["analysis_id"])

            if len(sources) < 2:
                continue

            findings.append(
                {
                    "identity": identity,
                    "first_seen": start.isoformat(),
                    "last_seen": end.isoformat(),
                    "sources": sorted(sources),
                    "indicator_count": len(indicators),
                    "risk_score": score,
                    "related_analysis_ids": sorted(r for r in related if r is not None),
                    "sample_indicators": sorted(indicators)[:8],
                }
            )

    dedup = {}
    for f in sorted(findings, key=lambda x: (x["identity"], -x["risk_score"])):
        key = (f["identity"], tuple(f["sources"]))
        if key not in dedup or f["risk_score"] > dedup[key]["risk_score"]:
            dedup[key] = f

    final_findings = sorted(dedup.values(), key=lambda x: x["risk_score"], reverse=True)[:20]
    score_counter = Counter()
    for f in final_findings:
        if f["risk_score"] >= 80:
            score_counter["critical"] += 1
        elif f["risk_score"] >= 40:
            score_counter["high"] += 1
        elif f["risk_score"] >= 15:
            score_counter["medium"] += 1
        else:
            score_counter["low"] += 1

    return {
        "findings": final_findings,
        "count": len(final_findings),
        "severity_counts": dict(score_counter),
    }
