import ipaddress
import json
import os
import re
import time
from collections import Counter
from typing import Dict, List, Tuple


IP_REGEX = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
DOMAIN_REGEX = re.compile(r"\b(?:[a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?\.)+[a-z]{2,24}\b", re.I)
SHA256_REGEX = re.compile(r"\b[a-f0-9]{64}\b", re.I)
SHA1_REGEX = re.compile(r"\b[a-f0-9]{40}\b", re.I)
MD5_REGEX = re.compile(r"\b[a-f0-9]{32}\b", re.I)

DEFAULT_FEED = {
    "generated_at": "2026-05-30T00:00:00Z",
    "indicators": [
        {
            "type": "ip",
            "value": "185.220.101.1",
            "name": "Known Tor Exit Node Abuse",
            "severity": "medium",
            "score": 25,
            "source": "forensis-default-ti",
        },
        {
            "type": "domain",
            "value": "pastebin-malware.example",
            "name": "Malware Payload Domain",
            "severity": "high",
            "score": 45,
            "source": "forensis-default-ti",
        },
        {
            "type": "hash",
            "value": "44d88612fea8a8f36de82e1278abb02f",
            "name": "EICAR / Test Malware Marker",
            "severity": "low",
            "score": 10,
            "source": "forensis-default-ti",
        },
    ],
    "cidr": [
        {
            "value": "45.95.147.0/24",
            "name": "Known Suspicious VPS Segment",
            "severity": "medium",
            "score": 30,
            "source": "forensis-default-ti",
        }
    ],
}

SEVERITY_SCORE = {
    "critical": 60,
    "high": 40,
    "medium": 20,
    "low": 10,
}


def _safe_load_json(path: str, fallback):
    if not os.path.isfile(path):
        return fallback
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
        if isinstance(data, dict):
            return data
    except Exception:
        return fallback
    return fallback


def _normalize_indicator(ind_type: str, value: str):
    t = (ind_type or "").lower().strip()
    v = (value or "").strip().lower()
    return t, v


class ThreatIntelEngine:
    def __init__(self, intel_dir: str, allowlist_engine=None):
        self.intel_dir = intel_dir
        self.feed_path = os.path.join(intel_dir, "ioc_feed.json")
        self.cache_path = os.path.join(intel_dir, "lookup_cache.json")
        self.allowlist_engine = allowlist_engine
        self.cache_ttl_seconds = int(os.getenv("FORENSIS_TI_CACHE_TTL", "43200"))
        self.max_hits = int(os.getenv("FORENSIS_TI_MAX_HITS", "500"))
        self.cache_max_entries = max(200, int(os.getenv("FORENSIS_TI_CACHE_MAX_ENTRIES", "50000")))
        os.makedirs(intel_dir, exist_ok=True)
        self.feed = {}
        self.cache = {}
        self.exact = {}
        self.cidr_rules = []
        self._cache_dirty = False
        self.reload()
        self._ensure_defaults()

    def _ensure_defaults(self):
        if not os.path.isfile(self.feed_path):
            with open(self.feed_path, "w", encoding="utf-8") as f:
                json.dump(DEFAULT_FEED, f, indent=2)
        self.reload()

    def reload(self):
        self.feed = _safe_load_json(self.feed_path, DEFAULT_FEED.copy())
        self.cache = _safe_load_json(self.cache_path, {})
        self._cache_dirty = False
        self._build_indexes()

    def _build_indexes(self):
        self.exact = {"ip": {}, "domain": {}, "hash": {}}
        self.cidr_rules = []

        for item in self.feed.get("indicators", []) or []:
            ind_type, value = _normalize_indicator(item.get("type"), item.get("value"))
            if ind_type not in {"ip", "domain", "hash"} or not value:
                continue
            self.exact[ind_type][value] = item

        for entry in self.feed.get("cidr", []) or []:
            cidr_text = str(entry.get("value", "")).strip()
            if not cidr_text:
                continue
            try:
                net = ipaddress.ip_network(cidr_text, strict=False)
                self.cidr_rules.append((net, entry))
            except ValueError:
                continue

    def _cache_get(self, key: str):
        now = int(time.time())
        obj = self.cache.get(key)
        if not isinstance(obj, dict):
            return None
        ts = int(obj.get("ts", 0))
        if now - ts > self.cache_ttl_seconds:
            self.cache.pop(key, None)
            self._cache_dirty = True
            return None
        return obj.get("result")

    def _cache_set(self, key: str, result):
        self.cache[key] = {
            "ts": int(time.time()),
            "result": result,
        }
        self._cache_dirty = True
        if len(self.cache) > self.cache_max_entries:
            # Keep newest cache entries to avoid unbounded growth.
            ordered = sorted(
                ((k, v.get("ts", 0)) for k, v in self.cache.items() if isinstance(v, dict)),
                key=lambda item: item[1],
                reverse=True,
            )
            keep_keys = {k for k, _ in ordered[: self.cache_max_entries]}
            for old_key in list(self.cache.keys()):
                if old_key not in keep_keys:
                    self.cache.pop(old_key, None)

    def _save_cache(self):
        try:
            tmp_path = f"{self.cache_path}.tmp"
            with open(tmp_path, "w", encoding="utf-8") as f:
                json.dump(self.cache, f, indent=2)
            os.replace(tmp_path, self.cache_path)
            self._cache_dirty = False
        except Exception:
            return

    def _lookup_ip(self, value: str):
        exact = self.exact["ip"].get(value)
        if exact:
            return exact
        try:
            ip_obj = ipaddress.ip_address(value)
        except ValueError:
            return None
        for network, entry in self.cidr_rules:
            if ip_obj in network:
                return entry
        return None

    def _lookup_domain(self, value: str):
        exact = self.exact["domain"].get(value)
        if exact:
            return exact
        for dom, item in self.exact["domain"].items():
            if dom.startswith("*."):
                suffix = dom[1:]
                if value.endswith(suffix):
                    return item
            elif value == dom or value.endswith("." + dom):
                return item
        return None

    def _lookup_hash(self, value: str):
        return self.exact["hash"].get(value)

    def lookup_indicator(self, ind_type: str, value: str):
        ind_type, value = _normalize_indicator(ind_type, value)
        if ind_type not in {"ip", "domain", "hash"} or not value:
            return {"matched": False}

        if self.allowlist_engine and self.allowlist_engine.is_allowlisted(ind_type, value):
            return {"matched": False, "allowlisted": True}

        cache_key = f"{ind_type}:{value}"
        cached = self._cache_get(cache_key)
        if cached is not None:
            return cached

        hit = None
        if ind_type == "ip":
            hit = self._lookup_ip(value)
        elif ind_type == "domain":
            hit = self._lookup_domain(value)
        elif ind_type == "hash":
            hit = self._lookup_hash(value)

        if not hit:
            result = {"matched": False}
            self._cache_set(cache_key, result)
            return result

        severity = str(hit.get("severity", "medium")).lower()
        score = int(hit.get("score") or SEVERITY_SCORE.get(severity, 20))
        result = {
            "matched": True,
            "type": ind_type,
            "value": value,
            "name": hit.get("name") or "Threat Intel Match",
            "severity": severity,
            "score": score,
            "source": hit.get("source") or "threat-intel-feed",
        }
        self._cache_set(cache_key, result)
        return result

    def _extract_from_text(self, text: str):
        indicators = []
        if not text:
            return indicators
        text = text[:500000]

        for m in IP_REGEX.findall(text):
            indicators.append(("ip", m))
        for m in DOMAIN_REGEX.findall(text.lower()):
            indicators.append(("domain", m))
        for m in SHA256_REGEX.findall(text):
            indicators.append(("hash", m))
        for m in SHA1_REGEX.findall(text):
            indicators.append(("hash", m))
        for m in MD5_REGEX.findall(text):
            indicators.append(("hash", m))
        return indicators

    def extract_indicators(self, event: Dict):
        direct = []
        for key in ("ip", "src_ip", "dst_ip"):
            val = str(event.get(key, "")).strip()
            if val:
                direct.append(("ip", val))

        for key in ("host", "domain"):
            val = str(event.get(key, "")).strip().lower()
            if val and "." in val and " " not in val:
                direct.append(("domain", val))

        text_parts = []
        for key in ("message", "raw", "path", "process", "uri"):
            val = event.get(key)
            if val is not None:
                text_parts.append(str(val))
        text_indicators = self._extract_from_text(" ".join(text_parts))

        unique = set()
        out: List[Tuple[str, str]] = []
        for ind_type, value in direct + text_indicators:
            t, v = _normalize_indicator(ind_type, value)
            if not v:
                continue
            key = (t, v)
            if key in unique:
                continue
            unique.add(key)
            out.append(key)
        return out

    def enrich_events(self, events: List[Dict], source_type: str):
        hits = []
        seen = set()
        total_score = 0
        severity_counts = Counter()
        indicator_counter = Counter()

        for idx, evt in enumerate(events[:2000]):
            evt_hits = []
            for ind_type, value in self.extract_indicators(evt):
                res = self.lookup_indicator(ind_type, value)
                if not res.get("matched"):
                    continue
                hit_key = (res["type"], res["value"], res.get("name"))
                if hit_key in seen:
                    continue
                seen.add(hit_key)
                entry = {
                    "event_index": idx,
                    "source_type": source_type,
                    "indicator_type": res["type"],
                    "indicator_value": res["value"],
                    "name": res.get("name"),
                    "severity": res.get("severity", "medium"),
                    "score": int(res.get("score", 0)),
                    "source": res.get("source"),
                }
                hits.append(entry)
                evt_hits.append(entry)
                total_score += entry["score"]
                severity_counts[entry["severity"]] += 1
                indicator_counter[f"{entry['indicator_type']}:{entry['indicator_value']}"] += 1
                if len(hits) >= self.max_hits:
                    break
            if evt_hits:
                evt["threat_intel_hits"] = evt_hits[:5]
                evt["threat_intel_score"] = sum(h["score"] for h in evt_hits[:5])
            if len(hits) >= self.max_hits:
                break

        if self._cache_dirty:
            self._save_cache()

        return {
            "hits": hits,
            "hit_count": len(hits),
            "total_score": total_score,
            "severity_counts": dict(severity_counts),
            "top_indicators": indicator_counter.most_common(10),
        }
