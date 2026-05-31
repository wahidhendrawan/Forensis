import ipaddress
import json
import os
import re
import time
import hashlib
from collections import Counter
from typing import Dict, List, Tuple

try:
    import requests
except Exception:
    requests = None  # type: ignore


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


def _safe_int_env(name: str, default: int, min_value: int = None, max_value: int = None) -> int:
    raw = (os.getenv(name, "") or "").strip()
    try:
        value = int(raw) if raw else int(default)
    except (TypeError, ValueError):
        value = int(default)
    if min_value is not None and value < min_value:
        value = min_value
    if max_value is not None and value > max_value:
        value = max_value
    return value


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


def _is_public_ip(value: str) -> bool:
    try:
        ip_obj = ipaddress.ip_address(value)
    except ValueError:
        return False
    if getattr(ip_obj, "version", 0) != 4:
        return False
    if ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_link_local:
        return False
    if ip_obj.is_multicast or ip_obj.is_reserved or ip_obj.is_unspecified:
        return False
    return bool(getattr(ip_obj, "is_global", False))


class ThreatIntelEngine:
    def __init__(self, intel_dir: str, allowlist_engine=None, otx_api_key_getter=None):
        self.intel_dir = intel_dir
        self.feed_path = os.path.join(intel_dir, "ioc_feed.json")
        self.cache_path = os.path.join(intel_dir, "lookup_cache.json")
        self.allowlist_engine = allowlist_engine
        self.otx_api_key_getter = otx_api_key_getter
        self.cache_ttl_seconds = _safe_int_env("FORENSIS_TI_CACHE_TTL", 43200, min_value=300, max_value=604800)
        self.max_hits = _safe_int_env("FORENSIS_TI_MAX_HITS", 500, min_value=50, max_value=5000)
        self.cache_max_entries = _safe_int_env("FORENSIS_TI_CACHE_MAX_ENTRIES", 50000, min_value=200, max_value=500000)
        self.otx_base_url = os.getenv("FORENSIS_OTX_BASE_URL", "https://otx.alienvault.com/api/v1").rstrip("/")
        self.otx_timeout_seconds = _safe_int_env("FORENSIS_OTX_TIMEOUT_SECONDS", 4, min_value=2, max_value=20)
        self.otx_max_lookups = _safe_int_env("FORENSIS_OTX_MAX_LOOKUPS", 30, min_value=1, max_value=300)
        self.otx_max_seconds = _safe_int_env("FORENSIS_OTX_MAX_SECONDS", 12, min_value=2, max_value=120)
        os.makedirs(intel_dir, exist_ok=True)
        self.feed = {}
        self.cache = {}
        self.exact = {}
        self.cidr_rules = []
        self._cache_dirty = False
        self._otx_lookups = 0
        self._otx_deadline = 0.0
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

    def invalidate_cache_prefix(self, prefix: str):
        if not prefix:
            return
        modified = False
        for key in list(self.cache.keys()):
            if str(key).startswith(prefix):
                self.cache.pop(key, None)
                modified = True
        if modified:
            self._cache_dirty = True
            self._save_cache()

    def _get_otx_api_key(self) -> str:
        if not callable(self.otx_api_key_getter):
            return ""
        try:
            value = self.otx_api_key_getter()
        except Exception:
            return ""
        if value is None:
            return ""
        return str(value).strip()

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

    def _lookup_local_indicator(self, ind_type: str, value: str):
        cache_key = f"local:{ind_type}:{value}"
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

    def _lookup_otx_ip(self, value: str):
        if self._otx_deadline and time.monotonic() >= self._otx_deadline:
            return {"matched": False, "budget_exceeded": True}
        if self._otx_lookups >= self.otx_max_lookups:
            return {"matched": False}
        if not _is_public_ip(value):
            return {"matched": False}
        if not requests:
            return {"matched": False}

        api_key = self._get_otx_api_key()
        if not api_key:
            return {"matched": False}

        cache_key = f"otx:ip:{value}"
        cached = self._cache_get(cache_key)
        if cached is not None:
            return cached

        self._otx_lookups += 1
        url = f"{self.otx_base_url}/indicators/IPv4/{value}/general"
        headers = {
            "X-OTX-API-KEY": api_key,
            "Accept": "application/json",
            "User-Agent": "Forensis-ThreatIntel/1.0",
        }
        try:
            resp = requests.get(url, headers=headers, timeout=self.otx_timeout_seconds)
        except Exception:
            result = {"matched": False}
            self._cache_set(cache_key, result)
            return result

        if resp.status_code in {401, 403}:
            # Do not cache auth failures aggressively; key may be rotated quickly.
            return {"matched": False, "auth_error": True}
        if resp.status_code >= 500:
            return {"matched": False}
        if resp.status_code != 200:
            result = {"matched": False}
            self._cache_set(cache_key, result)
            return result

        try:
            payload = resp.json()
        except Exception:
            result = {"matched": False}
            self._cache_set(cache_key, result)
            return result

        pulse_info = payload.get("pulse_info") or {}
        pulse_count = int(pulse_info.get("count") or 0)
        reputation = payload.get("reputation")
        try:
            reputation = int(reputation)
        except (TypeError, ValueError):
            reputation = 0

        if pulse_count <= 0 and reputation >= 0:
            result = {"matched": False}
            self._cache_set(cache_key, result)
            return result

        severity = "low"
        score = 12
        if pulse_count >= 20 or reputation <= -15:
            severity = "critical"
            score = 70
        elif pulse_count >= 8 or reputation <= -7:
            severity = "high"
            score = 50
        elif pulse_count >= 3 or reputation <= -3:
            severity = "medium"
            score = 30
        elif pulse_count >= 1 or reputation < 0:
            severity = "low"
            score = 15

        country = str(payload.get("country_name") or "").strip()
        asn = str(payload.get("asn") or "").strip()
        details = []
        if pulse_count:
            details.append(f"pulses={pulse_count}")
        if reputation:
            details.append(f"reputation={reputation}")
        if country:
            details.append(f"country={country}")
        if asn:
            details.append(f"asn={asn}")

        name = "OTX IP Reputation"
        if details:
            name = f"OTX IP Reputation ({', '.join(details)})"
        result = {
            "matched": True,
            "type": "ip",
            "value": value,
            "name": name,
            "severity": severity,
            "score": score,
            "source": "otx-api",
            "pulse_count": pulse_count,
            "reputation": reputation,
            "external_ref": url,
            "cache_tag": hashlib.sha1(f"{value}:{pulse_count}:{reputation}".encode("utf-8")).hexdigest()[:12],
        }
        self._cache_set(cache_key, result)
        return result

    def lookup_indicator(self, ind_type: str, value: str, source_type: str = None):
        ind_type, value = _normalize_indicator(ind_type, value)
        if ind_type not in {"ip", "domain", "hash"} or not value:
            return {"matched": False}

        if self.allowlist_engine and self.allowlist_engine.is_allowlisted(ind_type, value):
            return {"matched": False, "allowlisted": True}

        local_result = self._lookup_local_indicator(ind_type, value)
        if local_result.get("matched"):
            return local_result

        source = str(source_type or "").lower()
        allow_otx = source in {"log", "logs"}
        if allow_otx and ind_type == "ip":
            otx_result = self._lookup_otx_ip(value)
            if otx_result.get("matched"):
                return otx_result
        return {"matched": False}

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
        self._otx_lookups = 0
        source = str(source_type or "").lower()
        self._otx_deadline = time.monotonic() + self.otx_max_seconds if source in {"log", "logs"} else 0.0
        hits = []
        seen = set()
        total_score = 0
        severity_counts = Counter()
        indicator_counter = Counter()

        for idx, evt in enumerate(events[:2000]):
            evt_hits = []
            for ind_type, value in self.extract_indicators(evt):
                res = self.lookup_indicator(ind_type, value, source_type=source_type)
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
        self._otx_deadline = 0.0

        return {
            "hits": hits,
            "hit_count": len(hits),
            "total_score": total_score,
            "severity_counts": dict(severity_counts),
            "top_indicators": indicator_counter.most_common(10),
        }
