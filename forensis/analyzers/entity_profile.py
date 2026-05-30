import ipaddress
import json
import os
from typing import Dict, List


DEFAULT_ALLOWLIST = {
    "ips": ["127.0.0.1", "::1"],
    "domains": ["localhost"],
    "hashes": [],
    "processes": [],
    "paths": [],
}

DEFAULT_BASELINE = {
    "known_ports": [22, 53, 80, 123, 135, 139, 443, 445, 3389, 5985, 5986],
    "known_protocols": ["TCP", "UDP", "ICMP"],
    "trusted_processes": [
        "systemd",
        "sshd",
        "cron",
        "nginx",
        "apache2",
        "svchost.exe",
        "lsass.exe",
        "explorer.exe",
    ],
    "trusted_hosts": ["localhost"],
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


class EntityProfileEngine:
    def __init__(self, config_dir: str):
        self.config_dir = config_dir
        self.allowlist_path = os.path.join(config_dir, "entity_allowlist.json")
        self.baseline_path = os.path.join(config_dir, "entity_baseline.json")
        os.makedirs(config_dir, exist_ok=True)
        self.allowlist = {}
        self.baseline = {}
        self.reload()
        self._ensure_defaults()

    def _ensure_defaults(self):
        if not os.path.isfile(self.allowlist_path):
            with open(self.allowlist_path, "w", encoding="utf-8") as f:
                json.dump(DEFAULT_ALLOWLIST, f, indent=2)
        if not os.path.isfile(self.baseline_path):
            with open(self.baseline_path, "w", encoding="utf-8") as f:
                json.dump(DEFAULT_BASELINE, f, indent=2)
        self.reload()

    def reload(self):
        self.allowlist = _safe_load_json(self.allowlist_path, DEFAULT_ALLOWLIST.copy())
        self.baseline = _safe_load_json(self.baseline_path, DEFAULT_BASELINE.copy())

    def _domain_allowed(self, value: str) -> bool:
        domains = self.allowlist.get("domains", []) or []
        val = value.lower().strip(".")
        for item in domains:
            d = str(item).lower().strip().strip(".")
            if not d:
                continue
            if val == d or val.endswith("." + d):
                return True
        return False

    def _ip_allowed(self, value: str) -> bool:
        candidates = self.allowlist.get("ips", []) or []
        try:
            ip_obj = ipaddress.ip_address(value)
        except ValueError:
            return False
        for item in candidates:
            text = str(item).strip()
            if not text:
                continue
            if "/" in text:
                try:
                    if ip_obj in ipaddress.ip_network(text, strict=False):
                        return True
                except ValueError:
                    continue
            elif text == value:
                return True
        return False

    def is_allowlisted(self, indicator_type: str, value: str) -> bool:
        if not value:
            return False
        indicator_type = (indicator_type or "").lower()
        val = str(value).strip()
        if not val:
            return False

        if indicator_type == "ip":
            return self._ip_allowed(val)
        if indicator_type == "domain":
            return self._domain_allowed(val)

        bucket = self.allowlist.get(f"{indicator_type}s", []) or []
        return val.lower() in {str(item).lower() for item in bucket}

    def evaluate_events(self, events: List[Dict], source_type: str):
        anomalies = []
        suppressed = 0
        seen = set()

        known_ports = {int(p) for p in (self.baseline.get("known_ports", []) or []) if str(p).isdigit()}
        known_protocols = {str(p).upper() for p in (self.baseline.get("known_protocols", []) or [])}
        trusted_processes = {str(p).lower() for p in (self.baseline.get("trusted_processes", []) or [])}

        for evt in events[:1500]:
            proto = str(evt.get("proto", "")).upper()
            if proto and known_protocols and proto not in known_protocols:
                key = ("proto", proto)
                if key not in seen:
                    seen.add(key)
                    anomalies.append(
                        {
                            "reason": f"Protocol {proto} is outside environment baseline.",
                            "severity": "medium",
                            "category": "baseline_deviation",
                            "indicator": "unknown_protocol",
                            "event": evt,
                        }
                    )

            for port_key in ("dst_port", "dport"):
                p = evt.get(port_key)
                try:
                    port = int(p)
                except (TypeError, ValueError):
                    continue
                if known_ports and port not in known_ports and port > 0:
                    key = ("port", port)
                    if key not in seen:
                        seen.add(key)
                        anomalies.append(
                            {
                                "reason": f"Port {port} is outside known baseline ports.",
                                "severity": "low",
                                "category": "baseline_deviation",
                                "indicator": "unknown_port",
                                "event": evt,
                            }
                        )

            process = str(evt.get("process", "")).strip().lower()
            if process and trusted_processes and process not in trusted_processes:
                key = ("process", process)
                if key not in seen:
                    seen.add(key)
                    anomalies.append(
                        {
                            "reason": f"Process {process} is not present in trusted process baseline.",
                            "severity": "low",
                            "category": "baseline_deviation",
                            "indicator": "unknown_process",
                            "event": evt,
                        }
                    )

            for ip_key in ("ip", "src_ip", "dst_ip"):
                ip_val = str(evt.get(ip_key, "")).strip()
                if not ip_val:
                    continue
                if self.is_allowlisted("ip", ip_val):
                    suppressed += 1

        return {
            "anomalies": anomalies[:200],
            "suppressed": suppressed,
            "count": len(anomalies),
        }
