import os
import socket
from typing import List, Dict
from urllib.parse import urlparse
import yaml

try:
    import requests
    from requests.packages.urllib3.exceptions import InsecureRequestWarning
    requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
except ImportError:
    requests = None  # type: ignore


import ipaddress

def _is_private_ip(ip_str: str) -> bool:
    try:
        ip = ipaddress.ip_address(ip_str)
        return ip.is_private or ip.is_loopback or ip.is_link_local
    except ValueError:
        return False


def _is_safe_url(url: str) -> bool:
    try:
        parsed = urlparse(url)
        if parsed.scheme not in ("http", "https"):
            return False
        hostname = parsed.hostname
        if not hostname:
            return False
        try:
            addrs = socket.getaddrinfo(hostname, None, proto=socket.IPPROTO_TCP)
            for family, _, _, _, sockaddr in addrs:
                ip = sockaddr[0]
                if _is_private_ip(ip):
                    return False
        except socket.gaierror:
            return False
        return True
    except Exception:
        return False


class SigmaRule:
    def __init__(self, raw: Dict):
        self.raw = raw
        self.id = raw.get("id")
        self.title = raw.get("title")
        self.description = raw.get("description")
        self.level = raw.get("level")
        self.logsource = raw.get("logsource", {})
        self.detection = raw.get("detection", {})

    def match_event(self, event: Dict) -> bool:
        detection = self.detection or {}
        selection = detection.get("selection")
        condition = detection.get("condition", "selection")

        if not selection:
            return False

        # Flatten event fields
        fields: Dict[str, str] = {}
        for k, v in event.items():
            if isinstance(v, dict):
                for kk, vv in v.items():
                    fields[kk] = str(vv)
            else:
                fields[k] = str(v)

        def match_selection(sel: Dict) -> bool:
            for field, expected in sel.items():
                value = fields.get(field)
                if value is None:
                    return False
                sval = str(value).lower()
                if isinstance(expected, list):
                    if not any(str(e).lower() in sval for e in expected):
                        return False
                else:
                    if str(expected).lower() not in sval:
                        return False
            return True

        # For now only simple "selection" condition is supported
        if condition.strip() == "selection":
            return match_selection(selection)

        return match_selection(selection)


class SigmaEngine:
    def __init__(self, rules_dir: str, remote_dir: str = None):
        self.rules_dir = rules_dir
        self.remote_dir = remote_dir or os.path.join(self.rules_dir, "_remote")
        os.makedirs(self.remote_dir, exist_ok=True)
        self.rules: List[SigmaRule] = []
        self.reload_rules()
        # Optional: sync from env on startup
        self._auto_sync_from_env()

    def _load_rules_from_dir(self, directory: str):
        if not os.path.isdir(directory):
            return
        for root, _, files in os.walk(directory):
            for name in files:
                if not name.lower().endswith((".yml", ".yaml")):
                    continue
                path = os.path.join(root, name)
                try:
                    with open(path, "r", encoding="utf-8") as f:
                        data = yaml.safe_load(f) or {}
                        if isinstance(data, dict):
                            self.rules.append(SigmaRule(data))
                except Exception:
                    continue

    def reload_rules(self):
        # Reload all Sigma rules from local and remote directories.
        self.rules = []
        self._load_rules_from_dir(self.rules_dir)
        if os.path.isdir(self.remote_dir):
            self._load_rules_from_dir(self.remote_dir)

    def _auto_sync_from_env(self):
        urls_raw = os.getenv("FORENSIS_SIGMA_URLS", "").strip()
        if not urls_raw:
            return
        urls = [u.strip() for u in urls_raw.split(",") if u.strip()]
        if not urls:
            return
        self.sync_from_urls(urls)
        self.reload_rules()

    def sync_from_urls(self, urls: List[str]):
        if not requests:
            return

        os.makedirs(self.remote_dir, exist_ok=True)

        for url in urls:
            if not _is_safe_url(url):
                continue
            try:
                resp = requests.get(url, timeout=5)
                if resp.status_code != 200:
                    continue
                content = resp.text
                name = os.path.basename(url.split("?")[0]) or "remote_rule.yml"
                if not name.lower().endswith((".yml", ".yaml")):
                    name += ".yml"
                dest = os.path.join(self.remote_dir, name)
                with open(dest, "w", encoding="utf-8") as f:
                    f.write(content)
            except Exception:
                continue

    def correlate_events(self, events: List[Dict]):
        matches = []
        for idx, evt in enumerate(events):
            for rule in self.rules:
                try:
                    if rule.match_event(evt):
                        matches.append(
                            {
                                "event_index": idx,
                                "rule_id": rule.id,
                                "rule_title": rule.title,
                                "rule_level": rule.level,
                                "description": rule.description,
                                "event": evt,
                            }
                        )
                except Exception:
                    continue
        return matches
