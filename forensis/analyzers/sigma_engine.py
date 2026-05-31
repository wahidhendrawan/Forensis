import os
import io
import json
import socket
import re
import fnmatch
import tarfile
import tempfile
import shutil
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
try:
    import fcntl  # Unix-only advisory lock for baseline refresh.
except ImportError:
    fcntl = None  # type: ignore

MAX_REMOTE_URLS = 20
MAX_REMOTE_RULE_BYTES = 1024 * 1024
SIGMAHQ_DEFAULT_REPO = "SigmaHQ/sigma"
SIGMAHQ_DEFAULT_COMMIT = "994da16651194500b607a3007186c29779e1f961"
SIGMAHQ_DEFAULT_RULES_SUBDIR = "rules"
SIGMAHQ_BASELINE_TIMEOUT = 60
SIGMAHQ_BASELINE_MAX_ARCHIVE_BYTES = 200 * 1024 * 1024
SIGMAHQ_BASELINE_MAX_RULE_FILES = 20000
SIGMAHQ_BASELINE_MAX_RULE_FILE_BYTES = 2 * 1024 * 1024

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
        condition = detection.get("condition", "selection")
        selections = {
            str(name): sel
            for name, sel in detection.items()
            if isinstance(sel, dict)
        }
        if not selections:
            return False

        # Flatten event fields and keep case-insensitive lookup.
        fields: Dict[str, str] = {}
        for k, v in event.items():
            if isinstance(v, dict):
                for kk, vv in v.items():
                    fields[str(kk)] = str(vv)
                    fields[str(kk).lower()] = str(vv)
            else:
                fields[str(k)] = str(v)
                fields[str(k).lower()] = str(v)

        def _match_value(actual: str, expected, modifier: str) -> bool:
            sval = str(actual).strip()
            exp = str(expected).strip()
            if not sval or not exp:
                return False

            mod = (modifier or "contains").lower()
            sval_lower = sval.lower()
            exp_lower = exp.lower()

            if mod in {"eq", "exact"}:
                return sval_lower == exp_lower
            if mod == "startswith":
                return sval_lower.startswith(exp_lower)
            if mod == "endswith":
                return sval_lower.endswith(exp_lower)
            if mod in {"regex", "re"}:
                try:
                    return re.search(exp, sval, flags=re.I) is not None
                except re.error:
                    return False
            if mod in {"gt", "gte", "lt", "lte"}:
                try:
                    left = float(sval)
                    right = float(exp)
                except ValueError:
                    return False
                if mod == "gt":
                    return left > right
                if mod == "gte":
                    return left >= right
                if mod == "lt":
                    return left < right
                return left <= right
            if "*" in exp_lower or "?" in exp_lower:
                return fnmatch.fnmatch(sval_lower, exp_lower)
            return exp_lower in sval_lower

        def match_selection(sel: Dict) -> bool:
            for field_expr, expected in sel.items():
                expr = str(field_expr)
                parts = expr.split("|", 1)
                field = parts[0].strip()
                modifier = parts[1].strip() if len(parts) > 1 else "contains"
                if not field:
                    return False
                value = fields.get(field) or fields.get(field.lower())
                if value is None:
                    return False
                if isinstance(expected, list):
                    if not any(_match_value(str(value), e, modifier) for e in expected):
                        return False
                else:
                    if not _match_value(str(value), expected, modifier):
                        return False
            return True

        def _eval_condition(expression: str) -> bool:
            cond = (expression or "").strip()
            if not cond:
                return False
            cond_l = cond.lower()

            if cond in selections:
                return match_selection(selections[cond])
            if cond_l == "selection" and "selection" in selections:
                return match_selection(selections["selection"])
            if cond_l == "1 of them":
                return any(match_selection(sel) for sel in selections.values())
            if cond_l == "all of them":
                return all(match_selection(sel) for sel in selections.values())
            if cond_l.startswith("1 of "):
                pattern = cond[5:].strip()
                named = [name for name in selections if fnmatch.fnmatch(name, pattern)]
                return any(match_selection(selections[name]) for name in named)
            if cond_l.startswith("all of "):
                pattern = cond[7:].strip()
                named = [name for name in selections if fnmatch.fnmatch(name, pattern)]
                return bool(named) and all(match_selection(selections[name]) for name in named)
            if re.search(r"\s+and\s+", cond, flags=re.I):
                parts = re.split(r"\s+and\s+", cond, flags=re.I)
                return all(_eval_condition(part) for part in parts)
            if re.search(r"\s+or\s+", cond, flags=re.I):
                parts = re.split(r"\s+or\s+", cond, flags=re.I)
                return any(_eval_condition(part) for part in parts)

            return False

        return _eval_condition(str(condition))


class SigmaEngine:
    def __init__(self, rules_dir: str, remote_dir: str = None, baseline_dir: str = None):
        self.rules_dir = rules_dir
        self.remote_dir = remote_dir or os.path.join(self.rules_dir, "_remote")
        self.baseline_dir = baseline_dir or os.path.join(self.rules_dir, "_sigmahq_baseline")
        self.baseline_meta_path = os.path.join(self.baseline_dir, "_meta.json")
        self.baseline_lock_path = os.path.join(self.baseline_dir, ".baseline.lock")
        self.baseline_repo = os.getenv("FORENSIS_SIGMAHQ_REPO", SIGMAHQ_DEFAULT_REPO).strip() or SIGMAHQ_DEFAULT_REPO
        self.baseline_commit = os.getenv("FORENSIS_SIGMAHQ_COMMIT", SIGMAHQ_DEFAULT_COMMIT).strip() or SIGMAHQ_DEFAULT_COMMIT
        self.baseline_rules_subdir = (
            os.getenv("FORENSIS_SIGMAHQ_RULES_SUBDIR", SIGMAHQ_DEFAULT_RULES_SUBDIR).strip().strip("/") or SIGMAHQ_DEFAULT_RULES_SUBDIR
        )
        os.makedirs(self.remote_dir, exist_ok=True)
        os.makedirs(self.baseline_dir, exist_ok=True)
        self.rules: List[SigmaRule] = []
        self._ensure_sigmahq_baseline()
        self.reload_rules()
        # Optional: sync from env on startup
        self._auto_sync_from_env()

    def _sigmahq_archive_url(self) -> str:
        return f"https://github.com/{self.baseline_repo}/archive/{self.baseline_commit}.tar.gz"

    def _load_baseline_meta(self) -> Dict:
        if not os.path.isfile(self.baseline_meta_path):
            return {}
        try:
            with open(self.baseline_meta_path, "r", encoding="utf-8") as f:
                data = json.load(f)
            if isinstance(data, dict):
                return data
        except Exception:
            return {}
        return {}

    def _baseline_ready(self) -> bool:
        meta = self._load_baseline_meta()
        if meta.get("repo") != self.baseline_repo:
            return False
        if meta.get("commit") != self.baseline_commit:
            return False
        if int(meta.get("rule_count", 0)) <= 0:
            return False
        for _, _, files in os.walk(self.baseline_dir):
            if any(name.lower().endswith((".yml", ".yaml")) for name in files):
                return True
        return False

    def _normalize_rule_relative_path(self, rel_path: str):
        rel = rel_path.replace("\\", "/").strip()
        if not rel:
            return None
        rel = os.path.normpath(rel)
        if rel.startswith("..") or os.path.isabs(rel):
            return None
        return rel

    def _download_sigmahq_archive(self):
        if not requests:
            return None
        url = self._sigmahq_archive_url()
        if not _is_safe_url(url):
            return None
        try:
            resp = requests.get(url, timeout=SIGMAHQ_BASELINE_TIMEOUT)
        except Exception:
            return None
        if resp.status_code != 200:
            return None
        if len(resp.content) > SIGMAHQ_BASELINE_MAX_ARCHIVE_BYTES:
            return None
        return resp.content

    def _extract_sigmahq_rules(self, archive_bytes: bytes, target_dir: str) -> int:
        rule_prefix = f"{self.baseline_rules_subdir}/"
        extracted_count = 0

        with tarfile.open(fileobj=io.BytesIO(archive_bytes), mode="r:gz") as tar:
            members = tar.getmembers()
            for member in members:
                if not member.isfile():
                    continue

                parts = member.name.split("/", 1)
                if len(parts) != 2:
                    continue
                repo_rel = parts[1]
                if not repo_rel.startswith(rule_prefix):
                    continue
                if not repo_rel.lower().endswith((".yml", ".yaml")):
                    continue
                if member.size > SIGMAHQ_BASELINE_MAX_RULE_FILE_BYTES:
                    continue

                rel_rule = repo_rel[len(rule_prefix) :]
                safe_rel = self._normalize_rule_relative_path(rel_rule)
                if not safe_rel:
                    continue

                dest_path = os.path.abspath(os.path.join(target_dir, safe_rel))
                target_abs = os.path.abspath(target_dir)
                if not (dest_path == target_abs or dest_path.startswith(target_abs + os.sep)):
                    continue

                source = tar.extractfile(member)
                if source is None:
                    continue
                os.makedirs(os.path.dirname(dest_path), exist_ok=True)
                with source:
                    data = source.read(SIGMAHQ_BASELINE_MAX_RULE_FILE_BYTES + 1)
                if len(data) > SIGMAHQ_BASELINE_MAX_RULE_FILE_BYTES:
                    continue
                with open(dest_path, "wb") as out:
                    out.write(data)
                extracted_count += 1
                if extracted_count >= SIGMAHQ_BASELINE_MAX_RULE_FILES:
                    break

        return extracted_count

    def _write_baseline_meta(self, rule_count: int):
        meta = {
            "repo": self.baseline_repo,
            "commit": self.baseline_commit,
            "rules_subdir": self.baseline_rules_subdir,
            "rule_count": int(rule_count),
            "archive_url": self._sigmahq_archive_url(),
        }
        try:
            with open(self.baseline_meta_path, "w", encoding="utf-8") as f:
                json.dump(meta, f, indent=2)
        except Exception:
            return

    def _ensure_sigmahq_baseline(self):
        force_refresh = os.getenv("FORENSIS_SIGMAHQ_REFRESH", "").strip().lower() in {"1", "true", "yes", "on"}
        if self._baseline_ready() and not force_refresh:
            return

        lock_file = None
        try:
            lock_file = open(self.baseline_lock_path, "a+", encoding="utf-8")
            if fcntl:
                fcntl.flock(lock_file.fileno(), fcntl.LOCK_EX)

            if self._baseline_ready() and not force_refresh:
                return

            archive_bytes = self._download_sigmahq_archive()
            if not archive_bytes:
                return

            temp_root = tempfile.mkdtemp(prefix="sigmahq_baseline_", dir=self.rules_dir)
            temp_rules_dir = os.path.join(temp_root, "rules")
            os.makedirs(temp_rules_dir, exist_ok=True)

            try:
                rule_count = self._extract_sigmahq_rules(archive_bytes, temp_rules_dir)
                if rule_count <= 0:
                    return

                swap_dir = self.baseline_dir + ".swap"
                if os.path.isdir(swap_dir):
                    shutil.rmtree(swap_dir, ignore_errors=True)
                os.replace(temp_rules_dir, swap_dir)
                if os.path.isdir(self.baseline_dir):
                    shutil.rmtree(self.baseline_dir, ignore_errors=True)
                os.replace(swap_dir, self.baseline_dir)
                self._write_baseline_meta(rule_count)
            finally:
                shutil.rmtree(temp_root, ignore_errors=True)
                swap_dir = self.baseline_dir + ".swap"
                if os.path.isdir(swap_dir):
                    shutil.rmtree(swap_dir, ignore_errors=True)
        finally:
            if lock_file:
                if fcntl:
                    try:
                        fcntl.flock(lock_file.fileno(), fcntl.LOCK_UN)
                    except Exception:
                        pass
                lock_file.close()

    def _is_sigma_rule(self, data: Dict) -> bool:
        return isinstance(data, dict) and isinstance(data.get("detection"), dict) and bool(data.get("title"))

    def _load_rules_from_dir(self, directory: str):
        if not os.path.isdir(directory):
            return
        remote_abs = os.path.abspath(self.remote_dir)
        for root, _, files in os.walk(directory):
            root_abs = os.path.abspath(root)
            if (root_abs == remote_abs or root_abs.startswith(remote_abs + os.sep)) and os.path.abspath(directory) != remote_abs:
                continue
            for name in files:
                if not name.lower().endswith((".yml", ".yaml")):
                    continue
                path = os.path.join(root, name)
                try:
                    with open(path, "r", encoding="utf-8") as f:
                        loaded_docs = list(yaml.safe_load_all(f))
                        for data in loaded_docs:
                            if isinstance(data, list):
                                for item in data:
                                    if self._is_sigma_rule(item):
                                        self.rules.append(SigmaRule(item))
                            elif self._is_sigma_rule(data):
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
        urls = [u.strip() for u in re.split(r"[\n,]+", urls_raw) if u.strip()]
        if not urls:
            return
        self.sync_from_urls(urls)
        self.reload_rules()

    def sync_from_urls(self, urls: List[str]):
        if not requests:
            return 0

        os.makedirs(self.remote_dir, exist_ok=True)
        imported = 0
        for idx, url in enumerate(urls[:MAX_REMOTE_URLS]):
            if not _is_safe_url(url):
                continue
            try:
                resp = requests.get(url, timeout=10)
                if resp.status_code != 200:
                    continue
                if len(resp.content) > MAX_REMOTE_RULE_BYTES:
                    continue

                content = resp.text or ""
                preview = content[:2048].lower()
                if "<html" in preview or "<!doctype html" in preview:
                    continue

                docs = list(yaml.safe_load_all(content))
                valid_docs = []
                for doc in docs:
                    if isinstance(doc, list):
                        for item in doc:
                            if self._is_sigma_rule(item):
                                valid_docs.append(item)
                    elif self._is_sigma_rule(doc):
                        valid_docs.append(doc)
                if not valid_docs:
                    continue

                name = os.path.basename(url.split("?")[0]) or "remote_rule.yml"
                name = re.sub(r"[^A-Za-z0-9._-]", "_", name)
                if not name.lower().endswith((".yml", ".yaml")):
                    name += ".yml"
                if name.startswith("."):
                    name = f"rule_{idx + 1}{name}"

                base, ext = os.path.splitext(name)
                if len(valid_docs) == 1:
                    dest = os.path.join(self.remote_dir, name)
                    with open(dest, "w", encoding="utf-8") as f:
                        yaml.safe_dump(valid_docs[0], f, sort_keys=False, allow_unicode=False)
                    imported += 1
                else:
                    for doc_idx, doc in enumerate(valid_docs, start=1):
                        dest_name = f"{base}_{doc_idx}{ext}"
                        dest = os.path.join(self.remote_dir, dest_name)
                        with open(dest, "w", encoding="utf-8") as f:
                            yaml.safe_dump(doc, f, sort_keys=False, allow_unicode=False)
                        imported += 1
            except Exception:
                continue
        return imported

    def correlate_events(self, events: List[Dict], max_events: int = None, max_matches: int = None):
        if not isinstance(events, list) or not self.rules:
            return []
        event_limit = None
        if isinstance(max_events, int) and max_events > 0:
            event_limit = max_events
        match_limit = None
        if isinstance(max_matches, int) and max_matches > 0:
            match_limit = max_matches

        matches = []
        for idx, evt in enumerate(events):
            if event_limit is not None and idx >= event_limit:
                break
            if not isinstance(evt, dict):
                continue
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
                        if match_limit is not None and len(matches) >= match_limit:
                            return matches
                except Exception:
                    continue
        return matches
