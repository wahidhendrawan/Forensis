import os
import io
import json
import logging
import socket
import re
import fnmatch
import tarfile
import tempfile
import shutil
from typing import List, Dict
from urllib.parse import urljoin, urlparse
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

try:  # optional Rust engine (forensis_core/); the Python matcher below stays the reference
    from forensis_core import correlate_sigma as _native_correlate, __version__ as _native_version
except ImportError:
    _native_correlate = None

logger = logging.getLogger(__name__)

MAX_REMOTE_URLS = 20
MAX_REDIRECTS = 5
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
        # is_global also rules out loopback, link-local (cloud metadata), CGNAT and reserved ranges.
        return not ipaddress.ip_address(ip_str).is_global
    except ValueError:
        return True  # unparseable address: fail closed


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


def _safe_get(url: str, timeout: int, max_bytes: int):
    """GET the body of url, re-checking _is_safe_url on every redirect hop; None if unsafe, not 200 or over max_bytes."""
    for _ in range(MAX_REDIRECTS + 1):
        if not _is_safe_url(url):
            return None
        resp = requests.get(url, timeout=timeout, allow_redirects=False, stream=True)
        try:
            if resp.status_code in (301, 302, 303, 307, 308):
                url = urljoin(url, resp.headers.get("Location", ""))
                continue
            if resp.status_code != 200:
                return None
            body = resp.raw.read(max_bytes + 1, decode_content=True)
            return body if len(body) <= max_bytes else None
        finally:
            resp.close()
    return None


NATIVE_MODES = {"contains", "eq", "startswith", "endswith", "glob"}


def _flatten(event: Dict) -> Dict[str, str]:
    """Event fields as strings, one level of nesting unpacked, with lower-cased keys added."""
    fields: Dict[str, str] = {}
    for k, v in event.items():
        if isinstance(v, dict):
            for kk, vv in v.items():
                fields[str(kk)] = str(vv)
                fields[str(kk).lower()] = str(vv)
        else:
            fields[str(k)] = str(v)
            fields[str(k).lower()] = str(v)
    return fields


def _compile_value(mod: str, expected):
    """(mode, exp) for one expected value; exp is lower-cased except for regex and numeric modes."""
    exp = str(expected).strip()
    exp_lower = exp.lower()
    if mod in {"eq", "exact"}:
        return ("eq", exp_lower)
    if mod in {"startswith", "endswith"}:
        return (mod, exp_lower)
    if mod in {"regex", "re"}:
        return ("regex", exp)
    if mod in {"gt", "gte", "lt", "lte"}:
        return (mod, exp)
    if "*" in exp_lower or "?" in exp_lower:
        return ("glob", exp_lower)
    return ("contains", exp_lower)


def _match_value(actual: str, mode: str, exp: str) -> bool:
    sval = str(actual).strip()
    if not sval or not exp:
        return False
    sval_lower = sval.lower()
    if mode == "eq":
        return sval_lower == exp
    if mode == "startswith":
        return sval_lower.startswith(exp)
    if mode == "endswith":
        return sval_lower.endswith(exp)
    if mode == "regex":
        try:
            return re.search(exp, sval, flags=re.I) is not None
        except re.error:
            return False
    if mode in {"gt", "gte", "lt", "lte"}:
        try:
            left = float(sval)
            right = float(exp)
        except ValueError:
            return False
        if mode == "gt":
            return left > right
        if mode == "gte":
            return left >= right
        if mode == "lt":
            return left < right
        return left <= right
    if mode == "glob":
        return fnmatch.fnmatch(sval_lower, exp)
    return exp in sval_lower


def _compile_condition(expression: str, names: Dict[str, int]):
    """The condition grammar of the reference as a tree: ("sel", i) | ("any", [...]) | ("all", [...]) | ("false",)."""
    cond = (expression or "").strip()
    if not cond:
        return ("false",)
    cond_l = cond.lower()
    if cond in names:
        return ("sel", names[cond])
    if cond_l == "selection" and "selection" in names:
        return ("sel", names["selection"])
    if cond_l == "1 of them":
        return ("any", [("sel", i) for i in names.values()])
    if cond_l == "all of them":
        return ("all", [("sel", i) for i in names.values()])
    if cond_l.startswith("1 of "):
        pattern = cond[5:].strip()
        return ("any", [("sel", i) for name, i in names.items() if fnmatch.fnmatch(name, pattern)])
    if cond_l.startswith("all of "):
        pattern = cond[7:].strip()
        named = [("sel", i) for name, i in names.items() if fnmatch.fnmatch(name, pattern)]
        return ("all", named) if named else ("false",)
    if re.search(r"\s+and\s+", cond, flags=re.I):
        return ("all", [_compile_condition(part, names) for part in re.split(r"\s+and\s+", cond, flags=re.I)])
    if re.search(r"\s+or\s+", cond, flags=re.I):
        return ("any", [_compile_condition(part, names) for part in re.split(r"\s+or\s+", cond, flags=re.I)])
    return ("false",)


class _CompiledRule:
    """A rule's detection block parsed once; `match` is the reference matcher, `native` says whether
    every value can be matched by forensis_core (no regex, numeric or bracket-glob values)."""

    __slots__ = ("selections", "condition", "native")

    def __init__(self, detection):
        detection = detection if isinstance(detection, dict) else {}
        self.selections = []  # [[(field, field_lower, [(mode, exp), ...]), ...], ...]
        names: Dict[str, int] = {}
        for name, sel in detection.items():
            if not isinstance(sel, dict):
                continue
            items = []
            for field_expr, expected in sel.items():
                parts = str(field_expr).split("|", 1)
                field = parts[0].strip()
                modifier = parts[1].strip() if len(parts) > 1 else "contains"
                mod = (modifier or "contains").lower()
                values = expected if isinstance(expected, list) else [expected]
                items.append((field, field.lower(), [_compile_value(mod, e) for e in values]))
            names[str(name)] = len(self.selections)
            self.selections.append(items)
        self.condition = _compile_condition(str(detection.get("condition", "selection")), names) if names else ("false",)
        self.native = all(
            mode in NATIVE_MODES and not (mode == "glob" and "[" in exp)
            for items in self.selections
            for _, _, values in items
            for mode, exp in values
        )

    def _match_selection(self, fields: Dict[str, str], items) -> bool:
        for field, field_lower, values in items:
            if not field:
                return False
            value = fields.get(field) or fields.get(field_lower)
            if value is None:
                return False
            if not any(_match_value(value, mode, exp) for mode, exp in values):
                return False
        return True

    def _eval(self, fields: Dict[str, str], node) -> bool:
        kind = node[0]
        if kind == "sel":
            return self._match_selection(fields, self.selections[node[1]])
        if kind == "any":
            return any(self._eval(fields, child) for child in node[1])
        if kind == "all":
            return all(self._eval(fields, child) for child in node[1])
        return False

    def match(self, fields: Dict[str, str]) -> bool:
        return self._eval(fields, self.condition)

    def as_native(self):
        return (self.selections, self.condition)


class SigmaRule:
    def __init__(self, raw: Dict):
        self.raw = raw
        self.id = raw.get("id")
        self.title = raw.get("title")
        self.description = raw.get("description")
        self.level = raw.get("level")
        self.logsource = raw.get("logsource", {})
        self.detection = raw.get("detection", {})
        self.compiled = _CompiledRule(self.detection)

    def match_event(self, event: Dict) -> bool:
        return self.compiled.match(_flatten(event))


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
        try:
            return _safe_get(self._sigmahq_archive_url(), SIGMAHQ_BASELINE_TIMEOUT, SIGMAHQ_BASELINE_MAX_ARCHIVE_BYTES)
        except Exception:
            return None

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
            try:
                body = _safe_get(url, 10, MAX_REMOTE_RULE_BYTES)
                if body is None:
                    continue

                content = body.decode("utf-8", errors="replace")
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
        event_limit = max_events if isinstance(max_events, int) and max_events > 0 else len(events)
        match_limit = max_matches if isinstance(max_matches, int) and max_matches > 0 else None

        flat = [_flatten(evt) if isinstance(evt, dict) else None for evt in events[:event_limit]]
        pairs = self._match_pairs(flat, match_limit)
        return [
            {
                "event_index": idx,
                "rule_id": self.rules[ri].id,
                "rule_title": self.rules[ri].title,
                "rule_level": self.rules[ri].level,
                "description": self.rules[ri].description,
                "event": events[idx],
            }
            for idx, ri in pairs
        ]

    def _match_pairs(self, flat, match_limit):
        """(event_index, rule_index) in event-then-rule order, at most match_limit of them."""
        if _native_correlate is None:
            logger.info("Sigma engine: python")
            rules = list(enumerate(self.rules))
            return self._match_pairs_python(flat, rules, match_limit)
        logger.info("Sigma engine: rust (forensis_core %s)", _native_version)
        native = [(ri, rule.compiled.as_native()) for ri, rule in enumerate(self.rules) if rule.compiled.native]
        pairs = [(idx, native[pos][0]) for idx, pos in _native_correlate(flat, [c for _, c in native], match_limit)]
        python_rules = [(ri, rule) for ri, rule in enumerate(self.rules) if not rule.compiled.native]
        if python_rules:
            # Events past the match_limit-th native pair cannot contribute: their pairs would sort after it.
            last_idx = pairs[-1][0] if match_limit is not None and len(pairs) >= match_limit else len(flat) - 1
            pairs += self._match_pairs_python(flat[: last_idx + 1], python_rules, match_limit)
            pairs.sort()
        return pairs[:match_limit] if match_limit is not None else pairs

    @staticmethod
    def _match_pairs_python(flat, rules, match_limit):
        pairs = []
        for idx, fields in enumerate(flat):
            if fields is None:
                continue
            for ri, rule in rules:
                try:
                    if rule.compiled.match(fields):
                        pairs.append((idx, ri))
                        if match_limit is not None and len(pairs) >= match_limit:
                            return pairs
                except Exception:
                    continue
        return pairs
