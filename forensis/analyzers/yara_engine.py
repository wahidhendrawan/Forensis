import os
from collections import Counter
from typing import Dict, List

try:
    import yara
except ImportError:
    yara = None  # type: ignore


class YaraEngine:
    def __init__(self, rules_dir: str, max_scan_bytes: int = 5 * 1024 * 1024):
        self.rules_dir = rules_dir
        self.max_scan_bytes = max_scan_bytes
        self.available = yara is not None
        self._compiled = []
        self.load_errors: List[Dict] = []
        self.reload_rules()

    def reload_rules(self):
        self._compiled = []
        self.load_errors = []
        if not self.available:
            return
        if not os.path.isdir(self.rules_dir):
            return

        for root, _, files in os.walk(self.rules_dir):
            for name in files:
                if not name.lower().endswith((".yar", ".yara")):
                    continue
                path = os.path.join(root, name)
                try:
                    compiled = yara.compile(filepath=path)
                    self._compiled.append((path, compiled))
                except Exception as exc:
                    self.load_errors.append({"path": path, "error": str(exc)})

    def _extract_string_samples(self, match, sample_limit: int = 4):
        samples = []
        strings_attr = getattr(match, "strings", []) or []
        for sm in strings_attr:
            if len(samples) >= sample_limit:
                break

            # yara >=4.0: StringMatch with .identifier and .instances.
            ident = getattr(sm, "identifier", None)
            instances = getattr(sm, "instances", None)
            if ident is not None and instances is not None:
                for inst in list(instances)[:2]:
                    matched_data = getattr(inst, "matched_data", b"")
                    if isinstance(matched_data, str):
                        text = matched_data
                    else:
                        text = bytes(matched_data).decode("utf-8", errors="ignore")
                    text = text.strip()
                    if not text:
                        continue
                    samples.append({"identifier": str(ident), "sample": text[:200]})
                    if len(samples) >= sample_limit:
                        break
                continue

            # yara <=3.9: tuple (offset, identifier, data)
            if isinstance(sm, tuple) and len(sm) == 3:
                _, old_ident, raw_data = sm
                if isinstance(raw_data, str):
                    text = raw_data
                else:
                    text = bytes(raw_data).decode("utf-8", errors="ignore")
                text = text.strip()
                if text:
                    samples.append({"identifier": str(old_ident), "sample": text[:200]})
        return samples

    def scan_text(self, text: str, source: str = "generic", max_hits: int = 100):
        if not self.available or not text:
            return []
        if not self._compiled:
            return []

        data = text.encode("utf-8", errors="ignore")[: self.max_scan_bytes]
        if not data:
            return []

        hits = []
        for path, compiled in self._compiled:
            try:
                matches = compiled.match(data=data, timeout=5)
            except Exception:
                continue
            for match in matches:
                hit = {
                    "source": source,
                    "rule": getattr(match, "rule", "unknown"),
                    "namespace": getattr(match, "namespace", None),
                    "tags": list(getattr(match, "tags", []) or []),
                    "meta": dict(getattr(match, "meta", {}) or {}),
                    "strings": self._extract_string_samples(match),
                    "rule_file": os.path.relpath(path, self.rules_dir),
                }
                hits.append(hit)
                if len(hits) >= max_hits:
                    return hits
        return hits

    def match_summary(self, hits: List[Dict]):
        rule_counter = Counter()
        for hit in hits:
            rule_counter[hit.get("rule", "unknown")] += 1
        return {
            "total_hits": len(hits),
            "top_rules": rule_counter.most_common(10),
            "engine_available": self.available,
            "loaded_rule_files": len(self._compiled),
            "load_error_count": len(self.load_errors),
        }
