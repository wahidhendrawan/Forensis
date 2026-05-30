import csv
import io
import json
import re
import xml.etree.ElementTree as ET
from collections import Counter
from typing import Dict, List, Tuple

import yaml

PLAYBOOKS = {
    "memory": {
        "windows.generic": {
            "tool": "volatility3",
            "steps": [
                {"focus": "processes", "commands": ["vol -f MEM.raw windows.pslist", "vol -f MEM.raw windows.pstree", "vol -f MEM.raw windows.psscan"]},
                {"focus": "network", "commands": ["vol -f MEM.raw windows.netscan"]},
                {"focus": "malware", "commands": ["vol -f MEM.raw windows.malfind", "vol -f MEM.raw windows.ldrmodules", "vol -f MEM.raw windows.dlllist"]},
                {"focus": "credentials", "commands": ["vol -f MEM.raw windows.hashdump", "vol -f MEM.raw windows.lsadump"]},
                {"focus": "registry", "commands": ["vol -f MEM.raw windows.registry.hivelist", "vol -f MEM.raw windows.registry.printkey"]},
            ],
        },
        "windows.enterprise.ir": {
            "tool": "volatility3",
            "steps": [
                {"focus": "timeline", "commands": ["vol -f MEM.raw windows.timeliner"]},
                {"focus": "process_hunting", "commands": ["vol -f MEM.raw windows.cmdline", "vol -f MEM.raw windows.envars", "vol -f MEM.raw windows.handles"]},
                {"focus": "lateral_movement", "commands": ["vol -f MEM.raw windows.sessions", "vol -f MEM.raw windows.netscan"]},
                {"focus": "credential_access", "commands": ["vol -f MEM.raw windows.lsadump", "vol -f MEM.raw windows.cachedump"]},
            ],
        },
        "linux.generic": {
            "tool": "volatility3",
            "steps": [
                {"focus": "processes", "commands": ["vol -f MEM.raw linux.pslist", "vol -f MEM.raw linux.pstree"]},
                {"focus": "network", "commands": ["vol -f MEM.raw linux.netstat", "vol -f MEM.raw linux.sockstat"]},
                {"focus": "kernel", "commands": ["vol -f MEM.raw linux.check_syscall", "vol -f MEM.raw linux.lsmod"]},
                {"focus": "persistence", "commands": ["vol -f MEM.raw linux.bash", "vol -f MEM.raw linux.check_creds"]},
            ],
        },
        "macos.quicktriage": {
            "tool": "volatility3",
            "steps": [
                {"focus": "processes", "commands": ["vol -f MEM.raw mac.pslist", "vol -f MEM.raw mac.pstree"]},
                {"focus": "network", "commands": ["vol -f MEM.raw mac.netstat"]},
                {"focus": "kernel_extensions", "commands": ["vol -f MEM.raw mac.lsmod"]},
            ],
        },
    },
    "network": {
        "intrusion_detection": {
            "tool": "tshark/zeek",
            "steps": [
                {"focus": "beaconing", "commands": ["tshark -r capture.pcap -q -z conv,ip", "zeek -r capture.pcap"]},
                {"focus": "exfiltration", "commands": ["tshark -r capture.pcap -Y 'http.request.method == POST' -T fields -e http.host -e http.content_length"]},
                {"focus": "scanning", "commands": ["tcpdump -nn -r capture.pcap 'tcp[tcpflags] & (tcp-syn|tcp-ack) == tcp-syn'"]},
            ],
        }
    },
    "logs": {
        "web_attack": {
            "tool": "grep/awk",
            "steps": [
                {"focus": "sqli", "commands": ["grep -Ei 'union|select|information_schema' access.log"]},
                {"focus": "bruteforce", "commands": ["awk '{print $9}' access.log | sort | uniq -c | sort -nr | head -n 20"]},
                {"focus": "webshell", "commands": ["grep -Ei 'eval\\(|base64_decode|system\\(' access.log"]},
            ],
        }
    },
}

SUSPICIOUS_PATTERNS = [
    {"label": "mimikatz", "category": "credential_access", "severity": "critical", "regex": re.compile(r"mimikatz|sekurlsa::|lsadump::", re.I)},
    {"label": "pypykatz", "category": "credential_access", "severity": "high", "regex": re.compile(r"pypykatz", re.I)},
    {"label": "lsass dump", "category": "credential_access", "severity": "critical", "regex": re.compile(r"lsass(\.exe)?|procdump|comsvcs\.dll", re.I)},
    {"label": "injected memory", "category": "execution", "severity": "high", "regex": re.compile(r"malfind|rwx|page_execute_readwrite|injected", re.I)},
    {"label": "cobalt strike beacon", "category": "command_and_control", "severity": "critical", "regex": re.compile(r"beacon|cobalt|meterpreter", re.I)},
    {"label": "encoded powershell", "category": "defense_evasion", "severity": "high", "regex": re.compile(r"powershell.*(-enc|frombase64string|iex)", re.I)},
    {"label": "living off the land", "category": "execution", "severity": "medium", "regex": re.compile(r"rundll32|regsvr32|mshta|certutil", re.I)},
    {"label": "suspicious network tunnel", "category": "command_and_control", "severity": "high", "regex": re.compile(r"4444|1337|9001|reverse shell|socks", re.I)},
    {"label": "credential material", "category": "credential_access", "severity": "high", "regex": re.compile(r"ntlm|krbtgt|ticket|hashdump|sam", re.I)},
]

RECOMMENDATIONS = {
    "credential_access": "Validate credential exposure scope and rotate impacted credentials immediately.",
    "execution": "Pivot to process tree lineage, command line, and loaded module correlation.",
    "command_and_control": "Correlate suspected C2 endpoints with DNS/PCAP and isolate affected hosts.",
    "defense_evasion": "Review encoded script execution and persistence mechanisms for follow-up containment.",
}


def get_playbook(category: str, profile: str):
    cat_data = PLAYBOOKS.get(category, {})
    profile_data = cat_data.get(profile, list(cat_data.values())[0] if cat_data else {})
    if not profile_data:
        return None

    steps = profile_data.get("steps", [])
    events = []
    for step in steps:
        events.append(
            {
                "source": f"{category}_playbook",
                "category": step["focus"],
                "tool": profile_data.get("tool"),
                "profile": profile,
                "message": f"Recommended analysis for {step['focus']} using {profile_data.get('tool')}",
            }
        )

    return {
        "profile": profile,
        "tool": profile_data.get("tool"),
        "steps": steps,
        "events": events,
    }


def _parse_json_blob(raw_output: str) -> List[Dict]:
    try:
        data = json.loads(raw_output)
    except json.JSONDecodeError:
        return []
    return _rows_from_object(data)


def _normalize_row(row: Dict) -> Dict:
    clean = {}
    for key, value in row.items():
        if key is None:
            continue
        clean_key = str(key).strip().lower().replace(" ", "_")
        if not clean_key:
            continue
        if isinstance(value, (dict, list)):
            clean_value = json.dumps(value, default=str)
        elif value is None:
            clean_value = ""
        else:
            clean_value = str(value).strip()
        clean[clean_key] = clean_value
    return clean


def _rows_from_object(obj) -> List[Dict]:
    if isinstance(obj, dict):
        for key in ("records", "rows", "events", "processes", "items", "data"):
            value = obj.get(key)
            if isinstance(value, list):
                rows = [_normalize_row(item) for item in value if isinstance(item, dict)]
                if rows:
                    return rows
        return [_normalize_row(obj)]
    if isinstance(obj, list):
        rows = [_normalize_row(item) for item in obj if isinstance(item, dict)]
        if rows:
            return rows
    return []


def _parse_json_lines(raw_output: str) -> List[Dict]:
    rows = []
    for line in raw_output.splitlines():
        line = line.strip()
        if not line or not line.startswith("{"):
            continue
        try:
            row = json.loads(line)
            if isinstance(row, dict):
                rows.append(_normalize_row(row))
        except json.JSONDecodeError:
            continue
    return rows


def _parse_yaml_blob(raw_output: str) -> List[Dict]:
    try:
        data = yaml.safe_load(raw_output)
    except Exception:
        return []
    return _rows_from_object(data)


def _parse_xml_blob(raw_output: str) -> List[Dict]:
    try:
        root = ET.fromstring(raw_output)
    except ET.ParseError:
        return []

    rows = []
    candidate_nodes = [child for child in list(root) if list(child)]
    if not candidate_nodes:
        candidate_nodes = [root]

    for node in candidate_nodes:
        row = {}
        for attr_key, attr_val in node.attrib.items():
            row[attr_key] = attr_val

        children = list(node)
        if children:
            for child in children:
                child_key = child.tag
                child_val = (child.text or "").strip()
                if not child_val and child.attrib:
                    child_val = json.dumps(child.attrib, default=str)
                if child_key in row and child_val:
                    if row[child_key]:
                        row[child_key] = f"{row[child_key]}; {child_val}"
                    else:
                        row[child_key] = child_val
                elif child_val:
                    row[child_key] = child_val
        else:
            text = (node.text or "").strip()
            if text:
                row["text"] = text

        norm = _normalize_row(row)
        if norm:
            rows.append(norm)
    return rows


def _parse_delimited(raw_output: str, delimiter: str) -> List[Dict]:
    sample = raw_output[:4096]
    if delimiter not in sample:
        return []
    try:
        buf = io.StringIO(raw_output)
        reader = csv.DictReader(buf, delimiter=delimiter)
        rows = []
        for row in reader:
            clean = _normalize_row(row)
            if any(clean.values()):
                rows.append(clean)
        return rows
    except Exception:
        return []


def _parse_key_value_lines(raw_output: str) -> List[Dict]:
    rows = []
    kv_pattern = re.compile(r"([A-Za-z][\w.\-/]*)\s*[:=]\s*(\"[^\"]*\"|'[^']*'|[^\s|;,]+)")
    for line in raw_output.splitlines():
        text = line.strip()
        if not text or text.startswith(("#", ";", "//")):
            continue
        pairs = kv_pattern.findall(text)
        if len(pairs) < 2:
            continue
        row = {key: value.strip().strip("\"'") for key, value in pairs}
        norm = _normalize_row(row)
        if any(norm.values()):
            rows.append(norm)
    return rows


def _parse_table_output(raw_output: str) -> List[Dict]:
    lines = [line.rstrip() for line in raw_output.splitlines() if line.strip()]
    if len(lines) < 3:
        return []

    header_index = None
    for i, line in enumerate(lines[:10]):
        if re.search(r"\s{2,}", line) and len(line.split()) >= 3:
            header_index = i
            break
    if header_index is None:
        return []

    headers = [h.strip().lower().replace(" ", "_") for h in re.split(r"\s{2,}", lines[header_index].strip()) if h.strip()]
    rows = []
    for line in lines[header_index + 1 :]:
        if re.match(r"^-{3,}\s*$", line):
            continue
        values = [v.strip() for v in re.split(r"\s{2,}", line.strip())]
        if len(values) < 2:
            continue
        row = {}
        for idx, header in enumerate(headers):
            row[header] = values[idx] if idx < len(values) else ""
        rows.append(_normalize_row(row))
    return rows


def _extract_structured_records(raw_output: str) -> Tuple[str, List[Dict]]:
    json_rows = _parse_json_blob(raw_output)
    if json_rows:
        return "json", json_rows

    parsers = [
        ("ndjson", _parse_json_lines(raw_output)),
        ("yaml", _parse_yaml_blob(raw_output)),
        ("xml", _parse_xml_blob(raw_output)),
        ("csv", _parse_delimited(raw_output, ",")),
        ("tsv", _parse_delimited(raw_output, "\t")),
        ("key_value", _parse_key_value_lines(raw_output)),
        ("table", _parse_table_output(raw_output)),
    ]
    for fmt, rows in parsers:
        if rows:
            return fmt, rows
    return "raw_text", []


def _flatten_record(record: Dict) -> str:
    items = [f"{k}={v}" for k, v in record.items()]
    return " | ".join(items)


def analyze_generic_output(raw_output: str, input_name: str = None) -> Dict:
    lines = [line for line in raw_output.splitlines() if line.strip()]
    detected_format, records = _extract_structured_records(raw_output)

    suspicious = []
    events = []
    severity_counts = Counter()
    categories = Counter()

    searchable_items = []
    if records:
        searchable_items = [_flatten_record(record) for record in records]
    else:
        searchable_items = lines

    for item in searchable_items:
        matched = False
        for pattern in SUSPICIOUS_PATTERNS:
            if pattern["regex"].search(item):
                matched = True
                severity = pattern["severity"]
                category = pattern["category"]
                severity_counts[severity] += 1
                categories[category] += 1
                suspicious.append(
                    {
                        "keyword": pattern["label"],
                        "line": item[:1500],
                        "category": category,
                        "severity": severity,
                        "source_format": detected_format,
                    }
                )
                events.append(
                    {
                        "source": "memory_triage",
                        "indicator": pattern["label"],
                        "category": category,
                        "severity": severity,
                        "message": item[:1500],
                    }
                )
        if not matched and detected_format == "table":
            lower = item.lower()
            if "svch0st" in lower or "0x0" in lower:
                severity_counts["medium"] += 1
                categories["execution"] += 1
                suspicious.append(
                    {
                        "keyword": "anomalous process artifact",
                        "line": item[:1500],
                        "category": "execution",
                        "severity": "medium",
                        "source_format": detected_format,
                    }
                )
                events.append(
                    {
                        "source": "memory_triage",
                        "indicator": "anomalous process artifact",
                        "category": "execution",
                        "severity": "medium",
                        "message": item[:1500],
                    }
                )

    recommendations = []
    for category, _ in categories.most_common(3):
        rec = RECOMMENDATIONS.get(category)
        if rec:
            recommendations.append(rec)

    summary = {
        "total_lines": len(lines),
        "parsed_records": len(records),
        "suspicious_hits": len(suspicious),
        "detected_format": detected_format,
        "input_name": input_name,
        "severity_counts": dict(severity_counts),
        "category_counts": dict(categories),
        "recommendations": recommendations,
    }

    return {
        "summary": summary,
        "suspicious": suspicious,
        "events": events,
        "detected_format": detected_format,
    }
