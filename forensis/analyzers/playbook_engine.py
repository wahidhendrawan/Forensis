import csv
import io
import json
import re
import defusedxml.ElementTree as ET
from collections import Counter
from typing import Dict, List, Tuple

import yaml

PLAYBOOKS = {
    "memory": {
        "windows.generic": {
            "tool": "volatility3",
            "steps": [
                {"focus": "image_validation", "commands": [{"cmd": "vol -f MEM.raw windows.info", "desc": "Detect OS build and kernel metadata for parser alignment."}, {"cmd": "vol -f MEM.raw windows.kdbgscan", "desc": "Identify valid kernel debugger structures and DTB candidates."}]},
                {"focus": "process_hunting", "commands": [{"cmd": "vol -f MEM.raw windows.pslist", "desc": "List active processes and parent-child relationships."}, {"cmd": "vol -f MEM.raw windows.pstree", "desc": "Visualize process lineage for suspicious spawn chains."}, {"cmd": "vol -f MEM.raw windows.psscan", "desc": "Recover hidden or terminated process artifacts."}, {"cmd": "vol -f MEM.raw windows.cmdline", "desc": "Extract command-line arguments used by suspicious processes."}]},
                {"focus": "code_injection", "commands": [{"cmd": "vol -f MEM.raw windows.malfind", "desc": "Find suspicious executable memory regions and injected code."}, {"cmd": "vol -f MEM.raw windows.ldrmodules", "desc": "Spot unlinked/hidden module anomalies in process memory."}, {"cmd": "vol -f MEM.raw windows.dlllist", "desc": "Review DLL load chain for unsigned or odd modules."}]},
                {"focus": "credential_access", "commands": [{"cmd": "vol -f MEM.raw windows.hashdump", "desc": "Dump SAM hashes if hives are recoverable."}, {"cmd": "vol -f MEM.raw windows.lsadump", "desc": "Extract LSA secrets that may expose credentials."}, {"cmd": "vol -f MEM.raw windows.cachedump", "desc": "Collect cached domain credential material."}]},
                {"focus": "network_and_lateral", "commands": [{"cmd": "vol -f MEM.raw windows.netscan", "desc": "Map active/closed connections and unusual remote endpoints."}, {"cmd": "vol -f MEM.raw windows.sessions", "desc": "Inspect user sessions for RDP/interactive compromise paths."}]},
                {"focus": "persistence_registry", "commands": [{"cmd": "vol -f MEM.raw windows.registry.hivelist", "desc": "Locate mounted and residual registry hives."}, {"cmd": "vol -f MEM.raw windows.registry.printkey --key \"Software\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Run\"", "desc": "Check autorun keys for persistence artifacts."}, {"cmd": "vol -f MEM.raw windows.svcscan", "desc": "Inspect suspicious services and binary path anomalies."}]},
            ],
        },
        "windows.enterprise.ir": {
            "tool": "volatility3",
            "steps": [
                {"focus": "timeline", "commands": [{"cmd": "vol -f MEM.raw windows.timeliner", "desc": "Create timeline of memory artifacts for incident chronology."}, {"cmd": "vol -f MEM.raw windows.filescan", "desc": "Identify file objects linked to attacker execution paths."}]},
                {"focus": "deep_process", "commands": [{"cmd": "vol -f MEM.raw windows.handles", "desc": "Inspect sensitive handle access such as LSASS or tokens."}, {"cmd": "vol -f MEM.raw windows.envars", "desc": "Review environment variables for LOLBIN abuse context."}, {"cmd": "vol -f MEM.raw windows.getsids", "desc": "Correlate process SID context with privilege abuse."}]},
                {"focus": "credential_and_token", "commands": [{"cmd": "vol -f MEM.raw windows.privs", "desc": "Inspect process privilege grants for escalation indicators."}, {"cmd": "vol -f MEM.raw windows.tokens", "desc": "Validate token impersonation or token theft activity."}, {"cmd": "vol -f MEM.raw windows.lsadump", "desc": "Validate possible credential dumping scope."}]},
                {"focus": "modules_and_drivers", "commands": [{"cmd": "vol -f MEM.raw windows.driverscan", "desc": "Hunt suspicious/unlinked kernel driver objects."}, {"cmd": "vol -f MEM.raw windows.modules", "desc": "Correlate loaded kernel modules with expected baseline."}]},
            ],
        },
        "linux.generic": {
            "tool": "volatility3",
            "steps": [
                {"focus": "processes", "commands": [{"cmd": "vol -f MEM.raw linux.pslist", "desc": "Enumerate running tasks and quick outliers."}, {"cmd": "vol -f MEM.raw linux.pstree", "desc": "Track process lineage and daemon abuse."}, {"cmd": "vol -f MEM.raw linux.lsof", "desc": "Map process-file interaction for dropped payloads."}]},
                {"focus": "network", "commands": [{"cmd": "vol -f MEM.raw linux.netstat", "desc": "Review sockets and attacker C2 endpoints."}, {"cmd": "vol -f MEM.raw linux.sockstat", "desc": "Correlate sockets to process ownership."}]},
                {"focus": "kernel_integrity", "commands": [{"cmd": "vol -f MEM.raw linux.lsmod", "desc": "List loaded modules and suspicious kernel implants."}, {"cmd": "vol -f MEM.raw linux.check_syscall", "desc": "Check syscall table tampering indicators."}, {"cmd": "vol -f MEM.raw linux.check_modules", "desc": "Detect module list inconsistencies."}]},
                {"focus": "persistence", "commands": [{"cmd": "vol -f MEM.raw linux.bash", "desc": "Recover shell history and attacker commands."}, {"cmd": "vol -f MEM.raw linux.check_creds", "desc": "Identify credential and privilege anomalies."}]},
            ],
        },
        "macos.quicktriage": {
            "tool": "volatility3",
            "steps": [
                {"focus": "processes", "commands": [{"cmd": "vol -f MEM.raw mac.pslist", "desc": "Collect active process inventory for triage baseline."}, {"cmd": "vol -f MEM.raw mac.pstree", "desc": "Trace process ancestry for suspicious execution."}]},
                {"focus": "network", "commands": [{"cmd": "vol -f MEM.raw mac.netstat", "desc": "Review open network sessions and unknown peers."}, {"cmd": "vol -f MEM.raw mac.ifconfig", "desc": "Inspect network interface states and rogue adapters."}]},
                {"focus": "kernel_extensions", "commands": [{"cmd": "vol -f MEM.raw mac.lsmod", "desc": "Audit loaded kernel extensions for non-standard modules."}]},
            ],
        },
    },
    "network": {
        "network.analysis.baseline": {
            "tool": "tshark/zeek/suricata",
            "steps": [
                {"focus": "flow_baseline", "commands": [{"cmd": "tshark -r capture.pcap -q -z conv,ip", "desc": "Build conversation baseline by source/destination pair."}, {"cmd": "tshark -r capture.pcap -q -z io,phs", "desc": "Review protocol hierarchy and unusual protocol spikes."}]},
                {"focus": "dns_and_c2", "commands": [{"cmd": "tshark -r capture.pcap -Y \"dns\" -T fields -e frame.time -e ip.src -e dns.qry.name", "desc": "Extract DNS query timeline for beaconing or DGAs."}, {"cmd": "zeek -r capture.pcap", "desc": "Generate Zeek conn/dns/http logs for enrichment."}]},
                {"focus": "lateral_movement", "commands": [{"cmd": "tshark -r capture.pcap -Y \"tcp.flags.syn==1 && tcp.flags.ack==0\" -T fields -e ip.src -e ip.dst -e tcp.dstport", "desc": "Hunt scanning/SYN bursts across internal ranges."}, {"cmd": "tshark -r capture.pcap -Y \"rdp || smb || winrm\" -T fields -e frame.time -e ip.src -e ip.dst", "desc": "Review lateral protocols (RDP/SMB/WinRM)."}]},
                {"focus": "payload_exfiltration", "commands": [{"cmd": "tshark -r capture.pcap -Y \"http.request.method == POST\" -T fields -e frame.time -e ip.src -e http.host -e http.content_length", "desc": "Spot large outbound HTTP POST requests."}, {"cmd": "suricata -r capture.pcap -S custom.rules", "desc": "Replay traffic through IDS rules for known signatures."}]},
            ],
        },
        "network.c2_hunting": {
            "tool": "zeek/tshark",
            "steps": [
                {"focus": "periodic_beaconing", "commands": [{"cmd": "zeek-cut id.orig_h id.resp_h resp_p duration < conn.log | sort | uniq -c | sort -nr | head", "desc": "Find repetitive endpoint pairs with uniform cadence."}]},
                {"focus": "encrypted_tunnels", "commands": [{"cmd": "tshark -r capture.pcap -Y \"tls.handshake\" -T fields -e frame.time -e ip.src -e ip.dst -e tls.handshake.extensions_server_name", "desc": "Extract TLS SNI metadata for suspicious destinations."}, {"cmd": "tshark -r capture.pcap -Y \"quic\" -T fields -e frame.time -e ip.src -e ip.dst", "desc": "Review QUIC traffic often used for covert C2."}]},
                {"focus": "ioc_validation", "commands": [{"cmd": "zeek-cut id.resp_h < conn.log | sort -u > dst_ips.txt", "desc": "Build destination IOC candidate list for TI matching."}, {"cmd": "cat dst_ips.txt | xargs -I{} sh -c 'echo {}'", "desc": "Prepare outbound destination list for enrichment pipeline."}]},
            ],
        },
        "network.analysis.deep_inspection": {
            "tool": "tshark/zeek/suricata",
            "steps": [
                {"focus": "signature_validation", "commands": [{"cmd": "suricata -r capture.pcap -S custom.rules -l ./suricata_out", "desc": "Run IDS signature replay for known malicious traffic patterns."}, {"cmd": "jq '.alert.signature,.src_ip,.dest_ip' suricata_out/eve.json 2>/dev/null | paste - - - | head -50", "desc": "Quick triage of top IDS alerts by source and destination."}]},
                {"focus": "http_and_tls_artifacts", "commands": [{"cmd": "zeek -r capture.pcap protocols/http protocols/ssl", "desc": "Extract HTTP and TLS metadata for suspicious host/domain pivoting."}, {"cmd": "tshark -r capture.pcap -Y \"http.request || tls.handshake\" -T fields -e frame.time -e ip.src -e ip.dst -e http.host -e tls.handshake.extensions_server_name", "desc": "Build timeline of cleartext hostnames and SNI indicators."}]},
                {"focus": "lateral_and_discovery", "commands": [{"cmd": "tshark -r capture.pcap -Y \"smb || dcerpc || kerberos\" -T fields -e frame.time -e ip.src -e ip.dst -e tcp.dstport", "desc": "Detect east-west authentication and remote service activity."}, {"cmd": "tshark -r capture.pcap -Y \"icmp || arp\" -T fields -e frame.time -e eth.src -e eth.dst", "desc": "Review discovery traffic bursts linked to reconnaissance."}]},
                {"focus": "compatibility_profile", "commands": [{"cmd": "tshark -r capture.pcap -q -z conv,ip", "desc": "Quick conversation overview for compatibility and fast baseline checks."}]}
            ],
        },
    },
    "logs": {
        "web_attack": {
            "tool": "grep/awk/jq",
            "steps": [
                {"focus": "sqli_and_rce", "commands": [{"cmd": "grep -Ei \"union|select|information_schema|sleep\\(|benchmark\\(\" access.log", "desc": "Detect SQLi and timing-based SQL payloads."}, {"cmd": "grep -Ei \"\\$\\{jndi:|cmd=|/bin/sh|powershell\" access.log", "desc": "Detect RCE payload and log4shell artifacts."}]},
                {"focus": "authentication_abuse", "commands": [{"cmd": "awk '$9 ~ /401|403/ {print $1}' access.log | sort | uniq -c | sort -nr | head -20", "desc": "Identify brute-force IPs from repeated auth failures."}, {"cmd": "awk '$7 ~ /login|auth/ {print $4,$1,$9,$7}' access.log | head -100", "desc": "Sample auth endpoint hits for quick triage."}]},
                {"focus": "webshell_hunting", "commands": [{"cmd": "grep -Ei \"base64_decode|eval\\(|assert\\(|system\\(|shell_exec\" access.log", "desc": "Hunt common webshell and code execution tokens."}, {"cmd": "grep -Ei \"\\.php\\?|\\.aspx\\?|cmd=|exec=\" access.log", "desc": "Detect suspicious query parameters to executable pages."}]},
                {"focus": "anomaly_summarization", "commands": [{"cmd": "awk '{print $9}' access.log | sort | uniq -c | sort -nr | head -20", "desc": "Summarize high-volume HTTP status anomalies."}, {"cmd": "jq -r '.ip,.status,.path' app.json 2>/dev/null | paste - - - | head -50", "desc": "Quick parse structured JSON application logs."}]},
            ],
        },
        "auth_compromise": {
            "tool": "grep/awk",
            "steps": [
                {"focus": "failed_login_spray", "commands": [{"cmd": "grep -Ei \"failed|invalid|authentication failure\" auth.log | awk '{print $(NF-3)}' | sort | uniq -c | sort -nr | head", "desc": "Detect password spray or brute-force source IP/user."}]},
                {"focus": "privilege_escalation", "commands": [{"cmd": "grep -Ei \"sudo|su:|root\" auth.log | tail -n 200", "desc": "Inspect privileged command execution and escalation trail."}, {"cmd": "grep -Ei \"new user|usermod|groupadd\" auth.log", "desc": "Detect suspicious account lifecycle events."}]},
                {"focus": "session_hijack", "commands": [{"cmd": "grep -Ei \"session opened|session closed\" auth.log | tail -n 200", "desc": "Review abnormal session churn and persistence attempts."}]},
            ],
        },
        "endpoint_detection": {
            "tool": "jq/grep",
            "steps": [
                {"focus": "powershell_and_lolbins", "commands": [{"cmd": "grep -Ei \"powershell.*-enc|frombase64string|mshta|rundll32|regsvr32|certutil\" endpoint.log", "desc": "Hunt encoded PowerShell and LOLBIN abuse."}]},
                {"focus": "credential_dumping", "commands": [{"cmd": "grep -Ei \"mimikatz|sekurlsa::|lsass|procdump\" endpoint.log", "desc": "Detect potential credential dumping traces."}]},
                {"focus": "persistence", "commands": [{"cmd": "grep -Ei \"run key|scheduled task|startup folder|service create\" endpoint.log", "desc": "Detect persistence establishment attempts."}]},
            ],
        },
    },
}

# Backward compatibility for legacy profile name used in previous releases.
PLAYBOOKS["network"]["intrusion_detection"] = PLAYBOOKS["network"]["network.analysis.deep_inspection"]

# Parser resource limits to prevent denial-of-service attacks
MAX_PARSED_RECORDS = 5000
MAX_PARSE_OUTPUT_BYTES = 50 * 1024 * 1024  # 50 MB

SUSPICIOUS_PATTERNS = [
    {"label": "mimikatz", "category": "credential_access", "severity": "critical", "regex": re.compile(r"mimikatz|sekurlsa::|lsadump::", re.I)},
    {"label": "pypykatz", "category": "credential_access", "severity": "high", "regex": re.compile(r"pypykatz", re.I)},
    {"label": "lsass dump", "category": "credential_access", "severity": "critical", "regex": re.compile(r"lsass(\.exe)?|procdump|comsvcs\.dll", re.I)},
    {"label": "injected memory", "category": "execution", "severity": "high", "regex": re.compile(r"malfind|rwx|page_execute_readwrite|injected", re.I)},
    {"label": "cobalt strike beacon", "category": "command_and_control", "severity": "critical", "regex": re.compile(r"beacon|cobalt|meterpreter", re.I)},
    {"label": "encoded powershell", "category": "defense_evasion", "severity": "high", "regex": re.compile(r"powershell.*(-enc|frombase64string|iex)", re.I)},
    {"label": "powershell download cradle", "category": "execution", "severity": "high", "regex": re.compile(r"invoke-webrequest|iwr\s+http|downloadstring|new-object\s+net\.webclient|bitsadmin", re.I)},
    {"label": "log4shell jndi artifact", "category": "execution", "severity": "critical", "regex": re.compile(r"\$\{jndi:(ldap|ldaps|rmi|dns|iiop)://", re.I)},
    {"label": "ransomware shadow copy tamper", "category": "impact", "severity": "critical", "regex": re.compile(r"vssadmin\s+delete\s+shadows|wmic\s+shadowcopy\s+delete|bcdedit\s+/set\s+\{default\}\s+recoveryenabled\s+no", re.I)},
    {"label": "base64 payload blob", "category": "defense_evasion", "severity": "medium", "regex": re.compile(r"[A-Za-z0-9+/]{120,}={0,2}", re.I)},
    {"label": "living off the land", "category": "execution", "severity": "medium", "regex": re.compile(r"rundll32|regsvr32|mshta|certutil", re.I)},
    {"label": "suspicious network tunnel", "category": "command_and_control", "severity": "high", "regex": re.compile(r"4444|1337|9001|reverse shell|socks", re.I)},
    {"label": "credential material", "category": "credential_access", "severity": "high", "regex": re.compile(r"ntlm|krbtgt|ticket|hashdump|sam", re.I)},
]

RECOMMENDATIONS = {
    "credential_access": "Validate credential exposure scope and rotate impacted credentials immediately.",
    "execution": "Pivot to process tree lineage, command line, and loaded module correlation.",
    "command_and_control": "Correlate suspected C2 endpoints with DNS/PCAP and isolate affected hosts.",
    "defense_evasion": "Review encoded script execution and persistence mechanisms for follow-up containment.",
    "impact": "Immediately isolate affected endpoints and validate destructive activity scope.",
}

SEVERITY_WEIGHT = {
    "critical": 5,
    "high": 3,
    "medium": 2,
    "low": 1,
}


def _normalize_command_entry(command):
    if isinstance(command, dict):
        cmd = str(command.get("cmd", "")).strip()
        if not cmd:
            return None
        desc = str(command.get("desc", "")).strip() or "Run command for focused validation."
        return {"cmd": cmd, "desc": desc}
    if isinstance(command, str):
        cmd = command.strip()
        if not cmd:
            return None
        return {"cmd": cmd, "desc": "Run command for focused validation."}
    return None


def get_playbook(category: str, profile: str):
    cat_data = PLAYBOOKS.get(category, {})
    profile_data = cat_data.get(profile, list(cat_data.values())[0] if cat_data else {})
    if not profile_data:
        return None

    raw_steps = profile_data.get("steps", [])
    steps = []
    for step in raw_steps:
        commands = []
        for cmd in step.get("commands", []):
            norm = _normalize_command_entry(cmd)
            if norm:
                commands.append(norm)
        steps.append(
            {
                "focus": step.get("focus", "general"),
                "commands": commands,
            }
        )

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
    # Reject oversized input before parsing
    if len(raw_output) > MAX_PARSE_OUTPUT_BYTES:
        raise ValueError(f"Input exceeds {MAX_PARSE_OUTPUT_BYTES // (1024 * 1024)} MB limit.")

    json_rows = _parse_json_blob(raw_output)
    if json_rows:
        if len(json_rows) > MAX_PARSED_RECORDS:
            raise ValueError(f"Parsed record count exceeds limit ({MAX_PARSED_RECORDS}).")
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
            if len(rows) > MAX_PARSED_RECORDS:
                raise ValueError(f"Parsed record count exceeds limit ({MAX_PARSED_RECORDS}).")
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
    indicators = Counter()

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
                indicators[pattern["label"]] += 1
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
                indicators["anomalous process artifact"] += 1
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

    threat_score = sum(SEVERITY_WEIGHT.get(severity, 1) * count for severity, count in severity_counts.items())

    summary = {
        "total_lines": len(lines),
        "parsed_records": len(records),
        "suspicious_hits": len(suspicious),
        "malicious_pattern_hits": len(suspicious),
        "detected_format": detected_format,
        "input_name": input_name,
        "severity_counts": dict(severity_counts),
        "category_counts": dict(categories),
        "top_indicators": indicators.most_common(10),
        "threat_score": threat_score,
        "recommendations": recommendations,
    }

    return {
        "summary": summary,
        "suspicious": suspicious,
        "events": events,
        "detected_format": detected_format,
    }
