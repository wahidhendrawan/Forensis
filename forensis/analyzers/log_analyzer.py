import re
import csv
import json
import io
from collections import Counter, defaultdict
from urllib.parse import unquote

APACHE_REGEX = re.compile(
    r'(?P<ip>\S+) \S+ \S+ \[(?P<time>[^\]]+)\] "(?P<method>\S+)\s(?P<path>\S+)[^"]*" (?P<status>\d{3}) (?P<size>\S+)'
)

SYSLOG_REGEX = re.compile(
    r'^(?P<time>\w{3}\s+\d{1,2}\s[\d:]{8})\s(?P<host>\S+)\s(?P<process>\S+):\s(?P<message>.*)$'
)

SEVERITY_WEIGHT = {
    "critical": 5,
    "high": 3,
    "medium": 2,
    "low": 1,
}

PATTERN_RULES = [
    {
        "name": "sql_injection",
        "severity": "high",
        "category": "injection",
        "reason": "Possible SQL injection payload in request/log content",
        "regex": re.compile(
            r"(union(?:\s+all)?\s+select\b|(?:or|and)\s+1\s*=\s*1\b|information_schema|xp_cmdshell|sleep\s*\(|benchmark\s*\()",
            re.I,
        ),
    },
    {
        "name": "xss_payload",
        "severity": "high",
        "category": "injection",
        "reason": "Possible XSS payload pattern detected",
        "regex": re.compile(r"(<script\b|javascript:|onerror\s*=|onload\s*=|%3cscript|alert\s*\()", re.I),
    },
    {
        "name": "path_traversal",
        "severity": "high",
        "category": "discovery",
        "reason": "Possible path traversal / sensitive file access attempt",
        "regex": re.compile(r"(\.\./|\.\.\\|%2e%2e%2f|/etc/passwd|/windows/win\.ini|/proc/self/environ)", re.I),
    },
    {
        "name": "command_injection",
        "severity": "critical",
        "category": "execution",
        "reason": "Possible command injection / shell execution payload",
        "regex": re.compile(r"([;&|`]\s*(?:bash|sh|cmd|powershell|wget|curl|nc|netcat)\b|\$\(|\bwhoami\b|\bchmod\b\s+\+x)", re.I),
    },
    {
        "name": "webshell_indicator",
        "severity": "critical",
        "category": "persistence",
        "reason": "Possible webshell or backdoor artifact in web access pattern",
        "regex": re.compile(r"(/cmd\.php|/shell\.php|/c99\.php|/r57\.php|base64_decode|eval\(|assert\()", re.I),
    },
    {
        "name": "credential_abuse",
        "severity": "high",
        "category": "credential_access",
        "reason": "Credential abuse or dumping indicator detected",
        "regex": re.compile(r"(failed password|authentication failure|invalid user|mimikatz|sekurlsa::|lsass)", re.I),
    },
    {
        "name": "scanner_activity",
        "severity": "medium",
        "category": "reconnaissance",
        "reason": "Security scanner / probing tool signature detected",
        "regex": re.compile(r"(sqlmap|nikto|acunetix|nmap|masscan|dirbuster|gobuster|wpscan|burp(?:suite)?)", re.I),
    },
    {
        "name": "log4shell_probe",
        "severity": "critical",
        "category": "execution",
        "reason": "Possible Log4Shell JNDI lookup payload detected",
        "regex": re.compile(r"\$\{jndi:(ldap|ldaps|rmi|dns|iiop)://", re.I),
    },
]

AUTH_FAILURE_REGEX = re.compile(r"(failed password|authentication failure|invalid user|login failed|unauthorized)", re.I)


def _parse_apache(line: str):
    m = APACHE_REGEX.search(line)
    if not m:
        return None
    data = m.groupdict()
    return {
        "source": "apache",
        "raw": line.strip(),
        "ip": data.get("ip"),
        "status": int(data.get("status") or 0),
        "method": data.get("method"),
        "path": data.get("path"),
        "size": int(data.get("size") or 0) if data.get("size", "-").isdigit() else 0,
        "timestamp": data.get("time"),
    }


def _parse_syslog(line: str):
    m = SYSLOG_REGEX.search(line)
    if not m:
        return None
    data = m.groupdict()
    return {
        "source": "syslog",
        "raw": line.strip(),
        "timestamp": data.get("time"),
        "host": data.get("host"),
        "process": data.get("process"),
        "message": data.get("message"),
    }


def _parse_generic(line: str):
    return {
        "source": "generic",
        "raw": line.strip(),
        "message": line.strip(),
    }


def _parse_csv(text: str):
    events = []
    try:
        f = io.StringIO(text)
        dialect = csv.Sniffer().sniff(text[:1024])
        reader = csv.DictReader(f, dialect=dialect)
        for row in reader:
            evt = dict(row)
            evt["source"] = "csv"
            evt["raw"] = json.dumps(row, default=str)
            evt["message"] = evt.get("message") or evt.get("msg") or evt.get("event") or str(row)
            events.append(evt)
    except Exception:
        pass
    return events


def _parse_json_lines(text: str, source_type: str = "json"):
    events = []
    for line in text.splitlines():
        if not line.strip():
            continue
        try:
            data = json.loads(line)
            if isinstance(data, dict):
                data["source"] = source_type
                data["raw"] = line
                if source_type in {"elastic", "splunk"}:
                    data["message"] = data.get("message") or data.get("_raw") or data.get("event") or str(data)
                    data["timestamp"] = data.get("@timestamp") or data.get("timestamp") or data.get("_time")
                events.append(data)
        except json.JSONDecodeError:
            continue
    return events


def _event_source(evt: dict) -> str:
    return str(
        evt.get("ip")
        or evt.get("host")
        or evt.get("src_ip")
        or evt.get("source_ip")
        or evt.get("client_ip")
        or "unknown"
    )


def _to_int(value):
    try:
        if value is None or value == "":
            return None
        return int(value)
    except (TypeError, ValueError):
        return None


def _event_text(evt: dict) -> str:
    parts = [
        evt.get("message"),
        evt.get("raw"),
        evt.get("path"),
        evt.get("request"),
        evt.get("uri"),
        evt.get("process"),
        evt.get("user"),
    ]
    raw_text = " ".join(str(p) for p in parts if p is not None).lower()
    try:
        decoded = unquote(raw_text)
    except Exception:
        decoded = raw_text
    if decoded == raw_text:
        return raw_text
    return f"{raw_text} {decoded}"


def _append_anomaly(anomalies, seen, reason, event, severity="medium", category="suspicious_pattern", indicator=None):
    raw = str(event.get("raw", event.get("message", "")))[:600]
    key = (reason, raw, severity, category, indicator or "")
    if key in seen:
        return
    seen.add(key)
    anomalies.append(
        {
            "reason": reason,
            "event": event,
            "severity": severity,
            "category": category,
            "indicator": indicator,
        }
    )


def _calc_threat_score(severity_counts: Counter):
    return sum(SEVERITY_WEIGHT.get(sev, 1) * count for sev, count in severity_counts.items())


def analyze_logs(text: str, log_type: str = "generic"):
    events = []
    anomalies = []
    anomaly_seen = set()
    counters = defaultdict(Counter)
    severity_counts = Counter()

    if log_type == "csv":
        events = _parse_csv(text)
        if not events:
            lines = [l for l in text.splitlines() if l.strip()]
            for line in lines:
                events.append(_parse_generic(line))
    elif log_type in {"elastic", "splunk"}:
        events = _parse_json_lines(text, source_type=log_type)
        if not events:
            try:
                data = json.loads(text)
                if isinstance(data, list):
                    for item in data:
                        if isinstance(item, dict):
                            item["source"] = log_type
                            item["raw"] = json.dumps(item, default=str)
                            item["message"] = item.get("message") or item.get("_raw") or str(item)
                            events.append(item)
                elif isinstance(data, dict):
                    data["source"] = log_type
                    data["raw"] = json.dumps(data, default=str)
                    data["message"] = data.get("message") or data.get("_raw") or str(data)
                    events.append(data)
            except json.JSONDecodeError:
                pass

        if not events and log_type == "splunk":
            events = _parse_csv(text)
    else:
        lines = [l for l in text.splitlines() if l.strip()]
        for line in lines:
            evt = None
            if log_type == "apache":
                evt = _parse_apache(line)
            elif log_type == "syslog":
                evt = _parse_syslog(line)
            if not evt:
                evt = _parse_generic(line)
            if evt:
                events.append(evt)

    source_auth_failures = Counter()
    source_4xx = Counter()
    source_5xx = Counter()
    source_unique_paths = defaultdict(set)

    for evt in events:
        src = _event_source(evt)
        counters["by_source"][src] += 1

        status = _to_int(evt.get("status"))
        if status is not None:
            counters["by_status"][status] += 1
            if 400 <= status < 500:
                source_4xx[src] += 1
            if status >= 500:
                source_5xx[src] += 1
            if status in {401, 403}:
                source_auth_failures[src] += 1

        path = evt.get("path")
        if path:
            source_unique_paths[src].add(str(path))

        msg = _event_text(evt)
        if AUTH_FAILURE_REGEX.search(msg):
            source_auth_failures[src] += 1

        for rule in PATTERN_RULES:
            if rule["regex"].search(msg):
                _append_anomaly(
                    anomalies,
                    anomaly_seen,
                    rule["reason"],
                    evt,
                    severity=rule["severity"],
                    category=rule["category"],
                    indicator=rule["name"],
                )
                severity_counts[rule["severity"]] += 1
                break

    for src, count in source_auth_failures.items():
        if count >= 5:
            _append_anomaly(
                anomalies,
                anomaly_seen,
                f"Potential brute-force/auth abuse from source {src} ({count} failed attempts)",
                {"source": "correlation", "raw": f"source={src} failed_auth={count}", "message": f"{count} failed authentication events"},
                severity="high",
                category="credential_access",
                indicator="bruteforce_pattern",
            )
            severity_counts["high"] += 1

    for src, count in source_4xx.items():
        if count >= 20:
            _append_anomaly(
                anomalies,
                anomaly_seen,
                f"High 4xx error burst from source {src} ({count} events)",
                {"source": "correlation", "raw": f"source={src} 4xx={count}", "message": f"{count} client error responses"},
                severity="medium",
                category="reconnaissance",
                indicator="http_4xx_burst",
            )
            severity_counts["medium"] += 1

    for src, count in source_5xx.items():
        if count >= 10:
            _append_anomaly(
                anomalies,
                anomaly_seen,
                f"High 5xx server error burst tied to source {src} ({count} events)",
                {"source": "correlation", "raw": f"source={src} 5xx={count}", "message": f"{count} server error responses"},
                severity="high",
                category="impact",
                indicator="http_5xx_burst",
            )
            severity_counts["high"] += 1

    for src, paths in source_unique_paths.items():
        if len(paths) >= 40:
            _append_anomaly(
                anomalies,
                anomaly_seen,
                f"High URI diversity from source {src} ({len(paths)} unique paths) - possible scanning",
                {"source": "correlation", "raw": f"source={src} unique_paths={len(paths)}", "message": f"{len(paths)} unique path requests"},
                severity="medium",
                category="reconnaissance",
                indicator="uri_scan_pattern",
            )
            severity_counts["medium"] += 1

    top_sources = counters["by_source"].most_common(10)
    top_status = counters["by_status"].most_common(10)
    threat_score = _calc_threat_score(severity_counts)

    summary = {
        "total_lines": len(text.splitlines()),
        "parsed_events": len(events),
        "top_sources": top_sources,
        "top_status": top_status,
        "anomaly_count": len(anomalies),
        "malicious_pattern_hits": len(anomalies),
        "severity_counts": dict(severity_counts),
        "threat_score": threat_score,
    }

    return {
        "summary": summary,
        "events": events,
        "anomalies": anomalies,
    }
