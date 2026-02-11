import re
import csv
import json
import io
from collections import Counter, defaultdict
from datetime import datetime

APACHE_REGEX = re.compile(
    r'(?P<ip>\S+) \S+ \S+ \[(?P<time>[^\]]+)\] "(?P<method>\S+)\s(?P<path>\S+)[^"]*" (?P<status>\d{3}) (?P<size>\S+)'
)

SYSLOG_REGEX = re.compile(
    r'^(?P<time>\w{3}\s+\d{1,2}\s[\d:]{8})\s(?P<host>\S+)\s(?P<process>\S+):\s(?P<message>.*)$'
)

def _parse_apache(line: str):
    m = APACHE_REGEX.search(line)
    if not m:
        return None
    data = m.groupdict()
    evt = {
        "source": "apache",
        "raw": line.strip(),
        "ip": data.get("ip"),
        "status": int(data.get("status") or 0),
        "method": data.get("method"),
        "path": data.get("path"),
        "size": int(data.get("size") or 0) if data.get("size", "-").isdigit() else 0,
        "timestamp": data.get("time"),
    }
    return evt

def _parse_syslog(line: str):
    m = SYSLOG_REGEX.search(line)
    if not m:
        return None
    data = m.groupdict()
    evt = {
        "source": "syslog",
        "raw": line.strip(),
        "timestamp": data.get("time"),
        "host": data.get("host"),
        "process": data.get("process"),
        "message": data.get("message"),
    }
    return evt

def _parse_generic(line: str):
    return {
        "source": "generic",
        "raw": line.strip(),
        "message": line.strip(),
    }

def _parse_csv(text: str):
    events = []
    try:
        # Use StringIO to parse the text as file-like object
        f = io.StringIO(text)
        # Sniff delimiter
        dialect = csv.Sniffer().sniff(text[:1024])
        reader = csv.DictReader(f, dialect=dialect)
        for row in reader:
            evt = dict(row)
            evt["source"] = "csv"
            evt["raw"] = json.dumps(row)
            # Try to find standard fields
            evt["message"] = evt.get("message") or evt.get("msg") or evt.get("event") or str(row)
            events.append(evt)
    except Exception:
        # Fallback if CSV parsing fails
        pass
    return events

def _parse_json_lines(text: str, source_type="json"):
    events = []
    for line in text.splitlines():
        if not line.strip(): continue
        try:
            data = json.loads(line)
            if isinstance(data, dict):
                 data["source"] = source_type
                 data["raw"] = line
                 # Normalize common fields for Elastic/Splunk
                 if source_type in ["elastic", "splunk"]:
                     data["message"] = data.get("message") or data.get("_raw") or data.get("event") or str(data)
                     data["timestamp"] = data.get("@timestamp") or data.get("timestamp") or data.get("_time")

                 events.append(data)
        except json.JSONDecodeError:
            continue
    return events

def analyze_logs(text: str, log_type: str = "generic"):
    events = []
    anomalies = []
    counters = defaultdict(Counter)

    # Pre-processing for structured types
    if log_type == "csv":
        events = _parse_csv(text)
        if not events: # If CSV parsing failed, treat as generic lines
             lines = [l for l in text.splitlines() if l.strip()]
             for line in lines:
                 events.append(_parse_generic(line))
    elif log_type in ["elastic", "splunk"]:
        # Try JSON lines first
        events = _parse_json_lines(text, source_type=log_type)
        if not events:
            # Maybe it's a huge JSON array?
            try:
                data = json.loads(text)
                if isinstance(data, list):
                    for item in data:
                        if isinstance(item, dict):
                            item["source"] = log_type
                            item["raw"] = json.dumps(item)
                            item["message"] = item.get("message") or item.get("_raw") or str(item)
                            events.append(item)
                elif isinstance(data, dict):
                     # Single event?
                     data["source"] = log_type
                     data["raw"] = json.dumps(data)
                     data["message"] = data.get("message") or data.get("_raw") or str(data)
                     events.append(data)
            except json.JSONDecodeError:
                 # Fallback to generic
                 pass

        if not events and log_type == "splunk":
             # Splunk might be CSV export
             events = _parse_csv(text)

    else:
        # Line based parsing
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

    # Post-processing events for stats and anomalies
    for evt in events:
        src = evt.get("ip") or evt.get("host") or evt.get("src_ip") or "unknown"
        counters["by_source"][src] += 1

        # Safe access to status
        status = evt.get("status")
        if status:
            counters["by_status"][status] += 1
            try:
                if int(status) >= 400:
                    anomalies.append({
                        "reason": f"HTTP {status} from {src}",
                        "event": evt,
                    })
            except (ValueError, TypeError):
                pass

        msg = str(evt.get("message", evt.get("raw", ""))).lower()
        suspicious_keywords = [
            "failed password",
            "authentication failure",
            "sql injection",
            "union select",
            "xp_cmdshell",
            "mimikatz",
            "powershell",
        ]
        for kw in suspicious_keywords:
            if kw in msg:
                anomalies.append(
                    {
                        "reason": f"Suspicious keyword '{kw}' in log line",
                        "event": evt,
                    }
                )
                break

    top_sources = counters["by_source"].most_common(10)
    top_status = counters["by_status"].most_common(10)

    summary = {
        "total_lines": len(text.splitlines()),
        "parsed_events": len(events),
        "top_sources": top_sources,
        "top_status": top_status,
        "anomaly_count": len(anomalies),
    }

    return {
        "summary": summary,
        "events": events,
        "anomalies": anomalies,
    }
