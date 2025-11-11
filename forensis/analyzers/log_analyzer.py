import re
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

def analyze_logs(text: str, log_type: str = "generic"):
    lines = [l for l in text.splitlines() if l.strip()]
    events = []
    anomalies = []
    counters = defaultdict(Counter)

    for line in lines:
        if log_type == "apache":
            evt = _parse_apache(line)
        elif log_type == "syslog":
            evt = _parse_syslog(line)
        else:
            evt = _parse_generic(line)

        if not evt:
            continue

        events.append(evt)

        src = evt.get("ip") or evt.get("host") or "unknown"
        counters["by_source"][src] += 1

        if "status" in evt:
            status = evt["status"]
            counters["by_status"][status] += 1
            if status >= 400:
                anomalies.append(
                    {
                        "reason": f"HTTP {status} from {src}",
                        "event": evt,
                    }
                )

        msg = evt.get("message", evt.get("raw", "")).lower()
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
        "total_lines": len(lines),
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
