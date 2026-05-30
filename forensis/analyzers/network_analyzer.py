from collections import defaultdict, Counter
import socket
import ipaddress
from datetime import datetime, timezone


def _try_import_dpkt():
    try:
        import dpkt
        return dpkt
    except ImportError:
        return None


KNOWN_C2_PORTS = {4444, 4445, 1337, 6667, 31337, 9001, 50050}
RISKY_ADMIN_PORTS = {22, 23, 135, 139, 445, 3389, 5985, 5986}
SEVERITY_WEIGHT = {"critical": 5, "high": 3, "medium": 2, "low": 1}


def _inet_to_str(inet):
    try:
        return socket.inet_ntop(socket.AF_INET, inet)
    except ValueError:
        try:
            return socket.inet_ntop(socket.AF_INET6, inet)
        except ValueError:
            return "unknown"


def _is_private_ip(ip_str: str) -> bool:
    try:
        return ipaddress.ip_address(ip_str).is_private
    except Exception:
        return False


def _proto_name(proto: int):
    if proto == 6:
        return "TCP"
    if proto == 17:
        return "UDP"
    if proto == 1:
        return "ICMP"
    return str(proto)


def _add_anomaly(anomalies, seen, severity_counts, flow, reason, severity, category, indicator):
    key = (flow.get("src"), flow.get("dst"), flow.get("sport"), flow.get("dport"), indicator, reason)
    if key in seen:
        return
    seen.add(key)
    anomalies.append(
        {
            "reason": reason,
            "flow": flow,
            "severity": severity,
            "category": category,
            "indicator": indicator,
        }
    )
    severity_counts[severity] += 1


def _calc_threat_score(severity_counts: Counter):
    return sum(SEVERITY_WEIGHT.get(sev, 1) * count for sev, count in severity_counts.items())

def _format_ts(ts):
    try:
        return datetime.fromtimestamp(float(ts), tz=timezone.utc).isoformat()
    except Exception:
        return ""


def analyze_pcap(path: str):
    dpkt = _try_import_dpkt()
    if dpkt is None:
        return {
            "summary": {"error": "dpkt is not installed."},
            "events": [],
            "flows": [],
            "anomalies": [],
        }

    flows = {}
    anomalies = []
    events = []
    anomaly_seen = set()
    severity_counts = Counter()
    total_packets = 0
    scan_tracker = defaultdict(lambda: {"dst_ports": set(), "dst_hosts": set(), "syn_packets": 0})

    try:
        with open(path, "rb") as f:
            try:
                reader = dpkt.pcap.Reader(f)
            except ValueError:
                f.seek(0)
                try:
                    reader = dpkt.pcapng.Reader(f)
                except Exception as e:
                    return {
                        "summary": {"error": f"Invalid PCAP format: {str(e)}"},
                        "events": [],
                        "flows": [],
                        "anomalies": [],
                    }

            for ts, buf in reader:
                total_packets += 1
                try:
                    eth = dpkt.ethernet.Ethernet(buf)
                    if not isinstance(eth.data, (dpkt.ip.IP, dpkt.ip6.IP6)):
                        continue
                    ip = eth.data
                    proto = ip.p if hasattr(ip, "p") else ip.nxt
                    src = _inet_to_str(ip.src)
                    dst = _inet_to_str(ip.dst)

                    sport = dport = None
                    payload_len = 0
                    tcp_flags = None

                    if proto in (dpkt.ip.IP_PROTO_TCP, dpkt.ip.IP_PROTO_UDP):
                        l4 = ip.data
                        sport = getattr(l4, "sport", None)
                        dport = getattr(l4, "dport", None)
                        payload_len = len(getattr(l4, "data", b""))
                        if proto == dpkt.ip.IP_PROTO_TCP:
                            tcp_flags = getattr(l4, "flags", None)
                            if tcp_flags is not None:
                                syn = bool(tcp_flags & dpkt.tcp.TH_SYN)
                                ack = bool(tcp_flags & dpkt.tcp.TH_ACK)
                                if syn and not ack:
                                    track = scan_tracker[src]
                                    track["syn_packets"] += 1
                                    if dport is not None:
                                        track["dst_ports"].add(dport)
                                    track["dst_hosts"].add(dst)
                    else:
                        payload_len = len(ip.data)

                    key = (src, dst, sport, dport, proto)
                    flow = flows.get(key)
                    if not flow:
                        flow = {
                            "src": src,
                            "dst": dst,
                            "sport": sport,
                            "dport": dport,
                            "proto": _proto_name(proto),
                            "first_ts": ts,
                            "last_ts": ts,
                            "packets": 0,
                            "bytes": 0,
                            "small_packets": 0,
                            "syn_packets": 0,
                        }
                        flows[key] = flow

                    flow["packets"] += 1
                    flow["bytes"] += len(buf)
                    flow["last_ts"] = ts
                    if payload_len < 100:
                        flow["small_packets"] += 1
                    if tcp_flags is not None:
                        syn = bool(tcp_flags & dpkt.tcp.TH_SYN)
                        ack = bool(tcp_flags & dpkt.tcp.TH_ACK)
                        if syn and not ack:
                            flow["syn_packets"] += 1

                except Exception:
                    continue
    except Exception as e:
        return {
            "summary": {"error": f"System error during analysis: {str(e)}"},
            "events": [],
            "flows": [],
            "anomalies": [],
        }

    for flow in flows.values():
        duration = flow["last_ts"] - flow["first_ts"]
        flow["duration"] = duration
        flow["pps"] = flow["packets"] / duration if duration > 0 else flow["packets"]
        flow["avg_payload"] = flow["bytes"] / max(flow["packets"], 1)
        flow["first_seen"] = _format_ts(flow["first_ts"])
        flow["last_seen"] = _format_ts(flow["last_ts"])

        src_private = _is_private_ip(flow["src"])
        dst_private = _is_private_ip(flow["dst"])
        dport = flow.get("dport")

        if dport in KNOWN_C2_PORTS:
            _add_anomaly(
                anomalies,
                anomaly_seen,
                severity_counts,
                flow,
                f"Connection on known C2/non-standard control port {dport}",
                severity="high",
                category="command_and_control",
                indicator="known_c2_port",
            )

        if dport in RISKY_ADMIN_PORTS and src_private and dst_private:
            _add_anomaly(
                anomalies,
                anomaly_seen,
                severity_counts,
                flow,
                f"Internal administrative service access on port {dport} (potential lateral movement)",
                severity="medium",
                category="lateral_movement",
                indicator="internal_admin_port",
            )

        if dport == 53 and flow["avg_payload"] > 200 and flow["packets"] > 30:
            _add_anomaly(
                anomalies,
                anomaly_seen,
                severity_counts,
                flow,
                "Possible DNS tunneling pattern (high payload over many DNS packets)",
                severity="high",
                category="command_and_control",
                indicator="dns_tunnel_pattern",
            )

        if flow["packets"] >= 80 and flow["avg_payload"] < 120 and duration > 30:
            _add_anomaly(
                anomalies,
                anomaly_seen,
                severity_counts,
                flow,
                "Possible beaconing (frequent small packets over time)",
                severity="medium",
                category="command_and_control",
                indicator="beaconing_pattern",
            )

        if flow["bytes"] > 10_000_000 and flow["packets"] < 40:
            _add_anomaly(
                anomalies,
                anomaly_seen,
                severity_counts,
                flow,
                "Large transfer in low packet count (possible bulk exfiltration)",
                severity="high",
                category="exfiltration",
                indicator="bulk_exfil_pattern",
            )

        if flow["pps"] > 300 and flow["packets"] > 200:
            _add_anomaly(
                anomalies,
                anomaly_seen,
                severity_counts,
                flow,
                "Abnormally high packets-per-second rate",
                severity="medium",
                category="impact",
                indicator="packet_flood_pattern",
            )

        events.append(
            {
                "source": "pcap_flow",
                "src_ip": flow["src"],
                "dst_ip": flow["dst"],
                "src_port": flow["sport"],
                "dst_port": flow["dport"],
                "proto": flow["proto"],
                "packets": flow["packets"],
                "bytes": flow["bytes"],
                "duration": duration,
                "avg_payload": flow["avg_payload"],
                "first_seen": flow["first_seen"],
                "last_seen": flow["last_seen"],
            }
        )

    for src, track in scan_tracker.items():
        unique_ports = len(track["dst_ports"])
        unique_hosts = len(track["dst_hosts"])
        syn_packets = track["syn_packets"]
        if unique_ports >= 30 or (unique_hosts >= 20 and syn_packets >= 40):
            flow = {
                "src": src,
                "dst": f"{unique_hosts} hosts",
                "sport": "-",
                "dport": f"{unique_ports} ports",
                "proto": "TCP",
                "packets": syn_packets,
                "bytes": 0,
                "duration": 0,
                "pps": syn_packets,
                "avg_payload": 0,
                "first_seen": "",
                "last_seen": "",
            }
            _add_anomaly(
                anomalies,
                anomaly_seen,
                severity_counts,
                flow,
                f"Potential port scan / SYN scan activity from {src}",
                severity="high",
                category="reconnaissance",
                indicator="syn_scan_pattern",
            )

    summary = {
        "total_packets": total_packets,
        "flow_count": len(flows),
        "anomaly_count": len(anomalies),
        "malicious_pattern_hits": len(anomalies),
        "severity_counts": dict(severity_counts),
        "threat_score": _calc_threat_score(severity_counts),
        "first_seen": _format_ts(min((f["first_ts"] for f in flows.values()), default=0)) if flows else "",
        "last_seen": _format_ts(max((f["last_ts"] for f in flows.values()), default=0)) if flows else "",
    }

    return {
        "summary": summary,
        "events": events,
        "flows": sorted(flows.values(), key=lambda f: f["bytes"], reverse=True)[:200],
        "anomalies": anomalies,
    }
