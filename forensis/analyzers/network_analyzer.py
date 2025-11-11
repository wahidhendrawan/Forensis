from collections import defaultdict
import socket

def _try_import_dpkt():
    try:
        import dpkt
        return dpkt
    except ImportError:
        return None

SUSPICIOUS_PORTS = {4444, 1337, 6667, 8080, 3389, 22, 23}

def _inet_to_str(inet):
    try:
        return socket.inet_ntop(socket.AF_INET, inet)
    except ValueError:
        try:
            return socket.inet_ntop(socket.AF_INET6, inet)
        except ValueError:
            return "unknown"

def analyze_pcap(path: str):
    dpkt = _try_import_dpkt()
    if dpkt is None:
        return {
            "summary": {
                "error": "dpkt is not installed. Please run 'pip install dpkt' to enable PCAP analysis.",
            },
            "events": [],
            "flows": [],
            "anomalies": [],
        }

    flows = {}
    anomalies = []
    events = []
    total_packets = 0

    with open(path, "rb") as f:
        pcap = dpkt.pcap.Reader(f)
        for ts, buf in pcap:
            total_packets += 1
            try:
                eth = dpkt.ethernet.Ethernet(buf)
                ip = eth.data
                if not hasattr(ip, "p"):
                    continue
                proto = ip.p
                src = _inet_to_str(ip.src)
                dst = _inet_to_str(ip.dst)

                sport = dport = None
                payload_len = 0

                if proto in (dpkt.ip.IP_PROTO_TCP, dpkt.ip.IP_PROTO_UDP):
                    l4 = ip.data
                    sport = getattr(l4, "sport", None)
                    dport = getattr(l4, "dport", None)
                    payload_len = len(l4.data or b"")
                else:
                    payload_len = len(ip.data or b"")

                key = (src, dst, sport, dport, proto)
                flow = flows.get(key)
                if not flow:
                    flow = {
                        "src": src,
                        "dst": dst,
                        "sport": sport,
                        "dport": dport,
                        "proto": proto,
                        "first_ts": ts,
                        "last_ts": ts,
                        "packets": 0,
                        "bytes": 0,
                        "small_packets": 0,
                    }
                    flows[key] = flow

                flow["packets"] += 1
                flow["bytes"] += len(buf)
                flow["last_ts"] = ts
                if payload_len and payload_len < 100:
                    flow["small_packets"] += 1

            except Exception:
                continue

    for key, flow in flows.items():
        duration = flow["last_ts"] - flow["first_ts"]
        flow["duration"] = duration
        if duration > 0:
            flow["pps"] = flow["packets"] / duration
        else:
            flow["pps"] = flow["packets"]

        avg_payload = flow["bytes"] / max(flow["packets"], 1)
        flow["avg_payload"] = avg_payload

        suspicious_reasons = []
        if flow["dport"] in SUSPICIOUS_PORTS:
            suspicious_reasons.append(f"Suspicious destination port {flow['dport']}")
        if flow["packets"] > 50 and avg_payload < 150:
            suspicious_reasons.append("Many small packets (possible beaconing)")
        if duration > 300 and flow["bytes"] < 10 * 1024:
            suspicious_reasons.append("Long-lived low-volume flow")

        if suspicious_reasons:
            anomalies.append(
                {
                    "reason": "; ".join(suspicious_reasons),
                    "flow": flow,
                }
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
            }
        )

    summary = {
        "total_packets": total_packets,
        "flow_count": len(flows),
        "anomaly_count": len(anomalies),
    }

    sorted_flows = sorted(flows.values(), key=lambda f: f["bytes"], reverse=True)[:50]

    return {
        "summary": summary,
        "events": events,
        "flows": sorted_flows,
        "anomalies": anomalies,
    }
