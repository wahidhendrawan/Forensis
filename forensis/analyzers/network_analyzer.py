from collections import defaultdict
import socket
import logging

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
            "summary": {"error": "dpkt is not installed."},
            "events": [], "flows": [], "anomalies": [],
        }

    flows = {}
    anomalies = []
    events = []
    total_packets = 0

    try:
        with open(path, "rb") as f:
            # Try PCAP first, then PCAPNG
            try:
                reader = dpkt.pcap.Reader(f)
            except ValueError:
                f.seek(0)
                try:
                    reader = dpkt.pcapng.Reader(f)
                except Exception as e:
                    return {
                        "summary": {"error": f"Invalid PCAP format: {str(e)}"},
                        "events": [], "flows": [], "anomalies": []
                    }

            for ts, buf in reader:
                total_packets += 1
                try:
                    eth = dpkt.ethernet.Ethernet(buf)
                    if not isinstance(eth.data, (dpkt.ip.IP, dpkt.ip6.IP6)):
                        continue
                    ip = eth.data
                    proto = ip.p if hasattr(ip, 'p') else ip.nxt
                    src = _inet_to_str(ip.src)
                    dst = _inet_to_str(ip.dst)

                    sport = dport = None
                    payload_len = 0

                    if proto in (dpkt.ip.IP_PROTO_TCP, dpkt.ip.IP_PROTO_UDP):
                        l4 = ip.data
                        sport = getattr(l4, "sport", None)
                        dport = getattr(l4, "dport", None)
                        payload_len = len(getattr(l4, "data", b""))
                    else:
                        payload_len = len(ip.data)

                    key = (src, dst, sport, dport, proto)
                    flow = flows.get(key)
                    if not flow:
                        flow = {
                            "src": src, "dst": dst, "sport": sport, "dport": dport,
                            "proto": proto, "first_ts": ts, "last_ts": ts,
                            "packets": 0, "bytes": 0, "small_packets": 0,
                        }
                        flows[key] = flow

                    flow["packets"] += 1
                    flow["bytes"] += len(buf)
                    flow["last_ts"] = ts
                    if payload_len < 100:
                        flow["small_packets"] += 1

                except Exception:
                    continue
    except Exception as e:
        return {
            "summary": {"error": f"System error during analysis: {str(e)}"},
            "events": [], "flows": [], "anomalies": []
        }

    for key, flow in flows.items():
        duration = flow["last_ts"] - flow["first_ts"]
        flow["duration"] = duration
        flow["pps"] = flow["packets"] / duration if duration > 0 else flow["packets"]
        avg_payload = flow["bytes"] / max(flow["packets"], 1)
        flow["avg_payload"] = avg_payload

        suspicious = []
        if flow["dport"] in SUSPICIOUS_PORTS:
            suspicious.append(f"Suspicious port {flow['dport']}")
        if flow["packets"] > 50 and avg_payload < 150:
            suspicious.append("Possible beaconing (small packets)")
        
        if suspicious:
            anomalies.append({"reason": "; ".join(suspicious), "flow": flow})

        events.append({
            "source": "pcap_flow", "src_ip": flow["src"], "dst_ip": flow["dst"],
            "src_port": flow["sport"], "dst_port": flow["dport"], "proto": flow["proto"],
            "packets": flow["packets"], "bytes": flow["bytes"], "duration": duration
        })

    return {
        "summary": {"total_packets": total_packets, "flow_count": len(flows), "anomaly_count": len(anomalies)},
        "events": events,
        "flows": sorted(flows.values(), key=lambda f: f["bytes"], reverse=True)[:50],
        "anomalies": anomalies,
    }
