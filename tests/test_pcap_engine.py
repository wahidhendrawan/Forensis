"""
Parity tests for the optional Rust PCAP engine (forensis_core) against the dpkt reference.
Captures are generated here with dpkt; the Rust half is skipped when the extension isn't built.
"""
import io
import logging
import random
import struct
from decimal import Decimal

import dpkt
import pytest

from forensis.analyzers import network_analyzer as na

needs_native = pytest.mark.skipif(na._native_analyze_pcap is None, reason="forensis_core extension not built")


def _native(path):
    return na._native_analyze_pcap(
        str(path), na.PCAP_MAX_PACKETS, na.PCAP_MAX_TRACKED_FLOWS, na.DISPLAY_TZ_NAME, na._format_ts, na._is_private_ip
    )


def _assert_identical(a, b, where="result"):
    """Equal values, identical types and identical dict key order (JSON output is the same)."""
    assert type(a) is type(b), f"{where}: {type(a).__name__} != {type(b).__name__} ({a!r} vs {b!r})"
    if isinstance(a, dict):
        assert list(a) == list(b), f"{where}: keys {list(a)} != {list(b)}"
        for k in a:
            _assert_identical(a[k], b[k], f"{where}.{k}")
    elif isinstance(a, list):
        assert len(a) == len(b), f"{where}: len {len(a)} != {len(b)}"
        for i, (x, y) in enumerate(zip(a, b)):
            _assert_identical(x, y, f"{where}[{i}]")
    else:
        assert a == b and str(a) == str(b), f"{where}: {a!r} != {b!r}"


def _check_parity(path):
    ref = na._analyze_pcap_python(str(path))
    if na._native_analyze_pcap is not None:  # Rust half skipped when the extension isn't built
        _assert_identical(ref, _native(path))
    return ref


# ---------------------------------------------------------------- frame builders

V4 = {name: bytes(map(int, name.split("."))) for name in [
    "10.0.0.5", "10.0.0.6", "10.0.0.7", "10.0.0.8", "10.0.0.9", "10.0.0.10", "10.0.0.20",
    "10.0.0.66", "10.0.0.99", "8.8.8.8", "203.0.113.10", "203.0.113.20", "198.51.100.7", "198.51.100.66",
]}


def _eth(payload, eth_type=0x0800, tags=()):
    tag_types = tags[1:] + (eth_type,) if tags else ()
    tag_bytes = b"".join(struct.pack(">HH", 100 + i, t) for i, t in enumerate(tag_types))
    outer = tags[0] if tags else eth_type
    return b"\x02\x00\x00\x00\x00\x01\x02\x00\x00\x00\x00\x02" + struct.pack(">H", outer) + tag_bytes + bytes(payload)


def _ip4(src, dst, proto, l4, **kw):
    ip = dpkt.ip.IP(src=V4[src], dst=V4[dst], p=proto, data=l4, **kw)
    ip.len = 20 + len(bytes(l4))
    return ip


def _ip6(src, dst, nxt, l4):
    payload = bytes(l4)
    return struct.pack(">IHBB", 0x60000000, len(payload), nxt, 64) + src + dst + payload


def _tcp(sport, dport, flags=dpkt.tcp.TH_ACK, data=b""):
    return dpkt.tcp.TCP(sport=sport, dport=dport, flags=flags, data=data)


def _udp(sport, dport, data=b""):
    return dpkt.udp.UDP(sport=sport, dport=dport, ulen=8 + len(data), data=data)


def _client_hello(sni):
    name = sni.encode()
    sni_ext = struct.pack(">HHHBH", 0, len(name) + 5, len(name) + 3, 0, len(name)) + name
    body = b"\x03\x03" + b"\x11" * 32 + b"\x00" + b"\x00\x02\x13\x01" + b"\x01\x00" + struct.pack(">H", len(sni_ext)) + sni_ext
    hs = b"\x01" + struct.pack(">I", len(body))[1:] + body
    return b"\x16\x03\x01" + struct.pack(">H", len(hs)) + hs


def _dns(qid, response=False):
    msg = dpkt.dns.DNS(id=qid, qd=[dpkt.dns.DNS.Q(name="example.com")])
    if response:
        msg.op = dpkt.dns.DNS_RA | dpkt.dns.DNS_QR
        msg.an = [dpkt.dns.DNS.RR(name="example.com", type=dpkt.dns.DNS_A, rdata=b"\x5d\xb8\xd8\x22")]
    return bytes(msg)


def _frames(bulk=True):
    """(timestamp, frame) pairs covering the protocols and every anomaly rule."""
    v6a = bytes.fromhex("20010db8000000000000000000000001")
    v6b = bytes.fromhex("20010db8000000000000000000000002")
    mapped = bytes.fromhex("00000000000000000000ffff0a000001")
    t, out = 1_700_000_000.0, []

    def add(frame, dt=0.5):
        nonlocal t
        t += dt
        out.append((t, bytes(frame)))

    # TCP handshake + HTTP request with Host/path, TLS ClientHello with SNI
    add(_eth(_ip4("10.0.0.5", "203.0.113.10", 6, _tcp(50001, 80, dpkt.tcp.TH_SYN))))
    add(_eth(_ip4("203.0.113.10", "10.0.0.5", 6, _tcp(80, 50001, dpkt.tcp.TH_SYN | dpkt.tcp.TH_ACK))))
    add(_eth(_ip4("10.0.0.5", "203.0.113.10", 6, _tcp(50001, 80, data=b"GET /index.html?q=1 HTTP/1.1\r\nHost: example.com\r\n\r\n"))))
    add(_eth(_ip4("10.0.0.5", "203.0.113.10", 6, _tcp(50002, 443, data=_client_hello("c2.example.net")))))
    # DNS query / response
    add(_eth(_ip4("10.0.0.5", "8.8.8.8", 17, _udp(53000, 53, _dns(7)))))
    add(_eth(_ip4("8.8.8.8", "10.0.0.5", 17, _udp(53, 53000, _dns(7, response=True)))))
    # ICMP echo, ICMP unreachable quoting the original header
    add(_eth(_ip4("10.0.0.5", "8.8.8.8", 1, dpkt.icmp.ICMP(type=8, data=dpkt.icmp.ICMP.Echo(id=1, seq=1, data=b"ping")))))
    quoted = bytes(_ip4("10.0.0.5", "8.8.8.8", 17, _udp(1, 2, b"x" * 40)))[:28]
    add(_eth(_ip4("8.8.8.8", "10.0.0.5", 1, dpkt.icmp.ICMP(type=3, data=b"\x00" * 4 + quoted))))
    # IPv6 TCP/UDP/ICMPv6, IPv4-mapped source, hop-by-hop extension header
    add(_eth(_ip6(v6a, v6b, 6, _tcp(40000, 443, data=_client_hello("v6.example.org"))), 0x86DD))
    add(_eth(_ip6(v6b, v6a, 17, _udp(53, 40001, _dns(9, response=True))), 0x86DD))
    add(_eth(_ip6(v6a, v6b, 58, b"\x80\x00\x00\x00\x00\x01\x00\x01pong"), 0x86DD))
    add(_eth(_ip6(mapped, v6b, 17, _udp(1000, 2000, b"m")), 0x86DD))
    add(_eth(_ip6(v6a, v6b, 0, b"\x06\x00\x01\x04\x00\x00\x00\x00" + bytes(_tcp(40002, 22, dpkt.tcp.TH_SYN))), 0x86DD))
    # VLAN, QinQ, triple tag, MPLS
    add(_eth(_ip4("10.0.0.6", "203.0.113.20", 17, _udp(1111, 2222, b"vlan")), tags=(0x8100,)))
    add(_eth(_ip4("10.0.0.6", "203.0.113.20", 6, _tcp(1112, 8080)), tags=(0x88A8, 0x8100)))
    add(_eth(_ip4("10.0.0.6", "203.0.113.20", 6, _tcp(1113, 8080)), tags=(0x8100, 0x8100, 0x8100)))
    add(_eth(b"\x00\x01\x01\x40" + bytes(_ip4("10.0.0.6", "203.0.113.20", 17, _udp(1114, 53))), 0x8847))
    # tunnels and fragments: IP-in-IP, GRE, non-first fragment
    add(_eth(_ip4("10.0.0.6", "203.0.113.20", 4, _ip4("10.0.0.5", "8.8.8.8", 17, _udp(5, 6, b"inner")))))
    gre = struct.pack(">HH", 0, 0x0800) + bytes(_ip4("10.0.0.5", "8.8.8.8", 1, dpkt.icmp.ICMP(type=8, data=b"x" * 120)))
    add(_eth(_ip4("10.0.0.6", "203.0.113.20", 47, gre)))
    add(_eth(_ip4("10.0.0.6", "203.0.113.20", 17, _udp(7, 8, b"frag" * 10), _flags_offset=0x0010)))
    # truncated / garbage frames
    full = _eth(_ip4("10.0.0.5", "203.0.113.10", 6, _tcp(50003, 8443, data=b"z" * 50)))
    for cut in (5, 13, 30, 40, 54):
        add(full[:cut])
    add(random.Random(1).randbytes(60))
    add(_eth(b"\x00\x01\x08\x00\x06\x04\x00\x01" + b"\x00" * 20, 0x0806))  # ARP
    # anomaly rules: C2 port (TCP + UDP on the same ports are deduplicated), internal admin port
    add(_eth(_ip4("10.0.0.9", "198.51.100.66", 6, _tcp(51000, 4444))))
    add(_eth(_ip4("10.0.0.9", "198.51.100.66", 17, _udp(51000, 4444, b"c2"))))
    add(_eth(_ip4("10.0.0.10", "10.0.0.20", 6, _tcp(52000, 445, dpkt.tcp.TH_SYN))))
    for i in range(35):  # DNS tunnel: many large DNS packets
        add(_eth(_ip4("10.0.0.7", "8.8.8.8", 17, _udp(5353, 53, b"A" * 300))), 0.01)
    for i in range(90):  # beaconing: small packets over > 30 s
        add(_eth(_ip4("10.0.0.5", "203.0.113.10", 6, _tcp(50010, 8443, data=b"hb"))), 1.0)
    for i in range(250):  # packet flood: > 300 pps
        add(_eth(_ip4("10.0.0.6", "203.0.113.20", 17, _udp(9000, 9999, b"f"))), 0.001)
    for port in range(1, 41):  # SYN scan: >= 30 ports
        add(_eth(_ip4("10.0.0.66", "10.0.0.99", 6, _tcp(40000, port, dpkt.tcp.TH_SYN))), 0.001)
    add(_eth(_ip4("10.0.0.5", "203.0.113.10", 6, _tcp(50001, 80))), -100.0)  # clock going backwards
    if bulk:  # bulk exfil: > 10 MB in < 40 packets (IP total length 0, as with TSO)
        for i in range(35):
            tcp = bytes(_tcp(40000, 443, data=b"\x00" * 300_000))
            add(_eth(struct.pack(">BBHHHBBH4s4s", 0x45, 0, 0, 0, 0, 64, 6, 0, V4["10.0.0.8"], V4["198.51.100.7"]) + tcp), 0.01)
    return out


def _write_pcap(path, frames, nano=False):
    with open(path, "wb") as f:
        w = dpkt.pcap.Writer(f, snaplen=65535, nano=nano)
        for ts, frame in frames:
            w.writepkt(frame, ts=ts)


def _write_pcapng(path, frames, tsresol=None):
    idb = None
    if tsresol is not None:
        opts = [dpkt.pcapng.PcapngOptionLE(code=dpkt.pcapng.PCAPNG_OPT_IF_TSRESOL, data=bytes([tsresol])),
                dpkt.pcapng.PcapngOptionLE(code=dpkt.pcapng.PCAPNG_OPT_ENDOFOPT)]
        idb = dpkt.pcapng.InterfaceDescriptionBlockLE(snaplen=65535, opts=opts)
    with open(path, "wb") as f:
        w = dpkt.pcapng.Writer(f, snaplen=65535, idb=idb)
        for ts, frame in frames:
            w.writepkt(frame, ts=ts)


# ---------------------------------------------------------------- tests


def test_parity_mixed_capture(tmp_path):
    path = tmp_path / "mixed.pcap"
    frames = _frames()
    _write_pcap(path, frames)
    ref = _check_parity(path)
    indicators = {a["indicator"] for a in ref["anomalies"]}
    assert indicators == {
        "known_c2_port", "internal_admin_port", "dns_tunnel_pattern", "beaconing_pattern",
        "bulk_exfil_pattern", "packet_flood_pattern", "syn_scan_pattern",
    }
    assert sum(a["indicator"] == "known_c2_port" for a in ref["anomalies"]) == 1  # TCP/UDP pair deduplicated
    srcs = {f["src_ip"] for f in ref["events"]}
    assert {"2001:db8::1", "::ffff:10.0.0.1"} <= srcs
    assert any(f["src_port"] is None and f["proto"] == "TCP" for f in ref["events"])  # truncated TCP header
    assert ref["summary"]["total_packets"] == len(frames)


@pytest.mark.parametrize("tsresol", [None, 9])
def test_parity_pcapng(tmp_path, tsresol):
    path = tmp_path / "mixed.pcapng"
    _write_pcapng(path, _frames(bulk=False), tsresol=tsresol)
    ref = _check_parity(path)
    assert ref["summary"]["flow_count"] > 40


def test_parity_nanosecond_pcap(tmp_path):
    path = tmp_path / "nano.pcap"
    _write_pcap(path, _frames(bulk=False)[:60], nano=True)
    ref = _check_parity(path)
    assert isinstance(ref["flows"][0]["first_ts"], Decimal)


def test_parity_packet_and_flow_caps(tmp_path, monkeypatch):
    path = tmp_path / "caps.pcap"
    _write_pcap(path, _frames(bulk=False))
    monkeypatch.setattr(na, "PCAP_MAX_PACKETS", 100)
    monkeypatch.setattr(na, "PCAP_MAX_TRACKED_FLOWS", 12)
    ref = _check_parity(path)
    assert ref["summary"]["packets_truncated"] is True
    assert ref["summary"]["total_packets"] == 100
    assert ref["summary"]["flow_count"] == 12 and ref["summary"]["dropped_new_flows"] > 0


def _pcap_bytes(frames):
    buf = io.BytesIO()
    w = dpkt.pcap.Writer(buf, snaplen=65535)
    for ts, frame in frames:
        w.writepkt(frame, ts=ts)
    return buf.getvalue()


@pytest.mark.parametrize("name", [
    "empty", "short", "not_pcap", "header_only", "truncated_record", "truncated_data", "pcapng_bad_version", "missing",
])
def test_parity_errors_and_edge_files(tmp_path, name):
    good = _pcap_bytes(_frames(bulk=False)[:5])
    content = {
        "empty": b"",
        "short": b"\xd4\xc3\xb2",
        "not_pcap": b"this is not a valid pcap file",
        "header_only": good[:24],
        "truncated_record": good[:24 + 16 + 54 + 7],
        "truncated_data": good[:-10],
        "pcapng_bad_version": struct.pack("<IIIHHq", 0x0A0D0D0A, 28, 0x1A2B3C4D, 2, 0, -1) + struct.pack("<I", 28),
    }.get(name)
    path = tmp_path / f"{name}.pcap"
    if content is not None:
        path.write_bytes(content)
    ref = _check_parity(path)
    assert ("error" in ref["summary"]) == (name not in ("header_only", "truncated_data"))


def test_fuzz_random_and_truncated_captures_never_crash(tmp_path):
    """Random bytes, truncations, bit flips and mangled frames: a result dict (and parity) on both engines."""
    rng = random.Random(1234)
    frames = _frames(bulk=False)
    pcap = _pcap_bytes(frames)
    ng_path = tmp_path / "base.pcapng"
    _write_pcapng(ng_path, frames[:80])
    pcapng = ng_path.read_bytes()
    path = tmp_path / "fuzz.pcap"
    flows = 0
    for i in range(400):
        base = rng.choice([pcap, pcapng])
        kind = i % 4
        if kind == 0:
            data = rng.randbytes(rng.randrange(0, 600))
        elif kind == 1:
            data = base[: rng.randrange(0, len(base))]
        elif kind == 2:
            data = bytearray(base)
            for _ in range(rng.randrange(1, 40)):
                data[rng.randrange(24, len(data))] = rng.getrandbits(8)
            data = bytes(data)
        else:  # valid file framing, mangled frames: exercises the L2-L4 decoders
            mangled = []
            for ts, frame in rng.sample(frames, 60):
                frame = bytearray(frame[: rng.randrange(0, len(frame) + 1)] if rng.random() < 0.3 else frame)
                for _ in range(rng.randrange(0, 6)):
                    if frame:
                        frame[rng.randrange(len(frame))] = rng.getrandbits(8)
                mangled.append((ts, bytes(frame)))
            data = _pcap_bytes(mangled)
        path.write_bytes(data)
        ref = _check_parity(path)
        assert set(ref) == {"summary", "events", "flows", "anomalies"}
        flows += ref["summary"].get("flow_count", 0)
    assert flows > 1000  # the corpus really reaches the flow logic


@needs_native
def test_analyze_pcap_uses_rust_engine_and_logs_it(tmp_path, caplog):
    path = tmp_path / "small.pcap"
    _write_pcap(path, _frames(bulk=False)[:10])
    with caplog.at_level(logging.INFO, logger=na.__name__):
        result = na.analyze_pcap(str(path))
    assert "PCAP engine: rust" in caplog.text
    _assert_identical(na._analyze_pcap_python(str(path)), result)
