"""
Parity tests for the optional Rust indicator extractor (forensis_core.extract_indicators) against the
Python reference (ThreatIntelEngine.extract_indicators). The Rust half is skipped when the extension isn't built.
"""
import copy
import random

import pytest

from forensis.analyzers import threat_intel as ti
from tests.test_pcap_engine import _assert_identical

needs_native = pytest.mark.skipif(ti._native_extract_indicators is None, reason="forensis_core extension not built")


@pytest.fixture
def engine(tmp_path):
    return ti.ThreatIntelEngine(str(tmp_path))


def _native(events):
    return ti._native_extract_indicators(
        events, ti.IP_REGEX.pattern, ti.DOMAIN_REGEX.pattern,
        [ti.SHA256_REGEX.pattern, ti.SHA1_REGEX.pattern, ti.MD5_REGEX.pattern],
    )


def _check_parity(engine, events):
    ref = [engine.extract_indicators(e) for e in events]
    if ti._native_extract_indicators is not None:
        _assert_identical(ref, _native(events))
    return ref


PAYLOADS = [
    "conn from 185.220.101.1 to 10.0.0.5:443", "999.1.1.1", "1.2.3.4.5", "v1.2.3.4x", "٤.٤.٤.٤",
    "GET http://pastebin-malware.example/x.php", "mail.Evil-Corp.co.uk.", "a..b", "-bad.com", "x.y", "x.toolongtldabcdefghijklmnopqrstuvwxyz",
    "44D88612FEA8A8F36DE82E1278ABB02F", "da39a3ee5e6b4b0d3255bfef95601890afd80709",
    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", "xe3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef00",
    "café.fr", "İΣ ΣΑΣ.com", "KELVIN K.com", "ſ.net", "日本語.jp", "\U0001F600.io", "x\x1cy.com", "\u0085pad.org\u0085",
    "a_b.com", "_a.com", "a.b_c", "1.2.3.4\n5.6.7.8", "a.b\tc.d",
]
DIRECT = [None, "", "   ", " 1.2.3.4 ", "Evil.COM", "no dot", "host.name ", "a.b c", 10, 1.5, True, {"k": "v"}, ["x.y"], "\udcff.com", " \udcff ", "\ud800"]
TEXT_KEYS = ["message", "raw", "path", "process", "uri"]


def _random_event(rng):
    evt = {}
    for k in rng.sample(["ip", "src_ip", "dst_ip", "host", "domain"], rng.randint(0, 5)):
        evt[k] = rng.choice(DIRECT)
    for k in rng.sample(TEXT_KEYS, rng.randint(0, 5)):
        n = rng.randint(0, 4)
        evt[k] = rng.choice([None, 7, {"m": "x"}, " ".join(rng.choice(PAYLOADS) for _ in range(n))])
    return evt


def test_fixed_events_parity(engine):
    events = [
        {},
        {"ip": None, "host": None, "message": None},
        {"ip": " 1.2.3.4 ", "host": "Evil.COM", "message": "conn to 8.8.8.8 from EVIL.com hash 44D88612FEA8A8F36DE82E1278ABB02F"},
        {"src_ip": "1.2.3.4", "dst_ip": "1.2.3.4", "raw": "1.2.3.4 1.2.3.4", "domain": "a.b c"},
        {"message": "İΣ ΣΑΣ.com KELVIN K.com ſ.net"},
        {"ip": "\udcff", "host": "\udcff.com", "message": "lone \udcff surrogate 9.9.9.9"},
        {"path": 0, "process": {"n": 1}, "uri": 1.5},
    ]
    ref = _check_parity(engine, events)
    assert ref[0] == []
    assert ref[1] == [("ip", "none")]  # str(None)
    assert ref[2] == [("ip", "1.2.3.4"), ("domain", "evil.com"), ("ip", "8.8.8.8"), ("hash", "44d88612fea8a8f36de82e1278abb02f")]
    assert ref[3] == [("ip", "1.2.3.4")]
    assert ref[5][:2] == [("ip", "\udcff"), ("domain", "\udcff.com")]


def test_text_cut_at_500000_chars(engine):
    text = "é" * 499_990 + " 1.1.1.1 " + "2.2.2.2"
    events = [{"message": text}, {"raw": "x" * 500_000 + "3.3.3.3"}]
    ref = _check_parity(engine, events)
    assert ref[0] == [("ip", "1.1.1.1")] and ref[1] == []


def test_fuzz_parity(engine):
    rng = random.Random(1234)
    events = [_random_event(rng) for _ in range(3000)]
    ref = _check_parity(engine, events)
    assert any(ref), "fuzz produced no indicators at all"


def test_batches_and_order(engine):
    # more than one native batch (256) keeps the per-event order
    events = [{"ip": str(i), "message": "x.com" if i % 3 == 0 else "no"} for i in range(900)]
    ref = _check_parity(engine, events)
    assert [r[0][1] for r in ref] == [str(i) for i in range(900)]


@needs_native
def test_native_rejects_non_dict_events():
    with pytest.raises(TypeError):
        _native([{"a": 1}, "not a dict"])


def test_enrich_events_parity(engine, monkeypatch):
    rng = random.Random(7)
    events = [_random_event(rng) for _ in range(300)]
    events += [
        {"ip": "185.220.101.1", "message": "pastebin-malware.example served 44d88612fea8a8f36de82e1278abb02f"},
        {"src_ip": "45.95.147.9", "host": "sub.pastebin-malware.example"},
        {"message": "nothing here"},
    ]
    with_engine = engine.enrich_events(copy.deepcopy(events), "logs")
    monkeypatch.setattr(ti, "_native_extract_indicators", None)
    pure_events = copy.deepcopy(events)
    pure = engine.enrich_events(pure_events, "logs")
    monkeypatch.undo()
    assert pure["hit_count"] >= 3
    _assert_identical(pure, with_engine)
    enriched = copy.deepcopy(events)
    engine.enrich_events(enriched, "logs")
    _assert_identical(pure_events, enriched, "events")
