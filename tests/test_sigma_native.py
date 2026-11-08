"""
Parity tests for the optional Rust Sigma matcher (forensis_core.correlate_sigma) against the Python
reference (sigma_engine._CompiledRule.match). The Rust half is skipped when the extension isn't built.
"""
import random

import pytest

from forensis.analyzers import sigma_engine as se
from tests.test_pcap_engine import _assert_identical

needs_native = pytest.mark.skipif(se._native_correlate is None, reason="forensis_core extension not built")


def _engine(tmp_path, monkeypatch, detections):
    monkeypatch.setattr(se.SigmaEngine, "_ensure_sigmahq_baseline", lambda self: None)
    eng = se.SigmaEngine(str(tmp_path))
    eng.rules = [se.SigmaRule({"title": f"r{i}", "id": str(i), "level": "low", "detection": d}) for i, d in enumerate(detections)]
    return eng


def _check_parity(eng, events, monkeypatch, **limits):
    with_engine = eng.correlate_events(events, **limits)
    monkeypatch.setattr(se, "_native_correlate", None)
    pure = eng.correlate_events(events, **limits)
    monkeypatch.undo()
    _assert_identical(pure, with_engine)
    return pure


FIELDS = ["Image", "CommandLine", "User", "EventID", "message", "process.cmd", "Empty", "Spaces"]
VALUES = ["C:\\Windows\\System32\\cmd.exe", "powershell -enc AAAA", "MIMIKATZ.exe sekurlsa::logonpasswords", "", "   ",
          "notepad.exe", 4624, 1, None, True, 1.5, "caf\u00e9 \u0130\u03a3", "a*b?c", "x\x1cy", "\u0085pad\u0085", "[abc]", "line1\nline2"]
MODS = ["", "|contains", "|contains|all", "|eq", "|exact", "|startswith", "|endswith", "|re", "|gt", "|lt", "|windash", "|cidr"]
EXPECTED = ["cmd.exe", "CMD", "*.exe", "power?hell", "*", "?", "", " ", "4624", "1", "mimikatz", "sekurlsa::", "[abc]", "[a-c]*", "a*b", "\\.exe$", "(?i)notepad", "(", "1e3", "caf\u00e9", "\u0130\u03a3", "\u0131", "x\x1cy", "pad", "line1*line2", "none", "true"]
CONDS = ["selection", "sel_a", "1 of them", "all of them", "1 of sel_*", "all of sel_*", "sel_a and sel_b", "sel_a or sel_b",
         "sel_a or sel_b and sel_c", "(sel_a or sel_b) and sel_c", "not sel_a", "SELECTION", "", "nope", "1 of x*", "all of x*"]


def _random_detection(rng):
    det = {}
    for name in rng.sample(["selection", "sel_a", "sel_b", "sel_c", "filter"], rng.randint(0, 3)):
        sel = {}
        for _ in range(rng.randint(0, 3)):
            key = rng.choice(FIELDS) + rng.choice(MODS)
            if rng.random() < 0.1:
                key = rng.choice(["", "|contains", " Image |eq"])
            vals = [rng.choice(EXPECTED) for _ in range(rng.randint(0, 3))]
            sel[key] = vals if rng.random() < 0.5 else rng.choice(EXPECTED + [None, 7, True])
        det[name] = sel
    if rng.random() < 0.9:
        det["condition"] = rng.choice(CONDS)
    if rng.random() < 0.05:
        det["selection"] = "not a dict"
    return det


def _random_event(rng):
    evt = {}
    for f in rng.sample(FIELDS + ["image", "USER"], rng.randint(0, 6)):
        evt[f] = rng.choice(VALUES)
    if rng.random() < 0.3:
        evt["process"] = {"cmd": rng.choice(VALUES), "Image": rng.choice(VALUES)}
    if rng.random() < 0.05:
        return rng.choice(["not a dict", None, 3])
    return evt


def test_fixed_rules_parity(tmp_path, monkeypatch):
    detections = [
        {"selection": {"CommandLine|contains": "mimikatz"}},
        {"selection": {"Image|endswith": ["\\cmd.exe", "\\powershell.exe"], "User": "admin"}, "condition": "selection"},
        {"sel_a": {"EventID": 4624}, "sel_b": {"message|re": "logon\\s+ok"}, "condition": "sel_a and sel_b"},
        {"sel_a": {"Image": "*\\notepad.exe"}, "sel_b": {"Image": "[nN]otepad*"}, "condition": "1 of sel_*"},
        {"selection": {"EventID|gt": "4000"}},
        {"selection": {"Spaces": " "}},
        {"selection": {"": "x"}},
        {"selection": {"Empty": "x", "empty": "y"}},
        {"selection": {"process.cmd|startswith": "whoami"}, "condition": "all of them"},
        {"selection": {"CommandLine|contains|all": ["enc", "nothing-here"]}},
        {"condition": "selection"},
        {"selection": "oops"},
    ]
    eng = _engine(tmp_path, monkeypatch, detections)
    assert [r.compiled.native for r in eng.rules] == [True, True, False, False, False, True, True, True, True, True, True, True]
    events = [
        {"CommandLine": "C:\\Tools\\MIMIKATZ.EXE", "Image": "C:\\Windows\\System32\\cmd.exe", "User": "Admin", "EventID": 4624, "message": "Logon   OK"},
        {"Image": "c:\\notepad.exe", "EventID": "4688", "Spaces": "   ", "Empty": "", "empty": "x"},
        {"process": {"cmd": "whoami /all"}, "CommandLine": "powershell -enc AAAA"},
        "not a dict",
        {},
    ]
    pure = _check_parity(eng, events, monkeypatch)
    hits = {(m["event_index"], m["rule_id"]) for m in pure}
    assert {(0, "0"), (0, "1"), (0, "2"), (0, "4"), (1, "3"), (2, "9")} <= hits
    # " " strips to nothing, "" is never a field name, nested keys flatten to "cmd" not "process.cmd"
    assert all(m["rule_id"] not in {"5", "6", "8", "10", "11"} for m in pure)


def test_fuzz_parity(tmp_path, monkeypatch):
    rng = random.Random(42)
    eng = _engine(tmp_path, monkeypatch, [_random_detection(rng) for _ in range(300)])
    assert any(r.compiled.native for r in eng.rules) and any(not r.compiled.native for r in eng.rules)
    events = [_random_event(rng) for _ in range(400)]
    pure = _check_parity(eng, events, monkeypatch)
    assert pure, "fuzz produced no matches at all"
    for max_events, max_matches in [(50, None), (None, 25), (120, 7), (3, 1)]:
        _check_parity(eng, events, monkeypatch, max_events=max_events, max_matches=max_matches)


def test_match_event_api_is_reference(tmp_path, monkeypatch):
    rule = se.SigmaRule({"title": "t", "detection": {"selection": {"CommandLine": "whoami"}}})
    assert rule.match_event({"CommandLine": "cmd /c WHOAMI"})
    assert not rule.match_event({"commandline": ""})


@needs_native
def test_native_rejects_non_native_mode():
    with pytest.raises(ValueError):
        se._native_correlate([{"a": "b"}], [([[("a", "a", [("regex", "b")])]], ("sel", 0))], None)
