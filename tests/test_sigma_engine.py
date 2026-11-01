"""
Sigma engine tests: rule matcher basics and remote rule sync SSRF guards.
"""

import socket
from types import SimpleNamespace

import pytest

from forensis.analyzers import sigma_engine
from forensis.analyzers.sigma_engine import SigmaEngine, SigmaRule


def _rule(detection):
    return SigmaRule({"title": "t", "detection": detection})


class TestSigmaMatcher:
    def test_default_modifier_is_case_insensitive_contains(self):
        rule = _rule(
            {"selection": {"CommandLine": "MimiKatz"}, "condition": "selection"}
        )
        assert rule.match_event({"CommandLine": "C:\\tools\\mimikatz.exe"})
        assert not rule.match_event({"CommandLine": "notepad.exe"})
        assert not rule.match_event({"Image": "mimikatz.exe"})  # field missing

    @pytest.mark.parametrize(
        "field_expr, expected, value, hit",
        [
            ("Image|startswith", "c:\\windows", "C:\\Windows\\cmd.exe", True),
            ("Image|endswith", "\\cmd.exe", "C:\\Windows\\cmd.exe", True),
            ("Image|endswith", "\\cmd.exe", "C:\\cmd.exe.bak", False),
            ("Image|re", r"cmd\.(exe|com)$", "c:\\cmd.com", True),
            ("Image|eq", "cmd.exe", "xcmd.exe", False),
            ("bytes|gt", "100", "250", True),
            ("bytes|gt", "100", "50", False),
            ("Image", "*\\power*.exe", "C:\\powershell.exe", True),
        ],
    )
    def test_modifiers(self, field_expr, expected, value, hit):
        rule = _rule({"selection": {field_expr: expected}, "condition": "selection"})
        assert rule.match_event({field_expr.split("|")[0]: value}) is hit

    def test_list_values_are_or_and_fields_are_and(self):
        rule = _rule(
            {
                "selection": {"Image": ["cmd.exe", "powershell.exe"], "User": "admin"},
                "condition": "selection",
            }
        )
        assert rule.match_event({"Image": "powershell.exe", "User": "admin"})
        assert not rule.match_event({"Image": "powershell.exe", "User": "guest"})

    def test_conditions(self):
        detection = {"sel_a": {"a": "1"}, "sel_b": {"b": "2"}}
        both, only_a = {"a": "1", "b": "2"}, {"a": "1"}
        assert _rule({**detection, "condition": "sel_a and sel_b"}).match_event(both)
        assert not _rule({**detection, "condition": "sel_a and sel_b"}).match_event(
            only_a
        )
        assert _rule({**detection, "condition": "sel_a or sel_b"}).match_event(only_a)
        assert _rule({**detection, "condition": "1 of sel_*"}).match_event(only_a)
        assert not _rule({**detection, "condition": "all of them"}).match_event(only_a)
        assert not _rule({**detection, "condition": "unsupported_expr"}).match_event(
            both
        )

    def test_nested_event_fields_are_flattened(self):
        rule = _rule({"selection": {"cmd": "whoami"}, "condition": "selection"})
        assert rule.match_event({"process": {"cmd": "whoami /all"}})

    def test_correlate_events_respects_limits(self, tmp_path, monkeypatch):
        engine = _engine(tmp_path, monkeypatch)
        engine.rules = [_rule({"selection": {"msg": "bad"}, "condition": "selection"})]
        events = [{"msg": "bad"}] * 5 + ["not-a-dict"]
        assert len(engine.correlate_events(events)) == 5
        assert len(engine.correlate_events(events, max_events=2)) == 2
        assert len(engine.correlate_events(events, max_matches=3)) == 3


RULE_YAML = b"title: Remote rule\ndetection:\n  selection:\n    msg: evil\n  condition: selection\n"
PUBLIC_DNS = {
    "rules.example.org": "93.184.215.14",
    "mirror.example.org": "93.184.215.15",
}


def _engine(tmp_path, monkeypatch):
    monkeypatch.delenv("FORENSIS_SIGMA_URLS", raising=False)
    monkeypatch.setattr(SigmaEngine, "_ensure_sigmahq_baseline", lambda self: None)
    return SigmaEngine(str(tmp_path))


class _Resp:
    def __init__(self, status, body=b"", location=None):
        self.status_code = status
        self.headers = {"Location": location} if location else {}
        self.raw = SimpleNamespace(read=lambda n, decode_content=True: body[:n])

    def close(self):
        pass


@pytest.fixture
def fake_net(monkeypatch):
    """Fake DNS (hostnames above are public, IP literals resolve to themselves) and a scripted requests.get."""
    monkeypatch.setattr(
        sigma_engine.socket,
        "getaddrinfo",
        lambda host, *a, **k: [
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", (PUBLIC_DNS.get(host, host), 0))
        ],
    )
    routes, requested = {}, []

    def fake_get(url, **kwargs):
        assert kwargs.get("allow_redirects") is False
        requested.append(url)
        return routes[url]

    monkeypatch.setattr(sigma_engine.requests, "get", fake_get)
    return routes, requested


class TestRemoteSyncSSRF:
    def test_redirect_to_metadata_endpoint_is_not_followed(
        self, tmp_path, monkeypatch, fake_net
    ):
        routes, requested = fake_net
        routes["https://rules.example.org/r.yml"] = _Resp(
            302, location="http://169.254.169.254/latest/meta-data/"
        )
        engine = _engine(tmp_path, monkeypatch)

        assert engine.sync_from_urls(["https://rules.example.org/r.yml"]) == 0
        assert requested == ["https://rules.example.org/r.yml"]

    def test_redirect_to_private_network_is_not_followed(
        self, tmp_path, monkeypatch, fake_net
    ):
        routes, requested = fake_net
        routes["https://rules.example.org/r.yml"] = _Resp(
            301, location="http://10.0.0.5/r.yml"
        )
        engine = _engine(tmp_path, monkeypatch)

        assert engine.sync_from_urls(["https://rules.example.org/r.yml"]) == 0
        assert "http://10.0.0.5/r.yml" not in requested

    def test_redirect_to_public_host_is_followed(self, tmp_path, monkeypatch, fake_net):
        routes, requested = fake_net
        routes["https://rules.example.org/r.yml"] = _Resp(
            302, location="https://mirror.example.org/r.yml"
        )
        routes["https://mirror.example.org/r.yml"] = _Resp(200, RULE_YAML)
        engine = _engine(tmp_path, monkeypatch)

        assert engine.sync_from_urls(["https://rules.example.org/r.yml"]) == 1
        assert requested == [
            "https://rules.example.org/r.yml",
            "https://mirror.example.org/r.yml",
        ]

    def test_redirect_loop_is_bounded(self, tmp_path, monkeypatch, fake_net):
        routes, requested = fake_net
        routes["https://rules.example.org/r.yml"] = _Resp(302, location="/r.yml")
        engine = _engine(tmp_path, monkeypatch)

        assert engine.sync_from_urls(["https://rules.example.org/r.yml"]) == 0
        assert len(requested) == sigma_engine.MAX_REDIRECTS + 1

    def test_private_url_is_never_requested(self, tmp_path, monkeypatch, fake_net):
        _, requested = fake_net
        engine = _engine(tmp_path, monkeypatch)

        assert (
            engine.sync_from_urls(
                [
                    "http://127.0.0.1/r.yml",
                    "http://169.254.169.254/r.yml",
                    "file:///etc/passwd",
                ]
            )
            == 0
        )
        assert requested == []

    def test_oversized_body_is_rejected(self, tmp_path, monkeypatch, fake_net):
        routes, _ = fake_net
        routes["https://rules.example.org/r.yml"] = _Resp(
            200, RULE_YAML + b"#" * sigma_engine.MAX_REMOTE_RULE_BYTES
        )
        engine = _engine(tmp_path, monkeypatch)

        assert engine.sync_from_urls(["https://rules.example.org/r.yml"]) == 0
