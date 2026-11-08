"""correlate_recent_analyses: identities seen by more than one analysis type inside the window become findings."""
from datetime import datetime, timedelta

from forensis.analyzers.correlation_engine import correlate_recent_analyses

T0 = datetime(2026, 1, 1, 12, 0, 0)


class Rec:
    def __init__(self, id, type, minutes, results):
        self.id, self.type, self.timestamp, self._results = id, type, T0 + timedelta(minutes=minutes), results

    def get_results(self):
        if self._results == "boom":
            raise RuntimeError("corrupt")
        return self._results


def _logs(ip, score=10, indicator="sql_injection"):
    return {"events": [{"ip": ip}], "summary": {"threat_score": score, "threat_intel_score": 5, "top_sources": [[ip, 3]]},
            "anomalies": [{"indicator": indicator}]}


def _net(ip, score=20):
    return {"events": [{"src_ip": ip, "dst_ip": "unknown"}], "summary": {"threat_score": score, "yara_top_rules": [["Beacon", 1]]}, "anomalies": []}


def test_cross_source_identity_becomes_a_finding():
    out = correlate_recent_analyses([Rec(1, "logs", 0, _logs("10.0.0.1")), Rec(2, "network", 30, _net("10.0.0.1"))])
    assert out["count"] == 1
    f = out["findings"][0]
    assert f["identity"] == "10.0.0.1" and f["sources"] == ["logs", "network"]
    assert f["risk_score"] == 15 + 20 and f["related_analysis_ids"] == [1, 2]
    assert f["first_seen"] == T0.isoformat() and f["last_seen"] == (T0 + timedelta(minutes=30)).isoformat()
    assert f["sample_indicators"] == ["sql_injection", "yara:Beacon"] and f["indicator_count"] == 2
    assert out["severity_counts"] == {"medium": 1}


def test_single_source_or_outside_window_is_ignored():
    same = [Rec(1, "logs", 0, _logs("10.0.0.1")), Rec(2, "log analysis", 1, _logs("10.0.0.1"))]
    assert correlate_recent_analyses(same)["count"] == 0
    far = [Rec(1, "logs", 0, _logs("10.0.0.1")), Rec(2, "network", 61, _net("10.0.0.1"))]
    assert correlate_recent_analyses(far, window_minutes=60)["count"] == 0
    assert correlate_recent_analyses(far, window_minutes=120)["count"] == 1


def test_bad_records_and_placeholder_identities_are_skipped():
    recs = [
        Rec(1, "logs", 0, "boom"),
        Rec(2, "logs", 0, {"events": [{"ip": "unknown"}, {"host": "-"}], "summary": {}}),
        Rec(3, "network", 0, _net("10.0.0.9")),
    ]
    no_ts = Rec(4, "logs", 0, _logs("10.0.0.9"))
    no_ts.timestamp = None
    assert correlate_recent_analyses(recs + [no_ts])["count"] == 0


def test_severity_buckets_and_dedup_keep_highest_score():
    recs = [Rec(1, "logs", 0, _logs("A", score=100)), Rec(2, "network", 5, _net("A", score=1)), Rec(3, "memory", 10, {"events": [{"host": "A"}], "summary": {"threat_score": 0}})]
    out = correlate_recent_analyses(recs)
    assert [f["sources"] for f in out["findings"]] == [["logs", "memory", "network"], ["memory", "network"]]
    assert out["findings"][0]["risk_score"] == 106 and out["severity_counts"] == {"critical": 1, "low": 1}
