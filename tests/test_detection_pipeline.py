"""enrich_analysis_results: engine outputs become anomalies, counts and summary fields; engines may fail."""
from forensis.analyzers.detection_pipeline import enrich_analysis_results


class FakeTI:
    def __init__(self, hits):
        self.hits = hits

    def enrich_events(self, events, analysis_type):
        return {"hit_count": len(self.hits), "total_score": 10 * len(self.hits), "top_indicators": [["1.2.3.4", 2]],
                "severity_counts": {"high": len(self.hits)}, "hits": self.hits}


class FakeBaseline:
    def evaluate_events(self, events, analysis_type):
        return {"anomalies": [{"reason": "New host", "severity": "LOW", "indicator": "baseline_new_entity", "event": {"raw": "host=x"}}],
                "suppressed": 3, "count": 1}


class FakeYara:
    def __init__(self):
        self.blobs = []

    def scan_text(self, blob, source, max_hits):
        self.blobs.append(blob)
        return [{"rule": "Webshell", "rule_file": "web.yar", "meta": {"severity": "weird"}, "strings": [{"sample": "eval("}, {"sample": "base64"}, {"sample": "x"}]}]

    def match_summary(self, hits):
        return {"total_hits": len(hits), "top_rules": [["Webshell", 1]], "engine_available": True, "loaded_rule_files": 2}


class Raising:
    def enrich_events(self, *a):
        raise RuntimeError("ti down")

    evaluate_events = enrich_events
    scan_text = enrich_events

    def match_summary(self, hits):
        return {}


def _results():
    return {
        "summary": {"malicious_pattern_hits": 2, "severity_counts": {"HIGH": "1", "bogus": "x"}},
        "events": [{"ip": "1.2.3.4", "message": "GET /shell.php"}, {"ip": "5.6.7.8", "raw": "second"}],
        "anomalies": [{"reason": "Existing", "severity": "high", "indicator": "sql_injection", "event": {"raw": "GET /shell.php"}}],
    }


def test_without_engines_normalizes_summary():
    out = enrich_analysis_results(_results(), "logs")
    s = out["summary"]
    assert s["severity_counts"] == {"high": 1}  # non-numeric count dropped, key lower-cased
    assert s["anomaly_count"] == s["engine_anomaly_count"] == 1
    assert s["malicious_pattern_hits"] == s["detected_signal_hits"] == 2 and s["parser_signal_hits"] == 2
    assert s["threat_score"] == 3
    assert s["threat_intel_hits"] == 0 and s["yara_hits"] == 0 and s["yara_engine_available"] is False
    assert s["baseline_deviation_hits"] == 0 and s["allowlist_suppressed"] == 0


def test_engines_add_deduplicated_anomalies():
    hit = {"name": "Bad IP", "indicator_type": "ip", "indicator_value": "1.2.3.4", "severity": "HIGH", "event_index": 1}
    yara = FakeYara()
    out = enrich_analysis_results(_results(), "logs", yara_engine=yara, threat_intel_engine=FakeTI([hit, dict(hit)]), entity_profile_engine=FakeBaseline())
    reasons = [a["reason"] for a in out["anomalies"]]
    assert reasons == ["Existing", "Threat intel match: Bad IP (ip=1.2.3.4)", "New host", "YARA match: Webshell"]
    ti = out["anomalies"][1]
    assert ti["event"] is out["events"][1] and ti["category"] == "threat_intel"
    yara_item = out["anomalies"][3]
    assert yara_item["severity"] == "high" and yara_item["event"]["message"] == "eval(, base64"  # unknown severity -> high, 2 samples
    s = out["summary"]
    assert s["severity_counts"] == {"high": 3, "low": 1}
    assert s["anomaly_count"] == 4 and s["malicious_pattern_hits"] == 4 and s["threat_score"] == 10
    assert s["threat_intel_hits"] == 2 and s["threat_intel_score"] == 20 and s["ti_top_indicators"] == [["1.2.3.4", 2]]
    assert s["yara_hits"] == 1 and s["yara_top_rules"] == [["Webshell", 1]] and s["yara_engine_available"] is True and s["yara_loaded_rule_files"] == 2
    assert s["baseline_deviation_hits"] == 1 and s["allowlist_suppressed"] == 3
    assert yara.blobs == ["GET /shell.php | 1.2.3.4\nsecond | 5.6.7.8"]  # built from events when no raw_blob


def test_raw_blob_is_scanned_as_is():
    yara = FakeYara()
    enrich_analysis_results(_results(), "logs", yara_engine=yara, raw_blob="RAW")
    assert yara.blobs == ["RAW"]


def test_preexisting_anomaly_is_not_duplicated_by_engine():
    results = _results()
    results["anomalies"] = [{"reason": "New host", "severity": "low", "indicator": "baseline_new_entity", "event": {"raw": "host=x"}}]
    out = enrich_analysis_results(results, "logs", entity_profile_engine=FakeBaseline())
    assert len(out["anomalies"]) == 1 and out["summary"]["severity_counts"] == {"high": 1}


def test_failing_engines_do_not_break_the_analysis():
    out = enrich_analysis_results(_results(), "logs", yara_engine=Raising(), threat_intel_engine=Raising(), entity_profile_engine=Raising())
    s = out["summary"]
    assert len(out["anomalies"]) == 1 and s["threat_intel_hits"] == 0 and s["yara_hits"] == 0 and s["baseline_deviation_hits"] == 0


def test_non_dict_results_pass_through():
    assert enrich_analysis_results(None, "logs") is None
    assert enrich_analysis_results([1], "logs") == [1]
