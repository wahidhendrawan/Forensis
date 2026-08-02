"""
Test suite for analyzers and parsers.
Feeds known-good and malformed input from qa_datasets/ to analyzer functions
and asserts they parse without crashing and produce expected structure.
"""
import os
import json
import pytest

from forensis.analyzers.log_analyzer import analyze_logs
from forensis.analyzers.playbook_engine import analyze_generic_output, get_playbook
from forensis.analyzers.network_analyzer import analyze_pcap
from forensis.analyzers.entity_profile import EntityProfileEngine
from forensis.services.rule_service import select_sigma_candidate_events, extract_result_summary

QA_DIR = os.path.join(os.path.dirname(__file__), "..", "qa_datasets")


def _read_dataset(*parts):
    with open(os.path.join(QA_DIR, *parts), "r", encoding="utf-8") as f:
        return f.read()


class TestLogAnalyzer:
    """Tests for the log analyzer."""

    def test_benign_log_low_threat(self):
        """Benign web log should produce a low threat score."""
        text = _read_dataset("logs", "benign_web.log")
        result = analyze_logs(text, log_type="apache")

        assert "summary" in result
        assert "events" in result
        assert "anomalies" in result
        assert result["summary"]["parsed_events"] > 0
        # Benign traffic should have a low threat score per regression expectations
        assert result["summary"]["threat_score"] <= 6

    def test_malicious_log_detects_attacks(self):
        """Malicious web log should detect multiple attack patterns."""
        text = _read_dataset("logs", "malicious_web.log")
        result = analyze_logs(text, log_type="apache")

        assert result["summary"]["parsed_events"] > 0
        assert result["summary"]["anomaly_count"] >= 3
        assert result["summary"]["threat_score"] >= 12

        # Verify specific attack indicators are detected
        indicators = {a.get("indicator") for a in result["anomalies"]}
        assert "sql_injection" in indicators
        assert "xss_payload" in indicators
        assert "log4shell_probe" in indicators
        # Rules are first-match-per-event; whoami is classified as command injection
        # before the overlapping webshell rule is evaluated.
        assert "command_injection" in indicators

    def test_empty_input_no_crash(self):
        """Empty input should not crash and return a valid structure."""
        result = analyze_logs("", log_type="generic")
        assert result["summary"]["parsed_events"] == 0
        assert result["anomalies"] == []
        assert result["events"] == []

    def test_malformed_input_no_crash(self):
        """Malformed/garbage input should be handled gracefully."""
        garbage = "\x00\x01\x02 not a log line ][{}!@#\n\n random text 12345"
        result = analyze_logs(garbage, log_type="apache")
        # Should fall back to generic parsing without exceptions
        assert "summary" in result
        assert isinstance(result["events"], list)

    def test_csv_parsing(self):
        """CSV log format should be parsed into events."""
        csv_text = "ip,status,message\n10.0.0.1,200,ok\n10.0.0.2,404,not found\n"
        result = analyze_logs(csv_text, log_type="csv")
        assert result["summary"]["parsed_events"] >= 2

    def test_bruteforce_correlation(self):
        """Repeated auth failures from one source should trigger correlation."""
        lines = "\n".join(
            f'1.2.3.4 - - [30/May/2026:12:00:0{i} +0000] "GET /login HTTP/1.1" 401 80'
            for i in range(6)
        )
        result = analyze_logs(lines, log_type="apache")
        indicators = {a.get("indicator") for a in result["anomalies"]}
        assert "bruteforce_pattern" in indicators


class TestMemoryAnalyzer:
    """Tests for generic output analyzer (memory triage)."""

    def test_benign_memory_low_threat(self):
        """Benign memory sample should produce low threat score."""
        text = _read_dataset("memory", "benign_memory.txt")
        result = analyze_generic_output(text, input_name="benign_memory.txt")

        assert "summary" in result
        assert "suspicious" in result
        assert "events" in result
        assert result["summary"]["threat_score"] <= 6

    def test_malicious_memory_detects_credential_access(self):
        """Malicious memory sample should detect mimikatz/credential dumping."""
        text = _read_dataset("memory", "malicious_memory.txt")
        result = analyze_generic_output(text, input_name="malicious_memory.txt")

        assert result["summary"]["suspicious_hits"] >= 3
        assert result["summary"]["threat_score"] >= 10

        keywords = {s.get("keyword") for s in result["suspicious"]}
        assert "mimikatz" in keywords
        assert "encoded powershell" in keywords

    def test_empty_memory_no_crash(self):
        """Empty memory input should not crash."""
        result = analyze_generic_output("", input_name="empty.txt")
        assert result["summary"]["suspicious_hits"] == 0
        assert result["suspicious"] == []

    def test_json_records_parsing(self):
        """JSON structured output should be parsed into records."""
        blob = json.dumps(
            [
                {"process": "explorer.exe", "pid": 1200},
                {"process": "cmd.exe", "pid": 3100},
            ]
        )
        result = analyze_generic_output(blob, input_name="proc.json")
        assert result["summary"]["parsed_records"] == 2
        assert result["detected_format"] == "json"


class TestNetworkAnalyzer:
    """Tests for network analyzer and network event handling."""

    def test_analyze_pcap_invalid_file(self, tmp_path):
        """Invalid PCAP data should return an error structure, not crash."""
        bad_pcap = tmp_path / "bad.pcap"
        bad_pcap.write_bytes(b"this is not a valid pcap file")
        result = analyze_pcap(str(bad_pcap))
        assert "summary" in result
        assert "events" in result
        assert "flows" in result
        assert "anomalies" in result
        # dpkt may be absent (error) or reject invalid format
        assert "error" in result["summary"]

    def test_network_events_sigma_candidate_selection(self):
        """Malicious network events should feed into sigma candidate selection."""
        events = json.loads(_read_dataset("network", "malicious_events.json"))
        results = {"events": events, "anomalies": [], "flows": events}
        candidates = select_sigma_candidate_events(results, "network", limit=50)
        assert len(candidates) >= 2
        # C2 port destination should be present in candidate set
        dst_ports = {str(c.get("dst_port")) for c in candidates}
        assert "4444" in dst_ports

    def test_benign_network_events_structure(self):
        """Benign network events should be well-formed and summarizable."""
        events = json.loads(_read_dataset("network", "benign_events.json"))
        results = {"events": events, "anomalies": [], "flows": events, "summary": {}}
        summary = extract_result_summary(results)
        assert summary["event_count"] == len(events)
        assert summary["anomaly_count"] == 0


class TestEntityProfileEngine:
    """Tests for the entity baseline / allowlist engine."""

    def test_baseline_deviation_detects_bad_port(self, tmp_path):
        """Events on non-baseline ports should be flagged."""
        engine = EntityProfileEngine(str(tmp_path))
        events = [
            {"src_ip": "10.0.0.1", "dst_port": 4444, "proto": "TCP"},
        ]
        result = engine.evaluate_events(events, "network")
        indicators = {a.get("indicator") for a in result["anomalies"]}
        assert "unknown_port" in indicators

    def test_allowlisted_ip_suppressed(self, tmp_path):
        """Allowlisted loopback IPs should be counted as suppressed."""
        engine = EntityProfileEngine(str(tmp_path))
        events = [{"src_ip": "127.0.0.1", "dst_port": 443, "proto": "TCP"}]
        result = engine.evaluate_events(events, "network")
        assert result["suppressed"] >= 1


class TestPlaybookEngine:
    """Tests for playbook generation."""

    def test_get_memory_playbook(self):
        """Memory playbook should return steps and events."""
        pb = get_playbook("memory", "windows.generic")
        assert pb is not None
        assert pb["tool"] == "volatility3"
        assert len(pb["steps"]) > 0
        assert len(pb["events"]) > 0

    def test_get_network_playbook(self):
        """Network playbook should be retrievable."""
        pb = get_playbook("network", "network.analysis.baseline")
        assert pb is not None
        assert len(pb["steps"]) > 0
