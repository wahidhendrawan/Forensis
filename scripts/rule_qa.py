#!/usr/bin/env python3
import argparse
import json
import os
import sys
from copy import deepcopy
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Dict, Tuple

ROOT_DIR = Path(__file__).resolve().parents[1]
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from forensis.analyzers.correlation_engine import correlate_recent_analyses
from forensis.analyzers.detection_pipeline import enrich_analysis_results
from forensis.analyzers.entity_profile import EntityProfileEngine
from forensis.analyzers.log_analyzer import analyze_logs
from forensis.analyzers.playbook_engine import analyze_generic_output
from forensis.analyzers.threat_intel import ThreatIntelEngine
from forensis.analyzers.yara_engine import YaraEngine


DEFAULT_EXPECTATIONS = {
    "logs_benign": {"max": {"threat_score": 6, "malicious_pattern_hits": 4}},
    "logs_malicious": {
        "min": {
            "threat_score": 12,
            "malicious_pattern_hits": 4,
            "threat_intel_hits": 1,
            "yara_hits": 1,
        }
    },
    "network_benign": {"max": {"threat_score": 6, "malicious_pattern_hits": 4}},
    "network_malicious": {
        "min": {
            "threat_score": 10,
            "malicious_pattern_hits": 2,
            "threat_intel_hits": 2,
            "yara_hits": 1,
        }
    },
    "memory_benign": {"max": {"threat_score": 6, "malicious_pattern_hits": 4}},
    "memory_malicious": {
        "min": {
            "threat_score": 10,
            "malicious_pattern_hits": 3,
            "yara_hits": 1,
        }
    },
    "cross_source": {"min": {"findings": 1}},
}


@dataclass
class _FakeHistory:
    id: int
    type: str
    timestamp: datetime
    _results: Dict

    def get_results(self):
        return self._results


def _load_text(path: Path) -> str:
    return path.read_text(encoding="utf-8", errors="ignore")


def _load_json(path: Path):
    with path.open("r", encoding="utf-8") as f:
        return json.load(f)


def _make_network_results(events):
    total_packets = 0
    for evt in events:
        try:
            total_packets += int(evt.get("packets", 0))
        except (TypeError, ValueError):
            continue
    return {
        "summary": {
            "total_packets": total_packets,
            "flow_count": len(events),
            "anomaly_count": 0,
            "severity_counts": {},
        },
        "events": events,
        "flows": events,
        "anomalies": [],
    }


def _extract_metrics(results: Dict) -> Dict[str, int]:
    summary = results.get("summary", {}) or {}
    return {
        "threat_score": int(summary.get("threat_score") or 0),
        "malicious_pattern_hits": int(summary.get("malicious_pattern_hits") or summary.get("anomaly_count") or 0),
        "threat_intel_hits": int(summary.get("threat_intel_hits") or 0),
        "threat_intel_score": int(summary.get("threat_intel_score") or 0),
        "yara_hits": int(summary.get("yara_hits") or 0),
        "baseline_deviation_hits": int(summary.get("baseline_deviation_hits") or 0),
        "allowlist_suppressed": int(summary.get("allowlist_suppressed") or 0),
        "anomaly_count": int(summary.get("anomaly_count") or 0),
    }


def _evaluate_thresholds(case_name: str, metrics: Dict[str, int], thresholds: Dict) -> Tuple[bool, list]:
    failures = []

    for key, expected_min in (thresholds.get("min", {}) or {}).items():
        actual = int(metrics.get(key, 0))
        if actual < int(expected_min):
            failures.append(f"{case_name}: {key} expected >= {expected_min}, got {actual}")

    for key, expected_max in (thresholds.get("max", {}) or {}).items():
        actual = int(metrics.get(key, 0))
        if actual > int(expected_max):
            failures.append(f"{case_name}: {key} expected <= {expected_max}, got {actual}")

    return len(failures) == 0, failures


def _load_expectations(path: Path) -> Dict:
    if not path.is_file():
        return deepcopy(DEFAULT_EXPECTATIONS)
    data = _load_json(path)
    if not isinstance(data, dict):
        return deepcopy(DEFAULT_EXPECTATIONS)
    merged = deepcopy(DEFAULT_EXPECTATIONS)
    for key, value in data.items():
        if isinstance(value, dict):
            merged[key] = value
    return merged


def run_qa(expectations_path: Path):
    datasets_dir = ROOT_DIR / "qa_datasets"
    engines = {
        "yara": YaraEngine(str(ROOT_DIR / "yara_rules")),
        "entity": EntityProfileEngine(str(ROOT_DIR / "config")),
    }
    engines["ti"] = ThreatIntelEngine(str(ROOT_DIR / "threat_intel"), allowlist_engine=engines["entity"])
    yara_available = bool(engines["yara"].available and getattr(engines["yara"], "_compiled", []))

    logs_benign = _load_text(datasets_dir / "logs" / "benign_web.log")
    logs_malicious = _load_text(datasets_dir / "logs" / "malicious_web.log")
    memory_benign = _load_text(datasets_dir / "memory" / "benign_memory.txt")
    memory_malicious = _load_text(datasets_dir / "memory" / "malicious_memory.txt")
    network_benign = _load_json(datasets_dir / "network" / "benign_events.json")
    network_malicious = _load_json(datasets_dir / "network" / "malicious_events.json")

    case_results = {}

    log_benign_results = analyze_logs(logs_benign, log_type="apache")
    case_results["logs_benign"] = enrich_analysis_results(
        log_benign_results,
        "logs",
        yara_engine=engines["yara"],
        threat_intel_engine=engines["ti"],
        entity_profile_engine=engines["entity"],
        raw_blob=logs_benign,
    )

    log_mal_results = analyze_logs(logs_malicious, log_type="apache")
    case_results["logs_malicious"] = enrich_analysis_results(
        log_mal_results,
        "logs",
        yara_engine=engines["yara"],
        threat_intel_engine=engines["ti"],
        entity_profile_engine=engines["entity"],
        raw_blob=logs_malicious,
    )

    net_benign_results = _make_network_results(network_benign)
    case_results["network_benign"] = enrich_analysis_results(
        net_benign_results,
        "network",
        yara_engine=engines["yara"],
        threat_intel_engine=engines["ti"],
        entity_profile_engine=engines["entity"],
        raw_blob=json.dumps(network_benign, default=str),
    )

    net_mal_results = _make_network_results(network_malicious)
    case_results["network_malicious"] = enrich_analysis_results(
        net_mal_results,
        "network",
        yara_engine=engines["yara"],
        threat_intel_engine=engines["ti"],
        entity_profile_engine=engines["entity"],
        raw_blob=json.dumps(network_malicious, default=str),
    )

    mem_benign_results = analyze_generic_output(memory_benign, input_name="benign_memory.txt")
    case_results["memory_benign"] = enrich_analysis_results(
        mem_benign_results,
        "memory",
        yara_engine=engines["yara"],
        threat_intel_engine=engines["ti"],
        entity_profile_engine=engines["entity"],
        raw_blob=memory_benign,
    )

    mem_mal_results = analyze_generic_output(memory_malicious, input_name="malicious_memory.txt")
    case_results["memory_malicious"] = enrich_analysis_results(
        mem_mal_results,
        "memory",
        yara_engine=engines["yara"],
        threat_intel_engine=engines["ti"],
        entity_profile_engine=engines["entity"],
        raw_blob=memory_malicious,
    )

    now = datetime.now(tz=timezone.utc)
    cross_records = [
        _FakeHistory(id=1, type="logs", timestamp=now - timedelta(minutes=18), _results=case_results["logs_malicious"]),
        _FakeHistory(id=2, type="network", timestamp=now - timedelta(minutes=12), _results=case_results["network_malicious"]),
        _FakeHistory(id=3, type="memory_triage", timestamp=now - timedelta(minutes=9), _results=case_results["memory_malicious"]),
    ]
    cross = correlate_recent_analyses(cross_records, window_minutes=60)

    expectations = _load_expectations(expectations_path)
    if not yara_available:
        for case_name, threshold in expectations.items():
            if not isinstance(threshold, dict):
                continue
            for bound in ("min", "max"):
                block = threshold.get(bound)
                if isinstance(block, dict):
                    block.pop("yara_hits", None)

    failures = []
    report = {"engine_status": {"yara_available": yara_available}}

    for case_name, result in case_results.items():
        metrics = _extract_metrics(result)
        report[case_name] = metrics
        ok, errs = _evaluate_thresholds(case_name, metrics, expectations.get(case_name, {}))
        if not ok:
            failures.extend(errs)

    cross_metrics = {"findings": int(cross.get("count", 0))}
    report["cross_source"] = cross_metrics
    ok, errs = _evaluate_thresholds("cross_source", cross_metrics, expectations.get("cross_source", {}))
    if not ok:
        failures.extend(errs)

    return report, failures


def main():
    parser = argparse.ArgumentParser(description="Run rule QA regression checks for Forensis detection engines.")
    parser.add_argument(
        "--expectations",
        default=str(ROOT_DIR / "qa_datasets" / "regression_expectations.json"),
        help="Path to regression expectation JSON.",
    )
    parser.add_argument("--json", action="store_true", help="Print machine-readable JSON report.")
    args = parser.parse_args()

    report, failures = run_qa(Path(args.expectations))

    if args.json:
        print(json.dumps({"report": report, "failures": failures}, indent=2))
    else:
        print("Rule QA Report")
        print("=" * 60)
        for case_name, metrics in report.items():
            print(f"- {case_name}")
            for key, value in sorted(metrics.items()):
                print(f"  {key}: {value}")
        print("=" * 60)
        if failures:
            print("STATUS: FAILED")
            for item in failures:
                print(f"  - {item}")
        else:
            print("STATUS: PASSED")

    if failures:
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
