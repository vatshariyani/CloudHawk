"""
T28: Tests for the rule engine condition evaluator, rule loading, and the
Phase 3 detection helpers (severity scoring, deduplication, compliance).
"""

import pytest

from detection.rule_engine import RuleEngine
from detection.severity import SeverityScorer
from alerts.dedup import AlertDeduplicator
from compliance.compliance_engine import ComplianceEngine


# ---------------------------------------------------------------------------
# Condition evaluator
# ---------------------------------------------------------------------------
@pytest.fixture
def engine(rules_file, tmp_path):
    # events_file can be empty; we test evaluate_condition directly
    events = tmp_path / "events.json"
    events.write_text("[]")
    return RuleEngine(rules_file, str(events), threads=1, chunk_size=10)


class TestEvaluateCondition:
    def test_equality(self, engine):
        assert engine.evaluate_condition({"source": "AWS_S3"}, 'source == "AWS_S3"')
        assert not engine.evaluate_condition({"source": "AWS_EC2"}, 'source == "AWS_S3"')

    def test_inequality(self, engine):
        assert engine.evaluate_condition({"x": "a"}, 'x != "b"')
        assert not engine.evaluate_condition({"x": "b"}, 'x != "b"')

    def test_numeric_comparison(self, engine):
        assert engine.evaluate_condition({"port": 22}, "port == 22")
        assert engine.evaluate_condition({"port": 100}, "port > 50")
        assert engine.evaluate_condition({"port": 10}, "port < 50")
        assert engine.evaluate_condition({"port": 50}, "port >= 50")
        assert engine.evaluate_condition({"port": 50}, "port <= 50")

    def test_dot_notation(self, engine):
        ev = {"sg": {"cidr": "0.0.0.0/0", "from_port": 22}}
        assert engine.evaluate_condition(ev, 'sg.cidr == "0.0.0.0/0"')
        assert engine.evaluate_condition(ev, "sg.from_port == 22")

    def test_null_checks(self, engine):
        assert engine.evaluate_condition({"a": 1}, "missing == null")
        assert engine.evaluate_condition({"a": 1}, "a != null")
        assert not engine.evaluate_condition({"a": 1}, "a == null")

    def test_contains(self, engine):
        assert engine.evaluate_condition({"desc": "open to world"}, 'desc.contains("world")')
        assert not engine.evaluate_condition({"desc": "private"}, 'desc.contains("world")')

    def test_in_membership(self, engine):
        assert engine.evaluate_condition({"port": "3306"}, 'port in "3306, 5432, 1433"')
        assert not engine.evaluate_condition({"port": "22"}, 'port in "3306, 5432"')

    def test_not_in_membership(self, engine):
        assert engine.evaluate_condition({"port": "22"}, 'port not in "3306, 5432"')
        assert not engine.evaluate_condition({"port": "3306"}, 'port not in "3306, 5432"')

    def test_and_precedence(self, engine):
        ev = {"a": "1", "b": "2"}
        assert engine.evaluate_condition(ev, 'a == "1" and b == "2"')
        assert not engine.evaluate_condition(ev, 'a == "1" and b == "9"')

    def test_or_precedence(self, engine):
        ev = {"a": "1", "b": "2"}
        assert engine.evaluate_condition(ev, 'a == "9" or b == "2"')
        assert not engine.evaluate_condition(ev, 'a == "9" or b == "9"')

    def test_and_binds_tighter_than_or(self, engine):
        # a==1 and b==9  → False ; or c==3 → True
        ev = {"a": "1", "b": "2", "c": "3"}
        assert engine.evaluate_condition(ev, 'a == "1" and b == "9" or c == "3"')

    def test_missing_field_is_false(self, engine):
        assert not engine.evaluate_condition({}, 'nothere == "x"')

    def test_malformed_condition_returns_false(self, engine):
        assert not engine.evaluate_condition({"a": 1}, "this is not valid syntax")


# ---------------------------------------------------------------------------
# Rule loading
# ---------------------------------------------------------------------------
class TestLoadRules:
    def test_loads_valid_rules(self, engine):
        assert len(engine.rules) == 2
        assert {r["id"] for r in engine.rules} == {"EC2-SG-001", "S3-PUB-001"}

    def test_skips_rule_without_condition(self, tmp_path):
        bad = tmp_path / "bad.yaml"
        bad.write_text("rules:\n  - id: NO-COND\n    title: x\n")
        ev = tmp_path / "e.json"
        ev.write_text("[]")
        eng = RuleEngine(str(bad), str(ev))
        assert eng.rules == []

    def test_missing_file_returns_empty(self, tmp_path):
        ev = tmp_path / "e.json"
        ev.write_text("[]")
        eng = RuleEngine(str(tmp_path / "nope.yaml"), str(ev))
        assert eng.rules == []


# ---------------------------------------------------------------------------
# Processing (end-to-end against events)
# ---------------------------------------------------------------------------
class TestProcessing:
    def test_process_chunk_generates_alerts(self, engine, sample_events):
        engine.process_chunk(sample_events)
        rule_ids = {a["rule_id"] for a in engine.alerts}
        assert "EC2-SG-001" in rule_ids
        assert "S3-PUB-001" in rule_ids

    def test_alert_carries_log_excerpt(self, engine, sample_events):
        engine.process_chunk([sample_events[0]])
        assert engine.alerts
        assert engine.alerts[0]["log_excerpt"] == sample_events[0]


# ---------------------------------------------------------------------------
# T14: severity scoring
# ---------------------------------------------------------------------------
class TestSeverityScorer:
    def test_score_added_and_bounded(self, sample_alerts):
        scored = SeverityScorer().score_alerts(sample_alerts)
        assert all(0 <= a["severity_score"] <= 100 for a in scored)

    def test_sorted_descending(self, sample_alerts):
        scored = SeverityScorer().score_alerts(sample_alerts)
        scores = [a["severity_score"] for a in scored]
        assert scores == sorted(scores, reverse=True)

    def test_critical_outranks_medium(self, sample_alerts):
        scored = SeverityScorer().score_alerts(sample_alerts)
        crit = next(a for a in scored if a["severity"] == "CRITICAL")
        med = next(a for a in scored if a["severity"] == "MEDIUM")
        assert crit["severity_score"] > med["severity_score"]

    def test_empty_input(self):
        assert SeverityScorer().score_alerts([]) == []

    def test_posture_score_perfect_when_empty(self):
        result = SeverityScorer.posture_score([])
        assert result["score"] == 100
        assert result["grade"] == "A"

    def test_posture_score_penalises(self, sample_alerts):
        result = SeverityScorer.posture_score(sample_alerts)
        assert result["score"] < 100
        assert result["grade"] in {"A", "B", "C", "D", "F"}


# ---------------------------------------------------------------------------
# T15: deduplication
# ---------------------------------------------------------------------------
class TestDeduplicator:
    def test_collapses_same_rule_resource_in_window(self, sample_alerts):
        # two EC2-SG-001 / sg-001 alerts 5 min apart → collapse to 1
        deduped = AlertDeduplicator(cooldown_minutes=60).deduplicate(sample_alerts)
        ec2 = [a for a in deduped if a["rule_id"] == "EC2-SG-001"]
        assert len(ec2) == 1

    def test_keeps_highest_severity_in_window(self, sample_alerts):
        deduped = AlertDeduplicator(cooldown_minutes=60).deduplicate(sample_alerts)
        ec2 = next(a for a in deduped if a["rule_id"] == "EC2-SG-001")
        assert ec2["severity"] == "CRITICAL"

    def test_distinct_rules_preserved(self, sample_alerts):
        deduped = AlertDeduplicator(cooldown_minutes=60).deduplicate(sample_alerts)
        assert any(a["rule_id"] == "IAM-USER-001" for a in deduped)

    def test_separate_windows_kept(self, sample_alerts):
        # tiny cooldown → the 5-min-apart pair becomes two separate alerts
        deduped = AlertDeduplicator(cooldown_minutes=1).deduplicate(sample_alerts)
        ec2 = [a for a in deduped if a["rule_id"] == "EC2-SG-001"]
        assert len(ec2) == 2

    def test_stats(self, sample_alerts):
        d = AlertDeduplicator(cooldown_minutes=60)
        deduped = d.deduplicate(sample_alerts)
        stats = d.stats(sample_alerts, deduped)
        assert stats["original_count"] == 3
        assert stats["suppressed"] == len(sample_alerts) - len(deduped)


# ---------------------------------------------------------------------------
# T16: compliance engine
# ---------------------------------------------------------------------------
class TestComplianceEngine:
    def test_loads_three_frameworks(self):
        engine = ComplianceEngine()
        ids = {f["id"] for f in engine.frameworks}
        assert {"CIS", "SOC2", "ISO27001"} <= ids

    def test_assess_returns_all_frameworks(self, sample_alerts):
        report = ComplianceEngine().assess(sample_alerts)
        assert len(report["frameworks"]) == 3
        assert 0 <= report["pass_rate"] <= 100

    def test_filter_single_framework(self, sample_alerts):
        report = ComplianceEngine().assess(sample_alerts, framework_id="ISO27001")
        assert len(report["frameworks"]) == 1
        assert report["frameworks"][0]["id"] == "ISO27001"

    def test_open_critical_fails_control(self, sample_alerts):
        # EC2-SG-001 (CRITICAL, open) maps into ISO 8.20 Network Security → FAIL
        report = ComplianceEngine().assess(sample_alerts, framework_id="ISO27001")
        controls = {c["id"]: c for c in report["frameworks"][0]["controls"]}
        assert controls["8.20"]["status"] == "FAIL"

    def test_no_findings_passes(self):
        report = ComplianceEngine().assess([], framework_id="CIS")
        fw = report["frameworks"][0]
        assert fw["failing"] == 0
        assert fw["status"] == "PASS"

    def test_resolved_alerts_ignored(self, sample_alerts):
        for a in sample_alerts:
            a["status"] = "RESOLVED"
        report = ComplianceEngine().assess(sample_alerts, framework_id="ISO27001")
        assert report["frameworks"][0]["failing"] == 0
