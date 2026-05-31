"""
T16: Compliance report generator
Loads compliance_rules.yaml (CIS v8, SOC 2 Type II, ISO 27001:2022),
maps each control's rule_ids to open alert findings, and produces a
structured pass/fail report per framework.
"""

import logging
import os
import yaml
from datetime import datetime, timezone
from typing import Dict, List, Optional

logger = logging.getLogger(__name__)

_DEFAULT_RULES_FILE = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "detection", "compliance_rules.yaml",
)

SEV_RANK = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0}


class ComplianceEngine:
    def __init__(self, rules_file: str = _DEFAULT_RULES_FILE):
        self.rules_file = rules_file
        self.frameworks: List[Dict] = []
        self._load()

    def _load(self) -> None:
        try:
            with open(self.rules_file) as fh:
                data = yaml.safe_load(fh) or {}
            self.frameworks = data.get("frameworks", [])
            logger.info("Loaded %d compliance frameworks from %s", len(self.frameworks), self.rules_file)
        except Exception as e:
            logger.error("Failed to load compliance rules: %s", e)
            self.frameworks = []

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def assess(self, alerts: List[Dict], framework_id: Optional[str] = None) -> Dict:
        """
        Assess compliance against all frameworks (or a single one).

        alerts: list of alert dicts from alerts.json (rule_id, severity, status, …)
        framework_id: optional "CIS" | "SOC2" | "ISO27001" to filter

        Returns a report dict suitable for JSON serialisation.
        """
        # Build a lookup: rule_id → list of open alerts
        open_by_rule: Dict[str, List[Dict]] = {}
        for a in alerts:
            if a.get("status", "OPEN") == "RESOLVED":
                continue
            rid = a.get("rule_id") or ""
            if rid:
                open_by_rule.setdefault(rid, []).append(a)

        frameworks = [
            f for f in self.frameworks
            if framework_id is None or f.get("id") == framework_id
        ]

        report_frameworks = []
        for fw in frameworks:
            fw_result = self._assess_framework(fw, open_by_rule)
            report_frameworks.append(fw_result)

        total_controls = sum(f["total_controls"] for f in report_frameworks)
        passing = sum(f["passing"] for f in report_frameworks)
        failing = sum(f["failing"] for f in report_frameworks)

        return {
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "total_controls": total_controls,
            "passing": passing,
            "failing": failing,
            "pass_rate": round(passing / total_controls * 100, 1) if total_controls else 0,
            "frameworks": report_frameworks,
        }

    # ------------------------------------------------------------------
    # Internals
    # ------------------------------------------------------------------

    def _assess_framework(self, framework: Dict, open_by_rule: Dict[str, List[Dict]]) -> Dict:
        controls = framework.get("controls", [])
        assessed = []

        for ctrl in controls:
            ctrl_result = self._assess_control(ctrl, open_by_rule)
            assessed.append(ctrl_result)

        passing = sum(1 for c in assessed if c["status"] == "PASS")
        failing = sum(1 for c in assessed if c["status"] == "FAIL")
        warning = sum(1 for c in assessed if c["status"] == "WARNING")

        total = len(assessed)
        pass_rate = round(passing / total * 100, 1) if total else 0

        return {
            "id": framework.get("id"),
            "name": framework.get("name"),
            "total_controls": total,
            "passing": passing,
            "failing": failing,
            "warning": warning,
            "pass_rate": pass_rate,
            "status": "PASS" if failing == 0 else "FAIL",
            "controls": assessed,
        }

    def _assess_control(self, control: Dict, open_by_rule: Dict[str, List[Dict]]) -> Dict:
        rule_ids: List[str] = control.get("rule_ids", [])
        findings: List[Dict] = []

        for rid in rule_ids:
            for alert in open_by_rule.get(rid, []):
                findings.append({
                    "rule_id": rid,
                    "severity": alert.get("severity", "LOW"),
                    "title": alert.get("title", ""),
                    "resource_id": alert.get("resource_id") or (alert.get("log_excerpt") or {}).get("resource_id", ""),
                    "timestamp": alert.get("timestamp", ""),
                })

        critical = sum(1 for f in findings if f["severity"] == "CRITICAL")
        high = sum(1 for f in findings if f["severity"] == "HIGH")

        if not rule_ids:
            status = "NOT_APPLICABLE"
        elif not findings:
            status = "PASS"
        elif critical > 0 or high > 0:
            status = "FAIL"
        else:
            status = "WARNING"

        return {
            "id": control.get("id"),
            "title": control.get("title"),
            "description": control.get("description"),
            "category": control.get("category"),
            "severity": control.get("severity"),
            "status": status,
            "total_findings": len(findings),
            "critical_findings": critical,
            "high_findings": high,
            "findings": findings,
        }
