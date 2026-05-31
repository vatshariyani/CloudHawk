"""
T14: Alert severity scoring
Adds a numeric severity_score (0-100) to each alert combining:
  - Base weight from declared severity
  - Frequency amplifier: rules that fire many times score higher
  - Recency amplifier: alerts from the last hour score higher
Also computes an overall posture score for the fleet.
"""

import logging
from datetime import datetime, timezone
from typing import Dict, List

logger = logging.getLogger(__name__)

SEV_BASE = {"CRITICAL": 40, "HIGH": 30, "MEDIUM": 20, "LOW": 10, "INFO": 5}
SEV_RANK = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0}


class SeverityScorer:
    def __init__(self, cooldown_minutes: int = 60):
        self.cooldown_minutes = cooldown_minutes

    def score_alerts(self, alerts: List[Dict]) -> List[Dict]:
        """Return alerts sorted by severity_score desc, each enriched with severity_score."""
        if not alerts:
            return []

        # Count open hits per rule for frequency amplifier
        rule_hits: Dict[str, int] = {}
        for a in alerts:
            rid = a.get("rule_id") or ""
            rule_hits[rid] = rule_hits.get(rid, 0) + 1
        max_hits = max(rule_hits.values(), default=1)

        now = datetime.now(timezone.utc)
        scored = []
        for a in alerts:
            base = SEV_BASE.get(a.get("severity", "LOW"), 10)

            # Frequency bonus 0-30: proportional to how many times this rule fired
            freq_bonus = int(30 * (rule_hits.get(a.get("rule_id", ""), 1) / max_hits))

            # Recency bonus 0-30: full bonus within first hour, linear decay to 0 at cooldown
            recency_bonus = 0
            try:
                ts_str = a.get("timestamp", "")
                if ts_str:
                    ts = datetime.fromisoformat(ts_str.replace("Z", "+00:00"))
                    if ts.tzinfo is None:
                        ts = ts.replace(tzinfo=timezone.utc)
                    age_min = (now - ts).total_seconds() / 60
                    recency_bonus = max(0, int(30 * (1 - min(age_min / self.cooldown_minutes, 1))))
            except Exception:
                pass

            scored.append({**a, "severity_score": min(100, base + freq_bonus + recency_bonus)})

        scored.sort(key=lambda x: x["severity_score"], reverse=True)
        return scored

    @staticmethod
    def posture_score(alerts: List[Dict]) -> Dict:
        """Compute fleet posture score (0-100, higher = better) and letter grade."""
        if not alerts:
            return {"score": 100, "grade": "A", "breakdown": {}}

        counts: Dict[str, int] = {}
        for a in alerts:
            sev = a.get("severity", "LOW")
            counts[sev] = counts.get(sev, 0) + 1

        penalty = (
            counts.get("CRITICAL", 0) * 20
            + counts.get("HIGH", 0) * 10
            + counts.get("MEDIUM", 0) * 5
            + counts.get("LOW", 0) * 2
        )
        score = max(0, 100 - penalty)
        grade = (
            "A" if score >= 90 else
            "B" if score >= 80 else
            "C" if score >= 70 else
            "D" if score >= 60 else "F"
        )
        return {"score": score, "grade": grade, "breakdown": counts}
