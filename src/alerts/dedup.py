"""
T15: Alert deduplication & cooldown
Dedup key: (rule_id, resource_id).
Within each cooldown window only the highest-severity alert is kept.
Successive windows that cross the cooldown boundary each produce one alert.
"""

import logging
from datetime import datetime, timezone
from typing import Dict, List, Tuple

logger = logging.getLogger(__name__)

SEV_RANK = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0}


def _resource_id(alert: Dict) -> str:
    rid = alert.get("resource_id")
    if not rid:
        rid = (alert.get("log_excerpt") or {}).get("resource_id", "")
    return rid or ""


def _parse_ts(alert: Dict):
    ts_str = alert.get("timestamp", "")
    if not ts_str:
        return None
    try:
        ts = datetime.fromisoformat(ts_str.replace("Z", "+00:00"))
        if ts.tzinfo is None:
            ts = ts.replace(tzinfo=timezone.utc)
        return ts
    except Exception:
        return None


class AlertDeduplicator:
    def __init__(self, cooldown_minutes: int = 60):
        self.cooldown_minutes = cooldown_minutes

    def deduplicate(self, alerts: List[Dict]) -> List[Dict]:
        """
        Deduplicate alerts by (rule_id, resource_id).
        Within a cooldown window, the highest-severity alert wins.
        Returns a new list; input is not mutated.
        """
        # Group by dedup key
        groups: Dict[Tuple, List[Dict]] = {}
        ungrouped: List[Dict] = []
        for a in alerts:
            rule_id = a.get("rule_id") or ""
            res_id = _resource_id(a)
            if rule_id:
                key = (rule_id, res_id)
                groups.setdefault(key, []).append(a)
            else:
                ungrouped.append(a)

        result: List[Dict] = list(ungrouped)

        for group in groups.values():
            if len(group) == 1:
                result.append(group[0])
                continue

            # Sort by timestamp ascending
            group.sort(key=lambda a: (a.get("timestamp") or ""))

            window_start = _parse_ts(group[0])
            window_best = group[0]

            for a in group[1:]:
                ts = _parse_ts(a)
                in_window = (
                    ts is None
                    or window_start is None
                    or (ts - window_start).total_seconds() / 60 <= self.cooldown_minutes
                )
                if in_window:
                    if SEV_RANK.get(a.get("severity", "LOW"), 0) > SEV_RANK.get(window_best.get("severity", "LOW"), 0):
                        window_best = a
                else:
                    result.append(window_best)
                    window_start = ts
                    window_best = a

            result.append(window_best)

        logger.info(
            "Deduplication: %d → %d alerts (%d suppressed, cooldown=%dmin)",
            len(alerts), len(result), len(alerts) - len(result), self.cooldown_minutes,
        )
        return result

    def stats(self, original: List[Dict], deduped: List[Dict]) -> Dict:
        return {
            "original_count": len(original),
            "deduped_count": len(deduped),
            "suppressed": len(original) - len(deduped),
            "cooldown_minutes": self.cooldown_minutes,
        }
