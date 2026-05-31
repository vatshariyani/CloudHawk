import os
import json
import yaml
import logging
import threading
from queue import Queue, Empty
from datetime import datetime, timezone
from typing import List, Dict, Any, Optional

logger = logging.getLogger(__name__)

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ALERTS_DIR = os.path.join(BASE_DIR, "alerts")
ALERTS_FILE = os.path.join(ALERTS_DIR, "alerts.json")


class RuleEngine:
    def __init__(self, rules_file: str, events_file: str, threads: int = 4, chunk_size: int = 500):
        self.rules = self.load_rules(rules_file)
        self.events_file = events_file
        self.threads = threads
        self.chunk_size = chunk_size
        self.alerts: List[Dict] = []
        self.lock = threading.Lock()
        self.alerts_file = ALERTS_FILE

    # ------------------------------------------------------------------
    # Loading
    # ------------------------------------------------------------------

    def load_rules(self, rules_file: str) -> List[Dict]:
        try:
            with open(rules_file, "r") as f:
                rules_data = yaml.safe_load(f)
        except FileNotFoundError:
            logger.error(f"Rules file not found: {rules_file}")
            return []
        except yaml.YAMLError as e:
            logger.error(f"YAML parse error in rules file: {e}")
            return []

        if isinstance(rules_data, dict):
            rules = rules_data.get("rules", [rules_data])
        elif isinstance(rules_data, list):
            rules = rules_data
        else:
            logger.error(f"Invalid rules file format: {rules_file}")
            return []

        clean: List[Dict] = []
        for rule in rules:
            if not isinstance(rule, dict):
                logger.warning(f"Skipping non-dict rule: {rule}")
                continue
            if "id" not in rule:
                logger.warning(f"Skipping rule missing 'id': {rule}")
                continue
            # B10 fix: reject rules with null/missing condition
            if not rule.get("condition"):
                logger.warning(f"Skipping rule '{rule.get('id')}' — condition is null or missing")
                continue
            clean.append(rule)

        logger.info(f"Loaded {len(clean)} valid rules from {rules_file}")
        return clean

    def load_events(self) -> List[Dict]:
        try:
            with open(self.events_file, "r") as f:
                events = json.load(f)
        except FileNotFoundError:
            logger.warning(f"Events file not found: {self.events_file}")
            return []
        except json.JSONDecodeError as e:
            logger.error(f"Invalid JSON in events file: {e}")
            return []

        if not isinstance(events, list):
            logger.warning("Events file must contain a JSON array")
            return []

        logger.info(f"Loaded {len(events)} events from {self.events_file}")
        return events

    def save_alerts(self, alerts_file: Optional[str] = None) -> str:
        if alerts_file is None:
            alerts_file = self.alerts_file
        try:
            os.makedirs(os.path.dirname(alerts_file), exist_ok=True)
            payload = {
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "total_alerts": len(self.alerts),
                "rules_processed": len(self.rules),
                "alerts": self.alerts,
            }
            with open(alerts_file, "w") as f:
                json.dump(payload, f, indent=2, default=str)
            logger.info(f"Saved {len(self.alerts)} alerts to {alerts_file}")
            return alerts_file
        except Exception as e:
            logger.error(f"Failed to save alerts: {e}")
            return ""

    # ------------------------------------------------------------------
    # Condition evaluator
    # ------------------------------------------------------------------

    def evaluate_condition(self, event: Dict, condition: str) -> bool:
        """
        Evaluate a rule condition string against an event.

        Supported syntax:
          field == "value"      field != "value"
          field > N             field >= N    field < N    field <= N
          field == null         field != null
          field.contains("x")
          field in "a,b,c"      (exact CSV membership, not substring)
          field not in "a,b,c"
          <cond> and <cond>     <cond> or <cond>   (standard precedence: and > or)
        """
        try:
            return self._eval(event, condition.strip())
        except Exception as e:
            # B4 fix: log with rule context so broken conditions are visible
            logger.warning(f"Condition evaluation error for '{condition}': {e}")
            return False

    def _eval(self, event: Dict, condition: str) -> bool:
        # B1 fix: correct precedence — split on OR first, then AND within each OR branch
        # This gives standard precedence: AND binds tighter than OR.
        or_parts = self._split_top_level(condition, " or ")
        if len(or_parts) > 1:
            return any(self._eval_and(event, part.strip()) for part in or_parts)
        return self._eval_and(event, condition)

    def _eval_and(self, event: Dict, condition: str) -> bool:
        and_parts = self._split_top_level(condition, " and ")
        if len(and_parts) > 1:
            return all(self._eval_atom(event, part.strip()) for part in and_parts)
        return self._eval_atom(event, condition)

    @staticmethod
    def _split_top_level(condition: str, separator: str) -> List[str]:
        """Split on separator only outside quoted strings."""
        parts: List[str] = []
        depth = 0
        in_quote: Optional[str] = None
        current: List[str] = []
        i = 0
        sep_len = len(separator)
        while i < len(condition):
            ch = condition[i]
            if in_quote:
                current.append(ch)
                if ch == in_quote:
                    in_quote = None
            elif ch in ('"', "'"):
                in_quote = ch
                current.append(ch)
            elif ch == "(":
                depth += 1
                current.append(ch)
            elif ch == ")":
                depth -= 1
                current.append(ch)
            elif depth == 0 and condition[i:i + sep_len] == separator:
                parts.append("".join(current))
                current = []
                i += sep_len
                continue
            else:
                current.append(ch)
            i += 1
        parts.append("".join(current))
        return parts

    def _eval_atom(self, event: Dict, condition: str) -> bool:
        # null checks
        if condition.endswith(" == null"):
            field = condition[: -len(" == null")].strip()
            return self._get(event, field) is None
        if condition.endswith(" != null"):
            field = condition[: -len(" != null")].strip()
            return self._get(event, field) is not None

        # .contains()
        if ".contains(" in condition:
            # B5 fix: only strip the trailing ) to handle values with (
            dot_idx = condition.index(".contains(")
            field = condition[:dot_idx].strip()
            value = condition[dot_idx + len(".contains("):]
            if value.endswith(")"):
                value = value[:-1]
            value = value.strip().strip('"').strip("'")
            current = self._get(event, field)
            return current is not None and value in str(current)

        # not in / in  (check before comparison operators to avoid <= / >= confusion)
        if " not in " in condition:
            field, value = condition.split(" not in ", 1)
            return self._eval_membership(event, field.strip(), value.strip(), negate=True)
        if " in " in condition:
            field, value = condition.split(" in ", 1)
            return self._eval_membership(event, field.strip(), value.strip(), negate=False)

        # comparison operators — check multi-char ops before single-char
        for op in ("!=", ">=", "<=", "==", ">", "<"):
            if op in condition:
                field, value = condition.split(op, 1)
                field = field.strip()
                value = value.strip().strip('"').strip("'")
                current = self._get(event, field)
                if current is None:
                    return False
                return self._compare(current, op, value)

        logger.warning(f"Unrecognised condition syntax: '{condition}'")
        return False

    def _eval_membership(self, event: Dict, field: str, raw_value: str, negate: bool) -> bool:
        """B2 fix: exact CSV membership, not substring match."""
        current = self._get(event, field)
        raw_value = raw_value.strip().strip('"').strip("'")
        members = {m.strip() for m in raw_value.split(",")}
        is_member = str(current) in members if current is not None else False
        return (not is_member) if negate else is_member

    def _compare(self, current: Any, op: str, value: str) -> bool:
        # B3 fix: attempt numeric comparison only when both sides parse cleanly
        try:
            lhs = float(current)
            rhs = float(value)
            if op == "==":
                return lhs == rhs
            if op == "!=":
                return lhs != rhs
            if op == ">":
                return lhs > rhs
            if op == "<":
                return lhs < rhs
            if op == ">=":
                return lhs >= rhs
            if op == "<=":
                return lhs <= rhs
        except (ValueError, TypeError):
            pass
        # Fall back to string comparison
        lhs_s, rhs_s = str(current), str(value)
        if op == "==":
            return lhs_s == rhs_s
        if op == "!=":
            return lhs_s != rhs_s
        return False

    def _get(self, event: Dict, field_path: str) -> Any:
        """Resolve dot-notation field path against event dict."""
        current: Any = event
        for key in field_path.split("."):
            if isinstance(current, dict) and key in current:
                current = current[key]
            else:
                return None
        return current

    # ------------------------------------------------------------------
    # Processing
    # ------------------------------------------------------------------

    def process_chunk(self, chunk: List[Dict]) -> None:
        local_alerts: List[Dict] = []
        for event in chunk:
            for rule in self.rules:
                try:
                    if self.evaluate_condition(event, rule["condition"]):
                        local_alerts.append({
                            "timestamp": datetime.now(timezone.utc).isoformat(),
                            "rule_id": rule.get("id", "N/A"),
                            "title": rule.get("title", "No title"),
                            "description": rule.get("description", ""),
                            "severity": rule.get("severity", "INFO"),
                            "remediation": rule.get("remediation", ""),
                            "service": rule.get("service", "UNKNOWN"),
                            "log_excerpt": event,
                        })
                except Exception as e:
                    logger.error(f"Error processing rule '{rule.get('id')}': {e}")

        with self.lock:
            self.alerts.extend(local_alerts)

    def run(self) -> None:
        logger.info(f"Starting rule engine — {self.threads} threads, chunk size {self.chunk_size}")

        events = self.load_events()
        if not events:
            logger.warning("No events to process")
            return
        if not self.rules:
            logger.warning("No rules loaded")
            return

        logger.info(f"Processing {len(events)} events against {len(self.rules)} rules")

        q: Queue = Queue()
        for i in range(0, len(events), self.chunk_size):
            q.put(events[i: i + self.chunk_size])

        def worker() -> None:
            while True:
                try:
                    # B6 fix: only catch Empty, not all exceptions
                    chunk = q.get(timeout=1)
                    self.process_chunk(chunk)
                    q.task_done()
                except Empty:
                    break

        threads = []
        for i in range(self.threads):
            t = threading.Thread(target=worker, name=f"Worker-{i + 1}", daemon=True)
            t.start()
            threads.append(t)

        # B7 fix: wait for queue to drain before joining threads
        q.join()
        for t in threads:
            t.join()

        # T15: deduplicate before scoring and saving
        try:
            from alerts.dedup import AlertDeduplicator
            deduper = AlertDeduplicator(cooldown_minutes=60)
            self.alerts = deduper.deduplicate(self.alerts)
        except Exception as e:
            logger.warning(f"Deduplication unavailable: {e}")

        # T14: add numeric severity_score to each alert
        try:
            from detection.severity import SeverityScorer
            self.alerts = SeverityScorer().score_alerts(self.alerts)
        except Exception as e:
            logger.warning(f"Severity scoring unavailable: {e}")

        self.save_alerts()

        severity_counts: Dict[str, int] = {}
        for alert in self.alerts:
            sev = alert.get("severity", "UNKNOWN")
            severity_counts[sev] = severity_counts.get(sev, 0) + 1

        logger.info(
            f"Rule engine complete — {len(events)} events, "
            f"{len(self.rules)} rules, {len(self.alerts)} alerts"
        )
        for sev, count in sorted(severity_counts.items()):
            logger.info(f"  {sev}: {count}")


if __name__ == "__main__":
    import sys

    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")

    rules_file = os.path.join(BASE_DIR, "detection", "security_rules.yaml")
    events_file = os.path.join(BASE_DIR, "logs", "aws_security_events_latest.json")

    if len(sys.argv) > 1:
        rules_file = sys.argv[1]
    if len(sys.argv) > 2:
        events_file = sys.argv[2]

    try:
        engine = RuleEngine(rules_file, events_file, threads=4, chunk_size=100)
        engine.run()
    except Exception as e:
        logger.error(f"Rule engine failed: {e}")
        sys.exit(1)
