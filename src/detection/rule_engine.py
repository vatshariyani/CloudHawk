import os
import json
import yaml
import threading
from queue import Queue
from datetime import datetime

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
LOG_FILE = os.path.join(BASE_DIR, "collector", "logs", "All_Logs.json")
RULES_FILE = os.path.join(BASE_DIR, "detection", "rules.yaml")
ALERTS_DIR = os.path.join(BASE_DIR, "alerts")
ALERTS_FILE = os.path.join(ALERTS_DIR, "alerts.json")

class RuleEngine:
    def __init__(self, rules_file, log_file, threads=4, chunk_size=500):
        self.rules = self.load_rules(rules_file)
        self.log_file = log_file
        self.threads = threads
        self.chunk_size = chunk_size
        self.alerts = []
        self.lock = threading.Lock()

    def load_rules(self, rules_file):
        with open(rules_file, "r") as f:
            rules = yaml.safe_load(f)
            # Ensure it's a list of dicts
            if isinstance(rules, dict):
                rules = [rules]
            clean_rules = []
            for r in rules:
                if isinstance(r, dict):
                    clean_rules.append(r)
                else:
                    print(f"⚠️ Skipping invalid rule: {r}")
            return clean_rules


    def load_logs(self):
        try:
            with open(self.log_file, "r") as f:
                return json.load(f)
        except FileNotFoundError:
            print(f"⚠️ Log file not found: {self.log_file}")
            return []
        except json.JSONDecodeError as e:
            print(f"⚠️ Invalid JSON in log file: {e}")
            return []
        except Exception as e:
            print(f"⚠️ Error loading logs: {e}")
            return []

    def save_alerts(self, alerts_file=ALERTS_FILE):
        try:
            # Ensure alerts directory exists
            os.makedirs(os.path.dirname(alerts_file), exist_ok=True)
            with open(alerts_file, "w") as f:
                json.dump(self.alerts, f, indent=2, default=str)
        except Exception as e:
            print(f"⚠️ Failed to save alerts: {e}")

    def evaluate_condition(self, log, condition: str) -> bool:
        """
        Evaluate conditions with support for multiple operators:
        - .contains("value")
        - ==, !=, >, <, >=, <=
        - and, or (basic support)
        - in, not in
        """
        try:
            # Handle complex conditions with and/or
            if " and " in condition:
                parts = condition.split(" and ")
                return all(self.evaluate_condition(log, part.strip()) for part in parts)
            elif " or " in condition:
                parts = condition.split(" or ")
                return any(self.evaluate_condition(log, part.strip()) for part in parts)
            
            # Handle .contains() operator
            if ".contains(" in condition:
                field, value = condition.split(".contains(")
                value = value.strip(")").strip('"').strip("'")
                keys = field.split(".")
                
                # Traverse nested log object
                current = log
                for k in keys:
                    if isinstance(current, dict) and k in current:
                        current = current[k]
                    else:
                        return False
                
                # Handle list/dict -> convert to string
                return value in str(current)
            
            # Handle comparison operators
            operators = ["!=", ">=", "<=", "==", ">", "<"]
            for op in operators:
                if op in condition:
                    field, value = condition.split(op, 1)
                    field, value = field.strip(), value.strip().strip('"').strip("'")
                    keys = field.split(".")
                    
                    # Traverse nested log object
                    current = log
                    for k in keys:
                        if isinstance(current, dict) and k in current:
                            current = current[k]
                        else:
                            return False
                    
                    # Convert to appropriate type for comparison
                    try:
                        if op in [">", "<", ">=", "<="]:
                            # Numeric comparison
                            current_val = float(current) if str(current).replace('.', '').replace('-', '').isdigit() else 0
                            compare_val = float(value) if value.replace('.', '').replace('-', '').isdigit() else 0
                        else:
                            # String comparison
                            current_val = str(current)
                            compare_val = str(value)
                        
                        if op == "==":
                            return current_val == compare_val
                        elif op == "!=":
                            return current_val != compare_val
                        elif op == ">":
                            return current_val > compare_val
                        elif op == "<":
                            return current_val < compare_val
                        elif op == ">=":
                            return current_val >= compare_val
                        elif op == "<=":
                            return current_val <= compare_val
                    except (ValueError, TypeError):
                        return False
            
            # Handle "in" and "not in" operators
            if " not in " in condition:
                field, value = condition.split(" not in ")
                field, value = field.strip(), value.strip().strip('"').strip("'")
                keys = field.split(".")
                
                current = log
                for k in keys:
                    if isinstance(current, dict) and k in current:
                        current = current[k]
                    else:
                        return True  # Field doesn't exist, so "not in" is true
                
                return str(current) not in str(value)
            elif " in " in condition:
                field, value = condition.split(" in ")
                field, value = field.strip(), value.strip().strip('"').strip("'")
                keys = field.split(".")
                
                current = log
                for k in keys:
                    if isinstance(current, dict) and k in current:
                        current = current[k]
                    else:
                        return False
                
                return str(current) in str(value)
            
            return False
        except Exception as e:
            print(f"⚠️ Condition evaluation failed for '{condition}': {e}")
            return False

    def process_chunk(self, chunk):
        local_alerts = []
        for log in chunk:
            for rule in self.rules:
                if not isinstance(rule, dict) or "condition" not in rule:
                    continue  # skip bad entries
                if self.evaluate_condition(log, rule["condition"]):
                    alert = {
                        "timestamp": datetime.utcnow().isoformat(),
                        "rule_id": rule.get("id", "N/A"),
                        "title": rule.get("title", "No title"),
                        "description": rule.get("description", ""),
                        "severity": rule.get("severity", "INFO"),
                        "remediation": rule.get("remediation", ""),
                        "log_excerpt": log,
                    }
                    local_alerts.append(alert)

        with self.lock:
            self.alerts.extend(local_alerts)


    def run(self):
        logs = self.load_logs()
        q = Queue()

        # Split logs into chunks
        for i in range(0, len(logs), self.chunk_size):
            q.put(logs[i : i + self.chunk_size])

        def worker():
            while True:
                try:
                    chunk = q.get(timeout=1)  # Use timeout instead of get_nowait
                except:
                    break
                self.process_chunk(chunk)
                q.task_done()

        threads = []
        for _ in range(self.threads):
            t = threading.Thread(target=worker)
            t.start()
            threads.append(t)

        for t in threads:
            t.join()

        self.save_alerts()


if __name__ == "__main__":
    engine = RuleEngine(RULES_FILE, LOG_FILE, threads=8, chunk_size=500)
    engine.run()
    print(f"✅ Detection complete. Alerts saved in {ALERTS_FILE}")
