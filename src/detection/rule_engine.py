import os
import json
import yaml
import threading
from queue import Queue
from datetime import datetime
from typing import List, Dict, Any, Optional

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ALERTS_DIR = os.path.join(BASE_DIR, "alerts")
ALERTS_FILE = os.path.join(ALERTS_DIR, "alerts.json")

class RuleEngine:
    def __init__(self, rules_file: str, events_file: str, threads: int = 4, chunk_size: int = 500):
        """
        Initialize Rule Engine for security event analysis
        
        Args:
            rules_file: Path to YAML file containing detection rules
            events_file: Path to JSON file containing security events
            threads: Number of worker threads for processing
            chunk_size: Number of events to process per chunk
        """
        self.rules = self.load_rules(rules_file)
        self.events_file = events_file
        self.threads = threads
        self.chunk_size = chunk_size
        self.alerts = []
        self.lock = threading.Lock()
        self.alerts_file = ALERTS_FILE

    def load_rules(self, rules_file: str) -> List[Dict]:
        """Load detection rules from YAML file"""
        try:
            with open(rules_file, "r") as f:
                rules_data = yaml.safe_load(f)
                
            # Handle different YAML structures
            if isinstance(rules_data, dict):
                if 'rules' in rules_data:
                    rules = rules_data['rules']
                else:
                    rules = [rules_data]
            elif isinstance(rules_data, list):
                rules = rules_data
            else:
                print(f"⚠️ Invalid rules file format: {rules_file}")
                return []
            
            # Validate and clean rules
            clean_rules = []
            for rule in rules:
                if isinstance(rule, dict) and 'id' in rule and 'condition' in rule:
                    clean_rules.append(rule)
                else:
                    print(f"⚠️ Skipping invalid rule: {rule}")
            
            print(f"✅ Loaded {len(clean_rules)} valid rules from {rules_file}")
            return clean_rules
            
        except FileNotFoundError:
            print(f"❌ Rules file not found: {rules_file}")
            return []
        except yaml.YAMLError as e:
            print(f"❌ Error parsing rules file: {e}")
            return []
        except Exception as e:
            print(f"❌ Error loading rules: {e}")
            return []


    def load_events(self) -> List[Dict]:
        """Load security events from JSON file"""
        try:
            with open(self.events_file, "r") as f:
                events = json.load(f)
            
            if not isinstance(events, list):
                print(f"⚠️ Events file should contain a list of events")
                return []
            
            print(f"✅ Loaded {len(events)} security events from {self.events_file}")
            return events
            
        except FileNotFoundError:
            print(f"⚠️ Events file not found: {self.events_file}")
            return []
        except json.JSONDecodeError as e:
            print(f"⚠️ Invalid JSON in events file: {e}")
            return []
        except Exception as e:
            print(f"⚠️ Error loading events: {e}")
            return []

    def save_alerts(self, alerts_file: str = None) -> str:
        """Save generated alerts to JSON file"""
        if alerts_file is None:
            alerts_file = self.alerts_file
            
        try:
            # Ensure alerts directory exists
            os.makedirs(os.path.dirname(alerts_file), exist_ok=True)
            
            # Add metadata to alerts
            alerts_data = {
                "timestamp": datetime.utcnow().isoformat(),
                "total_alerts": len(self.alerts),
                "rules_processed": len(self.rules),
                "alerts": self.alerts
            }
            
            with open(alerts_file, "w") as f:
                json.dump(alerts_data, f, indent=2, default=str)
            
            print(f"✅ Saved {len(self.alerts)} alerts to {alerts_file}")
            return alerts_file
            
        except Exception as e:
            print(f"❌ Failed to save alerts: {e}")
            return ""

    def evaluate_condition(self, event: Dict, condition: str) -> bool:
        """
        Evaluate conditions against security events with support for:
        - .contains("value")
        - ==, !=, >, <, >=, <=
        - and, or (basic support)
        - in, not in
        - null checks
        """
        try:
            # Handle complex conditions with and/or
            if " and " in condition:
                parts = condition.split(" and ")
                return all(self.evaluate_condition(event, part.strip()) for part in parts)
            elif " or " in condition:
                parts = condition.split(" or ")
                return any(self.evaluate_condition(event, part.strip()) for part in parts)
            
            # Handle null checks
            if " == null" in condition:
                field = condition.replace(" == null", "").strip()
                return self._get_nested_value(event, field) is None
            elif " != null" in condition:
                field = condition.replace(" != null", "").strip()
                return self._get_nested_value(event, field) is not None
            
            # Handle .contains() operator
            if ".contains(" in condition:
                field, value = condition.split(".contains(")
                value = value.strip(")").strip('"').strip("'")
                current = self._get_nested_value(event, field.strip())
                
                if current is None:
                    return False
                
                # Handle list/dict -> convert to string
                return value in str(current)
            
            # Handle comparison operators
            operators = ["!=", ">=", "<=", "==", ">", "<"]
            for op in operators:
                if op in condition:
                    field, value = condition.split(op, 1)
                    field, value = field.strip(), value.strip().strip('"').strip("'")
                    current = self._get_nested_value(event, field)
                    
                    if current is None:
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
                current = self._get_nested_value(event, field)
                
                if current is None:
                    return True  # Field doesn't exist, so "not in" is true
                
                return str(current) not in str(value)
            elif " in " in condition:
                field, value = condition.split(" in ")
                field, value = field.strip(), value.strip().strip('"').strip("'")
                current = self._get_nested_value(event, field)
                
                if current is None:
                    return False
                
                return str(current) in str(value)
            
            return False
        except Exception as e:
            print(f"⚠️ Condition evaluation failed for '{condition}': {e}")
            return False
    
    def _get_nested_value(self, event: Dict, field_path: str) -> Any:
        """Get nested value from event using dot notation"""
        try:
            keys = field_path.split(".")
            current = event
            
            for key in keys:
                if isinstance(current, dict) and key in current:
                    current = current[key]
                else:
                    return None
            
            return current
        except Exception:
            return None

    def process_chunk(self, chunk: List[Dict]) -> None:
        """Process a chunk of security events against all rules"""
        local_alerts = []
        
        for event in chunk:
            for rule in self.rules:
                if not isinstance(rule, dict) or "condition" not in rule:
                    continue  # skip invalid rules
                
                try:
                    if self.evaluate_condition(event, rule["condition"]):
                        alert = {
                            "timestamp": datetime.utcnow().isoformat(),
                            "rule_id": rule.get("id", "N/A"),
                            "title": rule.get("title", "No title"),
                            "description": rule.get("description", ""),
                            "severity": rule.get("severity", "INFO"),
                            "remediation": rule.get("remediation", ""),
                            "service": rule.get("service", "UNKNOWN"),
                            "log_excerpt": event,
                        }
                        local_alerts.append(alert)
                except Exception as e:
                    print(f"⚠️ Error processing rule {rule.get('id', 'N/A')}: {e}")

        with self.lock:
            self.alerts.extend(local_alerts)


    def run(self) -> None:
        """Run the rule engine to process security events"""
        print(f"🚀 Starting rule engine with {self.threads} threads...")
        
        # Load security events
        events = self.load_events()
        if not events:
            print("⚠️ No events to process")
            return
        
        if not self.rules:
            print("⚠️ No rules loaded")
            return
        
        print(f"📊 Processing {len(events)} events against {len(self.rules)} rules...")
        
        # Create queue and split events into chunks
        q = Queue()
        for i in range(0, len(events), self.chunk_size):
            chunk = events[i:i + self.chunk_size]
            q.put(chunk)

        def worker():
            """Worker thread function"""
            while True:
                try:
                    chunk = q.get(timeout=1)
                    self.process_chunk(chunk)
                    q.task_done()
                except:
                    break

        # Start worker threads
        threads = []
        for i in range(self.threads):
            t = threading.Thread(target=worker, name=f"Worker-{i+1}")
            t.start()
            threads.append(t)

        # Wait for all threads to complete
        for t in threads:
            t.join()

        # Save results
        alerts_file = self.save_alerts()
        
        # Print summary
        print(f"\n📈 Rule Engine Summary:")
        print(f"   Events processed: {len(events)}")
        print(f"   Rules evaluated: {len(self.rules)}")
        print(f"   Alerts generated: {len(self.alerts)}")
        print(f"   Alerts saved to: {alerts_file}")
        
        # Count alerts by severity
        severity_counts = {}
        for alert in self.alerts:
            severity = alert.get('severity', 'UNKNOWN')
            severity_counts[severity] = severity_counts.get(severity, 0) + 1
        
        if severity_counts:
            print(f"\n🚨 Alerts by Severity:")
            for severity, count in sorted(severity_counts.items()):
                print(f"   {severity}: {count}")


if __name__ == "__main__":
    import sys
    import os
    
    # Default paths
    rules_file = os.path.join(BASE_DIR, "detection", "security_rules.yaml")
    events_file = os.path.join(BASE_DIR, "logs", "aws_security_events_latest.json")
    
    # Allow command line arguments
    if len(sys.argv) > 1:
        rules_file = sys.argv[1]
    if len(sys.argv) > 2:
        events_file = sys.argv[2]
    
    print("🦅 CloudHawk Rule Engine")
    print("=" * 50)
    print(f"Rules file: {rules_file}")
    print(f"Events file: {events_file}")
    print()
    
    try:
        engine = RuleEngine(rules_file, events_file, threads=4, chunk_size=100)
        engine.run()
        print(f"\n✅ Detection complete. Alerts saved in {ALERTS_FILE}")
    except Exception as e:
        print(f"❌ Error: {e}")
        sys.exit(1)
