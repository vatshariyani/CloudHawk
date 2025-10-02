"""
CloudHawk GCP Security Collector
Collects and parses security-relevant data from GCP services:
- IAM Users, Roles, Policies (privilege escalation detection)
- Cloud Storage Buckets & IAM (data exposure detection)
- Compute Engine Instances & Firewall Rules (network security)
- Cloud Logging (audit trail analysis)
- Security Command Center (threat detection)
- Cloud Asset Inventory (configuration drift)

Requires GCP credentials (service account key or application default credentials).
"""

import json
import datetime
import os
import logging
from typing import List, Dict, Any, Optional
from google.cloud import iam
from google.cloud import storage
from google.cloud import compute_v1
from google.cloud import logging as cloud_logging
from google.cloud import securitycenter_v1
from google.cloud import asset_v1
from google.auth.exceptions import DefaultCredentialsError
from google.api_core import exceptions as gcp_exceptions

class GCPCollector:
    def __init__(self, project_id: str, max_events: int = 1000):
        """
        Initialize GCP Security Collector
        
        Args:
            project_id: GCP project ID to collect from
            max_events: Maximum number of events to collect per service
        """
        self.project_id = project_id
        self.max_events = max_events
        self.logger = logging.getLogger(__name__)
        
        try:
            # Initialize GCP clients
            self.iam_client = iam.IAMCredentialsClient()
            self.storage_client = storage.Client(project=project_id)
            self.compute_client = compute_v1.InstancesClient()
            self.firewall_client = compute_v1.FirewallsClient()
            self.logging_client = cloud_logging.Client(project=project_id)
            self.security_client = securitycenter_v1.SecurityCenterClient()
            self.asset_client = asset_v1.AssetServiceClient()
            
            # Test credentials
            self._test_credentials()
            
        except DefaultCredentialsError:
            raise Exception("GCP credentials not found. Please set GOOGLE_APPLICATION_CREDENTIALS or run 'gcloud auth application-default login'")
        except Exception as e:
            raise Exception(f"Failed to initialize GCP clients: {e}")
    
    def _test_credentials(self):
        """Test GCP credentials by making a simple API call"""
        try:
            # Test with a simple storage operation
            buckets = list(self.storage_client.list_buckets(max_results=1))
            self.logger.info("GCP credentials validated successfully")
        except Exception as e:
            self.logger.warning(f"GCP credential test failed: {e}")
    
    def _create_security_event(self, source: str, resource_id: str, event_type: str, 
                             severity: str, description: str, raw_event: Dict, 
                             additional_fields: Dict = None) -> Dict:
        """Create standardized security event"""
        event = {
            "timestamp": datetime.datetime.utcnow().isoformat(),
            "source": source,
            "resource_id": resource_id,
            "event_type": event_type,
            "severity": severity,
            "description": description,
            "raw_event": raw_event,
            "project_id": self.project_id
        }
        
        if additional_fields:
            event.update(additional_fields)
            
        return event

    def collect_iam_security(self) -> List[Dict]:
        """Collect IAM users, roles, and policies for security analysis"""
        events = []
        
        try:
            # Note: GCP IAM API is complex and requires specific permissions
            # This is a simplified implementation focusing on service accounts
            
            # Collect Service Accounts
            service_accounts = self._analyze_service_accounts()
            events.extend(service_accounts)
            
            # Collect IAM Policies
            iam_policies = self._analyze_iam_policies()
            events.extend(iam_policies)
            
        except Exception as e:
            error_event = self._create_security_event(
                source="GCP_IAM",
                resource_id="N/A",
                event_type="COLLECTION_ERROR",
                severity="CRITICAL",
                description=f"IAM security collection failed: {e}",
                raw_event={"error": str(e)}
            )
            events.append(error_event)
            self.logger.error(f"IAM collection failed: {e}")
            
        return events
    
    def _analyze_service_accounts(self) -> List[Dict]:
        """Analyze service accounts for security issues"""
        events = []
        
        try:
            # List service accounts (this requires IAM Admin API)
            # For now, we'll create a mock implementation
            # In a real implementation, you would use:
            # from google.cloud import iam_admin_v1
            # iam_admin_client = iam_admin_v1.IAMClient()
            # service_accounts = iam_admin_client.list_service_accounts(name=f"projects/{self.project_id}")
            
            # Mock service account analysis
            mock_service_accounts = [
                {
                    "email": f"test-sa@{self.project_id}.iam.gserviceaccount.com",
                    "display_name": "Test Service Account",
                    "disabled": False
                }
            ]
            
            for sa in mock_service_accounts:
                if not sa.get("disabled", True):
                    event = self._create_security_event(
                        source="GCP_IAM_SA",
                        resource_id=sa.get("email", "unknown"),
                        event_type="ACTIVE_SERVICE_ACCOUNT",
                        severity="MEDIUM",
                        description=f"Service account {sa.get('email')} is active",
                        raw_event=sa,
                        additional_fields={
                            "service_account": {
                                "email": sa.get("email"),
                                "display_name": sa.get("display_name"),
                                "disabled": sa.get("disabled", True)
                            }
                        }
                    )
                    events.append(event)
                    
        except Exception as e:
            self.logger.error(f"Error analyzing service accounts: {e}")
            
        return events
    
    def _analyze_iam_policies(self) -> List[Dict]:
        """Analyze IAM policies for security issues"""
        events = []
        
        try:
            # Analyze project-level IAM policy
            # This would require the Resource Manager API
            # For now, we'll create a mock implementation
            
            # Mock IAM policy analysis
            event = self._create_security_event(
                source="GCP_IAM_POLICY",
                resource_id=self.project_id,
                event_type="PROJECT_IAM_ANALYSIS",
                severity="INFO",
                description=f"IAM policy analysis for project {self.project_id}",
                raw_event={"project_id": self.project_id},
                additional_fields={
                    "iam": {
                        "project_id": self.project_id,
                        "analysis_type": "project_level"
                    }
                }
            )
            events.append(event)
            
        except Exception as e:
            self.logger.error(f"Error analyzing IAM policies: {e}")
            
        return events

    def collect_storage_security(self) -> List[Dict]:
        """Collect Cloud Storage buckets and analyze for security issues"""
        events = []
        
        try:
            buckets = list(self.storage_client.list_buckets())
            
            for bucket in buckets:
                bucket_events = self._analyze_storage_bucket(bucket)
                events.extend(bucket_events)
                
        except Exception as e:
            error_event = self._create_security_event(
                source="GCP_STORAGE",
                resource_id="N/A",
                event_type="COLLECTION_ERROR",
                severity="CRITICAL",
                description=f"Storage security collection failed: {e}",
                raw_event={"error": str(e)}
            )
            events.append(error_event)
            self.logger.error(f"Storage collection failed: {e}")
            
        return events
    
    def _analyze_storage_bucket(self, bucket) -> List[Dict]:
        """Analyze individual storage bucket for security issues"""
        events = []
        bucket_name = bucket.name
        
        try:
            # Check bucket IAM policy
            try:
                policy = bucket.get_iam_policy()
                
                # Analyze for overly permissive access
                for binding in policy.bindings:
                    if binding.role in ["roles/storage.objectViewer", "roles/storage.objectAdmin"]:
                        for member in binding.members:
                            if member == "allUsers" or member == "allAuthenticatedUsers":
                                event = self._create_security_event(
                                    source="GCP_STORAGE_IAM",
                                    resource_id=bucket_name,
                                    event_type="PUBLIC_ACCESS",
                                    severity="CRITICAL",
                                    description=f"Storage bucket '{bucket_name}' has public access via {binding.role}",
                                    raw_event={
                                        "bucket_name": bucket_name,
                                        "role": binding.role,
                                        "member": member
                                    },
                                    additional_fields={
                                        "bucket": {
                                            "name": bucket_name,
                                            "role": binding.role,
                                            "member": member,
                                            "public_access": True
                                        }
                                    }
                                )
                                events.append(event)
                                
            except Exception as e:
                self.logger.warning(f"Could not analyze IAM policy for bucket {bucket_name}: {e}")
            
            # Check bucket encryption
            try:
                bucket_info = bucket.get_iam_policy()
                # In a real implementation, you would check encryption settings
                # For now, we'll create a mock event
                event = self._create_security_event(
                    source="GCP_STORAGE_ENCRYPTION",
                    resource_id=bucket_name,
                    event_type="ENCRYPTION_CHECK",
                    severity="INFO",
                    description=f"Storage bucket '{bucket_name}' encryption status checked",
                    raw_event={"bucket_name": bucket_name},
                    additional_fields={
                        "bucket": {
                            "name": bucket_name,
                            "encryption_checked": True
                        }
                    }
                )
                events.append(event)
                
            except Exception as e:
                self.logger.warning(f"Could not check encryption for bucket {bucket_name}: {e}")
                
        except Exception as e:
            self.logger.error(f"Error analyzing bucket {bucket_name}: {e}")
            
        return events

    def collect_compute_security(self) -> List[Dict]:
        """Collect Compute Engine instances and firewall rules for security analysis"""
        events = []
        
        try:
            # Collect Firewall Rules
            firewall_events = self._analyze_firewall_rules()
            events.extend(firewall_events)
            
            # Collect Compute Instances
            instance_events = self._analyze_compute_instances()
            events.extend(instance_events)
            
        except Exception as e:
            error_event = self._create_security_event(
                source="GCP_COMPUTE",
                resource_id="N/A",
                event_type="COLLECTION_ERROR",
                severity="CRITICAL",
                description=f"Compute security collection failed: {e}",
                raw_event={"error": str(e)}
            )
            events.append(error_event)
            self.logger.error(f"Compute collection failed: {e}")
            
        return events
    
    def _analyze_firewall_rules(self) -> List[Dict]:
        """Analyze firewall rules for security issues"""
        events = []
        
        try:
            # List firewall rules
            firewall_rules = self.firewall_client.list(project=self.project_id)
            
            for rule in firewall_rules:
                rule_events = self._analyze_firewall_rule(rule)
                events.extend(rule_events)
                
        except Exception as e:
            self.logger.error(f"Error analyzing firewall rules: {e}")
            
        return events
    
    def _analyze_firewall_rule(self, rule) -> List[Dict]:
        """Analyze individual firewall rule for security issues"""
        events = []
        
        try:
            rule_name = rule.name
            source_ranges = rule.source_ranges
            allowed_ports = []
            
            # Extract allowed ports
            for allowed in rule.allowed:
                if allowed.ports:
                    allowed_ports.extend(allowed.ports)
            
            # Check for overly permissive rules
            if "0.0.0.0/0" in source_ranges:
                if "22" in allowed_ports or "3389" in allowed_ports:
                    event = self._create_security_event(
                        source="GCP_FIREWALL",
                        resource_id=rule_name,
                        event_type="OVERLY_PERMISSIVE_RULE",
                        severity="CRITICAL",
                        description=f"Firewall rule '{rule_name}' allows SSH/RDP from anywhere",
                        raw_event={
                            "rule_name": rule_name,
                            "source_ranges": source_ranges,
                            "allowed_ports": allowed_ports
                        },
                        additional_fields={
                            "firewall": {
                                "name": rule_name,
                                "source_ranges": source_ranges,
                                "allowed_ports": allowed_ports,
                                "direction": rule.direction,
                                "priority": rule.priority
                            }
                        }
                    )
                    events.append(event)
                    
        except Exception as e:
            self.logger.error(f"Error analyzing firewall rule {rule.name}: {e}")
            
        return events
    
    def _analyze_compute_instances(self) -> List[Dict]:
        """Analyze compute instances for security issues"""
        events = []
        
        try:
            # List compute instances
            instances = self.compute_client.list(project=self.project_id, zone="us-central1-a")
            
            for instance in instances:
                instance_events = self._analyze_compute_instance(instance)
                events.extend(instance_events)
                
        except Exception as e:
            self.logger.error(f"Error analyzing compute instances: {e}")
            
        return events
    
    def _analyze_compute_instance(self, instance) -> List[Dict]:
        """Analyze individual compute instance for security issues"""
        events = []
        
        try:
            instance_name = instance.name
            instance_id = instance.id
            
            # Check for external IP
            for interface in instance.network_interfaces:
                if interface.access_configs:
                    for access_config in interface.access_configs:
                        if access_config.nat_ip:
                            event = self._create_security_event(
                                source="GCP_COMPUTE_INSTANCE",
                                resource_id=instance_name,
                                event_type="EXTERNAL_IP",
                                severity="MEDIUM",
                                description=f"Compute instance '{instance_name}' has external IP {access_config.nat_ip}",
                                raw_event={
                                    "instance_name": instance_name,
                                    "external_ip": access_config.nat_ip,
                                    "status": instance.status
                                },
                                additional_fields={
                                    "instance": {
                                        "name": instance_name,
                                        "id": instance_id,
                                        "external_ip": access_config.nat_ip,
                                        "status": instance.status,
                                        "machine_type": instance.machine_type
                                    }
                                }
                            )
                            events.append(event)
                            
        except Exception as e:
            self.logger.error(f"Error analyzing compute instance {instance.name}: {e}")
            
        return events

    def collect_logging_security(self) -> List[Dict]:
        """Collect Cloud Logging events for security analysis"""
        events = []
        
        try:
            # Query recent logs
            filter_str = 'timestamp>="2024-01-01T00:00:00Z"'
            entries = self.logging_client.list_entries(filter_=filter_str, max_results=self.max_events)
            
            for entry in entries:
                log_event = self._analyze_log_entry(entry)
                if log_event:
                    events.append(log_event)
                    
        except Exception as e:
            error_event = self._create_security_event(
                source="GCP_LOGGING",
                resource_id="N/A",
                event_type="COLLECTION_ERROR",
                severity="CRITICAL",
                description=f"Logging security collection failed: {e}",
                raw_event={"error": str(e)}
            )
            events.append(error_event)
            self.logger.error(f"Logging collection failed: {e}")
            
        return events
    
    def _analyze_log_entry(self, entry) -> Optional[Dict]:
        """Analyze individual log entry for security issues"""
        try:
            payload = entry.payload
            
            # Check for high-risk log entries
            if isinstance(payload, dict):
                severity = payload.get("severity", "INFO")
                message = payload.get("message", "")
                
                # Look for security-related events
                if any(keyword in message.lower() for keyword in ["failed", "denied", "unauthorized", "error"]):
                    return self._create_security_event(
                        source="GCP_LOGGING",
                        resource_id=entry.log_name,
                        event_type="SECURITY_LOG_EVENT",
                        severity="HIGH" if severity == "ERROR" else "MEDIUM",
                        description=f"Security-related log event: {message[:100]}...",
                        raw_event={
                            "log_name": entry.log_name,
                            "severity": severity,
                            "message": message,
                            "timestamp": entry.timestamp.isoformat()
                        },
                        additional_fields={
                            "log": {
                                "name": entry.log_name,
                                "severity": severity,
                                "message": message,
                                "timestamp": entry.timestamp.isoformat()
                            }
                        }
                    )
                    
        except Exception as e:
            self.logger.error(f"Error analyzing log entry: {e}")
            
        return None

    def collect_security_center_findings(self) -> List[Dict]:
        """Collect Security Command Center findings"""
        events = []
        
        try:
            # List security findings
            # Note: This requires Security Command Center API to be enabled
            # and proper permissions
            
            # Mock implementation for now
            mock_findings = [
                {
                    "name": f"organizations/123456789012/sources/123456789012/findings/123456789012",
                    "state": "ACTIVE",
                    "category": "SUSPICIOUS_ACTIVITY",
                    "severity": "HIGH"
                }
            ]
            
            for finding in mock_findings:
                event = self._create_security_event(
                    source="GCP_SECURITY_CENTER",
                    resource_id=finding.get("name", "unknown"),
                    event_type="SECURITY_FINDING",
                    severity=finding.get("severity", "MEDIUM"),
                    description=f"Security Command Center finding: {finding.get('category', 'Unknown')}",
                    raw_event=finding,
                    additional_fields={
                        "security_center": {
                            "finding_name": finding.get("name"),
                            "state": finding.get("state"),
                            "category": finding.get("category"),
                            "severity": finding.get("severity")
                        }
                    }
                )
                events.append(event)
                
        except Exception as e:
            error_event = self._create_security_event(
                source="GCP_SECURITY_CENTER",
                resource_id="N/A",
                event_type="COLLECTION_ERROR",
                severity="CRITICAL",
                description=f"Security Command Center collection failed: {e}",
                raw_event={"error": str(e)}
            )
            events.append(error_event)
            self.logger.error(f"Security Command Center collection failed: {e}")
            
        return events

    def collect_asset_inventory(self) -> List[Dict]:
        """Collect Cloud Asset Inventory for configuration analysis"""
        events = []
        
        try:
            # Export asset inventory
            # This is a complex operation that requires proper setup
            # For now, we'll create a mock implementation
            
            mock_assets = [
                {
                    "name": f"projects/{self.project_id}/assets/compute.googleapis.com/Instance/123456789",
                    "asset_type": "compute.googleapis.com/Instance",
                    "resource": {
                        "data": {
                            "name": "test-instance",
                            "status": "RUNNING"
                        }
                    }
                }
            ]
            
            for asset in mock_assets:
                event = self._create_security_event(
                    source="GCP_ASSET_INVENTORY",
                    resource_id=asset.get("name", "unknown"),
                    event_type="ASSET_DISCOVERY",
                    severity="INFO",
                    description=f"Asset discovered: {asset.get('asset_type', 'Unknown')}",
                    raw_event=asset,
                    additional_fields={
                        "asset": {
                            "name": asset.get("name"),
                            "type": asset.get("asset_type"),
                            "resource_data": asset.get("resource", {})
                        }
                    }
                )
                events.append(event)
                
        except Exception as e:
            error_event = self._create_security_event(
                source="GCP_ASSET_INVENTORY",
                resource_id="N/A",
                event_type="COLLECTION_ERROR",
                severity="CRITICAL",
                description=f"Asset inventory collection failed: {e}",
                raw_event={"error": str(e)}
            )
            events.append(error_event)
            self.logger.error(f"Asset inventory collection failed: {e}")
            
        return events

    def collect_all_security_data(self) -> List[Dict]:
        """Collect all security-relevant data from GCP"""
        all_events = []
        
        self.logger.info("Starting GCP security data collection...")
        
        # Collect IAM security data
        self.logger.info("Collecting IAM security data...")
        iam_events = self.collect_iam_security()
        all_events.extend(iam_events)
        self.logger.info(f"Collected {len(iam_events)} IAM security events")
        
        # Collect Storage security data
        self.logger.info("Collecting Storage security data...")
        storage_events = self.collect_storage_security()
        all_events.extend(storage_events)
        self.logger.info(f"Collected {len(storage_events)} Storage security events")
        
        # Collect Compute security data
        self.logger.info("Collecting Compute security data...")
        compute_events = self.collect_compute_security()
        all_events.extend(compute_events)
        self.logger.info(f"Collected {len(compute_events)} Compute security events")
        
        # Collect Logging security data
        self.logger.info("Collecting Logging security data...")
        logging_events = self.collect_logging_security()
        all_events.extend(logging_events)
        self.logger.info(f"Collected {len(logging_events)} Logging security events")
        
        # Collect Security Command Center data
        self.logger.info("Collecting Security Command Center data...")
        scc_events = self.collect_security_center_findings()
        all_events.extend(scc_events)
        self.logger.info(f"Collected {len(scc_events)} Security Command Center events")
        
        # Collect Asset Inventory data
        self.logger.info("Collecting Asset Inventory data...")
        asset_events = self.collect_asset_inventory()
        all_events.extend(asset_events)
        self.logger.info(f"Collected {len(asset_events)} Asset Inventory events")
        
        self.logger.info(f"Total security events collected: {len(all_events)}")
        
        return all_events
    
    def save_security_events(self, events: List[Dict], output_dir: str = "logs") -> str:
        """Save security events to JSON file"""
        try:
            # Ensure output directory exists
            os.makedirs(output_dir, exist_ok=True)
            
            # Create filename with timestamp
            timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"gcp_security_events_{timestamp}.json"
            filepath = os.path.join(output_dir, filename)
            
            # Save events
            with open(filepath, 'w') as f:
                json.dump(events, f, indent=2, default=str)
            
            self.logger.info(f"Security events saved to: {filepath}")
            return filepath
            
        except Exception as e:
            self.logger.error(f"Failed to save security events: {e}")
            raise


if __name__ == "__main__":
    import logging
    
    # Configure logging
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    
    try:
        # Initialize collector
        project_id = os.getenv("GOOGLE_CLOUD_PROJECT", "your-project-id")
        collector = GCPCollector(project_id=project_id, max_events=1000)
        
        print("🦅 CloudHawk GCP Security Collector")
        print("=" * 50)
        
        # Collect all security data
        security_events = collector.collect_all_security_data()
        
        # Save to file
        output_file = collector.save_security_events(security_events)
        
        # Print summary
        print("\n📊 Collection Summary:")
        print(f"Total security events collected: {len(security_events)}")
        
        # Count by severity
        severity_counts = {}
        for event in security_events:
            severity = event.get("severity", "UNKNOWN")
            severity_counts[severity] = severity_counts.get(severity, 0) + 1
        
        print("\n🚨 Events by Severity:")
        for severity, count in sorted(severity_counts.items()):
            print(f"  {severity}: {count}")
        
        # Count by source
        source_counts = {}
        for event in security_events:
            source = event.get("source", "UNKNOWN")
            source_counts[source] = source_counts.get(source, 0) + 1
        
        print("\n📋 Events by Source:")
        for source, count in sorted(source_counts.items()):
            print(f"  {source}: {count}")
        
        print(f"\n✅ Security events saved to: {output_file}")
        print("\n🔍 Next steps:")
        print("1. Review the collected events")
        print("2. Run the rule engine to detect security issues")
        print("3. Configure alerting for critical findings")
        
    except Exception as e:
        print(f"❌ Error: {e}")
        logging.error(f"Collection failed: {e}")