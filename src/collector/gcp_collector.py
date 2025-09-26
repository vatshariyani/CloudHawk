"""
CloudHawk GCP Security Collector
Collects and parses security-relevant data from Google Cloud Platform services:
- IAM (Users, Roles, Policies, Service Accounts)
- Cloud Storage (Buckets, IAM policies, encryption)
- Compute Engine (Instances, firewall rules, disk encryption)
- Cloud Logging (Audit logs, security events)
- Security Command Center (Findings, recommendations)
- Cloud Asset Inventory (Resource discovery, policy analysis)

Requires GCP credentials (from `gcloud auth application-default login` or service account).
"""

import json
import datetime
import os
import logging
from typing import List, Dict, Any, Optional
from google.cloud import storage
from google.cloud import compute_v1
from google.cloud import logging_v2
from google.cloud import securitycenter_v1
from google.cloud import asset_v1
from google.cloud import iam_v2
from google.auth import default
from google.auth.exceptions import DefaultCredentialsError
from google.api_core import exceptions as gcp_exceptions

class GCPCollector:
    def __init__(self, project_id: str, credentials_path: str = None):
        """
        Initialize GCP Security Collector
        
        Args:
            project_id: GCP Project ID
            credentials_path: Path to service account key file (optional)
        """
        self.project_id = project_id
        self.credentials_path = credentials_path
        self.logger = logging.getLogger(__name__)
        
        try:
            # Initialize GCP credentials
            if credentials_path:
                os.environ['GOOGLE_APPLICATION_CREDENTIALS'] = credentials_path
            
            # Get default credentials
            self.credentials, _ = default()
            
            # Initialize GCP clients
            self.storage_client = storage.Client(project=project_id)
            self.compute_client = compute_v1.InstancesClient()
            self.logging_client = logging_v2.LoggingServiceV2Client()
            self.security_client = securitycenter_v1.SecurityCenterClient()
            self.asset_client = asset_v1.AssetServiceClient()
            self.iam_client = iam_v2.IAMClient()
            
            # Test credentials
            self._test_credentials()
            
        except DefaultCredentialsError:
            raise Exception("GCP credentials not found. Please run 'gcloud auth application-default login' or set GOOGLE_APPLICATION_CREDENTIALS.")
        except Exception as e:
            raise Exception(f"Failed to initialize GCP clients: {e}")
    
    def _test_credentials(self):
        """Test GCP credentials by making a simple API call"""
        try:
            # Test with a simple storage bucket list
            list(self.storage_client.list_buckets())
            self.logger.info("GCP credentials validated successfully")
        except Exception as e:
            self.logger.warning(f"GCP credential test failed: {e}")
            raise Exception(f"GCP credential test failed: {e}")
    
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

    def collect_all_security_data(self) -> List[Dict]:
        """Collect all security-relevant data from GCP"""
        all_events = []
        
        self.logger.info("Starting GCP security data collection...")
        
        # Collect IAM security data
        self.logger.info("Collecting IAM security data...")
        iam_events = self.collect_iam_security()
        all_events.extend(iam_events)
        self.logger.info(f"Collected {len(iam_events)} IAM security events")
        
        # Collect Cloud Storage security data
        self.logger.info("Collecting Cloud Storage security data...")
        storage_events = self.collect_storage_security()
        all_events.extend(storage_events)
        self.logger.info(f"Collected {len(storage_events)} Cloud Storage security events")
        
        # Collect Compute Engine security data
        self.logger.info("Collecting Compute Engine security data...")
        compute_events = self.collect_compute_security()
        all_events.extend(compute_events)
        self.logger.info(f"Collected {len(compute_events)} Compute Engine security events")
        
        # Collect Cloud Logging data
        self.logger.info("Collecting Cloud Logging data...")
        logging_events = self.collect_logging_security()
        all_events.extend(logging_events)
        self.logger.info(f"Collected {len(logging_events)} Cloud Logging events")
        
        # Collect Security Command Center data
        self.logger.info("Collecting Security Command Center data...")
        scc_events = self.collect_security_command_center()
        all_events.extend(scc_events)
        self.logger.info(f"Collected {len(scc_events)} Security Command Center events")
        
        # Collect Cloud Asset Inventory data
        self.logger.info("Collecting Cloud Asset Inventory data...")
        asset_events = self.collect_asset_inventory()
        all_events.extend(asset_events)
        self.logger.info(f"Collected {len(asset_events)} Cloud Asset Inventory events")
        
        self.logger.info(f"Total security events collected: {len(all_events)}")
        
        return all_events

    def collect_iam_security(self) -> List[Dict]:
        """Collect IAM security data"""
        events = []
        
        try:
            # List service accounts
            service_accounts = self.iam_client.list_service_accounts(
                name=f"projects/{self.project_id}"
            )
            
            for sa in service_accounts:
                sa_events = self._analyze_service_account(sa)
                events.extend(sa_events)
            
            # List IAM policies
            policy_events = self._analyze_iam_policies()
            events.extend(policy_events)
                
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

    def _analyze_service_account(self, service_account) -> List[Dict]:
        """Analyze service account for security issues"""
        events = []
        sa_name = service_account.name
        sa_email = service_account.email
        
        try:
            # Check for service account keys
            try:
                keys = self.iam_client.list_service_account_keys(
                    name=sa_name
                )
                
                key_count = len(list(keys.keys))
                if key_count > 0:
                    event = self._create_security_event(
                        source="GCP_IAM_SA",
                        resource_id=sa_email,
                        event_type="SERVICE_ACCOUNT_KEYS",
                        severity="HIGH",
                        description=f"Service account '{sa_email}' has {key_count} keys (should use workload identity)",
                        raw_event=service_account.__dict__,
                        additional_fields={
                            "service_account": {
                                "email": sa_email,
                                "name": sa_name,
                                "key_count": key_count,
                                "display_name": service_account.display_name
                            }
                        }
                    )
                    events.append(event)
                    
            except gcp_exceptions.PermissionDenied:
                self.logger.warning(f"Permission denied accessing keys for {sa_email}")
            
            # Check for overly permissive roles
            try:
                # This would require additional API calls to get IAM policy
                # For now, we'll just note the service account exists
                pass
                
            except Exception as e:
                self.logger.warning(f"Error analyzing roles for {sa_email}: {e}")
                
        except Exception as e:
            self.logger.error(f"Error analyzing service account {sa_email}: {e}")
            
        return events

    def _analyze_iam_policies(self) -> List[Dict]:
        """Analyze IAM policies for security issues"""
        events = []
        
        try:
            # Get IAM policy for the project
            policy = self.iam_client.get_iam_policy(
                resource=f"projects/{self.project_id}"
            )
            
            # Analyze bindings for overly permissive access
            for binding in policy.bindings:
                role = binding.role
                members = list(binding.members)
                
                # Check for overly permissive roles
                dangerous_roles = [
                    "roles/owner",
                    "roles/editor", 
                    "roles/iam.serviceAccountTokenCreator"
                ]
                
                if role in dangerous_roles:
                    # Check if it's granted to all users or all authenticated users
                    for member in members:
                        if member in ["allUsers", "allAuthenticatedUsers"]:
                            event = self._create_security_event(
                                source="GCP_IAM_POLICY",
                                resource_id=self.project_id,
                                event_type="OVERLY_PERMISSIVE_ROLE",
                                severity="CRITICAL",
                                description=f"Project has dangerous role '{role}' granted to '{member}'",
                                raw_event=policy.__dict__,
                                additional_fields={
                                    "iam_policy": {
                                        "role": role,
                                        "member": member,
                                        "project_id": self.project_id
                                    }
                                }
                            )
                            events.append(event)
                            
        except Exception as e:
            self.logger.error(f"Error analyzing IAM policies: {e}")
            
        return events

    def collect_storage_security(self) -> List[Dict]:
        """Collect Cloud Storage security data"""
        events = []
        
        try:
            # List all buckets
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
                description=f"Cloud Storage security collection failed: {e}",
                raw_event={"error": str(e)}
            )
            events.append(error_event)
            self.logger.error(f"Cloud Storage collection failed: {e}")
            
        return events

    def _analyze_storage_bucket(self, bucket) -> List[Dict]:
        """Analyze individual storage bucket for security issues"""
        events = []
        bucket_name = bucket.name
        
        try:
            # Check if bucket is publicly accessible
            try:
                policy = bucket.get_iam_policy()
                
                for binding in policy.bindings:
                    role = binding.get("role", "")
                    members = binding.get("members", [])
                    
                    # Check for public access
                    if "allUsers" in members or "allAuthenticatedUsers" in members:
                        if role in ["roles/storage.objectViewer", "roles/storage.objectAdmin"]:
                            event = self._create_security_event(
                                source="GCP_STORAGE_BUCKET",
                                resource_id=bucket_name,
                                event_type="PUBLIC_ACCESS",
                                severity="CRITICAL",
                                description=f"Storage bucket '{bucket_name}' has public access with role '{role}'",
                                raw_event=bucket.__dict__,
                                additional_fields={
                                    "bucket": {
                                        "name": bucket_name,
                                        "public_access": True,
                                        "role": role,
                                        "members": members
                                    }
                                }
                            )
                            events.append(event)
                            
            except Exception as e:
                self.logger.warning(f"Could not get IAM policy for bucket {bucket_name}: {e}")
            
            # Check encryption
            if not bucket.default_kms_key_name:
                event = self._create_security_event(
                    source="GCP_STORAGE_BUCKET",
                    resource_id=bucket_name,
                    event_type="NO_ENCRYPTION",
                    severity="HIGH",
                    description=f"Storage bucket '{bucket_name}' has no customer-managed encryption key",
                    raw_event=bucket.__dict__,
                    additional_fields={
                        "bucket": {
                            "name": bucket_name,
                            "encryption_enabled": False,
                            "kms_key": None
                        }
                    }
                )
                events.append(event)
            
            # Check versioning
            if not bucket.versioning_enabled:
                event = self._create_security_event(
                    source="GCP_STORAGE_BUCKET",
                    resource_id=bucket_name,
                    event_type="VERSIONING_DISABLED",
                    severity="MEDIUM",
                    description=f"Storage bucket '{bucket_name}' has versioning disabled",
                    raw_event=bucket.__dict__,
                    additional_fields={
                        "bucket": {
                            "name": bucket_name,
                            "versioning_enabled": False
                        }
                    }
                )
                events.append(event)
                
        except Exception as e:
            self.logger.error(f"Error analyzing bucket {bucket_name}: {e}")
            
        return events

    def collect_compute_security(self) -> List[Dict]:
        """Collect Compute Engine security data"""
        events = []
        
        try:
            # List all instances
            instances = self.compute_client.list(
                project=self.project_id,
                zone="us-central1-a"  # This would need to be dynamic for all zones
            )
            
            for instance in instances:
                instance_events = self._analyze_compute_instance(instance)
                events.extend(instance_events)
                
        except Exception as e:
            error_event = self._create_security_event(
                source="GCP_COMPUTE",
                resource_id="N/A",
                event_type="COLLECTION_ERROR",
                severity="CRITICAL",
                description=f"Compute Engine security collection failed: {e}",
                raw_event={"error": str(e)}
            )
            events.append(error_event)
            self.logger.error(f"Compute Engine collection failed: {e}")
            
        return events

    def _analyze_compute_instance(self, instance) -> List[Dict]:
        """Analyze individual compute instance for security issues"""
        events = []
        instance_name = instance.name
        
        try:
            # Check if instance has external IP
            for network_interface in instance.network_interfaces:
                if network_interface.access_configs:
                    for access_config in network_interface.access_configs:
                        if access_config.nat_i_p:
                            event = self._create_security_event(
                                source="GCP_COMPUTE_INSTANCE",
                                resource_id=instance_name,
                                event_type="EXTERNAL_IP",
                                severity="MEDIUM",
                                description=f"Compute instance '{instance_name}' has external IP {access_config.nat_i_p}",
                                raw_event=instance.__dict__,
                                additional_fields={
                                    "instance": {
                                        "name": instance_name,
                                        "external_ip": access_config.nat_i_p,
                                        "zone": instance.zone.split('/')[-1]
                                    }
                                }
                            )
                            events.append(event)
            
            # Check disk encryption
            for disk in instance.disks:
                if not disk.disk_encryption_key:
                    event = self._create_security_event(
                        source="GCP_COMPUTE_INSTANCE",
                        resource_id=instance_name,
                        event_type="NO_DISK_ENCRYPTION",
                        severity="HIGH",
                        description=f"Compute instance '{instance_name}' has unencrypted disk",
                        raw_event=instance.__dict__,
                        additional_fields={
                            "instance": {
                                "name": instance_name,
                                "disk_encryption": False,
                                "zone": instance.zone.split('/')[-1]
                            }
                        }
                    )
                    events.append(event)
                    
        except Exception as e:
            self.logger.error(f"Error analyzing instance {instance_name}: {e}")
            
        return events

    def collect_logging_security(self) -> List[Dict]:
        """Collect Cloud Logging security data"""
        events = []
        
        try:
            # Get audit logs for the last 24 hours
            end_time = datetime.datetime.utcnow()
            start_time = end_time - datetime.timedelta(hours=24)
            
            # Filter for security-related log entries
            filter_str = f"""
                resource.type="gce_instance" OR
                resource.type="gcs_bucket" OR
                resource.type="iam_policy" OR
                protoPayload.methodName="google.iam.v1.IAMPolicy.SetIamPolicy" OR
                protoPayload.methodName="storage.buckets.create" OR
                protoPayload.methodName="storage.buckets.update"
            """
            
            entries = self.logging_client.list_entries(
                filter_=filter_str,
                page_size=100
            )
            
            for entry in entries:
                log_events = self._analyze_log_entry(entry)
                events.extend(log_events)
                
        except Exception as e:
            error_event = self._create_security_event(
                source="GCP_LOGGING",
                resource_id="N/A",
                event_type="COLLECTION_ERROR",
                severity="CRITICAL",
                description=f"Cloud Logging security collection failed: {e}",
                raw_event={"error": str(e)}
            )
            events.append(error_event)
            self.logger.error(f"Cloud Logging collection failed: {e}")
            
        return events

    def _analyze_log_entry(self, entry) -> List[Dict]:
        """Analyze individual log entry for security issues"""
        events = []
        
        try:
            # Check for high-risk operations
            method_name = entry.payload.get("methodName", "") if hasattr(entry, 'payload') else ""
            
            high_risk_methods = [
                "google.iam.v1.IAMPolicy.SetIamPolicy",
                "storage.buckets.delete",
                "compute.instances.delete",
                "iam.serviceAccounts.delete"
            ]
            
            if method_name in high_risk_methods:
                event = self._create_security_event(
                    source="GCP_LOGGING",
                    resource_id=entry.resource.get("labels", {}).get("instance_id", "unknown"),
                    event_type="HIGH_RISK_OPERATION",
                    severity="HIGH",
                    description=f"High-risk operation detected: {method_name}",
                    raw_event=entry.__dict__,
                    additional_fields={
                        "log_entry": {
                            "method_name": method_name,
                            "timestamp": entry.timestamp.isoformat(),
                            "resource_type": entry.resource.get("type", ""),
                            "severity": entry.severity.name if entry.severity else "INFO"
                        }
                    }
                )
                events.append(event)
                
        except Exception as e:
            self.logger.error(f"Error analyzing log entry: {e}")
            
        return events

    def collect_security_command_center(self) -> List[Dict]:
        """Collect Security Command Center findings"""
        events = []
        
        try:
            # List findings from Security Command Center
            parent = f"organizations/{self.project_id}"  # This might need adjustment based on org structure
            
            findings = self.security_client.list_findings(
                parent=parent,
                page_size=100
            )
            
            for finding in findings:
                scc_events = self._analyze_scc_finding(finding)
                events.extend(scc_events)
                
        except Exception as e:
            # SCC might not be enabled or accessible
            self.logger.warning(f"Security Command Center collection failed (might not be enabled): {e}")
            
        return events

    def _analyze_scc_finding(self, finding) -> List[Dict]:
        """Analyze Security Command Center finding"""
        events = []
        
        try:
            # Map SCC severity to our severity levels
            severity_map = {
                "CRITICAL": "CRITICAL",
                "HIGH": "HIGH",
                "MEDIUM": "MEDIUM",
                "LOW": "LOW"
            }
            
            severity = severity_map.get(finding.severity.name, "MEDIUM")
            
            event = self._create_security_event(
                source="GCP_SCC",
                resource_id=finding.name,
                event_type="SECURITY_FINDING",
                severity=severity,
                description=f"Security Command Center finding: {finding.category}",
                raw_event=finding.__dict__,
                additional_fields={
                    "scc_finding": {
                        "name": finding.name,
                        "category": finding.category,
                        "severity": finding.severity.name,
                        "state": finding.state.name,
                        "resource_name": finding.resource_name
                    }
                }
            )
            events.append(event)
            
        except Exception as e:
            self.logger.error(f"Error analyzing SCC finding: {e}")
            
        return events

    def collect_asset_inventory(self) -> List[Dict]:
        """Collect Cloud Asset Inventory data"""
        events = []
        
        try:
            # List all assets
            parent = f"projects/{self.project_id}"
            
            assets = self.asset_client.list_assets(
                parent=parent,
                asset_types=["compute.googleapis.com/Instance", "storage.googleapis.com/Bucket"]
            )
            
            for asset in assets:
                asset_events = self._analyze_asset(asset)
                events.extend(asset_events)
                
        except Exception as e:
            error_event = self._create_security_event(
                source="GCP_ASSET_INVENTORY",
                resource_id="N/A",
                event_type="COLLECTION_ERROR",
                severity="CRITICAL",
                description=f"Cloud Asset Inventory collection failed: {e}",
                raw_event={"error": str(e)}
            )
            events.append(error_event)
            self.logger.error(f"Cloud Asset Inventory collection failed: {e}")
            
        return events

    def _analyze_asset(self, asset) -> List[Dict]:
        """Analyze individual asset for security issues"""
        events = []
        
        try:
            # Check for assets without proper labels
            if not asset.resource.data.get("labels"):
                event = self._create_security_event(
                    source="GCP_ASSET_INVENTORY",
                    resource_id=asset.name,
                    event_type="NO_LABELS",
                    severity="LOW",
                    description=f"Asset '{asset.name}' has no labels for organization",
                    raw_event=asset.__dict__,
                    additional_fields={
                        "asset": {
                            "name": asset.name,
                            "asset_type": asset.asset_type,
                            "resource_name": asset.resource.name,
                            "labels": asset.resource.data.get("labels", {})
                        }
                    }
                )
                events.append(event)
                
        except Exception as e:
            self.logger.error(f"Error analyzing asset {asset.name}: {e}")
            
        return events

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
        # You need to provide your GCP project ID
        project_id = os.getenv("GOOGLE_CLOUD_PROJECT", "your-project-id")
        
        collector = GCPCollector(project_id=project_id)
        
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
