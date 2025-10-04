"""
CloudHawk GCP Security Collector (Alternative Implementation)
Enhanced Google Cloud Platform security data collection with additional focus on:
- Cloud Security Command Center (SCC) findings
- Cloud Asset Inventory security insights
- Cloud Logging security events
- Cloud Monitoring security metrics
- Cloud IAM security analysis
- Cloud KMS security status

This is an alternative implementation with enhanced security focus.
"""

import json
import datetime
import os
import logging
from typing import List, Dict, Any, Optional
from google.cloud import securitycenter
from google.cloud import asset
from google.cloud import logging as cloud_logging
from google.cloud import monitoring_v3
from google.cloud import iam
from google.cloud import kms
from google.cloud import storage
from google.oauth2 import service_account
from google.auth import default

class GCPCollectorV1:
    """Enhanced GCP security data collector with advanced security focus"""
    
    def __init__(self, config: Dict[str, Any]):
        """Initialize GCP collector with enhanced security capabilities"""
        self.config = config
        self.gcp_config = config.get('gcp', {})
        self.project_id = self.gcp_config.get('project_id')
        self.credentials_path = self.gcp_config.get('credentials_path')
        self.organization_id = self.gcp_config.get('organization_id')
        
        # Setup logging
        self.logger = logging.getLogger(__name__)
        
        # Initialize GCP clients
        self.credentials = None
        self.scc_client = None
        self.asset_client = None
        self.logging_client = None
        self.monitoring_client = None
        self.iam_client = None
        self.kms_client = None
        self.storage_client = None
        
        self._setup_credentials()
        self._initialize_clients()
    
    def _setup_credentials(self):
        """Setup GCP credentials with enhanced security"""
        try:
            if self.credentials_path and os.path.exists(self.credentials_path):
                # Use service account key file
                self.credentials = service_account.Credentials.from_service_account_file(
                    self.credentials_path
                )
                self.logger.info("Using GCP service account credentials")
            else:
                # Use default credentials
                self.credentials, _ = default()
                self.logger.info("Using GCP default credentials")
        except Exception as e:
            self.logger.error(f"Failed to setup GCP credentials: {e}")
            raise
    
    def _initialize_clients(self):
        """Initialize GCP management clients"""
        try:
            if not self.project_id:
                raise ValueError("GCP project_id is required")
            
            # Initialize all GCP clients
            self.scc_client = securitycenter.SecurityCenterClient(credentials=self.credentials)
            self.asset_client = asset.AssetServiceClient(credentials=self.credentials)
            self.logging_client = cloud_logging.Client(credentials=self.credentials)
            self.monitoring_client = monitoring_v3.MetricServiceClient(credentials=self.credentials)
            self.iam_client = iam.IAMCredentialsClient(credentials=self.credentials)
            self.kms_client = kms.KeyManagementServiceClient(credentials=self.credentials)
            self.storage_client = storage.Client(credentials=self.credentials)
            
            self.logger.info("GCP clients initialized successfully")
        except Exception as e:
            self.logger.error(f"Failed to initialize GCP clients: {e}")
            raise
    
    def collect_scc_findings(self) -> List[Dict[str, Any]]:
        """Collect Cloud Security Command Center findings"""
        findings = []
        try:
            # Get SCC findings
            parent = f"organizations/{self.organization_id}" if self.organization_id else f"projects/{self.project_id}"
            
            findings_list = self.scc_client.list_findings(
                parent=f"{parent}/sources/-"
            )
            
            for finding in findings_list:
                finding_data = {
                    'name': finding.name,
                    'parent': finding.parent,
                    'resource_name': finding.resource_name,
                    'state': finding.state.name,
                    'category': finding.category,
                    'external_uri': finding.external_uri,
                    'source_properties': dict(finding.source_properties),
                    'security_marks': dict(finding.security_marks.marks),
                    'event_time': finding.event_time.timestamp() if finding.event_time else None,
                    'create_time': finding.create_time.timestamp() if finding.create_time else None,
                    'source': 'gcp_scc'
                }
                findings.append(finding_data)
            
            self.logger.info(f"Collected {len(findings)} SCC findings")
        except Exception as e:
            self.logger.error(f"Failed to collect SCC findings: {e}")
        
        return findings
    
    def collect_asset_inventory(self) -> List[Dict[str, Any]]:
        """Collect Cloud Asset Inventory security insights"""
        assets = []
        try:
            # Get asset inventory
            parent = f"projects/{self.project_id}"
            
            assets_list = self.asset_client.search_all_resources(
                scope=parent,
                asset_types=['*'],
                read_mask='*'
            )
            
            for asset in assets_list:
                asset_data = {
                    'name': asset.name,
                    'asset_type': asset.asset_type,
                    'project': asset.project,
                    'location': asset.location,
                    'labels': dict(asset.labels),
                    'create_time': asset.create_time.timestamp() if asset.create_time else None,
                    'update_time': asset.update_time.timestamp() if asset.update_time else None,
                    'ancestors': list(asset.ancestors),
                    'source': 'gcp_asset_inventory'
                }
                assets.append(asset_data)
            
            self.logger.info(f"Collected {len(assets)} asset inventory items")
        except Exception as e:
            self.logger.error(f"Failed to collect asset inventory: {e}")
        
        return assets
    
    def collect_security_logs(self) -> List[Dict[str, Any]]:
        """Collect Cloud Logging security events"""
        security_logs = []
        try:
            # Get security-related logs
            filter_str = """
            resource.type="gce_instance" OR 
            resource.type="gcs_bucket" OR 
            resource.type="gke_cluster" OR
            protoPayload.serviceName="cloudkms.googleapis.com" OR
            protoPayload.serviceName="iam.googleapis.com"
            """
            
            entries = self.logging_client.list_entries(
                filter_=filter_str,
                max_results=1000
            )
            
            for entry in entries:
                log_data = {
                    'timestamp': entry.timestamp.isoformat(),
                    'severity': entry.severity.name,
                    'resource': dict(entry.resource),
                    'log_name': entry.log_name,
                    'labels': dict(entry.labels),
                    'proto_payload': dict(entry.proto_payload) if entry.proto_payload else None,
                    'json_payload': dict(entry.json_payload) if entry.json_payload else None,
                    'text_payload': entry.text_payload,
                    'source': 'gcp_logging'
                }
                security_logs.append(log_data)
            
            self.logger.info(f"Collected {len(security_logs)} security log entries")
        except Exception as e:
            self.logger.error(f"Failed to collect security logs: {e}")
        
        return security_logs
    
    def collect_monitoring_metrics(self) -> List[Dict[str, Any]]:
        """Collect Cloud Monitoring security metrics"""
        metrics = []
        try:
            # Get security-related metrics
            project_name = f"projects/{self.project_id}"
            
            # List available metrics
            metrics_list = self.monitoring_client.list_metric_descriptors(
                name=project_name,
                filter='metric.type:"compute.googleapis.com" OR metric.type:"storage.googleapis.com"'
            )
            
            for metric in metrics_list:
                metric_data = {
                    'name': metric.name,
                    'type': metric.type,
                    'labels': [{'key': label.key, 'value_type': label.value_type} for label in metric.labels],
                    'metric_kind': metric.metric_kind.name,
                    'value_type': metric.value_type.name,
                    'unit': metric.unit,
                    'description': metric.description,
                    'source': 'gcp_monitoring'
                }
                metrics.append(metric_data)
            
            self.logger.info(f"Collected {len(metrics)} monitoring metrics")
        except Exception as e:
            self.logger.error(f"Failed to collect monitoring metrics: {e}")
        
        return metrics
    
    def collect_iam_analysis(self) -> List[Dict[str, Any]]:
        """Collect Cloud IAM security analysis"""
        iam_data = []
        try:
            # This would require additional IAM analysis
            # For now, we'll return a placeholder structure
            self.logger.info("IAM security analysis requires additional API calls")
        except Exception as e:
            self.logger.error(f"Failed to collect IAM analysis: {e}")
        
        return iam_data
    
    def collect_kms_security_status(self) -> List[Dict[str, Any]]:
        """Collect Cloud KMS security status"""
        kms_data = []
        try:
            # Get KMS key rings and keys
            parent = f"projects/{self.project_id}/locations/global"
            
            key_rings = self.kms_client.list_key_rings(parent=parent)
            
            for key_ring in key_rings:
                kms_info = {
                    'name': key_ring.name,
                    'create_time': key_ring.create_time.timestamp() if key_ring.create_time else None,
                    'source': 'gcp_kms'
                }
                kms_data.append(kms_info)
            
            self.logger.info(f"Collected {len(kms_data)} KMS key rings")
        except Exception as e:
            self.logger.error(f"Failed to collect KMS security status: {e}")
        
        return kms_data
    
    def collect_all_security_data(self) -> Dict[str, Any]:
        """Collect all GCP security data using enhanced methods"""
        self.logger.info("Starting enhanced GCP security data collection...")
        
        security_data = {
            'timestamp': datetime.datetime.utcnow().isoformat(),
            'source': 'gcp_enhanced',
            'project_id': self.project_id,
            'scc_findings': self.collect_scc_findings(),
            'asset_inventory': self.collect_asset_inventory(),
            'security_logs': self.collect_security_logs(),
            'monitoring_metrics': self.collect_monitoring_metrics(),
            'iam_analysis': self.collect_iam_analysis(),
            'kms_security': self.collect_kms_security_status()
        }
        
        self.logger.info("Enhanced GCP security data collection completed")
        return security_data
    
    def save_security_data(self, data: Dict[str, Any], output_dir: str = "logs"):
        """Save collected security data to file"""
        try:
            os.makedirs(output_dir, exist_ok=True)
            
            timestamp = datetime.datetime.utcnow().strftime("%Y%m%d_%H%M%S")
            filename = f"gcp_enhanced_security_events_{timestamp}.json"
            filepath = os.path.join(output_dir, filename)
            
            with open(filepath, 'w') as f:
                json.dump(data, f, indent=2, default=str)
            
            self.logger.info(f"Enhanced GCP security data saved to {filepath}")
            return filepath
        except Exception as e:
            self.logger.error(f"Failed to save enhanced GCP security data: {e}")
            return None

def main():
    """Main function for testing the enhanced GCP collector"""
    import yaml
    
    # Load configuration
    config_path = os.path.join(os.path.dirname(__file__), '..', '..', 'config', 'config.yaml')
    
    try:
        with open(config_path, 'r') as f:
            config = yaml.safe_load(f)
    except FileNotFoundError:
        print("Configuration file not found. Using default configuration.")
        config = {
            'gcp': {
                'project_id': 'your-project-id'
            }
        }
    
    # Initialize enhanced GCP collector
    collector = GCPCollectorV1(config)
    
    # Collect security data
    security_data = collector.collect_all_security_data()
    
    # Save data
    output_file = collector.save_security_data(security_data)
    if output_file:
        print(f"Enhanced GCP security data collected and saved to: {output_file}")
    else:
        print("Failed to save enhanced GCP security data")

if __name__ == "__main__":
    main()
