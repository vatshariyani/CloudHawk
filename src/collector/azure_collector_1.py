"""
CloudHawk Azure Security Collector (Alternative Implementation)
Enhanced Azure security data collection with additional focus on:
- Azure Security Center recommendations
- Azure AD Identity Protection
- Azure Policy compliance
- Azure Monitor security alerts
- Azure Sentinel incidents

This is an alternative implementation with enhanced security focus.
"""

import json
import datetime
import os
import logging
from typing import List, Dict, Any, Optional
from azure.identity import DefaultAzureCredential, ClientSecretCredential
from azure.mgmt.resource import ResourceManagementClient
from azure.mgmt.security import SecurityCenter
from azure.mgmt.authorization import AuthorizationManagementClient
from azure.mgmt.storage import StorageManagementClient
from azure.mgmt.compute import ComputeManagementClient
from azure.mgmt.keyvault import KeyVaultManagementClient
from azure.mgmt.monitor import MonitorManagementClient
from azure.mgmt.resourcegraph import ResourceGraphClient
from azure.mgmt.policy import PolicyClient
from azure.mgmt.policyinsights import PolicyInsightsClient

class AzureCollectorV1:
    """Enhanced Azure security data collector with advanced security focus"""
    
    def __init__(self, config: Dict[str, Any]):
        """Initialize Azure collector with enhanced security capabilities"""
        self.config = config
        self.azure_config = config.get('azure', {})
        self.tenant_id = self.azure_config.get('tenant_id')
        self.client_id = self.azure_config.get('client_id')
        self.client_secret = self.azure_config.get('client_secret')
        self.subscription_id = self.azure_config.get('subscription_id')
        
        # Setup logging
        self.logger = logging.getLogger(__name__)
        
        # Initialize Azure clients
        self.credential = None
        self.security_center = None
        self.resource_client = None
        self.authorization_client = None
        self.storage_client = None
        self.compute_client = None
        self.keyvault_client = None
        self.monitor_client = None
        self.resource_graph_client = None
        self.policy_client = None
        self.policy_insights_client = None
        
        self._setup_credentials()
        self._initialize_clients()
    
    def _setup_credentials(self):
        """Setup Azure credentials with enhanced security"""
        try:
            if self.client_id and self.client_secret and self.tenant_id:
                # Use service principal
                self.credential = ClientSecretCredential(
                    tenant_id=self.tenant_id,
                    client_id=self.client_id,
                    client_secret=self.client_secret
                )
                self.logger.info("Using Azure service principal authentication")
            else:
                # Use default credential chain
                self.credential = DefaultAzureCredential()
                self.logger.info("Using Azure default credential chain")
        except Exception as e:
            self.logger.error(f"Failed to setup Azure credentials: {e}")
            raise
    
    def _initialize_clients(self):
        """Initialize Azure management clients"""
        try:
            if not self.subscription_id:
                raise ValueError("Azure subscription_id is required")
            
            # Initialize all Azure clients
            self.security_center = SecurityCenter(
                self.credential, self.subscription_id
            )
            self.resource_client = ResourceManagementClient(
                self.credential, self.subscription_id
            )
            self.authorization_client = AuthorizationManagementClient(
                self.credential, self.subscription_id
            )
            self.storage_client = StorageManagementClient(
                self.credential, self.subscription_id
            )
            self.compute_client = ComputeManagementClient(
                self.credential, self.subscription_id
            )
            self.keyvault_client = KeyVaultManagementClient(
                self.credential, self.subscription_id
            )
            self.monitor_client = MonitorManagementClient(
                self.credential, self.subscription_id
            )
            self.resource_graph_client = ResourceGraphClient(
                self.credential
            )
            self.policy_client = PolicyClient(
                self.credential, self.subscription_id
            )
            self.policy_insights_client = PolicyInsightsClient(
                self.credential, self.subscription_id
            )
            
            self.logger.info("Azure clients initialized successfully")
        except Exception as e:
            self.logger.error(f"Failed to initialize Azure clients: {e}")
            raise
    
    def collect_security_center_recommendations(self) -> List[Dict[str, Any]]:
        """Collect Azure Security Center recommendations"""
        recommendations = []
        try:
            # Get security recommendations
            recommendations_list = self.security_center.recommendations.list()
            
            for rec in recommendations_list:
                recommendation = {
                    'id': rec.id,
                    'name': rec.display_name,
                    'description': rec.description,
                    'severity': rec.severity,
                    'category': rec.category,
                    'resource_group': rec.resource_group,
                    'resource_type': rec.resource_type,
                    'status': rec.status,
                    'created_time': rec.created_time.isoformat() if rec.created_time else None,
                    'updated_time': rec.updated_time.isoformat() if rec.updated_time else None,
                    'source': 'azure_security_center'
                }
                recommendations.append(recommendation)
            
            self.logger.info(f"Collected {len(recommendations)} security recommendations")
        except Exception as e:
            self.logger.error(f"Failed to collect security recommendations: {e}")
        
        return recommendations
    
    def collect_identity_protection_alerts(self) -> List[Dict[str, Any]]:
        """Collect Azure AD Identity Protection alerts"""
        alerts = []
        try:
            # This would require Azure AD Graph API or Microsoft Graph API
            # For now, we'll return a placeholder structure
            self.logger.info("Identity Protection alerts collection requires Microsoft Graph API")
        except Exception as e:
            self.logger.error(f"Failed to collect identity protection alerts: {e}")
        
        return alerts
    
    def collect_policy_compliance(self) -> List[Dict[str, Any]]:
        """Collect Azure Policy compliance data"""
        compliance_data = []
        try:
            # Get policy compliance states
            policy_states = self.policy_insights_client.policy_states.list_query_results_for_subscription(
                policy_states_resource='latest',
                subscription_id=self.subscription_id
            )
            
            for state in policy_states.value:
                compliance = {
                    'policy_assignment_id': state.policy_assignment_id,
                    'policy_definition_id': state.policy_definition_id,
                    'compliance_state': state.compliance_state,
                    'resource_id': state.resource_id,
                    'resource_type': state.resource_type,
                    'resource_group': state.resource_group,
                    'timestamp': state.timestamp.isoformat() if state.timestamp else None,
                    'source': 'azure_policy'
                }
                compliance_data.append(compliance)
            
            self.logger.info(f"Collected {len(compliance_data)} policy compliance records")
        except Exception as e:
            self.logger.error(f"Failed to collect policy compliance: {e}")
        
        return compliance_data
    
    def collect_monitor_security_alerts(self) -> List[Dict[str, Any]]:
        """Collect Azure Monitor security alerts"""
        alerts = []
        try:
            # Get security alerts from Azure Monitor
            # This requires specific alert rules to be configured
            self.logger.info("Monitor security alerts collection requires configured alert rules")
        except Exception as e:
            self.logger.error(f"Failed to collect monitor security alerts: {e}")
        
        return alerts
    
    def collect_sentinel_incidents(self) -> List[Dict[str, Any]]:
        """Collect Azure Sentinel security incidents"""
        incidents = []
        try:
            # This would require Azure Sentinel API
            # For now, we'll return a placeholder structure
            self.logger.info("Sentinel incidents collection requires Azure Sentinel API")
        except Exception as e:
            self.logger.error(f"Failed to collect Sentinel incidents: {e}")
        
        return incidents
    
    def collect_all_security_data(self) -> Dict[str, Any]:
        """Collect all Azure security data using enhanced methods"""
        self.logger.info("Starting enhanced Azure security data collection...")
        
        security_data = {
            'timestamp': datetime.datetime.utcnow().isoformat(),
            'source': 'azure_enhanced',
            'subscription_id': self.subscription_id,
            'recommendations': self.collect_security_center_recommendations(),
            'identity_protection_alerts': self.collect_identity_protection_alerts(),
            'policy_compliance': self.collect_policy_compliance(),
            'monitor_alerts': self.collect_monitor_security_alerts(),
            'sentinel_incidents': self.collect_sentinel_incidents()
        }
        
        self.logger.info("Enhanced Azure security data collection completed")
        return security_data
    
    def save_security_data(self, data: Dict[str, Any], output_dir: str = "logs"):
        """Save collected security data to file"""
        try:
            os.makedirs(output_dir, exist_ok=True)
            
            timestamp = datetime.datetime.utcnow().strftime("%Y%m%d_%H%M%S")
            filename = f"azure_enhanced_security_events_{timestamp}.json"
            filepath = os.path.join(output_dir, filename)
            
            with open(filepath, 'w') as f:
                json.dump(data, f, indent=2, default=str)
            
            self.logger.info(f"Enhanced Azure security data saved to {filepath}")
            return filepath
        except Exception as e:
            self.logger.error(f"Failed to save enhanced Azure security data: {e}")
            return None

def main():
    """Main function for testing the enhanced Azure collector"""
    import yaml
    
    # Load configuration
    config_path = os.path.join(os.path.dirname(__file__), '..', '..', 'config', 'config.yaml')
    
    try:
        with open(config_path, 'r') as f:
            config = yaml.safe_load(f)
    except FileNotFoundError:
        print("Configuration file not found. Using default configuration.")
        config = {
            'azure': {
                'subscription_id': 'your-subscription-id'
            }
        }
    
    # Initialize enhanced Azure collector
    collector = AzureCollectorV1(config)
    
    # Collect security data
    security_data = collector.collect_all_security_data()
    
    # Save data
    output_file = collector.save_security_data(security_data)
    if output_file:
        print(f"Enhanced Azure security data collected and saved to: {output_file}")
    else:
        print("Failed to save enhanced Azure security data")

if __name__ == "__main__":
    main()
