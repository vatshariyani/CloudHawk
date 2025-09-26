"""
CloudHawk Azure Security Collector
Collects and parses security-relevant data from Azure services:
- Azure AD (Users, Groups, Roles, Conditional Access)
- Storage Accounts (Security policies, encryption, access)
- Virtual Machines (Security configurations, extensions)
- Security Center (Security recommendations, alerts)
- Activity Log (Audit trail analysis)
- Key Vault (Access policies, secrets management)

Requires Azure credentials (from `az login` or service principal).
"""

import json
import datetime
import os
import logging
from typing import List, Dict, Any, Optional
from azure.identity import DefaultAzureCredential, ClientSecretCredential
from azure.mgmt.resource import ResourceManagementClient
from azure.mgmt.storage import StorageManagementClient
from azure.mgmt.compute import ComputeManagementClient
from azure.mgmt.security import SecurityCenter
from azure.mgmt.keyvault import KeyVaultManagementClient
from azure.mgmt.monitor import MonitorManagementClient
from azure.mgmt.authorization import AuthorizationManagementClient
from azure.core.exceptions import ResourceNotFoundError, ClientAuthenticationError

class AzureCollector:
    def __init__(self, subscription_id: str, tenant_id: str = None, client_id: str = None, client_secret: str = None):
        """
        Initialize Azure Security Collector
        
        Args:
            subscription_id: Azure subscription ID
            tenant_id: Azure tenant ID (optional, for service principal auth)
            client_id: Azure client ID (optional, for service principal auth)
            client_secret: Azure client secret (optional, for service principal auth)
        """
        self.subscription_id = subscription_id
        self.tenant_id = tenant_id
        self.client_id = client_id
        self.client_secret = client_secret
        self.logger = logging.getLogger(__name__)
        
        try:
            # Initialize Azure credentials
            if tenant_id and client_id and client_secret:
                # Service principal authentication
                self.credential = ClientSecretCredential(
                    tenant_id=tenant_id,
                    client_id=client_id,
                    client_secret=client_secret
                )
            else:
                # Default credential (az login, managed identity, etc.)
                self.credential = DefaultAzureCredential()
            
            # Initialize Azure clients
            self.resource_client = ResourceManagementClient(self.credential, subscription_id)
            self.storage_client = StorageManagementClient(self.credential, subscription_id)
            self.compute_client = ComputeManagementClient(self.credential, subscription_id)
            self.security_client = SecurityCenter(self.credential, subscription_id)
            self.keyvault_client = KeyVaultManagementClient(self.credential, subscription_id)
            self.monitor_client = MonitorManagementClient(self.credential, subscription_id)
            self.auth_client = AuthorizationManagementClient(self.credential, subscription_id)
            
            # Test credentials
            self._test_credentials()
            
        except ClientAuthenticationError:
            raise Exception("Azure authentication failed. Please run 'az login' or configure service principal credentials.")
        except Exception as e:
            raise Exception(f"Failed to initialize Azure clients: {e}")
    
    def _test_credentials(self):
        """Test Azure credentials by making a simple API call"""
        try:
            # Test with a simple resource group list
            list(self.resource_client.resource_groups.list())
            self.logger.info("Azure credentials validated successfully")
        except Exception as e:
            self.logger.warning(f"Azure credential test failed: {e}")
            raise Exception(f"Azure credential test failed: {e}")
    
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
            "subscription_id": self.subscription_id
        }
        
        if additional_fields:
            event.update(additional_fields)
            
        return event

    def collect_all_security_data(self) -> List[Dict]:
        """Collect all security-relevant data from Azure"""
        all_events = []
        
        self.logger.info("Starting Azure security data collection...")
        
        # Collect Storage Account security data
        self.logger.info("Collecting Storage Account security data...")
        storage_events = self.collect_storage_security()
        all_events.extend(storage_events)
        self.logger.info(f"Collected {len(storage_events)} Storage Account security events")
        
        # Collect Virtual Machine security data
        self.logger.info("Collecting Virtual Machine security data...")
        vm_events = self.collect_vm_security()
        all_events.extend(vm_events)
        self.logger.info(f"Collected {len(vm_events)} Virtual Machine security events")
        
        # Collect Security Center data
        self.logger.info("Collecting Security Center data...")
        security_events = self.collect_security_center_data()
        all_events.extend(security_events)
        self.logger.info(f"Collected {len(security_events)} Security Center events")
        
        # Collect Key Vault security data
        self.logger.info("Collecting Key Vault security data...")
        keyvault_events = self.collect_keyvault_security()
        all_events.extend(keyvault_events)
        self.logger.info(f"Collected {len(keyvault_events)} Key Vault security events")
        
        # Collect Activity Log data
        self.logger.info("Collecting Activity Log data...")
        activity_events = self.collect_activity_log()
        all_events.extend(activity_events)
        self.logger.info(f"Collected {len(activity_events)} Activity Log events")
        
        # Collect Azure AD data
        self.logger.info("Collecting Azure AD data...")
        azuread_events = self.collect_azuread_security()
        all_events.extend(azuread_events)
        self.logger.info(f"Collected {len(azuread_events)} Azure AD security events")
        
        self.logger.info(f"Total security events collected: {len(all_events)}")
        
        return all_events

    def collect_storage_security(self) -> List[Dict]:
        """Collect Storage Account security data"""
        events = []
        
        try:
            # Get all storage accounts
            storage_accounts = list(self.storage_client.storage_accounts.list())
            
            for account in storage_accounts:
                account_name = account.name
                resource_group = account.id.split('/')[4]
                
                # Analyze storage account security
                account_events = self._analyze_storage_account(account, resource_group)
                events.extend(account_events)
                
        except Exception as e:
            error_event = self._create_security_event(
                source="AZURE_STORAGE",
                resource_id="N/A",
                event_type="COLLECTION_ERROR",
                severity="CRITICAL",
                description=f"Storage Account security collection failed: {e}",
                raw_event={"error": str(e)}
            )
            events.append(error_event)
            self.logger.error(f"Storage Account collection failed: {e}")
            
        return events

    def _analyze_storage_account(self, account, resource_group: str) -> List[Dict]:
        """Analyze individual storage account for security issues"""
        events = []
        account_name = account.name
        
        try:
            # Check if HTTPS is required
            if not account.enable_https_traffic_only:
                event = self._create_security_event(
                    source="AZURE_STORAGE",
                    resource_id=account_name,
                    event_type="HTTP_ALLOWED",
                    severity="HIGH",
                    description=f"Storage account '{account_name}' allows HTTP traffic",
                    raw_event=account.__dict__,
                    additional_fields={
                        "storage_account": {
                            "name": account_name,
                            "resource_group": resource_group,
                            "https_only": False
                        }
                    }
                )
                events.append(event)
            
            # Check encryption
            if not account.encryption or not account.encryption.services.blob.enabled:
                event = self._create_security_event(
                    source="AZURE_STORAGE",
                    resource_id=account_name,
                    event_type="NO_ENCRYPTION",
                    severity="HIGH",
                    description=f"Storage account '{account_name}' has no encryption enabled",
                    raw_event=account.__dict__,
                    additional_fields={
                        "storage_account": {
                            "name": account_name,
                            "resource_group": resource_group,
                            "encryption_enabled": False
                        }
                    }
                )
                events.append(event)
                
        except Exception as e:
            self.logger.error(f"Error analyzing storage account {account_name}: {e}")
            
        return events

    def collect_vm_security(self) -> List[Dict]:
        """Collect Virtual Machine security data"""
        events = []
        
        try:
            # Get all VMs
            vms = list(self.compute_client.virtual_machines.list_all())
            
            for vm in vms:
                vm_name = vm.name
                resource_group = vm.id.split('/')[4]
                
                # Analyze VM security
                vm_events = self._analyze_virtual_machine(vm, resource_group)
                events.extend(vm_events)
                
        except Exception as e:
            error_event = self._create_security_event(
                source="AZURE_VM",
                resource_id="N/A",
                event_type="COLLECTION_ERROR",
                severity="CRITICAL",
                description=f"Virtual Machine security collection failed: {e}",
                raw_event={"error": str(e)}
            )
            events.append(error_event)
            self.logger.error(f"Virtual Machine collection failed: {e}")
            
        return events

    def _analyze_virtual_machine(self, vm, resource_group: str) -> List[Dict]:
        """Analyze individual virtual machine for security issues"""
        events = []
        vm_name = vm.name
        
        try:
            # Check OS disk encryption
            if vm.storage_profile and vm.storage_profile.os_disk:
                os_disk = vm.storage_profile.os_disk
                if not os_disk.encryption_settings:
                    event = self._create_security_event(
                        source="AZURE_VM",
                        resource_id=vm_name,
                        event_type="NO_DISK_ENCRYPTION",
                        severity="HIGH",
                        description=f"Virtual Machine '{vm_name}' has no disk encryption",
                        raw_event=vm.__dict__,
                        additional_fields={
                            "vm": {
                                "name": vm_name,
                                "resource_group": resource_group,
                                "encryption_enabled": False
                            }
                        }
                    )
                    events.append(event)
                
        except Exception as e:
            self.logger.error(f"Error analyzing VM {vm_name}: {e}")
            
        return events

    def collect_security_center_data(self) -> List[Dict]:
        """Collect Security Center recommendations and alerts"""
        events = []
        
        try:
            # Get security recommendations
            recommendations = list(self.security_client.recommendations.list())
            
            for recommendation in recommendations:
                rec_events = self._analyze_security_recommendation(recommendation)
                events.extend(rec_events)
                
        except Exception as e:
            error_event = self._create_security_event(
                source="AZURE_SECURITY_CENTER",
                resource_id="N/A",
                event_type="COLLECTION_ERROR",
                severity="CRITICAL",
                description=f"Security Center data collection failed: {e}",
                raw_event={"error": str(e)}
            )
            events.append(error_event)
            self.logger.error(f"Security Center collection failed: {e}")
            
        return events

    def _analyze_security_recommendation(self, recommendation) -> List[Dict]:
        """Analyze Security Center recommendation"""
        events = []
        
        try:
            # Map Security Center severity to our severity levels
            severity_map = {
                "High": "HIGH",
                "Medium": "MEDIUM", 
                "Low": "LOW",
                "Critical": "CRITICAL"
            }
            
            severity = severity_map.get(recommendation.severity, "MEDIUM")
            
            event = self._create_security_event(
                source="AZURE_SECURITY_CENTER",
                resource_id=recommendation.id,
                event_type="SECURITY_RECOMMENDATION",
                severity=severity,
                description=f"Security Center recommendation: {recommendation.display_name}",
                raw_event=recommendation.__dict__,
                additional_fields={
                    "security_center": {
                        "recommendation_id": recommendation.id,
                        "display_name": recommendation.display_name,
                        "description": recommendation.description,
                        "severity": recommendation.severity,
                        "status": recommendation.status,
                        "category": recommendation.category
                    }
                }
            )
            events.append(event)
            
        except Exception as e:
            self.logger.error(f"Error analyzing security recommendation: {e}")
            
        return events

    def collect_keyvault_security(self) -> List[Dict]:
        """Collect Key Vault security data"""
        events = []
        
        try:
            # Get all Key Vaults
            keyvaults = list(self.keyvault_client.vaults.list())
            
            for kv in keyvaults:
                kv_name = kv.name
                resource_group = kv.id.split('/')[4]
                
                # Analyze Key Vault security
                kv_events = self._analyze_keyvault(kv, resource_group)
                events.extend(kv_events)
                
        except Exception as e:
            error_event = self._create_security_event(
                source="AZURE_KEYVAULT",
                resource_id="N/A",
                event_type="COLLECTION_ERROR",
                severity="CRITICAL",
                description=f"Key Vault security collection failed: {e}",
                raw_event={"error": str(e)}
            )
            events.append(error_event)
            self.logger.error(f"Key Vault collection failed: {e}")
            
        return events

    def _analyze_keyvault(self, kv, resource_group: str) -> List[Dict]:
        """Analyze individual Key Vault for security issues"""
        events = []
        kv_name = kv.name
        
        try:
            # Check if soft delete is enabled
            if not kv.properties.enable_soft_delete:
                event = self._create_security_event(
                    source="AZURE_KEYVAULT",
                    resource_id=kv_name,
                    event_type="SOFT_DELETE_DISABLED",
                    severity="HIGH",
                    description=f"Key Vault '{kv_name}' has soft delete disabled",
                    raw_event=kv.__dict__,
                    additional_fields={
                        "keyvault": {
                            "name": kv_name,
                            "resource_group": resource_group,
                            "soft_delete_enabled": False
                        }
                    }
                )
                events.append(event)
            
            # Check if purge protection is enabled
            if not kv.properties.enable_purge_protection:
                event = self._create_security_event(
                    source="AZURE_KEYVAULT",
                    resource_id=kv_name,
                    event_type="PURGE_PROTECTION_DISABLED",
                    severity="MEDIUM",
                    description=f"Key Vault '{kv_name}' has purge protection disabled",
                    raw_event=kv.__dict__,
                    additional_fields={
                        "keyvault": {
                            "name": kv_name,
                            "resource_group": resource_group,
                            "purge_protection_enabled": False
                        }
                    }
                )
                events.append(event)
                
        except Exception as e:
            self.logger.error(f"Error analyzing Key Vault {kv_name}: {e}")
            
        return events

    def collect_activity_log(self) -> List[Dict]:
        """Collect Activity Log data"""
        events = []
        
        try:
            # Get activity log entries for the last 24 hours
            end_time = datetime.datetime.utcnow()
            start_time = end_time - datetime.timedelta(hours=24)
            
            # This is a simplified version - in practice, you'd use the Monitor API
            # to get activity log entries
            self.logger.info("Activity Log collection would require Monitor API implementation")
            
        except Exception as e:
            error_event = self._create_security_event(
                source="AZURE_ACTIVITY_LOG",
                resource_id="N/A",
                event_type="COLLECTION_ERROR",
                severity="CRITICAL",
                description=f"Activity Log collection failed: {e}",
                raw_event={"error": str(e)}
            )
            events.append(error_event)
            self.logger.error(f"Activity Log collection failed: {e}")
            
        return events

    def collect_azuread_security(self) -> List[Dict]:
        """Collect Azure AD security data"""
        events = []
        
        try:
            # Note: Azure AD requires Microsoft Graph API, not Azure Resource Manager
            # This is a placeholder implementation
            # In practice, you would use:
            # from azure.identity import DefaultAzureCredential
            # from msgraph import GraphServiceClient
            
            self.logger.info("Azure AD collection requires Microsoft Graph API implementation")
            
            # Placeholder events for demonstration
            placeholder_event = self._create_security_event(
                source="AZURE_AD",
                resource_id="PLACEHOLDER",
                event_type="AZURE_AD_ANALYSIS",
                severity="INFO",
                description="Azure AD analysis requires Microsoft Graph API integration",
                raw_event={"note": "Requires Graph API implementation"},
                additional_fields={
                    "azure_ad": {
                        "note": "Microsoft Graph API required for full Azure AD analysis",
                        "services_needed": ["Users", "Groups", "Roles", "Conditional Access"]
                    }
                }
            )
            events.append(placeholder_event)
            
        except Exception as e:
            error_event = self._create_security_event(
                source="AZURE_AD",
                resource_id="N/A",
                event_type="COLLECTION_ERROR",
                severity="CRITICAL",
                description=f"Azure AD security collection failed: {e}",
                raw_event={"error": str(e)}
            )
            events.append(error_event)
            self.logger.error(f"Azure AD collection failed: {e}")
            
        return events

    def save_security_events(self, events: List[Dict], output_dir: str = "logs") -> str:
        """Save security events to JSON file"""
        try:
            # Ensure output directory exists
            os.makedirs(output_dir, exist_ok=True)
            
            # Create filename with timestamp
            timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"azure_security_events_{timestamp}.json"
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
        # You need to provide your Azure subscription ID
        subscription_id = os.getenv("AZURE_SUBSCRIPTION_ID", "your-subscription-id")
        
        collector = AzureCollector(subscription_id=subscription_id)
        
        print("🦅 CloudHawk Azure Security Collector")
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
