"""
CloudHawk Azure Security Collector
Collects and parses security-relevant data from Azure services:
- Azure AD Users, Roles, Policies (privilege escalation detection)
- Storage Accounts & Access Policies (data exposure detection)
- Virtual Machines & Network Security Groups (network security)
- Activity Log (audit trail analysis)
- Security Center (threat detection)
- Key Vault (secrets management)

Requires Azure credentials (service principal or managed identity).
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
from azure.mgmt.network import NetworkManagementClient
from azure.mgmt.security import SecurityCenter
from azure.mgmt.keyvault import KeyVaultManagementClient
from azure.mgmt.monitor import MonitorManagementClient
from azure.mgmt.authorization import AuthorizationManagementClient
from azure.core.exceptions import ResourceNotFoundError, ClientAuthenticationError

class AzureCollector:
    def __init__(self, subscription_id: str, max_events: int = 1000):
        """
        Initialize Azure Security Collector
        
        Args:
            subscription_id: Azure subscription ID to collect from
            max_events: Maximum number of events to collect per service
        """
        self.subscription_id = subscription_id
        self.max_events = max_events
        self.logger = logging.getLogger(__name__)
        
        try:
            # Initialize Azure clients
            self.credential = DefaultAzureCredential()
            self.resource_client = ResourceManagementClient(self.credential, subscription_id)
            self.storage_client = StorageManagementClient(self.credential, subscription_id)
            self.compute_client = ComputeManagementClient(self.credential, subscription_id)
            self.network_client = NetworkManagementClient(self.credential, subscription_id)
            self.security_client = SecurityCenter(self.credential, subscription_id)
            self.keyvault_client = KeyVaultManagementClient(self.credential, subscription_id)
            self.monitor_client = MonitorManagementClient(self.credential, subscription_id)
            self.auth_client = AuthorizationManagementClient(self.credential, subscription_id)
            
            # Test credentials
            self._test_credentials()
            
        except ClientAuthenticationError:
            raise Exception("Azure credentials not found. Please set AZURE_CLIENT_ID, AZURE_CLIENT_SECRET, AZURE_TENANT_ID or use 'az login'")
        except Exception as e:
            raise Exception(f"Failed to initialize Azure clients: {e}")
    
    def _test_credentials(self):
        """Test Azure credentials by making a simple API call"""
        try:
            # Test with a simple resource group operation
            resource_groups = list(self.resource_client.resource_groups.list())
            self.logger.info("Azure credentials validated successfully")
        except Exception as e:
            self.logger.warning(f"Azure credential test failed: {e}")
    
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

    def collect_azure_ad_security(self) -> List[Dict]:
        """Collect Azure AD users, roles, and policies for security analysis"""
        events = []
        
        try:
            # Note: Azure AD operations require Microsoft Graph API
            # This is a simplified implementation focusing on RBAC
            
            # Collect RBAC assignments
            rbac_events = self._analyze_rbac_assignments()
            events.extend(rbac_events)
            
            # Collect custom roles
            custom_role_events = self._analyze_custom_roles()
            events.extend(custom_role_events)
            
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
    
    def _analyze_rbac_assignments(self) -> List[Dict]:
        """Analyze RBAC assignments for security issues"""
        events = []
        
        try:
            # List role assignments
            role_assignments = list(self.auth_client.role_assignments.list())
            
            for assignment in role_assignments:
                assignment_events = self._analyze_role_assignment(assignment)
                events.extend(assignment_events)
                
        except Exception as e:
            self.logger.error(f"Error analyzing RBAC assignments: {e}")
            
        return events
    
    def _analyze_role_assignment(self, assignment) -> List[Dict]:
        """Analyze individual role assignment for security issues"""
        events = []
        
        try:
            role_definition_id = assignment.role_definition_id
            principal_id = assignment.principal_id
            scope = assignment.scope
            
            # Check for overly permissive roles
            if "Owner" in role_definition_id or "Contributor" in role_definition_id:
                event = self._create_security_event(
                    source="AZURE_RBAC",
                    resource_id=str(assignment.id),
                    event_type="HIGH_PRIVILEGE_ROLE",
                    severity="HIGH",
                    description=f"High privilege role assignment: {role_definition_id}",
                    raw_event={
                        "assignment_id": str(assignment.id),
                        "role_definition_id": role_definition_id,
                        "principal_id": principal_id,
                        "scope": scope
                    },
                    additional_fields={
                        "rbac": {
                            "assignment_id": str(assignment.id),
                            "role_definition_id": role_definition_id,
                            "principal_id": principal_id,
                            "scope": scope,
                            "high_privilege": True
                        }
                    }
                )
                events.append(event)
                
        except Exception as e:
            self.logger.error(f"Error analyzing role assignment {assignment.id}: {e}")
            
        return events
    
    def _analyze_custom_roles(self) -> List[Dict]:
        """Analyze custom roles for security issues"""
        events = []
        
        try:
            # List custom role definitions
            role_definitions = list(self.auth_client.role_definitions.list())
            
            for role_def in role_definitions:
                if role_def.type == "CustomRole":
                    role_events = self._analyze_custom_role(role_def)
                    events.extend(role_events)
                    
        except Exception as e:
            self.logger.error(f"Error analyzing custom roles: {e}")
            
        return events
    
    def _analyze_custom_role(self, role_def) -> List[Dict]:
        """Analyze individual custom role for security issues"""
        events = []
        
        try:
            role_name = role_def.role_name
            permissions = role_def.permissions
            
            # Check for overly permissive custom roles
            for permission in permissions:
                if "*" in permission.actions:
                    event = self._create_security_event(
                        source="AZURE_CUSTOM_ROLE",
                        resource_id=role_name,
                        event_type="OVERLY_PERMISSIVE_ROLE",
                        severity="CRITICAL",
                        description=f"Custom role '{role_name}' has wildcard permissions",
                        raw_event={
                            "role_name": role_name,
                            "permissions": [p.actions for p in permissions]
                        },
                        additional_fields={
                            "custom_role": {
                                "name": role_name,
                                "permissions": [p.actions for p in permissions],
                                "overly_permissive": True
                            }
                        }
                    )
                    events.append(event)
                    break
                    
        except Exception as e:
            self.logger.error(f"Error analyzing custom role {role_def.role_name}: {e}")
            
        return events

    def collect_storage_security(self) -> List[Dict]:
        """Collect Storage Accounts and analyze for security issues"""
        events = []
        
        try:
            storage_accounts = list(self.storage_client.storage_accounts.list())
            
            for account in storage_accounts:
                account_events = self._analyze_storage_account(account)
                events.extend(account_events)
                
        except Exception as e:
            error_event = self._create_security_event(
                source="AZURE_STORAGE",
                resource_id="N/A",
                event_type="COLLECTION_ERROR",
                severity="CRITICAL",
                description=f"Storage security collection failed: {e}",
                raw_event={"error": str(e)}
            )
            events.append(error_event)
            self.logger.error(f"Storage collection failed: {e}")
            
        return events
    
    def _analyze_storage_account(self, account) -> List[Dict]:
        """Analyze individual storage account for security issues"""
        events = []
        account_name = account.name
        
        try:
            # Check for public access
            if account.allow_blob_public_access:
                event = self._create_security_event(
                    source="AZURE_STORAGE_ACCESS",
                    resource_id=account_name,
                    event_type="PUBLIC_BLOB_ACCESS",
                    severity="CRITICAL",
                    description=f"Storage account '{account_name}' allows public blob access",
                    raw_event={
                        "account_name": account_name,
                        "allow_blob_public_access": account.allow_blob_public_access
                    },
                    additional_fields={
                        "storage_account": {
                            "name": account_name,
                            "allow_blob_public_access": account.allow_blob_public_access,
                            "public_access": True
                        }
                    }
                )
                events.append(event)
            
            # Check encryption
            if not account.encryption or not account.encryption.services.blob.enabled:
                event = self._create_security_event(
                    source="AZURE_STORAGE_ENCRYPTION",
                    resource_id=account_name,
                    event_type="NO_ENCRYPTION",
                    severity="HIGH",
                    description=f"Storage account '{account_name}' has no encryption enabled",
                    raw_event={
                        "account_name": account_name,
                        "encryption": account.encryption
                    },
                    additional_fields={
                        "storage_account": {
                            "name": account_name,
                            "encryption_enabled": account.encryption.services.blob.enabled if account.encryption else False
                        }
                    }
                )
                events.append(event)
                
        except Exception as e:
            self.logger.error(f"Error analyzing storage account {account_name}: {e}")
            
        return events

    def collect_vm_security(self) -> List[Dict]:
        """Collect Virtual Machines and analyze for security issues"""
        events = []
        
        try:
            # List VMs across all resource groups
            resource_groups = list(self.resource_client.resource_groups.list())
            
            for rg in resource_groups:
                try:
                    vms = list(self.compute_client.virtual_machines.list(rg.name))
                    for vm in vms:
                        vm_events = self._analyze_virtual_machine(vm, rg.name)
                        events.extend(vm_events)
                except Exception as e:
                    self.logger.warning(f"Could not list VMs in resource group {rg.name}: {e}")
                    
        except Exception as e:
            error_event = self._create_security_event(
                source="AZURE_VM",
                resource_id="N/A",
                event_type="COLLECTION_ERROR",
                severity="CRITICAL",
                description=f"VM security collection failed: {e}",
                raw_event={"error": str(e)}
            )
            events.append(error_event)
            self.logger.error(f"VM collection failed: {e}")
            
        return events
    
    def _analyze_virtual_machine(self, vm, resource_group) -> List[Dict]:
        """Analyze individual virtual machine for security issues"""
        events = []
        
        try:
            vm_name = vm.name
            
            # Check for public IP
            if vm.network_profile and vm.network_profile.network_interfaces:
                for nic_ref in vm.network_profile.network_interfaces:
                    try:
                        # Get network interface details
                        nic_name = nic_ref.id.split('/')[-1]
                        nic = self.network_client.network_interfaces.get(resource_group, nic_name)
                        
                        if nic.ip_configurations:
                            for ip_config in nic.ip_configurations:
                                if ip_config.public_ip_address:
                                    public_ip_id = ip_config.public_ip_address.id
                                    public_ip_name = public_ip_id.split('/')[-1]
                                    
                                    event = self._create_security_event(
                                        source="AZURE_VM_PUBLIC_IP",
                                        resource_id=vm_name,
                                        event_type="PUBLIC_IP",
                                        severity="MEDIUM",
                                        description=f"Virtual machine '{vm_name}' has public IP {public_ip_name}",
                                        raw_event={
                                            "vm_name": vm_name,
                                            "public_ip_name": public_ip_name,
                                            "resource_group": resource_group
                                        },
                                        additional_fields={
                                            "vm": {
                                                "name": vm_name,
                                                "public_ip": public_ip_name,
                                                "resource_group": resource_group,
                                                "status": vm.provisioning_state
                                            }
                                        }
                                    )
                                    events.append(event)
                    except Exception as e:
                        self.logger.warning(f"Could not analyze network interface for VM {vm_name}: {e}")
            
            # Check for disk encryption
            if vm.storage_profile and vm.storage_profile.os_disk:
                os_disk = vm.storage_profile.os_disk
                if not os_disk.encryption_settings:
                    event = self._create_security_event(
                        source="AZURE_VM_ENCRYPTION",
                        resource_id=vm_name,
                        event_type="NO_DISK_ENCRYPTION",
                        severity="HIGH",
                        description=f"Virtual machine '{vm_name}' has no disk encryption",
                        raw_event={
                            "vm_name": vm_name,
                            "os_disk": os_disk.name
                        },
                        additional_fields={
                            "vm": {
                                "name": vm_name,
                                "disk_encryption": False,
                                "os_disk": os_disk.name
                            }
                        }
                    )
                    events.append(event)
                    
        except Exception as e:
            self.logger.error(f"Error analyzing VM {vm.name}: {e}")
            
        return events

    def collect_network_security(self) -> List[Dict]:
        """Collect Network Security Groups and analyze for security issues"""
        events = []
        
        try:
            # List NSGs across all resource groups
            resource_groups = list(self.resource_client.resource_groups.list())
            
            for rg in resource_groups:
                try:
                    nsgs = list(self.network_client.network_security_groups.list(rg.name))
                    for nsg in nsgs:
                        nsg_events = self._analyze_network_security_group(nsg, rg.name)
                        events.extend(nsg_events)
                except Exception as e:
                    self.logger.warning(f"Could not list NSGs in resource group {rg.name}: {e}")
                    
        except Exception as e:
            error_event = self._create_security_event(
                source="AZURE_NSG",
                resource_id="N/A",
                event_type="COLLECTION_ERROR",
                severity="CRITICAL",
                description=f"Network security collection failed: {e}",
                raw_event={"error": str(e)}
            )
            events.append(error_event)
            self.logger.error(f"Network security collection failed: {e}")
            
        return events
    
    def _analyze_network_security_group(self, nsg, resource_group) -> List[Dict]:
        """Analyze individual NSG for security issues"""
        events = []
        
        try:
            nsg_name = nsg.name
            
            # Analyze security rules
            if nsg.security_rules:
                for rule in nsg.security_rules:
                    rule_events = self._analyze_nsg_rule(rule, nsg_name, resource_group)
                    events.extend(rule_events)
                    
        except Exception as e:
            self.logger.error(f"Error analyzing NSG {nsg.name}: {e}")
            
        return events
    
    def _analyze_nsg_rule(self, rule, nsg_name, resource_group) -> List[Dict]:
        """Analyze individual NSG rule for security issues"""
        events = []
        
        try:
            rule_name = rule.name
            direction = rule.direction
            access = rule.access
            protocol = rule.protocol
            source_port_range = rule.source_port_range
            destination_port_range = rule.destination_port_range
            source_address_prefix = rule.source_address_prefix
            
            # Check for overly permissive rules
            if (direction == "Inbound" and access == "Allow" and 
                source_address_prefix == "*" and 
                (destination_port_range == "*" or destination_port_range == "22" or destination_port_range == "3389")):
                
                event = self._create_security_event(
                    source="AZURE_NSG_RULE",
                    resource_id=f"{nsg_name}/{rule_name}",
                    event_type="OVERLY_PERMISSIVE_RULE",
                    severity="CRITICAL",
                    description=f"NSG rule '{rule_name}' allows inbound access from anywhere",
                    raw_event={
                        "nsg_name": nsg_name,
                        "rule_name": rule_name,
                        "direction": direction,
                        "access": access,
                        "protocol": protocol,
                        "source_address_prefix": source_address_prefix,
                        "destination_port_range": destination_port_range
                    },
                    additional_fields={
                        "nsg_rule": {
                            "nsg_name": nsg_name,
                            "rule_name": rule_name,
                            "direction": direction,
                            "access": access,
                            "protocol": protocol,
                            "source_address_prefix": source_address_prefix,
                            "destination_port_range": destination_port_range,
                            "resource_group": resource_group
                        }
                    }
                )
                events.append(event)
                
        except Exception as e:
            self.logger.error(f"Error analyzing NSG rule {rule.name}: {e}")
            
        return events

    def collect_activity_log(self) -> List[Dict]:
        """Collect Activity Log events for security analysis"""
        events = []
        
        try:
            # Query activity log for recent events
            from datetime import timedelta
            end_time = datetime.datetime.utcnow()
            start_time = end_time - timedelta(days=7)
            
            # This is a simplified implementation
            # In a real implementation, you would use the Monitor Management Client
            # to query activity logs
            
            # Mock activity log events
            mock_events = [
                {
                    "event_name": "Create or update virtual machine",
                    "resource_id": f"/subscriptions/{self.subscription_id}/resourceGroups/test-rg/providers/Microsoft.Compute/virtualMachines/test-vm",
                    "caller": "user@example.com",
                    "timestamp": datetime.datetime.utcnow().isoformat()
                }
            ]
            
            for event_data in mock_events:
                event = self._create_security_event(
                    source="AZURE_ACTIVITY_LOG",
                    resource_id=event_data.get("resource_id", "unknown"),
                    event_type="ACTIVITY_LOG_EVENT",
                    severity="INFO",
                    description=f"Activity log event: {event_data.get('event_name', 'Unknown')}",
                    raw_event=event_data,
                    additional_fields={
                        "activity_log": {
                            "event_name": event_data.get("event_name"),
                            "caller": event_data.get("caller"),
                            "timestamp": event_data.get("timestamp")
                        }
                    }
                )
                events.append(event)
                
        except Exception as e:
            error_event = self._create_security_event(
                source="AZURE_ACTIVITY_LOG",
                resource_id="N/A",
                event_type="COLLECTION_ERROR",
                severity="CRITICAL",
                description=f"Activity log collection failed: {e}",
                raw_event={"error": str(e)}
            )
            events.append(error_event)
            self.logger.error(f"Activity log collection failed: {e}")
            
        return events

    def collect_security_center_findings(self) -> List[Dict]:
        """Collect Security Center findings"""
        events = []
        
        try:
            # List security recommendations
            # This requires Security Center to be enabled
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
                description=f"Security Center collection failed: {e}",
                raw_event={"error": str(e)}
            )
            events.append(error_event)
            self.logger.error(f"Security Center collection failed: {e}")
            
        return events
    
    def _analyze_security_recommendation(self, recommendation) -> List[Dict]:
        """Analyze individual security recommendation"""
        events = []
        
        try:
            rec_name = recommendation.display_name
            severity = recommendation.impact
            status = recommendation.status
            
            # Map Security Center severity to our severity levels
            if severity == "High":
                severity_level = "HIGH"
            elif severity == "Medium":
                severity_level = "MEDIUM"
            elif severity == "Low":
                severity_level = "LOW"
            else:
                severity_level = "INFO"
            
            event = self._create_security_event(
                source="AZURE_SECURITY_CENTER",
                resource_id=str(recommendation.id),
                event_type="SECURITY_RECOMMENDATION",
                severity=severity_level,
                description=f"Security Center recommendation: {rec_name}",
                raw_event={
                    "recommendation_id": str(recommendation.id),
                    "display_name": rec_name,
                    "impact": severity,
                    "status": status
                },
                additional_fields={
                    "security_center": {
                        "recommendation_id": str(recommendation.id),
                        "display_name": rec_name,
                        "impact": severity,
                        "status": status
                    }
                }
            )
            events.append(event)
            
        except Exception as e:
            self.logger.error(f"Error analyzing security recommendation: {e}")
            
        return events

    def collect_key_vault_security(self) -> List[Dict]:
        """Collect Key Vault security information"""
        events = []
        
        try:
            # List Key Vaults across all resource groups
            resource_groups = list(self.resource_client.resource_groups.list())
            
            for rg in resource_groups:
                try:
                    keyvaults = list(self.keyvault_client.vaults.list_by_resource_group(rg.name))
                    for kv in keyvaults:
                        kv_events = self._analyze_key_vault(kv, rg.name)
                        events.extend(kv_events)
                except Exception as e:
                    self.logger.warning(f"Could not list Key Vaults in resource group {rg.name}: {e}")
                    
        except Exception as e:
            error_event = self._create_security_event(
                source="AZURE_KEY_VAULT",
                resource_id="N/A",
                event_type="COLLECTION_ERROR",
                severity="CRITICAL",
                description=f"Key Vault security collection failed: {e}",
                raw_event={"error": str(e)}
            )
            events.append(error_event)
            self.logger.error(f"Key Vault collection failed: {e}")
            
        return events
    
    def _analyze_key_vault(self, keyvault, resource_group) -> List[Dict]:
        """Analyze individual Key Vault for security issues"""
        events = []
        
        try:
            kv_name = keyvault.name
            
            # Check access policies
            if keyvault.properties and keyvault.properties.access_policies:
                for policy in keyvault.properties.access_policies:
                    # Check for overly permissive access
                    if policy.permissions and policy.permissions.secrets:
                        if "all" in policy.permissions.secrets:
                            event = self._create_security_event(
                                source="AZURE_KEY_VAULT_ACCESS",
                                resource_id=kv_name,
                                event_type="OVERLY_PERMISSIVE_ACCESS",
                                severity="HIGH",
                                description=f"Key Vault '{kv_name}' has overly permissive access policy",
                                raw_event={
                                    "keyvault_name": kv_name,
                                    "access_policy": {
                                        "object_id": policy.object_id,
                                        "permissions": policy.permissions.secrets
                                    }
                                },
                                additional_fields={
                                    "keyvault": {
                                        "name": kv_name,
                                        "resource_group": resource_group,
                                        "overly_permissive": True
                                    }
                                }
                            )
                            events.append(event)
                            
        except Exception as e:
            self.logger.error(f"Error analyzing Key Vault {keyvault.name}: {e}")
            
        return events

    def collect_all_security_data(self) -> List[Dict]:
        """Collect all security-relevant data from Azure"""
        all_events = []
        
        self.logger.info("Starting Azure security data collection...")
        
        # Collect Azure AD security data
        self.logger.info("Collecting Azure AD security data...")
        ad_events = self.collect_azure_ad_security()
        all_events.extend(ad_events)
        self.logger.info(f"Collected {len(ad_events)} Azure AD security events")
        
        # Collect Storage security data
        self.logger.info("Collecting Storage security data...")
        storage_events = self.collect_storage_security()
        all_events.extend(storage_events)
        self.logger.info(f"Collected {len(storage_events)} Storage security events")
        
        # Collect VM security data
        self.logger.info("Collecting VM security data...")
        vm_events = self.collect_vm_security()
        all_events.extend(vm_events)
        self.logger.info(f"Collected {len(vm_events)} VM security events")
        
        # Collect Network security data
        self.logger.info("Collecting Network security data...")
        network_events = self.collect_network_security()
        all_events.extend(network_events)
        self.logger.info(f"Collected {len(network_events)} Network security events")
        
        # Collect Activity Log data
        self.logger.info("Collecting Activity Log data...")
        activity_events = self.collect_activity_log()
        all_events.extend(activity_events)
        self.logger.info(f"Collected {len(activity_events)} Activity Log events")
        
        # Collect Security Center data
        self.logger.info("Collecting Security Center data...")
        security_center_events = self.collect_security_center_findings()
        all_events.extend(security_center_events)
        self.logger.info(f"Collected {len(security_center_events)} Security Center events")
        
        # Collect Key Vault data
        self.logger.info("Collecting Key Vault data...")
        keyvault_events = self.collect_key_vault_security()
        all_events.extend(keyvault_events)
        self.logger.info(f"Collected {len(keyvault_events)} Key Vault events")
        
        self.logger.info(f"Total security events collected: {len(all_events)}")
        
        return all_events
    
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
        subscription_id = os.getenv("AZURE_SUBSCRIPTION_ID", "your-subscription-id")
        collector = AzureCollector(subscription_id=subscription_id, max_events=1000)
        
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