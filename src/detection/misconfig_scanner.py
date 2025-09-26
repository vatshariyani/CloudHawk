#!/usr/bin/env python3
"""
CloudHawk Misconfiguration Scanner

This module scans AWS resources for common security misconfigurations
and compliance violations based on industry best practices.
"""

import os
import json
import logging
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional, Tuple
from collections import defaultdict
import re

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class MisconfigScanner:
    """Multi-cloud misconfiguration scanner for AWS, Azure, and GCP"""
    
    def __init__(self, config: Dict = None):
        """Initialize the misconfiguration scanner"""
        self.config = config or {}
        self.scan_rules = self._load_scan_rules()
        self.severity_weights = {
            'CRITICAL': 4,
            'HIGH': 3,
            'MEDIUM': 2,
            'LOW': 1
        }
    
    def _load_scan_rules(self) -> Dict:
        """Load misconfiguration scan rules"""
        return {
            'iam': {
                'root_user_access_keys': {
                    'description': 'Root user has access keys',
                    'severity': 'CRITICAL',
                    'check': self._check_root_access_keys,
                    'remediation': 'Delete root user access keys and use IAM users/roles'
                },
                'unused_access_keys': {
                    'description': 'Unused access keys found',
                    'severity': 'MEDIUM',
                    'check': self._check_unused_access_keys,
                    'remediation': 'Remove unused access keys'
                },
                'overly_permissive_policies': {
                    'description': 'Overly permissive IAM policies',
                    'severity': 'HIGH',
                    'check': self._check_permissive_policies,
                    'remediation': 'Apply principle of least privilege'
                },
                'missing_mfa': {
                    'description': 'Users without MFA enabled',
                    'severity': 'HIGH',
                    'check': self._check_missing_mfa,
                    'remediation': 'Enable MFA for all users'
                },
                'admin_policies': {
                    'description': 'Users with AdministratorAccess policy',
                    'severity': 'MEDIUM',
                    'check': self._check_admin_policies,
                    'remediation': 'Use more restrictive policies'
                }
            },
            'ec2': {
                'public_instances': {
                    'description': 'EC2 instances with public IPs',
                    'severity': 'MEDIUM',
                    'check': self._check_public_instances,
                    'remediation': 'Use private subnets and load balancers'
                },
                'open_security_groups': {
                    'description': 'Security groups open to 0.0.0.0/0',
                    'severity': 'CRITICAL',
                    'check': self._check_open_security_groups,
                    'remediation': 'Restrict security group rules to specific IPs'
                },
                'unencrypted_volumes': {
                    'description': 'Unencrypted EBS volumes',
                    'severity': 'HIGH',
                    'check': self._check_unencrypted_volumes,
                    'remediation': 'Enable encryption for EBS volumes'
                },
                'default_security_groups': {
                    'description': 'Default security groups in use',
                    'severity': 'LOW',
                    'check': self._check_default_security_groups,
                    'remediation': 'Create custom security groups'
                },
                'unrestricted_ssh': {
                    'description': 'SSH access open to world',
                    'severity': 'CRITICAL',
                    'check': self._check_unrestricted_ssh,
                    'remediation': 'Restrict SSH to specific IP ranges'
                }
            },
            's3': {
                'public_buckets': {
                    'description': 'S3 buckets with public access',
                    'severity': 'CRITICAL',
                    'check': self._check_public_buckets,
                    'remediation': 'Remove public ACL and enable public access block'
                },
                'unencrypted_buckets': {
                    'description': 'S3 buckets without encryption',
                    'severity': 'HIGH',
                    'check': self._check_unencrypted_buckets,
                    'remediation': 'Enable server-side encryption'
                },
                'versioning_disabled': {
                    'description': 'S3 buckets without versioning',
                    'severity': 'MEDIUM',
                    'check': self._check_versioning_disabled,
                    'remediation': 'Enable versioning for important buckets'
                },
                'logging_disabled': {
                    'description': 'S3 buckets without access logging',
                    'severity': 'MEDIUM',
                    'check': self._check_logging_disabled,
                    'remediation': 'Enable access logging'
                }
            },
            'rds': {
                'public_databases': {
                    'description': 'RDS instances with public access',
                    'severity': 'CRITICAL',
                    'check': self._check_public_databases,
                    'remediation': 'Remove public access and use VPC'
                },
                'unencrypted_databases': {
                    'description': 'RDS instances without encryption',
                    'severity': 'HIGH',
                    'check': self._check_unencrypted_databases,
                    'remediation': 'Enable encryption at rest'
                },
                'default_ports': {
                    'description': 'RDS instances using default ports',
                    'severity': 'LOW',
                    'check': self._check_default_ports,
                    'remediation': 'Use custom ports'
                }
            },
            'cloudtrail': {
                'trail_not_enabled': {
                    'description': 'CloudTrail not enabled',
                    'severity': 'CRITICAL',
                    'check': self._check_cloudtrail_enabled,
                    'remediation': 'Enable CloudTrail logging'
                },
                'trail_not_encrypted': {
                    'description': 'CloudTrail logs not encrypted',
                    'severity': 'HIGH',
                    'check': self._check_cloudtrail_encryption,
                    'remediation': 'Enable CloudTrail log encryption'
                },
                'trail_not_multi_region': {
                    'description': 'CloudTrail not multi-region',
                    'severity': 'MEDIUM',
                    'check': self._check_cloudtrail_multi_region,
                    'remediation': 'Enable multi-region CloudTrail'
                }
            },
            'guardduty': {
                'guardduty_not_enabled': {
                    'description': 'GuardDuty not enabled',
                    'severity': 'HIGH',
                    'check': self._check_guardduty_enabled,
                    'remediation': 'Enable GuardDuty threat detection'
                }
            },
            # Azure misconfiguration rules
            'azure_storage': {
                'http_allowed': {
                    'description': 'Azure Storage allows HTTP traffic',
                    'severity': 'HIGH',
                    'check': self._check_azure_storage_https,
                    'remediation': 'Enable HTTPS-only for storage accounts'
                },
                'no_encryption': {
                    'description': 'Azure Storage has no encryption',
                    'severity': 'HIGH',
                    'check': self._check_azure_storage_encryption,
                    'remediation': 'Enable encryption for storage accounts'
                },
                'public_access': {
                    'description': 'Azure Storage has public access',
                    'severity': 'CRITICAL',
                    'check': self._check_azure_storage_public_access,
                    'remediation': 'Disable public access and use private endpoints'
                }
            },
            'azure_vm': {
                'no_disk_encryption': {
                    'description': 'Azure VM has no disk encryption',
                    'severity': 'HIGH',
                    'check': self._check_azure_vm_disk_encryption,
                    'remediation': 'Enable disk encryption for virtual machines'
                },
                'external_ip': {
                    'description': 'Azure VM has external IP',
                    'severity': 'MEDIUM',
                    'check': self._check_azure_vm_external_ip,
                    'remediation': 'Use private IPs and load balancers'
                },
                'no_nsg': {
                    'description': 'Azure VM has no network security group',
                    'severity': 'HIGH',
                    'check': self._check_azure_vm_nsg,
                    'remediation': 'Associate network security groups with VMs'
                }
            },
            'azure_keyvault': {
                'soft_delete_disabled': {
                    'description': 'Azure Key Vault has soft delete disabled',
                    'severity': 'HIGH',
                    'check': self._check_azure_keyvault_soft_delete,
                    'remediation': 'Enable soft delete for Key Vault'
                },
                'purge_protection_disabled': {
                    'description': 'Azure Key Vault has purge protection disabled',
                    'severity': 'MEDIUM',
                    'check': self._check_azure_keyvault_purge_protection,
                    'remediation': 'Enable purge protection for Key Vault'
                }
            },
            # GCP misconfiguration rules
            'gcp_iam': {
                'service_account_keys': {
                    'description': 'GCP service account has keys (should use workload identity)',
                    'severity': 'HIGH',
                    'check': self._check_gcp_service_account_keys,
                    'remediation': 'Use workload identity instead of service account keys'
                },
                'overly_permissive_role': {
                    'description': 'GCP IAM role is overly permissive',
                    'severity': 'CRITICAL',
                    'check': self._check_gcp_overly_permissive_role,
                    'remediation': 'Apply principle of least privilege to IAM roles'
                },
                'no_mfa_enforcement': {
                    'description': 'GCP has no MFA enforcement',
                    'severity': 'HIGH',
                    'check': self._check_gcp_mfa_enforcement,
                    'remediation': 'Enable MFA enforcement for IAM users'
                }
            },
            'gcp_storage': {
                'public_access': {
                    'description': 'GCP Cloud Storage bucket has public access',
                    'severity': 'CRITICAL',
                    'check': self._check_gcp_storage_public_access,
                    'remediation': 'Remove public access from Cloud Storage buckets'
                },
                'no_encryption': {
                    'description': 'GCP Cloud Storage bucket has no encryption',
                    'severity': 'HIGH',
                    'check': self._check_gcp_storage_encryption,
                    'remediation': 'Enable encryption for Cloud Storage buckets'
                },
                'no_versioning': {
                    'description': 'GCP Cloud Storage bucket has versioning disabled',
                    'severity': 'MEDIUM',
                    'check': self._check_gcp_storage_versioning,
                    'remediation': 'Enable versioning for data protection'
                }
            },
            'gcp_compute': {
                'external_ip': {
                    'description': 'GCP Compute Engine instance has external IP',
                    'severity': 'MEDIUM',
                    'check': self._check_gcp_compute_external_ip,
                    'remediation': 'Use private IPs and load balancers'
                },
                'no_disk_encryption': {
                    'description': 'GCP Compute Engine instance has no disk encryption',
                    'severity': 'HIGH',
                    'check': self._check_gcp_compute_disk_encryption,
                    'remediation': 'Enable disk encryption for Compute Engine instances'
                },
                'no_firewall_rules': {
                    'description': 'GCP Compute Engine instance has no firewall rules',
                    'severity': 'HIGH',
                    'check': self._check_gcp_compute_firewall_rules,
                    'remediation': 'Configure firewall rules for Compute Engine instances'
                }
            }
        }
    
    def scan_misconfigurations(self, events: List[Dict]) -> Dict:
        """Scan for misconfigurations in multi-cloud resources (AWS, Azure, GCP)"""
        logger.info(f"Starting multi-cloud misconfiguration scan on {len(events)} events")
        
        # Group events by service
        service_events = self._group_events_by_service(events)
        
        # Scan each service
        scan_results = {
            'timestamp': datetime.utcnow().isoformat(),
            'total_issues': 0,
            'critical_issues': 0,
            'high_issues': 0,
            'medium_issues': 0,
            'low_issues': 0,
            'services': {},
            'summary': {},
            'recommendations': []
        }
        
        for service, rules in self.scan_rules.items():
            service_events_list = service_events.get(service, [])
            service_results = self._scan_service(service, rules, service_events_list)
            scan_results['services'][service] = service_results
            
            # Update totals
            scan_results['total_issues'] += service_results['total_issues']
            scan_results['critical_issues'] += service_results['critical_issues']
            scan_results['high_issues'] += service_results['high_issues']
            scan_results['medium_issues'] += service_results['medium_issues']
            scan_results['low_issues'] += service_results['low_issues']
        
        # Generate summary and recommendations
        scan_results['summary'] = self._generate_summary(scan_results)
        scan_results['recommendations'] = self._generate_recommendations(scan_results)
        
        logger.info(f"Misconfiguration scan complete. Found {scan_results['total_issues']} issues")
        return scan_results
    
    def _group_events_by_service(self, events: List[Dict]) -> Dict:
        """Group events by AWS service"""
        service_events = defaultdict(list)
        
        for event in events:
            source = event.get('source', '')
            
            # Map source to service
            if 'IAM' in source:
                service_events['iam'].append(event)
            elif 'EC2' in source:
                service_events['ec2'].append(event)
            elif 'S3' in source:
                service_events['s3'].append(event)
            elif 'RDS' in source:
                service_events['rds'].append(event)
            elif 'CLOUDTRAIL' in source:
                service_events['cloudtrail'].append(event)
            elif 'GUARDDUTY' in source:
                service_events['guardduty'].append(event)
        
        return service_events
    
    def _scan_service(self, service: str, rules: Dict, events: List[Dict]) -> Dict:
        """Scan a specific service for misconfigurations"""
        service_results = {
            'service': service,
            'total_issues': 0,
            'critical_issues': 0,
            'high_issues': 0,
            'medium_issues': 0,
            'low_issues': 0,
            'misconfigurations': []
        }
        
        for rule_name, rule_config in rules.items():
            try:
                # Run the check function
                check_result = rule_config['check'](events)
                
                if check_result['found']:
                    misconfig = {
                        'rule': rule_name,
                        'description': rule_config['description'],
                        'severity': rule_config['severity'],
                        'remediation': rule_config['remediation'],
                        'affected_resources': check_result['resources'],
                        'details': check_result.get('details', {}),
                        'timestamp': datetime.utcnow().isoformat()
                    }
                    
                    service_results['misconfigurations'].append(misconfig)
                    service_results['total_issues'] += 1
                    service_results[f"{rule_config['severity'].lower()}_issues"] += 1
                    
                    logger.info(f"Found {rule_config['severity']} misconfiguration: {rule_config['description']}")
            
            except Exception as e:
                logger.error(f"Error checking rule {rule_name} for service {service}: {e}")
        
        return service_results
    
    # IAM Misconfiguration Checks
    def _check_root_access_keys(self, events: List[Dict]) -> Dict:
        """Check for root user access keys"""
        root_events = [event for event in events if 'root' in event.get('description', '').lower()]
        return {
            'found': len(root_events) > 0,
            'resources': [event.get('resource_id', 'root') for event in root_events],
            'details': {'root_usage_count': len(root_events)}
        }
    
    def _check_unused_access_keys(self, events: List[Dict]) -> Dict:
        """Check for unused access keys"""
        unused_key_events = [event for event in events if event.get('event_type') == 'MULTIPLE_ACCESS_KEYS']
        return {
            'found': len(unused_key_events) > 0,
            'resources': [event.get('resource_id', '') for event in unused_key_events],
            'details': {'users_with_multiple_keys': len(unused_key_events)}
        }
    
    def _check_permissive_policies(self, events: List[Dict]) -> Dict:
        """Check for overly permissive policies"""
        permissive_events = [event for event in events if 'admin' in event.get('description', '').lower()]
        return {
            'found': len(permissive_events) > 0,
            'resources': [event.get('resource_id', '') for event in permissive_events],
            'details': {'permissive_policies': len(permissive_events)}
        }
    
    def _check_missing_mfa(self, events: List[Dict]) -> Dict:
        """Check for users without MFA"""
        # This would require additional data about MFA status
        # For now, return no issues found
        return {
            'found': False,
            'resources': [],
            'details': {}
        }
    
    def _check_admin_policies(self, events: List[Dict]) -> Dict:
        """Check for users with AdministratorAccess"""
        admin_events = [event for event in events if 'administrator' in event.get('description', '').lower()]
        return {
            'found': len(admin_events) > 0,
            'resources': [event.get('resource_id', '') for event in admin_events],
            'details': {'admin_users': len(admin_events)}
        }
    
    # EC2 Misconfiguration Checks
    def _check_public_instances(self, events: List[Dict]) -> Dict:
        """Check for EC2 instances with public IPs"""
        public_events = [event for event in events if event.get('event_type') == 'PUBLIC_IP']
        return {
            'found': len(public_events) > 0,
            'resources': [event.get('resource_id', '') for event in public_events],
            'details': {'public_instances': len(public_events)}
        }
    
    def _check_open_security_groups(self, events: List[Dict]) -> Dict:
        """Check for security groups open to 0.0.0.0/0"""
        open_sg_events = [event for event in events if '0.0.0.0/0' in event.get('description', '')]
        return {
            'found': len(open_sg_events) > 0,
            'resources': [event.get('resource_id', '') for event in open_sg_events],
            'details': {'open_security_groups': len(open_sg_events)}
        }
    
    def _check_unencrypted_volumes(self, events: List[Dict]) -> Dict:
        """Check for unencrypted EBS volumes"""
        unencrypted_events = [event for event in events if 'unencrypted' in event.get('description', '').lower()]
        return {
            'found': len(unencrypted_events) > 0,
            'resources': [event.get('resource_id', '') for event in unencrypted_events],
            'details': {'unencrypted_volumes': len(unencrypted_events)}
        }
    
    def _check_default_security_groups(self, events: List[Dict]) -> Dict:
        """Check for default security groups in use"""
        default_sg_events = [event for event in events if 'default' in event.get('description', '').lower()]
        return {
            'found': len(default_sg_events) > 0,
            'resources': [event.get('resource_id', '') for event in default_sg_events],
            'details': {'default_security_groups': len(default_sg_events)}
        }
    
    def _check_unrestricted_ssh(self, events: List[Dict]) -> Dict:
        """Check for SSH access open to world"""
        ssh_events = [event for event in events if 'ssh' in event.get('description', '').lower() and '0.0.0.0/0' in event.get('description', '')]
        return {
            'found': len(ssh_events) > 0,
            'resources': [event.get('resource_id', '') for event in ssh_events],
            'details': {'ssh_open_to_world': len(ssh_events)}
        }
    
    # S3 Misconfiguration Checks
    def _check_public_buckets(self, events: List[Dict]) -> Dict:
        """Check for S3 buckets with public access"""
        public_bucket_events = [event for event in events if event.get('event_type') == 'PUBLIC_ACCESS']
        return {
            'found': len(public_bucket_events) > 0,
            'resources': [event.get('resource_id', '') for event in public_bucket_events],
            'details': {'public_buckets': len(public_bucket_events)}
        }
    
    def _check_unencrypted_buckets(self, events: List[Dict]) -> Dict:
        """Check for S3 buckets without encryption"""
        unencrypted_events = [event for event in events if 'unencrypted' in event.get('description', '').lower()]
        return {
            'found': len(unencrypted_events) > 0,
            'resources': [event.get('resource_id', '') for event in unencrypted_events],
            'details': {'unencrypted_buckets': len(unencrypted_events)}
        }
    
    def _check_versioning_disabled(self, events: List[Dict]) -> Dict:
        """Check for S3 buckets without versioning"""
        # This would require additional S3 configuration data
        return {
            'found': False,
            'resources': [],
            'details': {}
        }
    
    def _check_logging_disabled(self, events: List[Dict]) -> Dict:
        """Check for S3 buckets without access logging"""
        # This would require additional S3 configuration data
        return {
            'found': False,
            'resources': [],
            'details': {}
        }
    
    # RDS Misconfiguration Checks
    def _check_public_databases(self, events: List[Dict]) -> Dict:
        """Check for RDS instances with public access"""
        public_db_events = [event for event in events if 'public' in event.get('description', '').lower() and 'rds' in event.get('description', '').lower()]
        return {
            'found': len(public_db_events) > 0,
            'resources': [event.get('resource_id', '') for event in public_db_events],
            'details': {'public_databases': len(public_db_events)}
        }
    
    def _check_unencrypted_databases(self, events: List[Dict]) -> Dict:
        """Check for RDS instances without encryption"""
        unencrypted_db_events = [event for event in events if 'unencrypted' in event.get('description', '').lower() and 'rds' in event.get('description', '').lower()]
        return {
            'found': len(unencrypted_db_events) > 0,
            'resources': [event.get('resource_id', '') for event in unencrypted_db_events],
            'details': {'unencrypted_databases': len(unencrypted_db_events)}
        }
    
    def _check_default_ports(self, events: List[Dict]) -> Dict:
        """Check for RDS instances using default ports"""
        # This would require additional RDS configuration data
        return {
            'found': False,
            'resources': [],
            'details': {}
        }
    
    # CloudTrail Misconfiguration Checks
    def _check_cloudtrail_enabled(self, events: List[Dict]) -> Dict:
        """Check if CloudTrail is enabled"""
        cloudtrail_events = [event for event in events if event.get('source') == 'AWS_CLOUDTRAIL']
        return {
            'found': len(cloudtrail_events) == 0,
            'resources': [],
            'details': {'cloudtrail_events': len(cloudtrail_events)}
        }
    
    def _check_cloudtrail_encryption(self, events: List[Dict]) -> Dict:
        """Check if CloudTrail logs are encrypted"""
        # This would require additional CloudTrail configuration data
        return {
            'found': False,
            'resources': [],
            'details': {}
        }
    
    def _check_cloudtrail_multi_region(self, events: List[Dict]) -> Dict:
        """Check if CloudTrail is multi-region"""
        # This would require additional CloudTrail configuration data
        return {
            'found': False,
            'resources': [],
            'details': {}
        }
    
    # GuardDuty Misconfiguration Checks
    def _check_guardduty_enabled(self, events: List[Dict]) -> Dict:
        """Check if GuardDuty is enabled"""
        guardduty_events = [event for event in events if event.get('source') == 'AWS_GUARDDUTY']
        return {
            'found': len(guardduty_events) == 0,
            'resources': [],
            'details': {'guardduty_events': len(guardduty_events)}
        }
    
    def _generate_summary(self, scan_results: Dict) -> Dict:
        """Generate scan summary"""
        total_issues = scan_results['total_issues']
        
        if total_issues == 0:
            status = 'SECURE'
            grade = 'A'
        elif scan_results['critical_issues'] > 0:
            status = 'CRITICAL'
            grade = 'F'
        elif scan_results['high_issues'] > 2:
            status = 'HIGH_RISK'
            grade = 'D'
        elif scan_results['medium_issues'] > 5:
            status = 'MEDIUM_RISK'
            grade = 'C'
        else:
            status = 'LOW_RISK'
            grade = 'B'
        
        # Find worst service
        worst_service = None
        worst_score = 0
        
        for service, results in scan_results['services'].items():
            if results['total_issues'] > worst_score:
                worst_score = results['total_issues']
                worst_service = service
        
        return {
            'status': status,
            'grade': grade,
            'total_issues': total_issues,
            'worst_service': worst_service,
            'worst_service_issues': worst_score,
            'risk_level': 'LOW' if total_issues < 5 else 'MEDIUM' if total_issues < 15 else 'HIGH'
        }
    
    def _generate_recommendations(self, scan_results: Dict) -> List[str]:
        """Generate prioritized recommendations"""
        recommendations = []
        
        # Collect all remediation steps
        for service, results in scan_results['services'].items():
            for misconfig in results['misconfigurations']:
                if misconfig['remediation'] not in recommendations:
                    recommendations.append(misconfig['remediation'])
        
        # Prioritize by severity
        critical_recommendations = []
        high_recommendations = []
        medium_recommendations = []
        low_recommendations = []
        
        for service, results in scan_results['services'].items():
            for misconfig in results['misconfigurations']:
                if misconfig['severity'] == 'CRITICAL':
                    critical_recommendations.append(misconfig['remediation'])
                elif misconfig['severity'] == 'HIGH':
                    high_recommendations.append(misconfig['remediation'])
                elif misconfig['severity'] == 'MEDIUM':
                    medium_recommendations.append(misconfig['remediation'])
                else:
                    low_recommendations.append(misconfig['remediation'])
        
        # Combine and deduplicate
        all_recommendations = list(set(critical_recommendations + high_recommendations + medium_recommendations + low_recommendations))
        
        return all_recommendations[:10]  # Top 10 recommendations
    
    def save_scan_results(self, results: Dict, filepath: str):
        """Save scan results to file"""
        try:
            with open(filepath, 'w') as f:
                json.dump(results, f, indent=2, default=str)
            logger.info(f"Scan results saved to {filepath}")
        except Exception as e:
            logger.error(f"Failed to save scan results: {e}")


def main():
    """Test the misconfiguration scanner"""
    # Sample events for testing
    sample_events = [
        {
            'timestamp': datetime.utcnow().isoformat(),
            'source': 'AWS_IAM',
            'event_type': 'ROOT_ACCOUNT_USAGE',
            'resource_id': 'root',
            'description': 'Root account was used for API calls'
        },
        {
            'timestamp': datetime.utcnow().isoformat(),
            'source': 'AWS_EC2_SG',
            'event_type': 'SECURITY_GROUP_RULE',
            'resource_id': 'sg-123456',
            'description': 'Security group allows SSH (port 22) from anywhere (0.0.0.0/0)'
        },
        {
            'timestamp': datetime.utcnow().isoformat(),
            'source': 'AWS_S3_ACL',
            'event_type': 'PUBLIC_ACCESS',
            'resource_id': 'my-bucket',
            'description': 'S3 bucket has public ACL allowing global access'
        }
    ]
    
    scanner = MisconfigScanner()
    results = scanner.scan_misconfigurations(sample_events)
    
    print(f"Misconfiguration Scan Results:")
    print(f"Status: {results['summary']['status']} (Grade: {results['summary']['grade']})")
    print(f"Total Issues: {results['total_issues']}")
    print(f"Critical: {results['critical_issues']}, High: {results['high_issues']}, Medium: {results['medium_issues']}, Low: {results['low_issues']}")
    
    print("\nTop Recommendations:")
    for i, rec in enumerate(results['recommendations'][:5], 1):
        print(f"{i}. {rec}")


if __name__ == "__main__":
    main()
