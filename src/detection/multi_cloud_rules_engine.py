#!/usr/bin/env python3
"""
CloudHawk Multi-Cloud Rules Engine

This module provides a comprehensive rules engine that supports AWS, Azure, and GCP
security rules with cross-cloud correlation capabilities.
"""

import os
import json
import yaml
import logging
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional, Tuple
from collections import defaultdict
import re

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class MultiCloudRulesEngine:
    """Multi-cloud security rules engine for AWS, Azure, and GCP"""
    
    def __init__(self, rules_file: str = None, config: Dict = None):
        """Initialize the multi-cloud rules engine"""
        self.config = config or {}
        self.rules_file = rules_file or 'src/detection/security_rules.yaml'
        self.rules = self._load_rules()
        self.cross_cloud_rules = self._load_cross_cloud_rules()
        self.alert_count = 0
        self.alerts = []
        
    def _load_rules(self) -> List[Dict]:
        """Load security rules from YAML file"""
        try:
            with open(self.rules_file, 'r') as f:
                rules_data = yaml.safe_load(f)
                return rules_data.get('rules', [])
        except Exception as e:
            logger.error(f"Failed to load rules from {self.rules_file}: {e}")
            return []
    
    def _load_cross_cloud_rules(self) -> List[Dict]:
        """Load cross-cloud correlation rules"""
        return [
            {
                'id': 'CROSS-CLOUD-001',
                'title': 'Cross-cloud credential exposure',
                'description': 'Same credentials found across multiple cloud providers',
                'severity': 'CRITICAL',
                'condition': self._check_cross_cloud_credentials,
                'remediation': 'Rotate credentials and use provider-specific authentication'
            },
            {
                'id': 'CROSS-CLOUD-002',
                'title': 'Cross-cloud data replication',
                'description': 'Same data replicated across multiple cloud providers',
                'severity': 'HIGH',
                'condition': self._check_cross_cloud_data_replication,
                'remediation': 'Review data replication strategy and access controls'
            },
            {
                'id': 'CROSS-CLOUD-003',
                'title': 'Cross-cloud privilege escalation',
                'description': 'Privilege escalation patterns across multiple providers',
                'severity': 'CRITICAL',
                'condition': self._check_cross_cloud_privilege_escalation,
                'remediation': 'Review IAM policies and implement least privilege'
            },
            {
                'id': 'CROSS-CLOUD-004',
                'title': 'Cross-cloud anomaly correlation',
                'description': 'Anomalous activity patterns across multiple providers',
                'severity': 'HIGH',
                'condition': self._check_cross_cloud_anomalies,
                'remediation': 'Investigate coordinated attacks across cloud providers'
            }
        ]
    
    def evaluate_events(self, events: List[Dict]) -> List[Dict]:
        """Evaluate events against all rules"""
        logger.info(f"Evaluating {len(events)} events against multi-cloud rules")
        
        # Group events by provider
        provider_events = self._group_events_by_provider(events)
        
        # Evaluate provider-specific rules
        provider_alerts = []
        for provider, provider_events_list in provider_events.items():
            alerts = self._evaluate_provider_events(provider, provider_events_list)
            provider_alerts.extend(alerts)
        
        # Evaluate cross-cloud rules
        cross_cloud_alerts = self._evaluate_cross_cloud_rules(events)
        
        # Combine all alerts
        all_alerts = provider_alerts + cross_cloud_alerts
        self.alerts = all_alerts
        self.alert_count = len(all_alerts)
        
        logger.info(f"Multi-cloud rules evaluation complete: {len(all_alerts)} alerts generated")
        return all_alerts
    
    def _group_events_by_provider(self, events: List[Dict]) -> Dict[str, List[Dict]]:
        """Group events by cloud provider"""
        provider_events = defaultdict(list)
        
        for event in events:
            source = event.get('source', '')
            if source.startswith('AWS_'):
                provider_events['aws'].append(event)
            elif source.startswith('AZURE_'):
                provider_events['azure'].append(event)
            elif source.startswith('GCP_'):
                provider_events['gcp'].append(event)
            else:
                provider_events['unknown'].append(event)
        
        return dict(provider_events)
    
    def _evaluate_provider_events(self, provider: str, events: List[Dict]) -> List[Dict]:
        """Evaluate events for specific provider"""
        alerts = []
        
        # Filter rules for this provider
        provider_rules = [rule for rule in self.rules if self._is_rule_for_provider(rule, provider)]
        
        for rule in provider_rules:
            try:
                if self._evaluate_rule_condition(rule, events):
                    alert = self._create_alert(rule, events, provider)
                    alerts.append(alert)
            except Exception as e:
                logger.error(f"Error evaluating rule {rule.get('id', 'unknown')}: {e}")
        
        return alerts
    
    def _is_rule_for_provider(self, rule: Dict, provider: str) -> bool:
        """Check if rule applies to specific provider"""
        condition = rule.get('condition', '')
        
        if provider == 'aws':
            return 'AWS_' in condition or 'source == "AWS_' in condition
        elif provider == 'azure':
            return 'AZURE_' in condition or 'source == "AZURE_' in condition
        elif provider == 'gcp':
            return 'GCP_' in condition or 'source == "GCP_' in condition
        
        return False
    
    def _evaluate_rule_condition(self, rule: Dict, events: List[Dict]) -> bool:
        """Evaluate rule condition against events"""
        condition = rule.get('condition', '')
        if not condition:
            return False
        
        # Simple condition evaluation (in production, use a proper expression evaluator)
        for event in events:
            if self._check_condition(condition, event):
                return True
        
        return False
    
    def _check_condition(self, condition: str, event: Dict) -> bool:
        """Check if event matches condition"""
        try:
            # Replace condition variables with event values
            condition = condition.replace('source', f'"{event.get("source", "")}"')
            condition = condition.replace('event_type', f'"{event.get("event_type", "")}"')
            
            # Add event fields to evaluation context
            context = {
                'source': event.get('source', ''),
                'event_type': event.get('event_type', ''),
                'severity': event.get('severity', ''),
                'description': event.get('description', ''),
                'timestamp': event.get('timestamp', ''),
                **event.get('raw_event', {}),
                **event.get('additional_fields', {})
            }
            
            # Simple evaluation (in production, use ast.literal_eval or similar)
            if '==' in condition:
                parts = condition.split('==')
                if len(parts) == 2:
                    left = parts[0].strip().strip('"')
                    right = parts[1].strip().strip('"')
                    return context.get(left, '') == right
            
            return False
        except Exception as e:
            logger.error(f"Error evaluating condition '{condition}': {e}")
            return False
    
    def _evaluate_cross_cloud_rules(self, events: List[Dict]) -> List[Dict]:
        """Evaluate cross-cloud correlation rules"""
        alerts = []
        
        for rule in self.cross_cloud_rules:
            try:
                if rule['condition'](events):
                    alert = self._create_cross_cloud_alert(rule, events)
                    alerts.append(alert)
            except Exception as e:
                logger.error(f"Error evaluating cross-cloud rule {rule.get('id', 'unknown')}: {e}")
        
        return alerts
    
    def _check_cross_cloud_credentials(self, events: List[Dict]) -> bool:
        """Check for cross-cloud credential exposure"""
        # Look for same credentials across different providers
        credentials = defaultdict(list)
        
        for event in events:
            source = event.get('source', '')
            if 'credential' in event.get('description', '').lower():
                provider = 'aws' if source.startswith('AWS_') else 'azure' if source.startswith('AZURE_') else 'gcp' if source.startswith('GCP_') else 'unknown'
                credentials[event.get('resource_id', '')].append(provider)
        
        # Check if same credential appears in multiple providers
        for cred_id, providers in credentials.items():
            if len(set(providers)) > 1:
                return True
        
        return False
    
    def _check_cross_cloud_data_replication(self, events: List[Dict]) -> bool:
        """Check for cross-cloud data replication"""
        # Look for same data across different providers
        data_hashes = defaultdict(list)
        
        for event in events:
            if 'data_hash' in event.get('additional_fields', {}):
                data_hash = event['additional_fields']['data_hash']
                source = event.get('source', '')
                provider = 'aws' if source.startswith('AWS_') else 'azure' if source.startswith('AZURE_') else 'gcp' if source.startswith('GCP_') else 'unknown'
                data_hashes[data_hash].append(provider)
        
        # Check if same data appears in multiple providers
        for data_hash, providers in data_hashes.items():
            if len(set(providers)) > 1:
                return True
        
        return False
    
    def _check_cross_cloud_privilege_escalation(self, events: List[Dict]) -> bool:
        """Check for cross-cloud privilege escalation patterns"""
        # Look for privilege escalation patterns across providers
        escalation_events = []
        
        for event in events:
            if 'privilege' in event.get('description', '').lower() or 'escalation' in event.get('description', '').lower():
                escalation_events.append(event)
        
        # Check if escalation events occur across multiple providers
        providers = set()
        for event in escalation_events:
            source = event.get('source', '')
            if source.startswith('AWS_'):
                providers.add('aws')
            elif source.startswith('AZURE_'):
                providers.add('azure')
            elif source.startswith('GCP_'):
                providers.add('gcp')
        
        return len(providers) > 1
    
    def _check_cross_cloud_anomalies(self, events: List[Dict]) -> bool:
        """Check for cross-cloud anomaly correlation"""
        # Look for anomalous patterns across providers
        anomaly_events = []
        
        for event in events:
            if event.get('severity') in ['HIGH', 'CRITICAL'] and 'anomaly' in event.get('description', '').lower():
                anomaly_events.append(event)
        
        # Check if anomalies occur across multiple providers
        providers = set()
        for event in anomaly_events:
            source = event.get('source', '')
            if source.startswith('AWS_'):
                providers.add('aws')
            elif source.startswith('AZURE_'):
                providers.add('azure')
            elif source.startswith('GCP_'):
                providers.add('gcp')
        
        return len(providers) > 1
    
    def _create_alert(self, rule: Dict, events: List[Dict], provider: str) -> Dict:
        """Create alert from rule and events"""
        return {
            'id': f"{rule.get('id', 'unknown')}-{self.alert_count + 1}",
            'title': rule.get('title', 'Unknown Rule'),
            'description': rule.get('description', ''),
            'severity': rule.get('severity', 'MEDIUM'),
            'service': rule.get('service', 'UNKNOWN'),
            'provider': provider.upper(),
            'remediation': rule.get('remediation', ''),
            'timestamp': datetime.utcnow().isoformat(),
            'affected_events': len(events),
            'rule_id': rule.get('id', 'unknown')
        }
    
    def _create_cross_cloud_alert(self, rule: Dict, events: List[Dict]) -> Dict:
        """Create cross-cloud alert"""
        return {
            'id': f"{rule.get('id', 'unknown')}-{self.alert_count + 1}",
            'title': rule.get('title', 'Unknown Cross-Cloud Rule'),
            'description': rule.get('description', ''),
            'severity': rule.get('severity', 'MEDIUM'),
            'service': 'CROSS_CLOUD',
            'provider': 'MULTI_CLOUD',
            'remediation': rule.get('remediation', ''),
            'timestamp': datetime.utcnow().isoformat(),
            'affected_events': len(events),
            'rule_id': rule.get('id', 'unknown'),
            'cross_cloud': True
        }
    
    def get_alert_summary(self) -> Dict:
        """Get summary of generated alerts"""
        if not self.alerts:
            return {
                'total_alerts': 0,
                'by_severity': {},
                'by_provider': {},
                'by_service': {},
                'cross_cloud_alerts': 0
            }
        
        summary = {
            'total_alerts': len(self.alerts),
            'by_severity': defaultdict(int),
            'by_provider': defaultdict(int),
            'by_service': defaultdict(int),
            'cross_cloud_alerts': 0
        }
        
        for alert in self.alerts:
            summary['by_severity'][alert.get('severity', 'UNKNOWN')] += 1
            summary['by_provider'][alert.get('provider', 'UNKNOWN')] += 1
            summary['by_service'][alert.get('service', 'UNKNOWN')] += 1
            
            if alert.get('cross_cloud', False):
                summary['cross_cloud_alerts'] += 1
        
        return dict(summary)
    
    def save_alerts(self, output_file: str = None) -> str:
        """Save alerts to JSON file"""
        if not output_file:
            timestamp = datetime.utcnow().strftime('%Y%m%d_%H%M%S')
            output_file = f"alerts/multi_cloud_alerts_{timestamp}.json"
        
        os.makedirs(os.path.dirname(output_file), exist_ok=True)
        
        alert_data = {
            'timestamp': datetime.utcnow().isoformat(),
            'total_alerts': len(self.alerts),
            'summary': self.get_alert_summary(),
            'alerts': self.alerts
        }
        
        with open(output_file, 'w') as f:
            json.dump(alert_data, f, indent=2)
        
        logger.info(f"Saved {len(self.alerts)} alerts to {output_file}")
        return output_file

if __name__ == "__main__":
    # Test the multi-cloud rules engine
    engine = MultiCloudRulesEngine()
    
    # Sample events for testing
    test_events = [
        {
            'source': 'AWS_S3',
            'event_type': 'PUBLIC_ACCESS',
            'severity': 'CRITICAL',
            'description': 'S3 bucket has public access',
            'timestamp': datetime.utcnow().isoformat()
        },
        {
            'source': 'AZURE_STORAGE',
            'event_type': 'PUBLIC_ACCESS',
            'severity': 'CRITICAL',
            'description': 'Azure Storage has public access',
            'timestamp': datetime.utcnow().isoformat()
        },
        {
            'source': 'GCP_STORAGE_BUCKET',
            'event_type': 'PUBLIC_ACCESS',
            'severity': 'CRITICAL',
            'description': 'GCP bucket has public access',
            'timestamp': datetime.utcnow().isoformat()
        }
    ]
    
    # Evaluate events
    alerts = engine.evaluate_events(test_events)
    
    # Print results
    print(f"Generated {len(alerts)} alerts")
    for alert in alerts:
        print(f"- {alert['title']} ({alert['severity']}) - {alert['provider']}")
    
    # Save alerts
    output_file = engine.save_alerts()
    print(f"Alerts saved to {output_file}")
