#!/usr/bin/env python3
"""
CloudHawk Health Scoring Module

This module calculates security health scores for AWS resources and services
based on security events, configurations, and best practices.
"""

import os
import json
import logging
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional, Tuple
from collections import defaultdict
import statistics

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class HealthScorer:
    """Security health scoring engine"""
    
    def __init__(self, config: Dict = None):
        """Initialize the health scorer"""
        self.config = config or {}
        self.weights = self.config.get('weights', {
            'critical_issues': 0.4,
            'high_issues': 0.3,
            'medium_issues': 0.2,
            'low_issues': 0.1
        })
        self.time_decay_days = self.config.get('time_decay_days', 30)
        
        # Health score categories
        self.categories = {
            'iam_security': self._score_iam_security,
            'network_security': self._score_network_security,
            'data_security': self._score_data_security,
            'monitoring_security': self._score_monitoring_security,
            'compliance_security': self._score_compliance_security,
            'access_security': self._score_access_security
        }
    
    def calculate_health_score(self, events: List[Dict], alerts: List[Dict] = None) -> Dict:
        """Calculate overall security health score"""
        logger.info(f"Calculating health score for {len(events)} events")
        
        if alerts is None:
            alerts = []
        
        # Group events by category
        categorized_events = self._categorize_events(events)
        
        # Calculate scores for each category
        category_scores = {}
        for category, events_list in categorized_events.items():
            if category in self.categories:
                try:
                    score = self.categories[category](events_list, alerts)
                    category_scores[category] = score
                    logger.info(f"{category} score: {score['score']}/100")
                except Exception as e:
                    logger.error(f"Error calculating {category} score: {e}")
                    category_scores[category] = {
                        'score': 0,
                        'max_score': 100,
                        'issues': [],
                        'recommendations': []
                    }
        
        # Calculate overall score
        overall_score = self._calculate_overall_score(category_scores)
        
        # Generate health report
        health_report = {
            'overall_score': overall_score,
            'category_scores': category_scores,
            'timestamp': datetime.utcnow().isoformat(),
            'summary': self._generate_summary(overall_score, category_scores),
            'trends': self._calculate_trends(category_scores),
            'recommendations': self._generate_recommendations(category_scores)
        }
        
        logger.info(f"Overall health score: {overall_score['score']}/100")
        return health_report
    
    def _categorize_events(self, events: List[Dict]) -> Dict:
        """Categorize events by security domain"""
        categorized = defaultdict(list)
        
        for event in events:
            source = event.get('source', '')
            event_type = event.get('event_type', '')
            
            # IAM Security
            if source in ['AWS_IAM', 'AWS_IAM_USER', 'AWS_IAM_ROLE']:
                categorized['iam_security'].append(event)
            
            # Network Security
            elif source in ['AWS_EC2_SG', 'AWS_EC2_INSTANCE', 'AWS_VPC']:
                categorized['network_security'].append(event)
            
            # Data Security
            elif source in ['AWS_S3', 'AWS_S3_ACL', 'AWS_RDS']:
                categorized['data_security'].append(event)
            
            # Monitoring Security
            elif source in ['AWS_CLOUDTRAIL', 'AWS_GUARDDUTY', 'AWS_CLOUDWATCH']:
                categorized['monitoring_security'].append(event)
            
            # Access Security
            elif 'ACCESS' in event_type or 'LOGIN' in event_type:
                categorized['access_security'].append(event)
            
            # Default to compliance
            else:
                categorized['compliance_security'].append(event)
        
        return categorized
    
    def _score_iam_security(self, events: List[Dict], alerts: List[Dict]) -> Dict:
        """Calculate IAM security score"""
        score = 100
        max_score = 100
        issues = []
        recommendations = []
        
        # Check for critical IAM issues
        critical_issues = [alert for alert in alerts if alert.get('service') == 'IAM' and alert.get('severity') == 'CRITICAL']
        high_issues = [alert for alert in alerts if alert.get('service') == 'IAM' and alert.get('severity') == 'HIGH']
        medium_issues = [alert for alert in alerts if alert.get('service') == 'IAM' and alert.get('severity') == 'MEDIUM']
        
        # Deduct points for issues
        score -= len(critical_issues) * 20
        score -= len(high_issues) * 10
        score -= len(medium_issues) * 5
        
        # Check for root account usage
        root_usage = [event for event in events if 'root' in event.get('description', '').lower()]
        if root_usage:
            score -= 15
            issues.append("Root account usage detected")
            recommendations.append("Disable root account access keys and use IAM users/roles")
        
        # Check for unused access keys
        users_with_keys = set()
        for event in events:
            if event.get('event_type') == 'MULTIPLE_ACCESS_KEYS':
                users_with_keys.add(event.get('resource_id', ''))
        
        if users_with_keys:
            score -= len(users_with_keys) * 5
            issues.append(f"{len(users_with_keys)} users with multiple access keys")
            recommendations.append("Remove unused access keys, keep only one active key per user")
        
        # Check for overly permissive policies
        permissive_policies = [event for event in events if 'admin' in event.get('description', '').lower()]
        if permissive_policies:
            score -= 10
            issues.append("Overly permissive IAM policies detected")
            recommendations.append("Review and restrict IAM policies to follow least privilege principle")
        
        # Ensure score doesn't go below 0
        score = max(0, score)
        
        return {
            'score': score,
            'max_score': max_score,
            'issues': issues,
            'recommendations': recommendations,
            'details': {
                'critical_issues': len(critical_issues),
                'high_issues': len(high_issues),
                'medium_issues': len(medium_issues),
                'root_usage': len(root_usage),
                'users_with_multiple_keys': len(users_with_keys),
                'permissive_policies': len(permissive_policies)
            }
        }
    
    def _score_network_security(self, events: List[Dict], alerts: List[Dict]) -> Dict:
        """Calculate network security score"""
        score = 100
        max_score = 100
        issues = []
        recommendations = []
        
        # Check for critical network issues
        critical_issues = [alert for alert in alerts if alert.get('service') == 'EC2' and alert.get('severity') == 'CRITICAL']
        high_issues = [alert for alert in alerts if alert.get('service') == 'EC2' and alert.get('severity') == 'HIGH']
        
        # Deduct points for issues
        score -= len(critical_issues) * 15
        score -= len(high_issues) * 8
        
        # Check for open security groups
        open_sg_events = [event for event in events if '0.0.0.0/0' in event.get('description', '')]
        if open_sg_events:
            score -= len(open_sg_events) * 10
            issues.append(f"{len(open_sg_events)} security groups open to the world")
            recommendations.append("Restrict security group rules to specific IP ranges")
        
        # Check for public instances
        public_instances = [event for event in events if event.get('event_type') == 'PUBLIC_IP']
        if public_instances:
            score -= len(public_instances) * 8
            issues.append(f"{len(public_instances)} instances with public IPs")
            recommendations.append("Use private subnets and load balancers instead of direct public IPs")
        
        # Check for SSH open to world
        ssh_open = [event for event in events if 'ssh' in event.get('description', '').lower() and '0.0.0.0/0' in event.get('description', '')]
        if ssh_open:
            score -= 20
            issues.append("SSH access open to the world")
            recommendations.append("Restrict SSH access to specific IP ranges or use VPN/bastion host")
        
        # Check for RDP open to world
        rdp_open = [event for event in events if 'rdp' in event.get('description', '').lower() and '0.0.0.0/0' in event.get('description', '')]
        if rdp_open:
            score -= 20
            issues.append("RDP access open to the world")
            recommendations.append("Restrict RDP access to specific IP ranges")
        
        # Ensure score doesn't go below 0
        score = max(0, score)
        
        return {
            'score': score,
            'max_score': max_score,
            'issues': issues,
            'recommendations': recommendations,
            'details': {
                'critical_issues': len(critical_issues),
                'high_issues': len(high_issues),
                'open_security_groups': len(open_sg_events),
                'public_instances': len(public_instances),
                'ssh_open_to_world': len(ssh_open),
                'rdp_open_to_world': len(rdp_open)
            }
        }
    
    def _score_data_security(self, events: List[Dict], alerts: List[Dict]) -> Dict:
        """Calculate data security score"""
        score = 100
        max_score = 100
        issues = []
        recommendations = []
        
        # Check for critical data issues
        critical_issues = [alert for alert in alerts if alert.get('service') == 'S3' and alert.get('severity') == 'CRITICAL']
        high_issues = [alert for alert in alerts if alert.get('service') == 'S3' and alert.get('severity') == 'HIGH']
        
        # Deduct points for issues
        score -= len(critical_issues) * 20
        score -= len(high_issues) * 10
        
        # Check for public S3 buckets
        public_buckets = [event for event in events if event.get('event_type') == 'PUBLIC_ACCESS']
        if public_buckets:
            score -= len(public_buckets) * 15
            issues.append(f"{len(public_buckets)} S3 buckets with public access")
            recommendations.append("Remove public ACL and enable public access block")
        
        # Check for unencrypted data
        unencrypted_events = [event for event in events if 'unencrypted' in event.get('description', '').lower()]
        if unencrypted_events:
            score -= len(unencrypted_events) * 10
            issues.append(f"{len(unencrypted_events)} unencrypted resources detected")
            recommendations.append("Enable encryption for all data at rest and in transit")
        
        # Check for missing backup
        backup_issues = [event for event in events if 'backup' in event.get('description', '').lower()]
        if backup_issues:
            score -= 5
            issues.append("Backup configuration issues detected")
            recommendations.append("Implement regular automated backups")
        
        # Ensure score doesn't go below 0
        score = max(0, score)
        
        return {
            'score': score,
            'max_score': max_score,
            'issues': issues,
            'recommendations': recommendations,
            'details': {
                'critical_issues': len(critical_issues),
                'high_issues': len(high_issues),
                'public_buckets': len(public_buckets),
                'unencrypted_resources': len(unencrypted_events),
                'backup_issues': len(backup_issues)
            }
        }
    
    def _score_monitoring_security(self, events: List[Dict], alerts: List[Dict]) -> Dict:
        """Calculate monitoring security score"""
        score = 100
        max_score = 100
        issues = []
        recommendations = []
        
        # Check for monitoring issues
        monitoring_issues = [alert for alert in alerts if alert.get('service') in ['CloudTrail', 'GuardDuty', 'CloudWatch']]
        
        # Deduct points for issues
        score -= len(monitoring_issues) * 5
        
        # Check for CloudTrail issues
        cloudtrail_issues = [event for event in events if event.get('source') == 'AWS_CLOUDTRAIL' and 'error' in event.get('description', '').lower()]
        if cloudtrail_issues:
            score -= 15
            issues.append("CloudTrail logging issues detected")
            recommendations.append("Ensure CloudTrail is properly configured and logging")
        
        # Check for GuardDuty issues
        guardduty_issues = [event for event in events if event.get('source') == 'AWS_GUARDDUTY' and 'error' in event.get('description', '').lower()]
        if guardduty_issues:
            score -= 10
            issues.append("GuardDuty configuration issues detected")
            recommendations.append("Enable and properly configure GuardDuty")
        
        # Check for missing monitoring
        if not any(event.get('source') == 'AWS_CLOUDTRAIL' for event in events):
            score -= 20
            issues.append("No CloudTrail events detected")
            recommendations.append("Enable CloudTrail for comprehensive logging")
        
        # Ensure score doesn't go below 0
        score = max(0, score)
        
        return {
            'score': score,
            'max_score': max_score,
            'issues': issues,
            'recommendations': recommendations,
            'details': {
                'monitoring_issues': len(monitoring_issues),
                'cloudtrail_issues': len(cloudtrail_issues),
                'guardduty_issues': len(guardduty_issues),
                'has_cloudtrail': any(event.get('source') == 'AWS_CLOUDTRAIL' for event in events)
            }
        }
    
    def _score_compliance_security(self, events: List[Dict], alerts: List[Dict]) -> Dict:
        """Calculate compliance security score"""
        score = 100
        max_score = 100
        issues = []
        recommendations = []
        
        # Check for compliance issues
        compliance_issues = [alert for alert in alerts if alert.get('severity') in ['CRITICAL', 'HIGH']]
        
        # Deduct points for issues
        score -= len(compliance_issues) * 3
        
        # Check for collection errors
        collection_errors = [event for event in events if event.get('event_type') == 'COLLECTION_ERROR']
        if collection_errors:
            score -= len(collection_errors) * 5
            issues.append(f"{len(collection_errors)} data collection errors")
            recommendations.append("Fix AWS credentials and permissions for data collection")
        
        # Check for missing security controls
        security_controls = ['MFA', 'encryption', 'backup', 'monitoring']
        missing_controls = []
        
        for control in security_controls:
            if not any(control in event.get('description', '').lower() for event in events):
                missing_controls.append(control)
        
        if missing_controls:
            score -= len(missing_controls) * 5
            issues.append(f"Missing security controls: {', '.join(missing_controls)}")
            recommendations.append("Implement missing security controls")
        
        # Ensure score doesn't go below 0
        score = max(0, score)
        
        return {
            'score': score,
            'max_score': max_score,
            'issues': issues,
            'recommendations': recommendations,
            'details': {
                'compliance_issues': len(compliance_issues),
                'collection_errors': len(collection_errors),
                'missing_controls': missing_controls
            }
        }
    
    def _score_access_security(self, events: List[Dict], alerts: List[Dict]) -> Dict:
        """Calculate access security score"""
        score = 100
        max_score = 100
        issues = []
        recommendations = []
        
        # Check for access issues
        access_issues = [alert for alert in alerts if 'access' in alert.get('title', '').lower()]
        
        # Deduct points for issues
        score -= len(access_issues) * 8
        
        # Check for failed login attempts
        failed_logins = [event for event in events if 'failed' in event.get('description', '').lower() and 'login' in event.get('description', '').lower()]
        if failed_logins:
            score -= min(len(failed_logins) * 2, 20)
            issues.append(f"{len(failed_logins)} failed login attempts")
            recommendations.append("Investigate failed login attempts and implement account lockout policies")
        
        # Check for unusual access patterns
        unusual_access = [event for event in events if 'unusual' in event.get('description', '').lower()]
        if unusual_access:
            score -= len(unusual_access) * 5
            issues.append(f"{len(unusual_access)} unusual access patterns detected")
            recommendations.append("Review and investigate unusual access patterns")
        
        # Check for privilege escalation
        privilege_escalation = [event for event in events if 'privilege' in event.get('description', '').lower() or 'escalation' in event.get('description', '').lower()]
        if privilege_escalation:
            score -= len(privilege_escalation) * 15
            issues.append(f"{len(privilege_escalation)} privilege escalation attempts")
            recommendations.append("Review privilege escalation attempts and implement proper access controls")
        
        # Ensure score doesn't go below 0
        score = max(0, score)
        
        return {
            'score': score,
            'max_score': max_score,
            'issues': issues,
            'recommendations': recommendations,
            'details': {
                'access_issues': len(access_issues),
                'failed_logins': len(failed_logins),
                'unusual_access': len(unusual_access),
                'privilege_escalation': len(privilege_escalation)
            }
        }
    
    def _calculate_overall_score(self, category_scores: Dict) -> Dict:
        """Calculate weighted overall score"""
        if not category_scores:
            return {'score': 0, 'max_score': 100, 'grade': 'F'}
        
        # Calculate weighted average
        total_weighted_score = 0
        total_weight = 0
        
        for category, score_data in category_scores.items():
            weight = self.weights.get(category, 1.0)
            total_weighted_score += score_data['score'] * weight
            total_weight += weight
        
        overall_score = total_weighted_score / total_weight if total_weight > 0 else 0
        
        # Determine grade
        if overall_score >= 90:
            grade = 'A'
        elif overall_score >= 80:
            grade = 'B'
        elif overall_score >= 70:
            grade = 'C'
        elif overall_score >= 60:
            grade = 'D'
        else:
            grade = 'F'
        
        return {
            'score': round(overall_score, 1),
            'max_score': 100,
            'grade': grade
        }
    
    def _generate_summary(self, overall_score: Dict, category_scores: Dict) -> Dict:
        """Generate health summary"""
        total_issues = sum(len(score.get('issues', [])) for score in category_scores.values())
        total_recommendations = sum(len(score.get('recommendations', [])) for score in category_scores.values())
        
        # Find worst category
        worst_category = min(category_scores.items(), key=lambda x: x[1]['score']) if category_scores else None
        
        return {
            'total_issues': total_issues,
            'total_recommendations': total_recommendations,
            'worst_category': worst_category[0] if worst_category else None,
            'worst_category_score': worst_category[1]['score'] if worst_category else 0,
            'status': 'HEALTHY' if overall_score['score'] >= 80 else 'NEEDS_ATTENTION' if overall_score['score'] >= 60 else 'CRITICAL'
        }
    
    def _calculate_trends(self, category_scores: Dict) -> Dict:
        """Calculate trends (placeholder for future implementation)"""
        return {
            'trend': 'STABLE',  # Would need historical data to calculate actual trends
            'change_period': '7_days',
            'change_percentage': 0
        }
    
    def _generate_recommendations(self, category_scores: Dict) -> List[str]:
        """Generate prioritized recommendations"""
        all_recommendations = []
        
        # Collect all recommendations
        for category, score_data in category_scores.items():
            for recommendation in score_data.get('recommendations', []):
                all_recommendations.append({
                    'recommendation': recommendation,
                    'category': category,
                    'priority': 'HIGH' if score_data['score'] < 50 else 'MEDIUM' if score_data['score'] < 80 else 'LOW'
                })
        
        # Sort by priority and category score
        all_recommendations.sort(key=lambda x: (
            x['priority'] == 'HIGH',
            x['priority'] == 'MEDIUM',
            category_scores.get(x['category'], {}).get('score', 100)
        ))
        
        return [rec['recommendation'] for rec in all_recommendations[:10]]  # Top 10 recommendations


def main():
    """Test the health scorer"""
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
            'description': 'Security group allows SSH (port 22) from anywhere'
        }
    ]
    
    sample_alerts = [
        {
            'severity': 'CRITICAL',
            'service': 'IAM',
            'title': 'Root account usage detected'
        },
        {
            'severity': 'CRITICAL',
            'service': 'EC2',
            'title': 'SSH open to world'
        }
    ]
    
    scorer = HealthScorer()
    health_report = scorer.calculate_health_score(sample_events, sample_alerts)
    
    print(f"Overall Health Score: {health_report['overall_score']['score']}/100 ({health_report['overall_score']['grade']})")
    print(f"Status: {health_report['summary']['status']}")
    print(f"Total Issues: {health_report['summary']['total_issues']}")
    print(f"Total Recommendations: {health_report['summary']['total_recommendations']}")


if __name__ == "__main__":
    main()
