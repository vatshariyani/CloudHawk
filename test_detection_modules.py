#!/usr/bin/env python3
"""
Test script for CloudHawk Detection Modules

This script demonstrates the functionality of all detection modules:
- Anomaly Detection
- Health Scoring
- Misconfiguration Scanning
- Vulnerability Scanning
- Detection Engine Integration
"""

import os
import sys
import json
import logging
from datetime import datetime, timedelta

# Add src to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'src'))

from detection.anomaly_detector import AnomalyDetector
from detection.health_scorer import HealthScorer
from detection.misconfig_scanner import MisconfigScanner
from detection.vulnerability_scanner import VulnerabilityScanner
from detection.detection_engine import DetectionEngine

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

def create_sample_events():
    """Create sample security events for testing"""
    base_time = datetime.utcnow()
    
    events = [
        # IAM Events
        {
            'timestamp': (base_time - timedelta(hours=1)).isoformat(),
            'source': 'AWS_IAM',
            'event_type': 'ROOT_ACCOUNT_USAGE',
            'resource_id': 'root',
            'description': 'Root account was used for API calls',
            'severity': 'CRITICAL',
            'region': 'us-east-1',
            'raw_event': {
                'eventName': 'CreateUser',
                'userIdentity': {'userName': 'root'},
                'sourceIPAddress': '192.168.1.1'
            }
        },
        {
            'timestamp': (base_time - timedelta(minutes=30)).isoformat(),
            'source': 'AWS_IAM_USER',
            'event_type': 'MULTIPLE_ACCESS_KEYS',
            'resource_id': 'user123',
            'description': 'IAM user has more than one active access key',
            'severity': 'MEDIUM',
            'region': 'us-east-1',
            'raw_event': {
                'eventName': 'ListAccessKeys',
                'userIdentity': {'userName': 'user123'},
                'sourceIPAddress': '192.168.1.2'
            }
        },
        
        # EC2 Events
        {
            'timestamp': (base_time - timedelta(hours=2)).isoformat(),
            'source': 'AWS_EC2_SG',
            'event_type': 'SECURITY_GROUP_RULE',
            'resource_id': 'sg-123456',
            'description': 'Security group allows SSH (port 22) from anywhere (0.0.0.0/0)',
            'severity': 'CRITICAL',
            'region': 'us-east-1',
            'raw_event': {
                'eventName': 'AuthorizeSecurityGroupIngress',
                'userIdentity': {'userName': 'admin'},
                'sourceIPAddress': '192.168.1.3'
            }
        },
        {
            'timestamp': (base_time - timedelta(minutes=45)).isoformat(),
            'source': 'AWS_EC2_INSTANCE',
            'event_type': 'PUBLIC_IP',
            'resource_id': 'i-1234567890abcdef0',
            'description': 'EC2 instance has a public IP address',
            'severity': 'MEDIUM',
            'region': 'us-east-1',
            'raw_event': {
                'eventName': 'RunInstances',
                'userIdentity': {'userName': 'admin'},
                'sourceIPAddress': '192.168.1.4'
            }
        },
        
        # S3 Events
        {
            'timestamp': (base_time - timedelta(hours=3)).isoformat(),
            'source': 'AWS_S3_ACL',
            'event_type': 'PUBLIC_ACCESS',
            'resource_id': 'my-bucket',
            'description': 'S3 bucket has public ACL allowing global access',
            'severity': 'CRITICAL',
            'region': 'us-east-1',
            'raw_event': {
                'eventName': 'PutBucketAcl',
                'userIdentity': {'userName': 'admin'},
                'sourceIPAddress': '192.168.1.5'
            }
        },
        
        # CloudTrail Events
        {
            'timestamp': (base_time - timedelta(minutes=15)).isoformat(),
            'source': 'AWS_CLOUDTRAIL',
            'event_type': 'TRAIL_CONFIGURATION',
            'resource_id': 'cloudtrail-123',
            'description': 'CloudTrail logging configuration',
            'severity': 'INFO',
            'region': 'us-east-1',
            'raw_event': {
                'eventName': 'CreateTrail',
                'userIdentity': {'userName': 'admin'},
                'sourceIPAddress': '192.168.1.6'
            }
        },
        
        # GuardDuty Events
        {
            'timestamp': (base_time - timedelta(minutes=5)).isoformat(),
            'source': 'AWS_GUARDDUTY',
            'event_type': 'THREAT_DETECTION',
            'resource_id': 'finding-123',
            'description': 'GuardDuty detected suspicious activity',
            'severity': 'HIGH',
            'region': 'us-east-1',
            'raw_event': {
                'eventName': 'CreateDetector',
                'userIdentity': {'userName': 'admin'},
                'sourceIPAddress': '192.168.1.7'
            }
        },
        
        # Collection Error
        {
            'timestamp': (base_time - timedelta(minutes=10)).isoformat(),
            'source': 'COLLECTION',
            'event_type': 'COLLECTION_ERROR',
            'resource_id': 'collection-error-1',
            'description': 'Error occurred during AWS data collection',
            'severity': 'CRITICAL',
            'region': 'us-east-1',
            'raw_event': {
                'error': 'SubscriptionRequiredException',
                'service': 'GuardDuty'
            }
        }
    ]
    
    return events

def create_sample_alerts():
    """Create sample alerts for testing"""
    return [
        {
            'timestamp': datetime.utcnow().isoformat(),
            'rule_id': 'EC2-SG-001',
            'title': 'SSH open to world',
            'description': 'Security group allows SSH (port 22) from anywhere',
            'severity': 'CRITICAL',
            'remediation': 'Restrict SSH access to specific IP ranges or use VPN/bastion host',
            'service': 'EC2',
            'log_excerpt': {}
        },
        {
            'timestamp': datetime.utcnow().isoformat(),
            'rule_id': 'S3-ACL-001',
            'title': 'S3 bucket with public ACL',
            'description': 'S3 bucket has public ACL allowing global access',
            'severity': 'CRITICAL',
            'remediation': 'Remove public ACL and enable public access block',
            'service': 'S3',
            'log_excerpt': {}
        },
        {
            'timestamp': datetime.utcnow().isoformat(),
            'rule_id': 'IAM-USER-001',
            'title': 'IAM user with multiple access keys',
            'description': 'IAM user has more than one active access key',
            'severity': 'MEDIUM',
            'remediation': 'Remove unused access keys, keep only one active key per user',
            'service': 'IAM',
            'log_excerpt': {}
        }
    ]

def create_sample_resource_configs():
    """Create sample resource configurations for testing"""
    return {
        's3_buckets': {
            'my-bucket': {
                'public_read': True,
                'encryption_enabled': False,
                'versioning_enabled': False,
                'logging_enabled': False
            },
            'secure-bucket': {
                'public_read': False,
                'encryption_enabled': True,
                'versioning_enabled': True,
                'logging_enabled': True
            }
        },
        'ec2_instances': {
            'i-1234567890abcdef0': {
                'public_ip': True,
                'instance_type': 't2.micro',
                'volumes': [
                    {'id': 'vol-1234567890abcdef0', 'encrypted': False, 'size': 8},
                    {'id': 'vol-0987654321fedcba0', 'encrypted': True, 'size': 20}
                ]
            },
            'i-0987654321fedcba0': {
                'public_ip': False,
                'instance_type': 't3.small',
                'volumes': [
                    {'id': 'vol-abcdef1234567890', 'encrypted': True, 'size': 30}
                ]
            }
        },
        'rds_instances': {
            'db-instance-1': {
                'public_access': True,
                'encryption_enabled': False,
                'engine': 'mysql',
                'port': 3306
            },
            'db-instance-2': {
                'public_access': False,
                'encryption_enabled': True,
                'engine': 'postgres',
                'port': 5432
            }
        }
    }

def test_anomaly_detector():
    """Test the anomaly detector"""
    print("\n" + "="*60)
    print("TESTING ANOMALY DETECTOR")
    print("="*60)
    
    events = create_sample_events()
    detector = AnomalyDetector()
    
    # Run anomaly detection
    anomalies = detector.analyze_events(events)
    
    print(f"Detected {len(anomalies)} anomalies:")
    for i, anomaly in enumerate(anomalies, 1):
        print(f"{i}. {anomaly['title']}")
        print(f"   Type: {anomaly['type']}")
        print(f"   Severity: {anomaly['severity']}")
        print(f"   Score: {anomaly.get('severity_score', 'N/A')}")
        print(f"   Description: {anomaly['description']}")
        print()
    
    return anomalies

def test_health_scorer():
    """Test the health scorer"""
    print("\n" + "="*60)
    print("TESTING HEALTH SCORER")
    print("="*60)
    
    events = create_sample_events()
    alerts = create_sample_alerts()
    scorer = HealthScorer()
    
    # Run health scoring
    health_report = scorer.calculate_health_score(events, alerts)
    
    print(f"Overall Health Score: {health_report['overall_score']['score']}/100")
    print(f"Grade: {health_report['overall_score']['grade']}")
    print(f"Status: {health_report['summary']['status']}")
    print()
    
    print("Category Scores:")
    for category, score_data in health_report['category_scores'].items():
        print(f"  {category}: {score_data['score']}/100")
        if score_data['issues']:
            print(f"    Issues: {len(score_data['issues'])}")
        if score_data['recommendations']:
            print(f"    Recommendations: {len(score_data['recommendations'])}")
    print()
    
    print("Top Recommendations:")
    for i, rec in enumerate(health_report['recommendations'][:5], 1):
        print(f"  {i}. {rec}")
    
    return health_report

def test_misconfig_scanner():
    """Test the misconfiguration scanner"""
    print("\n" + "="*60)
    print("TESTING MISCONFIGURATION SCANNER")
    print("="*60)
    
    events = create_sample_events()
    scanner = MisconfigScanner()
    
    # Run misconfiguration scan
    scan_results = scanner.scan_misconfigurations(events)
    
    print(f"Scan Status: {scan_results['summary']['status']}")
    print(f"Grade: {scan_results['summary']['grade']}")
    print(f"Total Issues: {scan_results['total_issues']}")
    print(f"Critical: {scan_results['critical_issues']}, High: {scan_results['high_issues']}, Medium: {scan_results['medium_issues']}, Low: {scan_results['low_issues']}")
    print()
    
    print("Service Results:")
    for service, results in scan_results['services'].items():
        if results['total_issues'] > 0:
            print(f"  {service.upper()}: {results['total_issues']} issues")
            for misconfig in results['misconfigurations']:
                print(f"    - {misconfig['description']} ({misconfig['severity']})")
    print()
    
    print("Top Recommendations:")
    for i, rec in enumerate(scan_results['recommendations'][:5], 1):
        print(f"  {i}. {rec}")
    
    return scan_results

def test_vulnerability_scanner():
    """Test the vulnerability scanner"""
    print("\n" + "="*60)
    print("TESTING VULNERABILITY SCANNER")
    print("="*60)
    
    events = create_sample_events()
    resource_configs = create_sample_resource_configs()
    scanner = VulnerabilityScanner()
    
    # Run vulnerability scan
    vuln_results = scanner.scan_vulnerabilities(events, resource_configs)
    
    print(f"Scan Status: {vuln_results['summary']['status']}")
    print(f"Risk Level: {vuln_results['summary']['risk_level']}")
    print(f"Total Vulnerabilities: {vuln_results['total_vulnerabilities']}")
    print(f"Critical: {vuln_results['critical_vulnerabilities']}, High: {vuln_results['high_vulnerabilities']}, Medium: {vuln_results['medium_vulnerabilities']}, Low: {vuln_results['low_vulnerabilities']}")
    print(f"Average CVSS Score: {vuln_results['summary']['average_cvss_score']}")
    print()
    
    print("Vulnerabilities Found:")
    for i, vuln in enumerate(vuln_results['vulnerabilities'][:5], 1):
        print(f"  {i}. {vuln['title']}")
        print(f"     Type: {vuln['type']}")
        print(f"     Severity: {vuln['severity']}")
        print(f"     CVSS Score: {vuln.get('cvss_score', 'N/A')}")
        print(f"     Resource: {vuln['affected_resource']}")
        print()
    
    print("Top Recommendations:")
    for i, rec in enumerate(vuln_results['recommendations'][:5], 1):
        print(f"  {i}. {rec}")
    
    return vuln_results

def test_detection_engine():
    """Test the integrated detection engine"""
    print("\n" + "="*60)
    print("TESTING DETECTION ENGINE (INTEGRATED)")
    print("="*60)
    
    # Create sample events file
    events = create_sample_events()
    events_file = 'test_events.json'
    
    with open(events_file, 'w') as f:
        json.dump(events, f, indent=2, default=str)
    
    try:
        # Initialize detection engine
        config = {
            'rule_engine_threads': 2,
            'rule_engine_chunk_size': 50,
            'anomaly_detection': {
                'anomaly_threshold': 2.0,
                'min_samples': 5
            }
        }
        
        engine = DetectionEngine(config)
        
        # Print detection statistics
        stats = engine.get_detection_statistics()
        print("Detection Engine Statistics:")
        print(f"  Rule Engine: {stats['rule_engine']['rules_loaded']} rules loaded")
        print(f"  Anomaly Detector: {stats['anomaly_detector']['patterns']} patterns")
        print(f"  Health Scorer: {stats['health_scorer']['categories']} categories")
        print(f"  Misconfig Scanner: {stats['misconfig_scanner']['total_rules']} rules across {stats['misconfig_scanner']['services']} services")
        print(f"  Vulnerability Scanner: {stats['vulnerability_scanner']['cve_entries']} CVE entries, {stats['vulnerability_scanner']['patterns']} patterns")
        print()
        
        # Run comprehensive scan
        resource_configs = create_sample_resource_configs()
        results = engine.run_comprehensive_scan(events_file, resource_configs)
        
        # Print comprehensive results
        summary = results['summary']
        print("Comprehensive Scan Results:")
        print(f"  Total Issues: {summary['total_issues']}")
        print(f"  Critical: {summary['critical_issues']}, High: {summary['high_issues']}, Medium: {summary['medium_issues']}, Low: {summary['low_issues']}")
        print(f"  Overall Risk Score: {summary['overall_risk_score']}/100")
        print(f"  Overall Health Score: {summary['overall_health_score']}/100")
        print()
        
        print("Detection Summary:")
        detection_summary = summary['detection_summary']
        print(f"  Rule-based Alerts: {detection_summary['rule_based_alerts']}")
        print(f"  Anomalies Detected: {detection_summary['anomalies_detected']}")
        print(f"  Misconfigurations Found: {detection_summary['misconfigurations_found']}")
        print(f"  Vulnerabilities Found: {detection_summary['vulnerabilities_found']}")
        print(f"  Health Grade: {detection_summary['health_grade']}")
        print()
        
        print("Top Recommendations:")
        for i, rec in enumerate(summary['top_recommendations'][:5], 1):
            print(f"  {i}. {rec}")
        
        # Save results
        engine.save_results('test_detection_results.json')
        print(f"\nResults saved to test_detection_results.json")
        
        return results
    
    finally:
        # Clean up
        if os.path.exists(events_file):
            os.remove(events_file)

def main():
    """Run all detection module tests"""
    print("🦅 CloudHawk Detection Modules Test Suite")
    print("="*60)
    print("Testing all detection capabilities...")
    
    try:
        # Test individual modules
        anomalies = test_anomaly_detector()
        health_report = test_health_scorer()
        misconfig_results = test_misconfig_scanner()
        vuln_results = test_vulnerability_scanner()
        
        # Test integrated engine
        comprehensive_results = test_detection_engine()
        
        print("\n" + "="*60)
        print("TEST SUMMARY")
        print("="*60)
        print("✅ All detection modules tested successfully!")
        print(f"✅ Anomaly Detection: {len(anomalies)} anomalies found")
        print(f"✅ Health Scoring: {health_report['overall_score']['score']}/100 score")
        print(f"✅ Misconfiguration Scan: {misconfig_results['total_issues']} issues found")
        print(f"✅ Vulnerability Scan: {vuln_results['total_vulnerabilities']} vulnerabilities found")
        print(f"✅ Integrated Engine: {comprehensive_results['summary']['total_issues']} total issues")
        
        print("\n🎉 All tests completed successfully!")
        
    except Exception as e:
        logger.error(f"Test failed: {e}")
        print(f"\n❌ Test failed: {e}")
        return 1
    
    return 0

if __name__ == "__main__":
    exit(main())
