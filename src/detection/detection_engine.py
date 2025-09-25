#!/usr/bin/env python3
"""
CloudHawk Detection Engine

This module integrates all detection capabilities including:
- Rule-based detection
- Anomaly detection
- Health scoring
- Misconfiguration scanning
- Vulnerability scanning
"""

import os
import json
import logging
from datetime import datetime
from typing import Dict, List, Any, Optional
import yaml

# Import detection modules
from .rule_engine import RuleEngine
from .anomaly_detector import AnomalyDetector
from .health_scorer import HealthScorer
from .misconfig_scanner import MisconfigScanner
from .vulnerability_scanner import VulnerabilityScanner

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class DetectionEngine:
    """Main detection engine that orchestrates all detection capabilities"""
    
    def __init__(self, config: Dict = None):
        """Initialize the detection engine"""
        self.config = config or {}
        self.base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        
        # Initialize detection modules
        self.rule_engine = RuleEngine(
            rules_file=os.path.join(self.base_dir, 'detection', 'security_rules.yaml'),
            events_file='',  # Will be set when running
            threads=self.config.get('rule_engine_threads', 4),
            chunk_size=self.config.get('rule_engine_chunk_size', 100)
        )
        
        self.anomaly_detector = AnomalyDetector(
            config=self.config.get('anomaly_detection', {})
        )
        
        self.health_scorer = HealthScorer(
            config=self.config.get('health_scoring', {})
        )
        
        self.misconfig_scanner = MisconfigScanner(
            config=self.config.get('misconfig_scanning', {})
        )
        
        self.vulnerability_scanner = VulnerabilityScanner(
            config=self.config.get('vulnerability_scanning', {})
        )
        
        # Results storage
        self.results = {
            'rule_based_alerts': [],
            'anomaly_detection': [],
            'health_score': {},
            'misconfigurations': {},
            'vulnerabilities': {},
            'summary': {}
        }
    
    def run_comprehensive_scan(self, events_file: str, resource_configs: Dict = None) -> Dict:
        """Run comprehensive security scan using all detection methods"""
        logger.info("Starting comprehensive security scan")
        
        # Load events
        events = self._load_events(events_file)
        if not events:
            logger.error("No events loaded, cannot proceed with scan")
            return self.results
        
        logger.info(f"Loaded {len(events)} events for analysis")
        
        # 1. Rule-based detection
        logger.info("Running rule-based detection...")
        self.rule_engine.events_file = events_file
        self.rule_engine.run()
        self.results['rule_based_alerts'] = self.rule_engine.alerts
        
        # 2. Anomaly detection
        logger.info("Running anomaly detection...")
        try:
            anomalies = self.anomaly_detector.analyze_events(events)
            self.results['anomaly_detection'] = anomalies
        except Exception as e:
            logger.error(f"Anomaly detection failed: {e}")
            self.results['anomaly_detection'] = []
        
        # 3. Health scoring
        logger.info("Running health scoring...")
        try:
            health_score = self.health_scorer.calculate_health_score(
                events, 
                self.results['rule_based_alerts']
            )
            self.results['health_score'] = health_score
        except Exception as e:
            logger.error(f"Health scoring failed: {e}")
            self.results['health_score'] = {}
        
        # 4. Misconfiguration scanning
        logger.info("Running misconfiguration scan...")
        try:
            misconfigs = self.misconfig_scanner.scan_misconfigurations(events)
            self.results['misconfigurations'] = misconfigs
        except Exception as e:
            logger.error(f"Misconfiguration scanning failed: {e}")
            self.results['misconfigurations'] = {}
        
        # 5. Vulnerability scanning
        logger.info("Running vulnerability scan...")
        try:
            vulnerabilities = self.vulnerability_scanner.scan_vulnerabilities(
                events, 
                resource_configs
            )
            self.results['vulnerabilities'] = vulnerabilities
        except Exception as e:
            logger.error(f"Vulnerability scanning failed: {e}")
            self.results['vulnerabilities'] = {}
        
        # Generate comprehensive summary
        self.results['summary'] = self._generate_comprehensive_summary()
        
        logger.info("Comprehensive security scan completed")
        return self.results
    
    def run_rule_based_detection(self, events_file: str) -> List[Dict]:
        """Run only rule-based detection"""
        logger.info("Running rule-based detection only")
        
        self.rule_engine.events_file = events_file
        self.rule_engine.run()
        
        return self.rule_engine.alerts
    
    def run_anomaly_detection(self, events_file: str) -> List[Dict]:
        """Run only anomaly detection"""
        logger.info("Running anomaly detection only")
        
        events = self._load_events(events_file)
        if not events:
            return []
        
        return self.anomaly_detector.analyze_events(events)
    
    def run_health_scoring(self, events_file: str, alerts: List[Dict] = None) -> Dict:
        """Run only health scoring"""
        logger.info("Running health scoring only")
        
        events = self._load_events(events_file)
        if not events:
            return {}
        
        return self.health_scorer.calculate_health_score(events, alerts)
    
    def run_misconfig_scanning(self, events_file: str) -> Dict:
        """Run only misconfiguration scanning"""
        logger.info("Running misconfiguration scanning only")
        
        events = self._load_events(events_file)
        if not events:
            return {}
        
        return self.misconfig_scanner.scan_misconfigurations(events)
    
    def run_vulnerability_scanning(self, events_file: str, resource_configs: Dict = None) -> Dict:
        """Run only vulnerability scanning"""
        logger.info("Running vulnerability scanning only")
        
        events = self._load_events(events_file)
        if not events:
            return {}
        
        return self.vulnerability_scanner.scan_vulnerabilities(events, resource_configs)
    
    def _load_events(self, events_file: str) -> List[Dict]:
        """Load events from file"""
        try:
            if not os.path.exists(events_file):
                logger.error(f"Events file not found: {events_file}")
                return []
            
            with open(events_file, 'r') as f:
                data = json.load(f)
            
            # Handle different event file formats
            if isinstance(data, list):
                return data
            elif isinstance(data, dict) and 'events' in data:
                return data['events']
            else:
                logger.error(f"Unexpected events file format: {events_file}")
                return []
        
        except Exception as e:
            logger.error(f"Failed to load events from {events_file}: {e}")
            return []
    
    def _generate_comprehensive_summary(self) -> Dict:
        """Generate comprehensive summary of all detection results"""
        summary = {
            'timestamp': datetime.utcnow().isoformat(),
            'total_issues': 0,
            'critical_issues': 0,
            'high_issues': 0,
            'medium_issues': 0,
            'low_issues': 0,
            'overall_risk_score': 0,
            'overall_health_score': 0,
            'detection_summary': {},
            'top_recommendations': []
        }
        
        # Count rule-based alerts
        rule_alerts = self.results.get('rule_based_alerts', [])
        for alert in rule_alerts:
            severity = alert.get('severity', 'LOW')
            summary['total_issues'] += 1
            summary[f'{severity.lower()}_issues'] += 1
        
        # Count anomalies
        anomalies = self.results.get('anomaly_detection', [])
        for anomaly in anomalies:
            severity = anomaly.get('severity', 'LOW')
            summary['total_issues'] += 1
            summary[f'{severity.lower()}_issues'] += 1
        
        # Count misconfigurations
        misconfigs = self.results.get('misconfigurations', {})
        if misconfigs:
            summary['total_issues'] += misconfigs.get('total_issues', 0)
            summary['critical_issues'] += misconfigs.get('critical_issues', 0)
            summary['high_issues'] += misconfigs.get('high_issues', 0)
            summary['medium_issues'] += misconfigs.get('medium_issues', 0)
            summary['low_issues'] += misconfigs.get('low_issues', 0)
        
        # Count vulnerabilities
        vulnerabilities = self.results.get('vulnerabilities', {})
        if vulnerabilities:
            summary['total_issues'] += vulnerabilities.get('total_vulnerabilities', 0)
            summary['critical_issues'] += vulnerabilities.get('critical_vulnerabilities', 0)
            summary['high_issues'] += vulnerabilities.get('high_vulnerabilities', 0)
            summary['medium_issues'] += vulnerabilities.get('medium_vulnerabilities', 0)
            summary['low_issues'] += vulnerabilities.get('low_vulnerabilities', 0)
        
        # Calculate overall risk score (0-100, higher is worse)
        risk_score = (
            summary['critical_issues'] * 25 +
            summary['high_issues'] * 15 +
            summary['medium_issues'] * 8 +
            summary['low_issues'] * 3
        )
        summary['overall_risk_score'] = min(risk_score, 100)
        
        # Get health score
        health_score = self.results.get('health_score', {})
        if health_score:
            overall_health = health_score.get('overall_score', {})
            summary['overall_health_score'] = overall_health.get('score', 0)
        
        # Generate detection summary
        summary['detection_summary'] = {
            'rule_based_alerts': len(rule_alerts),
            'anomalies_detected': len(anomalies),
            'misconfigurations_found': misconfigs.get('total_issues', 0),
            'vulnerabilities_found': vulnerabilities.get('total_vulnerabilities', 0),
            'health_grade': health_score.get('overall_score', {}).get('grade', 'F')
        }
        
        # Collect top recommendations
        recommendations = []
        
        # From health scorer
        if health_score:
            recommendations.extend(health_score.get('recommendations', []))
        
        # From misconfig scanner
        if misconfigs:
            recommendations.extend(misconfigs.get('recommendations', []))
        
        # From vulnerability scanner
        if vulnerabilities:
            recommendations.extend(vulnerabilities.get('recommendations', []))
        
        # Deduplicate and limit
        unique_recommendations = list(dict.fromkeys(recommendations))
        summary['top_recommendations'] = unique_recommendations[:10]
        
        return summary
    
    def save_results(self, output_file: str):
        """Save all detection results to file"""
        try:
            # Ensure output directory exists
            output_dir = os.path.dirname(output_file)
            if output_dir and not os.path.exists(output_dir):
                os.makedirs(output_dir)
            
            with open(output_file, 'w') as f:
                json.dump(self.results, f, indent=2, default=str)
            
            logger.info(f"Detection results saved to {output_file}")
        
        except Exception as e:
            logger.error(f"Failed to save results to {output_file}: {e}")
    
    def load_baseline_data(self, baseline_file: str):
        """Load baseline data for anomaly detection"""
        try:
            self.anomaly_detector.load_baseline(baseline_file)
            logger.info(f"Baseline data loaded from {baseline_file}")
        except Exception as e:
            logger.error(f"Failed to load baseline data: {e}")
    
    def save_baseline_data(self, baseline_file: str):
        """Save baseline data for anomaly detection"""
        try:
            self.anomaly_detector.save_baseline(baseline_file)
            logger.info(f"Baseline data saved to {baseline_file}")
        except Exception as e:
            logger.error(f"Failed to save baseline data: {e}")
    
    def get_detection_statistics(self) -> Dict:
        """Get statistics about detection capabilities"""
        return {
            'rule_engine': {
                'rules_loaded': len(self.rule_engine.rules),
                'threads': self.rule_engine.threads,
                'chunk_size': self.rule_engine.chunk_size
            },
            'anomaly_detector': {
                'patterns': len(self.anomaly_detector.patterns),
                'threshold': self.anomaly_detector.anomaly_threshold,
                'min_samples': self.anomaly_detector.min_samples
            },
            'health_scorer': {
                'categories': len(self.health_scorer.categories),
                'weights': self.health_scorer.weights
            },
            'misconfig_scanner': {
                'services': len(self.misconfig_scanner.scan_rules),
                'total_rules': sum(len(rules) for rules in self.misconfig_scanner.scan_rules.values())
            },
            'vulnerability_scanner': {
                'cve_entries': len(self.vulnerability_scanner.cve_database),
                'patterns': len(self.vulnerability_scanner.vulnerability_patterns)
            }
        }


def main():
    """Test the detection engine"""
    # Sample configuration
    config = {
        'rule_engine_threads': 4,
        'rule_engine_chunk_size': 100,
        'anomaly_detection': {
            'anomaly_threshold': 2.0,
            'min_samples': 10
        },
        'health_scoring': {
            'weights': {
                'critical_issues': 0.4,
                'high_issues': 0.3,
                'medium_issues': 0.2,
                'low_issues': 0.1
            }
        }
    }
    
    # Initialize detection engine
    engine = DetectionEngine(config)
    
    # Print detection statistics
    stats = engine.get_detection_statistics()
    print("Detection Engine Statistics:")
    print(json.dumps(stats, indent=2))
    
    # Test with sample events file (if it exists)
    sample_events_file = os.path.join(os.path.dirname(__file__), '..', 'logs', 'aws_security_events_latest.json')
    if os.path.exists(sample_events_file):
        print(f"\nRunning comprehensive scan on {sample_events_file}")
        results = engine.run_comprehensive_scan(sample_events_file)
        
        print(f"\nScan Results Summary:")
        print(f"Total Issues: {results['summary']['total_issues']}")
        print(f"Critical: {results['summary']['critical_issues']}")
        print(f"High: {results['summary']['high_issues']}")
        print(f"Medium: {results['summary']['medium_issues']}")
        print(f"Low: {results['summary']['low_issues']}")
        print(f"Overall Risk Score: {results['summary']['overall_risk_score']}/100")
        print(f"Overall Health Score: {results['summary']['overall_health_score']}/100")
    else:
        print(f"\nSample events file not found: {sample_events_file}")


if __name__ == "__main__":
    main()
