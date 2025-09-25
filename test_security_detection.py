#!/usr/bin/env python3
"""
CloudHawk Security Detection Test Script
========================================

This script demonstrates the complete CloudHawk security detection workflow:
1. Collect security data from AWS
2. Run rule engine to detect security issues
3. Display results and recommendations

Usage:
    python test_security_detection.py
"""

import os
import sys
import json
import logging
from datetime import datetime

# Add src to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'src'))

from collector.aws_collector import AWSCollector
from detection.rule_engine import RuleEngine

def setup_logging():
    """Setup logging configuration"""
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        handlers=[
            logging.StreamHandler(),
            logging.FileHandler('cloudhawk.log')
        ]
    )

def main():
    """Main execution function"""
    print("🦅 CloudHawk Security Detection System")
    print("=" * 50)
    
    setup_logging()
    logger = logging.getLogger(__name__)
    
    try:
        # Step 1: Initialize AWS Collector
        print("\n📡 Step 1: Initializing AWS Security Collector...")
        collector = AWSCollector(region="us-east-1", max_events=500)
        print("✅ AWS Collector initialized successfully")
        
        # Step 2: Collect Security Data
        print("\n🔍 Step 2: Collecting AWS Security Data...")
        security_events = collector.collect_all_security_data()
        print(f"✅ Collected {len(security_events)} security events")
        
        # Step 3: Save collected data
        print("\n💾 Step 3: Saving collected data...")
        events_file = collector.save_security_events(security_events)
        print(f"✅ Security events saved to: {events_file}")
        
        # Step 4: Initialize Rule Engine
        print("\n⚙️ Step 4: Initializing Rule Engine...")
        rules_file = os.path.join("src", "detection", "security_rules.yaml")
        rule_engine = RuleEngine(rules_file, events_file, threads=4, chunk_size=100)
        print("✅ Rule Engine initialized successfully")
        
        # Step 5: Run Detection
        print("\n🚨 Step 5: Running Security Detection...")
        rule_engine.run()
        print(f"✅ Detection complete. Generated {len(rule_engine.alerts)} alerts")
        
        # Step 6: Display Results
        print("\n📊 Step 6: Security Detection Results")
        print("=" * 50)
        
        if not rule_engine.alerts:
            print("🎉 No security issues detected!")
            return
        
        # Group alerts by severity
        severity_groups = {}
        for alert in rule_engine.alerts:
            severity = alert.get('severity', 'UNKNOWN')
            if severity not in severity_groups:
                severity_groups[severity] = []
            severity_groups[severity].append(alert)
        
        # Display alerts by severity (Critical first)
        severity_order = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']
        for severity in severity_order:
            if severity in severity_groups:
                alerts = severity_groups[severity]
                print(f"\n🚨 {severity} SEVERITY ({len(alerts)} alerts):")
                print("-" * 40)
                
                for i, alert in enumerate(alerts, 1):
                    print(f"\n{i}. {alert.get('title', 'Unknown')}")
                    print(f"   Rule ID: {alert.get('rule_id', 'N/A')}")
                    print(f"   Description: {alert.get('description', 'N/A')}")
                    print(f"   Remediation: {alert.get('remediation', 'N/A')}")
                    
                    # Show log excerpt for context
                    log_excerpt = alert.get('log_excerpt', {})
                    if log_excerpt:
                        resource_id = log_excerpt.get('resource_id', 'N/A')
                        source = log_excerpt.get('source', 'N/A')
                        print(f"   Resource: {resource_id} ({source})")
        
        # Summary
        print(f"\n📈 Summary:")
        print(f"   Total Events Analyzed: {len(security_events)}")
        print(f"   Total Alerts Generated: {len(rule_engine.alerts)}")
        for severity in severity_order:
            if severity in severity_groups:
                count = len(severity_groups[severity])
                print(f"   {severity}: {count}")
        
        # Recommendations
        print(f"\n💡 Recommendations:")
        print("   1. Address CRITICAL alerts immediately")
        print("   2. Review HIGH severity alerts within 24 hours")
        print("   3. Plan remediation for MEDIUM/LOW alerts")
        print("   4. Set up automated monitoring and alerting")
        print("   5. Regular security assessments (weekly/monthly)")
        
        print(f"\n✅ Security detection complete!")
        print(f"📄 Detailed logs saved to: cloudhawk.log")
        print(f"📊 Alerts saved to: {rule_engine.alerts_file}")
        
    except Exception as e:
        logger.error(f"Security detection failed: {e}")
        print(f"\n❌ Error: {e}")
        print("Please check your AWS credentials and permissions.")
        return 1
    
    return 0

if __name__ == "__main__":
    exit_code = main()
    sys.exit(exit_code)
