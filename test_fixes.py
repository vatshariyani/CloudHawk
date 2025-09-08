#!/usr/bin/env python3
"""
Test script to verify CloudHawk fixes
"""

import sys
import os
import json

# Add src to path
sys.path.append(os.path.join(os.path.dirname(__file__), 'src'))

from detection.rule_engine import RuleEngine
from collector.aws_collector import AWSCollector

def test_rule_engine():
    """Test the improved rule engine"""
    print("🧪 Testing Rule Engine...")
    
    # Create test logs
    test_logs = [
        {
            "timestamp": "2024-01-01T00:00:00Z",
            "source": "AWS_S3",
            "resource_id": "test-bucket",
            "event_type": "S3_POLICY",
            "severity": "HIGH",
            "description": "Test bucket",
            "raw_event": {},
            "bucket": {
                "name": "test-bucket",
                "acl": "public-read",
                "policy": {"Statement": [{"Principal": "*"}]},
                "encryption": "Not enabled",
                "publicAccessBlock": False,
                "logging": False,
                "versioning": False
            }
        },
        {
            "timestamp": "2024-01-01T00:00:00Z",
            "source": "AWS_EC2",
            "resource_id": "sg-123456",
            "event_type": "SECURITY_GROUP",
            "severity": "HIGH",
            "description": "Test security group",
            "raw_event": {},
            "sg": {
                "name": "test-sg",
                "id": "sg-123456",
                "rules": "tcp/22-22,0.0.0.0/0"
            }
        }
    ]
    
    # Save test logs
    os.makedirs("src/collector/logs", exist_ok=True)
    with open("src/collector/logs/All_Logs.json", "w") as f:
        json.dump(test_logs, f, indent=2)
    
    # Test rule engine
    rules_file = "src/detection/rules.yaml"
    log_file = "src/collector/logs/All_Logs.json"
    
    engine = RuleEngine(rules_file, log_file, threads=2, chunk_size=100)
    engine.run()
    
    print(f"✅ Rule engine processed {len(test_logs)} logs")
    print(f"✅ Generated {len(engine.alerts)} alerts")
    
    # Show some alerts
    for alert in engine.alerts[:3]:
        print(f"   - {alert['title']}: {alert['severity']}")
    
    return len(engine.alerts) > 0

def test_aws_collector():
    """Test the improved AWS collector"""
    print("\n🧪 Testing AWS Collector...")
    
    try:
        collector = AWSCollector(region="us-east-1")
        print("✅ AWS Collector initialized successfully")
        
        # Test that the collector methods exist and are callable
        methods = [
            'collect_ec2', 'collect_s3', 'collect_iam', 'collect_cloudtrail',
            'collect_cloudwatch_logs', 'collect_ssm_logs', 'collect_config_changes',
            'collect_guardduty', 'collect_inspector', 'collect_vpc_flow_logs'
        ]
        
        for method in methods:
            if hasattr(collector, method):
                print(f"✅ Method {method} exists")
            else:
                print(f"❌ Method {method} missing")
                return False
        
        return True
        
    except Exception as e:
        print(f"❌ AWS Collector test failed: {e}")
        return False

def main():
    """Run all tests"""
    print("🚀 CloudHawk Fix Verification Tests\n")
    
    tests_passed = 0
    total_tests = 2
    
    # Test rule engine
    if test_rule_engine():
        tests_passed += 1
    
    # Test AWS collector
    if test_aws_collector():
        tests_passed += 1
    
    print(f"\n📊 Test Results: {tests_passed}/{total_tests} tests passed")
    
    if tests_passed == total_tests:
        print("🎉 All tests passed! CloudHawk fixes are working correctly.")
        return 0
    else:
        print("⚠️ Some tests failed. Please review the issues above.")
        return 1

if __name__ == "__main__":
    sys.exit(main())
