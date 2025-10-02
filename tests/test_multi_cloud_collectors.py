#!/usr/bin/env python3
"""
Test script for CloudHawk multi-cloud collectors
Tests AWS, GCP, and Azure collectors to ensure they work correctly
"""

import os
import sys
import json
import logging
from datetime import datetime

# Add src directory to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'src'))

from collector.aws_collector import AWSCollector
from collector.gcp_collector import GCPCollector
from collector.azure_collector import AzureCollector

def test_aws_collector():
    """Test AWS collector"""
    print("🦅 Testing AWS Collector")
    print("=" * 50)
    
    try:
        # Initialize AWS collector
        collector = AWSCollector(region="us-east-1", max_events=100)
        
        # Test individual collection methods
        print("Testing EC2 security collection...")
        ec2_events = collector.collect_ec2_security()
        print(f"  ✓ Collected {len(ec2_events)} EC2 events")
        
        print("Testing S3 security collection...")
        s3_events = collector.collect_s3_security()
        print(f"  ✓ Collected {len(s3_events)} S3 events")
        
        print("Testing IAM security collection...")
        iam_events = collector.collect_iam_security()
        print(f"  ✓ Collected {len(iam_events)} IAM events")
        
        print("Testing CloudTrail security collection...")
        cloudtrail_events = collector.collect_cloudtrail_security()
        print(f"  ✓ Collected {len(cloudtrail_events)} CloudTrail events")
        
        print("Testing GuardDuty security collection...")
        guardduty_events = collector.collect_guardduty_security()
        print(f"  ✓ Collected {len(guardduty_events)} GuardDuty events")
        
        # Test full collection
        print("\nTesting full AWS collection...")
        all_events = collector.collect_all_security_data()
        print(f"  ✓ Total events collected: {len(all_events)}")
        
        # Save events
        output_file = collector.save_security_events(all_events, "logs")
        print(f"  ✓ Events saved to: {output_file}")
        
        return True
        
    except Exception as e:
        print(f"  ❌ AWS collector test failed: {e}")
        return False

def test_gcp_collector():
    """Test GCP collector"""
    print("\n🦅 Testing GCP Collector")
    print("=" * 50)
    
    try:
        # Get project ID from environment or use default
        project_id = os.getenv("GOOGLE_CLOUD_PROJECT", "test-project")
        
        # Initialize GCP collector
        collector = GCPCollector(project_id=project_id, max_events=100)
        
        # Test individual collection methods
        print("Testing IAM security collection...")
        iam_events = collector.collect_iam_security()
        print(f"  ✓ Collected {len(iam_events)} IAM events")
        
        print("Testing Storage security collection...")
        storage_events = collector.collect_storage_security()
        print(f"  ✓ Collected {len(storage_events)} Storage events")
        
        print("Testing Compute security collection...")
        compute_events = collector.collect_compute_security()
        print(f"  ✓ Collected {len(compute_events)} Compute events")
        
        print("Testing Logging security collection...")
        logging_events = collector.collect_logging_security()
        print(f"  ✓ Collected {len(logging_events)} Logging events")
        
        print("Testing Security Command Center collection...")
        scc_events = collector.collect_security_center_findings()
        print(f"  ✓ Collected {len(scc_events)} Security Command Center events")
        
        print("Testing Asset Inventory collection...")
        asset_events = collector.collect_asset_inventory()
        print(f"  ✓ Collected {len(asset_events)} Asset Inventory events")
        
        # Test full collection
        print("\nTesting full GCP collection...")
        all_events = collector.collect_all_security_data()
        print(f"  ✓ Total events collected: {len(all_events)}")
        
        # Save events
        output_file = collector.save_security_events(all_events, "logs")
        print(f"  ✓ Events saved to: {output_file}")
        
        return True
        
    except Exception as e:
        print(f"  ❌ GCP collector test failed: {e}")
        return False

def test_azure_collector():
    """Test Azure collector"""
    print("\n🦅 Testing Azure Collector")
    print("=" * 50)
    
    try:
        # Get subscription ID from environment or use default
        subscription_id = os.getenv("AZURE_SUBSCRIPTION_ID", "test-subscription")
        
        # Initialize Azure collector
        collector = AzureCollector(subscription_id=subscription_id, max_events=100)
        
        # Test individual collection methods
        print("Testing Azure AD security collection...")
        ad_events = collector.collect_azure_ad_security()
        print(f"  ✓ Collected {len(ad_events)} Azure AD events")
        
        print("Testing Storage security collection...")
        storage_events = collector.collect_storage_security()
        print(f"  ✓ Collected {len(storage_events)} Storage events")
        
        print("Testing VM security collection...")
        vm_events = collector.collect_vm_security()
        print(f"  ✓ Collected {len(vm_events)} VM events")
        
        print("Testing Network security collection...")
        network_events = collector.collect_network_security()
        print(f"  ✓ Collected {len(network_events)} Network events")
        
        print("Testing Activity Log collection...")
        activity_events = collector.collect_activity_log()
        print(f"  ✓ Collected {len(activity_events)} Activity Log events")
        
        print("Testing Security Center collection...")
        security_center_events = collector.collect_security_center_findings()
        print(f"  ✓ Collected {len(security_center_events)} Security Center events")
        
        print("Testing Key Vault collection...")
        keyvault_events = collector.collect_key_vault_security()
        print(f"  ✓ Collected {len(keyvault_events)} Key Vault events")
        
        # Test full collection
        print("\nTesting full Azure collection...")
        all_events = collector.collect_all_security_data()
        print(f"  ✓ Total events collected: {len(all_events)}")
        
        # Save events
        output_file = collector.save_security_events(all_events, "logs")
        print(f"  ✓ Events saved to: {output_file}")
        
        return True
        
    except Exception as e:
        print(f"  ❌ Azure collector test failed: {e}")
        return False

def test_rule_engine_integration():
    """Test rule engine integration with multi-cloud events"""
    print("\n🦅 Testing Rule Engine Integration")
    print("=" * 50)
    
    try:
        from detection.rule_engine import RuleEngine
        
        # Check if we have any event files
        logs_dir = "logs"
        if not os.path.exists(logs_dir):
            print("  ⚠️  No logs directory found, skipping rule engine test")
            return True
        
        # Find the most recent event file
        event_files = [f for f in os.listdir(logs_dir) if f.endswith('.json')]
        if not event_files:
            print("  ⚠️  No event files found, skipping rule engine test")
            return True
        
        latest_file = max(event_files, key=lambda x: os.path.getctime(os.path.join(logs_dir, x)))
        events_file = os.path.join(logs_dir, latest_file)
        
        print(f"  ✓ Using events file: {latest_file}")
        
        # Initialize rule engine
        rules_file = "src/detection/security_rules.yaml"
        rule_engine = RuleEngine(rules_file, events_file, threads=2, chunk_size=50)
        
        # Run rule engine
        print("  ✓ Running rule engine...")
        rule_engine.run()
        
        print(f"  ✓ Generated {len(rule_engine.alerts)} alerts")
        
        # Show alert summary
        severity_counts = {}
        for alert in rule_engine.alerts:
            severity = alert.get('severity', 'UNKNOWN')
            severity_counts[severity] = severity_counts.get(severity, 0) + 1
        
        print("  📊 Alert Summary:")
        for severity, count in sorted(severity_counts.items()):
            print(f"    {severity}: {count}")
        
        return True
        
    except Exception as e:
        print(f"  ❌ Rule engine test failed: {e}")
        return False

def main():
    """Main test function"""
    print("🦅 CloudHawk Multi-Cloud Collector Test Suite")
    print("=" * 60)
    print(f"Test started at: {datetime.now().isoformat()}")
    print()
    
    # Configure logging
    logging.basicConfig(
        level=logging.WARNING,  # Reduce log noise during testing
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    
    # Create logs directory
    os.makedirs("logs", exist_ok=True)
    
    # Test results
    results = {}
    
    # Test AWS collector
    results['aws'] = test_aws_collector()
    
    # Test GCP collector
    results['gcp'] = test_gcp_collector()
    
    # Test Azure collector
    results['azure'] = test_azure_collector()
    
    # Test rule engine integration
    results['rule_engine'] = test_rule_engine_integration()
    
    # Print summary
    print("\n" + "=" * 60)
    print("📊 Test Results Summary")
    print("=" * 60)
    
    for test_name, passed in results.items():
        status = "✅ PASSED" if passed else "❌ FAILED"
        print(f"{test_name.upper()}: {status}")
    
    total_tests = len(results)
    passed_tests = sum(results.values())
    
    print(f"\nOverall: {passed_tests}/{total_tests} tests passed")
    
    if passed_tests == total_tests:
        print("🎉 All tests passed! Multi-cloud collectors are working correctly.")
    else:
        print("⚠️  Some tests failed. Check the output above for details.")
    
    print(f"\nTest completed at: {datetime.now().isoformat()}")

if __name__ == "__main__":
    main()
