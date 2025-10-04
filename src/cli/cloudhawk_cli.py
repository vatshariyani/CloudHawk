#!/usr/bin/env python3
"""
CloudHawk Command Line Interface
===============================

A comprehensive CLI for CloudHawk security monitoring tool.
Provides commands for scanning, detection, alerting, and management.

Usage:
    cloudhawk scan aws --region us-east-1
    cloudhawk detect --rules custom-rules.yaml
    cloudhawk alerts --severity CRITICAL
    cloudhawk config --show
"""

import os
import sys
import json
import yaml
import argparse
import logging
from datetime import datetime
from typing import Dict, List, Any, Optional

# Add parent directory to path for imports
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from collector.aws_collector import AWSCollector
from detection.rule_engine import RuleEngine

class CloudHawkCLI:
    """Main CLI controller"""
    
    def __init__(self):
        self.base_dir = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
        self.config_file = os.path.join(self.base_dir, 'config', 'config.yaml')
        self.alerts_file = os.path.join(self.base_dir, 'src', 'alerts', 'alerts.json')
        self.rules_file = os.path.join(self.base_dir, 'src', 'detection', 'security_rules.yaml')
        
        # Setup logging
        self.setup_logging()
        self.logger = logging.getLogger(__name__)
        
        # Load configuration
        self.config = self.load_config()
    
    def setup_logging(self, level: str = "INFO"):
        """Setup logging configuration"""
        logging.basicConfig(
            level=getattr(logging, level.upper()),
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            handlers=[
                logging.StreamHandler(),
                logging.FileHandler(os.path.join(self.base_dir, 'cloudhawk.log'))
            ]
        )
    
    def load_config(self) -> Dict:
        """Load configuration from YAML file"""
        try:
            with open(self.config_file, 'r') as f:
                return yaml.safe_load(f)
        except FileNotFoundError:
            self.logger.warning(f"Config file not found: {self.config_file}")
            return self.get_default_config()
        except Exception as e:
            self.logger.error(f"Error loading config: {e}")
            return self.get_default_config()
    
    def get_default_config(self) -> Dict:
        """Get default configuration"""
        return {
            'aws': {
                'default_region': 'us-east-1',
                'max_events_per_service': 1000,
                'services': ['ec2', 's3', 'iam', 'cloudtrail', 'guardduty']
            },
            'detection': {
                'rule_engine': {
                    'threads': 4,
                    'chunk_size': 100
                }
            }
        }
    
    def print_banner(self):
        """Print CloudHawk banner"""
        print("🦅 CloudHawk Security Monitoring Tool")
        print("=" * 50)
    
    def scan_aws(self, args):
        """Scan AWS infrastructure for security issues"""
        self.print_banner()
        print(f"🔍 Starting AWS security scan...")
        print(f"Region: {args.region}")
        print(f"Max events: {args.max_events}")
        print(f"Services: {', '.join(args.services)}")
        print()
        
        try:
            # Initialize AWS collector
            collector = AWSCollector(
                region=args.region,
                max_events=args.max_events
            )
            
            # Collect security data
            print("📡 Collecting security data...")
            security_events = collector.collect_all_security_data()
            
            # Save events
            print("💾 Saving security events...")
            events_file = collector.save_security_events(security_events)
            
            # Run rule engine
            print("⚙️ Running rule engine...")
            rule_engine = RuleEngine(
                self.rules_file,
                events_file,
                threads=args.threads,
                chunk_size=args.chunk_size
            )
            rule_engine.run()
            
            # Print summary
            print(f"\n📊 Scan Summary:")
            print(f"   Events collected: {len(security_events)}")
            print(f"   Alerts generated: {len(rule_engine.alerts)}")
            print(f"   Events file: {events_file}")
            print(f"   Alerts file: {rule_engine.alerts_file}")
            
            # Count by severity
            severity_counts = {}
            for alert in rule_engine.alerts:
                severity = alert.get('severity', 'UNKNOWN')
                severity_counts[severity] = severity_counts.get(severity, 0) + 1
            
            if severity_counts:
                print(f"\n🚨 Alerts by Severity:")
                for severity, count in sorted(severity_counts.items()):
                    print(f"   {severity}: {count}")
            
            return 0
            
        except Exception as e:
            self.logger.error(f"Scan failed: {e}")
            print(f"❌ Error: {e}")
            return 1
    
    def detect(self, args):
        """Run detection on existing events"""
        self.print_banner()
        print(f"🔍 Running security detection...")
        print(f"Rules file: {args.rules}")
        print(f"Events file: {args.events}")
        print()
        
        try:
            # Initialize rule engine
            rule_engine = RuleEngine(
                args.rules,
                args.events,
                threads=args.threads,
                chunk_size=args.chunk_size
            )
            
            # Run detection
            rule_engine.run()
            
            # Print summary
            print(f"\n📊 Detection Summary:")
            print(f"   Alerts generated: {len(rule_engine.alerts)}")
            print(f"   Alerts file: {rule_engine.alerts_file}")
            
            return 0
            
        except Exception as e:
            self.logger.error(f"Detection failed: {e}")
            print(f"❌ Error: {e}")
            return 1
    
    def show_alerts(self, args):
        """Show security alerts"""
        self.print_banner()
        
        try:
            # Load alerts
            if not os.path.exists(self.alerts_file):
                print("⚠️ No alerts file found. Run a scan first.")
                return 1
            
            with open(self.alerts_file, 'r') as f:
                alerts_data = json.load(f)
            
            alerts = alerts_data.get('alerts', [])
            
            # Apply filters
            if args.severity:
                alerts = [a for a in alerts if a.get('severity') == args.severity]
            
            if args.service:
                alerts = [a for a in alerts if a.get('service') == args.service]
            
            if args.limit:
                alerts = alerts[:args.limit]
            
            # Print alerts
            print(f"🚨 Security Alerts ({len(alerts)} found)")
            print("=" * 50)
            
            if not alerts:
                print("✅ No alerts found matching your criteria.")
                return 0
            
            for i, alert in enumerate(alerts, 1):
                print(f"\n{i}. {alert.get('title', 'Unknown')}")
                print(f"   Severity: {alert.get('severity', 'UNKNOWN')}")
                print(f"   Service: {alert.get('service', 'UNKNOWN')}")
                print(f"   Rule ID: {alert.get('rule_id', 'N/A')}")
                print(f"   Description: {alert.get('description', 'N/A')}")
                print(f"   Remediation: {alert.get('remediation', 'N/A')}")
                print(f"   Timestamp: {alert.get('timestamp', 'N/A')}")
                
                if args.verbose:
                    print(f"   Raw Event: {json.dumps(alert.get('log_excerpt', {}), indent=2)}")
            
            return 0
            
        except Exception as e:
            self.logger.error(f"Error showing alerts: {e}")
            print(f"❌ Error: {e}")
            return 1
    
    def show_config(self, args):
        """Show configuration"""
        self.print_banner()
        print("⚙️ CloudHawk Configuration")
        print("=" * 50)
        
        if args.format == 'json':
            print(json.dumps(self.config, indent=2))
        else:
            print(yaml.dump(self.config, default_flow_style=False))
        
        return 0
    
    def show_rules(self, args):
        """Show detection rules"""
        self.print_banner()
        print("📋 Detection Rules")
        print("=" * 50)
        
        try:
            with open(self.rules_file, 'r') as f:
                rules_data = yaml.safe_load(f)
            
            rules = rules_data.get('rules', [])
            
            if args.service:
                rules = [r for r in rules if r.get('service') == args.service]
            
            if args.severity:
                rules = [r for r in rules if r.get('severity') == args.severity]
            
            print(f"Total rules: {len(rules)}")
            print()
            
            for i, rule in enumerate(rules, 1):
                print(f"{i}. {rule.get('id', 'N/A')} - {rule.get('title', 'No title')}")
                print(f"   Service: {rule.get('service', 'UNKNOWN')}")
                print(f"   Severity: {rule.get('severity', 'UNKNOWN')}")
                print(f"   Condition: {rule.get('condition', 'N/A')}")
                print(f"   Description: {rule.get('description', 'N/A')}")
                print()
            
            return 0
            
        except Exception as e:
            self.logger.error(f"Error showing rules: {e}")
            print(f"❌ Error: {e}")
            return 1
    
    def web_server(self, args):
        """Start web server"""
        self.print_banner()
        print("🌐 Starting CloudHawk Web Dashboard...")
        print(f"Port: {args.port}")
        print(f"Host: {args.host}")
        print()
        
        try:
            # Import and run Flask app
            sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'web'))
            from app import app
            
            app.run(host=args.host, port=args.port, debug=args.debug)
            return 0
            
        except Exception as e:
            self.logger.error(f"Error starting web server: {e}")
            print(f"❌ Error: {e}")
            return 1

def main():
    """Main CLI entry point"""
    cli = CloudHawkCLI()
    
    # Main parser
    parser = argparse.ArgumentParser(
        description='CloudHawk Security Monitoring Tool',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  cloudhawk scan aws --region us-east-1
  cloudhawk detect --events events.json --rules rules.yaml
  cloudhawk alerts --severity CRITICAL --limit 10
  cloudhawk config --show
  cloudhawk rules --service EC2
  cloudhawk web --port 8080
        """
    )
    
    parser.add_argument('--version', action='version', version='CloudHawk 1.0.0')
    parser.add_argument('--verbose', '-v', action='store_true', help='Verbose output')
    parser.add_argument('--log-level', default='INFO', choices=['DEBUG', 'INFO', 'WARNING', 'ERROR'],
                       help='Set logging level')
    
    # Subcommands
    subparsers = parser.add_subparsers(dest='command', help='Available commands')
    
    # Scan command
    scan_parser = subparsers.add_parser('scan', help='Scan infrastructure for security issues')
    scan_subparsers = scan_parser.add_subparsers(dest='provider', help='Cloud provider')
    
    # AWS scan
    aws_scan_parser = scan_subparsers.add_parser('aws', help='Scan AWS infrastructure')
    aws_scan_parser.add_argument('--region', default='us-east-1', help='AWS region')
    aws_scan_parser.add_argument('--max-events', type=int, default=1000, help='Max events per service')
    aws_scan_parser.add_argument('--services', nargs='+', 
                                choices=['ec2', 's3', 'iam', 'cloudtrail', 'guardduty'],
                                default=['ec2', 's3', 'iam', 'cloudtrail', 'guardduty'],
                                help='Services to scan')
    aws_scan_parser.add_argument('--threads', type=int, default=4, help='Number of threads')
    aws_scan_parser.add_argument('--chunk-size', type=int, default=100, help='Chunk size for processing')
    
    # Detect command
    detect_parser = subparsers.add_parser('detect', help='Run detection on existing events')
    detect_parser.add_argument('--events', required=True, help='Path to events JSON file')
    detect_parser.add_argument('--rules', help='Path to rules YAML file')
    detect_parser.add_argument('--threads', type=int, default=4, help='Number of threads')
    detect_parser.add_argument('--chunk-size', type=int, default=100, help='Chunk size for processing')
    
    # Alerts command
    alerts_parser = subparsers.add_parser('alerts', help='Show security alerts')
    alerts_parser.add_argument('--severity', choices=['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'],
                              help='Filter by severity')
    alerts_parser.add_argument('--service', help='Filter by service')
    alerts_parser.add_argument('--limit', type=int, help='Limit number of alerts')
    alerts_parser.add_argument('--verbose', action='store_true', help='Show detailed information')
    
    # Config command
    config_parser = subparsers.add_parser('config', help='Configuration management')
    config_parser.add_argument('--show', action='store_true', help='Show current configuration')
    config_parser.add_argument('--format', choices=['yaml', 'json'], default='yaml',
                              help='Output format')
    
    # Rules command
    rules_parser = subparsers.add_parser('rules', help='Show detection rules')
    rules_parser.add_argument('--service', help='Filter by service')
    rules_parser.add_argument('--severity', choices=['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'],
                             help='Filter by severity')
    
    # Web command
    web_parser = subparsers.add_parser('web', help='Start web dashboard')
    web_parser.add_argument('--host', default='0.0.0.0', help='Host to bind to')
    web_parser.add_argument('--port', type=int, default=5000, help='Port to bind to')
    web_parser.add_argument('--debug', action='store_true', help='Enable debug mode')
    
    # Parse arguments
    args = parser.parse_args()
    
    # Setup logging level
    if args.verbose or args.log_level:
        cli.setup_logging(args.log_level)
    
    # Execute command
    if args.command == 'scan':
        if args.provider == 'aws':
            return cli.scan_aws(args)
        else:
            parser.error("Please specify a cloud provider (aws)")
    
    elif args.command == 'detect':
        if not args.rules:
            args.rules = cli.rules_file
        return cli.detect(args)
    
    elif args.command == 'alerts':
        return cli.show_alerts(args)
    
    elif args.command == 'config':
        if args.show:
            return cli.show_config(args)
        else:
            parser.error("Please specify an action (--show)")
    
    elif args.command == 'rules':
        return cli.show_rules(args)
    
    elif args.command == 'web':
        return cli.web_server(args)
    
    else:
        parser.print_help()
        return 1

if __name__ == '__main__':
    sys.exit(main())
