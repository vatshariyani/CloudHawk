#!/usr/bin/env python3
"""
CloudHawk Setup Script
=====================

Setup script for CloudHawk security monitoring tool.
Handles installation, configuration, and initial setup.
"""

import os
import sys
import subprocess
import shutil
from pathlib import Path

def run_command(command, description):
    """Run a command and handle errors"""
    print(f"🔄 {description}...")
    try:
        result = subprocess.run(command, shell=True, check=True, capture_output=True, text=True)
        print(f"✅ {description} completed successfully")
        return True
    except subprocess.CalledProcessError as e:
        print(f"❌ {description} failed: {e}")
        print(f"Error output: {e.stderr}")
        return False

def create_directories():
    """Create necessary directories"""
    directories = [
        "logs",
        "alerts", 
        "src/alerts",
        "src/web/templates",
        "src/web/static"
    ]
    
    for directory in directories:
        Path(directory).mkdir(parents=True, exist_ok=True)
        print(f"📁 Created directory: {directory}")

def install_dependencies():
    """Install Python dependencies"""
    if not run_command("pip install -r requirements.txt", "Installing Python dependencies"):
        return False
    return True

def setup_config():
    """Setup configuration file"""
    config_file = "config.yaml"
    if not os.path.exists(config_file):
        print("📝 Creating default configuration file...")
        default_config = """# CloudHawk Configuration File
# AWS Security Detection Tool

# AWS Configuration
aws:
  # Default region for data collection
  default_region: "us-east-1"
  
  # Maximum events to collect per service
  max_events_per_service: 1000
  
  # Services to monitor
  services:
    - ec2
    - s3
    - iam
    - cloudtrail
    - guardduty

# Detection Configuration
detection:
  # Rule engine settings
  rule_engine:
    threads: 4
    chunk_size: 100
  
  # Alert thresholds
  alert_thresholds:
    critical: 0    # Alert on any critical findings
    high: 5        # Alert if more than 5 high severity findings
    medium: 20     # Alert if more than 20 medium severity findings
    low: 50        # Alert if more than 50 low severity findings

# Output Configuration
output:
  # Directory for log files
  log_directory: "logs"
  
  # File formats to save
  formats:
    - json
    - csv
  
  # Include raw events in output
  include_raw_events: true

# Alerting Configuration
alerting:
  # Enable/disable alerting
  enabled: false
  
  # Alert channels
  channels:
    slack:
      enabled: false
      webhook_url: ""
      channel: "#security-alerts"
    
    email:
      enabled: false
      smtp_server: ""
      smtp_port: 587
      username: ""
      password: ""
      recipients: []

# Security Configuration
security:
  # Mask sensitive data in logs
  mask_sensitive_data: true
  
  # Data retention (days)
  data_retention_days: 30
  
  # Encryption for stored data
  encrypt_stored_data: false
"""
        with open(config_file, 'w') as f:
            f.write(default_config)
        print(f"✅ Created {config_file}")
    else:
        print(f"📄 Configuration file {config_file} already exists")

def setup_aws_credentials():
    """Check AWS credentials setup"""
    print("🔑 Checking AWS credentials...")
    
    # Check if AWS CLI is installed
    if not shutil.which("aws"):
        print("⚠️ AWS CLI not found. Please install AWS CLI and configure credentials:")
        print("   https://docs.aws.amazon.com/cli/latest/userguide/getting-started-install.html")
        return False
    
    # Check if credentials are configured
    try:
        result = subprocess.run(["aws", "sts", "get-caller-identity"], 
                              capture_output=True, text=True, check=True)
        print("✅ AWS credentials are configured and valid")
        return True
    except subprocess.CalledProcessError:
        print("⚠️ AWS credentials not configured. Please run:")
        print("   aws configure")
        return False

def create_executable_script():
    """Create executable script for CloudHawk CLI"""
    script_content = """#!/usr/bin/env python3
import sys
import os

# Add src to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'src'))

from cli.cloudhawk_cli import main

if __name__ == '__main__':
    sys.exit(main())
"""
    
    script_path = "cloudhawk"
    with open(script_path, 'w') as f:
        f.write(script_content)
    
    # Make executable on Unix systems
    if os.name != 'nt':
        os.chmod(script_path, 0o755)
    
    print(f"✅ Created executable script: {script_path}")

def run_tests():
    """Run basic tests"""
    print("🧪 Running basic tests...")
    
    # Test imports
    try:
        sys.path.insert(0, 'src')
        from collector.aws_collector import AWSCollector
        from detection.rule_engine import RuleEngine
        print("✅ Core modules import successfully")
    except ImportError as e:
        print(f"❌ Import test failed: {e}")
        return False
    
    # Test configuration loading
    try:
        import yaml
        with open('config.yaml', 'r') as f:
            config = yaml.safe_load(f)
        print("✅ Configuration file loads successfully")
    except Exception as e:
        print(f"❌ Configuration test failed: {e}")
        return False
    
    return True

def main():
    """Main setup function"""
    print("🦅 CloudHawk Setup")
    print("=" * 50)
    
    # Check Python version
    if sys.version_info < (3, 8):
        print("❌ Python 3.8 or higher is required")
        sys.exit(1)
    
    print(f"✅ Python {sys.version_info.major}.{sys.version_info.minor} detected")
    
    # Create directories
    create_directories()
    
    # Install dependencies
    if not install_dependencies():
        print("❌ Setup failed during dependency installation")
        sys.exit(1)
    
    # Setup configuration
    setup_config()
    
    # Check AWS credentials
    aws_ok = setup_aws_credentials()
    
    # Create executable script
    create_executable_script()
    
    # Run tests
    if not run_tests():
        print("❌ Setup failed during testing")
        sys.exit(1)
    
    print("\n🎉 CloudHawk setup completed successfully!")
    print("\n📋 Next steps:")
    print("1. Configure AWS credentials if not already done:")
    print("   aws configure")
    print("\n2. Run a security scan:")
    print("   python test_security_detection.py")
    print("\n3. Start the web dashboard:")
    print("   python src/web/app.py")
    print("\n4. Use the CLI:")
    print("   python src/cli/cloudhawk_cli.py --help")
    
    if not aws_ok:
        print("\n⚠️ Note: AWS credentials need to be configured before running scans")
    
    print("\n📚 For more information, see README.md")

if __name__ == '__main__':
    main()
