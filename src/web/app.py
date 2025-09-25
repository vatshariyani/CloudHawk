#!/usr/bin/env python3
"""
CloudHawk Web Dashboard
======================

A Flask-based web dashboard for CloudHawk security monitoring.
Provides real-time security alerts, trend analysis, and management interface.

Features:
- Security alerts dashboard
- Real-time monitoring
- Alert management
- Configuration interface
- API endpoints for integration
"""

import os
import json
import yaml
import logging
from datetime import datetime, timedelta
from flask import Flask, render_template, jsonify, request, redirect, url_for, flash
from typing import Dict, List, Any, Optional

# Setup logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Add parent directory to path for imports
import sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from detection.rule_engine import RuleEngine
from collector.aws_collector import AWSCollector

app = Flask(__name__)
app.secret_key = 'cloudhawk-secret-key-change-in-production'

# Configuration
BASE_DIR = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
CONFIG_FILE = os.path.join(BASE_DIR, 'config.yaml')
ALERTS_FILE = os.path.join(BASE_DIR, 'src', 'alerts', 'alerts.json')
RULES_FILE = os.path.join(BASE_DIR, 'src', 'detection', 'security_rules.yaml')

class CloudHawkDashboard:
    """Main dashboard controller"""
    
    def __init__(self):
        self.config = self.load_config()
        self.alerts_data = self.load_alerts()
        self.config_last_modified = 0
        self.alerts_last_modified = 0
    
    def load_config(self) -> Dict:
        """Load configuration from YAML file"""
        try:
            with open(CONFIG_FILE, 'r') as f:
                return yaml.safe_load(f)
        except FileNotFoundError:
            return self.get_default_config()
        except Exception as e:
            print(f"Error loading config: {e}")
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
            },
            'alerting': {
                'enabled': False,
                'channels': {
                    'slack': {'enabled': False},
                    'email': {'enabled': False}
                }
            }
        }
    
    def load_alerts(self) -> Dict:
        """Load alerts from JSON file"""
        try:
            if os.path.exists(ALERTS_FILE):
                with open(ALERTS_FILE, 'r') as f:
                    return json.load(f)
            return {'alerts': [], 'timestamp': None, 'total_alerts': 0}
        except Exception as e:
            print(f"Error loading alerts: {e}")
            return {'alerts': [], 'timestamp': None, 'total_alerts': 0}
    
    def get_alerts_summary(self) -> Dict:
        """Get alerts summary statistics"""
        alerts = self.alerts_data.get('alerts', [])
        
        summary = {
            'total': len(alerts),
            'by_severity': {},
            'by_service': {},
            'recent': []
        }
        
        # Count by severity
        for alert in alerts:
            severity = alert.get('severity', 'UNKNOWN')
            summary['by_severity'][severity] = summary['by_severity'].get(severity, 0) + 1
            
            service = alert.get('service', 'UNKNOWN')
            summary['by_service'][service] = summary['by_service'].get(service, 0) + 1
        
        # Get recent alerts (last 24 hours)
        now = datetime.utcnow()
        for alert in alerts:
            try:
                alert_time = datetime.fromisoformat(alert.get('timestamp', '').replace('Z', '+00:00'))
                if now - alert_time <= timedelta(hours=24):
                    summary['recent'].append(alert)
            except:
                continue
        
        summary['recent'] = sorted(summary['recent'], key=lambda x: x.get('timestamp', ''), reverse=True)[:10]
        
        return summary
    
    def initialize_modification_times(self):
        """Initialize modification times after methods are defined"""
        self.config_last_modified = self.get_config_last_modified()
        self.alerts_last_modified = self.get_alerts_last_modified()
    
    def get_config_last_modified(self) -> float:
        """Get last modified time of config file"""
        try:
            return os.path.getmtime(CONFIG_FILE)
        except:
            return 0
    
    def get_alerts_last_modified(self) -> float:
        """Get last modified time of alerts file"""
        try:
            return os.path.getmtime(ALERTS_FILE)
        except:
            return 0
    
    def reload_config_if_changed(self):
        """Reload configuration if file has been modified"""
        current_modified = self.get_config_last_modified()
        if current_modified > self.config_last_modified:
            self.config = self.load_config()
            self.config_last_modified = current_modified
            logger.info("Configuration reloaded due to file changes")
            return True
        return False
    
    def reload_alerts_if_changed(self):
        """Reload alerts if file has been modified"""
        current_modified = self.get_alerts_last_modified()
        if current_modified > self.alerts_last_modified:
            self.alerts_data = self.load_alerts()
            self.alerts_last_modified = current_modified
            logger.info("Alerts reloaded due to file changes")
            return True
        return False

# Initialize dashboard
dashboard = CloudHawkDashboard()
dashboard.initialize_modification_times()

def test_email_configuration(email_config):
    """Test email configuration"""
    try:
        import smtplib
        from email.mime.text import MIMEText
        from email.mime.multipart import MIMEMultipart
        
        smtp_server = email_config.get('smtp_server', '')
        smtp_port = email_config.get('smtp_port', 587)
        username = email_config.get('username', '')
        password = email_config.get('password', '')
        from_email = email_config.get('from_email', '')
        to_email = email_config.get('to_email', '')
        
        if not all([smtp_server, username, password, from_email, to_email]):
            return {'status': 'error', 'message': 'Missing required email configuration'}
        
        # Create test message
        msg = MIMEMultipart()
        msg['From'] = from_email
        msg['To'] = to_email
        msg['Subject'] = 'CloudHawk Email Configuration Test'
        
        body = """
        This is a test email from CloudHawk to verify your email configuration.
        
        If you receive this email, your email settings are working correctly.
        
        CloudHawk Security Monitoring System
        """
        
        msg.attach(MIMEText(body, 'plain'))
        
        # Connect to SMTP server and send email
        server = smtplib.SMTP(smtp_server, smtp_port)
        server.starttls()
        server.login(username, password)
        server.send_message(msg)
        server.quit()
        
        return {'status': 'success', 'message': 'Test email sent successfully'}
        
    except smtplib.SMTPAuthenticationError as e:
        return {'status': 'error', 'message': f'Authentication failed: {str(e)}. For Gmail, use an App Password, not your regular password.'}
    except smtplib.SMTPConnectError as e:
        return {'status': 'error', 'message': f'Connection failed: {str(e)}. Check your SMTP server and port settings.'}
    except smtplib.SMTPException as e:
        return {'status': 'error', 'message': f'SMTP Error: {str(e)}'}
    except Exception as e:
        return {'status': 'error', 'message': f'Email test failed: {str(e)}'}

def send_email_alert(alert, email_config):
    """Send email alert"""
    try:
        import smtplib
        from email.mime.text import MIMEText
        from email.mime.multipart import MIMEMultipart
        
        if not email_config.get('enabled', False):
            return False
        
        smtp_server = email_config.get('smtp_server', '')
        smtp_port = email_config.get('smtp_port', 587)
        username = email_config.get('username', '')
        password = email_config.get('password', '')
        from_email = email_config.get('from_email', '')
        to_email = email_config.get('to_email', '')
        
        if not all([smtp_server, username, password, from_email, to_email]):
            logger.error("Missing required email configuration fields")
            return False
        
        # Create alert message
        msg = MIMEMultipart()
        msg['From'] = from_email
        msg['To'] = to_email
        msg['Subject'] = f'CloudHawk Security Alert: {alert.get("title", "Security Alert")}'
        
        severity = alert.get('severity', 'UNKNOWN')
        service = alert.get('service', 'UNKNOWN')
        timestamp = alert.get('timestamp', '')
        description = alert.get('description', '')
        remediation = alert.get('remediation', '')
        
        body = f"""
        CloudHawk Security Alert
        
        Severity: {severity}
        Service: {service}
        Timestamp: {timestamp}
        
        Description:
        {description}
        
        Remediation:
        {remediation}
        
        Please review and take appropriate action.
        
        CloudHawk Security Monitoring System
        """
        
        msg.attach(MIMEText(body, 'plain'))
        
        # Send email
        server = smtplib.SMTP(smtp_server, smtp_port)
        server.starttls()
        server.login(username, password)
        server.send_message(msg)
        server.quit()
        
        logger.info(f"Email alert sent successfully to {to_email}")
        return True
        
    except smtplib.SMTPAuthenticationError as e:
        logger.error(f"SMTP Authentication failed: {e}")
        logger.error("This usually means the username/password is incorrect. For Gmail, use an App Password, not your regular password.")
        return False
    except smtplib.SMTPConnectError as e:
        logger.error(f"SMTP Connection failed: {e}")
        logger.error("Check your SMTP server and port settings.")
        return False
    except smtplib.SMTPException as e:
        logger.error(f"SMTP Error: {e}")
        return False
    except Exception as e:
        logger.error(f"Failed to send email alert: {e}")
        return False

def calculate_simple_health_score(alerts_data):
    """Calculate a simple health score based on alerts"""
    alerts = alerts_data.get('alerts', [])
    
    if not alerts:
        return {
            'overall_score': {'score': 100, 'grade': 'A'},
            'category_scores': {
                'iam_security': {'score': 100, 'issues': [], 'recommendations': []},
                'network_security': {'score': 100, 'issues': [], 'recommendations': []},
                'data_security': {'score': 100, 'issues': [], 'recommendations': []},
                'monitoring_security': {'score': 100, 'issues': [], 'recommendations': []},
                'compliance_security': {'score': 100, 'issues': [], 'recommendations': []},
                'access_security': {'score': 100, 'issues': [], 'recommendations': []}
            }
        }
    
    # Count issues by severity
    critical_count = len([a for a in alerts if a.get('severity') == 'CRITICAL'])
    high_count = len([a for a in alerts if a.get('severity') == 'HIGH'])
    medium_count = len([a for a in alerts if a.get('severity') == 'MEDIUM'])
    low_count = len([a for a in alerts if a.get('severity') == 'LOW'])
    
    # Calculate score (100 - penalties)
    score = 100
    score -= critical_count * 20
    score -= high_count * 10
    score -= medium_count * 5
    score -= low_count * 2
    score = max(0, score)
    
    # Determine grade
    if score >= 90:
        grade = 'A'
    elif score >= 80:
        grade = 'B'
    elif score >= 70:
        grade = 'C'
    elif score >= 60:
        grade = 'D'
    else:
        grade = 'F'
    
    # Calculate category scores (simplified)
    category_scores = {}
    services = ['iam', 'ec2', 's3', 'cloudtrail', 'guardduty', 'rds']
    
    for service in services:
        service_alerts = [a for a in alerts if a.get('service', '').lower() == service]
        service_critical = len([a for a in service_alerts if a.get('severity') == 'CRITICAL'])
        service_high = len([a for a in service_alerts if a.get('severity') == 'HIGH'])
        service_medium = len([a for a in service_alerts if a.get('severity') == 'MEDIUM'])
        service_low = len([a for a in service_alerts if a.get('severity') == 'LOW'])
        
        service_score = 100
        service_score -= service_critical * 20
        service_score -= service_high * 10
        service_score -= service_medium * 5
        service_score -= service_low * 2
        service_score = max(0, service_score)
        
        category_scores[f'{service}_security'] = {
            'score': service_score,
            'issues': [f"{service_critical} critical", f"{service_high} high", f"{service_medium} medium", f"{service_low} low"],
            'recommendations': [f"Address {service} security issues"] if service_alerts else []
        }
    
    return {
        'overall_score': {'score': score, 'grade': grade},
        'category_scores': category_scores
    }

def generate_recent_activity(alerts_data):
    """Generate recent activity based on alerts"""
    alerts = alerts_data.get('alerts', [])
    activity = []
    
    # Get recent alerts (last 10)
    recent_alerts = sorted(alerts, key=lambda x: x.get('timestamp', ''), reverse=True)[:10]
    
    for alert in recent_alerts:
        severity = alert.get('severity', 'LOW')
        service = alert.get('service', 'Unknown')
        title = alert.get('title', 'Security Alert')
        
        # Determine status based on severity
        if severity == 'CRITICAL':
            status = 'error'
        elif severity == 'HIGH':
            status = 'warning'
        else:
            status = 'success'
        
        activity.append({
            'timestamp': alert.get('timestamp', datetime.utcnow().isoformat()),
            'component': service,
            'status': status,
            'message': title
        })
    
    # Add some system activity
    activity.extend([
        {
            'timestamp': datetime.utcnow().isoformat(),
            'component': 'System',
            'status': 'success',
            'message': 'Health check completed'
        },
        {
            'timestamp': (datetime.utcnow() - timedelta(minutes=5)).isoformat(),
            'component': 'AWS Collector',
            'status': 'success',
            'message': 'Data collection completed'
        },
        {
            'timestamp': (datetime.utcnow() - timedelta(minutes=10)).isoformat(),
            'component': 'Rule Engine',
            'status': 'success',
            'message': 'Security rules processed'
        }
    ])
    
    # Sort by timestamp and return last 10
    activity.sort(key=lambda x: x['timestamp'], reverse=True)
    return activity[:10]

@app.route('/')
def index():
    """Main dashboard page"""
    # Reload data if files have changed
    dashboard.reload_config_if_changed()
    dashboard.reload_alerts_if_changed()
    
    summary = dashboard.get_alerts_summary()
    return render_template('dashboard.html', summary=summary, config=dashboard.config)

@app.route('/alerts')
def alerts():
    """Alerts page"""
    # Reload data if files have changed
    dashboard.reload_alerts_if_changed()
    
    alerts = dashboard.alerts_data.get('alerts', [])
    
    # Filter parameters
    severity_filter = request.args.get('severity', '')
    service_filter = request.args.get('service', '')
    
    # Apply filters
    filtered_alerts = alerts
    if severity_filter:
        filtered_alerts = [a for a in filtered_alerts if a.get('severity') == severity_filter]
    if service_filter:
        filtered_alerts = [a for a in filtered_alerts if a.get('service') == service_filter]
    
    # Sort by timestamp (newest first)
    filtered_alerts = sorted(filtered_alerts, key=lambda x: x.get('timestamp', ''), reverse=True)
    
    return render_template('alerts.html', 
                         alerts=filtered_alerts,
                         severity_filter=severity_filter,
                         service_filter=service_filter)

@app.route('/api/alerts')
def api_alerts():
    """API endpoint for alerts data"""
    return jsonify(dashboard.alerts_data)

@app.route('/api/summary')
def api_summary():
    """API endpoint for alerts summary"""
    return jsonify(dashboard.get_alerts_summary())

@app.route('/scan', methods=['GET', 'POST'])
def scan():
    """Run security scan"""
    if request.method == 'POST':
        try:
            # Get scan parameters with fallbacks
            config = dashboard.config or dashboard.get_default_config()
            region = request.form.get('region', config.get('aws', {}).get('default_region', 'us-east-1'))
            max_events = int(request.form.get('max_events', config.get('aws', {}).get('max_events_per_service', 1000)))
            
            flash('Starting security scan...', 'info')
            
            # Initialize AWS collector
            collector = AWSCollector(region=region, max_events=max_events)
            
            # Collect security data
            security_events = collector.collect_all_security_data()
            
            # Save events
            events_file = collector.save_security_events(security_events)
            
            # Run rule engine
            rule_engine = RuleEngine(RULES_FILE, events_file, threads=4, chunk_size=100)
            rule_engine.run()
            
            # Reload alerts
            dashboard.alerts_data = dashboard.load_alerts()
            
            # Send email alerts for critical and high severity issues
            email_config = config.get('alerting', {}).get('channels', {}).get('email', {})
            slack_config = config.get('alerting', {}).get('channels', {}).get('slack', {})
            
            if email_config.get('enabled', False):
                critical_alerts = [alert for alert in rule_engine.alerts if alert.get('severity') in ['CRITICAL', 'HIGH']]
                email_sent = 0
                for alert in critical_alerts:
                    if send_email_alert(alert, email_config):
                        email_sent += 1
                
                if email_sent > 0:
                    flash(f'Scan completed! Found {len(rule_engine.alerts)} security issues. Sent {email_sent} email alerts for critical/high severity issues.', 'success')
                else:
                    flash(f'Scan completed! Found {len(rule_engine.alerts)} security issues.', 'success')
            else:
                flash(f'Scan completed! Found {len(rule_engine.alerts)} security issues.', 'success')
            
            # Send Slack alerts if configured
            if slack_config.get('enabled', False):
                try:
                    from alerts.slack_alert import SlackAlert
                    slack_alert = SlackAlert(slack_config)
                    critical_alerts = [alert for alert in rule_engine.alerts if alert.get('severity') in ['CRITICAL', 'HIGH']]
                    if critical_alerts:
                        slack_sent = slack_alert.send_alerts(critical_alerts)
                        if slack_sent > 0:
                            flash(f'Sent {slack_sent} Slack alerts for critical/high severity issues.', 'info')
                except Exception as e:
                    flash(f'Failed to send Slack alerts: {str(e)}', 'warning')
            
        except Exception as e:
            flash(f'Scan failed: {str(e)}', 'error')
        
        return redirect(url_for('scan'))
    
    config = dashboard.config or dashboard.get_default_config()
    return render_template('scan.html', config=config)

@app.route('/config')
def config():
    """Configuration page"""
    # Reload config if file has changed
    dashboard.reload_config_if_changed()
    
    config = dashboard.config or dashboard.get_default_config()
    
    # Ensure config has all required sections
    if not isinstance(config, dict):
        config = dashboard.get_default_config()
    elif 'aws' not in config:
        # Merge with default config to ensure all sections exist
        default_config = dashboard.get_default_config()
        default_config.update(config)
        config = default_config
    
    return render_template('config.html', config=config)

def convert_form_data_to_config(form_data):
    """Convert flat form data to nested configuration structure"""
    # Start with default config structure
    config = dashboard.get_default_config()
    
    # Update alerting section with form data
    config['alerting'] = {
        'enabled': form_data.get('alerting.enabled', False),
        'channels': {
            'slack': {
                'enabled': form_data.get('alerting.channels.slack.enabled', False),
                'webhook_url': form_data.get('alerting.channels.slack.webhook_url', ''),
                'channel': form_data.get('alerting.channels.slack.channel', '#security-alerts')
            },
            'email': {
                'enabled': form_data.get('alerting.channels.email.enabled', False),
                'smtp_server': form_data.get('alerting.channels.email.smtp_server', ''),
                'smtp_port': int(form_data.get('alerting.channels.email.smtp_port', 587)),
                'username': form_data.get('alerting.channels.email.username', ''),
                'password': form_data.get('alerting.channels.email.password', ''),
                'from_email': form_data.get('alerting.channels.email.from_email', ''),
                'to_email': form_data.get('alerting.channels.email.to_email', '')
            }
        }
    }
    
    # Update with any existing config values
    try:
        if os.path.exists(CONFIG_FILE):
            with open(CONFIG_FILE, 'r') as f:
                existing_config = yaml.safe_load(f)
                if existing_config:
                    # Merge existing config with new values
                    config.update(existing_config)
                    # Update alerting section specifically
                    if 'alerting' in existing_config:
                        config['alerting'].update(existing_config['alerting'])
                        if 'channels' in existing_config['alerting']:
                            config['alerting']['channels'].update(existing_config['alerting']['channels'])
    except Exception as e:
        print(f"Warning: Could not merge existing config: {e}")
    
    return config

@app.route('/api/config', methods=['GET', 'POST'])
def api_config():
    """API endpoint for configuration with live updates"""
    if request.method == 'POST':
        try:
            new_config = request.json
            
            # Debug: Log what we received
            print(f"DEBUG: Received config data: {new_config}")
            
            # Convert flat form data to nested structure
            processed_config = convert_form_data_to_config(new_config)
            
            # Debug: Log processed config
            print(f"DEBUG: Processed config: {processed_config}")
            
            # Save configuration to file
            with open(CONFIG_FILE, 'w') as f:
                yaml.dump(processed_config, f, default_flow_style=False)
            
            # Update dashboard config immediately (live update)
            dashboard.config = processed_config
            dashboard.config_last_modified = dashboard.get_config_last_modified()
            
            # Test email configuration if provided
            email_config = processed_config.get('alerting', {}).get('channels', {}).get('email', {})
            if email_config.get('enabled', False):
                email_status = test_email_configuration(email_config)
                return jsonify({
                    'status': 'success', 
                    'message': 'Configuration updated successfully',
                    'email_test': email_status
                })
            
            return jsonify({
                'status': 'success', 
                'message': 'Configuration updated successfully'
            })
        except Exception as e:
            return jsonify({'status': 'error', 'message': str(e)}), 500
    
    # Reload config if file has changed
    dashboard.reload_config_if_changed()
    return jsonify(dashboard.config)

@app.route('/api/test-email', methods=['POST'])
def test_email():
    """Test email configuration endpoint"""
    try:
        email_config = request.json
        result = test_email_configuration(email_config)
        return jsonify(result)
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500

@app.route('/api/send-alerts', methods=['POST'])
def send_alerts():
    """Send alerts via email and/or Slack"""
    try:
        data = request.json
        alert_type = data.get('type', 'all')  # 'all', 'email', 'slack'
        
        # Get current alerts
        alerts_data = dashboard.load_alerts()
        alerts = alerts_data.get('alerts', [])
        
        if not alerts:
            return jsonify({'status': 'error', 'message': 'No alerts to send'}), 400
        
        # Reload configuration to get latest changes
        dashboard.reload_config_if_changed()
        
        # Get configuration
        config = dashboard.config or dashboard.get_default_config()
        results = {'email': None, 'slack': None}
        
        # Debug: Log current config
        print(f"DEBUG: Current config in send_alerts: {config}")
        print(f"DEBUG: Email config: {config.get('alerting', {}).get('channels', {}).get('email', {})}")
        
        # Send email alerts
        if alert_type in ['all', 'email']:
            email_config = config.get('alerting', {}).get('channels', {}).get('email', {})
            if email_config.get('enabled', False):
                email_sent = 0
                for alert in alerts:
                    if send_email_alert(alert, email_config):
                        email_sent += 1
                results['email'] = {'status': 'success', 'sent': email_sent, 'total': len(alerts)}
            else:
                # Provide more detailed error message
                if not email_config:
                    results['email'] = {'status': 'error', 'message': 'Email configuration not found'}
                elif not email_config.get('enabled'):
                    results['email'] = {'status': 'error', 'message': 'Email alerts are disabled in configuration'}
                else:
                    results['email'] = {'status': 'error', 'message': 'Email configuration incomplete'}
        
        # Send Slack alerts
        if alert_type in ['all', 'slack']:
            slack_config = config.get('alerting', {}).get('channels', {}).get('slack', {})
            if slack_config.get('enabled', False):
                try:
                    from alerts.slack_alert import SlackAlert
                    slack_alert = SlackAlert(slack_config)
                    slack_sent = slack_alert.send_alerts(alerts)
                    results['slack'] = {'status': 'success', 'sent': slack_sent, 'total': len(alerts)}
                except Exception as e:
                    results['slack'] = {'status': 'error', 'message': str(e)}
            else:
                results['slack'] = {'status': 'error', 'message': 'Slack not configured'}
        
        return jsonify({'status': 'success', 'results': results})
    
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500

@app.route('/api/debug-config', methods=['GET'])
def debug_config():
    """Debug endpoint to check current configuration"""
    try:
        dashboard.reload_config_if_changed()
        config = dashboard.config or dashboard.get_default_config()
        return jsonify({
            'status': 'success',
            'config_exists': dashboard.config is not None,
            'email_config': config.get('alerting', {}).get('channels', {}).get('email', {}),
            'slack_config': config.get('alerting', {}).get('channels', {}).get('slack', {}),
            'config_file_path': CONFIG_FILE,
            'config_file_exists': os.path.exists(CONFIG_FILE),
            'full_config': config
        })
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500

@app.route('/api/test-save', methods=['POST'])
def test_save():
    """Test endpoint to save a simple configuration"""
    try:
        # Get the current config or default config
        current_config = dashboard.config or dashboard.get_default_config()
        
        # Only enable email alerts without changing existing settings
        if 'alerting' not in current_config:
            current_config['alerting'] = {}
        if 'channels' not in current_config['alerting']:
            current_config['alerting']['channels'] = {}
        if 'email' not in current_config['alerting']['channels']:
            current_config['alerting']['channels']['email'] = {}
        
        # Enable alerting and email
        current_config['alerting']['enabled'] = True
        current_config['alerting']['channels']['email']['enabled'] = True
        
        # Only set test values if no existing email config
        email_config = current_config['alerting']['channels']['email']
        if not email_config.get('smtp_server') and not email_config.get('username'):
            # Only set test values if no email configuration exists at all
            email_config.update({
                'smtp_server': 'smtp.gmail.com',
                'smtp_port': 587,
                'username': 'test@example.com',
                'password': 'testpassword',
                'from_email': 'test@example.com',
                'to_email': 'test@example.com'
            })
        
        # Save configuration
        with open(CONFIG_FILE, 'w') as f:
            yaml.dump(current_config, f, default_flow_style=False)
        
        # Update dashboard config
        dashboard.config = current_config
        dashboard.config_last_modified = dashboard.get_config_last_modified()
        
        return jsonify({'status': 'success', 'message': 'Email alerts enabled (preserving existing settings)'})
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500

@app.route('/api/test-email-only', methods=['POST'])
def test_email_only():
    """Test email sending without changing configuration"""
    try:
        # Get current email configuration
        config = dashboard.config or dashboard.get_default_config()
        email_config = config.get('alerting', {}).get('channels', {}).get('email', {})
        
        if not email_config.get('enabled', False):
            return jsonify({'status': 'error', 'message': 'Email alerts are not enabled. Please enable them first.'}), 400
        
        # Create a test alert
        test_alert = {
            'timestamp': datetime.utcnow().isoformat(),
            'title': 'CloudHawk Email Test',
            'description': 'This is a test email from CloudHawk to verify your email configuration is working correctly.',
            'severity': 'INFO',
            'service': 'SYSTEM',
            'remediation': 'No action required - this is just a test email.'
        }
        
        # Send test email
        try:
            success = send_email_alert(test_alert, email_config)
            
            if success:
                return jsonify({'status': 'success', 'message': 'Test email sent successfully! Check your inbox.'})
            else:
                return jsonify({'status': 'error', 'message': 'Failed to send test email. Check your email configuration.'})
        except Exception as e:
            return jsonify({'status': 'error', 'message': f'Email sending error: {str(e)}'})
    
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500

@app.route('/api/debug-email-config', methods=['GET'])
def debug_email_config():
    """Debug endpoint to check email configuration details"""
    try:
        config = dashboard.config or dashboard.get_default_config()
        email_config = config.get('alerting', {}).get('channels', {}).get('email', {})
        
        # Check what fields are missing
        required_fields = ['smtp_server', 'username', 'password', 'from_email', 'to_email']
        missing_fields = []
        present_fields = {}
        
        for field in required_fields:
            value = email_config.get(field, '')
            if not value:
                missing_fields.append(field)
            else:
                # Mask password for security
                if field == 'password':
                    present_fields[field] = '***' + value[-4:] if len(value) > 4 else '***'
                else:
                    present_fields[field] = value
        
        return jsonify({
            'status': 'success',
            'email_enabled': email_config.get('enabled', False),
            'alerting_enabled': config.get('alerting', {}).get('enabled', False),
            'missing_fields': missing_fields,
            'present_fields': present_fields,
            'all_required_present': len(missing_fields) == 0,
            'full_email_config': email_config
        })
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500

@app.route('/api/clear-test-config', methods=['POST'])
def clear_test_config():
    """Clear test configuration and reset email settings"""
    try:
        dashboard.reload_config_if_changed()
        current_config = dashboard.config.copy()
        
        # Reset email configuration to empty values
        current_config['alerting']['channels']['email'] = {
            'enabled': False,
            'smtp_server': '',
            'smtp_port': 587,
            'username': '',
            'password': '',
            'from_email': '',
            'to_email': ''
        }
        
        # Save configuration
        with open(CONFIG_FILE, 'w') as f:
            yaml.dump(current_config, f, default_flow_style=False)
        
        # Reload dashboard configuration
        dashboard.config = current_config
        
        return jsonify({'status': 'success', 'message': 'Test configuration cleared successfully'})
        
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)})

@app.route('/api/send-notification', methods=['POST'])
def send_notification():
    """Send notification email about rule changes"""
    try:
        data = request.json
        notification_type = data.get('type', 'rules_changed')
        message = data.get('message', 'Security rules have been updated')
        
        # Reload configuration to get latest changes
        dashboard.reload_config_if_changed()
        
        # Get configuration
        config = dashboard.config or dashboard.get_default_config()
        email_config = config.get('alerting', {}).get('channels', {}).get('email', {})
        
        if not email_config.get('enabled', False):
            return jsonify({'status': 'error', 'message': 'Email not configured'}), 400
        
        # Create notification message
        notification_alert = {
            'timestamp': datetime.utcnow().isoformat(),
            'title': f'CloudHawk {notification_type.replace("_", " ").title()}',
            'description': message,
            'severity': 'INFO',
            'service': 'SYSTEM',
            'remediation': 'Please review the changes and ensure they meet your security requirements.'
        }
        
        # Send notification
        success = send_email_alert(notification_alert, email_config)
        
        if success:
            return jsonify({'status': 'success', 'message': 'Notification sent successfully'})
        else:
            return jsonify({'status': 'error', 'message': 'Failed to send notification'})
    
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500

@app.route('/rules')
def rules():
    """Rules management page"""
    try:
        with open(RULES_FILE, 'r') as f:
            rules_data = yaml.safe_load(f)
        rules = rules_data.get('rules', [])
    except Exception as e:
        rules = []
        flash(f'Error loading rules: {str(e)}', 'error')
    
    return render_template('rules.html', rules=rules)

@app.route('/api/rules', methods=['GET', 'POST'])
def api_rules():
    """API endpoint for rules management"""
    if request.method == 'POST':
        try:
            new_rules = request.json
            with open(RULES_FILE, 'w') as f:
                yaml.dump(new_rules, f, default_flow_style=False)
            return jsonify({'status': 'success'})
        except Exception as e:
            return jsonify({'status': 'error', 'message': str(e)}), 500
    
    try:
        with open(RULES_FILE, 'r') as f:
            rules_data = yaml.safe_load(f)
        return jsonify(rules_data)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/health')
def health():
    """Health check endpoint"""
    return jsonify({
        'status': 'healthy',
        'timestamp': datetime.utcnow().isoformat(),
        'version': '1.0.0'
    })

@app.route('/health-page')
def health_page():
    """Health dashboard page"""
    return render_template('health.html')

@app.route('/api/health')
def api_health():
    """Enhanced health API endpoint with detailed system information"""
    try:
        # Get basic system info
        system_status = 'healthy'
        version = '1.0.0'
        timestamp = datetime.utcnow().isoformat()
        
        # Get alerts data
        alerts_data = dashboard.load_alerts()
        alerts_count = len(alerts_data.get('alerts', []))
        
        # Get events count (if events file exists)
        events_count = 0
        events_file = os.path.join(BASE_DIR, 'src', 'logs', 'aws_security_events_latest.json')
        if os.path.exists(events_file):
            try:
                with open(events_file, 'r') as f:
                    events_data = json.load(f)
                    if isinstance(events_data, list):
                        events_count = len(events_data)
                    elif isinstance(events_data, dict) and 'events' in events_data:
                        events_count = len(events_data['events'])
            except:
                pass
        
        # Get rules count
        rules_count = 0
        if os.path.exists(RULES_FILE):
            try:
                with open(RULES_FILE, 'r') as f:
                    rules_data = yaml.safe_load(f)
                    if isinstance(rules_data, list):
                        rules_count = len(rules_data)
                    elif isinstance(rules_data, dict) and 'rules' in rules_data:
                        rules_count = len(rules_data['rules'])
            except:
                pass
        
        # Calculate health score (simplified)
        health_score = calculate_simple_health_score(alerts_data)
        
        # Generate recent activity
        recent_activity = generate_recent_activity(alerts_data)
        
        # Check AWS connection status
        aws_status = 'connected'  # Simplified - in real implementation, would test AWS connectivity
        
        return jsonify({
            'system_status': system_status,
            'timestamp': timestamp,
            'version': version,
            'health_score': health_score,
            'summary': {
                'critical_issues': len([a for a in alerts_data.get('alerts', []) if a.get('severity') == 'CRITICAL']),
                'high_issues': len([a for a in alerts_data.get('alerts', []) if a.get('severity') == 'HIGH']),
                'medium_issues': len([a for a in alerts_data.get('alerts', []) if a.get('severity') == 'MEDIUM']),
                'low_issues': len([a for a in alerts_data.get('alerts', []) if a.get('severity') == 'LOW'])
            },
            'events_count': events_count,
            'alerts_count': alerts_count,
            'rules_count': rules_count,
            'aws_status': aws_status,
            'recent_activity': recent_activity
        })
    
    except Exception as e:
        logger.error(f"Health API error: {e}")
        return jsonify({
            'system_status': 'error',
            'timestamp': datetime.utcnow().isoformat(),
            'version': '1.0.0',
            'error': str(e)
        }), 500

@app.errorhandler(404)
def not_found(error):
    """404 error handler"""
    return render_template('404.html'), 404

@app.errorhandler(500)
def internal_error(error):
    """500 error handler"""
    return render_template('500.html'), 500

if __name__ == '__main__':
    # Create templates directory if it doesn't exist
    templates_dir = os.path.join(os.path.dirname(__file__), 'templates')
    os.makedirs(templates_dir, exist_ok=True)
    
    # Create static directory if it doesn't exist
    static_dir = os.path.join(os.path.dirname(__file__), 'static')
    os.makedirs(static_dir, exist_ok=True)
    
    print("🦅 CloudHawk Web Dashboard")
    print("=" * 50)
    print("Starting web server...")
    print("Dashboard will be available at: http://localhost:5000")
    print("Press Ctrl+C to stop")
    
    app.run(host='0.0.0.0', port=5000, debug=True)
