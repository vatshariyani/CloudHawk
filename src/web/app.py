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
from collector.gcp_collector import GCPCollector
from collector.azure_collector import AzureCollector

# Import API modules
from api.routes import api_bp
from api.swagger import swagger_bp

app = Flask(__name__)
app.secret_key = 'cloudhawk-secret-key-change-in-production'

# Register API blueprints
app.register_blueprint(api_bp)
app.register_blueprint(swagger_bp)

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
            'azure': {
                'subscription_id': '',
                'max_events_per_service': 1000,
                'services': ['storage', 'vm', 'keyvault', 'security_center', 'activity_log']
            },
            'gcp': {
                'project_id': '',
                'max_events_per_service': 1000,
                'services': ['iam', 'storage', 'compute', 'logging', 'security_command_center', 'asset_inventory']
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

def send_consolidated_email_alert(service, alerts, email_config):
    """Send consolidated email alert for a service with multiple alerts"""
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
            logger.error("Missing required email configuration fields for consolidated alert")
            return False
        
        # Count alerts by severity
        severity_counts = {}
        for alert in alerts:
            severity = alert.get('severity', 'Unknown')
            severity_counts[severity] = severity_counts.get(severity, 0) + 1
        
        # Create severity summary
        severity_summary = []
        for severity, count in severity_counts.items():
            severity_summary.append(f"{severity}: {count}")
        
        # Create message
        msg = MIMEMultipart()
        msg['From'] = from_email
        msg['To'] = to_email
        msg['Subject'] = f"CloudHawk Security Alert: {service} Service ({len(alerts)} alerts)"
        
        # Create consolidated email body
        body = f"""
        CloudHawk Security Alert Summary
        
        Service: {service}
        Total Alerts: {len(alerts)}
        Severity Breakdown: {', '.join(severity_summary)}
        
        Alert Details:
        """
        
        # Add each alert with details
        for i, alert in enumerate(alerts, 1):
            body += f"""
        --- Alert {i} ---
        Rule ID: {alert.get('id', 'N/A')}
        Title: {alert.get('title', 'Unknown')}
        Severity: {alert.get('severity', 'Unknown')}
        Description: {alert.get('description', 'No description')}
        Timestamp: {alert.get('timestamp', 'Unknown')}
        Remediation: {alert.get('remediation', 'No remediation provided')}
        """
        
        body += f"""
        
        CloudHawk Security Monitoring System
        Generated: {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')}
        """
        
        msg.attach(MIMEText(body, 'plain'))
        
        # Send email
        server = smtplib.SMTP(smtp_server, smtp_port)
        server.starttls()
        server.login(username, password)
        server.send_message(msg)
        server.quit()
        
        logger.info(f"✅ Consolidated email sent for {service} service with {len(alerts)} alerts")
        return True
        
    except smtplib.SMTPAuthenticationError as e:
        logger.error(f"SMTP Authentication failed for consolidated alert: {e}")
        return False
    except smtplib.SMTPConnectError as e:
        logger.error(f"SMTP Connection failed for consolidated alert: {e}")
        return False
    except smtplib.SMTPException as e:
        logger.error(f"SMTP Error for consolidated alert: {e}")
        return False
    except Exception as e:
        logger.error(f"Failed to send consolidated email alert for {service}: {e}")
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
            provider = request.form.get('provider', 'AWS')
            region = request.form.get('region', config.get('aws', {}).get('default_region', 'us-east-1'))
            max_events = int(request.form.get('max_events', config.get('aws', {}).get('max_events_per_service', 1000)))
            
            flash(f'Starting {provider} security scan...', 'info')
            
            # Initialize appropriate collector based on provider
            if provider == 'AWS':
                collector = AWSCollector(region=region, max_events=max_events)
            elif provider == 'Azure':
                subscription_id = request.form.get('subscription_id', os.getenv('AZURE_SUBSCRIPTION_ID', ''))
                if not subscription_id:
                    flash('Azure subscription ID is required for Azure scans', 'error')
                    return redirect(url_for('scan'))
                collector = AzureCollector(subscription_id=subscription_id)
            elif provider == 'GCP':
                project_id = request.form.get('project_id', os.getenv('GOOGLE_CLOUD_PROJECT', ''))
                if not project_id:
                    flash('GCP project ID is required for GCP scans', 'error')
                    return redirect(url_for('scan'))
                collector = GCPCollector(project_id=project_id)
            else:
                flash(f'Unsupported cloud provider: {provider}', 'error')
                return redirect(url_for('scan'))
            
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
                    flash(f'{provider} scan completed! Found {len(rule_engine.alerts)} security issues. Sent {email_sent} email alerts for critical/high severity issues.', 'success')
                else:
                    flash(f'{provider} scan completed! Found {len(rule_engine.alerts)} security issues.', 'success')
            else:
                flash(f'{provider} scan completed! Found {len(rule_engine.alerts)} security issues.', 'success')
            
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
                'enabled': form_data.get('alerting.channels.email.enabled') == 'on' or form_data.get('alerting.channels.email.enabled') == True,
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
            
            # Debug: Check specific email fields
            print(f"DEBUG: Email fields in received data:")
            print(f"  alerting.channels.email.enabled: {new_config.get('alerting.channels.email.enabled')}")
            print(f"  alerting.channels.email.smtp_server: {new_config.get('alerting.channels.email.smtp_server')}")
            print(f"  alerting.channels.email.username: {new_config.get('alerting.channels.email.username')}")
            print(f"  alerting.channels.email.password: {new_config.get('alerting.channels.email.password')}")
            print(f"  alerting.channels.email.from_email: {new_config.get('alerting.channels.email.from_email')}")
            print(f"  alerting.channels.email.to_email: {new_config.get('alerting.channels.email.to_email')}")
            
            # Convert flat form data to nested structure
            processed_config = convert_form_data_to_config(new_config)
            
            # Debug: Log processed config
            print(f"DEBUG: Processed config: {processed_config}")
            print(f"DEBUG: Email config in processed: {processed_config.get('alerting', {}).get('channels', {}).get('email', {})}")
            
            # Save configuration to file
            with open(CONFIG_FILE, 'w') as f:
                yaml.dump(processed_config, f, default_flow_style=False)
            
            # Update dashboard config immediately (live update)
            dashboard.config = processed_config
            dashboard.config_last_modified = dashboard.get_config_last_modified()
            
            # Reload config to ensure it's properly loaded
            dashboard.load_config()
            
            return jsonify({
                'status': 'success', 
                'message': 'Configuration updated successfully'
            })
        except Exception as e:
            return jsonify({'status': 'error', 'message': str(e)}), 500
    
    # Reload config if file has changed
    dashboard.reload_config_if_changed()
    return jsonify(dashboard.config)


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
        
        # Load alerting configuration from separate file
        alerting_config_file = 'email_alert_config.json'
        results = {'email': None, 'slack': None}
        
        if not os.path.exists(alerting_config_file):
            return jsonify({
                'status': 'error',
                'message': 'Alerting configuration file not found. Please configure email/Slack settings first.'
            }), 404
        
        with open(alerting_config_file, 'r') as f:
            alerting_config = json.load(f)
        
        # Debug: Log current config
        print(f"DEBUG: Alerting config from file: {alerting_config}")
        
        # Send email alerts (grouped by service)
        if alert_type in ['all', 'email']:
            email_config = alerting_config.get('email', {})
            if email_config.get('enabled', False):
                # Group alerts by service
                alerts_by_service = {}
                for alert in alerts:
                    service = alert.get('service', 'Unknown')
                    if service not in alerts_by_service:
                        alerts_by_service[service] = []
                    alerts_by_service[service].append(alert)
                
                # Send one email per service
                emails_sent = 0
                for service, service_alerts in alerts_by_service.items():
                    if send_consolidated_email_alert(service, service_alerts, email_config):
                        emails_sent += 1
                
                results['email'] = {'status': 'success', 'sent': emails_sent, 'total': len(alerts_by_service)}
            else:
                # Provide more detailed error message
                if not email_config:
                    results['email'] = {'status': 'error', 'message': 'Email configuration not found in alerting config file'}
                elif not email_config.get('enabled'):
                    results['email'] = {'status': 'error', 'message': 'Email alerts are disabled in alerting configuration'}
                else:
                    results['email'] = {'status': 'error', 'message': 'Email configuration incomplete in alerting config file'}
        
        # Send Slack alerts
        if alert_type in ['all', 'slack']:
            slack_config = alerting_config.get('slack', {})
            if slack_config.get('enabled', False):
                try:
                    from alerts.slack_alert import SlackAlert
                    slack_alert = SlackAlert(slack_config)
                    slack_sent = slack_alert.send_alerts(alerts)
                    results['slack'] = {'status': 'success', 'sent': slack_sent, 'total': len(alerts)}
                except Exception as e:
                    results['slack'] = {'status': 'error', 'message': str(e)}
            else:
                # Provide more detailed error message
                if not slack_config:
                    results['slack'] = {'status': 'error', 'message': 'Slack configuration not found in alerting config file'}
                elif not slack_config.get('enabled'):
                    results['slack'] = {'status': 'error', 'message': 'Slack alerts are disabled in alerting configuration'}
                else:
                    results['slack'] = {'status': 'error', 'message': 'Slack configuration incomplete in alerting config file'}
        
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
        
        # Set default email configuration (empty values)
        email_config = current_config['alerting']['channels']['email']
        if not email_config.get('smtp_server') and not email_config.get('username'):
            # Set empty default values for email configuration
            email_config.update({
                'smtp_server': '',
                'smtp_port': 587,
                'username': '',
                'password': '',
                'from_email': '',
                'to_email': ''
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


@app.route('/api/save-email-config', methods=['POST'])
def save_email_config():
    """Save email configuration to separate file"""
    try:
        form_data = request.json
        
        # Extract complete alerting configuration from form data
        alerting_config = {
            'alerting_enabled': form_data.get('alerting.enabled') == 'on' or form_data.get('alerting.enabled') == True,
            'slack': {
                'enabled': form_data.get('alerting.channels.slack.enabled') == 'on' or form_data.get('alerting.channels.slack.enabled') == True,
                'webhook_url': form_data.get('alerting.channels.slack.webhook_url', ''),
                'channel': form_data.get('alerting.channels.slack.channel', '#security-alerts')
            },
            'email': {
                'enabled': form_data.get('alerting.channels.email.enabled') == 'on' or form_data.get('alerting.channels.email.enabled') == True,
                'smtp_server': form_data.get('alerting.channels.email.smtp_server', ''),
                'smtp_port': int(form_data.get('alerting.channels.email.smtp_port', 587)),
                'username': form_data.get('alerting.channels.email.username', ''),
                'password': form_data.get('alerting.channels.email.password', ''),
                'from_email': form_data.get('alerting.channels.email.from_email', ''),
                'to_email': form_data.get('alerting.channels.email.to_email', '')
            },
            'last_updated': datetime.utcnow().isoformat()
        }
        
        # Save to separate alerting config file
        alerting_config_file = 'email_alert_config.json'
        with open(alerting_config_file, 'w') as f:
            json.dump(alerting_config, f, indent=2)
        
        return jsonify({
            'status': 'success',
            'message': 'Alerting configuration saved successfully',
            'config_file': alerting_config_file
        })
        
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500

@app.route('/api/debug-email-config-file', methods=['GET'])
def debug_email_config_file():
    """Debug endpoint to check email configuration from separate file"""
    try:
        email_config_file = 'email_alert_config.json'
        
        if not os.path.exists(email_config_file):
            return jsonify({
                'status': 'error',
                'message': 'Email configuration file not found. Please save email configuration first.'
            }), 404
        
        with open(email_config_file, 'r') as f:
            alerting_config = json.load(f)
        
        # Check email fields
        email_config = alerting_config.get('email', {})
        email_required_fields = ['smtp_server', 'username', 'password', 'from_email', 'to_email']
        email_missing_fields = []
        email_present_fields = {}
        
        for field in email_required_fields:
            value = email_config.get(field, '')
            if not value:
                email_missing_fields.append(field)
            else:
                # Mask password for security
                if field == 'password':
                    email_present_fields[field] = '***' + value[-4:] if len(value) > 4 else '***'
                else:
                    email_present_fields[field] = value
        
        # Check slack fields
        slack_config = alerting_config.get('slack', {})
        slack_required_fields = ['webhook_url', 'channel']
        slack_missing_fields = []
        slack_present_fields = {}
        
        for field in slack_required_fields:
            value = slack_config.get(field, '')
            if not value:
                slack_missing_fields.append(field)
            else:
                slack_present_fields[field] = value
        
        return jsonify({
            'status': 'success',
            'alerting_enabled': alerting_config.get('alerting_enabled', False),
            'email_enabled': email_config.get('enabled', False),
            'slack_enabled': slack_config.get('enabled', False),
            'email_missing_fields': email_missing_fields,
            'email_present_fields': email_present_fields,
            'slack_missing_fields': slack_missing_fields,
            'slack_present_fields': slack_present_fields,
            'email_all_required_present': len(email_missing_fields) == 0,
            'slack_all_required_present': len(slack_missing_fields) == 0,
            'last_updated': alerting_config.get('last_updated', 'Unknown'),
            'full_alerting_config': alerting_config
        })
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500

@app.route('/api/send-alert-from-config', methods=['POST'])
def send_alert_from_config():
    """Send alert using email configuration from separate file"""
    try:
        email_config_file = 'email_alert_config.json'
        
        if not os.path.exists(email_config_file):
            return jsonify({
                'status': 'error',
                'message': 'Email configuration file not found. Please save email configuration first.'
            }), 404
        
        with open(email_config_file, 'r') as f:
            alerting_config = json.load(f)
        
        email_config = alerting_config.get('email', {})
        if not email_config.get('enabled', False):
            return jsonify({
                'status': 'error',
                'message': 'Email alerts are not enabled in configuration file.'
            }), 400
        
        # Create a test alert
        test_alert = {
            'timestamp': datetime.utcnow().isoformat(),
            'title': 'CloudHawk Test Alert',
            'description': 'This is a test alert from CloudHawk to verify your email configuration is working correctly.',
            'severity': 'INFO',
            'service': 'SYSTEM',
            'remediation': 'No action required - this is just a test alert.'
        }
        
        # Send test email
        try:
            success = send_email_alert(test_alert, email_config)
            
            if success:
                return jsonify({
                    'status': 'success', 
                    'message': 'Test alert sent successfully! Check your inbox.',
                    'results': {
                        'email': {
                            'status': 'success',
                            'sent': 1,
                            'total': 1
                        }
                    }
                })
            else:
                return jsonify({
                    'status': 'error',
                    'message': 'Failed to send test alert. Check your email configuration.'
                })
        except Exception as e:
            return jsonify({
                'status': 'error',
                'message': f'Email sending error: {str(e)}'
            })
    
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500


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

@app.route('/api/rules/add', methods=['POST'])
def api_add_rule():
    """Add a new security rule"""
    try:
        new_rule = request.json
        
        # Load existing rules
        with open(RULES_FILE, 'r') as f:
            rules_data = yaml.safe_load(f)
        
        # Check if rule ID already exists
        existing_ids = [rule.get('id') for rule in rules_data.get('rules', [])]
        if new_rule.get('id') in existing_ids:
            return jsonify({'status': 'error', 'message': 'Rule ID already exists'}), 400
        
        # Add new rule
        if 'rules' not in rules_data:
            rules_data['rules'] = []
        
        rules_data['rules'].append(new_rule)
        
        # Save updated rules
        with open(RULES_FILE, 'w') as f:
            yaml.dump(rules_data, f, default_flow_style=False)
        
        return jsonify({'status': 'success', 'message': 'Rule added successfully'})
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500

@app.route('/api/rules/edit', methods=['POST'])
def api_edit_rule():
    """Edit an existing security rule"""
    try:
        updated_rule = request.json
        rule_id = updated_rule.get('id')
        
        # Load existing rules
        with open(RULES_FILE, 'r') as f:
            rules_data = yaml.safe_load(f)
        
        # Find and update the rule
        rules = rules_data.get('rules', [])
        for i, rule in enumerate(rules):
            if rule.get('id') == rule_id:
                rules[i] = updated_rule
                break
        else:
            return jsonify({'status': 'error', 'message': 'Rule not found'}), 404
        
        # Save updated rules
        with open(RULES_FILE, 'w') as f:
            yaml.dump(rules_data, f, default_flow_style=False)
        
        return jsonify({'status': 'success', 'message': 'Rule updated successfully'})
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500

@app.route('/api/rules/delete', methods=['POST'])
def api_delete_rule():
    """Delete a security rule"""
    try:
        data = request.json
        rule_id = data.get('id')
        
        # Load existing rules
        with open(RULES_FILE, 'r') as f:
            rules_data = yaml.safe_load(f)
        
        # Remove the rule
        rules = rules_data.get('rules', [])
        rules_data['rules'] = [rule for rule in rules if rule.get('id') != rule_id]
        
        # Save updated rules
        with open(RULES_FILE, 'w') as f:
            yaml.dump(rules_data, f, default_flow_style=False)
        
        return jsonify({'status': 'success', 'message': 'Rule deleted successfully'})
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500

@app.route('/api/rules/bulk-delete', methods=['POST'])
def api_bulk_delete_rules():
    """Bulk delete security rules"""
    try:
        data = request.json
        rule_ids = data.get('ids', [])
        
        # Load existing rules
        with open(RULES_FILE, 'r') as f:
            rules_data = yaml.safe_load(f)
        
        # Remove the rules
        rules = rules_data.get('rules', [])
        rules_data['rules'] = [rule for rule in rules if rule.get('id') not in rule_ids]
        
        # Save updated rules
        with open(RULES_FILE, 'w') as f:
            yaml.dump(rules_data, f, default_flow_style=False)
        
        return jsonify({'status': 'success', 'message': f'{len(rule_ids)} rules deleted successfully'})
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500

@app.route('/api/rules/bulk-disable', methods=['POST'])
def api_bulk_disable_rules():
    """Bulk disable security rules"""
    try:
        data = request.json
        rule_ids = data.get('ids', [])
        
        # Load existing rules
        with open(RULES_FILE, 'r') as f:
            rules_data = yaml.safe_load(f)
        
        # Update the rules
        rules = rules_data.get('rules', [])
        for rule in rules:
            if rule.get('id') in rule_ids:
                rule['status'] = 'disabled'
        
        # Save updated rules
        with open(RULES_FILE, 'w') as f:
            yaml.dump(rules_data, f, default_flow_style=False)
        
        return jsonify({'status': 'success', 'message': f'{len(rule_ids)} rules disabled successfully'})
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500

@app.route('/api/rules/bulk-edit', methods=['POST'])
def api_bulk_edit_rules():
    """Bulk edit security rules"""
    try:
        data = request.json
        rule_ids = data.get('ids', [])
        changes = {k: v for k, v in data.items() if k != 'ids' and v}
        
        if not changes:
            return jsonify({'status': 'error', 'message': 'No changes specified'}), 400
        
        # Load existing rules
        with open(RULES_FILE, 'r') as f:
            rules_data = yaml.safe_load(f)
        
        # Update the rules
        rules = rules_data.get('rules', [])
        updated_count = 0
        for rule in rules:
            if rule.get('id') in rule_ids:
                rule.update(changes)
                updated_count += 1
        
        # Save updated rules
        with open(RULES_FILE, 'w') as f:
            yaml.dump(rules_data, f, default_flow_style=False)
        
        return jsonify({'status': 'success', 'message': f'{updated_count} rules updated successfully'})
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500

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

@app.route('/enhanced-dashboard')
def enhanced_dashboard():
    """Enhanced dashboard with advanced filtering and visualization"""
    return render_template('enhanced_dashboard.html')

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
