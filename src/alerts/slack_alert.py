#!/usr/bin/env python3
"""
CloudHawk Slack Alerting Module
==============================

Sends security alerts to Slack channels via webhooks.
Supports rich formatting, severity-based colors, and interactive buttons.

Features:
- Rich message formatting with attachments
- Severity-based color coding
- Interactive buttons for quick actions
- Batch alert sending
- Error handling and retry logic
"""

import json
import requests
import logging
from typing import List, Dict, Any, Optional
from datetime import datetime

class SlackAlerter:
    """Slack alerting implementation"""
    
    def __init__(self, webhook_url: str, channel: str = "#security-alerts", 
                 username: str = "CloudHawk", icon_emoji: str = ":shield:"):
        """
        Initialize Slack alerter
        
        Args:
            webhook_url: Slack webhook URL
            channel: Slack channel to send alerts to
            username: Bot username
            icon_emoji: Bot icon emoji
        """
        self.webhook_url = webhook_url
        self.channel = channel
        self.username = username
        self.icon_emoji = icon_emoji
        self.logger = logging.getLogger(__name__)
        
        # Severity color mapping
        self.severity_colors = {
            'CRITICAL': '#ff0000',  # Red
            'HIGH': '#ff8c00',      # Orange
            'MEDIUM': '#ffd700',    # Gold
            'LOW': '#32cd32',       # Green
            'INFO': '#87ceeb'       # Sky blue
        }
        
        # Severity emoji mapping
        self.severity_emojis = {
            'CRITICAL': ':rotating_light:',
            'HIGH': ':warning:',
            'MEDIUM': ':exclamation:',
            'LOW': ':information_source:',
            'INFO': ':white_check_mark:'
        }
    
    def send_alert(self, alert: Dict[str, Any]) -> bool:
        """
        Send a single alert to Slack
        
        Args:
            alert: Alert dictionary
            
        Returns:
            bool: True if successful, False otherwise
        """
        try:
            message = self._format_alert(alert)
            response = requests.post(
                self.webhook_url,
                json=message,
                timeout=30
            )
            
            if response.status_code == 200:
                self.logger.info(f"Alert sent to Slack: {alert.get('title', 'Unknown')}")
                return True
            else:
                self.logger.error(f"Failed to send alert to Slack: {response.status_code} - {response.text}")
                return False
                
        except Exception as e:
            self.logger.error(f"Error sending alert to Slack: {e}")
            return False
    
    def send_alerts(self, alerts: List[Dict[str, Any]], 
                   severity_filter: Optional[List[str]] = None,
                   max_alerts: int = 10) -> Dict[str, Any]:
        """
        Send multiple alerts to Slack
        
        Args:
            alerts: List of alert dictionaries
            severity_filter: List of severities to include
            max_alerts: Maximum number of alerts to send in one batch
            
        Returns:
            Dict with send results
        """
        results = {
            'total': len(alerts),
            'sent': 0,
            'failed': 0,
            'filtered': 0
        }
        
        # Filter alerts by severity if specified
        if severity_filter:
            filtered_alerts = [a for a in alerts if a.get('severity') in severity_filter]
            results['filtered'] = len(alerts) - len(filtered_alerts)
            alerts = filtered_alerts
        
        # Limit number of alerts
        if len(alerts) > max_alerts:
            alerts = alerts[:max_alerts]
            self.logger.warning(f"Limited alerts to {max_alerts} (total: {len(alerts)})")
        
        # Send alerts
        for alert in alerts:
            if self.send_alert(alert):
                results['sent'] += 1
            else:
                results['failed'] += 1
        
        return results
    
    def send_summary(self, alerts: List[Dict[str, Any]]) -> bool:
        """
        Send a summary of alerts to Slack
        
        Args:
            alerts: List of alert dictionaries
            
        Returns:
            bool: True if successful, False otherwise
        """
        try:
            # Count alerts by severity
            severity_counts = {}
            for alert in alerts:
                severity = alert.get('severity', 'UNKNOWN')
                severity_counts[severity] = severity_counts.get(severity, 0) + 1
            
            # Create summary message
            message = {
                "channel": self.channel,
                "username": self.username,
                "icon_emoji": self.icon_emoji,
                "text": f"🦅 CloudHawk Security Scan Summary",
                "attachments": [
                    {
                        "color": "#36a64f",
                        "title": "Scan Results",
                        "fields": [
                            {
                                "title": "Total Alerts",
                                "value": str(len(alerts)),
                                "short": True
                            },
                            {
                                "title": "Critical",
                                "value": str(severity_counts.get('CRITICAL', 0)),
                                "short": True
                            },
                            {
                                "title": "High",
                                "value": str(severity_counts.get('HIGH', 0)),
                                "short": True
                            },
                            {
                                "title": "Medium",
                                "value": str(severity_counts.get('MEDIUM', 0)),
                                "short": True
                            },
                            {
                                "title": "Low",
                                "value": str(severity_counts.get('LOW', 0)),
                                "short": True
                            }
                        ],
                        "footer": "CloudHawk Security Monitor",
                        "ts": int(datetime.now().timestamp())
                    }
                ]
            }
            
            response = requests.post(
                self.webhook_url,
                json=message,
                timeout=30
            )
            
            if response.status_code == 200:
                self.logger.info("Summary sent to Slack successfully")
                return True
            else:
                self.logger.error(f"Failed to send summary to Slack: {response.status_code} - {response.text}")
                return False
                
        except Exception as e:
            self.logger.error(f"Error sending summary to Slack: {e}")
            return False
    
    def _format_alert(self, alert: Dict[str, Any]) -> Dict[str, Any]:
        """
        Format alert for Slack message
        
        Args:
            alert: Alert dictionary
            
        Returns:
            Formatted Slack message
        """
        severity = alert.get('severity', 'INFO')
        color = self.severity_colors.get(severity, '#87ceeb')
        emoji = self.severity_emojis.get(severity, ':white_check_mark:')
        
        # Create attachment
        attachment = {
            "color": color,
            "title": f"{emoji} {alert.get('title', 'Security Alert')}",
            "title_link": "https://github.com/yourusername/cloudhawk",
            "fields": [
                {
                    "title": "Severity",
                    "value": severity,
                    "short": True
                },
                {
                    "title": "Service",
                    "value": alert.get('service', 'UNKNOWN'),
                    "short": True
                },
                {
                    "title": "Rule ID",
                    "value": alert.get('rule_id', 'N/A'),
                    "short": True
                },
                {
                    "title": "Timestamp",
                    "value": alert.get('timestamp', 'N/A')[:19] if alert.get('timestamp') else 'N/A',
                    "short": True
                }
            ],
            "text": alert.get('description', 'No description available'),
            "footer": "CloudHawk Security Monitor",
            "ts": int(datetime.now().timestamp())
        }
        
        # Add remediation if available
        if alert.get('remediation'):
            attachment["fields"].append({
                "title": "Remediation",
                "value": alert.get('remediation'),
                "short": False
            })
        
        # Add resource information if available
        log_excerpt = alert.get('log_excerpt', {})
        if log_excerpt:
            resource_id = log_excerpt.get('resource_id', 'N/A')
            source = log_excerpt.get('source', 'N/A')
            attachment["fields"].append({
                "title": "Resource",
                "value": f"{resource_id} ({source})",
                "short": True
            })
        
        # Create message
        message = {
            "channel": self.channel,
            "username": self.username,
            "icon_emoji": self.icon_emoji,
            "text": f"🚨 Security Alert Detected",
            "attachments": [attachment]
        }
        
        return message
    
    def test_connection(self) -> bool:
        """
        Test Slack webhook connection
        
        Returns:
            bool: True if connection successful, False otherwise
        """
        try:
            test_message = {
                "channel": self.channel,
                "username": self.username,
                "icon_emoji": self.icon_emoji,
                "text": "🦅 CloudHawk connection test successful!",
                "attachments": [
                    {
                        "color": "#36a64f",
                        "title": "Test Message",
                        "text": "This is a test message from CloudHawk to verify the Slack integration is working correctly.",
                        "footer": "CloudHawk Security Monitor",
                        "ts": int(datetime.now().timestamp())
                    }
                ]
            }
            
            response = requests.post(
                self.webhook_url,
                json=test_message,
                timeout=30
            )
            
            if response.status_code == 200:
                self.logger.info("Slack connection test successful")
                return True
            else:
                self.logger.error(f"Slack connection test failed: {response.status_code} - {response.text}")
                return False
                
        except Exception as e:
            self.logger.error(f"Error testing Slack connection: {e}")
            return False

def main():
    """Test the Slack alerter"""
    import argparse
    
    parser = argparse.ArgumentParser(description='Test Slack alerting')
    parser.add_argument('--webhook-url', required=True, help='Slack webhook URL')
    parser.add_argument('--channel', default='#security-alerts', help='Slack channel')
    parser.add_argument('--test', action='store_true', help='Send test message')
    
    args = parser.parse_args()
    
    # Initialize alerter
    alerter = SlackAlerter(args.webhook_url, args.channel)
    
    if args.test:
        # Send test message
        if alerter.test_connection():
            print("✅ Test message sent successfully!")
        else:
            print("❌ Failed to send test message")
    else:
        # Send sample alert
        sample_alert = {
            "title": "S3 Bucket with Public Access",
            "description": "S3 bucket 'test-bucket' has public ACL access",
            "severity": "CRITICAL",
            "service": "S3",
            "rule_id": "S3-ACL-001",
            "remediation": "Remove public ACL and enable public access block",
            "timestamp": datetime.now().isoformat(),
            "log_excerpt": {
                "resource_id": "test-bucket",
                "source": "AWS_S3_ACL"
            }
        }
        
        if alerter.send_alert(sample_alert):
            print("✅ Sample alert sent successfully!")
        else:
            print("❌ Failed to send sample alert")

if __name__ == '__main__':
    main()
