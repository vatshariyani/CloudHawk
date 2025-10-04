#!/usr/bin/env python3
"""
CloudHawk Email Alerting Module
==============================

Sends security alerts via email using SMTP.
Supports HTML formatting, attachments, and batch sending.

Features:
- HTML and plain text email formatting
- Severity-based styling
- Batch alert sending
- Attachment support for detailed reports
- Error handling and retry logic
"""

import smtplib
import logging
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.mime.base import MIMEBase
from email import encoders
from typing import List, Dict, Any, Optional
from datetime import datetime
import json

class EmailAlerter:
    """Email alerting implementation"""
    
    def __init__(self, smtp_server: str, smtp_port: int, username: str, password: str,
                 recipients: List[str], sender_email: Optional[str] = None):
        """
        Initialize Email alerter
        
        Args:
            smtp_server: SMTP server hostname
            smtp_port: SMTP server port
            username: SMTP username
            password: SMTP password
            recipients: List of recipient email addresses
            sender_email: Sender email address (defaults to username)
        """
        self.smtp_server = smtp_server
        self.smtp_port = smtp_port
        self.username = username
        self.password = password
        self.recipients = recipients
        self.sender_email = sender_email or username
        self.logger = logging.getLogger(__name__)
        
        # Severity color mapping for HTML
        self.severity_colors = {
            'CRITICAL': '#dc3545',  # Red
            'HIGH': '#fd7e14',      # Orange
            'MEDIUM': '#ffc107',    # Yellow
            'LOW': '#28a745',       # Green
            'INFO': '#17a2b8'       # Blue
        }
    
    def send_alert(self, alert: Dict[str, Any], subject_prefix: str = "CloudHawk Security Alert") -> bool:
        """
        Send a single alert via email
        
        Args:
            alert: Alert dictionary
            subject_prefix: Email subject prefix
            
        Returns:
            bool: True if successful, False otherwise
        """
        try:
            # Create message
            msg = MIMEMultipart('alternative')
            msg['From'] = self.sender_email
            msg['To'] = ', '.join(self.recipients)
            msg['Subject'] = f"{subject_prefix}: {alert.get('title', 'Security Alert')}"
            
            # Create HTML content
            html_content = self._format_alert_html(alert)
            html_part = MIMEText(html_content, 'html')
            
            # Create plain text content
            text_content = self._format_alert_text(alert)
            text_part = MIMEText(text_content, 'plain')
            
            # Attach parts
            msg.attach(text_part)
            msg.attach(html_part)
            
            # Send email
            with smtplib.SMTP(self.smtp_server, self.smtp_port) as server:
                server.starttls()
                server.login(self.username, self.password)
                server.send_message(msg)
            
            self.logger.info(f"Alert sent via email: {alert.get('title', 'Unknown')}")
            return True
            
        except Exception as e:
            self.logger.error(f"Error sending alert via email: {e}")
            return False
    
    def send_alerts(self, alerts: List[Dict[str, Any]], 
                   severity_filter: Optional[List[str]] = None,
                   max_alerts: int = 50) -> Dict[str, Any]:
        """
        Send multiple alerts via email
        
        Args:
            alerts: List of alert dictionaries
            severity_filter: List of severities to include
            max_alerts: Maximum number of alerts to include in one email
            
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
        if alerts:
            if self.send_batch_alerts(alerts):
                results['sent'] = len(alerts)
            else:
                results['failed'] = len(alerts)
        
        return results
    
    def send_batch_alerts(self, alerts: List[Dict[str, Any]]) -> bool:
        """
        Send multiple alerts in a single email
        
        Args:
            alerts: List of alert dictionaries
            
        Returns:
            bool: True if successful, False otherwise
        """
        try:
            # Create message
            msg = MIMEMultipart('alternative')
            msg['From'] = self.sender_email
            msg['To'] = ', '.join(self.recipients)
            msg['Subject'] = f"CloudHawk Security Report - {len(alerts)} Alerts"
            
            # Create HTML content
            html_content = self._format_batch_alerts_html(alerts)
            html_part = MIMEText(html_content, 'html')
            
            # Create plain text content
            text_content = self._format_batch_alerts_text(alerts)
            text_part = MIMEText(text_content, 'plain')
            
            # Attach parts
            msg.attach(text_part)
            msg.attach(html_part)
            
            # Add JSON attachment
            json_attachment = self._create_json_attachment(alerts)
            msg.attach(json_attachment)
            
            # Send email
            with smtplib.SMTP(self.smtp_server, self.smtp_port) as server:
                server.starttls()
                server.login(self.username, self.password)
                server.send_message(msg)
            
            self.logger.info(f"Batch alerts sent via email: {len(alerts)} alerts")
            return True
            
        except Exception as e:
            self.logger.error(f"Error sending batch alerts via email: {e}")
            return False
    
    def send_summary(self, alerts: List[Dict[str, Any]]) -> bool:
        """
        Send a summary of alerts via email
        
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
            
            # Create message
            msg = MIMEMultipart('alternative')
            msg['From'] = self.sender_email
            msg['To'] = ', '.join(self.recipients)
            msg['Subject'] = f"CloudHawk Security Scan Summary - {len(alerts)} Alerts"
            
            # Create HTML content
            html_content = self._format_summary_html(alerts, severity_counts)
            html_part = MIMEText(html_content, 'html')
            
            # Create plain text content
            text_content = self._format_summary_text(alerts, severity_counts)
            text_part = MIMEText(text_content, 'plain')
            
            # Attach parts
            msg.attach(text_part)
            msg.attach(html_part)
            
            # Send email
            with smtplib.SMTP(self.smtp_server, self.smtp_port) as server:
                server.starttls()
                server.login(self.username, self.password)
                server.send_message(msg)
            
            self.logger.info("Summary sent via email successfully")
            return True
            
        except Exception as e:
            self.logger.error(f"Error sending summary via email: {e}")
            return False
    
    def _format_alert_html(self, alert: Dict[str, Any]) -> str:
        """Format alert as HTML"""
        severity = alert.get('severity', 'INFO')
        color = self.severity_colors.get(severity, '#17a2b8')
        
        html = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <meta charset="utf-8">
            <title>CloudHawk Security Alert</title>
            <style>
                body {{ font-family: Arial, sans-serif; margin: 0; padding: 20px; background-color: #f5f5f5; }}
                .container {{ max-width: 600px; margin: 0 auto; background-color: white; padding: 20px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }}
                .header {{ background-color: {color}; color: white; padding: 15px; border-radius: 4px; margin-bottom: 20px; }}
                .alert-title {{ font-size: 18px; font-weight: bold; margin: 0; }}
                .alert-details {{ margin: 20px 0; }}
                .detail-row {{ margin: 10px 0; }}
                .detail-label {{ font-weight: bold; color: #333; }}
                .detail-value {{ color: #666; }}
                .remediation {{ background-color: #e7f3ff; border-left: 4px solid #2196F3; padding: 15px; margin: 20px 0; }}
                .footer {{ margin-top: 30px; padding-top: 20px; border-top: 1px solid #eee; color: #666; font-size: 12px; }}
            </style>
        </head>
        <body>
            <div class="container">
                <div class="header">
                    <h1 class="alert-title">🦅 CloudHawk Security Alert</h1>
                </div>
                
                <div class="alert-details">
                    <div class="detail-row">
                        <span class="detail-label">Title:</span>
                        <span class="detail-value">{alert.get('title', 'Unknown')}</span>
                    </div>
                    <div class="detail-row">
                        <span class="detail-label">Severity:</span>
                        <span class="detail-value" style="color: {color}; font-weight: bold;">{severity}</span>
                    </div>
                    <div class="detail-row">
                        <span class="detail-label">Service:</span>
                        <span class="detail-value">{alert.get('service', 'UNKNOWN')}</span>
                    </div>
                    <div class="detail-row">
                        <span class="detail-label">Rule ID:</span>
                        <span class="detail-value">{alert.get('rule_id', 'N/A')}</span>
                    </div>
                    <div class="detail-row">
                        <span class="detail-label">Timestamp:</span>
                        <span class="detail-value">{alert.get('timestamp', 'N/A')}</span>
                    </div>
                    <div class="detail-row">
                        <span class="detail-label">Description:</span>
                        <span class="detail-value">{alert.get('description', 'No description available')}</span>
                    </div>
                </div>
                
                {f'<div class="remediation"><strong>Remediation:</strong><br>{alert.get("remediation")}</div>' if alert.get('remediation') else ''}
                
                <div class="footer">
                    <p>This alert was generated by CloudHawk Security Monitoring Tool.</p>
                    <p>For more information, visit: <a href="https://github.com/vatshariyani/cloudhawk">CloudHawk GitHub</a></p>
                </div>
            </div>
        </body>
        </html>
        """
        
        return html
    
    def _format_alert_text(self, alert: Dict[str, Any]) -> str:
        """Format alert as plain text"""
        text = f"""
CloudHawk Security Alert
========================

Title: {alert.get('title', 'Unknown')}
Severity: {alert.get('severity', 'UNKNOWN')}
Service: {alert.get('service', 'UNKNOWN')}
Rule ID: {alert.get('rule_id', 'N/A')}
Timestamp: {alert.get('timestamp', 'N/A')}

Description:
{alert.get('description', 'No description available')}

{f"Remediation:\n{alert.get('remediation')}" if alert.get('remediation') else ''}

---
This alert was generated by CloudHawk Security Monitoring Tool.
For more information, visit: https://github.com/vatshariyani/cloudhawk
        """
        
        return text.strip()
    
    def _format_batch_alerts_html(self, alerts: List[Dict[str, Any]]) -> str:
        """Format multiple alerts as HTML"""
        html = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <meta charset="utf-8">
            <title>CloudHawk Security Report</title>
            <style>
                body {{ font-family: Arial, sans-serif; margin: 0; padding: 20px; background-color: #f5f5f5; }}
                .container {{ max-width: 800px; margin: 0 auto; background-color: white; padding: 20px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }}
                .header {{ background-color: #2c3e50; color: white; padding: 20px; border-radius: 4px; margin-bottom: 20px; }}
                .summary {{ background-color: #ecf0f1; padding: 15px; border-radius: 4px; margin-bottom: 20px; }}
                .alert {{ border: 1px solid #ddd; border-radius: 4px; margin: 15px 0; padding: 15px; }}
                .alert-critical {{ border-left: 4px solid #dc3545; }}
                .alert-high {{ border-left: 4px solid #fd7e14; }}
                .alert-medium {{ border-left: 4px solid #ffc107; }}
                .alert-low {{ border-left: 4px solid #28a745; }}
                .alert-title {{ font-weight: bold; margin-bottom: 10px; }}
                .alert-details {{ font-size: 14px; color: #666; }}
                .footer {{ margin-top: 30px; padding-top: 20px; border-top: 1px solid #eee; color: #666; font-size: 12px; }}
            </style>
        </head>
        <body>
            <div class="container">
                <div class="header">
                    <h1>🦅 CloudHawk Security Report</h1>
                    <p>Generated on {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
                </div>
                
                <div class="summary">
                    <h3>Summary</h3>
                    <p>Total Alerts: {len(alerts)}</p>
        """
        
        # Add severity counts
        severity_counts = {}
        for alert in alerts:
            severity = alert.get('severity', 'UNKNOWN')
            severity_counts[severity] = severity_counts.get(severity, 0) + 1
        
        for severity, count in sorted(severity_counts.items()):
            color = self.severity_colors.get(severity, '#17a2b8')
            html += f'<p style="color: {color}; font-weight: bold;">{severity}: {count}</p>'
        
        html += """
                </div>
        """
        
        # Add individual alerts
        for alert in alerts:
            severity = alert.get('severity', 'INFO')
            alert_class = f"alert-{severity.lower()}"
            
            html += f"""
                <div class="alert {alert_class}">
                    <div class="alert-title">{alert.get('title', 'Unknown')}</div>
                    <div class="alert-details">
                        <strong>Severity:</strong> {severity} | 
                        <strong>Service:</strong> {alert.get('service', 'UNKNOWN')} | 
                        <strong>Rule ID:</strong> {alert.get('rule_id', 'N/A')}<br>
                        <strong>Description:</strong> {alert.get('description', 'No description available')}
                        {f'<br><strong>Remediation:</strong> {alert.get("remediation")}' if alert.get('remediation') else ''}
                    </div>
                </div>
            """
        
        html += """
                <div class="footer">
                    <p>This report was generated by CloudHawk Security Monitoring Tool.</p>
                    <p>For more information, visit: <a href="https://github.com/vatshariyani/cloudhawk">CloudHawk GitHub</a></p>
                </div>
            </div>
        </body>
        </html>
        """
        
        return html
    
    def _format_batch_alerts_text(self, alerts: List[Dict[str, Any]]) -> str:
        """Format multiple alerts as plain text"""
        text = f"""
CloudHawk Security Report
========================

Generated on: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
Total Alerts: {len(alerts)}

"""
        
        # Add severity counts
        severity_counts = {}
        for alert in alerts:
            severity = alert.get('severity', 'UNKNOWN')
            severity_counts[severity] = severity_counts.get(severity, 0) + 1
        
        text += "Summary:\n"
        for severity, count in sorted(severity_counts.items()):
            text += f"  {severity}: {count}\n"
        
        text += "\n" + "="*50 + "\n\n"
        
        # Add individual alerts
        for i, alert in enumerate(alerts, 1):
            text += f"""
Alert {i}: {alert.get('title', 'Unknown')}
Severity: {alert.get('severity', 'UNKNOWN')}
Service: {alert.get('service', 'UNKNOWN')}
Rule ID: {alert.get('rule_id', 'N/A')}
Description: {alert.get('description', 'No description available')}
{f"Remediation: {alert.get('remediation')}" if alert.get('remediation') else ''}

"""
        
        text += """
---
This report was generated by CloudHawk Security Monitoring Tool.
For more information, visit: https://github.com/vatshariyani/cloudhawk
        """
        
        return text.strip()
    
    def _format_summary_html(self, alerts: List[Dict[str, Any]], severity_counts: Dict[str, int]) -> str:
        """Format summary as HTML"""
        html = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <meta charset="utf-8">
            <title>CloudHawk Security Summary</title>
            <style>
                body {{ font-family: Arial, sans-serif; margin: 0; padding: 20px; background-color: #f5f5f5; }}
                .container {{ max-width: 600px; margin: 0 auto; background-color: white; padding: 20px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }}
                .header {{ background-color: #2c3e50; color: white; padding: 20px; border-radius: 4px; margin-bottom: 20px; }}
                .summary {{ background-color: #ecf0f1; padding: 20px; border-radius: 4px; margin-bottom: 20px; }}
                .severity-item {{ margin: 10px 0; padding: 10px; border-radius: 4px; }}
                .footer {{ margin-top: 30px; padding-top: 20px; border-top: 1px solid #eee; color: #666; font-size: 12px; }}
            </style>
        </head>
        <body>
            <div class="container">
                <div class="header">
                    <h1>🦅 CloudHawk Security Summary</h1>
                    <p>Generated on {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
                </div>
                
                <div class="summary">
                    <h3>Scan Results</h3>
                    <p><strong>Total Alerts:</strong> {len(alerts)}</p>
        """
        
        for severity, count in sorted(severity_counts.items()):
            color = self.severity_colors.get(severity, '#17a2b8')
            html += f'<div class="severity-item" style="background-color: {color}; color: white;"><strong>{severity}:</strong> {count}</div>'
        
        html += """
                </div>
                
                <div class="footer">
                    <p>This summary was generated by CloudHawk Security Monitoring Tool.</p>
                    <p>For more information, visit: <a href="https://github.com/vatshariyani/cloudhawk">CloudHawk GitHub</a></p>
                </div>
            </div>
        </body>
        </html>
        """
        
        return html
    
    def _format_summary_text(self, alerts: List[Dict[str, Any]], severity_counts: Dict[str, int]) -> str:
        """Format summary as plain text"""
        text = f"""
CloudHawk Security Summary
=========================

Generated on: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

Scan Results:
Total Alerts: {len(alerts)}

"""
        
        for severity, count in sorted(severity_counts.items()):
            text += f"{severity}: {count}\n"
        
        text += """
---
This summary was generated by CloudHawk Security Monitoring Tool.
For more information, visit: https://github.com/vatshariyani/cloudhawk
        """
        
        return text.strip()
    
    def _create_json_attachment(self, alerts: List[Dict[str, Any]]) -> MIMEBase:
        """Create JSON attachment with alerts data"""
        json_data = json.dumps(alerts, indent=2, default=str)
        
        attachment = MIMEBase('application', 'json')
        attachment.set_payload(json_data.encode('utf-8'))
        encoders.encode_base64(attachment)
        attachment.add_header(
            'Content-Disposition',
            f'attachment; filename=cloudhawk-alerts-{datetime.now().strftime("%Y%m%d-%H%M%S")}.json'
        )
        
        return attachment
    
    def test_connection(self) -> bool:
        """
        Test email connection
        
        Returns:
            bool: True if connection successful, False otherwise
        """
        try:
            with smtplib.SMTP(self.smtp_server, self.smtp_port) as server:
                server.starttls()
                server.login(self.username, self.password)
            
            self.logger.info("Email connection test successful")
            return True
            
        except Exception as e:
            self.logger.error(f"Email connection test failed: {e}")
            return False

def main():
    """Test the email alerter"""
    import argparse
    
    parser = argparse.ArgumentParser(description='Test email alerting')
    parser.add_argument('--smtp-server', required=True, help='SMTP server')
    parser.add_argument('--smtp-port', type=int, default=587, help='SMTP port')
    parser.add_argument('--username', required=True, help='SMTP username')
    parser.add_argument('--password', required=True, help='SMTP password')
    parser.add_argument('--recipients', required=True, nargs='+', help='Recipient emails')
    parser.add_argument('--test', action='store_true', help='Send test message')
    
    args = parser.parse_args()
    
    # Initialize alerter
    alerter = EmailAlerter(
        args.smtp_server, args.smtp_port, args.username, args.password, args.recipients
    )
    
    if args.test:
        # Send test message
        test_alert = {
            "title": "Test Alert",
            "description": "This is a test alert from CloudHawk",
            "severity": "INFO",
            "service": "TEST",
            "rule_id": "TEST-001",
            "timestamp": datetime.now().isoformat()
        }
        
        if alerter.send_alert(test_alert, "CloudHawk Test"):
            print("✅ Test alert sent successfully!")
        else:
            print("❌ Failed to send test alert")
    else:
        # Test connection
        if alerter.test_connection():
            print("✅ Email connection test successful!")
        else:
            print("❌ Email connection test failed")

if __name__ == '__main__':
    main()
