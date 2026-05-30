#!/usr/bin/env python3
"""CloudHawk Email Alerting Module — sends security alerts via SMTP."""

import html
import json
import logging
import smtplib
from datetime import datetime, timezone
from email import encoders
from email.mime.base import MIMEBase
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from typing import Dict, List, Any, Optional

logger = logging.getLogger(__name__)

_SEVERITY_COLORS = {
    "CRITICAL": "#dc3545",
    "HIGH": "#fd7e14",
    "MEDIUM": "#ffc107",
    "LOW": "#28a745",
    "INFO": "#17a2b8",
}

# Maximum JSON attachment size in bytes (512 KB)
_MAX_JSON_ATTACHMENT_BYTES = 512 * 1024


class EmailAlerter:
    """Send CloudHawk security alerts via SMTP."""

    def __init__(
        self,
        smtp_server: str,
        smtp_port: int,
        username: str,
        password: str,
        recipients: List[str],
        sender_email: Optional[str] = None,
    ):
        self.smtp_server = smtp_server
        self.smtp_port = int(smtp_port)
        self.username = username
        self.password = password
        self.recipients = recipients if isinstance(recipients, list) else [recipients]
        self.sender_email = sender_email or username

    # ------------------------------------------------------------------
    # SMTP connection
    # ------------------------------------------------------------------

    def _connect(self) -> smtplib.SMTP:
        """Open and authenticate an SMTP connection. Caller must close it."""
        server = smtplib.SMTP(self.smtp_server, self.smtp_port)
        server.starttls()
        server.login(self.username, self.password)
        return server

    def _send(self, msg: MIMEMultipart) -> bool:
        """Send a pre-built message, returning True on success."""
        server = None
        try:
            server = self._connect()
            server.send_message(msg)
            return True
        except smtplib.SMTPAuthenticationError as e:
            # B9 fix: differentiate error types
            logger.error(f"SMTP authentication failed: {e}")
        except smtplib.SMTPConnectError as e:
            logger.error(f"SMTP connection failed: {e}")
        except smtplib.SMTPRecipientsRefused as e:
            logger.error(f"SMTP recipients refused: {e}")
        except smtplib.SMTPException as e:
            logger.error(f"SMTP error: {e}")
        except Exception as e:
            logger.error(f"Unexpected email error: {e}")
        finally:
            if server:
                try:
                    server.quit()
                except Exception:
                    pass
        return False

    def _base_msg(self, subject: str) -> MIMEMultipart:
        msg = MIMEMultipart("alternative")
        msg["From"] = self.sender_email
        msg["To"] = ", ".join(self.recipients)
        msg["Subject"] = subject
        return msg

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def send_alert(self, alert: Dict[str, Any], subject_prefix: str = "CloudHawk Security Alert") -> bool:
        msg = self._base_msg(f"{subject_prefix}: {alert.get('title', 'Security Alert')}")
        msg.attach(MIMEText(self._alert_text(alert), "plain"))
        msg.attach(MIMEText(self._alert_html(alert), "html"))
        ok = self._send(msg)
        if ok:
            logger.info(f"Email alert sent: {alert.get('title', 'unknown')}")
        return ok

    def send_alerts(
        self,
        alerts: List[Dict[str, Any]],
        severity_filter: Optional[List[str]] = None,
        max_alerts: int = 50,
    ) -> Dict[str, Any]:
        results = {"total": len(alerts), "sent": 0, "failed": 0, "filtered": 0}

        if severity_filter:
            filtered = [a for a in alerts if a.get("severity") in severity_filter]
            results["filtered"] = len(alerts) - len(filtered)
            alerts = filtered

        if len(alerts) > max_alerts:
            logger.warning(f"Capping email batch at {max_alerts} (total: {len(alerts)})")
            alerts = alerts[:max_alerts]

        if alerts:
            if self.send_batch_alerts(alerts):
                results["sent"] = len(alerts)
            else:
                results["failed"] = len(alerts)

        return results

    def send_batch_alerts(self, alerts: List[Dict[str, Any]]) -> bool:
        msg = self._base_msg(f"CloudHawk Security Report — {len(alerts)} Alerts")
        msg.attach(MIMEText(self._batch_text(alerts), "plain"))
        msg.attach(MIMEText(self._batch_html(alerts), "html"))

        # B11 fix: only attach JSON if it fits within the size cap
        attachment = self._json_attachment(alerts)
        if attachment:
            msg.attach(attachment)

        ok = self._send(msg)
        if ok:
            logger.info(f"Batch email sent: {len(alerts)} alerts")
        return ok

    def send_summary(self, alerts: List[Dict[str, Any]]) -> bool:
        counts: Dict[str, int] = {}
        for a in alerts:
            sev = a.get("severity", "UNKNOWN")
            counts[sev] = counts.get(sev, 0) + 1

        msg = self._base_msg(f"CloudHawk Security Scan Summary — {len(alerts)} Alerts")
        msg.attach(MIMEText(self._summary_text(alerts, counts), "plain"))
        msg.attach(MIMEText(self._summary_html(alerts, counts), "html"))
        ok = self._send(msg)
        if ok:
            logger.info("Summary email sent")
        return ok

    def test_connection(self) -> bool:
        server = None
        try:
            server = self._connect()
            logger.info("Email connection test successful")
            return True
        except smtplib.SMTPAuthenticationError as e:
            logger.error(f"Email auth failed: {e}")
        except smtplib.SMTPConnectError as e:
            logger.error(f"Email connect failed: {e}")
        except Exception as e:
            logger.error(f"Email test error: {e}")
        finally:
            if server:
                try:
                    server.quit()
                except Exception:
                    pass
        return False

    # ------------------------------------------------------------------
    # Formatters — plain text
    # ------------------------------------------------------------------

    def _alert_text(self, alert: Dict[str, Any]) -> str:
        lines = [
            "CloudHawk Security Alert",
            "=" * 24,
            f"Title:       {alert.get('title', 'Unknown')}",
            f"Severity:    {alert.get('severity', 'UNKNOWN')}",
            f"Service:     {alert.get('service', 'UNKNOWN')}",
            f"Rule ID:     {alert.get('rule_id', 'N/A')}",
            f"OWASP:       {alert.get('owasp', 'N/A')}",
            f"Timestamp:   {alert.get('timestamp', 'N/A')}",
            "",
            f"Description:\n{alert.get('description', '')}",
        ]
        if alert.get("remediation"):
            lines += ["", f"Remediation:\n{alert['remediation']}"]
        lines += ["", "---", "CloudHawk Security Monitoring — https://github.com/vatshariyani/cloudhawk"]
        return "\n".join(lines)

    def _batch_text(self, alerts: List[Dict[str, Any]]) -> str:
        now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
        counts: Dict[str, int] = {}
        for a in alerts:
            sev = a.get("severity", "UNKNOWN")
            counts[sev] = counts.get(sev, 0) + 1

        lines = [
            "CloudHawk Security Report",
            "=" * 25,
            f"Generated: {now}",
            f"Total Alerts: {len(alerts)}",
            "",
            "Summary:",
        ]
        for sev, cnt in sorted(counts.items()):
            lines.append(f"  {sev}: {cnt}")
        lines.append("\n" + "=" * 50)

        for i, a in enumerate(alerts, 1):
            lines += [
                f"\nAlert {i}: {a.get('title', 'Unknown')}",
                f"  Severity:    {a.get('severity', 'UNKNOWN')}",
                f"  Service:     {a.get('service', 'UNKNOWN')}",
                f"  Rule ID:     {a.get('rule_id', 'N/A')}",
                f"  OWASP:       {a.get('owasp', 'N/A')}",
                f"  Description: {a.get('description', '')}",
            ]
            if a.get("remediation"):
                lines.append(f"  Remediation: {a['remediation']}")

        lines += ["", "---", "CloudHawk Security Monitoring — https://github.com/vatshariyani/cloudhawk"]
        return "\n".join(lines)

    def _summary_text(self, alerts: List[Dict[str, Any]], counts: Dict[str, int]) -> str:
        now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
        lines = [
            "CloudHawk Security Summary",
            "=" * 26,
            f"Generated: {now}",
            f"Total Alerts: {len(alerts)}",
            "",
        ]
        for sev, cnt in sorted(counts.items()):
            lines.append(f"{sev}: {cnt}")
        lines += ["", "---", "CloudHawk Security Monitoring — https://github.com/vatshariyani/cloudhawk"]
        return "\n".join(lines)

    # ------------------------------------------------------------------
    # Formatters — HTML (B8 fix: html.escape() on all user-controlled fields)
    # ------------------------------------------------------------------

    @staticmethod
    def _e(value: Any) -> str:
        """HTML-escape a value."""
        return html.escape(str(value) if value is not None else "")

    def _html_wrapper(self, title: str, body: str) -> str:
        return f"""<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8">
  <title>{self._e(title)}</title>
  <style>
    body{{font-family:Arial,sans-serif;margin:0;padding:20px;background:#f5f5f5}}
    .wrap{{max-width:700px;margin:0 auto;background:#fff;padding:20px;border-radius:8px;box-shadow:0 2px 4px rgba(0,0,0,.1)}}
    .hdr{{background:#2c3e50;color:#fff;padding:20px;border-radius:4px;margin-bottom:20px}}
    .hdr h1{{margin:0;font-size:20px}}
    table{{width:100%;border-collapse:collapse;margin:16px 0}}
    th,td{{text-align:left;padding:8px 12px;border-bottom:1px solid #eee}}
    th{{background:#f0f0f0;font-weight:bold}}
    .badge{{display:inline-block;padding:2px 8px;border-radius:4px;color:#fff;font-size:12px;font-weight:bold}}
    .rem{{background:#e7f3ff;border-left:4px solid #2196F3;padding:12px;margin:12px 0}}
    .ftr{{margin-top:24px;padding-top:16px;border-top:1px solid #eee;color:#888;font-size:12px}}
  </style>
</head>
<body><div class="wrap">{body}</div></body>
</html>"""

    def _severity_badge(self, severity: str) -> str:
        color = _SEVERITY_COLORS.get(severity, "#17a2b8")
        return f'<span class="badge" style="background:{color}">{self._e(severity)}</span>'

    def _alert_html(self, alert: Dict[str, Any]) -> str:
        severity = alert.get("severity", "INFO")
        color = _SEVERITY_COLORS.get(severity, "#17a2b8")
        rem = (f'<div class="rem"><strong>Remediation:</strong><br>{self._e(alert["remediation"])}</div>'
               if alert.get("remediation") else "")
        body = f"""
<div class="hdr"><h1>CloudHawk Security Alert</h1></div>
<table>
  <tr><th>Field</th><th>Value</th></tr>
  <tr><td>Title</td><td>{self._e(alert.get('title'))}</td></tr>
  <tr><td>Severity</td><td>{self._severity_badge(severity)}</td></tr>
  <tr><td>Service</td><td>{self._e(alert.get('service', 'UNKNOWN'))}</td></tr>
  <tr><td>Rule ID</td><td>{self._e(alert.get('rule_id', 'N/A'))}</td></tr>
  <tr><td>OWASP</td><td>{self._e(alert.get('owasp', 'N/A'))}</td></tr>
  <tr><td>Timestamp</td><td>{self._e(alert.get('timestamp', 'N/A'))}</td></tr>
  <tr><td>Description</td><td>{self._e(alert.get('description', ''))}</td></tr>
</table>
{rem}
<div class="ftr">CloudHawk Security Monitoring &mdash;
  <a href="https://github.com/vatshariyani/cloudhawk">GitHub</a></div>"""
        return self._html_wrapper("CloudHawk Security Alert", body)

    def _batch_html(self, alerts: List[Dict[str, Any]]) -> str:
        now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
        counts: Dict[str, int] = {}
        for a in alerts:
            sev = a.get("severity", "UNKNOWN")
            counts[sev] = counts.get(sev, 0) + 1

        summary_rows = "".join(
            f"<tr><td>{self._e(s)}</td><td>{c}</td></tr>"
            for s, c in sorted(counts.items())
        )

        alert_rows = ""
        for a in alerts:
            sev = a.get("severity", "INFO")
            rem = (f'<br><em>Remediation:</em> {self._e(a["remediation"])}' if a.get("remediation") else "")
            alert_rows += f"""
<tr>
  <td>{self._e(a.get('title', 'Unknown'))}</td>
  <td>{self._severity_badge(sev)}</td>
  <td>{self._e(a.get('service', 'UNKNOWN'))}</td>
  <td>{self._e(a.get('rule_id', 'N/A'))}</td>
  <td>{self._e(a.get('owasp', 'N/A'))}</td>
  <td>{self._e(a.get('description', ''))}{rem}</td>
</tr>"""

        body = f"""
<div class="hdr"><h1>CloudHawk Security Report</h1><p style="margin:4px 0 0">Generated {self._e(now)}</p></div>
<h3>Summary — {len(alerts)} alerts</h3>
<table>
  <tr><th>Severity</th><th>Count</th></tr>
  {summary_rows}
</table>
<h3>Alerts</h3>
<table>
  <tr><th>Title</th><th>Severity</th><th>Service</th><th>Rule ID</th><th>OWASP</th><th>Details</th></tr>
  {alert_rows}
</table>
<div class="ftr">CloudHawk Security Monitoring &mdash;
  <a href="https://github.com/vatshariyani/cloudhawk">GitHub</a></div>"""
        return self._html_wrapper("CloudHawk Security Report", body)

    def _summary_html(self, alerts: List[Dict[str, Any]], counts: Dict[str, int]) -> str:
        now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
        rows = "".join(
            f'<tr><td>{self._e(s)}</td>'
            f'<td><span class="badge" style="background:{_SEVERITY_COLORS.get(s,"#17a2b8")}">{c}</span></td></tr>'
            for s, c in sorted(counts.items())
        )
        body = f"""
<div class="hdr"><h1>CloudHawk Security Summary</h1><p style="margin:4px 0 0">Generated {self._e(now)}</p></div>
<table>
  <tr><th>Severity</th><th>Count</th></tr>
  {rows}
  <tr><td><strong>Total</strong></td><td><strong>{len(alerts)}</strong></td></tr>
</table>
<div class="ftr">CloudHawk Security Monitoring &mdash;
  <a href="https://github.com/vatshariyani/cloudhawk">GitHub</a></div>"""
        return self._html_wrapper("CloudHawk Security Summary", body)

    # ------------------------------------------------------------------
    # JSON attachment
    # ------------------------------------------------------------------

    def _json_attachment(self, alerts: List[Dict[str, Any]]) -> Optional[MIMEBase]:
        """B11 fix: skip attachment if serialised data exceeds size cap."""
        data = json.dumps(alerts, indent=2, default=str).encode("utf-8")
        if len(data) > _MAX_JSON_ATTACHMENT_BYTES:
            logger.warning(
                f"JSON attachment skipped — {len(data)} bytes exceeds "
                f"{_MAX_JSON_ATTACHMENT_BYTES} byte cap"
            )
            return None
        part = MIMEBase("application", "json")
        part.set_payload(data)
        encoders.encode_base64(part)
        part.add_header(
            "Content-Disposition",
            f'attachment; filename="cloudhawk-alerts-{datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")}.json"',
        )
        return part


if __name__ == "__main__":
    import argparse

    logging.basicConfig(level=logging.INFO)
    parser = argparse.ArgumentParser(description="Test email alerting")
    parser.add_argument("--smtp-server", required=True)
    parser.add_argument("--smtp-port", type=int, default=587)
    parser.add_argument("--username", required=True)
    parser.add_argument("--password", required=True)
    parser.add_argument("--recipients", required=True, nargs="+")
    parser.add_argument("--test", action="store_true")
    args = parser.parse_args()

    alerter = EmailAlerter(args.smtp_server, args.smtp_port, args.username, args.password, args.recipients)
    if args.test:
        ok = alerter.send_alert({
            "title": "Test Alert",
            "description": "This is a test alert from CloudHawk",
            "severity": "INFO",
            "service": "TEST",
            "rule_id": "TEST-001",
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }, "CloudHawk Test")
    else:
        ok = alerter.test_connection()
    print("OK" if ok else "FAILED")
