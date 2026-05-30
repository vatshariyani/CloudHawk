#!/usr/bin/env python3
"""CloudHawk Slack Alerting Module — sends security alerts via Slack webhooks."""

import time
import logging
from typing import Dict, List, Any, Optional, Union
from datetime import datetime, timezone

import requests

logger = logging.getLogger(__name__)

_SEVERITY_COLORS = {
    "CRITICAL": "#ff0000",
    "HIGH": "#ff8c00",
    "MEDIUM": "#ffd700",
    "LOW": "#32cd32",
    "INFO": "#87ceeb",
}

_SEVERITY_EMOJIS = {
    "CRITICAL": ":rotating_light:",
    "HIGH": ":warning:",
    "MEDIUM": ":exclamation:",
    "LOW": ":information_source:",
    "INFO": ":white_check_mark:",
}


# B1+B2 fix: class named SlackAlert (matches app.py import) and accepts either
# a config dict or individual keyword args.
class SlackAlert:
    """Send CloudHawk security alerts to a Slack channel via an incoming webhook."""

    def __init__(
        self,
        config_or_webhook: Union[Dict[str, Any], str],
        channel: str = "#security-alerts",
        username: str = "CloudHawk",
        icon_emoji: str = ":shield:",
    ):
        # Accept a config dict (as app.py passes) or a bare webhook URL string
        if isinstance(config_or_webhook, dict):
            cfg = config_or_webhook
            self.webhook_url: str = cfg.get("webhook_url", "")
            self.channel: str = cfg.get("channel", channel)
            self.username: str = cfg.get("username", username)
            self.icon_emoji: str = cfg.get("icon_emoji", icon_emoji)
        else:
            self.webhook_url = config_or_webhook
            self.channel = channel
            self.username = username
            self.icon_emoji = icon_emoji

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def send_alert(self, alert: Dict[str, Any], retries: int = 3) -> bool:
        """Send a single alert. Returns True on success."""
        # B5 fix: validate webhook URL before attempting a request
        if not self.webhook_url:
            logger.error("Slack webhook URL is not configured")
            return False

        payload = self._format_alert(alert)
        # B7 fix: retry with exponential backoff on transient failures
        for attempt in range(1, retries + 1):
            try:
                resp = requests.post(self.webhook_url, json=payload, timeout=10)
                if resp.status_code == 200:
                    logger.info(f"Slack alert sent: {alert.get('title', 'unknown')}")
                    return True
                if resp.status_code == 429:
                    # Rate limited — wait for Retry-After header or 1 s default
                    wait = int(resp.headers.get("Retry-After", 1))
                    logger.warning(f"Slack rate limited, waiting {wait}s (attempt {attempt}/{retries})")
                    time.sleep(wait)
                    continue
                logger.error(f"Slack rejected alert: {resp.status_code} {resp.text}")
                return False
            except requests.RequestException as e:
                logger.warning(f"Slack request failed (attempt {attempt}/{retries}): {e}")
                if attempt < retries:
                    time.sleep(2 ** (attempt - 1))  # 1s, 2s, 4s
        logger.error(f"Failed to send Slack alert after {retries} attempts")
        return False

    def send_alerts(
        self,
        alerts: List[Dict[str, Any]],
        severity_filter: Optional[List[str]] = None,
        max_alerts: int = 10,
    ) -> int:
        """
        Send multiple alerts. Returns count of successfully sent alerts.
        B3 fix: returns int, not dict, so callers can do `if sent_count:`.
        """
        if not self.webhook_url:
            logger.error("Slack webhook URL is not configured")
            return 0

        if severity_filter:
            alerts = [a for a in alerts if a.get("severity") in severity_filter]

        # B4 fix: capture original total before slicing for the warning
        original_count = len(alerts)
        if original_count > max_alerts:
            logger.warning(f"Capping Slack alerts at {max_alerts} (total: {original_count})")
            alerts = alerts[:max_alerts]

        sent = 0
        for alert in alerts:
            if self.send_alert(alert):
                sent += 1
            # B6 fix: respect Slack's ~1 msg/sec rate limit
            time.sleep(1)

        return sent

    def send_summary(self, alerts: List[Dict[str, Any]]) -> bool:
        """Send a scan summary block to Slack."""
        if not self.webhook_url:
            logger.error("Slack webhook URL is not configured")
            return False

        counts: Dict[str, int] = {}
        for a in alerts:
            sev = a.get("severity", "UNKNOWN")
            counts[sev] = counts.get(sev, 0) + 1

        fields = [{"title": "Total Alerts", "value": str(len(alerts)), "short": True}]
        for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
            if sev in counts:
                fields.append({"title": sev, "value": str(counts[sev]), "short": True})

        payload = {
            "channel": self.channel,
            "username": self.username,
            "icon_emoji": self.icon_emoji,
            "text": "CloudHawk Security Scan Summary",
            "attachments": [{
                "color": "#36a64f",
                "title": "Scan Results",
                "fields": fields,
                "footer": "CloudHawk Security Monitor",
                "ts": int(datetime.now(timezone.utc).timestamp()),
            }],
        }
        return self._post(payload)

    def test_connection(self) -> bool:
        """Send a test message to verify the webhook works."""
        if not self.webhook_url:
            logger.error("Slack webhook URL is not configured")
            return False

        payload = {
            "channel": self.channel,
            "username": self.username,
            "icon_emoji": self.icon_emoji,
            "text": "CloudHawk connection test successful",
            "attachments": [{
                "color": "#36a64f",
                "title": "Test Message",
                "text": "CloudHawk Slack integration is working correctly.",
                "footer": "CloudHawk Security Monitor",
                "ts": int(datetime.now(timezone.utc).timestamp()),
            }],
        }
        return self._post(payload)

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _post(self, payload: Dict[str, Any]) -> bool:
        try:
            resp = requests.post(self.webhook_url, json=payload, timeout=10)
            if resp.status_code == 200:
                return True
            logger.error(f"Slack POST failed: {resp.status_code} {resp.text}")
            return False
        except requests.RequestException as e:
            logger.error(f"Slack POST error: {e}")
            return False

    def _format_alert(self, alert: Dict[str, Any]) -> Dict[str, Any]:
        severity = alert.get("severity", "INFO")
        color = _SEVERITY_COLORS.get(severity, "#87ceeb")
        emoji = _SEVERITY_EMOJIS.get(severity, ":white_check_mark:")

        fields = [
            {"title": "Severity", "value": severity, "short": True},
            {"title": "Service", "value": alert.get("service", "UNKNOWN"), "short": True},
            {"title": "Rule ID", "value": alert.get("rule_id", "N/A"), "short": True},
            {
                "title": "Timestamp",
                "value": (alert.get("timestamp") or "N/A")[:19],
                "short": True,
            },
        ]

        if alert.get("remediation"):
            fields.append({"title": "Remediation", "value": alert["remediation"], "short": False})

        log_excerpt = alert.get("log_excerpt") or {}
        if log_excerpt.get("resource_id"):
            fields.append({
                "title": "Resource",
                "value": f"{log_excerpt['resource_id']} ({log_excerpt.get('source', 'N/A')})",
                "short": True,
            })

        return {
            "channel": self.channel,
            "username": self.username,
            "icon_emoji": self.icon_emoji,
            "text": "Security Alert Detected",
            "attachments": [{
                "color": color,
                "title": f"{emoji} {alert.get('title', 'Security Alert')}",
                "text": alert.get("description", "No description available"),
                "fields": fields,
                "footer": "CloudHawk Security Monitor",
                "ts": int(datetime.now(timezone.utc).timestamp()),
            }],
        }


# Backwards-compatible alias
SlackAlerter = SlackAlert


if __name__ == "__main__":
    import argparse

    logging.basicConfig(level=logging.INFO)
    parser = argparse.ArgumentParser(description="Test Slack alerting")
    parser.add_argument("--webhook-url", required=True)
    parser.add_argument("--channel", default="#security-alerts")
    parser.add_argument("--test", action="store_true")
    args = parser.parse_args()

    alerter = SlackAlert(args.webhook_url, channel=args.channel)
    if args.test:
        ok = alerter.test_connection()
    else:
        ok = alerter.send_alert({
            "title": "S3 Bucket with Public Access",
            "description": "S3 bucket 'test-bucket' has public ACL access",
            "severity": "CRITICAL",
            "service": "S3",
            "rule_id": "S3-ACL-001",
            "remediation": "Remove public ACL and enable public access block",
            "timestamp": datetime.now(timezone.utc).isoformat(),
        })
    print("OK" if ok else "FAILED")
