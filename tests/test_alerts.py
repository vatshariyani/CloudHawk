"""
T30: Tests for alert routing — Slack webhooks and SMTP email.
requests (Slack) and smtplib (email) are mocked, so no network/SMTP is used.
time.sleep is patched out so rate-limit pauses don't slow the suite.
"""

from unittest.mock import MagicMock, patch

import pytest

from alerts.slack_alert import SlackAlert
from alerts.email_alert import EmailAlerter


@pytest.fixture
def alerts():
    return [
        {"title": "SSH open", "severity": "CRITICAL", "service": "EC2",
         "rule_id": "EC2-SG-001", "description": "open", "timestamp": "2025-10-02T10:00:00Z"},
        {"title": "No MFA", "severity": "MEDIUM", "service": "IAM",
         "rule_id": "IAM-USER-001", "description": "no mfa", "timestamp": "2025-10-02T09:00:00Z"},
    ]


# ---------------------------------------------------------------------------
# Slack
# ---------------------------------------------------------------------------
class TestSlackAlert:
    def test_accepts_config_dict(self):
        s = SlackAlert({"webhook_url": "https://hooks.slack.com/x", "channel": "#sec"})
        assert s.webhook_url == "https://hooks.slack.com/x"
        assert s.channel == "#sec"

    def test_accepts_bare_url(self):
        s = SlackAlert("https://hooks.slack.com/y")
        assert s.webhook_url == "https://hooks.slack.com/y"

    def test_no_webhook_send_alert_false(self):
        assert SlackAlert("").send_alert({"title": "x"}) is False

    def test_no_webhook_send_alerts_zero(self, alerts):
        assert SlackAlert("").send_alerts(alerts) == 0

    @patch("alerts.slack_alert.time.sleep", lambda *_: None)
    @patch("alerts.slack_alert.requests")
    def test_send_alert_success(self, mock_requests):
        mock_requests.post.return_value = MagicMock(status_code=200)
        ok = SlackAlert("https://hooks.slack.com/x").send_alert({"title": "t", "severity": "HIGH"})
        assert ok is True
        mock_requests.post.assert_called_once()

    @patch("alerts.slack_alert.time.sleep", lambda *_: None)
    @patch("alerts.slack_alert.requests")
    def test_send_alert_rejected(self, mock_requests):
        mock_requests.post.return_value = MagicMock(status_code=400, text="bad")
        ok = SlackAlert("https://hooks.slack.com/x").send_alert({"title": "t"})
        assert ok is False

    @patch("alerts.slack_alert.time.sleep", lambda *_: None)
    @patch("alerts.slack_alert.requests")
    def test_send_alerts_counts_successes(self, mock_requests, alerts):
        mock_requests.post.return_value = MagicMock(status_code=200)
        sent = SlackAlert("https://hooks.slack.com/x").send_alerts(alerts)
        assert sent == 2

    @patch("alerts.slack_alert.time.sleep", lambda *_: None)
    @patch("alerts.slack_alert.requests")
    def test_send_alerts_severity_filter(self, mock_requests, alerts):
        mock_requests.post.return_value = MagicMock(status_code=200)
        sent = SlackAlert("https://hooks.slack.com/x").send_alerts(alerts, severity_filter=["CRITICAL"])
        assert sent == 1

    @patch("alerts.slack_alert.time.sleep", lambda *_: None)
    @patch("alerts.slack_alert.requests")
    def test_send_alerts_caps_at_max(self, mock_requests, alerts):
        mock_requests.post.return_value = MagicMock(status_code=200)
        sent = SlackAlert("https://hooks.slack.com/x").send_alerts(alerts, max_alerts=1)
        assert sent == 1

    @patch("alerts.slack_alert.time.sleep", lambda *_: None)
    @patch("alerts.slack_alert.requests")
    def test_format_includes_severity_color(self, mock_requests):
        captured = {}
        def _post(url, json=None, timeout=None):
            captured["payload"] = json
            return MagicMock(status_code=200)
        mock_requests.post.side_effect = _post
        SlackAlert("https://hooks.slack.com/x").send_alert({"title": "t", "severity": "CRITICAL"})
        color = captured["payload"]["attachments"][0]["color"]
        assert color == "#ff0000"


# ---------------------------------------------------------------------------
# Email
# ---------------------------------------------------------------------------
def _emailer():
    return EmailAlerter(
        smtp_server="smtp.example.com", smtp_port=587,
        username="user@example.com", password="pw",
        recipients=["to@example.com"],
    )


class TestEmailAlerter:
    def test_recipients_normalised_to_list(self):
        e = EmailAlerter("s", 587, "u", "p", "single@example.com")
        assert e.recipients == ["single@example.com"]

    def test_sender_defaults_to_username(self):
        assert _emailer().sender_email == "user@example.com"

    @patch("alerts.email_alert.smtplib.SMTP")
    def test_send_alert_success(self, mock_smtp):
        server = MagicMock()
        mock_smtp.return_value = server
        ok = _emailer().send_alert({"title": "t", "severity": "HIGH"})
        assert ok is True
        server.send_message.assert_called_once()
        server.starttls.assert_called_once()
        server.login.assert_called_once()

    @patch("alerts.email_alert.smtplib.SMTP")
    def test_send_alert_auth_failure_returns_false(self, mock_smtp):
        import smtplib
        server = MagicMock()
        server.login.side_effect = smtplib.SMTPAuthenticationError(535, b"bad creds")
        mock_smtp.return_value = server
        assert _emailer().send_alert({"title": "t"}) is False

    @patch("alerts.email_alert.smtplib.SMTP")
    def test_send_alerts_returns_result_dict(self, mock_smtp, alerts):
        mock_smtp.return_value = MagicMock()
        result = _emailer().send_alerts(alerts)
        assert result["total"] == 2
        assert result["sent"] == 2
        assert result["failed"] == 0

    @patch("alerts.email_alert.smtplib.SMTP")
    def test_send_alerts_severity_filter(self, mock_smtp, alerts):
        mock_smtp.return_value = MagicMock()
        result = _emailer().send_alerts(alerts, severity_filter=["CRITICAL"])
        assert result["filtered"] == 1
        assert result["sent"] == 1

    @patch("alerts.email_alert.smtplib.SMTP")
    def test_connection_closed_on_send(self, mock_smtp):
        server = MagicMock()
        mock_smtp.return_value = server
        _emailer().send_alert({"title": "t"})
        server.quit.assert_called_once()
