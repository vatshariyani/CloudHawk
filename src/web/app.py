#!/usr/bin/env python3
"""
CloudHawk Web Dashboard
Flask-based dashboard for security alerts, scanning, and configuration.
"""

import os
import json
import yaml
import logging
import smtplib
from datetime import datetime, timedelta, timezone
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from flask import Flask, render_template, jsonify, request, redirect, url_for, flash
from typing import Dict, List, Any, Optional

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

import sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from config import get_config as _global_config, reload as _reload_global_config

# B3 fix: guard collector/blueprint imports so a missing dep doesn't crash startup
try:
    from detection.rule_engine import RuleEngine
    _rule_engine_available = True
except Exception as _e:
    logger.warning(f"RuleEngine unavailable: {_e}")
    _rule_engine_available = False

try:
    from collector.aws_collector import AWSCollector
    _aws_available = True
except Exception as _e:
    logger.warning(f"AWSCollector unavailable: {_e}")
    _aws_available = False

try:
    from collector.gcp_collector import GCPCollector
    _gcp_available = True
except Exception as _e:
    logger.warning(f"GCPCollector unavailable (stubbed): {_e}")
    _gcp_available = False

try:
    from collector.azure_collector import AzureCollector
    _azure_available = True
except Exception as _e:
    logger.warning(f"AzureCollector unavailable (stubbed): {_e}")
    _azure_available = False

app = Flask(__name__)
# B1 fix: secret key from env var, never hardcoded
app.secret_key = os.environ.get("CLOUDHAWK_SECRET_KEY", os.urandom(32))

# Register API blueprints if available
try:
    from api.routes import api_bp
    from api.swagger import swagger_bp
    app.register_blueprint(api_bp)
    app.register_blueprint(swagger_bp)
except Exception as _e:
    logger.warning(f"API blueprints unavailable: {_e}")

BASE_DIR = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
CONFIG_FILE = os.path.join(BASE_DIR, "config", "config.yaml")
ALERTS_FILE = os.path.join(BASE_DIR, "src", "alerts", "alerts.json")
RULES_FILE = os.path.join(BASE_DIR, "src", "detection", "security_rules.yaml")
# B5 fix: alerting config stored under project tree, not CWD
ALERTING_CONFIG_FILE = os.path.join(BASE_DIR, "config", "alerting_config.json")


class CloudHawkDashboard:
    def __init__(self):
        self.config = self.load_config()
        self.alerts_data = self.load_alerts()
        self.config_last_modified = self._mtime(CONFIG_FILE)
        self.alerts_last_modified = self._mtime(ALERTS_FILE)

    @staticmethod
    def _mtime(path: str) -> float:
        try:
            return os.path.getmtime(path)
        except OSError:
            return 0.0

    def load_config(self) -> Dict:
        # T06: use centralised loader — missing keys always fall back to defaults
        try:
            return _reload_global_config(CONFIG_FILE)
        except Exception as e:
            logger.error(f"Error loading config: {e}")
            return self.get_default_config()

    def get_default_config(self) -> Dict:
        return {
            "aws": {
                "default_region": "us-east-1",
                "max_events_per_service": 1000,
                "services": ["ec2", "s3", "iam", "cloudtrail", "guardduty"],
            },
            "azure": {
                "subscription_id": "",
                "max_events_per_service": 1000,
                "services": ["storage", "vm", "keyvault", "security_center", "activity_log"],
            },
            "gcp": {
                "project_id": "",
                "max_events_per_service": 1000,
                "services": ["iam", "storage", "compute", "logging"],
            },
            "detection": {"rule_engine": {"threads": 4, "chunk_size": 100}},
            "alerting": {
                "enabled": False,
                "channels": {
                    "slack": {"enabled": False},
                    "email": {"enabled": False},
                },
            },
        }

    def _merge_with_defaults(self, config: Dict) -> Dict:
        """Deep-merge config onto defaults so missing top-level keys are filled in."""
        # B10 fix: merge all top-level sections, not just check for 'aws'
        result = self.get_default_config()
        for key, value in config.items():
            if key in result and isinstance(result[key], dict) and isinstance(value, dict):
                result[key].update(value)
            else:
                result[key] = value
        return result

    def load_alerts(self) -> Dict:
        try:
            if os.path.exists(ALERTS_FILE):
                with open(ALERTS_FILE, "r") as f:
                    return json.load(f)
        except Exception as e:
            logger.error(f"Error loading alerts: {e}")
        return {"alerts": [], "timestamp": None, "total_alerts": 0}

    def get_alerts_summary(self) -> Dict:
        alerts = self.alerts_data.get("alerts", [])
        summary: Dict = {"total": len(alerts), "by_severity": {}, "by_service": {}, "recent": []}

        for alert in alerts:
            sev = alert.get("severity", "UNKNOWN")
            summary["by_severity"][sev] = summary["by_severity"].get(sev, 0) + 1
            svc = alert.get("service", "UNKNOWN")
            summary["by_service"][svc] = summary["by_service"].get(svc, 0) + 1

        # B2 fix: use timezone-aware UTC now so subtraction works against ISO timestamps with offset
        now = datetime.now(timezone.utc)
        for alert in alerts:
            try:
                ts = alert.get("timestamp", "")
                if not ts:
                    continue
                alert_time = datetime.fromisoformat(ts.replace("Z", "+00:00"))
                # Make naive timestamps UTC-aware
                if alert_time.tzinfo is None:
                    alert_time = alert_time.replace(tzinfo=timezone.utc)
                if now - alert_time <= timedelta(hours=24):
                    summary["recent"].append(alert)
            except (ValueError, TypeError):
                continue

        summary["recent"] = sorted(
            summary["recent"], key=lambda x: x.get("timestamp", ""), reverse=True
        )[:10]
        return summary

    def reload_config_if_changed(self) -> bool:
        current = self._mtime(CONFIG_FILE)
        if current > self.config_last_modified:
            self.config = _reload_global_config(CONFIG_FILE)
            self.config_last_modified = current
            logger.info("Configuration reloaded")
            return True
        return False

    def reload_alerts_if_changed(self) -> bool:
        current = self._mtime(ALERTS_FILE)
        if current > self.alerts_last_modified:
            self.alerts_data = self.load_alerts()
            self.alerts_last_modified = current
            logger.info("Alerts reloaded")
            return True
        return False


dashboard = CloudHawkDashboard()


# ------------------------------------------------------------------
# Email helpers
# ------------------------------------------------------------------

def _make_smtp_connection(cfg: Dict):
    """Return an authenticated SMTP connection. Caller must close it."""
    server = smtplib.SMTP(cfg["smtp_server"], int(cfg.get("smtp_port", 587)))
    server.starttls()
    server.login(cfg["username"], cfg["password"])
    return server


def _validate_email_config(cfg: Dict) -> Optional[str]:
    required = ["smtp_server", "username", "password", "from_email", "to_email"]
    missing = [k for k in required if not cfg.get(k)]
    if missing:
        return f"Missing email config fields: {', '.join(missing)}"
    return None


def send_email_alert(alert: Dict, email_config: Dict) -> bool:
    if not email_config.get("enabled", False):
        return False
    err = _validate_email_config(email_config)
    if err:
        logger.error(err)
        return False

    msg = MIMEMultipart()
    msg["From"] = email_config["from_email"]
    msg["To"] = email_config["to_email"]
    msg["Subject"] = f"CloudHawk Security Alert: {alert.get('title', 'Security Alert')}"
    body = (
        f"CloudHawk Security Alert\n\n"
        f"Severity:    {alert.get('severity', 'UNKNOWN')}\n"
        f"Service:     {alert.get('service', 'UNKNOWN')}\n"
        f"Timestamp:   {alert.get('timestamp', '')}\n\n"
        f"Description:\n{alert.get('description', '')}\n\n"
        f"Remediation:\n{alert.get('remediation', '')}\n"
    )
    msg.attach(MIMEText(body, "plain"))

    # B6 fix: use try/finally to guarantee server.quit()
    server = None
    try:
        server = _make_smtp_connection(email_config)
        server.send_message(msg)
        logger.info(f"Email alert sent to {email_config['to_email']}")
        return True
    except smtplib.SMTPAuthenticationError as e:
        logger.error(f"SMTP auth failed: {e}")
    except smtplib.SMTPConnectError as e:
        logger.error(f"SMTP connect failed: {e}")
    except smtplib.SMTPException as e:
        logger.error(f"SMTP error: {e}")
    except Exception as e:
        logger.error(f"Email send failed: {e}")
    finally:
        if server:
            try:
                server.quit()
            except Exception:
                pass
    return False


def send_consolidated_email_alert(service: str, alerts: List[Dict], email_config: Dict) -> bool:
    if not email_config.get("enabled", False):
        return False
    err = _validate_email_config(email_config)
    if err:
        logger.error(err)
        return False

    severity_counts: Dict[str, int] = {}
    for a in alerts:
        sev = a.get("severity", "Unknown")
        severity_counts[sev] = severity_counts.get(sev, 0) + 1

    msg = MIMEMultipart()
    msg["From"] = email_config["from_email"]
    msg["To"] = email_config["to_email"]
    msg["Subject"] = f"CloudHawk Security Alert: {service} ({len(alerts)} alerts)"

    lines = [
        "CloudHawk Security Alert Summary",
        f"\nService: {service}",
        f"Total Alerts: {len(alerts)}",
        f"Severity Breakdown: {', '.join(f'{s}: {c}' for s, c in severity_counts.items())}",
        "\nAlert Details:",
    ]
    for i, a in enumerate(alerts, 1):
        lines += [
            f"\n--- Alert {i} ---",
            f"Rule ID:     {a.get('id', 'N/A')}",
            f"Title:       {a.get('title', 'Unknown')}",
            f"Severity:    {a.get('severity', 'Unknown')}",
            f"Description: {a.get('description', '')}",
            f"Timestamp:   {a.get('timestamp', '')}",
            f"Remediation: {a.get('remediation', '')}",
        ]
    lines.append(f"\nGenerated: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}")
    msg.attach(MIMEText("\n".join(lines), "plain"))

    server = None
    try:
        server = _make_smtp_connection(email_config)
        server.send_message(msg)
        logger.info(f"Consolidated email sent for {service} ({len(alerts)} alerts)")
        return True
    except smtplib.SMTPAuthenticationError as e:
        logger.error(f"SMTP auth failed (consolidated): {e}")
    except smtplib.SMTPConnectError as e:
        logger.error(f"SMTP connect failed (consolidated): {e}")
    except smtplib.SMTPException as e:
        logger.error(f"SMTP error (consolidated): {e}")
    except Exception as e:
        logger.error(f"Consolidated email failed for {service}: {e}")
    finally:
        if server:
            try:
                server.quit()
            except Exception:
                pass
    return False


# ------------------------------------------------------------------
# Health / activity helpers
# ------------------------------------------------------------------

def calculate_simple_health_score(alerts_data: Dict) -> Dict:
    alerts = alerts_data.get("alerts", [])
    if not alerts:
        empty_cats = {
            k: {"score": 100, "issues": [], "recommendations": []}
            for k in ["iam_security", "network_security", "data_security",
                      "monitoring_security", "compliance_security", "access_security"]
        }
        return {"overall_score": {"score": 100, "grade": "A"}, "category_scores": empty_cats}

    def _count(lst, sev):
        return sum(1 for a in lst if a.get("severity") == sev)

    def _score(lst):
        s = 100 - _count(lst, "CRITICAL") * 20 - _count(lst, "HIGH") * 10
        s -= _count(lst, "MEDIUM") * 5 + _count(lst, "LOW") * 2
        return max(0, s)

    overall = _score(alerts)
    grade = "A" if overall >= 90 else "B" if overall >= 80 else "C" if overall >= 70 else "D" if overall >= 60 else "F"

    category_scores: Dict = {}
    for svc in ["iam", "ec2", "s3", "cloudtrail", "guardduty", "rds"]:
        svc_alerts = [a for a in alerts if a.get("service", "").lower() == svc]
        svc_score = _score(svc_alerts)
        category_scores[f"{svc}_security"] = {
            "score": svc_score,
            "issues": [
                f"{_count(svc_alerts, 'CRITICAL')} critical",
                f"{_count(svc_alerts, 'HIGH')} high",
                f"{_count(svc_alerts, 'MEDIUM')} medium",
                f"{_count(svc_alerts, 'LOW')} low",
            ],
            "recommendations": [f"Address {svc} security issues"] if svc_alerts else [],
        }

    return {"overall_score": {"score": overall, "grade": grade}, "category_scores": category_scores}


def generate_recent_activity(alerts_data: Dict) -> List[Dict]:
    alerts = alerts_data.get("alerts", [])
    activity = []
    for a in sorted(alerts, key=lambda x: x.get("timestamp", ""), reverse=True)[:10]:
        sev = a.get("severity", "LOW")
        activity.append({
            "timestamp": a.get("timestamp", datetime.now(timezone.utc).isoformat()),
            "component": a.get("service", "Unknown"),
            "status": "error" if sev == "CRITICAL" else "warning" if sev == "HIGH" else "success",
            "message": a.get("title", "Security Alert"),
        })
    now = datetime.now(timezone.utc)
    activity += [
        {"timestamp": now.isoformat(), "component": "System", "status": "success", "message": "Health check completed"},
        {"timestamp": (now - timedelta(minutes=5)).isoformat(), "component": "AWS Collector", "status": "success", "message": "Data collection completed"},
        {"timestamp": (now - timedelta(minutes=10)).isoformat(), "component": "Rule Engine", "status": "success", "message": "Security rules processed"},
    ]
    activity.sort(key=lambda x: x["timestamp"], reverse=True)
    return activity[:10]


# ------------------------------------------------------------------
# Routes — pages
# ------------------------------------------------------------------

def _ch_data() -> Dict:
    dashboard.reload_alerts_if_changed()
    alerts = dashboard.alerts_data.get("alerts", [])
    try:
        with open(RULES_FILE) as fh:
            rules = (yaml.safe_load(fh) or {}).get("rules", [])
    except Exception:
        rules = []
    return {"alerts": alerts, "rules": rules,
            "last_scan": dashboard.alerts_data.get("timestamp", "—")}


@app.route("/")
def index():
    dashboard.reload_config_if_changed()
    dashboard.reload_alerts_if_changed()
    summary = dashboard.get_alerts_summary()
    return render_template("dashboard.html", summary=summary, config=dashboard.config,
                           ch_data=_ch_data())


@app.route("/alerts")
def alerts():
    dashboard.reload_alerts_if_changed()
    all_alerts = dashboard.alerts_data.get("alerts", [])
    severity_filter = request.args.get("severity", "")
    service_filter = request.args.get("service", "")
    filtered = [
        a for a in all_alerts
        if (not severity_filter or a.get("severity") == severity_filter)
        and (not service_filter or a.get("service") == service_filter)
    ]
    filtered.sort(key=lambda x: x.get("timestamp", ""), reverse=True)
    return render_template("alerts.html", alerts=filtered,
                           severity_filter=severity_filter, service_filter=service_filter,
                           ch_data=_ch_data())


@app.route("/timeline")
def timeline():
    dashboard.reload_alerts_if_changed()
    return render_template("timeline.html", ch_data=_ch_data())


@app.route("/compliance")
def compliance():
    dashboard.reload_alerts_if_changed()
    return render_template("compliance.html", ch_data=_ch_data())


@app.route("/scan", methods=["GET", "POST"])
def scan():
    if request.method == "POST":
        try:
            config = dashboard.config
            provider = request.form.get("provider", "AWS")
            region = request.form.get("region", config.get("aws", {}).get("default_region", "us-east-1"))
            max_events = int(request.form.get("max_events", config.get("aws", {}).get("max_events_per_service", 1000)))

            if provider == "AWS":
                if not _aws_available:
                    flash("AWS collector is not available", "error")
                    return redirect(url_for("scan"))
                collector = AWSCollector(region=region, max_events=max_events)
            elif provider == "Azure":
                if not _azure_available:
                    flash("Azure collector is not yet implemented", "error")
                    return redirect(url_for("scan"))
                subscription_id = request.form.get("subscription_id", os.getenv("AZURE_SUBSCRIPTION_ID", ""))
                if not subscription_id:
                    flash("Azure subscription ID is required", "error")
                    return redirect(url_for("scan"))
                collector = AzureCollector(subscription_id=subscription_id)
            elif provider == "GCP":
                if not _gcp_available:
                    flash("GCP collector is not yet implemented", "error")
                    return redirect(url_for("scan"))
                project_id = request.form.get("project_id", os.getenv("GOOGLE_CLOUD_PROJECT", ""))
                if not project_id:
                    flash("GCP project ID is required", "error")
                    return redirect(url_for("scan"))
                collector = GCPCollector(project_id=project_id)
            else:
                flash(f"Unsupported provider: {provider}", "error")
                return redirect(url_for("scan"))

            flash(f"Starting {provider} security scan...", "info")
            security_events = collector.collect_all_security_data()
            events_file = collector.save_security_events(security_events)

            # B11 fix: guard RuleEngine availability and attribute access
            num_alerts = 0
            if _rule_engine_available:
                rule_engine = RuleEngine(RULES_FILE, events_file, threads=4, chunk_size=100)
                rule_engine.run()
                num_alerts = len(getattr(rule_engine, "alerts", []))
                dashboard.alerts_data = dashboard.load_alerts()

                email_config = config.get("alerting", {}).get("channels", {}).get("email", {})
                if email_config.get("enabled", False):
                    critical_alerts = [a for a in getattr(rule_engine, "alerts", [])
                                       if a.get("severity") in ("CRITICAL", "HIGH")]
                    sent = sum(1 for a in critical_alerts if send_email_alert(a, email_config))
                    if sent:
                        flash(f"Sent {sent} email alerts for critical/high findings.", "info")

                slack_config = config.get("alerting", {}).get("channels", {}).get("slack", {})
                if slack_config.get("enabled", False):
                    try:
                        from alerts.slack_alert import SlackAlert
                        slack = SlackAlert(slack_config)
                        sent_slack = slack.send_alerts(
                            [a for a in getattr(rule_engine, "alerts", [])
                             if a.get("severity") in ("CRITICAL", "HIGH")]
                        )
                        if sent_slack:
                            flash(f"Sent {sent_slack} Slack alerts.", "info")
                    except Exception as e:
                        flash(f"Slack alerts failed: {e}", "warning")

            flash(f"{provider} scan completed — {num_alerts} security issues found.", "success")
        except Exception as e:
            logger.exception("Scan failed")
            flash(f"Scan failed: {e}", "error")
        return redirect(url_for("scan"))

    return render_template("scan.html", config=dashboard.config)


@app.route("/config")
def config():
    dashboard.reload_config_if_changed()
    return render_template("config.html", config=dashboard.config)


@app.route("/rules")
def rules():
    try:
        with open(RULES_FILE, "r") as f:
            rules_data = yaml.safe_load(f) or {}
        rule_list = rules_data.get("rules", [])
    except Exception as e:
        rule_list = []
        flash(f"Error loading rules: {e}", "error")
    return render_template("rules.html", rules=rule_list, ch_data=_ch_data())



# ------------------------------------------------------------------
# Routes — API
# ------------------------------------------------------------------

@app.route("/api/compliance/report")
def api_compliance_report():
    framework = request.args.get("framework")  # optional: CIS | SOC2 | ISO27001
    try:
        from compliance.compliance_engine import ComplianceEngine
        engine = ComplianceEngine()
        dashboard.reload_alerts_if_changed()
        alerts = dashboard.alerts_data.get("alerts", [])
        report = engine.assess(alerts, framework_id=framework or None)
        return jsonify(report)
    except Exception as e:
        logger.exception("Compliance report failed")
        return jsonify({"error": str(e)}), 500


@app.route("/api/alerts/status", methods=["POST"])
def api_alert_status():
    data = request.get_json(force=True) or {}
    status = (data.get("status") or "").upper()
    if status not in ("OPEN", "ACKNOWLEDGED", "RESOLVED"):
        return jsonify({"status": "error", "message": "invalid status"}), 400
    keys = {(i.get("rule_id"), i.get("resource_id"), i.get("timestamp"))
            for i in data.get("alerts", [])}
    for a in dashboard.alerts_data.get("alerts", []):
        log = a.get("log_excerpt", {}) or {}
        rid = a.get("resource_id") or log.get("resource_id")
        if (a.get("rule_id"), rid, a.get("timestamp")) in keys:
            a["status"] = status
    with open(ALERTS_FILE, "w") as fh:
        json.dump(dashboard.alerts_data, fh, indent=2, default=str)
    dashboard.alerts_last_modified = dashboard._mtime(ALERTS_FILE)
    return jsonify({"status": "success"})


@app.route("/api/alerts")
def api_alerts():
    return jsonify(dashboard.alerts_data)


@app.route("/api/summary")
def api_summary():
    return jsonify(dashboard.get_alerts_summary())


@app.route("/health")
def health():
    return jsonify({"status": "healthy", "timestamp": datetime.now(timezone.utc).isoformat(), "version": "1.0.0"})


@app.route("/api/health")
def api_health():
    try:
        alerts_data = dashboard.load_alerts()
        alerts = alerts_data.get("alerts", [])

        events_count = 0
        events_file = os.path.join(BASE_DIR, "src", "logs", "aws_security_events_latest.json")
        if os.path.exists(events_file):
            try:
                with open(events_file, "r") as f:
                    data = json.load(f)
                events_count = len(data) if isinstance(data, list) else len(data.get("events", []))
            except (json.JSONDecodeError, OSError):
                pass

        rules_count = 0
        if os.path.exists(RULES_FILE):
            try:
                with open(RULES_FILE, "r") as f:
                    rd = yaml.safe_load(f) or {}
                rules_count = len(rd.get("rules", rd) if isinstance(rd, dict) else rd)
            except Exception:
                pass

        return jsonify({
            "system_status": "healthy",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "version": "1.0.0",
            "health_score": calculate_simple_health_score(alerts_data),
            "summary": {
                "critical_issues": sum(1 for a in alerts if a.get("severity") == "CRITICAL"),
                "high_issues": sum(1 for a in alerts if a.get("severity") == "HIGH"),
                "medium_issues": sum(1 for a in alerts if a.get("severity") == "MEDIUM"),
                "low_issues": sum(1 for a in alerts if a.get("severity") == "LOW"),
            },
            "events_count": events_count,
            "alerts_count": len(alerts),
            "rules_count": rules_count,
            "recent_activity": generate_recent_activity(alerts_data),
        })
    except Exception as e:
        logger.exception("Health API error")
        return jsonify({"system_status": "error", "timestamp": datetime.now(timezone.utc).isoformat(),
                        "version": "1.0.0", "error": str(e)}), 500


@app.route("/api/config", methods=["GET", "POST"])
def api_config():
    if request.method == "POST":
        try:
            form_data = request.get_json(force=True) or {}
            processed = _build_config_from_form(form_data)
            os.makedirs(os.path.dirname(CONFIG_FILE), exist_ok=True)
            with open(CONFIG_FILE, "w") as f:
                yaml.dump(processed, f, default_flow_style=False)
            # B8 fix: assign return value
            dashboard.config = dashboard.load_config()
            dashboard.config_last_modified = dashboard._mtime(CONFIG_FILE)
            return jsonify({"status": "success", "message": "Configuration updated successfully"})
        except Exception as e:
            logger.exception("Config save failed")
            return jsonify({"status": "error", "message": str(e)}), 500

    dashboard.reload_config_if_changed()
    return jsonify(dashboard.config)


def _build_config_from_form(form_data: Dict) -> Dict:
    """
    B7 fix: build config by starting with defaults, overlaying saved file,
    then overlaying the submitted form values — form always wins.
    """
    # Start with defaults
    result = dashboard.get_default_config()

    # Overlay existing saved config
    if os.path.exists(CONFIG_FILE):
        try:
            with open(CONFIG_FILE, "r") as f:
                saved = yaml.safe_load(f) or {}
            result = dashboard._merge_with_defaults(saved)
        except Exception as e:
            logger.warning(f"Could not read existing config for merge: {e}")

    # Overlay alerting values from the submitted form (form values win)
    def _bool(val) -> bool:
        if isinstance(val, bool):
            return val
        return str(val).lower() in ("on", "true", "1", "yes")

    result["alerting"] = {
        "enabled": _bool(form_data.get("alerting.enabled", False)),
        "channels": {
            "slack": {
                "enabled": _bool(form_data.get("alerting.channels.slack.enabled", False)),
                "webhook_url": form_data.get("alerting.channels.slack.webhook_url", ""),
                "channel": form_data.get("alerting.channels.slack.channel", "#security-alerts"),
            },
            "email": {
                "enabled": _bool(form_data.get("alerting.channels.email.enabled", False)),
                "smtp_server": form_data.get("alerting.channels.email.smtp_server", ""),
                "smtp_port": int(form_data.get("alerting.channels.email.smtp_port", 587) or 587),
                "username": form_data.get("alerting.channels.email.username", ""),
                "password": form_data.get("alerting.channels.email.password", ""),
                "from_email": form_data.get("alerting.channels.email.from_email", ""),
                "to_email": form_data.get("alerting.channels.email.to_email", ""),
            },
        },
    }
    return result


@app.route("/api/save-email-config", methods=["POST"])
def save_email_config():
    try:
        form_data = request.get_json(force=True) or {}

        def _bool(val) -> bool:
            if isinstance(val, bool):
                return val
            return str(val).lower() in ("on", "true", "1", "yes")

        alerting_config = {
            "alerting_enabled": _bool(form_data.get("alerting.enabled", False)),
            "slack": {
                "enabled": _bool(form_data.get("alerting.channels.slack.enabled", False)),
                "webhook_url": form_data.get("alerting.channels.slack.webhook_url", ""),
                "channel": form_data.get("alerting.channels.slack.channel", "#security-alerts"),
            },
            "email": {
                "enabled": _bool(form_data.get("alerting.channels.email.enabled", False)),
                "smtp_server": form_data.get("alerting.channels.email.smtp_server", ""),
                "smtp_port": int(form_data.get("alerting.channels.email.smtp_port", 587) or 587),
                "username": form_data.get("alerting.channels.email.username", ""),
                "password": form_data.get("alerting.channels.email.password", ""),
                "from_email": form_data.get("alerting.channels.email.from_email", ""),
                "to_email": form_data.get("alerting.channels.email.to_email", ""),
            },
            "last_updated": datetime.now(timezone.utc).isoformat(),
        }
        os.makedirs(os.path.dirname(ALERTING_CONFIG_FILE), exist_ok=True)
        with open(ALERTING_CONFIG_FILE, "w") as f:
            json.dump(alerting_config, f, indent=2)
        return jsonify({"status": "success", "message": "Alerting configuration saved"})
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500


@app.route("/api/send-alerts", methods=["POST"])
def send_alerts():
    try:
        data = request.get_json(force=True) or {}
        alert_type = data.get("type", "all")

        alerts_data = dashboard.load_alerts()
        alerts = alerts_data.get("alerts", [])
        if not alerts:
            return jsonify({"status": "error", "message": "No alerts to send"}), 400

        if not os.path.exists(ALERTING_CONFIG_FILE):
            return jsonify({"status": "error", "message": "Alerting config not found. Save config first."}), 404

        with open(ALERTING_CONFIG_FILE, "r") as f:
            alerting_config = json.load(f)

        results: Dict = {"email": None, "slack": None}

        if alert_type in ("all", "email"):
            email_cfg = alerting_config.get("email", {})
            if email_cfg.get("enabled", False):
                by_service: Dict[str, List] = {}
                for a in alerts:
                    by_service.setdefault(a.get("service", "Unknown"), []).append(a)
                sent = sum(1 for svc, svc_alerts in by_service.items()
                           if send_consolidated_email_alert(svc, svc_alerts, email_cfg))
                results["email"] = {"status": "success", "sent": sent, "total": len(by_service)}
            else:
                results["email"] = {"status": "error", "message": "Email alerts disabled in config"}

        if alert_type in ("all", "slack"):
            slack_cfg = alerting_config.get("slack", {})
            if slack_cfg.get("enabled", False):
                try:
                    from alerts.slack_alert import SlackAlert
                    sent_slack = SlackAlert(slack_cfg).send_alerts(alerts)
                    results["slack"] = {"status": "success", "sent": sent_slack, "total": len(alerts)}
                except Exception as e:
                    results["slack"] = {"status": "error", "message": str(e)}
            else:
                results["slack"] = {"status": "error", "message": "Slack alerts disabled in config"}

        return jsonify({"status": "success", "results": results})
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500


@app.route("/api/send-alert-from-config", methods=["POST"])
def send_alert_from_config():
    try:
        if not os.path.exists(ALERTING_CONFIG_FILE):
            return jsonify({"status": "error", "message": "Alerting config not found. Save config first."}), 404
        with open(ALERTING_CONFIG_FILE, "r") as f:
            alerting_config = json.load(f)
        email_cfg = alerting_config.get("email", {})
        if not email_cfg.get("enabled", False):
            return jsonify({"status": "error", "message": "Email alerts are not enabled."}), 400

        test_alert = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "title": "CloudHawk Test Alert",
            "description": "Test alert verifying email configuration.",
            "severity": "INFO",
            "service": "SYSTEM",
            "remediation": "No action required.",
        }
        if send_email_alert(test_alert, email_cfg):
            return jsonify({"status": "success", "message": "Test alert sent. Check your inbox."})
        return jsonify({"status": "error", "message": "Failed to send test alert. Check email config."})
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500


@app.route("/api/send-notification", methods=["POST"])
def send_notification():
    try:
        data = request.get_json(force=True) or {}
        notification_type = data.get("type", "rules_changed")
        message = data.get("message", "Security rules have been updated")
        dashboard.reload_config_if_changed()
        email_cfg = dashboard.config.get("alerting", {}).get("channels", {}).get("email", {})
        if not email_cfg.get("enabled", False):
            return jsonify({"status": "error", "message": "Email not configured"}), 400
        alert = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "title": notification_type.replace("_", " ").title(),
            "description": message,
            "severity": "INFO",
            "service": "SYSTEM",
            "remediation": "Review the changes.",
        }
        if send_email_alert(alert, email_cfg):
            return jsonify({"status": "success", "message": "Notification sent"})
        return jsonify({"status": "error", "message": "Failed to send notification"})
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500


@app.route("/api/rules", methods=["GET", "POST"])
def api_rules():
    if request.method == "POST":
        try:
            new_rules = request.get_json(force=True)
            with open(RULES_FILE, "w") as f:
                yaml.dump(new_rules, f, default_flow_style=False)
            return jsonify({"status": "success"})
        except Exception as e:
            return jsonify({"status": "error", "message": str(e)}), 500
    try:
        with open(RULES_FILE, "r") as f:
            return jsonify(yaml.safe_load(f) or {})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


def _load_rules_data() -> Dict:
    with open(RULES_FILE, "r") as f:
        return yaml.safe_load(f) or {"rules": []}


def _save_rules_data(data: Dict) -> None:
    with open(RULES_FILE, "w") as f:
        yaml.dump(data, f, default_flow_style=False)


@app.route("/api/rules/add", methods=["POST"])
def api_add_rule():
    try:
        new_rule = request.get_json(force=True) or {}
        data = _load_rules_data()
        if new_rule.get("id") in {r.get("id") for r in data.get("rules", [])}:
            return jsonify({"status": "error", "message": "Rule ID already exists"}), 400
        data.setdefault("rules", []).append(new_rule)
        _save_rules_data(data)
        return jsonify({"status": "success", "message": "Rule added"})
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500


@app.route("/api/rules/edit", methods=["POST"])
def api_edit_rule():
    try:
        updated = request.get_json(force=True) or {}
        rule_id = updated.get("id")
        data = _load_rules_data()
        rules = data.get("rules", [])
        for i, r in enumerate(rules):
            if r.get("id") == rule_id:
                rules[i] = updated
                break
        else:
            return jsonify({"status": "error", "message": "Rule not found"}), 404
        _save_rules_data(data)
        return jsonify({"status": "success", "message": "Rule updated"})
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500


@app.route("/api/rules/delete", methods=["POST"])
def api_delete_rule():
    try:
        rule_id = (request.get_json(force=True) or {}).get("id")
        data = _load_rules_data()
        data["rules"] = [r for r in data.get("rules", []) if r.get("id") != rule_id]
        _save_rules_data(data)
        return jsonify({"status": "success", "message": "Rule deleted"})
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500


@app.route("/api/rules/bulk-delete", methods=["POST"])
def api_bulk_delete_rules():
    try:
        ids = set((request.get_json(force=True) or {}).get("ids", []))
        data = _load_rules_data()
        data["rules"] = [r for r in data.get("rules", []) if r.get("id") not in ids]
        _save_rules_data(data)
        return jsonify({"status": "success", "message": f"{len(ids)} rules deleted"})
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500


@app.route("/api/rules/bulk-disable", methods=["POST"])
def api_bulk_disable_rules():
    try:
        ids = set((request.get_json(force=True) or {}).get("ids", []))
        data = _load_rules_data()
        for r in data.get("rules", []):
            if r.get("id") in ids:
                r["status"] = "disabled"
        _save_rules_data(data)
        return jsonify({"status": "success", "message": f"{len(ids)} rules disabled"})
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500


@app.route("/api/rules/bulk-edit", methods=["POST"])
def api_bulk_edit_rules():
    try:
        body = request.get_json(force=True) or {}
        ids = set(body.get("ids", []))
        changes = {k: v for k, v in body.items() if k != "ids" and v}
        if not changes:
            return jsonify({"status": "error", "message": "No changes specified"}), 400
        data = _load_rules_data()
        count = 0
        for r in data.get("rules", []):
            if r.get("id") in ids:
                r.update(changes)
                count += 1
        _save_rules_data(data)
        return jsonify({"status": "success", "message": f"{count} rules updated"})
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500


# ------------------------------------------------------------------
# Error handlers
# ------------------------------------------------------------------

@app.errorhandler(404)
def not_found(error):
    return render_template("404.html"), 404


@app.errorhandler(500)
def internal_error(error):
    return render_template("500.html"), 500


# ------------------------------------------------------------------
# Entry point
# ------------------------------------------------------------------

if __name__ == "__main__":
    os.makedirs(os.path.join(os.path.dirname(__file__), "templates"), exist_ok=True)
    os.makedirs(os.path.join(os.path.dirname(__file__), "static"), exist_ok=True)
    print("CloudHawk Web Dashboard — http://localhost:5000")
    app.run(host="0.0.0.0", port=5000, debug=os.getenv("FLASK_DEBUG", "0") == "1")
