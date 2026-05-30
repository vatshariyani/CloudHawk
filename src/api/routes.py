"""
CloudHawk REST API — /api/v1/ blueprint

Endpoints
---------
GET  /api/v1/health
POST /api/v1/auth/token
POST /api/v1/auth/api-key        (admin)
GET  /api/v1/scans
POST /api/v1/scans
GET  /api/v1/scans/<scan_id>
GET  /api/v1/alerts              (paginated, filterable)
GET  /api/v1/alerts/<alert_id>
GET  /api/v1/rules
POST /api/v1/rules               (write)
GET  /api/v1/stats
"""

import json
import logging
import os
import secrets
from datetime import datetime

import yaml
from flask import Blueprint, jsonify, request

from .auth import auth_manager, rate_limit, require_admin, require_auth

logger = logging.getLogger(__name__)

api_bp = Blueprint("api", __name__, url_prefix="/api/v1")

BASE_DIR = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
RULES_FILE = os.path.join(BASE_DIR, "src", "detection", "security_rules.yaml")
ALERTS_FILE = os.path.join(BASE_DIR, "src", "alerts", "alerts.json")
LOGS_DIR = os.path.join(BASE_DIR, "logs")


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _load_alerts():
    if not os.path.exists(ALERTS_FILE):
        return []
    with open(ALERTS_FILE) as fh:
        data = json.load(fh)
    return data.get("alerts", []) if isinstance(data, dict) else data


def _parse_int(value, default: int, min_val: int = 0, max_val: int = 10_000) -> int:
    try:
        return max(min_val, min(max_val, int(value)))
    except (TypeError, ValueError):
        return default


# ---------------------------------------------------------------------------
# Health
# ---------------------------------------------------------------------------

@api_bp.route("/health", methods=["GET"])
@rate_limit(requests_per_minute=120)
def api_health():
    return jsonify({
        "status": "healthy",
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "version": "1.0.0",
        "services": {"api": "operational", "rule_engine": "operational"},
    })


# ---------------------------------------------------------------------------
# Auth
# ---------------------------------------------------------------------------

@api_bp.route("/auth/token", methods=["POST"])
@rate_limit(requests_per_minute=10)
def generate_token():
    data = request.get_json(silent=True) or {}
    user_id = data.get("user_id")
    if not user_id:
        return jsonify({"error": "user_id is required"}), 400
    permissions = data.get("permissions", ["read"])
    token = auth_manager.generate_jwt_token(user_id, permissions)
    return jsonify({"token": token, "expires_in": 86400, "permissions": permissions})


@api_bp.route("/auth/api-key", methods=["POST"])
@require_admin
@rate_limit(requests_per_minute=5)
def generate_api_key():
    data = request.get_json(silent=True) or {}
    name = data.get("name", "api-key")
    permissions = data.get("permissions", ["read"])
    api_key = auth_manager.generate_api_key(name, permissions)
    return jsonify({
        "api_key": api_key,
        "name": name,
        "permissions": permissions,
        "created_at": datetime.utcnow().isoformat() + "Z",
    })


# ---------------------------------------------------------------------------
# Scans
# ---------------------------------------------------------------------------

@api_bp.route("/scans", methods=["GET"])
@require_auth("read")
@rate_limit(requests_per_minute=60)
def list_scans():
    scans = []
    if os.path.exists(LOGS_DIR):
        for filename in os.listdir(LOGS_DIR):
            if not filename.endswith(".json"):
                continue
            filepath = os.path.join(LOGS_DIR, filename)
            stat = os.stat(filepath)
            scans.append({
                "id": filename[:-5],
                "filename": filename,
                "created_at": datetime.utcfromtimestamp(stat.st_ctime).isoformat() + "Z",
                "size_bytes": stat.st_size,
            })
    scans.sort(key=lambda x: x["created_at"], reverse=True)
    return jsonify({"scans": scans, "total": len(scans)})


@api_bp.route("/scans", methods=["POST"])
@require_auth("write")
@rate_limit(requests_per_minute=10)
def create_scan():
    """Trigger a live cloud scan and return the summary."""
    import sys
    sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
    from config import get_config

    data = request.get_json(silent=True) or {}
    provider = (data.get("cloud_provider") or "").upper()
    if provider not in ("AWS", "GCP", "AZURE"):
        return jsonify({"error": "cloud_provider must be one of: AWS, GCP, Azure"}), 400

    cfg = get_config()
    max_events = _parse_int(data.get("max_events"), 1000, 1, 10_000)

    try:
        if provider == "AWS":
            from collector.aws_collector import AWSCollector
            region = data.get("region") or cfg["aws"]["default_region"]
            collector = AWSCollector(region=region, max_events=max_events)
        elif provider == "GCP":
            project_id = data.get("project_id") or cfg["gcp"].get("project_id", "")
            if not project_id:
                return jsonify({"error": "project_id is required for GCP scans"}), 400
            from collector.gcp_collector import GCPCollector
            scan_cfg = dict(cfg)
            scan_cfg["gcp"] = dict(cfg.get("gcp", {}))
            scan_cfg["gcp"]["project_id"] = project_id
            scan_cfg["gcp"]["max_events_per_service"] = max_events
            collector = GCPCollector(scan_cfg)
        else:  # AZURE
            sub_id = data.get("subscription_id") or cfg["azure"].get("subscription_id", "")
            if not sub_id:
                return jsonify({"error": "subscription_id is required for Azure scans"}), 400
            from collector.azure_collector import AzureCollector
            scan_cfg = dict(cfg)
            scan_cfg["azure"] = dict(cfg.get("azure", {}))
            scan_cfg["azure"]["subscription_id"] = sub_id
            scan_cfg["azure"]["max_events_per_service"] = max_events
            collector = AzureCollector(scan_cfg)

        events = collector.collect_all()

        # Persist events
        os.makedirs(LOGS_DIR, exist_ok=True)
        ts = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
        out_file = os.path.join(LOGS_DIR, f"{provider.lower()}_events_{ts}.json")
        with open(out_file, "w") as fh:
            json.dump(events, fh, indent=2, default=str)

        scan_id = os.path.basename(out_file)[:-5]
        return jsonify({
            "scan_id": scan_id,
            "cloud_provider": provider,
            "events_collected": len(events),
            "status": "completed",
            "created_at": datetime.utcnow().isoformat() + "Z",
            "events_file": out_file,
        }), 201

    except Exception as exc:
        logger.error("Scan failed: %s", exc)
        return jsonify({"error": f"Scan failed: {exc}"}), 500


@api_bp.route("/scans/<scan_id>", methods=["GET"])
@require_auth("read")
@rate_limit(requests_per_minute=60)
def get_scan(scan_id):
    if not os.path.exists(LOGS_DIR):
        return jsonify({"error": "Scan not found"}), 404

    scan_file = None
    for filename in os.listdir(LOGS_DIR):
        if filename.startswith(scan_id) and filename.endswith(".json"):
            scan_file = os.path.join(LOGS_DIR, filename)
            break

    if not scan_file:
        return jsonify({"error": "Scan not found"}), 404

    with open(scan_file) as fh:
        events = json.load(fh)

    severity_counts: dict = {}
    source_counts: dict = {}
    for ev in events:
        sev = ev.get("severity", "UNKNOWN")
        src = ev.get("source", "UNKNOWN")
        severity_counts[sev] = severity_counts.get(sev, 0) + 1
        source_counts[src] = source_counts.get(src, 0) + 1

    limit = _parse_int(request.args.get("limit"), 100, 1, 1000)
    offset = _parse_int(request.args.get("offset"), 0)

    return jsonify({
        "scan_id": scan_id,
        "total_events": len(events),
        "severity_breakdown": severity_counts,
        "source_breakdown": source_counts,
        "created_at": datetime.utcfromtimestamp(os.path.getctime(scan_file)).isoformat() + "Z",
        "events": events[offset: offset + limit],
        "limit": limit,
        "offset": offset,
        "has_more": offset + limit < len(events),
    })


# ---------------------------------------------------------------------------
# Alerts  (T19 — paginated)
# ---------------------------------------------------------------------------

@api_bp.route("/alerts", methods=["GET"])
@require_auth("read")
@rate_limit(requests_per_minute=60)
def get_alerts():
    alerts = _load_alerts()

    severity = request.args.get("severity", "").upper() or None
    service = request.args.get("service") or None
    source = request.args.get("source") or None
    cloud = request.args.get("cloud") or None
    limit = _parse_int(request.args.get("limit"), 100, 1, 1000)
    offset = _parse_int(request.args.get("offset"), 0)

    if severity:
        alerts = [a for a in alerts if a.get("severity", "").upper() == severity]
    if service:
        alerts = [a for a in alerts if a.get("service") == service]
    if source:
        alerts = [a for a in alerts if a.get("source") == source]
    if cloud:
        alerts = [a for a in alerts if a.get("cloud") == cloud]

    total = len(alerts)
    page = alerts[offset: offset + limit]

    return jsonify({
        "alerts": page,
        "total": total,
        "limit": limit,
        "offset": offset,
        "has_more": offset + limit < total,
    })


@api_bp.route("/alerts/<alert_id>", methods=["GET"])
@require_auth("read")
@rate_limit(requests_per_minute=60)
def get_alert(alert_id):
    for alert in _load_alerts():
        if str(alert.get("id")) == alert_id:
            return jsonify(alert)
    return jsonify({"error": "Alert not found"}), 404


# ---------------------------------------------------------------------------
# Rules
# ---------------------------------------------------------------------------

@api_bp.route("/rules", methods=["GET"])
@require_auth("read")
@rate_limit(requests_per_minute=60)
def get_rules():
    if not os.path.exists(RULES_FILE):
        return jsonify({"error": "Rules file not found"}), 404
    with open(RULES_FILE) as fh:
        data = yaml.safe_load(fh)
    rules = data.get("rules", [])

    service = request.args.get("service") or None
    severity = (request.args.get("severity") or "").upper() or None
    if service:
        rules = [r for r in rules if r.get("service") == service]
    if severity:
        rules = [r for r in rules if r.get("severity", "").upper() == severity]

    return jsonify({"rules": rules, "total": len(rules)})


@api_bp.route("/rules", methods=["POST"])
@require_auth("write")
@rate_limit(requests_per_minute=10)
def create_rule():
    data = request.get_json(silent=True) or {}
    for field in ("id", "title", "description", "condition", "severity"):
        if not data.get(field):
            return jsonify({"error": f"Missing required field: {field}"}), 400

    if not os.path.exists(RULES_FILE):
        return jsonify({"error": "Rules file not found"}), 404

    with open(RULES_FILE) as fh:
        rules_data = yaml.safe_load(fh) or {"rules": []}

    # Reject duplicate IDs
    existing_ids = {r.get("id") for r in rules_data.get("rules", [])}
    if data["id"] in existing_ids:
        return jsonify({"error": f"Rule ID '{data['id']}' already exists"}), 409

    rules_data.setdefault("rules", []).append(data)
    with open(RULES_FILE, "w") as fh:
        yaml.dump(rules_data, fh, default_flow_style=False, allow_unicode=True)

    return jsonify({"message": "Rule created", "rule_id": data["id"]}), 201


# ---------------------------------------------------------------------------
# Stats
# ---------------------------------------------------------------------------

@api_bp.route("/stats", methods=["GET"])
@require_auth("read")
@rate_limit(requests_per_minute=60)
def get_stats():
    alerts = _load_alerts()
    sev_counts: dict = {}
    cloud_counts: dict = {}
    for a in alerts:
        s = a.get("severity", "UNKNOWN")
        c = a.get("cloud", "unknown")
        sev_counts[s] = sev_counts.get(s, 0) + 1
        cloud_counts[c] = cloud_counts.get(c, 0) + 1

    scan_count = 0
    if os.path.exists(LOGS_DIR):
        scan_count = sum(1 for f in os.listdir(LOGS_DIR) if f.endswith(".json"))

    return jsonify({
        "total_alerts": len(alerts),
        "total_scans": scan_count,
        "severity_breakdown": sev_counts,
        "cloud_breakdown": cloud_counts,
        "api_version": "1.0.0",
        "timestamp": datetime.utcnow().isoformat() + "Z",
    })


# ---------------------------------------------------------------------------
# Error handlers
# ---------------------------------------------------------------------------

@api_bp.errorhandler(404)
def not_found(error):
    return jsonify({"error": "Endpoint not found"}), 404


@api_bp.errorhandler(405)
def method_not_allowed(error):
    return jsonify({"error": "Method not allowed"}), 405


@api_bp.errorhandler(500)
def internal_error(error):
    return jsonify({"error": "Internal server error"}), 500
