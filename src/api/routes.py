"""
CloudHawk RESTful API Routes
Comprehensive API endpoints for external integrations
"""

import os
import json
import logging
from datetime import datetime, timedelta
from flask import Blueprint, request, jsonify, current_app
from typing import Dict, List, Any, Optional
import yaml

# Import authentication
from .auth import require_auth, require_admin, rate_limit, auth_manager

# Import collectors
import sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
from collector.aws_collector import AWSCollector
from collector.gcp_collector import GCPCollector
from collector.azure_collector import AzureCollector
from detection.rule_engine import RuleEngine

# Configure logging
logger = logging.getLogger(__name__)

# Create API blueprint
api_bp = Blueprint('api', __name__, url_prefix='/api/v1')

# Base directory for files
BASE_DIR = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
RULES_FILE = os.path.join(BASE_DIR, 'src', 'detection', 'security_rules.yaml')

@api_bp.route('/health', methods=['GET'])
@rate_limit(requests_per_minute=120)
def api_health():
    """Health check endpoint"""
    return jsonify({
        'status': 'healthy',
        'timestamp': datetime.utcnow().isoformat(),
        'version': '2.0.0',
        'services': {
            'api': 'operational',
            'collectors': 'operational',
            'rule_engine': 'operational'
        }
    })

@api_bp.route('/auth/token', methods=['POST'])
@rate_limit(requests_per_minute=10)
def generate_token():
    """Generate JWT token for API access"""
    try:
        data = request.get_json()
        user_id = data.get('user_id')
        permissions = data.get('permissions', ['read'])
        
        if not user_id:
            return jsonify({'error': 'user_id is required'}), 400
        
        token = auth_manager.generate_jwt_token(user_id, permissions)
        
        return jsonify({
            'token': token,
            'expires_in': 86400,  # 24 hours
            'permissions': permissions
        })
        
    except Exception as e:
        logger.error(f"Error generating token: {e}")
        return jsonify({'error': 'Failed to generate token'}), 500

@api_bp.route('/auth/api-key', methods=['POST'])
@require_admin
@rate_limit(requests_per_minute=5)
def generate_api_key():
    """Generate API key (admin only)"""
    try:
        data = request.get_json()
        name = data.get('name', 'api-key')
        permissions = data.get('permissions', ['read'])
        
        api_key = auth_manager.generate_api_key(name, permissions)
        
        return jsonify({
            'api_key': api_key,
            'name': name,
            'permissions': permissions,
            'created_at': datetime.utcnow().isoformat()
        })
        
    except Exception as e:
        logger.error(f"Error generating API key: {e}")
        return jsonify({'error': 'Failed to generate API key'}), 500

@api_bp.route('/scans', methods=['GET'])
@require_auth('read')
@rate_limit(requests_per_minute=60)
def list_scans():
    """List available scans"""
    try:
        # Get scan history from logs directory
        logs_dir = os.path.join(BASE_DIR, 'logs')
        scans = []
        
        if os.path.exists(logs_dir):
            for filename in os.listdir(logs_dir):
                if filename.endswith('.json'):
                    filepath = os.path.join(logs_dir, filename)
                    stat = os.stat(filepath)
                    
                    scan_info = {
                        'id': filename.replace('.json', ''),
                        'filename': filename,
                        'created_at': datetime.fromtimestamp(stat.st_ctime).isoformat(),
                        'size': stat.st_size,
                        'type': 'security_events'
                    }
                    scans.append(scan_info)
        
        return jsonify({
            'scans': sorted(scans, key=lambda x: x['created_at'], reverse=True),
            'total': len(scans)
        })
        
    except Exception as e:
        logger.error(f"Error listing scans: {e}")
        return jsonify({'error': 'Failed to list scans'}), 500

@api_bp.route('/scans', methods=['POST'])
@require_auth('write')
@rate_limit(requests_per_minute=10)
def create_scan():
    """Create a new security scan"""
    try:
        data = request.get_json()
        cloud_provider = data.get('cloud_provider', 'AWS')
        region = data.get('region', 'us-east-1')
        max_events = data.get('max_events', 1000)
        project_id = data.get('project_id')
        subscription_id = data.get('subscription_id')
        
        # Initialize appropriate collector
        if cloud_provider == 'AWS':
            collector = AWSCollector(region=region, max_events=max_events)
        elif cloud_provider == 'GCP':
            if not project_id:
                return jsonify({'error': 'project_id is required for GCP scans'}), 400
            collector = GCPCollector(project_id=project_id)
        elif cloud_provider == 'Azure':
            if not subscription_id:
                return jsonify({'error': 'subscription_id is required for Azure scans'}), 400
            collector = AzureCollector(subscription_id=subscription_id, max_events=max_events)
        else:
            return jsonify({'error': f'Unsupported cloud provider: {cloud_provider}'}), 400
        
        # Run scan
        logger.info(f"Starting {cloud_provider} scan via API")
        security_events = collector.collect_all_security_data()
        
        # Save events
        events_file = collector.save_security_events(security_events)
        
        # Run rule engine
        rule_engine = RuleEngine(RULES_FILE, events_file, threads=4, chunk_size=100)
        rule_engine.run()
        
        # Return scan results
        return jsonify({
            'scan_id': os.path.basename(events_file).replace('.json', ''),
            'cloud_provider': cloud_provider,
            'events_collected': len(security_events),
            'alerts_generated': len(rule_engine.alerts),
            'status': 'completed',
            'created_at': datetime.utcnow().isoformat(),
            'events_file': events_file
        })
        
    except Exception as e:
        logger.error(f"Error creating scan: {e}")
        return jsonify({'error': f'Scan failed: {str(e)}'}), 500

@api_bp.route('/scans/<scan_id>', methods=['GET'])
@require_auth('read')
@rate_limit(requests_per_minute=60)
def get_scan(scan_id):
    """Get scan details and results"""
    try:
        # Find scan file
        logs_dir = os.path.join(BASE_DIR, 'logs')
        scan_file = None
        
        for filename in os.listdir(logs_dir):
            if filename.startswith(scan_id) and filename.endswith('.json'):
                scan_file = os.path.join(logs_dir, filename)
                break
        
        if not scan_file or not os.path.exists(scan_file):
            return jsonify({'error': 'Scan not found'}), 404
        
        # Load scan data
        with open(scan_file, 'r') as f:
            events = json.load(f)
        
        # Analyze events
        severity_counts = {}
        source_counts = {}
        
        for event in events:
            severity = event.get('severity', 'UNKNOWN')
            source = event.get('source', 'UNKNOWN')
            
            severity_counts[severity] = severity_counts.get(severity, 0) + 1
            source_counts[source] = source_counts.get(source, 0) + 1
        
        return jsonify({
            'scan_id': scan_id,
            'total_events': len(events),
            'severity_breakdown': severity_counts,
            'source_breakdown': source_counts,
            'created_at': datetime.fromtimestamp(os.path.getctime(scan_file)).isoformat(),
            'events': events[:100]  # Return first 100 events
        })
        
    except Exception as e:
        logger.error(f"Error getting scan {scan_id}: {e}")
        return jsonify({'error': 'Failed to get scan details'}), 500

@api_bp.route('/alerts', methods=['GET'])
@require_auth('read')
@rate_limit(requests_per_minute=60)
def get_alerts():
    """Get security alerts with filtering"""
    try:
        # Load alerts from file
        alerts_file = os.path.join(BASE_DIR, 'src', 'alerts', 'alerts.json')
        
        if not os.path.exists(alerts_file):
            return jsonify({'alerts': [], 'total': 0})
        
        with open(alerts_file, 'r') as f:
            alerts_data = json.load(f)
        
        alerts = alerts_data.get('alerts', [])
        
        # Apply filters
        severity_filter = request.args.get('severity')
        service_filter = request.args.get('service')
        limit = int(request.args.get('limit', 100))
        offset = int(request.args.get('offset', 0))
        
        filtered_alerts = alerts
        
        if severity_filter:
            filtered_alerts = [a for a in filtered_alerts if a.get('severity') == severity_filter]
        
        if service_filter:
            filtered_alerts = [a for a in filtered_alerts if a.get('service') == service_filter]
        
        # Pagination
        total = len(filtered_alerts)
        paginated_alerts = filtered_alerts[offset:offset + limit]
        
        return jsonify({
            'alerts': paginated_alerts,
            'total': total,
            'limit': limit,
            'offset': offset,
            'has_more': offset + limit < total
        })
        
    except Exception as e:
        logger.error(f"Error getting alerts: {e}")
        return jsonify({'error': 'Failed to get alerts'}), 500

@api_bp.route('/alerts/<alert_id>', methods=['GET'])
@require_auth('read')
@rate_limit(requests_per_minute=60)
def get_alert(alert_id):
    """Get specific alert details"""
    try:
        # Load alerts from file
        alerts_file = os.path.join(BASE_DIR, 'src', 'alerts', 'alerts.json')
        
        if not os.path.exists(alerts_file):
            return jsonify({'error': 'Alert not found'}), 404
        
        with open(alerts_file, 'r') as f:
            alerts_data = json.load(f)
        
        alerts = alerts_data.get('alerts', [])
        
        # Find specific alert
        for alert in alerts:
            if alert.get('id') == alert_id:
                return jsonify(alert)
        
        return jsonify({'error': 'Alert not found'}), 404
        
    except Exception as e:
        logger.error(f"Error getting alert {alert_id}: {e}")
        return jsonify({'error': 'Failed to get alert'}), 500

@api_bp.route('/rules', methods=['GET'])
@require_auth('read')
@rate_limit(requests_per_minute=60)
def get_rules():
    """Get security rules"""
    try:
        if not os.path.exists(RULES_FILE):
            return jsonify({'error': 'Rules file not found'}), 404
        
        with open(RULES_FILE, 'r') as f:
            rules_data = yaml.safe_load(f)
        
        return jsonify(rules_data)
        
    except Exception as e:
        logger.error(f"Error getting rules: {e}")
        return jsonify({'error': 'Failed to get rules'}), 500

@api_bp.route('/rules', methods=['POST'])
@require_auth('write')
@rate_limit(requests_per_minute=10)
def create_rule():
    """Create a new security rule"""
    try:
        data = request.get_json()
        
        # Validate rule structure
        required_fields = ['id', 'title', 'description', 'condition', 'severity']
        for field in required_fields:
            if field not in data:
                return jsonify({'error': f'Missing required field: {field}'}), 400
        
        # Load existing rules
        if os.path.exists(RULES_FILE):
            with open(RULES_FILE, 'r') as f:
                rules_data = yaml.safe_load(f)
        else:
            rules_data = {'rules': []}
        
        # Add new rule
        rules_data['rules'].append(data)
        
        # Save rules
        with open(RULES_FILE, 'w') as f:
            yaml.dump(rules_data, f, default_flow_style=False)
        
        return jsonify({
            'message': 'Rule created successfully',
            'rule_id': data['id']
        })
        
    except Exception as e:
        logger.error(f"Error creating rule: {e}")
        return jsonify({'error': 'Failed to create rule'}), 500

@api_bp.route('/webhooks', methods=['POST'])
@require_auth('write')
@rate_limit(requests_per_minute=5)
def create_webhook():
    """Create a webhook for external integrations"""
    try:
        data = request.get_json()
        url = data.get('url')
        events = data.get('events', ['alert.created'])
        secret = data.get('secret', secrets.token_urlsafe(32))
        
        if not url:
            return jsonify({'error': 'URL is required'}), 400
        
        # In production, store webhooks in database
        webhook = {
            'id': secrets.token_urlsafe(16),
            'url': url,
            'events': events,
            'secret': secret,
            'created_at': datetime.utcnow().isoformat(),
            'active': True
        }
        
        return jsonify({
            'webhook': webhook,
            'message': 'Webhook created successfully'
        })
        
    except Exception as e:
        logger.error(f"Error creating webhook: {e}")
        return jsonify({'error': 'Failed to create webhook'}), 500

@api_bp.route('/stats', methods=['GET'])
@require_auth('read')
@rate_limit(requests_per_minute=60)
def get_stats():
    """Get system statistics"""
    try:
        # Load alerts for statistics
        alerts_file = os.path.join(BASE_DIR, 'src', 'alerts', 'alerts.json')
        alerts_count = 0
        severity_counts = {}
        
        if os.path.exists(alerts_file):
            with open(alerts_file, 'r') as f:
                alerts_data = json.load(f)
            
            alerts = alerts_data.get('alerts', [])
            alerts_count = len(alerts)
            
            for alert in alerts:
                severity = alert.get('severity', 'UNKNOWN')
                severity_counts[severity] = severity_counts.get(severity, 0) + 1
        
        # Count scan files
        logs_dir = os.path.join(BASE_DIR, 'logs')
        scan_count = 0
        if os.path.exists(logs_dir):
            scan_count = len([f for f in os.listdir(logs_dir) if f.endswith('.json')])
        
        return jsonify({
            'total_alerts': alerts_count,
            'total_scans': scan_count,
            'severity_breakdown': severity_counts,
            'api_version': '2.0.0',
            'timestamp': datetime.utcnow().isoformat()
        })
        
    except Exception as e:
        logger.error(f"Error getting stats: {e}")
        return jsonify({'error': 'Failed to get statistics'}), 500

@api_bp.errorhandler(404)
def not_found(error):
    """Handle 404 errors"""
    return jsonify({'error': 'Endpoint not found'}), 404

@api_bp.errorhandler(500)
def internal_error(error):
    """Handle 500 errors"""
    return jsonify({'error': 'Internal server error'}), 500
