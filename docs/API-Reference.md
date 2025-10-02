# 🔌 API Reference

CloudHawk provides a comprehensive RESTful API for programmatic access to all features. This guide covers all available endpoints, request/response formats, and integration examples.

## 🌐 Base URL

```
http://localhost:5000/api
```

## 🔐 Authentication

Currently, CloudHawk API is open (no authentication required). Future versions will support:
- API Key authentication
- OAuth 2.0
- JWT tokens

## 📊 Core Endpoints

### Health Check
```http
GET /api/health
```

**Response:**
```json
{
  "status": "healthy",
  "timestamp": "2025-09-26T22:50:00Z",
  "version": "1.0.0",
  "uptime": 3600
}
```

### System Status
```http
GET /api/status
```

**Response:**
```json
{
  "status": "running",
  "cloud_providers": {
    "aws": "connected",
    "azure": "connected", 
    "gcp": "disconnected"
  },
  "alerts": {
    "total": 25,
    "critical": 3,
    "high": 8,
    "medium": 10,
    "low": 4
  }
}
```

## 🚨 Alerts API

### Get All Alerts
```http
GET /api/alerts
```

**Query Parameters:**
- `severity`: Filter by severity (CRITICAL, HIGH, MEDIUM, LOW)
- `service`: Filter by service (EC2, S3, IAM, etc.)
- `limit`: Number of alerts to return (default: 100)
- `offset`: Pagination offset (default: 0)

**Example Request:**
```http
GET /api/alerts?severity=CRITICAL&service=EC2&limit=10
```

**Response:**
```json
{
  "alerts": [
    {
      "id": "EC2-001",
      "title": "EC2 Instance Public IP",
      "severity": "CRITICAL",
      "service": "EC2",
      "description": "EC2 instance has public IP address",
      "remediation": "Use private IPs or NAT gateway",
      "timestamp": "2025-09-26T22:50:00Z",
      "rule_id": "EC2-PUBLIC-IP-001"
    }
  ],
  "total": 1,
  "limit": 10,
  "offset": 0
}
```

### Get Alert by ID
```http
GET /api/alerts/{alert_id}
```

**Response:**
```json
{
  "id": "EC2-001",
  "title": "EC2 Instance Public IP",
  "severity": "CRITICAL",
  "service": "EC2",
  "description": "EC2 instance has public IP address",
  "remediation": "Use private IPs or NAT gateway",
  "timestamp": "2025-09-26T22:50:00Z",
  "rule_id": "EC2-PUBLIC-IP-001",
  "affected_resources": [
    {
      "type": "EC2 Instance",
      "id": "i-1234567890abcdef0",
      "region": "us-east-1"
    }
  ],
  "compliance": ["SOC2", "PCI-DSS"]
}
```

### Update Alert Status
```http
PUT /api/alerts/{alert_id}
```

**Request Body:**
```json
{
  "status": "acknowledged",
  "notes": "Working on remediation"
}
```

**Response:**
```json
{
  "status": "success",
  "message": "Alert updated successfully"
}
```

## 🔍 Scanning API

### Start Security Scan
```http
POST /api/scan
```

**Request Body:**
```json
{
  "provider": "aws",
  "region": "us-east-1",
  "services": ["EC2", "S3", "IAM"],
  "scan_type": "comprehensive"
}
```

**Response:**
```json
{
  "scan_id": "scan-1234567890",
  "status": "started",
  "message": "Security scan started successfully"
}
```

### Get Scan Status
```http
GET /api/scan/{scan_id}
```

**Response:**
```json
{
  "scan_id": "scan-1234567890",
  "status": "running",
  "progress": 65,
  "started_at": "2025-09-26T22:50:00Z",
  "estimated_completion": "2025-09-26T22:55:00Z"
}
```

### Get Scan Results
```http
GET /api/scan/{scan_id}/results
```

**Response:**
```json
{
  "scan_id": "scan-1234567890",
  "status": "completed",
  "started_at": "2025-09-26T22:50:00Z",
  "completed_at": "2025-09-26T22:55:00Z",
  "results": {
    "total_alerts": 25,
    "critical": 3,
    "high": 8,
    "medium": 10,
    "low": 4
  },
  "alerts": [...]
}
```

## 📋 Rules API

### Get All Rules
```http
GET /api/rules
```

**Query Parameters:**
- `service`: Filter by service
- `severity`: Filter by severity
- `category`: Filter by category
- `enabled`: Filter by enabled status

**Response:**
```json
{
  "rules": [
    {
      "id": "EC2-001",
      "title": "EC2 Instance Public IP",
      "description": "Detects EC2 instances with public IP addresses",
      "service": "EC2",
      "severity": "CRITICAL",
      "category": "Network Security",
      "enabled": true,
      "condition": "instance.public_ip != null",
      "remediation": "Use private IPs or NAT gateway"
    }
  ],
  "total": 1000
}
```

### Get Rule by ID
```http
GET /api/rules/{rule_id}
```

**Response:**
```json
{
  "id": "EC2-001",
  "title": "EC2 Instance Public IP",
  "description": "Detects EC2 instances with public IP addresses",
  "service": "EC2",
  "severity": "CRITICAL",
  "category": "Network Security",
  "enabled": true,
  "condition": "instance.public_ip != null",
  "remediation": "Use private IPs or NAT gateway",
  "tags": ["network", "security", "compliance"],
  "created_at": "2025-09-26T22:50:00Z",
  "updated_at": "2025-09-26T22:50:00Z"
}
```

### Create Custom Rule
```http
POST /api/rules
```

**Request Body:**
```json
{
  "title": "Custom Security Rule",
  "description": "Detects specific security condition",
  "service": "AWS_S3",
  "severity": "HIGH",
  "category": "Data Protection",
  "condition": "bucket.policy.contains('Principal:*')",
  "remediation": "Restrict bucket access to specific principals",
  "tags": ["custom", "compliance"]
}
```

**Response:**
```json
{
  "status": "success",
  "rule_id": "CUSTOM-001",
  "message": "Rule created successfully"
}
```

### Update Rule
```http
PUT /api/rules/{rule_id}
```

**Request Body:**
```json
{
  "enabled": false,
  "severity": "MEDIUM",
  "remediation": "Updated remediation steps"
}
```

**Response:**
```json
{
  "status": "success",
  "message": "Rule updated successfully"
}
```

### Delete Rule
```http
DELETE /api/rules/{rule_id}
```

**Response:**
```json
{
  "status": "success",
  "message": "Rule deleted successfully"
}
```

## 🔔 Alerting API

### Send Alerts
```http
POST /api/send-alerts
```

**Request Body:**
```json
{
  "type": "all",
  "severity_filter": ["CRITICAL", "HIGH"],
  "service_filter": ["EC2", "S3"]
}
```

**Response:**
```json
{
  "status": "success",
  "results": {
    "email": {
      "status": "success",
      "sent": 3,
      "total": 25
    },
    "slack": {
      "status": "success", 
      "sent": 3,
      "total": 25
    }
  }
}
```

### Test Email Configuration
```http
POST /api/debug-email-config-file
```

**Response:**
```json
{
  "status": "success",
  "email_enabled": true,
  "smtp_server": "smtp.gmail.com",
  "smtp_port": 587,
  "from_email": "alerts@company.com",
  "to_email": "security@company.com",
  "test_result": "Email configuration is working"
}
```

### Test Slack Configuration
```http
POST /api/test-slack
```

**Response:**
```json
{
  "status": "success",
  "slack_enabled": true,
  "webhook_url": "https://hooks.slack.com/services/...",
  "channel": "#security-alerts",
  "test_result": "Slack configuration is working"
}
```

## ⚙️ Configuration API

### Get Configuration
```http
GET /api/config
```

**Response:**
```json
{
  "aws": {
    "enabled": true,
    "regions": ["us-east-1", "us-west-2"],
    "services": ["EC2", "S3", "IAM"]
  },
  "azure": {
    "enabled": true,
    "subscription_id": "your-subscription-id",
    "services": ["Virtual Machines", "Storage"]
  },
  "gcp": {
    "enabled": true,
    "project_id": "your-project-id",
    "services": ["Compute Engine", "Cloud Storage"]
  }
}
```

### Update Configuration
```http
PUT /api/config
```

**Request Body:**
```json
{
  "aws": {
    "enabled": true,
    "regions": ["us-east-1"],
    "services": ["EC2", "S3"]
  }
}
```

**Response:**
```json
{
  "status": "success",
  "message": "Configuration updated successfully"
}
```

### Save Email Configuration
```http
POST /api/save-email-config
```

**Request Body:**
```json
{
  "email": {
    "enabled": true,
    "smtp_server": "smtp.gmail.com",
    "smtp_port": 587,
    "username": "alerts@company.com",
    "password": "your_password",
    "from_email": "alerts@company.com",
    "to_email": "security@company.com"
  },
  "slack": {
    "enabled": true,
    "webhook_url": "https://hooks.slack.com/services/...",
    "channel": "#security-alerts"
  }
}
```

**Response:**
```json
{
  "status": "success",
  "message": "Email configuration saved successfully"
}
```

## 📊 Analytics API

### Get Security Score
```http
GET /api/analytics/security-score
```

**Response:**
```json
{
  "overall_score": 85,
  "breakdown": {
    "aws": 90,
    "azure": 80,
    "gcp": 85
  },
  "trend": "improving",
  "last_updated": "2025-09-26T22:50:00Z"
}
```

### Get Alert Trends
```http
GET /api/analytics/trends
```

**Query Parameters:**
- `period`: Time period (7d, 30d, 90d)
- `service`: Filter by service

**Response:**
```json
{
  "period": "30d",
  "trends": [
    {
      "date": "2025-09-26",
      "critical": 3,
      "high": 8,
      "medium": 10,
      "low": 4
    }
  ],
  "summary": {
    "total_alerts": 25,
    "trend": "decreasing",
    "improvement": 15
  }
}
```

### Get Compliance Status
```http
GET /api/analytics/compliance
```

**Response:**
```json
{
  "soc2": {
    "status": "compliant",
    "score": 95,
    "issues": 2
  },
  "pci_dss": {
    "status": "non_compliant",
    "score": 70,
    "issues": 8
  },
  "cis": {
    "status": "partially_compliant",
    "score": 80,
    "issues": 5
  }
}
```

## 🔧 Health API

### Get System Health
```http
GET /api/health/system
```

**Response:**
```json
{
  "status": "healthy",
  "cpu_usage": 45.2,
  "memory_usage": 67.8,
  "disk_usage": 23.1,
  "uptime": 3600,
  "last_scan": "2025-09-26T22:50:00Z"
}
```

### Get Cloud Provider Health
```http
GET /api/health/cloud-providers
```

**Response:**
```json
{
  "aws": {
    "status": "connected",
    "last_check": "2025-09-26T22:50:00Z",
    "regions": ["us-east-1", "us-west-2"],
    "services": ["EC2", "S3", "IAM"]
  },
  "azure": {
    "status": "connected",
    "last_check": "2025-09-26T22:50:00Z",
    "subscription": "your-subscription-id",
    "services": ["Virtual Machines", "Storage"]
  },
  "gcp": {
    "status": "disconnected",
    "last_check": "2025-09-26T22:50:00Z",
    "error": "Authentication failed"
  }
}
```

## 📈 Integration Examples

### Python Integration
```python
import requests

# Get all critical alerts
response = requests.get('http://localhost:5000/api/alerts?severity=CRITICAL')
alerts = response.json()['alerts']

# Start a security scan
scan_data = {
    "provider": "aws",
    "region": "us-east-1",
    "services": ["EC2", "S3", "IAM"]
}
response = requests.post('http://localhost:5000/api/scan', json=scan_data)
scan_id = response.json()['scan_id']

# Check scan status
response = requests.get(f'http://localhost:5000/api/scan/{scan_id}')
status = response.json()['status']
```

### JavaScript Integration
```javascript
// Get security score
fetch('http://localhost:5000/api/analytics/security-score')
  .then(response => response.json())
  .then(data => {
    console.log('Security Score:', data.overall_score);
  });

// Send alerts
fetch('http://localhost:5000/api/send-alerts', {
  method: 'POST',
  headers: {
    'Content-Type': 'application/json'
  },
  body: JSON.stringify({
    type: 'all',
    severity_filter: ['CRITICAL', 'HIGH']
  })
})
.then(response => response.json())
.then(data => {
  console.log('Alerts sent:', data.results);
});
```

### cURL Examples
```bash
# Get all alerts
curl -X GET "http://localhost:5000/api/alerts"

# Get critical alerts for EC2
curl -X GET "http://localhost:5000/api/alerts?severity=CRITICAL&service=EC2"

# Start a scan
curl -X POST "http://localhost:5000/api/scan" \
  -H "Content-Type: application/json" \
  -d '{"provider": "aws", "region": "us-east-1", "services": ["EC2", "S3"]}'

# Send alerts
curl -X POST "http://localhost:5000/api/send-alerts" \
  -H "Content-Type: application/json" \
  -d '{"type": "all"}'
```

## 🔒 Error Handling

### Error Response Format
```json
{
  "error": {
    "code": "INVALID_REQUEST",
    "message": "Invalid request parameters",
    "details": "The 'severity' parameter must be one of: CRITICAL, HIGH, MEDIUM, LOW"
  }
}
```

### Common Error Codes
- `INVALID_REQUEST`: Invalid request parameters
- `NOT_FOUND`: Resource not found
- `UNAUTHORIZED`: Authentication required
- `FORBIDDEN`: Insufficient permissions
- `INTERNAL_ERROR`: Server error
- `SERVICE_UNAVAILABLE`: Service temporarily unavailable

### HTTP Status Codes
- `200`: Success
- `201`: Created
- `400`: Bad Request
- `401`: Unauthorized
- `403`: Forbidden
- `404`: Not Found
- `500`: Internal Server Error
- `503`: Service Unavailable

## 📚 SDKs and Libraries

### Python SDK
```python
# Install CloudHawk SDK
pip install cloudhawk-sdk

# Use the SDK
from cloudhawk import CloudHawk

client = CloudHawk('http://localhost:5000')
alerts = client.get_alerts(severity='CRITICAL')
scan_id = client.start_scan(provider='aws', region='us-east-1')
```

### JavaScript SDK
```javascript
// Install CloudHawk SDK
npm install cloudhawk-sdk

// Use the SDK
const CloudHawk = require('cloudhawk-sdk');
const client = new CloudHawk('http://localhost:5000');

const alerts = await client.getAlerts({ severity: 'CRITICAL' });
const scanId = await client.startScan({ provider: 'aws', region: 'us-east-1' });
```

## 📞 Support

- **API Documentation**: This guide and interactive docs
- **GitHub Issues**: [Report API issues](https://github.com/vatshariyani/cloudhawk/issues)
- **Discussions**: [API questions and examples](https://github.com/vatshariyani/cloudhawk/discussions)
- **Email**: api-support@cloudhawk.dev

---

**Next Steps**: Learn about [Custom Rules](Custom-Rules.md) or [Web Dashboard](Web-Dashboard.md) for user interface!
