# CloudHawk Configuration Guide

This guide covers all configuration options for CloudHawk, including cloud provider settings, detection rules, alerting, and more.

## Table of Contents
- [Basic Configuration](#basic-configuration)
- [Cloud Provider Settings](#cloud-provider-settings)
- [Detection Rules](#detection-rules)
- [Alerting Configuration](#alerting-configuration)
- [Web Dashboard Settings](#web-dashboard-settings)
- [Advanced Configuration](#advanced-configuration)

## Basic Configuration

The main configuration file is `config.yaml` in the root directory. Here's a basic configuration structure:

```yaml
# CloudHawk Configuration
version: "1.0"
debug: false
log_level: "INFO"

# Cloud Providers
cloud_providers:
  aws:
    enabled: true
    regions: ["us-east-1", "us-west-2"]
    access_key: "YOUR_ACCESS_KEY"
    secret_key: "YOUR_SECRET_KEY"
  
  azure:
    enabled: false
    tenant_id: "YOUR_TENANT_ID"
    client_id: "YOUR_CLIENT_ID"
    client_secret: "YOUR_CLIENT_SECRET"
  
  gcp:
    enabled: false
    project_id: "YOUR_PROJECT_ID"
    service_account_key: "path/to/service-account.json"

# Detection Settings
detection:
  enabled: true
  scan_interval: 3600  # seconds
  rules_file: "src/detection/rules.yaml"
  anomaly_detection: true
  vulnerability_scanning: true

# Alerting
alerting:
  enabled: true
  email:
    enabled: true
    smtp_server: "smtp.gmail.com"
    smtp_port: 587
    username: "your-email@gmail.com"
    password: "your-app-password"
    to_addresses: ["admin@company.com"]
  
  slack:
    enabled: true
    webhook_url: "https://hooks.slack.com/services/YOUR_WORKSPACE_ID/YOUR_CHANNEL_ID/YOUR_WEBHOOK_TOKEN"
    channel: "#security-alerts"
    username: "CloudHawk"
    icon_emoji: ":shield:"

# Web Dashboard
web_dashboard:
  enabled: true
  host: "0.0.0.0"
  port: 8080
  debug: false
  ssl_enabled: false
  ssl_cert: "path/to/cert.pem"
  ssl_key: "path/to/key.pem"
```

## Cloud Provider Settings

### AWS Configuration

```yaml
aws:
  enabled: true
  regions: ["us-east-1", "us-west-2", "eu-west-1"]
  access_key: "YOUR_ACCESS_KEY"
  secret_key: "YOUR_SECRET_KEY"
  session_token: "OPTIONAL_SESSION_TOKEN"  # For temporary credentials
  role_arn: "arn:aws:iam::123456789012:role/CloudHawkRole"  # For cross-account access
  external_id: "unique-external-id"  # For cross-account access
```

### Azure Configuration

```yaml
azure:
  enabled: true
  tenant_id: "YOUR_TENANT_ID"
  client_id: "YOUR_CLIENT_ID"
  client_secret: "YOUR_CLIENT_SECRET"
  subscription_id: "YOUR_SUBSCRIPTION_ID"
  resource_groups: ["production", "staging"]  # Optional: limit to specific resource groups
```

### GCP Configuration

```yaml
gcp:
  enabled: true
  project_id: "your-project-id"
  service_account_key: "path/to/service-account.json"
  # Alternative: use application default credentials
  # credentials_file: "~/.config/gcloud/application_default_credentials.json"
```

## Detection Rules

Detection rules are defined in `src/detection/rules.yaml`. Here's the structure:

```yaml
# Security Rules
security_rules:
  - name: "Public S3 Bucket"
    description: "Detects S3 buckets with public read access"
    severity: "HIGH"
    cloud_provider: "aws"
    resource_type: "s3_bucket"
    conditions:
      - field: "public_read"
        operator: "equals"
        value: true
    remediation: "Remove public read access from S3 bucket"

  - name: "Unencrypted RDS Instance"
    description: "Detects RDS instances without encryption"
    severity: "MEDIUM"
    cloud_provider: "aws"
    resource_type: "rds_instance"
    conditions:
      - field: "encryption"
        operator: "equals"
        value: false
    remediation: "Enable encryption for RDS instance"

# Misconfiguration Rules
misconfig_rules:
  - name: "Open Security Group"
    description: "Detects security groups with overly permissive rules"
    severity: "HIGH"
    cloud_provider: "aws"
    resource_type: "security_group"
    conditions:
      - field: "port_range"
        operator: "contains"
        value: "0.0.0.0/0"
    remediation: "Restrict security group rules to specific IP ranges"

# Anomaly Detection Rules
anomaly_rules:
  - name: "Unusual API Activity"
    description: "Detects unusual patterns in API calls"
    severity: "MEDIUM"
    cloud_provider: "aws"
    resource_type: "cloudtrail"
    conditions:
      - field: "api_calls_per_hour"
        operator: "greater_than"
        value: 1000
    remediation: "Review API usage patterns and investigate if necessary"
```

## Alerting Configuration

### Email Alerts

```yaml
alerting:
  email:
    enabled: true
    smtp_server: "smtp.gmail.com"
    smtp_port: 587
    use_tls: true
    username: "your-email@gmail.com"
    password: "your-app-password"
    from_address: "cloudhawk@company.com"
    to_addresses: 
      - "admin@company.com"
      - "security@company.com"
    subject_prefix: "[CloudHawk Alert]"
    template_file: "templates/email_alert.html"
```

### Slack Alerts

```yaml
alerting:
  slack:
    enabled: true
    webhook_url: "https://hooks.slack.com/services/YOUR_WORKSPACE_ID/YOUR_CHANNEL_ID/YOUR_WEBHOOK_TOKEN"
    channel: "#security-alerts"
    username: "CloudHawk"
    icon_emoji: ":shield:"
    color: "danger"  # danger, warning, good, or hex color
    mention_users: ["@admin", "@security"]
```

### Alert Severity Levels

- **CRITICAL**: Immediate action required
- **HIGH**: Action required within 24 hours
- **MEDIUM**: Action required within 7 days
- **LOW**: Informational, monitor for trends

## Web Dashboard Settings

```yaml
web_dashboard:
  enabled: true
  host: "0.0.0.0"
  port: 8080
  debug: false
  
  # SSL Configuration (optional)
  ssl_enabled: false
  ssl_cert: "path/to/cert.pem"
  ssl_key: "path/to/key.pem"
  
  # Authentication (optional)
  auth_enabled: false
  auth_type: "basic"  # basic, oauth, ldap
  username: "admin"
  password: "secure_password"
  
  # Session Configuration
  session_secret: "your-secret-key"
  session_timeout: 3600  # seconds
  
  # Rate Limiting
  rate_limit_enabled: true
  rate_limit_requests: 100
  rate_limit_window: 3600  # seconds
```

## Advanced Configuration

### Logging Configuration

```yaml
logging:
  level: "INFO"  # DEBUG, INFO, WARNING, ERROR, CRITICAL
  format: "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
  file: "cloudhawk.log"
  max_size: "10MB"
  backup_count: 5
  
  # Structured logging for JSON output
  structured: false
  json_format: true
```

### Performance Settings

```yaml
performance:
  max_workers: 4
  scan_timeout: 300  # seconds
  api_timeout: 30  # seconds
  retry_attempts: 3
  retry_delay: 5  # seconds
  
  # Caching
  cache_enabled: true
  cache_ttl: 3600  # seconds
  cache_size: 1000  # maximum number of cached items
```

### Data Retention

```yaml
data_retention:
  scan_results: 30  # days
  logs: 90  # days
  alerts: 180  # days
  
  # Automatic cleanup
  cleanup_enabled: true
  cleanup_schedule: "0 2 * * *"  # Daily at 2 AM
```

## Environment Variables

You can override configuration values using environment variables:

```bash
# CloudHawk Settings
export CLOUDHAWK_DEBUG=true
export CLOUDHAWK_LOG_LEVEL=DEBUG

# AWS Settings
export AWS_ACCESS_KEY_ID=your_access_key
export AWS_SECRET_ACCESS_KEY=your_secret_key
export AWS_DEFAULT_REGION=us-east-1

# Azure Settings
export AZURE_TENANT_ID=your_tenant_id
export AZURE_CLIENT_ID=your_client_id
export AZURE_CLIENT_SECRET=your_client_secret

# GCP Settings
export GOOGLE_APPLICATION_CREDENTIALS=path/to/service-account.json

# Database Settings
export CLOUDHAWK_DB_URL=postgresql://user:pass@localhost/cloudhawk
```

## Configuration Validation

CloudHawk validates configuration on startup. Common validation errors:

1. **Invalid YAML syntax**: Check indentation and syntax
2. **Missing required fields**: Ensure all required fields are present
3. **Invalid credentials**: Verify cloud provider credentials
4. **Network connectivity**: Ensure CloudHawk can reach cloud APIs
5. **File permissions**: Check that CloudHawk can read configuration files

## Security Best Practices

1. **Use environment variables** for sensitive data
2. **Restrict file permissions** on configuration files
3. **Use IAM roles** instead of access keys when possible
4. **Enable MFA** for cloud provider accounts
5. **Regular credential rotation**
6. **Monitor configuration changes**
7. **Use secrets management** services (AWS Secrets Manager, Azure Key Vault, etc.)

## Troubleshooting

### Common Issues

1. **Configuration not loading**: Check file path and permissions
2. **Cloud provider errors**: Verify credentials and permissions
3. **Alert delivery failures**: Check SMTP/Slack configuration
4. **Performance issues**: Adjust worker count and timeouts
5. **Memory usage**: Monitor cache size and data retention

### Debug Mode

Enable debug mode for detailed logging:

```yaml
debug: true
log_level: "DEBUG"
```

### Configuration Testing

Test your configuration:

```bash
# Validate configuration
python -m cloudhawk.config.validate

# Test cloud provider connectivity
python -m cloudhawk.config.test_connectivity

# Test alerting
python -m cloudhawk.config.test_alerts
```

## Example Configurations

### Development Environment

```yaml
# Minimal configuration for development
version: "1.0"
debug: true
log_level: "DEBUG"

cloud_providers:
  aws:
    enabled: true
    regions: ["us-east-1"]
    access_key: "dev-access-key"
    secret_key: "dev-secret-key"

detection:
  enabled: true
  scan_interval: 1800  # 30 minutes
  rules_file: "src/detection/rules.yaml"

alerting:
  enabled: false  # Disable alerts in dev

web_dashboard:
  enabled: true
  host: "127.0.0.1"
  port: 8080
  debug: true
```

### Production Environment

```yaml
# Production-ready configuration
version: "1.0"
debug: false
log_level: "INFO"

cloud_providers:
  aws:
    enabled: true
    regions: ["us-east-1", "us-west-2", "eu-west-1"]
    role_arn: "arn:aws:iam::123456789012:role/CloudHawkRole"
    external_id: "unique-external-id"

detection:
  enabled: true
  scan_interval: 3600  # 1 hour
  rules_file: "src/detection/rules.yaml"
  anomaly_detection: true
  vulnerability_scanning: true

alerting:
  enabled: true
  email:
    enabled: true
    smtp_server: "smtp.company.com"
    username: "cloudhawk@company.com"
    to_addresses: ["security@company.com"]
  slack:
    enabled: true
    webhook_url: "https://hooks.slack.com/services/YOUR_WORKSPACE_ID/YOUR_CHANNEL_ID/YOUR_WEBHOOK_TOKEN"
    channel: "#security-alerts"

web_dashboard:
  enabled: true
  host: "0.0.0.0"
  port: 8080
  ssl_enabled: true
  ssl_cert: "/etc/ssl/certs/cloudhawk.crt"
  ssl_key: "/etc/ssl/private/cloudhawk.key"
  auth_enabled: true
  username: "admin"
  password: "secure_password"

logging:
  level: "INFO"
  file: "/var/log/cloudhawk/cloudhawk.log"
  max_size: "50MB"
  backup_count: 10

performance:
  max_workers: 8
  scan_timeout: 600
  cache_enabled: true
  cache_ttl: 7200

data_retention:
  scan_results: 90
  logs: 180
  alerts: 365
  cleanup_enabled: true
```

## Configuration Management

### Version Control

- Store configuration files in version control
- Use separate configurations for different environments
- Document all custom rules and settings
- Review configuration changes before deployment

### Configuration Templates

Create templates for different environments:

```bash
# Development template
cp config.dev.yaml config.yaml

# Production template  
cp config.prod.yaml config.yaml

# Staging template
cp config.staging.yaml config.yaml
```

### Configuration Backup

Regularly backup your configuration:

```bash
# Backup current configuration
cp config.yaml config.backup.$(date +%Y%m%d).yaml

# Restore from backup
cp config.backup.20240101.yaml config.yaml
```

This completes the CloudHawk Configuration Guide. For more specific examples and advanced configurations, refer to the individual component documentation.
