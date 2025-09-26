# 🛠️ Custom Rules Guide

Create organization-specific security rules to detect threats and misconfigurations unique to your environment. This guide covers rule creation, testing, and management.

## 📋 Rule Structure

### Basic Rule Format
```yaml
- id: "CUSTOM-001"
  title: "Custom Security Rule"
  description: "Detects specific security condition"
  service: "AWS_S3"
  severity: "HIGH"
  category: "Data Protection"
  condition: "bucket.policy.contains('Principal:*')"
  remediation: "Restrict bucket access to specific principals"
  tags: ["custom", "compliance"]
  enabled: true
```

### Rule Components

#### **Rule ID**
- **Format**: `CUSTOM-XXX` or `SERVICE-XXX`
- **Example**: `CUSTOM-001`, `S3-CUSTOM-001`
- **Uniqueness**: Must be unique across all rules

#### **Title**
- **Purpose**: Clear, descriptive name
- **Example**: "S3 Bucket Public Read Access"
- **Best Practice**: Use action-oriented language

#### **Description**
- **Purpose**: Detailed explanation of what the rule detects
- **Example**: "Detects S3 buckets that allow public read access"
- **Best Practice**: Include context and impact

#### **Service**
- **AWS Services**: `AWS_S3`, `AWS_EC2`, `AWS_IAM`, `AWS_CLOUDTRAIL`
- **Azure Services**: `AZURE_STORAGE`, `AZURE_VM`, `AZURE_KEYVAULT`
- **GCP Services**: `GCP_STORAGE`, `GCP_COMPUTE`, `GCP_IAM`

#### **Severity Levels**
- **CRITICAL**: Immediate security risk
- **HIGH**: Significant security concern
- **MEDIUM**: Moderate security issue
- **LOW**: Best practice recommendation

#### **Categories**
- **Data Protection**: Encryption, access controls
- **Network Security**: Firewalls, security groups
- **Identity & Access**: IAM, RBAC, authentication
- **Compliance**: SOC2, PCI-DSS, HIPAA
- **Cost Optimization**: Unused resources, over-provisioning

## 🔍 Condition Syntax

### Basic Conditions
```yaml
# String contains
condition: "bucket.policy.contains('Principal:*')"

# String equals
condition: "instance.state == 'running'"

# Numeric comparison
condition: "instance.age_days > 90"

# Boolean check
condition: "bucket.encryption_enabled == false"

# Array contains
condition: "security_group.rules.contains('0.0.0.0/0')"
```

### Advanced Conditions
```yaml
# Multiple conditions (AND)
condition: "bucket.public == true AND bucket.encryption_enabled == false"

# Multiple conditions (OR)
condition: "instance.state == 'running' OR instance.state == 'pending'"

# Nested properties
condition: "bucket.policy.statement.effect == 'Allow'"

# Regular expressions
condition: "instance.name.matches('prod-.*')"

# Function calls
condition: "instance.age_days > 30 AND instance.tags.contains('production')"
```

### Available Properties

#### **AWS S3 Properties**
```yaml
bucket:
  name: "string"
  region: "string"
  public: boolean
  encryption_enabled: boolean
  versioning_enabled: boolean
  mfa_delete_enabled: boolean
  policy: object
  acl: object
  tags: object
  created_date: "datetime"
  last_modified: "datetime"
```

#### **AWS EC2 Properties**
```yaml
instance:
  id: "string"
  name: "string"
  state: "string"
  type: "string"
  public_ip: "string"
  private_ip: "string"
  security_groups: array
  key_name: "string"
  tags: object
  created_date: "datetime"
  age_days: number
```

#### **AWS IAM Properties**
```yaml
user:
  name: "string"
  access_keys: array
  policies: array
  groups: array
  last_login: "datetime"
  mfa_enabled: boolean
  password_age_days: number
  tags: object
```

#### **Azure Storage Properties**
```yaml
storage_account:
  name: "string"
  resource_group: "string"
  location: "string"
  public_access: "string"
  encryption_enabled: boolean
  https_required: boolean
  tags: object
  created_date: "datetime"
```

#### **GCP Storage Properties**
```yaml
bucket:
  name: "string"
  location: "string"
  public: boolean
  encryption_enabled: boolean
  versioning_enabled: boolean
  lifecycle_rules: array
  iam_policy: object
  labels: object
  created_date: "datetime"
```

## 🎯 Rule Examples

### AWS S3 Rules
```yaml
# Public S3 bucket
- id: "S3-PUBLIC-001"
  title: "S3 Bucket Public Access"
  description: "Detects S3 buckets with public read access"
  service: "AWS_S3"
  severity: "CRITICAL"
  condition: "bucket.public == true"
  remediation: "Remove public access and use IAM policies"

# Unencrypted S3 bucket
- id: "S3-ENCRYPTION-001"
  title: "S3 Bucket Not Encrypted"
  description: "Detects S3 buckets without encryption"
  service: "AWS_S3"
  severity: "HIGH"
  condition: "bucket.encryption_enabled == false"
  remediation: "Enable server-side encryption"

# S3 bucket without versioning
- id: "S3-VERSIONING-001"
  title: "S3 Bucket Versioning Disabled"
  description: "Detects S3 buckets without versioning"
  service: "AWS_S3"
  severity: "MEDIUM"
  condition: "bucket.versioning_enabled == false"
  remediation: "Enable versioning for data protection"
```

### AWS EC2 Rules
```yaml
# EC2 instance with public IP
- id: "EC2-PUBLIC-IP-001"
  title: "EC2 Instance Public IP"
  description: "Detects EC2 instances with public IP addresses"
  service: "AWS_EC2"
  severity: "HIGH"
  condition: "instance.public_ip != null"
  remediation: "Use private IPs or NAT gateway"

# EC2 instance without encryption
- id: "EC2-ENCRYPTION-001"
  title: "EC2 Instance Not Encrypted"
  description: "Detects EC2 instances without encryption"
  service: "AWS_EC2"
  severity: "HIGH"
  condition: "instance.encryption_enabled == false"
  remediation: "Enable EBS encryption"

# Old EC2 instances
- id: "EC2-AGE-001"
  title: "Old EC2 Instance"
  description: "Detects EC2 instances older than 90 days"
  service: "AWS_EC2"
  severity: "LOW"
  condition: "instance.age_days > 90"
  remediation: "Review and potentially terminate old instances"
```

### AWS IAM Rules
```yaml
# IAM user with admin access
- id: "IAM-ADMIN-001"
  title: "IAM User with Admin Access"
  description: "Detects IAM users with administrative privileges"
  service: "AWS_IAM"
  severity: "HIGH"
  condition: "user.policies.contains('AdministratorAccess')"
  remediation: "Apply principle of least privilege"

# IAM user without MFA
- id: "IAM-MFA-001"
  title: "IAM User without MFA"
  description: "Detects IAM users without MFA enabled"
  service: "AWS_IAM"
  severity: "HIGH"
  condition: "user.mfa_enabled == false"
  remediation: "Enable MFA for all IAM users"

# Old IAM access keys
- id: "IAM-KEY-AGE-001"
  title: "Old IAM Access Key"
  description: "Detects IAM access keys older than 90 days"
  service: "AWS_IAM"
  severity: "MEDIUM"
  condition: "user.access_keys.age_days > 90"
  remediation: "Rotate access keys regularly"
```

### Azure Rules
```yaml
# Azure storage account public access
- id: "AZURE-STORAGE-PUBLIC-001"
  title: "Azure Storage Account Public Access"
  description: "Detects Azure storage accounts with public access"
  service: "AZURE_STORAGE"
  severity: "CRITICAL"
  condition: "storage_account.public_access != 'None'"
  remediation: "Restrict public access to storage accounts"

# Azure VM without encryption
- id: "AZURE-VM-ENCRYPTION-001"
  title: "Azure VM Not Encrypted"
  description: "Detects Azure VMs without encryption"
  service: "AZURE_VM"
  severity: "HIGH"
  condition: "vm.encryption_enabled == false"
  remediation: "Enable disk encryption for VMs"
```

### GCP Rules
```yaml
# GCP bucket public access
- id: "GCP-BUCKET-PUBLIC-001"
  title: "GCP Bucket Public Access"
  description: "Detects GCP buckets with public access"
  service: "GCP_STORAGE"
  severity: "CRITICAL"
  condition: "bucket.public == true"
  remediation: "Remove public access and use IAM policies"

# GCP instance without encryption
- id: "GCP-INSTANCE-ENCRYPTION-001"
  title: "GCP Instance Not Encrypted"
  description: "Detects GCP instances without encryption"
  service: "GCP_COMPUTE"
  severity: "HIGH"
  condition: "instance.encryption_enabled == false"
  remediation: "Enable disk encryption for instances"
```

## 🧪 Testing Rules

### Rule Testing
```bash
# Test a specific rule
python src/detection/rule_engine.py --test-rule CUSTOM-001

# Test all custom rules
python src/detection/rule_engine.py --test-custom-rules

# Test rules against sample data
python src/detection/rule_engine.py --test-data sample_data.json
```

### Rule Validation
```bash
# Validate rule syntax
python src/detection/rule_engine.py --validate-rules

# Check rule dependencies
python src/detection/rule_engine.py --check-dependencies
```

### Performance Testing
```bash
# Test rule performance
python src/detection/rule_engine.py --benchmark-rules

# Test with large datasets
python src/detection/rule_engine.py --stress-test
```

## 📊 Rule Management

### Adding Rules
```bash
# Add rule via API
curl -X POST "http://localhost:5000/api/rules" \
  -H "Content-Type: application/json" \
  -d '{
    "title": "Custom Security Rule",
    "description": "Detects specific security condition",
    "service": "AWS_S3",
    "severity": "HIGH",
    "condition": "bucket.policy.contains('Principal:*')",
    "remediation": "Restrict bucket access to specific principals"
  }'
```

### Updating Rules
```bash
# Update rule via API
curl -X PUT "http://localhost:5000/api/rules/CUSTOM-001" \
  -H "Content-Type: application/json" \
  -d '{
    "enabled": false,
    "severity": "MEDIUM"
  }'
```

### Deleting Rules
```bash
# Delete rule via API
curl -X DELETE "http://localhost:5000/api/rules/CUSTOM-001"
```

## 🔧 Advanced Features

### Rule Dependencies
```yaml
# Rule with dependencies
- id: "CUSTOM-002"
  title: "Complex Security Rule"
  description: "Detects complex security condition"
  service: "AWS_S3"
  severity: "HIGH"
  condition: "bucket.public == true AND bucket.encryption_enabled == false"
  remediation: "Remove public access and enable encryption"
  dependencies: ["S3-PUBLIC-001", "S3-ENCRYPTION-001"]
  enabled: true
```

### Rule Categories
```yaml
# Group rules by category
categories:
  - name: "Data Protection"
    description: "Rules for data security and encryption"
    rules: ["S3-ENCRYPTION-001", "S3-VERSIONING-001"]
  
  - name: "Access Control"
    description: "Rules for access management"
    rules: ["IAM-ADMIN-001", "IAM-MFA-001"]
  
  - name: "Network Security"
    description: "Rules for network configuration"
    rules: ["EC2-PUBLIC-IP-001", "EC2-SECURITY-GROUP-001"]
```

### Rule Tags
```yaml
# Rules with tags
- id: "CUSTOM-003"
  title: "Compliance Rule"
  description: "Detects compliance violations"
  service: "AWS_S3"
  severity: "HIGH"
  condition: "bucket.policy.contains('Principal:*')"
  remediation: "Restrict bucket access to specific principals"
  tags: ["compliance", "soc2", "pci-dss"]
  enabled: true
```

## 📈 Rule Performance

### Optimization Tips
1. **Use specific conditions**: Avoid broad conditions when possible
2. **Index frequently used properties**: Cache common property lookups
3. **Avoid complex regex**: Use simple string operations when possible
4. **Test with real data**: Validate rules against actual cloud resources

### Performance Monitoring
```bash
# Monitor rule performance
python src/detection/rule_engine.py --monitor-performance

# Check rule execution times
python src/detection/rule_engine.py --execution-times
```

## 🔒 Security Considerations

### Rule Security
- **Validate conditions**: Ensure conditions are safe to execute
- **Sanitize inputs**: Prevent injection attacks in conditions
- **Limit complexity**: Avoid overly complex conditions
- **Test thoroughly**: Validate rules before deployment

### Access Control
- **Rule permissions**: Control who can create/modify rules
- **Audit logging**: Log all rule changes
- **Version control**: Track rule changes over time
- **Approval process**: Require approval for rule changes

## 📚 Best Practices

### Rule Design
1. **Clear naming**: Use descriptive rule IDs and titles
2. **Detailed descriptions**: Explain what the rule detects
3. **Actionable remediation**: Provide clear fix instructions
4. **Appropriate severity**: Match severity to actual risk
5. **Regular review**: Periodically review and update rules

### Rule Testing
1. **Test with sample data**: Validate rules with known good/bad data
2. **Performance testing**: Ensure rules don't impact system performance
3. **Edge case testing**: Test with unusual or boundary conditions
4. **Integration testing**: Test rules in the full system

### Rule Maintenance
1. **Version control**: Track rule changes over time
2. **Documentation**: Document rule purpose and usage
3. **Regular updates**: Keep rules current with cloud provider changes
4. **Deprecation**: Properly deprecate old rules

## 📞 Support

- **Rule Examples**: Check the examples in this guide
- **GitHub Issues**: [Report rule issues](https://github.com/vatshariyani/cloudhawk/issues)
- **Discussions**: [Ask rule questions](https://github.com/vatshariyani/cloudhawk/discussions)
- **Email**: rules-support@cloudhawk.dev

---

**Next Steps**: Learn about [API Reference](API-Reference.md) for programmatic rule management or [Web Dashboard](Web-Dashboard.md) for UI-based rule management!
