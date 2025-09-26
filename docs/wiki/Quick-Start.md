# 🚀 Quick Start Guide

Get up and running with CloudHawk in just a few minutes! This guide will walk you through your first security scan and show you how to use the web dashboard.

## ⚡ 5-Minute Setup

### Step 1: Install CloudHawk
```bash
# Clone the repository
git clone https://github.com/vatshariyani/cloudhawk.git
cd cloudhawk

# Install dependencies
pip install -r requirements.txt
```

### Step 2: Configure Cloud Access
```bash
# For AWS (choose one method)
aws configure
# OR
export AWS_ACCESS_KEY_ID=your_key
export AWS_SECRET_ACCESS_KEY=your_secret

# For Azure
az login

# For GCP
gcloud auth login
```

### Step 3: Start CloudHawk
```bash
# Start the web dashboard
python src/web/app.py

# Open your browser to http://localhost:5000
```

## 🎯 Your First Security Scan

### 1. Access the Web Dashboard
- Open your browser to `http://localhost:5000`
- You'll see the CloudHawk dashboard with a modern, responsive interface

### 2. Configure Your First Scan
- Click on **"Scan"** in the navigation menu
- Select your cloud provider (AWS, Azure, or GCP)
- Choose the services you want to scan:
  - **AWS**: EC2, S3, IAM, CloudTrail, GuardDuty
  - **Azure**: Virtual Machines, Storage, Key Vault, Security Center
  - **GCP**: Compute Engine, Cloud Storage, IAM, Security Command Center

### 3. Run the Scan
- Click **"Start Scan"** to begin the security analysis
- Monitor the progress in real-time
- View results as they're discovered

### 4. Review Security Alerts
- Navigate to **"Alerts"** to see discovered security issues
- Filter by severity: CRITICAL, HIGH, MEDIUM, LOW
- Click on individual alerts for detailed information

## 📊 Understanding the Dashboard

### Dashboard Overview
The main dashboard shows:
- **Security Score**: Overall health of your cloud infrastructure
- **Active Alerts**: Number of current security issues
- **Cloud Providers**: Status of each connected cloud
- **Recent Activity**: Latest security events and scans

### Navigation Menu
- **Dashboard**: Overview and summary
- **Alerts**: Security alerts and issues
- **Scan**: Run security scans
- **Rules**: Manage detection rules
- **Health**: System health and performance
- **Config**: Configuration settings

### Theme Toggle
- Click the **theme button** in the top navigation
- Switch between light and dark themes
- Your preference is saved automatically

## 🔍 Exploring Security Alerts

### Alert Types
CloudHawk detects various security issues:

#### **Critical Alerts** 🔴
- Public S3 buckets with sensitive data
- Root account usage
- Unencrypted storage
- Overly permissive IAM policies

#### **High Alerts** 🟠
- Security groups allowing all traffic
- Unused access keys
- Missing MFA on admin accounts
- Unencrypted data at rest

#### **Medium Alerts** 🟡
- Outdated security policies
- Unused resources
- Missing logging
- Non-compliant configurations

#### **Low Alerts** 🟢
- Best practice recommendations
- Optimization opportunities
- Minor configuration issues

### Alert Details
Each alert includes:
- **Title**: Clear description of the issue
- **Severity**: Risk level (CRITICAL, HIGH, MEDIUM, LOW)
- **Service**: Which cloud service is affected
- **Description**: Detailed explanation
- **Remediation**: Step-by-step fix instructions
- **Timestamp**: When the issue was detected

## ⚙️ Basic Configuration

### Email Alerts Setup
1. Go to **Config** → **Email Settings**
2. Enter your SMTP details:
   - SMTP Server: `smtp.gmail.com`
   - Port: `587`
   - Username: Your email
   - Password: Your app password
3. Click **"Save Config"**
4. Test with **"Debug Email"**

### Slack Notifications
1. Go to **Config** → **Slack Settings**
2. Enter your Slack webhook URL
3. Choose notification channel
4. Enable Slack alerts

## 🎯 Common Use Cases

### 1. Daily Security Monitoring
```bash
# Run daily security scan
python src/cli/cloudhawk_cli.py scan aws --region us-east-1

# Check for new alerts
python src/cli/cloudhawk_cli.py alerts --severity CRITICAL
```

### 2. Compliance Checking
- Review **Rules** section for compliance rules
- Filter alerts by compliance frameworks
- Generate compliance reports

### 3. Incident Response
- Monitor real-time alerts
- Filter by severity and service
- Use remediation steps to fix issues

### 4. Team Collaboration
- Set up email/Slack notifications
- Share dashboard access
- Create custom rules for your organization

## 🔧 Command Line Interface

### Basic Commands
```bash
# Run security scan
python src/cli/cloudhawk_cli.py scan aws

# View alerts
python src/cli/cloudhawk_cli.py alerts

# Show rules
python src/cli/cloudhawk_cli.py rules

# Start web dashboard
python src/cli/cloudhawk_cli.py web
```

### Advanced Options
```bash
# Scan specific services
python src/cli/cloudhawk_cli.py scan aws --services EC2,S3,IAM

# Filter alerts by severity
python src/cli/cloudhawk_cli.py alerts --severity HIGH,CRITICAL

# Export results
python src/cli/cloudhawk_cli.py export --format json
```

## 📈 Monitoring and Analytics

### Security Score
- **90-100**: Excellent security posture
- **70-89**: Good with minor issues
- **50-69**: Moderate risk, needs attention
- **0-49**: High risk, immediate action required

### Health Metrics
- **System Health**: Overall system performance
- **Collection Status**: Data collection success rate
- **Detection Rate**: Security rule effectiveness
- **Alert Volume**: Number of active alerts

### Trend Analysis
- **Security Trends**: Improvement over time
- **Alert Patterns**: Common security issues
- **Compliance Status**: Regulatory compliance tracking

## 🚨 Troubleshooting

### Common Issues

#### 1. "No alerts found"
- **Cause**: No security issues detected
- **Solution**: This is actually good! Your infrastructure is secure

#### 2. "Connection failed"
- **Cause**: Cloud provider authentication issues
- **Solution**: Check your cloud credentials and permissions

#### 3. "Scan failed"
- **Cause**: Insufficient permissions or network issues
- **Solution**: Verify cloud provider access and try again

### Getting Help
1. **Check logs**: `tail -f logs/cloudhawk.log`
2. **Verify configuration**: Review config.yaml
3. **Test connectivity**: Run individual collectors
4. **Contact support**: [GitHub Issues](https://github.com/vatshariyani/cloudhawk/issues)

## 🎯 Next Steps

### Immediate Actions
1. **Review Alerts**: Check all discovered security issues
2. **Fix Critical Issues**: Address CRITICAL and HIGH severity alerts
3. **Configure Notifications**: Set up email/Slack alerts
4. **Schedule Scans**: Set up regular security monitoring

### Advanced Features
1. **Custom Rules**: Create organization-specific detection rules
2. **API Integration**: Integrate with existing security tools
3. **Compliance Reporting**: Generate compliance reports
4. **Team Collaboration**: Set up team access and notifications

### Learning Resources
- [Configuration Guide](Configuration.md) - Detailed configuration options
- [Security Rules](Security-Rules.md) - Understanding detection rules
- [API Reference](API-Reference.md) - Integration and automation
- [Troubleshooting](Troubleshooting.md) - Common issues and solutions

## 🎉 Congratulations!

You've successfully set up CloudHawk and run your first security scan! 

**What's Next?**
- Explore the [Web Dashboard](Web-Dashboard.md) for detailed usage
- Configure [Alerting Setup](Alerting-Setup.md) for notifications
- Learn about [Custom Rules](Custom-Rules.md) for advanced detection
- Check out [API Reference](API-Reference.md) for automation

---

**Need Help?** Check out our [Troubleshooting Guide](Troubleshooting.md) or [FAQ](FAQ.md) for common questions!
