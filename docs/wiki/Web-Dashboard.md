# 🖥️ Web Dashboard Guide

The CloudHawk web dashboard provides a modern, responsive interface for monitoring your cloud security posture. This guide covers all features and functionality.

## 🚀 Getting Started

### Accessing the Dashboard
1. Start CloudHawk: `python src/web/app.py`
2. Open your browser to `http://localhost:5000`
3. You'll see the main dashboard with your security overview

### First-Time Setup
- **Configure Cloud Providers**: Set up AWS, Azure, or GCP access
- **Run Initial Scan**: Start your first security scan
- **Set Up Alerting**: Configure email and Slack notifications

## 📊 Dashboard Overview

### Main Dashboard
The dashboard provides a comprehensive view of your security posture:

#### **Security Score**
- **90-100**: Excellent security posture
- **70-89**: Good with minor issues
- **50-69**: Moderate risk, needs attention
- **0-49**: High risk, immediate action required

#### **Active Alerts**
- **Critical**: Immediate attention required
- **High**: Important security issues
- **Medium**: Moderate security concerns
- **Low**: Best practice recommendations

#### **Cloud Provider Status**
- **AWS**: Connection status and recent activity
- **Azure**: Subscription status and health
- **GCP**: Project status and monitoring

#### **Recent Activity**
- Latest security scans
- New alerts discovered
- System health updates

## 🎯 Navigation Menu

### Dashboard
- **Overview**: Security score and summary
- **Metrics**: Key performance indicators
- **Trends**: Security posture over time
- **Health**: System health and status

### Alerts
- **All Alerts**: Complete list of security issues
- **Filter by Severity**: Critical, High, Medium, Low
- **Filter by Service**: AWS, Azure, GCP services
- **Search**: Find specific alerts
- **Export**: Download alert reports

### Scan
- **Run Scans**: Start security scans
- **Scan History**: Previous scan results
- **Scheduled Scans**: Automated scanning
- **Scan Configuration**: Customize scan parameters

### Rules
- **Detection Rules**: Security rule management
- **Custom Rules**: Create organization-specific rules
- **Rule Categories**: Group rules by type
- **Rule Testing**: Test rule effectiveness

### Health
- **System Health**: Overall system status
- **Performance**: Resource usage and performance
- **Logs**: System and application logs
- **Monitoring**: Real-time system monitoring

### Config
- **Cloud Providers**: AWS, Azure, GCP configuration
- **Alerting**: Email and Slack settings
- **Performance**: System performance tuning
- **Security**: Access control and authentication

## 🔍 Alerts Management

### Viewing Alerts
The alerts page shows all discovered security issues:

#### **Alert List**
- **Severity Badge**: Color-coded severity levels
- **Title**: Clear description of the issue
- **Service**: Which cloud service is affected
- **Timestamp**: When the issue was detected
- **Status**: Active, Resolved, or Acknowledged

#### **Alert Details**
Click on any alert to see:
- **Description**: Detailed explanation
- **Remediation**: Step-by-step fix instructions
- **Affected Resources**: Specific resources involved
- **Compliance**: Related compliance requirements

### Filtering and Search
- **Severity Filter**: Show only specific severity levels
- **Service Filter**: Filter by cloud service
- **Date Range**: Show alerts from specific time periods
- **Search**: Find alerts by title or description
- **Sort**: Sort by severity, date, or service

### Alert Actions
- **Acknowledge**: Mark alert as reviewed
- **Resolve**: Mark alert as fixed
- **Export**: Download alert details
- **Share**: Send alert to team members

## 🔍 Security Scanning

### Running Scans
The scan page allows you to run security scans:

#### **Cloud Provider Selection**
- **AWS**: Select AWS regions and services
- **Azure**: Choose Azure subscriptions
- **GCP**: Select GCP projects

#### **Service Selection**
- **AWS Services**: EC2, S3, IAM, CloudTrail, GuardDuty
- **Azure Services**: Virtual Machines, Storage, Key Vault, Security Center
- **GCP Services**: Compute Engine, Cloud Storage, IAM, Security Command Center

#### **Scan Configuration**
- **Scan Depth**: Quick scan vs. comprehensive scan
- **Time Range**: Scan specific time periods
- **Custom Rules**: Include custom detection rules
- **Scheduling**: Set up automated scans

### Scan Results
After running a scan, you'll see:
- **Scan Summary**: Total issues found
- **Severity Breakdown**: Issues by severity level
- **Service Breakdown**: Issues by cloud service
- **Detailed Results**: Individual security issues

## ⚙️ Rules Management

### Detection Rules
The rules page shows all available security rules:

#### **Rule Categories**
- **IAM Security**: Identity and access management rules
- **Data Protection**: Data security and encryption rules
- **Network Security**: Network configuration rules
- **Compliance**: Regulatory compliance rules

#### **Rule Details**
Each rule includes:
- **Rule ID**: Unique identifier
- **Title**: Rule name and description
- **Service**: Which cloud service it applies to
- **Severity**: Risk level when triggered
- **Condition**: Detection logic
- **Remediation**: Fix instructions

### Custom Rules
Create organization-specific rules:

#### **Rule Creation**
- **Rule ID**: Unique identifier
- **Title**: Descriptive name
- **Description**: Detailed explanation
- **Service**: Target cloud service
- **Condition**: Detection logic
- **Severity**: Risk level
- **Remediation**: Fix instructions

#### **Rule Testing**
- **Test Rules**: Validate rule logic
- **Rule Performance**: Monitor rule effectiveness
- **Rule Updates**: Modify existing rules

## 🔔 Alerting Configuration

### Email Alerts
Configure email notifications:

#### **SMTP Settings**
- **SMTP Server**: Your email server
- **Port**: SMTP port (usually 587)
- **Authentication**: Username and password
- **From Address**: Sender email
- **To Address**: Recipient email

#### **Alert Preferences**
- **Severity Filter**: Which alerts to send
- **Frequency**: How often to send alerts
- **Format**: Email format and styling
- **Consolidation**: Group alerts by service

### Slack Notifications
Set up Slack integration:

#### **Webhook Configuration**
- **Webhook URL**: Slack webhook URL
- **Channel**: Target Slack channel
- **Username**: Bot username
- **Icon**: Bot icon and emoji

#### **Notification Settings**
- **Severity Filter**: Alert severity levels
- **Frequency**: Notification frequency
- **Format**: Message format and styling

## 🎨 User Interface

### Theme Toggle
- **Light Theme**: Clean, bright interface
- **Dark Theme**: Dark, easy-on-eyes interface
- **Auto-Save**: Your preference is saved automatically

### Responsive Design
- **Desktop**: Full-featured interface
- **Tablet**: Optimized for tablet use
- **Mobile**: Mobile-friendly interface

### Accessibility
- **Keyboard Navigation**: Full keyboard support
- **Screen Reader**: Compatible with screen readers
- **High Contrast**: High contrast mode support
- **Font Size**: Adjustable font sizes

## 📊 Analytics and Reporting

### Security Metrics
- **Security Score**: Overall security posture
- **Alert Trends**: Security issues over time
- **Compliance Status**: Regulatory compliance tracking
- **Risk Assessment**: Security risk analysis

### Performance Metrics
- **Scan Performance**: Scan speed and efficiency
- **System Performance**: Resource usage and performance
- **Detection Rate**: Security rule effectiveness
- **False Positive Rate**: Rule accuracy metrics

### Reports
- **Security Reports**: Comprehensive security analysis
- **Compliance Reports**: Regulatory compliance status
- **Executive Summary**: High-level security overview
- **Detailed Analysis**: In-depth security assessment

## 🔧 Advanced Features

### API Integration
- **RESTful API**: Programmatic access to CloudHawk
- **Webhooks**: Real-time event notifications
- **SDK**: Software development kits
- **Documentation**: Complete API documentation

### Automation
- **Scheduled Scans**: Automated security scanning
- **Alert Automation**: Automated alert responses
- **Integration**: Third-party tool integration
- **Workflows**: Custom security workflows

### Team Collaboration
- **User Management**: Team member access
- **Role-Based Access**: Different permission levels
- **Sharing**: Share alerts and reports
- **Notifications**: Team notification settings

## 🚨 Troubleshooting

### Common Issues

#### 1. Dashboard Not Loading
- **Check**: CloudHawk is running
- **Verify**: Port 5000 is accessible
- **Solution**: Restart CloudHawk service

#### 2. Alerts Not Showing
- **Check**: Security scans have been run
- **Verify**: Alert filters are not too restrictive
- **Solution**: Run a new security scan

#### 3. Configuration Issues
- **Check**: Configuration files are valid
- **Verify**: Cloud provider credentials
- **Solution**: Review configuration settings

### Getting Help
1. **Check Logs**: Review system logs
2. **Verify Configuration**: Ensure proper setup
3. **Test Connectivity**: Verify cloud provider access
4. **Contact Support**: [GitHub Issues](https://github.com/vatshariyani/cloudhawk/issues)

## 📞 Support

- **Documentation**: This wiki and API documentation
- **Issues**: [GitHub Issues](https://github.com/vatshariyani/cloudhawk/issues)
- **Discussions**: [GitHub Discussions](https://github.com/vatshariyani/cloudhawk/discussions)
- **Email**: support@cloudhawk.dev

---

**Next Steps**: Learn about [API Reference](API-Reference.md) for programmatic access or [Custom Rules](Custom-Rules.md) for advanced detection!
