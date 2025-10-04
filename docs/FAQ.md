# ❓ Frequently Asked Questions

This FAQ addresses the most common questions about CloudHawk installation, configuration, and usage.

## 🚀 Installation & Setup

### Q: What are the system requirements for CloudHawk?
**A:** CloudHawk requires:
- **Python**: 3.8+ (3.11+ recommended)
- **Memory**: 512MB minimum (2GB recommended)
- **Storage**: 1GB free space
- **Network**: Internet access for cloud API calls
- **Operating System**: Windows, macOS, or Linux

### Q: How do I install CloudHawk?
**A:** There are several installation methods:

#### Option 1: Pre-built Docker Image (Recommended)
```bash
# Clone and setup
git clone https://github.com/vatshariyani/cloudhawk.git
cd cloudhawk
./scripts/docker-deploy.sh setup

# Edit .env with your credentials
nano .env

# Start CloudHawk
./scripts/docker-deploy.sh start
```

#### Option 2: Build from Source
```bash
# Docker Compose
git clone https://github.com/vatshariyani/cloudhawk.git
cd cloudhawk
docker-compose up -d

# Manual Docker build
docker build -f deployment/Dockerfile -t cloudhawk .
docker run -d -p 5000:5000 cloudhawk
```

#### Option 3: Python Installation
```bash
git clone https://github.com/vatshariyani/cloudhawk.git
cd cloudhawk
pip install -r requirements.txt
python setup.py
```

### Q: Can I run CloudHawk in Docker?
**A:** Yes! CloudHawk is fully containerized with multiple deployment options:

#### Pre-built Image (Easiest)
```bash
# Setup and start
./scripts/docker-deploy.sh setup
./scripts/docker-deploy.sh start
```

#### Build from Source
```bash
# Docker Compose
docker-compose up -d

# Manual build
docker build -f deployment/Dockerfile -t cloudhawk .
docker run -d -p 5000:5000 cloudhawk
```

#### Production Deployment
```bash
# Use production compose file
docker-compose -f docker-compose.prod.yml up -d
```

### Q: What cloud providers does CloudHawk support?
**A:** CloudHawk supports:
- **AWS**: EC2, S3, IAM, CloudTrail, GuardDuty, VPC
- **Azure**: Virtual Machines, Storage, Key Vault, Security Center
- **GCP**: Compute Engine, Cloud Storage, IAM, Security Command Center

### Q: How do I use the pre-built Docker image?
**A:** The pre-built image is the easiest way to deploy CloudHawk:

```bash
# Setup CloudHawk
./scripts/docker-deploy.sh setup

# Edit .env file with your credentials
nano .env

# Start CloudHawk
./scripts/docker-deploy.sh start

# Access at http://localhost:5000
```

### Q: How do I update CloudHawk when using Docker?
**A:** To update to the latest version:

```bash
# Pull latest image
./scripts/docker-deploy.sh pull

# Restart with new image
./scripts/docker-deploy.sh restart

# Or manually
docker-compose -f docker-compose.prod.yml pull
docker-compose -f docker-compose.prod.yml up -d
```

### Q: How do I configure cloud credentials in Docker?
**A:** You can provide credentials in several ways:

#### Environment Variables (Recommended)
```bash
# In your .env file
AWS_ACCESS_KEY_ID=your_access_key
AWS_SECRET_ACCESS_KEY=your_secret_key
AWS_DEFAULT_REGION=us-east-1
```

#### Credentials Files
```bash
# Mount credentials files
docker run -v ~/.aws:/opt/cloudhawk/config/aws:ro cloudhawk
```

#### Docker Secrets
```bash
# Use Docker secrets for production
echo "your_secret" | docker secret create aws_secret_key -
```

## ⚙️ Configuration

### Q: How do I configure AWS access?
**A:** You can configure AWS in several ways:
```bash
# Method 1: AWS CLI
aws configure

# Method 2: Environment variables
export AWS_ACCESS_KEY_ID=your_key
export AWS_SECRET_ACCESS_KEY=your_secret

# Method 3: IAM Role (for EC2)
# Attach IAM role to EC2 instance
```

### Q: How do I configure Azure access?
**A:** Configure Azure using:
```bash
# Method 1: Azure CLI
az login
az account set --subscription "your-subscription-id"

# Method 2: Service Principal
export AZURE_CLIENT_ID=your_client_id
export AZURE_CLIENT_SECRET=your_client_secret
export AZURE_TENANT_ID=your_tenant_id
```

### Q: How do I configure GCP access?
**A:** Set up GCP access with:
```bash
# Method 1: Google Cloud SDK
gcloud auth login
gcloud config set project your-project-id

# Method 2: Service Account
export GOOGLE_APPLICATION_CREDENTIALS=path/to/service-account.json
```

### Q: What permissions does CloudHawk need?
**A:** CloudHawk needs read-only permissions:

**AWS Permissions:**
- CloudTrail: DescribeTrails, GetTrail, LookupEvents
- IAM: ListUsers, ListRoles, ListPolicies
- S3: ListAllMyBuckets, GetBucketPolicy
- EC2: DescribeInstances, DescribeSecurityGroups
- GuardDuty: ListDetectors, GetFindings

**Azure Permissions:**
- Reader role for resources
- Security Reader for Security Center
- Key Vault Reader for Key Vault

**GCP Permissions:**
- Viewer role for basic access
- Security Center Admin for Security Command Center
- Cloud Asset Viewer for Asset Inventory

## 🔔 Alerting & Notifications

### Q: How do I set up email alerts?
**A:** Configure email in the web dashboard:
1. Go to **Config** → **Email Settings**
2. Enter SMTP details (Gmail, Office 365, etc.)
3. Click **"Save Config"**
4. Test with **"Debug Email"**

### Q: How do I set up Slack notifications?
**A:** Set up Slack integration:
1. Create a Slack webhook URL
2. Go to **Config** → **Slack Settings**
3. Enter webhook URL and channel
4. Enable Slack alerts

### Q: Why aren't my email alerts working?
**A:** Common issues and solutions:

**Gmail Issues:**
- Use App Password, not regular password
- Enable 2-factor authentication
- Check SMTP settings: smtp.gmail.com:587

**Office 365 Issues:**
- Use smtp.office365.com:587
- Check authentication settings
- Verify account permissions

**General Issues:**
- Check firewall settings
- Verify SMTP server accessibility
- Test with debug email function

### Q: How do I customize alert content?
**A:** CloudHawk sends consolidated emails by service:
- **One email per service** (e.g., all EC2 alerts in one email)
- **Severity breakdown** per service
- **Detailed alert information** with remediation steps
- **Rule IDs and timestamps** for tracking

## 🔍 Security Scanning

### Q: How often should I run security scans?
**A:** Recommended scanning frequency:
- **Critical environments**: Every 4-6 hours
- **Production environments**: Daily
- **Development environments**: Weekly
- **Compliance requirements**: As needed

### Q: What security issues does CloudHawk detect?
**A:** CloudHawk detects 1000+ security issues:

**Critical Issues:**
- Public S3 buckets with sensitive data
- Root account usage
- Unencrypted storage
- Overly permissive IAM policies

**High Issues:**
- Security groups allowing all traffic
- Unused access keys
- Missing MFA on admin accounts
- Unencrypted data at rest

**Medium Issues:**
- Outdated security policies
- Unused resources
- Missing logging
- Non-compliant configurations

### Q: How do I create custom security rules?
**A:** Create custom rules in `security_rules.yaml`:
```yaml
- id: CUSTOM-001
  title: "Custom Security Rule"
  description: "Detects specific security condition"
  service: "AWS_S3"
  condition: "bucket.policy.contains('Principal:*')"
  severity: "HIGH"
  remediation: "Restrict bucket access to specific principals"
```

### Q: How accurate are the security detections?
**A:** CloudHawk provides:
- **High accuracy**: 95%+ for well-defined rules
- **Low false positives**: <5% for critical alerts
- **Continuous improvement**: Rules updated based on feedback
- **Customizable**: Adjust rules for your environment

## 📊 Web Dashboard

### Q: How do I access the web dashboard?
**A:** Access the dashboard:
1. Start CloudHawk: `python src/web/app.py`
2. Open browser to `http://localhost:5000`
3. Use different port if needed: `--port 8080`

### Q: Can I use the dashboard on mobile devices?
**A:** Yes! The dashboard is fully responsive:
- **Mobile-friendly**: Optimized for smartphones
- **Tablet-optimized**: Great experience on tablets
- **Touch-friendly**: Easy navigation on touch devices

### Q: How do I change the theme?
**A:** Click the **theme button** in the top navigation:
- **Light theme**: Clean, bright interface
- **Dark theme**: Easy-on-eyes interface
- **Auto-save**: Your preference is saved automatically

### Q: Can multiple users access the dashboard?
**A:** Currently, CloudHawk supports:
- **Single-user access**: One user at a time
- **Shared access**: Multiple users can access simultaneously
- **Future**: Role-based access control planned

## 🔧 Troubleshooting

### Q: Why is the dashboard not loading?
**A:** Common solutions:
1. **Check if CloudHawk is running**: `ps aux | grep python`
2. **Verify port availability**: `netstat -tlnp | grep 5000`
3. **Check firewall settings**: Ensure port 5000 is open
4. **Try different port**: `python src/web/app.py --port 8080`

### Q: Why aren't alerts showing up?
**A:** Possible causes:
1. **No scans run**: Run a security scan first
2. **No security issues**: Your infrastructure might be secure
3. **Filter settings**: Check alert filters
4. **Check logs**: Review system logs for errors

### Q: Why are scans failing?
**A:** Common issues:
1. **Authentication**: Check cloud provider credentials
2. **Permissions**: Verify required permissions
3. **Network**: Check internet connectivity
4. **Resources**: Ensure sufficient system resources

### Q: How do I check CloudHawk logs?
**A:** View logs with:
```bash
# View recent logs
tail -f logs/cloudhawk.log

# Search for errors
grep -i error logs/cloudhawk.log

# Check specific components
tail -f logs/aws_collector.log
tail -f logs/azure_collector.log
```

## 🚀 Performance

### Q: How much memory does CloudHawk use?
**A:** Memory usage depends on configuration:
- **Minimum**: 512MB for basic operation
- **Recommended**: 2GB for production use
- **Large environments**: 4GB+ for comprehensive scanning

### Q: How fast are security scans?
**A:** Scan speed depends on:
- **Environment size**: Number of resources
- **Scan depth**: Quick vs. comprehensive
- **Network speed**: API call latency
- **System resources**: CPU and memory

**Typical speeds:**
- **Small environment** (<100 resources): 1-2 minutes
- **Medium environment** (100-1000 resources): 5-10 minutes
- **Large environment** (1000+ resources): 15-30 minutes

### Q: Can I optimize CloudHawk performance?
**A:** Yes, several optimization options:
```yaml
# config.yaml
performance:
  max_workers: 4          # Adjust based on CPU cores
  batch_size: 1000        # Adjust based on memory
  cache_size: 10000      # Adjust based on available memory
  timeout: 300           # Adjust based on network speed
```

## 🔒 Security & Privacy

### Q: Is CloudHawk secure?
**A:** CloudHawk implements multiple security measures:
- **Read-only access**: Only reads cloud resources
- **Credential security**: Secure credential storage
- **Data encryption**: All data encrypted in transit and at rest
- **Audit logging**: Complete audit trail
- **No external data**: No data sent to external services

### Q: What data does CloudHawk collect?
**A:** CloudHawk collects:
- **Security configurations**: IAM policies, security groups, etc.
- **Access logs**: CloudTrail, Activity Logs, Audit Logs
- **Security findings**: GuardDuty, Security Center, SCC
- **Resource metadata**: Instance details, bucket policies, etc.

### Q: Where is data stored?
**A:** Data storage options:
- **Local storage**: JSON files in `logs/` directory
- **Database**: SQLite database (optional)
- **Cloud storage**: S3, Azure Blob, GCS (planned)
- **No external services**: Data stays in your environment

## 🤝 Support & Community

### Q: How do I get help?
**A:** Multiple support channels:
- **Documentation**: This wiki and README
- **GitHub Issues**: [Report bugs and request features](https://github.com/vatshariyani/cloudhawk/issues)
- **GitHub Discussions**: [Ask questions and share solutions](https://github.com/vatshariyani/cloudhawk/discussions)
- **Email**: support@cloudhawk.dev

### Q: How do I contribute to CloudHawk?
**A:** We welcome contributions:
1. **Fork the repository**
2. **Create a feature branch**
3. **Make your changes**
4. **Add tests for new functionality**
5. **Submit a pull request**

### Q: How do I report bugs?
**A:** When reporting bugs, please include:
- **System information**: OS, Python version, CloudHawk version
- **Steps to reproduce**: What you were doing when the issue occurred
- **Expected behavior**: What you expected to happen
- **Actual behavior**: What actually happened
- **Logs**: Relevant log entries
- **Configuration**: Non-sensitive configuration details

## 📈 Roadmap & Features

### Q: What features are planned?
**A:** Upcoming features:
- **v1.1**: Enhanced rule coverage and performance optimization
- **v1.2**: Additional cloud providers and services
- **v2.0**: ML-based anomaly detection
- **v2.1**: Kubernetes security monitoring
- **v2.2**: Compliance reporting (SOC2, PCI-DSS)

### Q: Can I request new features?
**A:** Yes! Feature requests are welcome:
- **GitHub Issues**: Create an issue with "enhancement" label
- **GitHub Discussions**: Discuss ideas with the community
- **Email**: Send detailed feature requests to support@cloudhawk.dev

### Q: How often is CloudHawk updated?
**A:** Update schedule:
- **Bug fixes**: As needed
- **Minor updates**: Monthly
- **Major releases**: Quarterly
- **Security updates**: Immediately

## 💰 Licensing & Commercial Use

### Q: Is CloudHawk free?
**A:** Yes! CloudHawk is:
- **Open source**: MIT license
- **Free to use**: No cost for personal or commercial use
- **Community-driven**: Developed by the community
- **No vendor lock-in**: Use with any cloud provider

### Q: Can I use CloudHawk commercially?
**A:** Yes! CloudHawk is:
- **MIT licensed**: Free for commercial use
- **No restrictions**: Use in any environment
- **Enterprise-ready**: Suitable for large organizations
- **Support available**: Professional support options

### Q: How do I get enterprise support?
**A:** Enterprise support options:
- **Email**: enterprise@cloudhawk.dev
- **Consulting**: Professional implementation services
- **Training**: Team training and workshops
- **Custom development**: Tailored solutions

---

**Still have questions?** Check our [Troubleshooting Guide](Troubleshooting.md) or [GitHub Discussions](https://github.com/vatshariyani/cloudhawk/discussions)!
