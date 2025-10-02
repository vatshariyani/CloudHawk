# 🚨 Troubleshooting Guide

This comprehensive troubleshooting guide helps you resolve common issues with CloudHawk installation, configuration, and operation.

## 🔍 Quick Diagnostics

### System Health Check
```bash
# Check CloudHawk status
curl http://localhost:5000/health

# Check system resources
python -c "import psutil; print(f'CPU: {psutil.cpu_percent()}%, Memory: {psutil.virtual_memory().percent}%')"

# Check disk space
df -h
```

### Log Analysis
```bash
# View recent logs
tail -f logs/cloudhawk.log

# Search for errors
grep -i error logs/cloudhawk.log

# Check specific component logs
tail -f logs/aws_collector.log
tail -f logs/azure_collector.log
tail -f logs/gcp_collector.log
```

## 🐛 Common Issues

### Installation Issues

#### 1. Python Version Issues
**Error**: `Python 3.8+ required`
```bash
# Check Python version
python --version

# Install Python 3.8+
# Ubuntu/Debian:
sudo apt update && sudo apt install python3.8

# macOS:
brew install python@3.8

# Windows: Download from python.org
```

#### 2. Missing Dependencies
**Error**: `ModuleNotFoundError: No module named 'azure'`
```bash
# Install all dependencies
pip install -r requirements.txt

# Install specific missing packages
pip install azure-identity azure-mgmt-resource

# For GCP
pip install google-cloud-storage google-cloud-compute
```

#### 3. Permission Errors
**Error**: `Permission denied`
```bash
# Fix file permissions
chmod +x bin/CloudHawk
chmod 755 src/
chmod 644 config.yaml

# Run with proper permissions
sudo python src/web/app.py
```

### Configuration Issues

#### 1. AWS Authentication Errors
**Error**: `AWS credentials not found`
```bash
# Check AWS credentials
aws sts get-caller-identity

# Configure AWS CLI
aws configure

# Set environment variables
export AWS_ACCESS_KEY_ID=your_key
export AWS_SECRET_ACCESS_KEY=your_secret
```

#### 2. Azure Authentication Errors
**Error**: `Azure authentication failed`
```bash
# Check Azure login
az account show

# Login to Azure
az login

# Set subscription
az account set --subscription "your-subscription-id"
```

#### 3. GCP Authentication Errors
**Error**: `GCP credentials not found`
```bash
# Check GCP authentication
gcloud auth list

# Login to GCP
gcloud auth login

# Set project
gcloud config set project your-project-id
```

### Web Dashboard Issues

#### 1. Dashboard Not Loading
**Error**: `Connection refused`
```bash
# Check if CloudHawk is running
ps aux | grep python

# Start CloudHawk
python src/web/app.py

# Check port availability
netstat -tlnp | grep 5000

# Use different port
python src/web/app.py --port 8080
```

#### 2. Alerts Not Showing
**Issue**: No alerts displayed
```bash
# Check if scans have been run
ls -la logs/

# Run a test scan
python test_security_detection.py

# Check alert data
cat alerts/alerts.json
```

#### 3. Configuration Not Saving
**Issue**: Settings not persisting
```bash
# Check file permissions
ls -la config.yaml
ls -la email_alert_config.json

# Fix permissions
chmod 644 config.yaml
chmod 644 email_alert_config.json

# Check disk space
df -h
```

### Cloud Provider Issues

#### 1. AWS API Errors
**Error**: `Access Denied`
```bash
# Check IAM permissions
aws iam get-user
aws iam list-attached-user-policies --user-name your-username

# Test specific permissions
aws s3 ls
aws ec2 describe-instances
aws iam list-users
```

#### 2. Azure API Errors
**Error**: `Insufficient privileges`
```bash
# Check Azure permissions
az role assignment list --assignee your-user-id

# Test specific permissions
az storage account list
az vm list
az keyvault list
```

#### 3. GCP API Errors
**Error**: `Permission denied`
```bash
# Check GCP permissions
gcloud projects get-iam-policy your-project-id

# Test specific permissions
gcloud storage buckets list
gcloud compute instances list
gcloud iam service-accounts list
```

### Alerting Issues

#### 1. Email Not Sending
**Error**: `SMTP authentication failed`
```bash
# Test email configuration
python -c "
import smtplib
server = smtplib.SMTP('smtp.gmail.com', 587)
server.starttls()
server.login('your-email@gmail.com', 'your-app-password')
print('Email configuration working')
server.quit()
"

# Check email config file
cat email_alert_config.json
```

#### 2. Slack Notifications Not Working
**Error**: `Slack webhook failed`
```bash
# Test Slack webhook
curl -X POST -H 'Content-type: application/json' \
  --data '{"text":"Test message"}' \
  YOUR_SLACK_WEBHOOK_URL

# Check Slack configuration
cat email_alert_config.json | grep slack
```

### Performance Issues

#### 1. Slow Scans
**Issue**: Scans taking too long
```bash
# Check system resources
top
htop

# Optimize configuration
# Reduce max_events_per_service in config.yaml
# Increase max_workers for parallel processing
```

#### 2. High Memory Usage
**Issue**: Memory consumption too high
```bash
# Monitor memory usage
python -c "
import psutil
print(f'Memory: {psutil.virtual_memory().percent}%')
print(f'Available: {psutil.virtual_memory().available / 1024**3:.1f} GB')
"

# Optimize memory settings
# Reduce cache_size in config.yaml
# Enable garbage collection
```

#### 3. Network Timeouts
**Issue**: API calls timing out
```bash
# Test network connectivity
ping google.com
curl -I https://api.aws.amazon.com

# Check proxy settings
echo $HTTP_PROXY
echo $HTTPS_PROXY

# Increase timeout in config.yaml
```

## 🔧 Advanced Troubleshooting

### Debug Mode
```bash
# Enable debug logging
export CLOUDHAWK_DEBUG=1
python src/web/app.py

# Verbose output
python src/web/app.py --verbose

# Trace all requests
python src/web/app.py --trace-requests
```

### Component Testing
```bash
# Test AWS collector
python src/collector/aws_collector.py --test

# Test Azure collector
python src/collector/azure_collector.py --test

# Test GCP collector
python src/collector/gcp_collector.py --test

# Test detection engine
python src/detection/detection_engine.py --test
```

### Network Diagnostics
```bash
# Check DNS resolution
nslookup api.aws.amazon.com
nslookup management.azure.com
nslookup cloudresourcemanager.googleapis.com

# Test HTTPS connectivity
curl -I https://api.aws.amazon.com
curl -I https://management.azure.com
curl -I https://cloudresourcemanager.googleapis.com

# Check firewall rules
iptables -L
ufw status
```

### Database Issues
```bash
# Check database connectivity
python -c "
import sqlite3
conn = sqlite3.connect('cloudhawk.db')
print('Database connection successful')
conn.close()
"

# Check database integrity
sqlite3 cloudhawk.db "PRAGMA integrity_check;"
```

## 🐳 Docker Issues

### Container Problems
```bash
# Check container status
docker ps
docker logs cloudhawk

# Check container health
docker inspect cloudhawk | grep -A 10 "Health"

# Restart container
docker restart cloudhawk
```

### Volume Mount Issues
```bash
# Check volume mounts
docker inspect cloudhawk | grep -A 5 "Mounts"

# Fix volume permissions
docker exec -it cloudhawk chown -R cloudhawk:cloudhawk /app/logs
```

### Network Issues
```bash
# Check container network
docker network ls
docker network inspect cloudhawk_default

# Test container connectivity
docker exec -it cloudhawk curl http://localhost:5000/health
```

## 📊 Performance Optimization

### System Tuning
```bash
# Increase file limits
echo "* soft nofile 65536" >> /etc/security/limits.conf
echo "* hard nofile 65536" >> /etc/security/limits.conf

# Optimize Python
export PYTHONOPTIMIZE=1
export PYTHONDONTWRITEBYTECODE=1
```

### Configuration Optimization
```yaml
# config.yaml optimizations
performance:
  max_workers: 4          # Adjust based on CPU cores
  batch_size: 1000        # Adjust based on memory
  cache_size: 10000       # Adjust based on available memory
  timeout: 300           # Adjust based on network speed
```

### Resource Monitoring
```bash
# Monitor system resources
watch -n 1 'echo "CPU: $(top -bn1 | grep "Cpu(s)" | awk "{print $2}" | cut -d"%" -f1)%"; echo "Memory: $(free | grep Mem | awk "{print $3/$2 * 100.0}")%"'

# Monitor CloudHawk processes
ps aux | grep python | grep cloudhawk
```

## 🔍 Log Analysis

### Log Levels
```bash
# Set log level
export CLOUDHAWK_LOG_LEVEL=DEBUG

# View specific log levels
grep "ERROR" logs/cloudhawk.log
grep "WARNING" logs/cloudhawk.log
grep "INFO" logs/cloudhawk.log
```

### Log Rotation
```bash
# Set up log rotation
sudo nano /etc/logrotate.d/cloudhawk

# Add configuration:
# /path/to/cloudhawk/logs/*.log {
#     daily
#     rotate 7
#     compress
#     delaycompress
#     missingok
#     notifempty
# }
```

### Log Parsing
```bash
# Parse logs for specific issues
grep -A 5 -B 5 "ERROR" logs/cloudhawk.log
grep -i "timeout" logs/cloudhawk.log
grep -i "permission" logs/cloudhawk.log
```

## 🆘 Emergency Recovery

### Data Recovery
```bash
# Backup important data
cp -r logs/ backup/logs-$(date +%Y%m%d)
cp config.yaml backup/config-$(date +%Y%m%d).yaml
cp email_alert_config.json backup/email_config-$(date +%Y%m%d).json

# Restore from backup
cp backup/config-20250101.yaml config.yaml
```

### Service Recovery
```bash
# Stop all CloudHawk processes
pkill -f cloudhawk
pkill -f python.*app.py

# Clean up resources
rm -f logs/*.log
rm -f *.pid

# Restart services
python src/web/app.py &
```

### Configuration Reset
```bash
# Reset to defaults
cp config.yaml.example config.yaml
cp email_alert_config.json.example email_alert_config.json

# Reconfigure
python setup.py
```

## 📞 Getting Help

### Self-Help Resources
1. **Check Logs**: Always check logs first
2. **Verify Configuration**: Ensure proper setup
3. **Test Connectivity**: Verify cloud provider access
4. **Review Documentation**: Check this wiki and README

### Community Support
- **GitHub Issues**: [Report bugs and request features](https://github.com/vatshariyani/cloudhawk/issues)
- **GitHub Discussions**: [Ask questions and share solutions](https://github.com/vatshariyani/cloudhawk/discussions)
- **Documentation**: [Comprehensive guides and API docs](https://github.com/vatshariyani/cloudhawk/wiki)

### Professional Support
- **Email**: support@cloudhawk.dev
- **Enterprise**: Contact for enterprise support options
- **Consulting**: Professional implementation services

## 📋 Issue Reporting

When reporting issues, please include:

### System Information
```bash
# Collect system info
python --version
pip list | grep -E "(azure|boto3|google-cloud)"
uname -a
df -h
free -h
```

### Configuration Details
```bash
# Collect config info (remove sensitive data)
cat config.yaml | grep -v password
cat email_alert_config.json | grep -v password
```

### Log Information
```bash
# Collect relevant logs
tail -n 100 logs/cloudhawk.log
grep -i error logs/cloudhawk.log
```

### Steps to Reproduce
1. What were you trying to do?
2. What steps did you follow?
3. What happened vs. what you expected?
4. Any error messages?

---

**Still having issues?** Check our [FAQ](FAQ.md) for common questions and answers!
