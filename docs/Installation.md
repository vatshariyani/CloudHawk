# 📦 Installation Guide

This guide will help you install CloudHawk on your system. CloudHawk supports multiple installation methods including pip, Docker, and source installation.

## 📋 Prerequisites

### System Requirements
- **Python**: 3.8+ (3.11+ recommended)
- **Memory**: 512MB minimum (2GB recommended)
- **Storage**: 1GB free space
- **Network**: Internet access for cloud API calls

### Cloud Provider Requirements
- **AWS**: AWS CLI configured with appropriate permissions
- **Azure**: Azure CLI configured with subscription access
- **GCP**: Google Cloud SDK with service account credentials

## 🚀 Installation Methods

### Method 1: Docker Installation (Recommended)

#### Option A: Pre-built Image (Easiest)
```bash
# Clone the repository
git clone https://github.com/vatshariyani/cloudhawk.git
cd cloudhawk

# Setup CloudHawk (creates .env file and directories)
./scripts/docker-deploy.sh setup

# Edit .env file with your credentials
nano .env

# Start CloudHawk
./scripts/docker-deploy.sh start

# Access the web dashboard at http://localhost:5000
```

#### Option B: Docker Compose (Build from Source)
```bash
# Clone the repository
git clone https://github.com/vatshariyani/cloudhawk.git
cd cloudhawk

# Start CloudHawk
docker-compose up -d

# Access the web dashboard at http://localhost:5000
```

#### Option C: Manual Docker Build
```bash
# Build the image
docker build -t cloudhawk .

# Run with configuration
docker run -d \
  --name cloudhawk \
  -p 5000:5000 \
  -v $(pwd)/config.yaml:/opt/cloudhawk/config.yaml:ro \
  -v $(pwd)/logs:/opt/cloudhawk/logs \
  -v ~/.aws:/opt/cloudhawk/config/aws:ro \
  cloudhawk
```

### Method 2: Python Installation

#### Using pip (Recommended)
```bash
# Clone the repository
git clone https://github.com/vatshariyani/cloudhawk.git
cd cloudhawk

# Install dependencies
pip install -r requirements.txt

# Run setup script
python setup.py
```

#### Using Virtual Environment
```bash
# Create virtual environment
python -m venv cloudhawk-env

# Activate virtual environment
# On Windows:
cloudhawk-env\Scripts\activate
# On macOS/Linux:
source cloudhawk-env/bin/activate

# Install CloudHawk
pip install -r requirements.txt
```

### Method 3: Source Installation

#### Development Installation
```bash
# Clone the repository
git clone https://github.com/vatshariyani/cloudhawk.git
cd cloudhawk

# Install in development mode
pip install -e .

# Install development dependencies
pip install -r requirements-dev.txt
```

## ⚙️ Configuration

### 1. Basic Configuration

Create your configuration file:
```bash
# Copy the example configuration
cp config.yaml.example config.yaml

# Edit the configuration
nano config.yaml
```

### 2. Cloud Provider Setup

#### AWS Configuration
```bash
# Configure AWS CLI
aws configure

# Or set environment variables
export AWS_ACCESS_KEY_ID=your_access_key
export AWS_SECRET_ACCESS_KEY=your_secret_key
export AWS_DEFAULT_REGION=us-east-1
```

#### Azure Configuration
```bash
# Login to Azure
az login

# Set subscription
az account set --subscription "your-subscription-id"

# Or set environment variables
export AZURE_SUBSCRIPTION_ID=your_subscription_id
export AZURE_TENANT_ID=your_tenant_id
```

#### GCP Configuration
```bash
# Authenticate with GCP
gcloud auth login

# Set project
gcloud config set project your-project-id

# Or set environment variables
export GOOGLE_CLOUD_PROJECT=your_project_id
export GOOGLE_APPLICATION_CREDENTIALS=path/to/service-account.json
```

### 3. Email Configuration

Configure email alerts in the web dashboard:
1. Start CloudHawk: `python src/web/app.py`
2. Navigate to `http://localhost:5000/config`
3. Configure email settings:
   - SMTP Server (e.g., smtp.gmail.com)
   - SMTP Port (e.g., 587)
   - Username and Password
   - From and To email addresses

### 4. Slack Configuration

Configure Slack notifications:
1. Create a Slack webhook URL
2. In the web dashboard, go to Configuration
3. Enable Slack alerts and enter your webhook URL

## 🧪 Verification

### Test Installation
```bash
# Test CloudHawk installation
python -c "import src.web.app; print('CloudHawk installed successfully')"

# Test AWS collector
python src/collector/aws_collector.py --test

# Test web dashboard
python src/web/app.py
# Visit http://localhost:5000
```

### Run Security Scan
```bash
# Run a test security scan
python test_security_detection.py

# Check for alerts
python src/cli/cloudhawk_cli.py alerts
```

## 🐳 Docker Configuration

### Pre-built Image Configuration
```yaml
# docker-compose.prod.yml
version: '3.8'
services:
  cloudhawk:
    image: ghcr.io/vatshariyani/cloudhawk:latest
    ports:
      - "5000:5000"
    environment:
      - AWS_ACCESS_KEY_ID=${AWS_ACCESS_KEY_ID}
      - AWS_SECRET_ACCESS_KEY=${AWS_SECRET_ACCESS_KEY}
      - AWS_DEFAULT_REGION=${AWS_DEFAULT_REGION}
    volumes:
      - cloudhawk_logs:/opt/cloudhawk/logs
      - cloudhawk_config:/opt/cloudhawk/config
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:5000/api/v1/health"]
      interval: 30s
      timeout: 10s
      retries: 3
```

### Build from Source Configuration
```yaml
# docker-compose.yml
version: '3.8'
services:
  cloudhawk:
    build: .
    ports:
      - "5000:5000"
    volumes:
      - ./config.yaml:/opt/cloudhawk/config.yaml:ro
      - ./logs:/opt/cloudhawk/logs
      - ~/.aws:/opt/cloudhawk/config/aws:ro
    environment:
      - AWS_ACCESS_KEY_ID=${AWS_ACCESS_KEY_ID}
      - AWS_SECRET_ACCESS_KEY=${AWS_SECRET_ACCESS_KEY}
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:5000/api/v1/health"]
      interval: 30s
      timeout: 10s
      retries: 3
```

### Docker Environment Variables
```bash
# AWS
AWS_ACCESS_KEY_ID=your_access_key
AWS_SECRET_ACCESS_KEY=your_secret_key
AWS_DEFAULT_REGION=us-east-1

# Azure
AZURE_SUBSCRIPTION_ID=your_subscription_id
AZURE_TENANT_ID=your_tenant_id

# GCP
GOOGLE_CLOUD_PROJECT=your_project_id
GOOGLE_APPLICATION_CREDENTIALS=/app/credentials.json
```

## 🔧 Advanced Configuration

### Performance Tuning
```yaml
# config.yaml
performance:
  max_workers: 4
  batch_size: 1000
  cache_size: 10000
  log_level: INFO
```

### Logging Configuration
```yaml
# config.yaml
logging:
  level: INFO
  file: logs/cloudhawk.log
  max_size: 100MB
  backup_count: 5
```

### Alerting Configuration
```yaml
# config.yaml
alerting:
  email:
    enabled: true
    smtp_server: smtp.gmail.com
    smtp_port: 587
    username: alerts@company.com
    password: your_password
    from_email: alerts@company.com
    to_email: security@company.com
  
  slack:
    enabled: true
    webhook_url: https://hooks.slack.com/services/...
    channel: "#security-alerts"
```

## 🚨 Troubleshooting

### Common Issues

#### 1. Import Errors
```bash
# Error: ModuleNotFoundError: No module named 'azure'
# Solution: Install missing dependencies
pip install -r requirements.txt
```

#### 2. Permission Errors
```bash
# Error: Permission denied
# Solution: Check file permissions
chmod +x bin/CloudHawk
```

#### 3. Port Already in Use
```bash
# Error: Port 5000 already in use
# Solution: Use different port
python src/web/app.py --port 8080
```

#### 4. Cloud Provider Authentication
```bash
# AWS: Check credentials
aws sts get-caller-identity

# Azure: Check login
az account show

# GCP: Check authentication
gcloud auth list
```

### Debug Mode
```bash
# Enable debug logging
export CLOUDHAWK_DEBUG=1
python src/web/app.py

# Check logs
tail -f logs/cloudhawk.log
```

### Health Checks
```bash
# Check CloudHawk health
curl http://localhost:5000/health

# Check Docker container health
docker inspect cloudhawk | grep -A 10 "Health"
```

## 📊 System Requirements

### Minimum Requirements
- **CPU**: 1 core
- **Memory**: 512MB RAM
- **Storage**: 1GB free space
- **Network**: Internet connection

### Recommended Requirements
- **CPU**: 2+ cores
- **Memory**: 2GB+ RAM
- **Storage**: 10GB+ free space
- **Network**: Stable internet connection

### Production Requirements
- **CPU**: 4+ cores
- **Memory**: 4GB+ RAM
- **Storage**: 50GB+ free space
- **Network**: High-speed internet connection
- **Backup**: Regular data backups

## 🔄 Updates

### Updating CloudHawk
```bash
# Pull latest changes
git pull origin main

# Update dependencies
pip install -r requirements.txt

# Restart services
docker-compose restart
```

### Version Management
```bash
# Check current version
python -c "import src.web.app; print(src.web.app.__version__)"

# Check for updates
git fetch origin
git log HEAD..origin/main --oneline
```

## 📞 Support

If you encounter issues during installation:

1. **Check the logs**: `tail -f logs/cloudhawk.log`
2. **Verify prerequisites**: Ensure all dependencies are installed
3. **Test connectivity**: Verify cloud provider access
4. **Review configuration**: Check config.yaml settings
5. **Contact support**: [GitHub Issues](https://github.com/vatshariyani/cloudhawk/issues)

---

**Next Steps**: After installation, proceed to [Quick Start](Quick-Start.md) to run your first security scan!
