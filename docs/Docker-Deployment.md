# 🐳 Docker Deployment Guide

This comprehensive guide covers deploying CloudHawk using Docker, including pre-built images and custom builds.

## 🚀 Quick Start

### Option 1: Pre-built Image (Recommended)

The easiest way to deploy CloudHawk is using our pre-built Docker images from GitHub Container Registry (GHCR).

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

### Option 2: Build from Source

If you prefer to build the Docker image yourself:

```bash
# Clone the repository
git clone https://github.com/vatshariyani/cloudhawk.git
cd cloudhawk

# Build the image
docker build -t cloudhawk:latest .

# Start with Docker Compose
docker-compose up -d

# Access the web dashboard at http://localhost:5000
```

## 📋 Prerequisites

### System Requirements
- **Docker**: 20.10+ (with Docker Compose)
- **Memory**: 512MB minimum (2GB recommended)
- **Storage**: 2GB free space
- **Network**: Internet access for cloud API calls

### Cloud Provider Requirements
- **AWS**: AWS credentials configured
- **Azure**: Azure credentials configured (optional)
- **GCP**: GCP credentials configured (optional)

## 🔧 Configuration

### Environment Variables

Create a `.env` file with your configuration:

```bash
# CloudHawk Configuration
GITHUB_REPOSITORY=vatshariyani/cloudhawk
CLOUDHAWK_PORT=5000
CLOUDHAWK_DOMAIN=cloudhawk.local

# AWS Configuration
AWS_ACCESS_KEY_ID=your_aws_access_key_id
AWS_SECRET_ACCESS_KEY=your_aws_secret_access_key
AWS_DEFAULT_REGION=us-east-1

# Azure Configuration (optional)
AZURE_CLIENT_ID=your_azure_client_id
AZURE_CLIENT_SECRET=your_azure_client_secret
AZURE_TENANT_ID=your_azure_tenant_id

# GCP Configuration (optional)
GCP_CREDENTIALS_PATH=./gcp-credentials.json

# Database Configuration (optional)
POSTGRES_DB=cloudhawk
POSTGRES_USER=cloudhawk
POSTGRES_PASSWORD=secure_password

# Redis Configuration (optional)
REDIS_PORT=6379
REDIS_PASSWORD=
```

### Cloud Provider Credentials

#### AWS Credentials
You can provide AWS credentials in several ways:

1. **Environment variables** (recommended):
   ```bash
   AWS_ACCESS_KEY_ID=your_access_key
   AWS_SECRET_ACCESS_KEY=your_secret_key
   AWS_DEFAULT_REGION=us-east-1
   ```

2. **Credentials file** (mount to container):
   ```bash
   # Create credentials file
   mkdir -p credentials
   cat > credentials/credentials << EOF
   [default]
   aws_access_key_id = your_access_key
   aws_secret_access_key = your_secret_key
   EOF
   
   # Set path in .env
   AWS_CREDENTIALS_PATH=./credentials
   ```

#### Azure Credentials
For Azure, use service principal authentication:

```bash
AZURE_CLIENT_ID=your_client_id
AZURE_CLIENT_SECRET=your_client_secret
AZURE_TENANT_ID=your_tenant_id
```

#### GCP Credentials
For GCP, download a service account JSON file:

```bash
# Download service account JSON from GCP Console
# Place it in your project directory as gcp-credentials.json
# Set the path in .env
GCP_CREDENTIALS_PATH=./gcp-credentials.json
```

## 🐳 Docker Compose Services

### Core Services

#### CloudHawk Service
```yaml
cloudhawk:
  image: ghcr.io/vatshariyani/cloudhawk:latest
  ports:
    - "5000:5000"
  environment:
    - CLOUDHAWK_PORT=5000
    - AWS_ACCESS_KEY_ID=${AWS_ACCESS_KEY_ID}
    - AWS_SECRET_ACCESS_KEY=${AWS_SECRET_ACCESS_KEY}
    - AWS_DEFAULT_REGION=${AWS_DEFAULT_REGION}
  volumes:
    - cloudhawk_logs:/opt/cloudhawk/logs
    - cloudhawk_config:/opt/cloudhawk/config
  restart: unless-stopped
  healthcheck:
    test: ["CMD", "curl", "-f", "http://localhost:5000/api/v1/health"]
    interval: 30s
    timeout: 10s
    retries: 3
```

#### Redis Service (Optional)
```yaml
redis:
  image: redis:7-alpine
  ports:
    - "6379:6379"
  volumes:
    - cloudhawk_redis:/data
  restart: unless-stopped
  command: redis-server --appendonly yes
```

#### PostgreSQL Service (Optional)
```yaml
postgres:
  image: postgres:15-alpine
  environment:
    - POSTGRES_DB=cloudhawk
    - POSTGRES_USER=cloudhawk
    - POSTGRES_PASSWORD=secure_password
  ports:
    - "5432:5432"
  volumes:
    - cloudhawk_postgres:/var/lib/postgresql/data
  restart: unless-stopped
```

#### Nginx Service (Optional)
```yaml
nginx:
  image: nginx:alpine
  ports:
    - "80:80"
    - "443:443"
  volumes:
    - ./nginx.conf:/etc/nginx/nginx.conf:ro
    - ./ssl:/etc/nginx/ssl:ro
  depends_on:
    - cloudhawk
  restart: unless-stopped
```

## 🛠️ Management Commands

### Using Deployment Scripts

#### Linux/macOS
```bash
# Setup CloudHawk
./scripts/docker-deploy.sh setup

# Start CloudHawk
./scripts/docker-deploy.sh start

# Stop CloudHawk
./scripts/docker-deploy.sh stop

# Restart CloudHawk
./scripts/docker-deploy.sh restart

# Show status
./scripts/docker-deploy.sh status

# Show logs
./scripts/docker-deploy.sh logs

# Pull latest image
./scripts/docker-deploy.sh pull
```

#### Windows
```cmd
REM Setup CloudHawk
scripts\docker-deploy.bat setup

REM Start CloudHawk
scripts\docker-deploy.bat start

REM Stop CloudHawk
scripts\docker-deploy.bat stop

REM Restart CloudHawk
scripts\docker-deploy.bat restart

REM Show status
scripts\docker-deploy.bat status

REM Show logs
scripts\docker-deploy.bat logs

REM Pull latest image
scripts\docker-deploy.bat pull
```

### Using Docker Compose Directly

```bash
# Start all services
docker-compose -f docker-compose.prod.yml up -d

# Stop all services
docker-compose -f docker-compose.prod.yml down

# View logs
docker-compose -f docker-compose.prod.yml logs -f

# Restart a specific service
docker-compose -f docker-compose.prod.yml restart cloudhawk

# Scale CloudHawk instances
docker-compose -f docker-compose.prod.yml up -d --scale cloudhawk=3
```

## 🔍 Monitoring and Logs

### View Application Logs
```bash
# View CloudHawk logs
docker-compose -f docker-compose.prod.yml logs -f cloudhawk

# View all service logs
docker-compose -f docker-compose.prod.yml logs -f

# View logs from specific time
docker-compose -f docker-compose.prod.yml logs --since="2024-01-01T00:00:00" cloudhawk
```

### Health Checks
```bash
# Check CloudHawk health
curl http://localhost:5000/api/v1/health

# Check Docker container health
docker inspect cloudhawk | grep -A 10 "Health"

# Check all service status
docker-compose -f docker-compose.prod.yml ps
```

### Debug Container
```bash
# Access CloudHawk container
docker-compose -f docker-compose.prod.yml exec cloudhawk bash

# Check CloudHawk status inside container
docker-compose -f docker-compose.prod.yml exec cloudhawk python -c "
import sys
sys.path.insert(0, '/opt/cloudhawk/src')
from collector.aws_collector import AWSCollector
print('CloudHawk modules loaded successfully')
"
```

## 🚨 Troubleshooting

### Common Issues

#### 1. Image Not Found
```bash
# Error: pull access denied for ghcr.io/vatshariyani/cloudhawk
# Solution: Check if the image exists and you have access
docker pull ghcr.io/vatshariyani/cloudhawk:latest
```

#### 2. Permission Denied
```bash
# Error: Permission denied
# Solution: Make sure the script is executable
chmod +x scripts/docker-deploy.sh

# Check Docker permissions
docker ps
```

#### 3. Port Already in Use
```bash
# Error: Port 5000 is already in use
# Solution: Change the port in .env file
CLOUDHAWK_PORT=8080

# Or stop the conflicting service
sudo lsof -i :5000
sudo kill -9 <PID>
```

#### 4. AWS Credentials Not Working
```bash
# Test AWS credentials
docker run --rm -e AWS_ACCESS_KEY_ID=$AWS_ACCESS_KEY_ID \
  -e AWS_SECRET_ACCESS_KEY=$AWS_SECRET_ACCESS_KEY \
  ghcr.io/vatshariyani/cloudhawk:latest \
  aws sts get-caller-identity
```

#### 5. Container Won't Start
```bash
# Check container logs
docker logs cloudhawk

# Check container status
docker inspect cloudhawk

# Restart container
docker restart cloudhawk
```

### Debug Mode
```bash
# Enable debug logging
export CLOUDHAWK_DEBUG=1
docker-compose -f docker-compose.prod.yml up -d

# Check debug logs
docker-compose -f docker-compose.prod.yml logs -f cloudhawk
```

## 🔒 Security Considerations

### Container Security
- CloudHawk runs as a non-root user inside the container
- Sensitive data is masked in logs
- Credentials are passed via environment variables or mounted files

### Network Security
- Use HTTPS in production (configure Nginx with SSL certificates)
- Restrict access to CloudHawk port using firewall rules
- Use Docker networks to isolate services

### Data Security
- Store persistent data in Docker volumes
- Encrypt sensitive data at rest
- Regularly rotate cloud provider credentials
- Use least-privilege IAM policies for cloud access

## 📈 Production Deployment

### Scaling
For production deployments, consider:

1. **Load Balancing**: Use multiple CloudHawk instances behind a load balancer
2. **Database**: Use external PostgreSQL/Redis instances
3. **Monitoring**: Add monitoring and alerting for the containers
4. **Backup**: Implement backup strategies for persistent data

### High Availability
```yaml
# Example: Multiple CloudHawk instances
version: '3.8'
services:
  cloudhawk-1:
    image: ghcr.io/vatshariyani/cloudhawk:latest
    # ... configuration
  
  cloudhawk-2:
    image: ghcr.io/vatshariyani/cloudhawk:latest
    # ... configuration
  
  nginx:
    image: nginx:alpine
    # Load balancer configuration
```

### Performance Optimization
```yaml
# Resource limits
services:
  cloudhawk:
    deploy:
      resources:
        limits:
          memory: 2G
          cpus: '1.0'
        reservations:
          memory: 512M
          cpus: '0.5'
```

## 🔄 Updates and Maintenance

### Updating CloudHawk
```bash
# Pull latest image
docker pull ghcr.io/vatshariyani/cloudhawk:latest

# Update running containers
docker-compose -f docker-compose.prod.yml up -d

# Or use the deployment script
./scripts/docker-deploy.sh pull
./scripts/docker-deploy.sh restart
```

### Backup and Restore
```bash
# Backup volumes
docker run --rm -v cloudhawk_logs:/data -v $(pwd):/backup alpine tar czf /backup/cloudhawk_logs.tar.gz -C /data .

# Restore volumes
docker run --rm -v cloudhawk_logs:/data -v $(pwd):/backup alpine tar xzf /backup/cloudhawk_logs.tar.gz -C /data
```

## 📞 Support

For issues and questions:
- Check the [troubleshooting section](#troubleshooting)
- Review the [main documentation](../README.md)
- Open an issue on GitHub
- Check the [FAQ](../docs/FAQ.md)

## License

This project is licensed under the MIT License - see the [LICENSE](../LICENSE) file for details.
