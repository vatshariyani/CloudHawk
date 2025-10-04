# CloudHawk Docker Deployment Guide

This guide explains how to deploy CloudHawk using Docker, either by pulling a pre-built image from GitHub Container Registry (GHCR) or by building the image yourself.

## Quick Start

### Option 1: Using Pre-built Image (Recommended)

1. **Clone the repository:**
   ```bash
   git clone https://github.com/vatshariyani/cloudhawk.git
   cd cloudhawk
   ```

2. **Setup CloudHawk:**
   ```bash
   # On Linux/macOS
   ./scripts/docker-deploy.sh setup
   
   # On Windows
   scripts\docker-deploy.bat setup
   ```

3. **Configure your environment:**
   Edit the `.env` file with your cloud provider credentials:
   ```bash
   # Update the repository name
   GITHUB_REPOSITORY=vatshariyani/cloudhawk
   
   # Add your AWS credentials
   AWS_ACCESS_KEY_ID=your_aws_access_key_id
   AWS_SECRET_ACCESS_KEY=your_aws_secret_access_key
   AWS_DEFAULT_REGION=us-east-1
   ```

4. **Start CloudHawk:**
   ```bash
   # On Linux/macOS
   ./scripts/docker-deploy.sh start
   
   # On Windows
   scripts\docker-deploy.bat start
   ```

5. **Access the dashboard:**
   Open your browser and go to `http://localhost:5000`

### Option 2: Build from Source

If you prefer to build the Docker image yourself:

1. **Build the image:**
   ```bash
   docker build -t cloudhawk:latest .
   ```

2. **Update docker-compose.prod.yml:**
   Change the image line to use your local build:
   ```yaml
   image: cloudhawk:latest
   ```

3. **Start CloudHawk:**
   ```bash
   docker-compose -f docker-compose.prod.yml up -d
   ```

## Configuration

### Environment Variables

The following environment variables can be configured in your `.env` file:

#### CloudHawk Configuration
- `GITHUB_REPOSITORY`: Your GitHub repository (e.g., `vatshariyani/cloudhawk`)
- `CLOUDHAWK_PORT`: Port to expose CloudHawk on (default: 5000)
- `CLOUDHAWK_DOMAIN`: Domain name for CloudHawk (default: cloudhawk.local)

#### AWS Configuration
- `AWS_ACCESS_KEY_ID`: Your AWS access key ID
- `AWS_SECRET_ACCESS_KEY`: Your AWS secret access key
- `AWS_DEFAULT_REGION`: AWS region (default: us-east-1)
- `AWS_CREDENTIALS_PATH`: Path to AWS credentials file (optional)

#### Azure Configuration (Optional)
- `AZURE_CLIENT_ID`: Azure client ID
- `AZURE_CLIENT_SECRET`: Azure client secret
- `AZURE_TENANT_ID`: Azure tenant ID
- `AZURE_CREDENTIALS_PATH`: Path to Azure credentials file (optional)

#### GCP Configuration (Optional)
- `GCP_CREDENTIALS_PATH`: Path to GCP service account JSON file

#### Database Configuration
- `POSTGRES_DB`: PostgreSQL database name (default: cloudhawk)
- `POSTGRES_USER`: PostgreSQL username (default: cloudhawk)
- `POSTGRES_PASSWORD`: PostgreSQL password
- `POSTGRES_PORT`: PostgreSQL port (default: 5432)

#### Redis Configuration
- `REDIS_PORT`: Redis port (default: 6379)
- `REDIS_PASSWORD`: Redis password (optional)

### Cloud Provider Credentials

#### AWS Credentials
You can provide AWS credentials in several ways:

1. **Environment variables** (recommended for Docker):
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
For Azure, you can use service principal authentication:

```bash
AZURE_CLIENT_ID=your_client_id
AZURE_CLIENT_SECRET=your_client_secret
AZURE_TENANT_ID=your_tenant_id
```

#### GCP Credentials
For GCP, download a service account JSON file and mount it:

```bash
# Download service account JSON from GCP Console
# Place it in your project directory as gcp-credentials.json
# Set the path in .env
GCP_CREDENTIALS_PATH=./gcp-credentials.json
```

## Docker Compose Services

The `docker-compose.prod.yml` file includes several optional services:

### Core Services
- **cloudhawk**: Main CloudHawk application
- **redis**: Optional Redis for caching and session management
- **postgres**: Optional PostgreSQL for persistent data storage
- **nginx**: Optional Nginx reverse proxy

### Service Configuration

#### CloudHawk Service
```yaml
cloudhawk:
  image: ghcr.io/vatshariyani/cloudhawk:latest
  ports:
    - "5000:5000"
  environment:
    - CLOUDHAWK_PORT=5000
    - AWS_ACCESS_KEY_ID=${AWS_ACCESS_KEY_ID}
    # ... other environment variables
  volumes:
    - cloudhawk_logs:/opt/cloudhawk/logs
    - cloudhawk_config:/opt/cloudhawk/config
```

#### Redis Service (Optional)
```yaml
redis:
  image: redis:7-alpine
  ports:
    - "6379:6379"
  volumes:
    - cloudhawk_redis:/data
```

#### PostgreSQL Service (Optional)
```yaml
postgres:
  image: postgres:15-alpine
  environment:
    - POSTGRES_DB=cloudhawk
    - POSTGRES_USER=cloudhawk
    - POSTGRES_PASSWORD=secure_password
  volumes:
    - cloudhawk_postgres:/var/lib/postgresql/data
```

## Management Commands

### Using the Deployment Scripts

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
```

## Troubleshooting

### Common Issues

#### 1. Image Not Found
If you get an error about the image not being found:

```bash
# Check if the image exists
docker images | grep cloudhawk

# Pull the latest image
docker pull ghcr.io/vatshariyani/cloudhawk:latest
```

#### 2. Permission Denied
If you get permission errors:

```bash
# Make sure the script is executable
chmod +x scripts/docker-deploy.sh

# Check Docker permissions
docker ps
```

#### 3. Port Already in Use
If port 5000 is already in use:

```bash
# Change the port in .env file
CLOUDHAWK_PORT=8080

# Or stop the conflicting service
sudo lsof -i :5000
sudo kill -9 <PID>
```

#### 4. AWS Credentials Not Working
Check your AWS credentials:

```bash
# Test AWS credentials
docker run --rm -e AWS_ACCESS_KEY_ID=$AWS_ACCESS_KEY_ID \
  -e AWS_SECRET_ACCESS_KEY=$AWS_SECRET_ACCESS_KEY \
  ghcr.io/vatshariyani/cloudhawk:latest \
  aws sts get-caller-identity
```

### Logs and Debugging

#### View Application Logs
```bash
# View CloudHawk logs
docker-compose -f docker-compose.prod.yml logs -f cloudhawk

# View all service logs
docker-compose -f docker-compose.prod.yml logs -f
```

#### Debug Container
```bash
# Access CloudHawk container
docker-compose -f docker-compose.prod.yml exec cloudhawk bash

# Check CloudHawk status
docker-compose -f docker-compose.prod.yml exec cloudhawk python -c "
import sys
sys.path.insert(0, '/opt/cloudhawk/src')
from collector.aws_collector import AWSCollector
print('CloudHawk modules loaded successfully')
"
```

## Security Considerations

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

## Production Deployment

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

## Support

For issues and questions:
- Check the [troubleshooting section](#troubleshooting)
- Review the [main documentation](../README.md)
- Open an issue on GitHub
- Check the [FAQ](../docs/FAQ.md)

## License

This project is licensed under the MIT License - see the [LICENSE](../LICENSE) file for details.