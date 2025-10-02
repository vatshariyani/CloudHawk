# 🐳 CloudHawk Docker Deployment Guide

## 🚀 **Quick Start (Like OpenVAS)**

### **Option 1: Using the CloudHawk Script (Recommended)**

```bash
# Linux/macOS
./bin/CloudHawk

# Windows
bin\CloudHawk.bat
```

### **Option 2: Using Docker Compose**

```bash
# Start CloudHawk
docker-compose up -d

# View logs
docker-compose logs -f

# Stop CloudHawk
docker-compose down
```

### **Option 3: Using Docker Directly**

```bash
# Build the image
docker build -t cloudhawk:latest .

# Run CloudHawk
docker run -d \
  --name cloudhawk \
  --restart unless-stopped \
  -p 5000:5000 \
  -v $(pwd)/logs:/opt/cloudhawk/logs \
  -v $(pwd)/config:/opt/cloudhawk/config \
  -v $(pwd)/data:/opt/cloudhawk/data \
  cloudhawk:latest
```

---

## 🌐 **Access CloudHawk**

Once running, access CloudHawk at:

- **🏠 Main Dashboard:** http://localhost:5000/
- **📊 Enhanced Dashboard:** http://localhost:5000/enhanced-dashboard
- **📚 API Documentation:** http://localhost:5000/api/docs
- **❤️ Health Check:** http://localhost:5000/api/v1/health
- **⚠️ Alerts:** http://localhost:5000/alerts
- **🔧 Configuration:** http://localhost:5000/config
- **📋 Rules:** http://localhost:5000/rules
- **🔍 Security Scan:** http://localhost:5000/scan

---

## 🔧 **Management Commands**

### **Using CloudHawk Script**

```bash
# Deploy and start CloudHawk
./bin/CloudHawk

# Check status
./bin/CloudHawk status

# View logs
./bin/CloudHawk logs

# Stop CloudHawk
./bin/CloudHawk stop

# Restart CloudHawk
./bin/CloudHawk restart

# Open container shell
./bin/CloudHawk shell

# Clean up (remove container and image)
./bin/CloudHawk clean

# Show help
./bin/CloudHawk help
```

### **Using Docker Commands**

```bash
# View logs
docker logs cloudhawk

# Stop CloudHawk
docker stop cloudhawk

# Start CloudHawk
docker start cloudhawk

# Restart CloudHawk
docker restart cloudhawk

# Remove CloudHawk
docker rm -f cloudhawk

# Remove image
docker rmi cloudhawk:latest
```

---

## 📊 **Features Available**

### **✅ Multi-Cloud Security Monitoring**
- **AWS:** EC2, S3, IAM, CloudTrail, GuardDuty, VPC
- **Azure:** Virtual Machines, Storage, Key Vault, Security Center, Activity Log
- **GCP:** Compute Engine, Cloud Storage, IAM, Security Command Center, Cloud Logging

### **✅ Advanced Analytics**
- **ML-based Anomaly Detection** with behavioral analysis
- **Real-time Dashboard** with interactive visualizations
- **Compliance Reporting** for SOC2, PCI-DSS, and CIS benchmarks
- **Trend Analysis** and risk assessment

### **✅ Enterprise Features**
- **RESTful API** with 20+ endpoints
- **Swagger/OpenAPI Documentation** for API testing
- **Webhook Support** for external integrations
- **Role-based Authentication** with JWT and API keys
- **Rate Limiting** and security controls

---

## 🔒 **Security Features**

### **Authentication & Authorization**
- JWT token-based authentication
- API key management
- Role-based permissions (read, write, admin)
- Rate limiting per endpoint

### **Data Protection**
- Encrypted data transmission (HTTPS)
- Secure credential storage
- Audit logging and monitoring
- Container security best practices

---

## 📈 **Performance & Scalability**

### **Optimized Docker Image**
- **Multi-stage build** for smaller image size
- **Python 3.11-slim** base image
- **Non-root user** for security
- **Health checks** for reliability

### **Resource Management**
- **Configurable memory limits**
- **CPU optimization**
- **Persistent volume mounts**
- **Automatic restart policies**

---

## 🛠️ **Configuration**

### **Environment Variables**
```bash
CLOUDHAWK_PORT=5000          # Web interface port
CLOUDHAWK_HOST=0.0.0.0       # Bind address
PYTHONUNBUFFERED=1           # Python output buffering
FLASK_ENV=production         # Flask environment
```

### **Volume Mounts**
```bash
./logs:/opt/cloudhawk/logs           # Log files
./config:/opt/cloudhawk/config       # Configuration files
./data:/opt/cloudhawk/data           # Persistent data
```

---

## 🔍 **Troubleshooting**

### **Common Issues**

**1. Port Already in Use**
```bash
# Check what's using port 5000
lsof -i :5000

# Use different port
docker run -p 5001:5000 cloudhawk:latest
```

**2. Permission Issues**
```bash
# Fix volume permissions
sudo chown -R 1000:1000 logs config data
```

**3. Container Won't Start**
```bash
# Check logs
docker logs cloudhawk

# Check container status
docker ps -a
```

**4. Health Check Fails**
```bash
# Check if CloudHawk is responding
curl http://localhost:5000/api/v1/health

# Check container logs
docker logs cloudhawk
```

### **Debug Mode**
```bash
# Run in debug mode
docker run -it --rm \
  -p 5000:5000 \
  -e FLASK_ENV=development \
  cloudhawk:latest
```

---

## 🚀 **Production Deployment**

### **Using Docker Compose (Recommended)**

```yaml
version: '3.8'
services:
  cloudhawk:
    build: .
    ports:
      - "5000:5000"
    volumes:
      - cloudhawk_logs:/opt/cloudhawk/logs
      - cloudhawk_config:/opt/cloudhawk/config
    environment:
      - FLASK_ENV=production
    restart: unless-stopped
```

### **Using Kubernetes**
```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: cloudhawk
spec:
  replicas: 1
  selector:
    matchLabels:
      app: cloudhawk
  template:
    metadata:
      labels:
        app: cloudhawk
    spec:
      containers:
      - name: cloudhawk
        image: cloudhawk:latest
        ports:
        - containerPort: 5000
        env:
        - name: FLASK_ENV
          value: "production"
```

---

## 📚 **API Usage**

### **Authentication**
```bash
# Generate API key
curl -X POST http://localhost:5000/api/v1/auth/api-key \
  -H "Content-Type: application/json" \
  -d '{"name": "my-api-key", "permissions": ["read", "write"]}'

# Use API key
curl -H "X-API-Key: YOUR_API_KEY" http://localhost:5000/api/v1/alerts
```

### **Create Security Scan**
```bash
curl -X POST http://localhost:5000/api/v1/scans \
  -H "X-API-Key: YOUR_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"cloud_provider": "AWS", "region": "us-east-1"}'
```

---

## 🎉 **Success!**

CloudHawk is now running and ready for use! You have:

- ✅ **Enterprise-grade security monitoring** for AWS, Azure, and GCP
- ✅ **ML-based anomaly detection** with behavioral analysis
- ✅ **Real-time dashboard** with advanced filtering and visualization
- ✅ **Compliance reporting** for SOC2, PCI-DSS, and CIS benchmarks
- ✅ **RESTful API** with comprehensive documentation
- ✅ **Easy deployment** like OpenVAS

**🚀 CloudHawk is ready to protect your cloud infrastructure!**
