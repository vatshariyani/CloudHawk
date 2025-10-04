# 🚀 CloudHawk Deployment Options

You now have **multiple ways** to deploy CloudHawk, each with its own advantages. Here are all your options:

## 🎯 **Option 1: Pre-built Image (Easiest)**

### Using Deployment Scripts
```bash
# Clone repository
git clone https://github.com/vatshariyani/cloudhawk.git
cd cloudhawk

# Setup CloudHawk
./scripts/docker-deploy.sh setup

# Edit .env with credentials
nano .env

# Start CloudHawk
./scripts/docker-deploy.sh start

# Access at http://localhost:5000
```

### Using /bin/CloudHawk Executable
```bash
# Clone repository
git clone https://github.com/vatshariyani/cloudhawk.git
cd cloudhawk

# Deploy CloudHawk (builds and starts automatically)
./bin/CloudHawk

# Or with specific commands
./bin/CloudHawk start    # Start CloudHawk
./bin/CloudHawk status   # Check status
./bin/CloudHawk logs     # View logs
./bin/CloudHawk stop     # Stop CloudHawk
```

## 🎯 **Option 2: Build from Source**

### Using Docker Compose
```bash
# Clone repository
git clone https://github.com/vatshariyani/cloudhawk.git
cd cloudhawk

# Start with Docker Compose
docker-compose up -d

# Access at http://localhost:5000
```

### Using /bin/CloudHawk (Builds Locally)
```bash
# Clone repository
git clone https://github.com/vatshariyani/cloudhawk.git
cd cloudhawk

# Deploy (builds image locally)
./bin/CloudHawk

# This will:
# 1. Build the Docker image locally
# 2. Start the container
# 3. Wait for it to be ready
# 4. Show access information
```

## 🎯 **Option 3: Manual Python Installation**

### Direct Python Installation
```bash
# Clone repository
git clone https://github.com/vatshariyani/cloudhawk.git
cd cloudhawk

# Install dependencies
pip install -r requirements.txt

# Run setup
python setup.py

# Start CloudHawk
python src/web/app.py

# Access at http://localhost:5000
```

## 📊 **Comparison of Options**

| Method | Ease of Use | Speed | Control | Best For |
|--------|-------------|-------|---------|----------|
| **Pre-built Image** | ⭐⭐⭐⭐⭐ | ⭐⭐⭐⭐⭐ | ⭐⭐⭐ | Quick deployment |
| **/bin/CloudHawk** | ⭐⭐⭐⭐⭐ | ⭐⭐⭐⭐ | ⭐⭐⭐⭐ | Easy management |
| **Docker Compose** | ⭐⭐⭐⭐ | ⭐⭐⭐ | ⭐⭐⭐⭐ | Development |
| **Python Direct** | ⭐⭐⭐ | ⭐⭐ | ⭐⭐⭐⭐⭐ | Customization |

## 🛠️ **Management Commands**

### Using /bin/CloudHawk
```bash
./bin/CloudHawk              # Deploy and start (default)
./bin/CloudHawk start         # Start CloudHawk
./bin/CloudHawk stop          # Stop CloudHawk
./bin/CloudHawk restart       # Restart CloudHawk
./bin/CloudHawk status        # Show status
./bin/CloudHawk logs          # View logs
./bin/CloudHawk shell         # Open container shell
./bin/CloudHawk clean         # Remove container and image
./bin/CloudHawk help          # Show help
```

### Using Deployment Scripts
```bash
./scripts/docker-deploy.sh setup    # Setup environment
./scripts/docker-deploy.sh start    # Start CloudHawk
./scripts/docker-deploy.sh stop     # Stop CloudHawk
./scripts/docker-deploy.sh restart  # Restart CloudHawk
./scripts/docker-deploy.sh status   # Show status
./scripts/docker-deploy.sh logs     # View logs
./scripts/docker-deploy.sh pull     # Pull latest image
```

### Using Docker Compose
```bash
docker-compose up -d          # Start all services
docker-compose down           # Stop all services
docker-compose restart        # Restart services
docker-compose logs          # View logs
docker-compose ps              # Show status
```

## 🎯 **Recommended Approach**

### For **Quick Testing**:
```bash
./bin/CloudHawk
```

### For **Production Deployment**:
```bash
./scripts/docker-deploy.sh setup
./scripts/docker-deploy.sh start
```

### For **Development**:
```bash
docker-compose up -d
```

### For **Customization**:
```bash
pip install -r requirements.txt
python src/web/app.py
```

## 🔧 **Platform-Specific Commands**

### Linux/macOS
```bash
# Using /bin/CloudHawk
./bin/CloudHawk

# Using deployment scripts
./scripts/docker-deploy.sh setup
./scripts/docker-deploy.sh start
```

### Windows
```cmd
REM Using /bin/CloudHawk.bat
bin\CloudHawk.bat

REM Using deployment scripts
scripts\docker-deploy.bat setup
scripts\docker-deploy.bat start
```

## 🌐 **Access Information**

Once CloudHawk is running, you can access:

- **🏠 Main Dashboard**: http://localhost:5000/
- **📊 Enhanced Dashboard**: http://localhost:5000/enhanced-dashboard
- **📚 API Documentation**: http://localhost:5000/api/docs
- **❤️ Health Check**: http://localhost:5000/api/v1/health
- **⚠️ Alerts**: http://localhost:5000/alerts
- **🔧 Configuration**: http://localhost:5000/config
- **📋 Rules**: http://localhost:5000/rules
- **🔍 Security Scan**: http://localhost:5000/scan

## 🎉 **Summary**

You now have **4 different ways** to deploy CloudHawk:

1. **Pre-built Image** (fastest, easiest)
2. **/bin/CloudHawk** (most user-friendly)
3. **Docker Compose** (good for development)
4. **Python Direct** (most customizable)

**Choose the method that best fits your needs!** All methods will give you the same CloudHawk functionality with the same web interface and API.
