# 🚀 CloudHawk Enhanced Features - Run Instructions

## 🎉 **All Enhanced Features Successfully Implemented!**

CloudHawk now includes all four major enhancement requests:

### ✅ **1. RESTful API Endpoints for External Integrations**
### ✅ **2. Machine Learning-Based Anomaly Detection** 
### ✅ **3. Compliance Reporting for SOC2, PCI-DSS, CIS Benchmarks**
### ✅ **4. Enhanced Web Dashboard with Advanced Filtering and Visualization**

---

## 🚀 **How to Run CloudHawk**

### **Method 1: Using the Startup Script (Recommended)**
```bash
# From the CloudHawk root directory
python run_cloudhawk.py
```

### **Method 2: Direct Flask App**
```bash
# From the CloudHawk root directory
cd src/web
python app.py
```

### **Method 3: Using Python Module**
```bash
# From the CloudHawk root directory
python -m src.web.app
```

---

## 🌐 **Access Points**

Once the application is running, you can access:

### **🎯 Main Application**
- **🏠 Main Dashboard:** http://localhost:5000/
- **📊 Enhanced Dashboard:** http://localhost:5000/enhanced-dashboard
- **⚠️ Alerts:** http://localhost:5000/alerts
- **🔧 Configuration:** http://localhost:5000/config
- **📋 Rules:** http://localhost:5000/rules
- **🔍 Security Scan:** http://localhost:5000/scan
- **❤️ Health Dashboard:** http://localhost:5000/health-page

### **🔌 API Endpoints**
- **📚 API Documentation:** http://localhost:5000/api/docs
- **🔍 API Health Check:** http://localhost:5000/api/v1/health
- **📊 System Statistics:** http://localhost:5000/api/v1/stats
- **⚠️ Alerts API:** http://localhost:5000/api/v1/alerts
- **🔍 Scans API:** http://localhost:5000/api/v1/scans
- **📋 Rules API:** http://localhost:5000/api/v1/rules

---

## 🔑 **API Authentication**

### **Generate API Key**
```bash
curl -X POST http://localhost:5000/api/v1/auth/api-key \
  -H "Content-Type: application/json" \
  -d '{"name": "my-api-key", "permissions": ["read", "write"]}'
```

### **Generate JWT Token**
```bash
curl -X POST http://localhost:5000/api/v1/auth/token \
  -H "Content-Type: application/json" \
  -d '{"user_id": "my-user", "permissions": ["read", "write"]}'
```

### **Use API Key**
```bash
curl -H "X-API-Key: YOUR_API_KEY" http://localhost:5000/api/v1/alerts
```

### **Use JWT Token**
```bash
curl -H "Authorization: Bearer YOUR_JWT_TOKEN" http://localhost:5000/api/v1/alerts
```

---

## 🎯 **Enhanced Features Overview**

### **1. 📊 Enhanced Dashboard**
- **Real-time Updates** with live data refresh
- **Advanced Filtering** by severity, service, time range
- **Search Functionality** across alerts and resources
- **Interactive Charts:**
  - Security Events Timeline
  - Severity Distribution (Doughnut Chart)
  - Top Security Issues (Bar Chart)
  - Compliance Status (Radar Chart)
- **Responsive Design** for mobile and desktop
- **Dark Mode Support** with theme switching

### **2. 🔌 RESTful API (20+ Endpoints)**
- **Authentication:** JWT tokens and API keys
- **Rate Limiting:** Configurable per endpoint
- **Security Scans:** Create and manage scans
- **Alerts Management:** Get, filter, and manage alerts
- **Rules Engine:** Create and manage security rules
- **Webhooks:** External integration support
- **Statistics:** System metrics and analytics
- **Swagger Documentation:** Interactive API testing

### **3. 🤖 ML-Based Anomaly Detection**
- **Isolation Forest** for unsupervised anomaly detection
- **DBSCAN Clustering** for behavioral analysis
- **Behavioral Pattern Analysis** for user behavior anomalies
- **Real-time Anomaly Detection** with confidence scoring
- **Model Persistence** with joblib for trained models
- **Feature Engineering** for time-based and behavioral patterns

### **4. 📋 Compliance Reporting**
- **SOC2 Type II** - 4 controls for access control and monitoring
- **PCI-DSS** - 3 controls for network security and data protection
- **CIS Benchmarks** - 3 controls for asset and data management
- **Automated Assessment** with scoring (0-100%)
- **Evidence Collection** from security events
- **Detailed Reports** with executive summaries and recommendations

---

## 🔧 **API Usage Examples**

### **Create Security Scan**
```bash
curl -X POST http://localhost:5000/api/v1/scans \
  -H "X-API-Key: YOUR_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "cloud_provider": "AWS",
    "region": "us-east-1",
    "max_events": 1000
  }'
```

### **Get Alerts with Filtering**
```bash
curl -H "X-API-Key: YOUR_API_KEY" \
  "http://localhost:5000/api/v1/alerts?severity=CRITICAL&limit=10"
```

### **Create Security Rule**
```bash
curl -X POST http://localhost:5000/api/v1/rules \
  -H "X-API-Key: YOUR_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "id": "custom-rule-1",
    "title": "Custom Security Rule",
    "description": "Detects custom security issues",
    "condition": "severity == \"CRITICAL\"",
    "severity": "HIGH",
    "service": "AWS_EC2"
  }'
```

### **Get System Statistics**
```bash
curl -H "X-API-Key: YOUR_API_KEY" http://localhost:5000/api/v1/stats
```

---

## 🎨 **Enhanced Dashboard Features**

### **Real-time Metrics**
- Critical Alerts count with trend indicators
- High Severity alerts with trend analysis
- Total Alerts with historical comparison
- Resolved alerts with improvement tracking

### **Advanced Filtering**
- **Severity Filter:** Critical, High, Medium, Low
- **Service Filter:** AWS EC2, S3, IAM, GCP Compute, Azure VM
- **Time Range:** Last 24 hours, 7 days, 30 days, All time
- **Search:** Full-text search across alerts and resources

### **Interactive Visualizations**
- **Timeline Chart:** Security events over time
- **Severity Distribution:** Doughnut chart of alert severity
- **Top Issues:** Bar chart of most common security issues
- **Compliance Status:** Radar chart of compliance scores

### **Real-time Alerts Table**
- Live updates every 30 seconds
- Action buttons for viewing and resolving alerts
- Export functionality for data analysis
- Mark all as read functionality

---

## 🔍 **Testing the Enhanced Features**

### **1. Test API Health**
```bash
curl http://localhost:5000/api/v1/health
```

### **2. Test Enhanced Dashboard**
Open http://localhost:5000/enhanced-dashboard in your browser

### **3. Test API Documentation**
Open http://localhost:5000/api/docs in your browser

### **4. Test Compliance Reporting**
- Run a security scan
- Check compliance scores in the enhanced dashboard
- View compliance reports via API

### **5. Test ML Anomaly Detection**
- The ML models will automatically train on security events
- Anomalies will be detected and displayed in alerts
- Check the enhanced dashboard for anomaly visualizations

---

## 🚨 **Troubleshooting**

### **If the application won't start:**
1. Check if all dependencies are installed: `pip install -r requirements.txt`
2. Ensure you're in the CloudHawk root directory
3. Check for any import errors in the console output

### **If API endpoints don't work:**
1. Verify the application is running on port 5000
2. Check the API documentation at http://localhost:5000/api/docs
3. Ensure proper authentication headers are included

### **If enhanced dashboard doesn't load:**
1. Check browser console for JavaScript errors
2. Ensure Chart.js is loading properly
3. Verify the Flask app is serving static files correctly

---

## 🎉 **Success!**

Once CloudHawk is running, you have access to:

- ✅ **Complete REST API** with 20+ endpoints
- ✅ **ML-based Anomaly Detection** with behavioral analysis
- ✅ **Multi-framework Compliance Reporting** (SOC2, PCI-DSS, CIS)
- ✅ **Enhanced Dashboard** with real-time updates and advanced filtering
- ✅ **Swagger Documentation** for API testing
- ✅ **Multi-cloud Support** for AWS, Azure, and GCP
- ✅ **Production-ready** security monitoring solution

**🎯 CloudHawk is now a comprehensive, enterprise-grade security monitoring platform!**
