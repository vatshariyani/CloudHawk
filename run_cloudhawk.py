#!/usr/bin/env python3
"""
CloudHawk Startup Script
Runs the CloudHawk application with all enhanced features
"""

import os
import sys
import logging
from pathlib import Path

# Add src to path
src_path = Path(__file__).parent / 'src'
sys.path.insert(0, str(src_path))

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

def main():
    """Start CloudHawk application"""
    try:
        print("🚀 Starting CloudHawk with Enhanced Features...")
        print("=" * 60)
        
        # Check if we're in the right directory
        if not os.path.exists('src/web/app.py'):
            print("❌ Error: Please run this script from the CloudHawk root directory")
            return False
        
        # Import and run the Flask app from the web directory
        from src.web.app import app
        
        print("✅ All modules imported successfully!")
        print("\n🌐 CloudHawk Enhanced Features Available:")
        print("   📊 Enhanced Dashboard: http://localhost:5000/enhanced-dashboard")
        print("   📚 API Documentation: http://localhost:5000/api/docs")
        print("   🔍 API Health Check: http://localhost:5000/api/v1/health")
        print("   🏠 Main Dashboard: http://localhost:5000/")
        print("   ⚠️  Alerts: http://localhost:5000/alerts")
        print("   🔧 Configuration: http://localhost:5000/config")
        print("   📋 Rules: http://localhost:5000/rules")
        print("   🔍 Scan: http://localhost:5000/scan")
        print("   ❤️  Health: http://localhost:5000/health-page")
        
        print("\n🔑 API Authentication:")
        print("   • Generate API Key: POST /api/v1/auth/api-key")
        print("   • Generate JWT Token: POST /api/v1/auth/token")
        print("   • Use API Key: X-API-Key header")
        print("   • Use JWT: Authorization: Bearer <token>")
        
        print("\n🤖 Enhanced Features:")
        print("   • ML-based Anomaly Detection")
        print("   • Compliance Reporting (SOC2, PCI-DSS, CIS)")
        print("   • Advanced Dashboard with Real-time Updates")
        print("   • RESTful API with 20+ Endpoints")
        print("   • Swagger/OpenAPI Documentation")
        
        print("\n" + "=" * 60)
        print("🚀 Starting Flask application...")
        print("=" * 60)
        
        # Run the Flask app
        app.run(
            host='0.0.0.0',
            port=5000,
            debug=True,
            use_reloader=False  # Disable reloader to avoid issues
        )
        
    except ImportError as e:
        print(f"❌ Import Error: {e}")
        print("💡 Try installing dependencies: pip install -r requirements.txt")
        return False
        
    except Exception as e:
        print(f"❌ Error starting CloudHawk: {e}")
        logger.error(f"Startup error: {e}", exc_info=True)
        return False

if __name__ == "__main__":
    success = main()
    if not success:
        sys.exit(1)
