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
        print("\n🌐 CloudHawk Console — screens:")
        print("   🏠 Overview:     http://localhost:5000/")
        print("   ⚠️  Alerts:       http://localhost:5000/alerts")
        print("   🕑 Timeline:     http://localhost:5000/timeline")
        print("   📋 Rules:        http://localhost:5000/rules")
        print("   📑 Compliance:   http://localhost:5000/compliance")
        print("   🔍 Scan:         http://localhost:5000/scan")
        print("   🔧 Config:       http://localhost:5000/config")
        print("\n📚 API:")
        print("   • Swagger / OpenAPI docs:  http://localhost:5000/api/docs/")
        print("   • API health check:        http://localhost:5000/api/v1/health")
        print("   • Compliance report:       http://localhost:5000/api/compliance/report")

        print("\n🔑 API Authentication:")
        print("   • Generate API Key: POST /api/v1/auth/api-key")
        print("   • Generate JWT Token: POST /api/v1/auth/token")
        print("   • Use API Key: X-API-Key header")
        print("   • Use JWT: Authorization: Bearer <token>")

        print("\n🤖 Features:")
        print("   • Multi-cloud collectors (AWS · GCP · Azure)")
        print("   • Severity scoring + alert deduplication")
        print("   • Compliance reporting (CIS v8, SOC 2, ISO 27001:2022)")
        print("   • RESTful API with Swagger/OpenAPI documentation")
        
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
