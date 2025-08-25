#!/usr/bin/env python3
"""
Vulnalyze Web Security Scanner
Enhanced run script with proper configuration and error handling

Usage:
    python run.py                 # Development mode
    python run.py --production    # Production mode
    python run.py --debug         # Debug mode with detailed logging
"""

import os
import sys
import argparse
import logging
from pathlib import Path

print("Current working directory:", os.getcwd())
print("Python sys.path:", sys.path)

def setup_logging(debug=False):
    """Configure application logging"""
    log_level = logging.DEBUG if debug else logging.INFO

    # Create logs directory
    log_dir = Path("logs")
    log_dir.mkdir(exist_ok=True)

    # Configure logging
    logging.basicConfig(
        level=log_level,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        handlers=[
            logging.FileHandler(log_dir / 'vulnalyze.log'),
            logging.StreamHandler(sys.stdout)
        ]
    )

def check_dependencies():
    """Check if required dependencies are installed"""
    required_packages = [
        'flask', 'flask_sqlalchemy', 'flask_login', 'flask_wtf',
        'celery', 'redis', 'requests', 'bs4'
    ]

    missing_packages = []
    for package in required_packages:
        try:
            __import__(package)
        except ImportError:
            missing_packages.append(package)

    if missing_packages:
        print("❌ Missing required packages:")
        for package in missing_packages:
            print(f"   - {package}")
        print("\n📦 Install missing packages with:")
        print("   pip install -r requirements.txt")
        sys.exit(1)

def create_directories():
    """Create necessary directories"""
    directories = ['uploads', 'logs', 'reports', 'static']
    for directory in directories:
        Path(directory).mkdir(exist_ok=True)
        print(f"✅ Created directory: {directory}")

def main():
    """Main application entry point"""
    parser = argparse.ArgumentParser(description='Vulnalyze Web Security Scanner')
    parser.add_argument('--production', action='store_true', help='Run in production mode')
    parser.add_argument('--debug', action='store_true', help='Enable debug logging')
    parser.add_argument('--port', type=int, default=5000, help='Port to run on (default: 5000)')
    parser.add_argument('--host', default='127.0.0.1', help='Host to bind to (default: 127.0.0.1)')

    args = parser.parse_args()

    # Setup logging
    setup_logging(args.debug)

    # Check dependencies
    print("🔍 Checking dependencies...")
    check_dependencies()
    print("✅ All dependencies satisfied")

    # Create necessary directories
    print("📁 Creating directories...")
    create_directories()

    # Import Flask application
    print("🚀 Initializing Vulnalyze...")
    from app import app, socketio

    if args.production:
        print("🏭 Starting Vulnalyze in PRODUCTION mode")
        print("⚠️  Make sure the following services are running:")
        print("   - Redis server (for background tasks)")
        print("   - Celery worker:")
        print("     celery -A celery_worker.celery_app worker --loglevel=info")
        print(f"🌍 Server will be available at: http://{args.host}:{args.port}")
        print("="*60)

        socketio.run(
            app,
            host='0.0.0.0' if args.host == '127.0.0.1' else args.host,
            port=args.port,
            debug=False,
            use_reloader=False
        )
    else:
        print("🔧 Starting Vulnalyze in DEVELOPMENT mode")
        print(f"📍 Application available at: http://{args.host}:{args.port}")
        print("👤 Default admin credentials:")
        print("")
        print("📋 To enable background scanning, run in another terminal:")
        print("   celery -A celery_worker.celery_app worker --loglevel=info")
        print("")
        print("🔴 To start Redis (required for WebSocket and background tasks):")
        print("   redis-server")
        print("")
        print("="*60)

        socketio.run(
            app,
            host=args.host,
            port=args.port,
            debug=True,
            use_reloader=True
        )

if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        print("\n🛑 Application stopped by user")
        sys.exit(0)
    except Exception as e:
        print(f"❌ Error starting application: {e}")
        sys.exit(1)
