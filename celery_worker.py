"""
Enhanced celery_worker.py with proper database integration and progress tracking
"""

import os
import sys
sys.path.append(os.path.abspath(os.path.dirname(__file__)))

import logging
import redis
from datetime import datetime, timedelta
from celery import Celery
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

# Configure logging first
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

print("Current working directory:", os.getcwd())
print("Python sys.path:", sys.path)

# Database connection for worker tasks - ABSOLUTE PATH
basedir = os.path.abspath(os.path.dirname(__file__))
from config import config
env = os.environ.get('FLASK_CONFIG', 'development')
DATABASE_URI = os.environ.get('DATABASE_URL') or config[env].SQLALCHEMY_DATABASE_URI
print(f"[CELERY STARTUP] Database URI: {DATABASE_URI}")

engine = create_engine(DATABASE_URI, connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

# Initialize Celery app with Redis broker
celery_app = Celery('vulnalyze_tasks', broker='redis://localhost:6379/0')

# Redis connection
try:
    redis_client = redis.Redis(host='localhost', port=6379, db=0)
    redis_client.ping()
    logger.info("Redis connected successfully")
except Exception as e:
    logger.error(f"Redis connection failed: {e}")
    redis_client = None

# Configure Celery
celery_app.conf.update(
    task_serializer='json',
    accept_content=['json'],
    result_serializer='json',
    timezone='UTC',
    enable_utc=True,
    result_expires=3600,
)

@celery_app.task(bind=True)
def run_scan_task(self, target_url, max_depth=2, delay=1, selected_plugins=None, scan_id=None, user_id=None):
    """Run vulnerability scan as a Celery task with database integration"""
    if not scan_id:
        logger.warning("Task started without scan_id - likely a stuck task from previous session")
        return {"status": "cancelled", "message": "Task cancelled - no scan_id provided"}
    
    print(f"[CELERY TASK] Using Database URI: {DATABASE_URI}")
    print(f"[CELERY TASK] Starting scan for {target_url}")
    
    task_id = self.request.id
    
    try:
        # Import modules here to avoid circular imports
        import plugins
        import scanner
        from plugins import load_plugins
        from scanner import WebSecurityScanner
        
        logger.info(f"Starting scan task {task_id} for {target_url}")
        
        if scan_id:
            update_scan_status(scan_id, 'running', 'Initializing scanner...', 0)
        
        # Load plugins
        loaded_plugins = load_plugins(selected_plugins) if selected_plugins else load_plugins()
        print(f"[CELERY TASK] Loaded plugins: {[plugin.name for plugin in loaded_plugins] if isinstance(loaded_plugins, list) else list(loaded_plugins.keys())}")
        
        def progress_callback(current, total, operation):
            if scan_id:
                progress = int((current / total) * 100) if total > 0 else 0
                update_scan_status(scan_id, 'running', operation, progress)
        
        # Create scanner instance
        scanner_instance = WebSecurityScanner(
            target_url=target_url,
            max_depth=max_depth,
            delay=delay,
            plugins=loaded_plugins,
            progress_callback=progress_callback
        )
        
        # Check for cancellation before starting
        if redis_client and redis_client.get(f"scan_cancel_{task_id}"):
            if scan_id:
                update_scan_status(scan_id, 'cancelled', 'Scan cancelled by user', 0)
            return {"status": "cancelled", "message": "Scan cancelled by user"}
        
        start_time = datetime.utcnow()
        if scan_id:
            update_scan_status(scan_id, 'running', 'Starting security scan...', 5)
        
        # Run the scan
        vulnerabilities = scanner_instance.run()
        end_time = datetime.utcnow()
        scan_duration = (end_time - start_time).total_seconds()
        
        print(f"[CELERY TASK] Scan completed. Found {len(vulnerabilities)} vulnerabilities")
        
        # Check for cancellation after scan
        if redis_client and redis_client.get(f"scan_cancel_{task_id}"):
            if scan_id:
                update_scan_status(scan_id, 'cancelled', 'Scan cancelled by user', 100)
            return {"status": "cancelled", "message": "Scan cancelled by user"}
        
        # Save vulnerabilities to database
        if scan_id and vulnerabilities:
            save_vulnerabilities_to_db(scan_id, vulnerabilities)
        
        if scan_id:
            update_scan_completion(scan_id, vulnerabilities, scan_duration)
        
        return {
            "status": "completed",
            "vulnerabilities": vulnerabilities,
            "total_found": len(vulnerabilities),
            "scan_duration": scan_duration,
            "pages_crawled": len(scanner_instance.visited_urls) if hasattr(scanner_instance, 'visited_urls') else 0
        }
        
    except Exception as e:
        logger.error(f"Scan task error: {e}")
        if scan_id:
            update_scan_status(scan_id, 'failed', f'Error: {str(e)}', 0)
        return {
            "status": "failed",
            "error": str(e),
            "vulnerabilities": []
        }

def update_scan_status(scan_id, status, operation, progress):
    """Update scan status in database"""
    try:
        # Create Flask app context for proper database access
        from app import create_app
        app = create_app()
        
        with app.app_context():
            from models import ScanHistory, db
            
            scan = ScanHistory.query.filter(ScanHistory.id == scan_id).first()
            if scan:
                scan.status = status
                scan.current_operation = operation
                scan.progress = progress
                if status == 'running' and not scan.started_at:
                    scan.started_at = datetime.utcnow()
                db.session.commit()
                logger.info(f"Updated scan {scan_id} status to {status}")
            else:
                logger.warning(f"Scan {scan_id} not found in database")
    except Exception as e:
        logger.error(f"Error updating scan status: {e}")

def save_vulnerabilities_to_db(scan_id, vulnerabilities):
    """Save discovered vulnerabilities to database using Flask-SQLAlchemy"""
    try:
        from app import create_app
        from models import Vulnerability, db
        
        app = create_app()
        with app.app_context():
            for vuln_data in vulnerabilities:
                inputs_param = ''
                if vuln_data.get('inputs'):
                    if isinstance(vuln_data['inputs'], list):
                        inputs_param = vuln_data['inputs'][0] if vuln_data['inputs'] else ''
                    else:
                        inputs_param = str(vuln_data['inputs'])
                
                vuln = Vulnerability(
                    scan_id=scan_id,
                    vuln_type=vuln_data.get('type', 'Unknown'),
                    severity=vuln_data.get('severity', 'Medium'),
                    url=vuln_data.get('url', ''),
                    method=vuln_data.get('method', 'GET'),
                    parameter=inputs_param,
                    payload=vuln_data.get('payload', ''),
                    evidence=str(vuln_data.get('evidence', '')),
                    title=f"{vuln_data.get('type', 'Unknown')} vulnerability",
                    description=f"Vulnerability found at {vuln_data.get('url', 'unknown location')}",
                    remediation=get_remediation_advice(vuln_data.get('type', 'Unknown'))
                )
                db.session.add(vuln)
            
            db.session.commit()
            logger.info(f"Saved {len(vulnerabilities)} vulnerabilities to database")

    except Exception as e:
        logger.error(f"Error saving vulnerabilities: {e}")

from datetime import datetime

def update_scan_completion(scan_id, vulnerabilities, duration):
    """Update scan with completion data using Flask app context and SQLAlchemy db"""
    try:
        # Create Flask app and push context
        from app import create_app
        app = create_app()
        with app.app_context():
            from models import ScanHistory, db  # import db

            # Query via Flask-SQLAlchemy
            scan = ScanHistory.query.get(scan_id)
            if not scan:
                app.logger.warning(f"Scan {scan_id} not found for completion update")
                return

            # Update fields
            scan.status = 'completed'
            scan.completed_at = datetime.utcnow()
            scan.scan_duration = duration
            scan.progress = 100
            scan.current_operation = 'Scan completed successfully'

            scan.total_vulnerabilities = len(vulnerabilities)
            scan.critical_count = sum(1 for v in vulnerabilities if v.get('severity', '').lower() == 'critical')
            scan.high_count     = sum(1 for v in vulnerabilities if v.get('severity', '').lower() == 'high')
            scan.medium_count   = sum(1 for v in vulnerabilities if v.get('severity', '').lower() == 'medium')
            scan.low_count      = sum(1 for v in vulnerabilities if v.get('severity', '').lower() == 'low')
            scan.info_count     = sum(1 for v in vulnerabilities if v.get('severity', '').lower() == 'info')

            # Commit to the shared database
            db.session.commit()
            app.logger.info(f"Scan {scan_id} marked completed")

            # Emit SocketIO update for the browser
            try:
                from flask_socketio import SocketIO
                socketio = SocketIO(message_queue=app.config['REDIS_URL'])
                socketio.emit(
                    'scan_update',
                    {'scan_id': scan_id, 'status': 'completed', 'progress': 100},
                    room=f'scan_{scan_id}'
                )
            except Exception as socke:
                app.logger.warning(f"SocketIO emit failed: {socke}")

    except Exception as e:
        # Log and continue
        import logging
        logging.getLogger(__name__).error(f"Error updating scan completion: {e}")

@celery_app.task
def cancel_scan_task(task_id):
    """Cancel a running scan task"""
    try:
        if redis_client:
            redis_client.set(f"scan_cancel_{task_id}", "1", ex=3600)
            logger.info(f"Cancellation requested for task {task_id}")
            return f"Cancellation requested for task {task_id}"
        else:
            logger.warning("Redis not available for scan cancellation")
            return "Redis not available for cancellation"
    except Exception as e:
        logger.error(f"Error cancelling task {task_id}: {e}")
        return f"Error cancelling task: {str(e)}"

@celery_app.task
def cleanup_old_scans():
    """Cleanup old scan data (run periodically)"""
    try:
        from models import ScanHistory
        
        cutoff_date = datetime.utcnow() - timedelta(days=30)
        db_session = SessionLocal()
        try:
            old_scans = db_session.query(ScanHistory).filter(
                ScanHistory.created_at < cutoff_date,
                ScanHistory.status.in_(['completed', 'failed', 'cancelled'])
            ).all()
            
            for scan in old_scans:
                db_session.delete(scan)
            
            db_session.commit()
            logger.info(f"Cleaned up {len(old_scans)} old scans")
            return f"Cleaned up {len(old_scans)} old scans"
        finally:
            db_session.close()
    except Exception as e:
        logger.error(f"Cleanup task error: {e}")
        return f"Cleanup error: {str(e)}"

def get_remediation_advice(vuln_type):
    """Get remediation advice for vulnerability types"""
    remediation_map = {
        'XSS': 'Implement input validation and output encoding. Use Content Security Policy (CSP) headers.',
        'SQLi': 'Use parameterized queries/prepared statements. Implement input validation and least privilege database access.',
        'CSRF': 'Implement CSRF tokens for state-changing operations. Use SameSite cookie attributes.',
        'LFI': 'Validate and sanitize file path inputs. Use whitelist of allowed files and directories.',
        'Command Injection': 'Avoid executing system commands with user input. Use parameterized commands and input validation.',
        'Open Redirect': 'Validate redirect URLs against a whitelist. Avoid user-controlled redirects.',
        'Directory Traversal': 'Implement proper input validation and use absolute paths. Restrict file access permissions.'
    }
    return remediation_map.get(vuln_type, 'Review and validate all user inputs. Follow secure coding practices.')

if __name__ == '__main__':
    print(f"Starting Celery worker with database: {DATABASE_URI}")
    celery_app.start()
