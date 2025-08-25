"""
Main Flask application factory for Vulnalyze
Complete Web Security Scanner with modern architecture
"""

import os
import redis
import logging
from datetime import datetime, timedelta
from functools import wraps

from flask import Flask, render_template, request, redirect, url_for, flash, jsonify, abort, current_app
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, login_user, logout_user, login_required, current_user
from flask_socketio import SocketIO, emit, join_room, leave_room
from flask_wtf.csrf import CSRFProtect
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from werkzeug.security import check_password_hash
from flask_migrate import Migrate
from models import db

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Initialize extensions (not tied to app yet)
csrf = CSRFProtect()
limiter = Limiter(key_func=get_remote_address)
socketio = SocketIO(cors_allowed_origins="*", async_mode='threading')
login_manager = LoginManager()
migrate = Migrate()

def create_app(config_name=None):
    """Application factory pattern"""
    if config_name is None:
        config_name = os.environ.get('FLASK_CONFIG', 'development')

    app = Flask(__name__)

    # Load configuration early
    from config import config
    app.config.from_object(config[config_name])

    # Initialize extensions with app
    db.init_app(app)
    csrf.init_app(app)
    limiter.init_app(app)
    socketio.init_app(app, cors_allowed_origins="*", async_mode='threading')
    login_manager.init_app(app)
    migrate.init_app(app, db)

    login_manager.login_view = 'auth.login'
    login_manager.login_message = 'Please log in to access this page.'
    login_manager.login_message_category = 'info'

    @login_manager.user_loader
    def load_user(user_id):
        from models import User
        return User.query.get(int(user_id))
    
    # Initialize Redis client and attach to app for use in routes/tasks
    try:
        app.redis_client = redis.Redis(host='localhost', port=6379, db=0)
        app.redis_client.ping()  # Test Redis connection
    except Exception as e:
        app.redis_client = None
        app.logger.error(f"Redis connection failed: {e}")

    # Create database tables and default admin - REMOVED db.create_all()
    with app.app_context():
        # Comment out db.create_all() - let migrations handle table creation
        # db.create_all()
        create_default_admin()

    # Import routes here to avoid circular imports
    import routes
    
    # Register blueprints
    app.register_blueprint(routes.auth_bp, url_prefix='/auth')
    app.register_blueprint(routes.main_bp)
    app.register_blueprint(routes.scan_bp, url_prefix='/scan')
    app.register_blueprint(routes.admin_bp, url_prefix='/admin')
    app.register_blueprint(routes.api_bp, url_prefix='/api/v1')

    # Register error handlers
    register_error_handlers(app)

    # Register context processors
    register_context_processors(app)

    return app

def create_default_admin():
    """Create default admin user if none exists"""
    try:
        from models import User, db
            
        admin = User.query.filter_by(role='admin').first()
        if not admin:
            admin_user = User(
                username='admin',
                email='admin@vulnalyze.local',
                full_name='System Administrator',
                role='admin',
                is_active=True,
                email_verified=True
            )
            admin_user.set_password('admin123')  # Change in production!
            db.session.add(admin_user)
            db.session.commit()
            logger.info("Created default admin user: admin / admin123")
    except Exception as e:
        # Tables don't exist yet - this is normal before migrations
        logger.info(f"Skipping admin creation (tables not created yet): {e}")
        pass

def register_error_handlers(app):
    """Register error handlers"""
    @app.errorhandler(403)
    def forbidden_error(error):
        return render_template('errors/403.html'), 403

    @app.errorhandler(404)
    def not_found_error(error):
        return render_template('errors/404.html'), 404

    @app.errorhandler(500)
    def internal_error(error):
        from models import db
        db.session.rollback()
        return render_template('errors/500.html'), 500

def register_context_processors(app):
    """Register context processors for templates"""
    @app.context_processor
    def inject_user_stats():
        """Inject user statistics into templates"""
        if current_user.is_authenticated:
            from models import ScanHistory
            recent_scans = current_user.scans.filter(
                ScanHistory.created_at >= datetime.utcnow() - timedelta(days=7)
            ).count()
            return {
                'user_recent_scans': recent_scans,
                'user_total_scans': current_user.total_scans,
                'user_total_vulns': current_user.total_vulnerabilities_found
            }
        return {}

    @app.context_processor
    def inject_system_info():
        """Inject system information"""
        return {
            'app_name': 'Vulnalyze',
            'app_version': '2.0.0',
            'current_year': datetime.utcnow().year
        }

# Decorators
def admin_required(f):
    """Decorator to require admin privileges"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or not current_user.is_admin:
            flash('Administrator privileges required.', 'error')
            return redirect(url_for('main.dashboard'))
        return f(*args, **kwargs)
    return decorated_function

# WebSocket event handlers
@socketio.on('join_scan_room')
def on_join_scan_room(data):
    """Join a scan-specific room for real-time updates"""
    if current_user.is_authenticated:
        scan_id = data.get('scan_id')
        if scan_id:
            join_room(f'scan_{scan_id}')
            emit('status', {'msg': f'Joined scan {scan_id} updates'})

@socketio.on('connect')
def on_connect():
    """Handle client connection"""
    if current_user.is_authenticated:
        emit('status', {'msg': f'Welcome {current_user.username}!'})

# Create app instance and socketio for imports in other modules
app = create_app()

@app.route('/dashboard')
@app.route('/')
@login_required
def dashboard():
    """Enhanced dashboard with proper statistics"""
    from models import ScanHistory, Vulnerability, db
    from forms import QuickScanForm
    from datetime import datetime, timedelta
    
    # Calculate statistics for current user
    user_scans = current_user.scans
    
    # Total scans
    total_scans = user_scans.count()
    
    # Recent scans (last 7 days)
    recent_scans_count = user_scans.filter(
        ScanHistory.created_at >= datetime.utcnow() - timedelta(days=7)
    ).count()
    
    # Total vulnerabilities - THIS IS THE KEY FIX
    total_vulnerabilities = db.session.query(Vulnerability).join(ScanHistory).filter(
        ScanHistory.user_id == current_user.id
    ).count()
    
    # Active/running scans
    active_scans = user_scans.filter(
        ScanHistory.status.in_(['running', 'pending'])
    ).count()
    
    # Recent scans for the table (last 10)
    recent_scans = user_scans.order_by(
        ScanHistory.created_at.desc()
    ).limit(10).all()
    
    # Create stats dictionary
    stats = {
        'total_scans': total_scans,
        'recent_scans': recent_scans_count,
        'total_vulnerabilities': total_vulnerabilities,
        'active_scans': active_scans
    }
    
    # Quick scan form
    quick_form = QuickScanForm()
    
    return render_template('dashboard/main.html', 
                         stats=stats, 
                         recent_scans=recent_scans,
                         quick_form=quick_form)

@app.route('/quick_scan', methods=['POST'])
@login_required
def quick_scan():
    """Handle quick scan form submission"""
    from forms import QuickScanForm
    form = QuickScanForm()
    if form.validate_on_submit():
        return redirect(url_for('scan.new', target_url=form.target_url.data))
    return redirect(url_for('main.dashboard'))
