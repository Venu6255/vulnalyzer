"""
Database models for Vulnalyze application

Enhanced with security features and proper relationships
"""

from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
import json

db = SQLAlchemy()

class User(db.Model, UserMixin):
    """Enhanced User model with security features"""
    __tablename__ = 'users'

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False, index=True)
    email = db.Column(db.String(120), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(255), nullable=False)
    role = db.Column(db.String(20), default='user', index=True)

    # Profile information
    full_name = db.Column(db.String(200))
    avatar = db.Column(db.String(200))
    organization = db.Column(db.String(200))

    # Security and tracking
    is_active = db.Column(db.Boolean, default=True, nullable=False, index=True)
    email_verified = db.Column(db.Boolean, default=False)
    failed_login_attempts = db.Column(db.Integer, default=0)
    locked_until = db.Column(db.DateTime)

    # Timestamps
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    last_login = db.Column(db.DateTime)
    last_seen = db.Column(db.DateTime)

    # Statistics
    total_scans = db.Column(db.Integer, default=0)
    total_vulnerabilities_found = db.Column(db.Integer, default=0)

    # Settings
    email_notifications = db.Column(db.Boolean, default=True)
    scan_notifications = db.Column(db.Boolean, default=True)
    theme_preference = db.Column(db.String(20), default='light')

    # Relationships
    scans = db.relationship('ScanHistory', backref='owner', lazy='dynamic', cascade='all, delete-orphan')

    def set_password(self, password):
        """Hash and set password"""
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        """Check if provided password matches hash"""
        return check_password_hash(self.password_hash, password)

    @property
    def is_admin(self):
        """Check if user is admin"""
        return self.role == 'admin'

    def get_id(self):
        """Return user ID as string (required by Flask-Login)"""
        return str(self.id)

    def update_last_seen(self):
        """Update last seen timestamp"""
        self.last_seen = datetime.utcnow()
        db.session.commit()

    def update_stats(self):
        """Update user statistics"""
        self.total_scans = self.scans.count()
        from .models import Vulnerability, ScanHistory  # Avoid circular import if needed
        self.total_vulnerabilities_found = db.session.query(Vulnerability).join(ScanHistory).filter(
            ScanHistory.user_id == self.id
        ).count()
        db.session.commit()

    def to_dict(self):
        return {
            'id': self.id,
            'target_url': self.target_url,
            'status': self.status,
            'created_at': self.created_at.isoformat(),
            'completed_at': self.completed_at.isoformat() if self.completed_at else None,
            'duration': self.duration_formatted,
            'total_vulnerabilities': self.total_vulnerabilities,  # ensure present
            'risk_summary': self.risk_summary
        }

    def __repr__(self):
        return f'<User {self.username}>'


class ScanHistory(db.Model):
    """Enhanced scan history with comprehensive tracking"""
    __tablename__ = 'scan_history'

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False, index=True)

    # Scan details
    target_url = db.Column(db.String(500), nullable=False, index=True)
    scan_type = db.Column(db.String(50), default='comprehensive')

    # Status and timing
    status = db.Column(db.String(50), default='pending', nullable=False, index=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False, index=True)
    started_at = db.Column(db.DateTime)
    completed_at = db.Column(db.DateTime)
    scan_duration = db.Column(db.Float)

    # Results
    total_vulnerabilities = db.Column(db.Integer, default=0)
    critical_count = db.Column(db.Integer, default=0)
    high_count = db.Column(db.Integer, default=0)
    medium_count = db.Column(db.Integer, default=0)
    low_count = db.Column(db.Integer, default=0)
    info_count = db.Column(db.Integer, default=0)

    # Scan configuration
    max_depth = db.Column(db.Integer, default=2)
    delay_between_requests = db.Column(db.Float, default=1.0)
    selected_plugins = db.Column(db.JSON)
    pages_crawled = db.Column(db.Integer, default=0)
    urls_discovered = db.Column(db.Integer, default=0)

    # Task tracking
    task_id = db.Column(db.String(100), unique=True, index=True)
    progress = db.Column(db.Integer, default=0)
    current_operation = db.Column(db.String(200))

    # Additional metadata
    user_agent = db.Column(db.String(500))
    notes = db.Column(db.Text)
    tags = db.Column(db.JSON)

    # Relationships
    vulnerabilities = db.relationship('Vulnerability', backref='scan', lazy='dynamic', cascade='all, delete-orphan')

    @property
    def duration_formatted(self):
        """Return human-readable duration"""
        if not self.scan_duration:
            return "N/A"
        seconds = int(self.scan_duration)
        if seconds < 60:
            return f"{seconds}s"
        elif seconds < 3600:
            minutes = seconds // 60
            remaining_seconds = seconds % 60
            return f"{minutes}m {remaining_seconds}s"
        else:
            hours = seconds // 3600
            remaining_minutes = (seconds % 3600) // 60
            return f"{hours}h {remaining_minutes}m"

    @property
    def risk_summary(self):
        """Return risk level summary"""
        if self.critical_count > 0:
            return 'Critical'
        elif self.high_count > 0:
            return 'High'
        elif self.medium_count > 0:
            return 'Medium'
        elif self.low_count > 0:
            return 'Low'
        else:
            return 'None'

    def to_dict(self):
        """Convert scan to dictionary"""
        return {
            'id': self.id,
            'target_url': self.target_url,
            'status': self.status,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'completed_at': self.completed_at.isoformat() if self.completed_at else None,
            'duration': self.duration_formatted,
            'total_vulnerabilities': self.total_vulnerabilities,
            'risk_summary': self.risk_summary,
        }

    def __repr__(self):
        return f'<ScanHistory {self.id} - {self.target_url}>'


class Vulnerability(db.Model):
    """Comprehensive vulnerability model"""
    __tablename__ = 'vulnerabilities'

    id = db.Column(db.Integer, primary_key=True)
    scan_id = db.Column(db.Integer, db.ForeignKey('scan_history.id'), nullable=False, index=True)

    # Vulnerability classification
    vuln_type = db.Column(db.String(100), nullable=False, index=True)
    severity = db.Column(db.String(20), nullable=False, index=True)
    confidence = db.Column(db.String(20), default='Medium')

    # Location information
    url = db.Column(db.String(1000), index=True)
    method = db.Column(db.String(10), default='GET')
    parameter = db.Column(db.String(200))
    endpoint = db.Column(db.String(500))

    # Vulnerability details
    title = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text)
    impact = db.Column(db.Text)
    remediation = db.Column(db.Text)

    # Technical details
    payload = db.Column(db.Text)
    evidence = db.Column(db.Text)
    request_data = db.Column(db.JSON)
    response_data = db.Column(db.JSON)

    # Classification and references
    cwe_id = db.Column(db.String(20))
    owasp_category = db.Column(db.String(50))
    cvss_score = db.Column(db.Float)
    references = db.Column(db.JSON)

    # Status tracking
    status = db.Column(db.String(20), default='open')
    verified = db.Column(db.Boolean, default=False)
    false_positive = db.Column(db.Boolean, default=False)

    # Timestamps
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False, index=True)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    @property
    def severity_color(self):
        """Return Bootstrap color class for severity"""
        colors = {
            'Critical': 'danger',
            'High': 'warning',
            'Medium': 'info',
            'Low': 'success',
            'Info': 'secondary'
        }
        return colors.get(self.severity, 'secondary')

    @property
    def severity_icon(self):
        """Return icon for severity"""
        icons = {
            'Critical': 'fas fa-bomb',
            'High': 'fas fa-exclamation-triangle',
            'Medium': 'fas fa-exclamation-circle',
            'Low': 'fas fa-info-circle',
            'Info': 'fas fa-lightbulb'
        }
        return icons.get(self.severity, 'fas fa-question-circle')

    def to_dict(self):
        """Convert vulnerability to dictionary"""
        return {
            'id': self.id,
            'type': self.vuln_type,
            'severity': self.severity,
            'title': self.title,
            'url': self.url,
            'method': self.method,
            'parameter': self.parameter,
            'description': self.description,
            'remediation': self.remediation,
            'status': self.status,
            'created_at': self.created_at.isoformat() if self.created_at else None,
        }

    def __repr__(self):
        return f'<Vulnerability {self.title}>'


class SystemStats(db.Model):
    """System statistics tracking"""
    __tablename__ = 'system_stats'

    id = db.Column(db.Integer, primary_key=True)
    date = db.Column(db.Date, default=datetime.utcnow().date, nullable=False, index=True)

    # Daily statistics
    total_scans = db.Column(db.Integer, default=0)
    completed_scans = db.Column(db.Integer, default=0)
    failed_scans = db.Column(db.Integer, default=0)
    total_vulnerabilities = db.Column(db.Integer, default=0)

    # Vulnerability breakdown
    critical_vulns = db.Column(db.Integer, default=0)
    high_vulns = db.Column(db.Integer, default=0)
    medium_vulns = db.Column(db.Integer, default=0)
    low_vulns = db.Column(db.Integer, default=0)

    # User statistics
    active_users = db.Column(db.Integer, default=0)
    new_users = db.Column(db.Integer, default=0)
    unique_targets = db.Column(db.Integer, default=0)

    def __repr__(self):
        return f'<SystemStats {self.date}>'


class AuditLog(db.Model):
    """System audit logging"""
    __tablename__ = 'audit_logs'

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), index=True)

    # Action details
    action = db.Column(db.String(100), nullable=False, index=True)
    resource_type = db.Column(db.String(50))
    resource_id = db.Column(db.Integer)
    details = db.Column(db.JSON)

    # Request information
    ip_address = db.Column(db.String(45))
    user_agent = db.Column(db.String(500))
    endpoint = db.Column(db.String(200))

    # Timestamp
    timestamp = db.Column(db.DateTime, default=datetime.utcnow, nullable=False, index=True)

    def __repr__(self):
        return f'<AuditLog {self.id} - {self.action}>'
