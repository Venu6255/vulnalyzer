"""
Route blueprints for Vulnalyze application
Organized into separate blueprints for better structure
"""

import os
import redis
from datetime import datetime, timedelta
from urllib.parse import urlparse
from flask import (Blueprint, render_template, request, redirect, url_for, make_response,
                   flash, jsonify, abort, current_app, send_file)
from flask_login import login_user, logout_user, login_required, current_user
from werkzeug.utils import secure_filename
from models import db, User, ScanHistory, Vulnerability, SystemStats, AuditLog
from forms import (LoginForm, RegisterForm, ScanForm, ProfileForm, ChangePasswordForm,
                  SearchForm, AdminUserForm, QuickScanForm, VulnerabilityForm, ReportForm)
# Import Celery functions here to avoid circular imports
from celery.result import AsyncResult
from plugins import get_available_plugins

import io
import csv
import xlsxwriter
from openpyxl import Workbook
from reportlab.lib.pagesizes import letter, A4
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer
from reportlab.lib.units import inch

# Blueprint definitions
auth_bp = Blueprint('auth', __name__)
main_bp = Blueprint('main', __name__)
scan_bp = Blueprint('scan', __name__)
admin_bp = Blueprint('admin', __name__)
api_bp = Blueprint('api', __name__)

# Authentication Routes
@auth_bp.route('/login', methods=['GET', 'POST'])
def login():
    """User login"""
    if current_user.is_authenticated:
        return redirect(url_for('main.dashboard'))

    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()

        if user and user.check_password(form.password.data):
            if not user.is_active:
                flash('Your account has been deactivated. Contact administrator.', 'error')
                return render_template('auth/login.html', form=form)

            # Check for account lockout
            if user.locked_until and user.locked_until > datetime.utcnow():
                flash('Account is temporarily locked due to failed login attempts.', 'error')
                return render_template('auth/login.html', form=form)

            # Reset failed attempts on successful login
            user.failed_login_attempts = 0
            user.locked_until = None
            user.last_login = datetime.utcnow()
            db.session.commit()

            login_user(user, remember=form.remember_me.data)
            next_page = request.args.get('next')
            if next_page and urlparse(next_page).netloc == '':
                return redirect(next_page)

            flash(f'Welcome back, {user.username}!', 'success')
            return redirect(url_for('main.dashboard'))
        else:
            # Handle failed login
            if user:
                user.failed_login_attempts += 1
                if user.failed_login_attempts >= 5:
                    user.locked_until = datetime.utcnow() + timedelta(minutes=15)
                    flash('Account locked for 15 minutes due to too many failed attempts.', 'error')
                else:
                    flash(f'Invalid credentials. {5 - user.failed_login_attempts} attempts remaining.', 'error')
                db.session.commit()
            else:
                flash('Invalid username or password.', 'error')

    return render_template('auth/login.html', form=form)

@auth_bp.route('/register', methods=['GET', 'POST'])
def register():
    """User registration"""
    if current_user.is_authenticated:
        return redirect(url_for('main.dashboard'))

    form = RegisterForm()
    if form.validate_on_submit():
        user = User(
            username=form.username.data,
            email=form.email.data,
            full_name=form.full_name.data or None,
            organization=form.organization.data or None,
            role='user',
            is_active=True
        )
        user.set_password(form.password.data)
        db.session.add(user)
        db.session.commit()

        flash('Registration successful! You can now log in.', 'success')
        return redirect(url_for('auth.login'))

    return render_template('auth/register.html', form=form)

@auth_bp.route('/logout')
@login_required
def logout():
    """User logout"""
    username = current_user.username
    logout_user()
    flash(f'Goodbye, {username}!', 'info')
    return redirect(url_for('main.index'))

# Main Routes
@main_bp.route('/')
def index():
    """Landing page"""
    if current_user.is_authenticated:
        return redirect(url_for('main.dashboard'))
    return render_template('main/index.html')

@main_bp.route('/dashboard')
@login_required
def dashboard():
    """User dashboard"""
    # Get recent scans
    recent_scans = current_user.scans.order_by(ScanHistory.created_at.desc()).limit(5).all()

    # Get vulnerability statistics
    total_vulns = db.session.query(Vulnerability).join(ScanHistory).filter(
        ScanHistory.user_id == current_user.id
    ).count()

    recent_vulns = db.session.query(Vulnerability).join(ScanHistory).filter(
        ScanHistory.user_id == current_user.id,
        Vulnerability.created_at >= datetime.utcnow() - timedelta(days=7)
    ).count()

    # Get scan statistics
    stats = {
        'total_scans': current_user.total_scans,
        'recent_scans': current_user.scans.filter(
            ScanHistory.created_at >= datetime.utcnow() - timedelta(days=7)
        ).count(),
        'total_vulnerabilities': total_vulns,
        'recent_vulnerabilities': recent_vulns,
        'active_scans': current_user.scans.filter(
            ScanHistory.status.in_(['pending', 'running'])
        ).count()
    }

    # Quick scan form
    quick_form = QuickScanForm()

    return render_template('main/dashboard.html',
                         recent_scans=recent_scans,
                         stats=stats,
                         quick_form=quick_form)

@main_bp.route('/profile', methods=['GET', 'POST'])
@login_required
def profile():
    """User profile management"""
    form = ProfileForm(obj=current_user)
    password_form = ChangePasswordForm()

    if form.validate_on_submit() and 'profile_submit' in request.form:
        current_user.username = form.username.data
        current_user.email = form.email.data
        current_user.full_name = form.full_name.data
        current_user.organization = form.organization.data
        current_user.theme_preference = form.theme_preference.data
        current_user.email_notifications = form.email_notifications.data
        current_user.scan_notifications = form.scan_notifications.data
        db.session.commit()

        flash('Profile updated successfully!', 'success')
        return redirect(url_for('main.profile'))

    if password_form.validate_on_submit() and 'password_submit' in request.form:
        if current_user.check_password(password_form.current_password.data):
            current_user.set_password(password_form.new_password.data)
            db.session.commit()
            flash('Password changed successfully!', 'success')
            return redirect(url_for('main.profile'))
        else:
            flash('Current password is incorrect.', 'error')

    return render_template('main/profile.html',
                         form=form,
                         password_form=password_form)

@main_bp.route('/change-password', methods=['GET', 'POST'])
@login_required
def change_password():
    form = ChangePasswordForm()
    if form.validate_on_submit():
        # Verify current password
        if not current_user.check_password(form.current_password.data):
            flash('Current password is incorrect.', 'error')
            return render_template('main/change_password.html', form=form)

        # Set new password
        current_user.set_password(form.new_password.data)
        db.session.commit()
        flash('Password changed successfully!', 'success')
        return redirect(url_for('main.profile'))

    return render_template('main/change_password.html', form=form)

# Scan Routes
@scan_bp.route('/new', methods=['GET', 'POST'])
@login_required
def new():
    """Create new scan"""
    form = ScanForm()
    if form.validate_on_submit():
        # Create new scan record
        scan = ScanHistory(
            user_id=current_user.id,
            target_url=form.target_url.data,
            scan_type=form.scan_type.data,
            max_depth=form.max_depth.data,
            delay_between_requests=form.delay.data,
            selected_plugins=form.plugins.data,
            status='pending',
            notes=form.notes.data
        )
        db.session.add(scan)
        db.session.flush()  # Get scan ID

        # Start background scan task
        try:
            # Import celery task function here to avoid circular imports
            from celery_worker import run_scan_task
            
            task = run_scan_task.delay(
                target_url=form.target_url.data,
                max_depth=form.max_depth.data,
                delay=form.delay.data,
                selected_plugins=form.plugins.data,
                scan_id=scan.id,
                user_id=current_user.id
            )

            scan.task_id = task.id
            scan.status = 'queued'
            db.session.commit()

            flash('Scan started successfully! You will be notified when complete.', 'success')
            return redirect(url_for('scan.status', scan_id=scan.id))

        except Exception as e:
            scan.status = 'failed'
            scan.current_operation = f'Failed to start: {str(e)}'
            db.session.commit()
            flash('Failed to start scan. Please try again.', 'error')

    available_plugins = get_available_plugins()
    return render_template('scan/new.html', form=form, available_plugins=available_plugins)

@scan_bp.route('/status/<int:scan_id>')
@login_required
def status(scan_id):
    """View scan status and results"""
    scan = ScanHistory.query.get_or_404(scan_id)

    # Check ownership or admin rights
    if scan.user_id != current_user.id and not current_user.is_admin:
        abort(403)

    vulnerabilities = scan.vulnerabilities.order_by(
        Vulnerability.severity.desc(),
        Vulnerability.created_at.desc()
    ).all()

    return render_template('scan/status.html', scan=scan, vulnerabilities=vulnerabilities)

@scan_bp.route('/list')
@login_required
def list_scans():
    """List user's scans"""
    page = request.args.get('page', 1, type=int)
    search_form = SearchForm()
    query = current_user.scans

    # Apply search filter
    if request.args.get('q'):
        search_term = request.args.get('q')
        query = query.filter(ScanHistory.target_url.contains(search_term))

    # Apply status filter
    status_filter = request.args.get('status')
    if status_filter and status_filter != 'all':
        query = query.filter(ScanHistory.status == status_filter)

    scans = query.order_by(ScanHistory.created_at.desc()).paginate(
        page=page, per_page=10, error_out=False
    )

    return render_template('scan/list.html', scans=scans, search_form=search_form)

@scan_bp.route('/cancel/<int:scan_id>', methods=['POST'])
@login_required
def cancel_scan(scan_id):
    scan = ScanHistory.query.get_or_404(scan_id)

    # Check if current user owns the scan or is admin
    if scan.user_id != current_user.id and not current_user.is_admin:
        return jsonify({"error": "Unauthorized"}), 403

    # Only running or queued scans can be cancelled
    if scan.status not in ['running', 'queued']:
        return jsonify({"error": "Scan not running or queued"}), 400

    if not scan.task_id:
        return jsonify({"error": "No task associated with this scan"}), 400

    # Import celery app here to avoid circular imports
    from celery_worker import celery_app
    
    # Revoke Celery task
    try:
        celery_app.control.revoke(scan.task_id, terminate=True)
    except Exception as e:
        current_app.logger.error(f"Error revoking Celery task {scan.task_id}: {e}")

    # Update scan status in database
    scan.status = 'cancelled'
    scan.current_operation = 'Scan cancelled by user'
    db.session.commit()

    return jsonify({"message": "Scan cancellation requested"}), 200

# Quick scan from dashboard
@main_bp.route('/quick-scan', methods=['POST'])
@login_required
def quick_scan():
    """Quick scan from dashboard"""
    form = QuickScanForm()
    if form.validate_on_submit():
        # Create quick scan with default settings
        scan = ScanHistory(
            user_id=current_user.id,
            target_url=form.target_url.data,
            scan_type='quick',
            max_depth=2,
            delay_between_requests=1.0,
            selected_plugins=['xss', 'sqli', 'csrf'],
            status='pending'
        )
        db.session.add(scan)
        db.session.flush()

        try:
            from celery_worker import run_scan_task
            
            task = run_scan_task.delay(
                target_url=form.target_url.data,
                max_depth=2,
                delay=1.0,
                selected_plugins=['xss', 'sqli', 'csrf'],
                scan_id=scan.id,
                user_id=current_user.id
            )

            scan.task_id = task.id
            scan.status = 'queued'
            db.session.commit()

            flash('Quick scan started!', 'success')
            return redirect(url_for('scan.status', scan_id=scan.id))

        except Exception as e:
            scan.status = 'failed'
            db.session.commit()
            flash('Failed to start quick scan.', 'error')

    return redirect(url_for('main.dashboard'))

# Scan progress endpoint
@main_bp.route('/scan/<int:scan_id>/progress')
@login_required
def scan_progress(scan_id):
    """Get scan progress via AJAX"""
    scan = ScanHistory.query.get_or_404(scan_id)

    if scan.user_id != current_user.id and not current_user.is_admin:
        abort(403)

    return jsonify({
        'status': scan.status,
        'progress': scan.progress,
        'current_operation': scan.current_operation,
        'vulnerabilities_found': scan.total_vulnerabilities
    })

# Admin Routes
@admin_bp.route('/')
@login_required
def dashboard():
    """Admin dashboard"""
    if not current_user.is_admin:
        abort(403)

    # Get system statistics
    total_users = User.query.count()
    active_users = User.query.filter_by(is_active=True).count()
    total_scans = ScanHistory.query.count()
    total_vulnerabilities = Vulnerability.query.count()


    # Recent activity
    recent_scans = ScanHistory.query.order_by(ScanHistory.created_at.desc()).limit(10).all()
    recent_users = User.query.order_by(User.created_at.desc()).limit(5).all()

    stats = {
        'total_users': total_users,
        'active_users': active_users,
        'total_scans': total_scans,
        'total_vulnerabilities': total_vulnerabilities
    }

    return render_template('admin/dashboard.html',
                         stats=stats,
                         recent_scans=recent_scans,
                         recent_users=recent_users,
                         total_vulnerabilities=total_vulnerabilities)

@admin_bp.route('/users')
@login_required
def users():
    """User management"""
    if not current_user.is_admin:
        abort(403)

    page = request.args.get('page', 1, type=int)
    users = User.query.order_by(User.created_at.desc()).paginate(
        page=page, per_page=20, error_out=False
    )

    return render_template('admin/users.html', users=users)

@admin_bp.route('/toggle_user/<int:user_id>', methods=['POST'])
@login_required
def toggle_user(user_id):
    """Toggle a user's active status"""
    if not current_user.is_admin:
        abort(403)
    
    user = User.query.get_or_404(user_id)
    user.is_active = not user.is_active
    db.session.commit()
    return redirect(url_for('admin.users'))

# API Routes
@api_bp.route('/scans', methods=['GET'])
@login_required
def api_list_scans():
    """API endpoint to list scans"""
    scans = current_user.scans.order_by(ScanHistory.created_at.desc()).limit(10).all()
    return jsonify([scan.to_dict() for scan in scans])

@api_bp.route('/scans/<int:scan_id>', methods=['GET'])
@login_required
def api_get_scan(scan_id):
    """API endpoint to get scan details"""
    scan = ScanHistory.query.get_or_404(scan_id)

    if scan.user_id != current_user.id and not current_user.is_admin:
        abort(403)

    return jsonify(scan.to_dict())

@scan_bp.route('/export/<int:scan_id>/<format>')
@login_required
def export_scan(scan_id, format):
    """Export scan results in PDF, CSV, or Excel format"""
    scan = ScanHistory.query.get_or_404(scan_id)
    
    # Check ownership or admin rights
    if scan.user_id != current_user.id and not current_user.is_admin:
        abort(403)
    
    vulnerabilities = scan.vulnerabilities.order_by(
        Vulnerability.severity.desc(),
        Vulnerability.created_at.desc()
    ).all()
    
    if format.lower() == 'pdf':
        return export_pdf(scan, vulnerabilities)
    elif format.lower() == 'csv':
        return export_csv(scan, vulnerabilities)
    elif format.lower() in ['excel', 'xlsx']:
        return export_excel(scan, vulnerabilities)
    else:
        abort(400)

def export_pdf(scan, vulnerabilities):
    """Generate PDF report"""
    buffer = io.BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=A4)
    styles = getSampleStyleSheet()
    story = []
    
    # Title
    title = Paragraph(f"<b>Vulnerability Scan Report</b>", styles['Title'])
    story.append(title)
    story.append(Spacer(1, 20))
    
    # Scan details
    scan_info = f"""
    <b>Target URL:</b> {scan.target_url}<br/>
    <b>Scan Date:</b> {scan.created_at.strftime('%Y-%m-%d %H:%M')}<br/>
    <b>Status:</b> {scan.status}<br/>
    <b>Duration:</b> {scan.duration_formatted}<br/>
    <b>Total Vulnerabilities:</b> {scan.total_vulnerabilities}<br/>
    """
    story.append(Paragraph(scan_info, styles['Normal']))
    story.append(Spacer(1, 20))
    
    if vulnerabilities:
        # Vulnerability table
        data = [['Severity', 'Type', 'URL', 'Parameter', 'Description']]
        for vuln in vulnerabilities:
            data.append([
                vuln.severity,
                vuln.vuln_type,
                vuln.url[:50] + '...' if len(vuln.url) > 50 else vuln.url,
                vuln.parameter or 'N/A',
                (vuln.description[:100] + '...') if vuln.description and len(vuln.description) > 100 else (vuln.description or 'N/A')
            ])
        
        table = Table(data, colWidths=[1*inch, 1*inch, 2*inch, 1*inch, 2*inch])
        table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, 0), 10),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
            ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
            ('GRID', (0, 0), (-1, -1), 1, colors.black),
            ('FONTSIZE', (0, 1), (-1, -1), 8),
        ]))
        story.append(table)
    
    doc.build(story)
    buffer.seek(0)
    
    response = make_response(buffer.getvalue())
    response.headers['Content-Type'] = 'application/pdf'
    response.headers['Content-Disposition'] = f'attachment; filename=scan_{scan.id}_report.pdf'
    return response

def export_csv(scan, vulnerabilities):
    """Generate CSV report without pandas"""
    output = io.StringIO()
    writer = csv.writer(output)
    
    # Write header
    writer.writerow(['Scan ID', 'Target URL', 'Scan Date', 'Severity', 'Vulnerability Type', 
                     'URL', 'Parameter', 'Description', 'Remediation', 'Payload', 'Evidence'])
    
    # Write data
    for vuln in vulnerabilities:
        writer.writerow([
            scan.id,
            scan.target_url,
            scan.created_at.strftime('%Y-%m-%d %H:%M'),
            vuln.severity,
            vuln.vuln_type,
            vuln.url,
            vuln.parameter or 'N/A',
            vuln.description or 'N/A',
            vuln.remediation or 'N/A',
            vuln.payload or 'N/A',
            vuln.evidence or 'N/A'
        ])
    
    response = make_response(output.getvalue())
    response.headers['Content-Type'] = 'text/csv'
    response.headers['Content-Disposition'] = f'attachment; filename=scan_{scan.id}_report.csv'
    return response

def export_excel(scan, vulnerabilities):
    """Generate Excel report using xlsxwriter"""
    output = io.BytesIO()
    
    with xlsxwriter.Workbook(output) as workbook:
        worksheet = workbook.add_worksheet('Vulnerability Report')
        
        # Write headers
        headers = ['Scan ID', 'Target URL', 'Scan Date', 'Severity', 'Vulnerability Type', 
                   'URL', 'Parameter', 'Description', 'Remediation', 'Payload', 'Evidence']
        for col, header in enumerate(headers):
            worksheet.write(0, col, header)
        
        # Write data
        for row, vuln in enumerate(vulnerabilities, 1):
            worksheet.write(row, 0, scan.id)
            worksheet.write(row, 1, scan.target_url)
            worksheet.write(row, 2, scan.created_at.strftime('%Y-%m-%d %H:%M'))
            worksheet.write(row, 3, vuln.severity)
            worksheet.write(row, 4, vuln.vuln_type)
            worksheet.write(row, 5, vuln.url)
            worksheet.write(row, 6, vuln.parameter or 'N/A')
            worksheet.write(row, 7, vuln.description or 'N/A')
            worksheet.write(row, 8, vuln.remediation or 'N/A')
            worksheet.write(row, 9, vuln.payload or 'N/A')
            worksheet.write(row, 10, vuln.evidence or 'N/A')
    
    output.seek(0)
    
    response = make_response(output.getvalue())
    response.headers['Content-Type'] = 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'
    response.headers['Content-Disposition'] = f'attachment; filename=scan_{scan.id}_report.xlsx'
    return response