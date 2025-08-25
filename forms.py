"""
Enhanced forms.py with comprehensive validation and security features
"""

import re
from flask_wtf import FlaskForm
from flask_wtf.file import FileField, FileAllowed
from wtforms import (StringField, PasswordField, SubmitField, TextAreaField, 
                     SelectField, IntegerField, FloatField, BooleanField, 
                     SelectMultipleField, HiddenField)
from wtforms.validators import (InputRequired, Length, EqualTo, ValidationError, 
                               NumberRange, URL, Optional, Email)
from wtforms.widgets import CheckboxInput, ListWidget

def validate_password_strength(form, field):
    """Validate password strength requirements"""
    password = field.data
    if len(password) < 8:
        raise ValidationError('Password must be at least 8 characters long.')
    if not re.search(r'[A-Z]', password):
        raise ValidationError('Password must include at least one uppercase letter.')
    if not re.search(r'[a-z]', password):
        raise ValidationError('Password must include at least one lowercase letter.')
    if not re.search(r'\d', password):
        raise ValidationError('Password must include at least one digit.')
    if not re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
        raise ValidationError('Password must include at least one special character.')

def validate_url_format(form, field):
    """Validate URL format"""
    url = field.data
    if not url.startswith(('http://', 'https://')):
        raise ValidationError('URL must start with http:// or https://')

class MultiCheckboxField(SelectMultipleField):
    """Custom field for multiple checkboxes"""
    widget = ListWidget(prefix_label=False)
    option_widget = CheckboxInput()

class RegisterForm(FlaskForm):
    """User registration form"""
    username = StringField('Username', validators=[
        InputRequired(message='Username is required.'),
        Length(4, 80, message='Username must be between 4 and 80 characters.')
    ], render_kw={"placeholder": "Enter username"})

    email = StringField('Email', validators=[
        InputRequired(message='Email is required.'),
        Email(message='Invalid email address.')
    ], render_kw={"placeholder": "Enter your email address"})

    full_name = StringField('Full Name', validators=[
        Optional(),
        Length(1, 200, message='Full name cannot exceed 200 characters.')
    ], render_kw={"placeholder": "Enter your full name (optional)"})

    organization = StringField('Organization', validators=[
        Optional(),
        Length(1, 200, message='Organization name cannot exceed 200 characters.')
    ], render_kw={"placeholder": "Enter your organization (optional)"})

    password = PasswordField('Password', validators=[
        InputRequired(message='Password is required.'),
        Length(min=8, message='Password must be at least 8 characters long.'),
        validate_password_strength
    ], render_kw={"placeholder": "Enter password"})

    confirm_password = PasswordField('Confirm Password', validators=[
        InputRequired(message='Please confirm your password.'),
        EqualTo('password', message='Passwords must match.')
    ], render_kw={"placeholder": "Confirm password"})

    agree_terms = BooleanField('I agree to the Terms of Service and Privacy Policy', validators=[
        InputRequired(message='You must agree to the terms and conditions.')
    ])

    submit = SubmitField('Create Account')

    def validate_username(self, username):
        """Check if username already exists"""
        from models import User
        if User.query.filter_by(username=username.data).first():
            raise ValidationError('Username already exists. Please choose a different one.')

    def validate_email(self, email):
        """Check if email already exists"""
        from models import User
        if User.query.filter_by(email=email.data).first():
            raise ValidationError('Email already registered.')

class LoginForm(FlaskForm):
    """User login form"""
    username = StringField('Username', validators=[
        InputRequired(message='Username is required.'),
        Length(4, 80, message='Username must be between 4 and 80 characters.')
    ], render_kw={"placeholder": "Enter username"})

    password = PasswordField('Password', validators=[
        InputRequired(message='Password is required.')
    ], render_kw={"placeholder": "Enter password"})

    remember_me = BooleanField('Remember Me')
    submit = SubmitField('Sign In')

class ProfileForm(FlaskForm):
    """User profile management form"""
    username = StringField('Username', validators=[
        InputRequired(message='Username is required.'),
        Length(4, 80, message='Username must be between 4 and 80 characters.')
    ])

    email = StringField('Email', validators=[
        InputRequired(message='Email is required.'),
        Email(message='Invalid email address.')
    ])

    full_name = StringField('Full Name', validators=[
        Optional(),
        Length(1, 200, message='Full name cannot exceed 200 characters.')
    ])

    organization = StringField('Organization', validators=[
        Optional(),
        Length(1, 200, message='Organization name cannot exceed 200 characters.')
    ])

    avatar = FileField('Avatar', validators=[
        FileAllowed(['jpg', 'jpeg', 'png', 'gif'], 'Only image files are allowed.')
    ])

    theme_preference = SelectField('Theme', choices=[
        ('light', 'Light'),
        ('dark', 'Dark'),
        ('auto', 'Auto')
    ], default='light')

    email_notifications = BooleanField('Email Notifications', default=True)
    scan_notifications = BooleanField('Scan Notifications', default=True)

    submit = SubmitField('Update Profile')

class ChangePasswordForm(FlaskForm):
    """Password change form"""
    current_password = PasswordField('Current Password', validators=[
        InputRequired(message='Current password is required.')
    ], render_kw={"placeholder": "Enter current password"})

    new_password = PasswordField('New Password', validators=[
        InputRequired(message='New password is required.'),
        Length(min=8, message='Password must be at least 8 characters long.'),
        validate_password_strength
    ], render_kw={"placeholder": "Enter new password"})

    confirm_password = PasswordField('Confirm New Password', validators=[
        InputRequired(message='Please confirm your new password.'),
        EqualTo('new_password', message='Passwords must match.')
    ], render_kw={"placeholder": "Confirm new password"})

    submit = SubmitField('Change Password')

class ScanForm(FlaskForm):
    """New scan configuration form"""
    target_url = StringField('Target URL', validators=[
        InputRequired(message='Target URL is required.'),
        URL(message='Please enter a valid URL.'),
        validate_url_format
    ], render_kw={"placeholder": "https://example.com"})

    scan_type = SelectField('Scan Type', choices=[
        ('quick', 'Quick Scan'),
        ('comprehensive', 'Comprehensive Scan'),
        ('custom', 'Custom Scan')
    ], default='comprehensive')

    max_depth = IntegerField('Crawl Depth', validators=[
        InputRequired(message='Crawl depth is required.'),
        NumberRange(min=1, max=10, message='Depth must be between 1 and 10.')
    ], default=2)

    delay = FloatField('Request Delay (seconds)', validators=[
        InputRequired(message='Delay is required.'),
        NumberRange(min=0.1, max=10.0, message='Delay must be between 0.1 and 10 seconds.')
    ], default=1.0)

    plugins = MultiCheckboxField('Vulnerability Checks',
        choices=[
            ('xss', 'Cross-Site Scripting (XSS)'),
            ('sqli', 'SQL Injection'),
            ('csrf', 'CSRF Protection'),
            ('lfi', 'Local File Inclusion'),
            ('command', 'Command Injection'),
            ('redirect', 'Open Redirect'),
            ('traversal', 'Directory Traversal')
        ],
        default=['xss', 'sqli', 'csrf'])

    notes = TextAreaField('Notes', validators=[
        Optional(),
        Length(max=1000, message='Notes cannot exceed 1000 characters.')
    ], render_kw={"rows": 3, "placeholder": "Optional notes about this scan..."})

    submit = SubmitField('Start Security Scan')

class QuickScanForm(FlaskForm):
    """Quick scan form for dashboard"""
    target_url = StringField('Quick Scan URL', validators=[
        InputRequired(message='Target URL is required.'),
        URL(message='Please enter a valid URL.'),
        validate_url_format
    ], render_kw={"placeholder": "https://example.com"})

    submit = SubmitField('Quick Scan')

class SearchForm(FlaskForm):
    """Search form for scans and vulnerabilities"""
    query = StringField('Search', validators=[
        Length(max=200, message='Search query too long.')
    ], render_kw={"placeholder": "Search scans or vulnerabilities..."})

    filter_type = SelectField('Filter', choices=[
        ('all', 'All Results'),
        ('scans', 'Scans Only'),
        ('vulnerabilities', 'Vulnerabilities Only')
    ], default='all')

    submit = SubmitField('Search')

class AdminUserForm(FlaskForm):
    """Admin user management form"""
    username = StringField('Username', validators=[
        InputRequired(message='Username is required.'),
        Length(4, 80, message='Username must be between 4 and 80 characters.')
    ])

    email = StringField('Email', validators=[
        InputRequired(message='Email is required.'),
        Email(message='Invalid email address.')
    ])

    role = SelectField('Role', choices=[
        ('user', 'User'),
        ('admin', 'Administrator')
    ], validators=[InputRequired()])

    is_active = BooleanField('Account Active', default=True)
    reset_password = BooleanField('Reset Password to Default')

    submit = SubmitField('Update User')

class VulnerabilityForm(FlaskForm):
    """Vulnerability management form"""
    status = SelectField('Status', choices=[
        ('open', 'Open'),
        ('confirmed', 'Confirmed'),
        ('false_positive', 'False Positive'),
        ('fixed', 'Fixed')
    ])

    verified = BooleanField('Mark as Verified')
    false_positive = BooleanField('Mark as False Positive')

    notes = TextAreaField('Analyst Notes', validators=[
        Length(max=1000, message='Notes cannot exceed 1000 characters.')
    ], render_kw={"rows": 4, "placeholder": "Add notes about this vulnerability..."})

    submit = SubmitField('Update Vulnerability')

class ReportForm(FlaskForm):
    """Report generation form"""
    scan_ids = MultiCheckboxField('Select Scans', coerce=int)

    report_format = SelectField('Format', choices=[
        ('pdf', 'PDF Report'),
        ('json', 'JSON Export'),
        ('csv', 'CSV Export')
    ], default='pdf')

    include_details = BooleanField('Include Vulnerability Details', default=True)
    include_remediation = BooleanField('Include Remediation Advice', default=True)
    include_executive_summary = BooleanField('Include Executive Summary', default=True)

    submit = SubmitField('Generate Report')
