# create_tables_fix.py
from app import create_app
from models import db, User, ScanHistory, Vulnerability, SystemStats, AuditLog

print("Creating Flask app...")
app = create_app()

with app.app_context():
    print(f"Database URI: {app.config['SQLALCHEMY_DATABASE_URI']}")
    print("Creating all tables...")
    
    # Import all models to ensure they're registered
    from models import User, ScanHistory, Vulnerability, SystemStats, AuditLog
    
    # Create all tables
    db.create_all()
    
    print("Checking if tables were created...")
    from sqlalchemy import inspect
    inspector = inspect(db.engine)
    tables = inspector.get_table_names()
    print(f"Tables created: {tables}")
    
    if 'vulnerabilities' in tables:
        print("✅ SUCCESS: vulnerabilities table created!")
    else:
        print("❌ FAILED: vulnerabilities table missing!")
    
    print("Database setup complete!")
