from app import app
from models import db, ScanHistory

with app.app_context():
    # Create tables if not already created
    db.create_all()
    
    # Verify connection and data access
    count = ScanHistory.query.count()
    print(f"Total scans in database: {count}")
