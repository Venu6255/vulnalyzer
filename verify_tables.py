from app import create_app
from models import ScanHistory, Vulnerability

app = create_app()

with app.app_context():
    try:
        scan_count = ScanHistory.query.count()
        vuln_count = Vulnerability.query.count()
        print(f"✅ Database connected successfully!")
        print(f"   Scan History records: {scan_count}")
        print(f"   Vulnerability records: {vuln_count}")
    except Exception as e:
        print(f"❌ Database error: {e}")
