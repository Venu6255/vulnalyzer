import os
from sqlalchemy import create_engine, text

# Use same database URI as config
basedir = os.path.abspath(os.path.dirname(__file__))
DATABASE_URI = os.environ.get('DATABASE_URL') or f"sqlite:///{os.path.join(basedir, 'vulnalyze.db')}"

print(f"Testing database connection: {DATABASE_URI}")

try:
    engine = create_engine(DATABASE_URI)
    with engine.connect() as conn:
        # Check if scan_history table exists
        result = conn.execute(text("SELECT name FROM sqlite_master WHERE type='table' AND name='scan_history'"))
        table_exists = result.fetchone() is not None
        
        if table_exists:
            # Count records
            result = conn.execute(text("SELECT COUNT(*) FROM scan_history"))
            count = result.fetchone()[0]
            print(f"✅ Database connected successfully!")
            print(f"✅ scan_history table exists with {count} records")
        else:
            print("❌ scan_history table does NOT exist")
            
except Exception as e:
    print(f"❌ Database connection failed: {e}")
