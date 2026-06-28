"""
数据库迁移：添加批量验证进度跟踪字段
确保用户能看到实时验证进度，不会"等了很长时间没有结果返回"
"""

import psycopg2
import sys
import os

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.core.config import settings

def main():
    """添加批量验证进度跟踪字段到 ct_scan_tasks 表"""

    print("=" * 60)
    print("Database Migration: Add Validation Progress Fields")
    print("=" * 60)

    db_url = settings.database_url
    if db_url.startswith("postgresql://"):
        db_url = db_url.replace("postgresql://", "")

    parts = db_url.split("@")
    user_pass = parts[0].split(":")
    host_db = parts[1].split("/")

    conn = psycopg2.connect(
        host=host_db[0].split(":")[0],
        port=host_db[0].split(":")[1] if ":" in host_db[0] else "5432",
        database=host_db[1],
        user=user_pass[0],
        password=user_pass[1]
    )

    cursor = conn.cursor()

    try:
        print("\n1. Adding validation_status field...")
        cursor.execute("""
            ALTER TABLE ct_scan_tasks
            ADD COLUMN IF NOT EXISTS validation_status VARCHAR(50) DEFAULT 'not_started'
        """)
        print("   [OK] validation_status added")

        print("\n2. Adding validation_progress field...")
        cursor.execute("""
            ALTER TABLE ct_scan_tasks
            ADD COLUMN IF NOT EXISTS validation_progress INTEGER DEFAULT 0
        """)
        print("   [OK] validation_progress added")

        print("\n3. Adding validation_total field...")
        cursor.execute("""
            ALTER TABLE ct_scan_tasks
            ADD COLUMN IF NOT EXISTS validation_total INTEGER DEFAULT 0
        """)
        print("   [OK] validation_total added")

        print("\n4. Adding validation_started_at field...")
        cursor.execute("""
            ALTER TABLE ct_scan_tasks
            ADD COLUMN IF NOT EXISTS validation_started_at TIMESTAMP
        """)
        print("   [OK] validation_started_at added")

        print("\n5. Adding validation_completed_at field...")
        cursor.execute("""
            ALTER TABLE ct_scan_tasks
            ADD COLUMN IF NOT EXISTS validation_completed_at TIMESTAMP
        """)
        print("   [OK] validation_completed_at added")

        print("\n6. Adding validation_error field...")
        cursor.execute("""
            ALTER TABLE ct_scan_tasks
            ADD COLUMN IF NOT EXISTS validation_error TEXT
        """)
        print("   [OK] validation_error added")

        print("\n7. Creating index on validation_status...")
        cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_ct_scan_tasks_validation_status
            ON ct_scan_tasks(validation_status)
        """)
        print("   [OK] Index created")

        conn.commit()
        print("\n[SUCCESS] Migration completed!")
        print("   - All validation progress fields added")
        print("   - Users will now see real-time validation progress")
        print("   - No more waiting without results!")

    except Exception as e:
        conn.rollback()
        print(f"\n[ERROR] Migration failed: {e}")
        raise
    finally:
        cursor.close()
        conn.close()

if __name__ == "__main__":
    main()
