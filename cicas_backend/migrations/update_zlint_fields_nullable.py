"""
数据库迁移：修改zlint字段为nullable，移除默认值
默认NULL表示"未验证"状态
"""

import psycopg2
import sys
import os

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.core.config import settings

def main():
    """修改zlint字段为nullable，表示未验证状态"""

    print("=" * 60)
    print("Database Migration: Update zlint fields to nullable")
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
        print("\n1. Updating is_zlint_compliant field...")
        # 移除NOT NULL约束和默认值
        cursor.execute("""
            ALTER TABLE ct_certificate_idn_results
            ALTER COLUMN is_zlint_compliant DROP NOT NULL,
            ALTER COLUMN is_zlint_compliant DROP DEFAULT
        """)
        print("   [OK] is_zlint_compliant is now nullable")

        print("\n2. Updating zlint_violation_count field...")
        cursor.execute("""
            ALTER TABLE ct_certificate_idn_results
            ALTER COLUMN zlint_violation_count DROP NOT NULL,
            ALTER COLUMN zlint_violation_count DROP DEFAULT
        """)
        print("   [OK] zlint_violation_count is now nullable")

        print("\n3. Updating existing records...")
        # 将默认值改为NULL（只更新那些明显是默认值的记录）
        cursor.execute("""
            UPDATE ct_certificate_idn_results
            SET
                is_zlint_compliant = NULL,
                zlint_violation_count = NULL,
                zlint_violations = NULL
            WHERE
                (is_zlint_compliant = TRUE AND zlint_violation_count = 0 AND zlint_violations IS NULL)
                OR (is_zlint_compliant = TRUE AND zlint_violation_count = 0 AND zlint_violations = '[]')
        """)
        updated = cursor.rowcount
        print(f"   [OK] Updated {updated} default records to NULL (unvalidated)")

        conn.commit()
        print("\n[SUCCESS] Migration completed!")
        print("   - Fields are now nullable")
        print("   - Default values removed")
        print(f"   - {updated} records updated to unvalidated state")

    except Exception as e:
        conn.rollback()
        print(f"\n[ERROR] Migration failed: {e}")
        raise
    finally:
        cursor.close()
        conn.close()

if __name__ == "__main__":
    main()
