"""
Migration: Extend operation field length from 100 to 300

Fix for: DataError - value too long for type character varying(100)
Some operation values can be very long (e.g., 124+ characters)

Run with: python migrations/extend_operation_field_length.py
"""

import sys
from pathlib import Path

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from sqlalchemy import text
from app.core.database import engine


def migrate():
    """Extend operation field length from VARCHAR(100) to VARCHAR(300)"""

    with engine.connect() as conn:
        print("Extending operation field length...")

        try:
            # Check current column type
            result = conn.execute(text("""
                SELECT character_maximum_length
                FROM information_schema.columns
                WHERE table_name = 'rules' AND column_name = 'operation'
            """))

            current_length = result.fetchone()
            if current_length:
                print(f"  Current operation field length: {current_length[0]}")

            # Alter column type
            conn.execute(text("""
                ALTER TABLE rules
                ALTER COLUMN operation TYPE VARCHAR(300)
            """))

            conn.commit()
            print("  [OK] Extended operation field to VARCHAR(300)")
            print("\n[SUCCESS] Migration completed successfully!")
            print("operation field can now store up to 300 characters")

        except Exception as e:
            conn.rollback()
            print(f"  [ERROR] Migration failed: {e}")
            raise


def rollback():
    """Rollback: Revert operation field to VARCHAR(100)"""

    with engine.connect() as conn:
        print("Rolling back: Reverting operation field to VARCHAR(100)...")

        try:
            conn.execute(text("""
                ALTER TABLE rules
                ALTER COLUMN operation TYPE VARCHAR(100)
            """))

            conn.commit()
            print("  [OK] Reverted operation field to VARCHAR(100)")
            print("\n[SUCCESS] Rollback completed successfully!")
            print("WARNING: This may cause data truncation if any values exceed 100 chars")

        except Exception as e:
            conn.rollback()
            print(f"  [ERROR] Rollback failed: {e}")
            raise


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Migration for operation field length")
    parser.add_argument("--rollback", action="store_true", help="Rollback the migration")
    args = parser.parse_args()

    if args.rollback:
        rollback()
    else:
        migrate()
