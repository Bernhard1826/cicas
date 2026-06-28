"""
Migration script to add status column to rules table
Run this script to apply the database schema changes.

Usage:
    python migrations/apply_migration.py
"""
import sys
from pathlib import Path

# Add parent directory to path to import app modules
sys.path.insert(0, str(Path(__file__).parent.parent))

from sqlalchemy import text
from app.core.database import engine
from app.core.logging_config import app_logger


def apply_migration():
    """Apply the migration to add status column to rules table"""
    try:
        with engine.connect() as conn:
            # Start transaction
            trans = conn.begin()

            try:
                # Check if status column already exists
                result = conn.execute(text("""
                    SELECT column_name
                    FROM information_schema.columns
                    WHERE table_name='rules' AND column_name='status'
                """))

                if result.fetchone():
                    app_logger.info("Migration skipped: status column already exists")
                    print("✓ Migration skipped: status column already exists")
                    return

                # Add status column
                app_logger.info("Adding status column to rules table...")
                print("Adding status column to rules table...")
                conn.execute(text("""
                    ALTER TABLE rules
                    ADD COLUMN status VARCHAR(50) DEFAULT 'active' NOT NULL
                """))

                # Create index
                app_logger.info("Creating index on status column...")
                print("Creating index on status column...")
                conn.execute(text("""
                    CREATE INDEX idx_rules_status ON rules(status)
                """))

                # Update existing rows (in case default didn't apply)
                app_logger.info("Updating existing rows...")
                print("Updating existing rows...")
                result = conn.execute(text("""
                    UPDATE rules SET status = 'active' WHERE status IS NULL
                """))

                # Commit transaction
                trans.commit()

                # Verify
                result = conn.execute(text("""
                    SELECT COUNT(*) as total, status
                    FROM rules
                    GROUP BY status
                """))

                print("\n✓ Migration completed successfully!")
                print("\nCurrent rule status distribution:")
                for row in result:
                    print(f"  - {row[1]}: {row[0]} rules")

                app_logger.info("Migration completed successfully")

            except Exception as e:
                # Rollback on error
                trans.rollback()
                raise e

    except Exception as e:
        app_logger.error(f"Migration failed: {e}")
        print(f"\n✗ Migration failed: {e}")
        sys.exit(1)


if __name__ == "__main__":
    print("=" * 60)
    print("PKI Standards Management System - Database Migration")
    print("Adding 'status' column to 'rules' table")
    print("=" * 60)
    print()

    apply_migration()
