"""
Migration: Add requirement_level and target_type fields to rules table
"""
import sys
import os

# Add the parent directory to the path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from sqlalchemy import text
from app.core.database import engine
from app.core.logging_config import app_logger


def upgrade():
    """Add requirement_level and target_type fields"""
    with engine.connect() as conn:
        try:
            # Add requirement_level field
            conn.execute(text("""
                ALTER TABLE rules
                ADD COLUMN IF NOT EXISTS requirement_level VARCHAR(20);
            """))
            conn.commit()
            app_logger.info("✓ Added requirement_level field to rules table")

            # Add target_type field with index
            conn.execute(text("""
                ALTER TABLE rules
                ADD COLUMN IF NOT EXISTS target_type VARCHAR(50);
            """))
            conn.commit()
            app_logger.info("✓ Added target_type field to rules table")

            # Create index on target_type
            conn.execute(text("""
                CREATE INDEX IF NOT EXISTS idx_rule_target_type ON rules(target_type);
            """))
            conn.commit()
            app_logger.info("✓ Created index on target_type")

            app_logger.info("Migration completed successfully!")

        except Exception as e:
            conn.rollback()
            app_logger.error(f"Migration failed: {e}")
            raise


def downgrade():
    """Remove requirement_level and target_type fields"""
    with engine.connect() as conn:
        try:
            # Drop index first
            conn.execute(text("""
                DROP INDEX IF EXISTS idx_rule_target_type;
            """))
            conn.commit()

            # Drop target_type field
            conn.execute(text("""
                ALTER TABLE rules
                DROP COLUMN IF EXISTS target_type;
            """))
            conn.commit()

            # Drop requirement_level field
            conn.execute(text("""
                ALTER TABLE rules
                DROP COLUMN IF EXISTS requirement_level;
            """))
            conn.commit()

            app_logger.info("Downgrade completed successfully!")

        except Exception as e:
            conn.rollback()
            app_logger.error(f"Downgrade failed: {e}")
            raise


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description='Migrate database')
    parser.add_argument('--downgrade', action='store_true', help='Downgrade instead of upgrade')
    args = parser.parse_args()

    if args.downgrade:
        print("Running downgrade...")
        downgrade()
    else:
        print("Running upgrade...")
        upgrade()
