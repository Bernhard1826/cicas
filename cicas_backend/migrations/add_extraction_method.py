"""
Migration script to add extraction_method column to rules table
Run: python migrations/add_extraction_method.py

Tracks rule extraction source:
- 'llm': LLM successfully processed (ir_data has value)
- 'regex_unclassified': skeleton not processed by LLM, saved as fallback
- 'manual': manually created rules (backwards compatibility)
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from sqlalchemy import text
from app.core.database import engine
from app.core.logging_config import app_logger


def apply_migration():
    try:
        with engine.connect() as conn:
            trans = conn.begin()

            try:
                # Check if column already exists
                result = conn.execute(text("""
                    SELECT column_name
                    FROM information_schema.columns
                    WHERE table_name='rules' AND column_name='extraction_method'
                """))

                if result.fetchone():
                    app_logger.info("Migration skipped: extraction_method column already exists")
                    print("✓ Migration skipped: extraction_method column already exists")
                    return

                # Add extraction_method column
                app_logger.info("Adding extraction_method column to rules table...")
                print("Adding extraction_method column to rules table...")
                conn.execute(text("""
                    ALTER TABLE rules
                    ADD COLUMN extraction_method VARCHAR(50) DEFAULT 'manual'
                """))

                # Set defaults based on existing data
                # If ir_data exists → 'llm', else → 'regex_unclassified'
                app_logger.info("Setting extraction_method values for existing rules...")
                print("Setting extraction_method values for existing rules...")
                conn.execute(text("""
                    UPDATE rules
                    SET extraction_method = CASE
                        WHEN ir_data IS NOT NULL AND ir_data != '' AND ir_data != 'null'
                        THEN 'llm'
                        ELSE 'regex_unclassified'
                    END
                """))

                # Create index
                app_logger.info("Creating index on extraction_method column...")
                print("Creating index on extraction_method column...")
                conn.execute(text("""
                    CREATE INDEX ix_rules_extraction_method ON rules(extraction_method)
                """))

                # Commit
                trans.commit()

                # Verify
                result = conn.execute(text("""
                    SELECT extraction_method, COUNT(*) as cnt
                    FROM rules
                    GROUP BY extraction_method
                    ORDER BY cnt DESC
                """))

                print("\n✓ Migration completed successfully!")
                print("\nCurrent rule extraction_method distribution:")
                for row in result:
                    print(f"  - {row[0]}: {row[1]} rules")

                app_logger.info("Migration completed successfully")

            except Exception as e:
                trans.rollback()
                raise e

    except Exception as e:
        app_logger.error(f"Migration failed: {e}")
        print(f"\n✗ Migration failed: {e}")
        sys.exit(1)


if __name__ == "__main__":
    print("=" * 60)
    print("PKI Standards Management System - Database Migration")
    print("Adding 'extraction_method' column to 'rules' table")
    print("=" * 60)
    print()

    apply_migration()