"""
Migration: Remove old zlint adversarial learning fields

These fields are no longer used after switching to three-layer validation:
- zlint_verified (replaced by check_rule_coverage_intelligent)
- zlint_lint_name (not needed)
- zlint_match_method (not needed)

Run with: python migrations/remove_zlint_adversarial_fields.py
"""

import sys
from pathlib import Path

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from sqlalchemy import text
from app.core.database import engine


def migrate():
    """Remove zlint adversarial learning fields from rules table"""

    with engine.connect() as conn:
        print("Removing old zlint adversarial learning fields...")

        # Drop indexes first
        indexes_to_drop = [
            'idx_rule_zlint_verified',
            'idx_rule_zlint_lint_name'
        ]

        for index_name in indexes_to_drop:
            try:
                conn.execute(text(f"""
                    DROP INDEX IF EXISTS {index_name}
                """))
                print(f"  [OK] Dropped index: {index_name}")
            except Exception as e:
                print(f"  [WARN] Failed to drop index {index_name}: {e}")

        # Drop columns
        columns_to_drop = [
            'zlint_verified',
            'zlint_lint_name',
            'zlint_match_method'
        ]

        for column_name in columns_to_drop:
            try:
                result = conn.execute(text(f"""
                    SELECT column_name
                    FROM information_schema.columns
                    WHERE table_name = 'rules' AND column_name = '{column_name}'
                """))

                if result.fetchone():
                    conn.execute(text(f"""
                        ALTER TABLE rules DROP COLUMN IF EXISTS {column_name}
                    """))
                    print(f"  [OK] Dropped column: {column_name}")
                else:
                    print(f"  [-] Column {column_name} does not exist, skipping")
            except Exception as e:
                print(f"  [WARN] Failed to drop column {column_name}: {e}")

        conn.commit()
        print("\n[SUCCESS] Migration completed successfully!")
        print("Removed fields: zlint_verified, zlint_lint_name, zlint_match_method")
        print("Now using three-layer validation (check_rule_coverage_intelligent)")


def rollback():
    """Rollback: Add zlint adversarial learning fields back"""

    with engine.connect() as conn:
        print("Rolling back: Adding zlint adversarial learning fields...")

        # Add columns back
        try:
            conn.execute(text("""
                ALTER TABLE rules
                ADD COLUMN IF NOT EXISTS zlint_verified BOOLEAN DEFAULT FALSE
            """))
            print("  [OK] Added column: zlint_verified")
        except Exception as e:
            print(f"  [WARN] Failed to add zlint_verified: {e}")

        try:
            conn.execute(text("""
                ALTER TABLE rules
                ADD COLUMN IF NOT EXISTS zlint_lint_name VARCHAR(200)
            """))
            print("  [OK] Added column: zlint_lint_name")
        except Exception as e:
            print(f"  [WARN] Failed to add zlint_lint_name: {e}")

        try:
            conn.execute(text("""
                ALTER TABLE rules
                ADD COLUMN IF NOT EXISTS zlint_match_method VARCHAR(50)
            """))
            print("  [OK] Added column: zlint_match_method")
        except Exception as e:
            print(f"  [WARN] Failed to add zlint_match_method: {e}")

        # Create indexes
        try:
            conn.execute(text("""
                CREATE INDEX IF NOT EXISTS idx_rule_zlint_verified ON rules (zlint_verified)
            """))
            print("  [OK] Created index: idx_rule_zlint_verified")
        except Exception as e:
            print(f"  [WARN] Failed to create index idx_rule_zlint_verified: {e}")

        try:
            conn.execute(text("""
                CREATE INDEX IF NOT EXISTS idx_rule_zlint_lint_name ON rules (zlint_lint_name)
            """))
            print("  [OK] Created index: idx_rule_zlint_lint_name")
        except Exception as e:
            print(f"  [WARN] Failed to create index idx_rule_zlint_lint_name: {e}")

        conn.commit()
        print("\n[SUCCESS] Rollback completed successfully!")


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Migration for zlint adversarial learning fields")
    parser.add_argument("--rollback", action="store_true", help="Rollback the migration")
    args = parser.parse_args()

    if args.rollback:
        rollback()
    else:
        migrate()
