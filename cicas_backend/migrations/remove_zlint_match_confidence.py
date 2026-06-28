"""
Migration: Remove zlint_match_confidence column

This field is redundant with similarity_score.
Now using similarity_score >= 0.95 to determine zlint coverage.

Run with: python migrations/remove_zlint_match_confidence.py
"""

import sys
from pathlib import Path

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from sqlalchemy import text
from app.core.database import engine


def migrate():
    """Remove zlint_match_confidence column from rules table"""

    with engine.connect() as conn:
        # Check if column exists
        result = conn.execute(text("""
            SELECT column_name
            FROM information_schema.columns
            WHERE table_name = 'rules' AND column_name = 'zlint_match_confidence'
        """))

        if result.fetchone():
            print("Dropping zlint_match_confidence column...")
            conn.execute(text("""
                ALTER TABLE rules DROP COLUMN IF EXISTS zlint_match_confidence
            """))
            conn.commit()
            print("✅ Successfully removed zlint_match_confidence column")
        else:
            print("Column zlint_match_confidence does not exist, skipping")


def rollback():
    """Rollback: Add zlint_match_confidence column back"""

    with engine.connect() as conn:
        result = conn.execute(text("""
            SELECT column_name
            FROM information_schema.columns
            WHERE table_name = 'rules' AND column_name = 'zlint_match_confidence'
        """))

        if not result.fetchone():
            print("Adding zlint_match_confidence column back...")
            conn.execute(text("""
                ALTER TABLE rules ADD COLUMN zlint_match_confidence FLOAT
            """))
            conn.commit()
            print("✅ Successfully added zlint_match_confidence column")
        else:
            print("Column zlint_match_confidence already exists")


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Migration for zlint_match_confidence")
    parser.add_argument("--rollback", action="store_true", help="Rollback the migration")
    args = parser.parse_args()

    if args.rollback:
        rollback()
    else:
        migrate()
