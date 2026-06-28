"""
Migration: Add exception_rules table

Creates:
1. exception_rules - 存储从规范文本中提取的例外规则（自动检测的RFC/CABF例外句式）

Design principle: EffectiveRule = NormalRule ∧ ¬ ExceptionRule

Exception patterns (基于RFC/CABF真实例外语言):
- UNLESS: "The subject field MUST be present unless the subjectAltName extension is present"
- ONLY_IF: "MUST use the rfc822Name only if such identities are present"
- EXCEPT: "CAs SHALL verify domain control except for domains validated under Enterprise RA"
- DOES_NOT_APPLY_TO: "This requirement does not apply to self-signed certificates"
- IN_CASE_OF: "In the case of a Key Compromise, the CA MUST revoke within 24 hours"

Run with: python migrations/add_exception_rules_table.py
"""

import sys
from pathlib import Path

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from sqlalchemy import text
from app.core.database import engine


def migrate():
    """Create exception_rules table and update rules table relationship"""

    with engine.connect() as conn:
        # 1. Create exception_rules table
        print("Creating exception_rules table...")
        conn.execute(text("""
            CREATE TABLE IF NOT EXISTS exception_rules (
                id SERIAL PRIMARY KEY,

                -- ========== Identity ==========
                exception_id VARCHAR(200) NOT NULL UNIQUE,
                target_rule_id INTEGER NOT NULL REFERENCES rules(id) ON DELETE CASCADE,

                -- ========== Exception Pattern ==========
                pattern VARCHAR(50) NOT NULL,  -- ExceptionPattern enum: unless, only_if, except, etc.
                effect VARCHAR(50) NOT NULL,   -- ExceptionEffect enum: negate, relax, restrict, etc.
                scope VARCHAR(50) NOT NULL,    -- ExceptionScope enum: field, extension, certificate_type, etc.

                -- ========== Exception Conditions (JSON) ==========
                condition_set TEXT,  -- JSON: ConditionSet structure with conditions list and logic

                -- ========== Source Provenance ==========
                document_id VARCHAR(100) NOT NULL,
                section_id VARCHAR(100),
                source_span TEXT,  -- JSON: SourceSpan structure (start_char, end_char, matched_text, context)

                -- ========== Semantic Information ==========
                justification TEXT,  -- Human-readable explanation of the exception

                -- ========== Metadata ==========
                auto_detected BOOLEAN DEFAULT TRUE,  -- Auto-detected (vs manually added)
                confidence FLOAT DEFAULT 1.0,        -- Detection confidence (0-1)
                needs_review BOOLEAN DEFAULT FALSE,  -- Whether manual review is needed
                metadata_json TEXT,                  -- Additional metadata (JSON)

                created_at TIMESTAMP DEFAULT NOW(),
                updated_at TIMESTAMP DEFAULT NOW()
            )
        """))

        # 2. Create indexes for exception_rules
        print("Creating indexes for exception_rules...")

        # Index on exception_id (unique, for fast lookup)
        conn.execute(text("""
            CREATE UNIQUE INDEX IF NOT EXISTS idx_exception_id
            ON exception_rules(exception_id)
        """))

        # Index on target_rule_id (for finding exceptions of a rule)
        conn.execute(text("""
            CREATE INDEX IF NOT EXISTS idx_exception_target_rule
            ON exception_rules(target_rule_id)
        """))

        # Index on pattern (for querying by exception type)
        conn.execute(text("""
            CREATE INDEX IF NOT EXISTS idx_exception_pattern
            ON exception_rules(pattern)
        """))

        # Composite index on auto_detected and needs_review (for filtering)
        conn.execute(text("""
            CREATE INDEX IF NOT EXISTS idx_exception_auto_detected
            ON exception_rules(auto_detected, needs_review)
        """))

        # Composite index on document_id and section_id (for document-level queries)
        conn.execute(text("""
            CREATE INDEX IF NOT EXISTS idx_exception_document_section
            ON exception_rules(document_id, section_id)
        """))

        conn.commit()
        print("[OK] Successfully created exception_rules table and indexes")

        # 3. Verify the table was created
        result = conn.execute(text("""
            SELECT COUNT(*) as count FROM information_schema.tables
            WHERE table_name = 'exception_rules'
        """))
        count = result.fetchone()[0]
        if count == 1:
            print("[OK] Verification: exception_rules table exists")
        else:
            print("[WARNING] exception_rules table not found after creation")


def rollback():
    """Rollback: Drop exception_rules table"""

    with engine.connect() as conn:
        print("Dropping exception_rules table...")
        conn.execute(text("DROP TABLE IF EXISTS exception_rules CASCADE"))

        conn.commit()
        print("[OK] Successfully dropped exception_rules table")


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Migration for exception rules")
    parser.add_argument("--rollback", action="store_true", help="Rollback the migration")
    args = parser.parse_args()

    if args.rollback:
        rollback()
    else:
        migrate()
