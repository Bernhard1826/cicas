"""
Migration: add zlint_lint_dsl table for DSL atoms from lint_ir_summaries.json.

Stores the DSL representation of each zlint lint alongside its metadata.
This table is the authoritative zlint-side DSL corpus.
"""
import psycopg2
import os
import sys

# Resolve path to cicas_backend for config
_backend_dir = os.path.dirname(os.path.abspath(__file__))
# parent of migrations/ -> cicas_backend/
_cicas_root = os.path.dirname(_backend_dir)
import json

# DB config
DATABASE_URL = os.getenv('DATABASE_URL',
                         'postgresql://postgres:123456@localhost:15432/cicas')

def run_migration():
    conn = psycopg2.connect(DATABASE_URL)
    cur = conn.cursor()

    try:
        print("Migrating: add zlint_lint_dsl table...")

        # Check if table exists
        cur.execute("""
            SELECT column_name FROM information_schema.columns
            WHERE table_name='zlint_lint_dsl' LIMIT 1
        """)
        if cur.fetchone():
            print("  [SKIP] zlint_lint_dsl already exists")
            return

        cur.execute("""
            CREATE TABLE zlint_lint_dsl (
                id               SERIAL PRIMARY KEY,
                lint_name        VARCHAR(256) NOT NULL,
                source           VARCHAR(64)  NOT NULL,
                section          VARCHAR(128),
                package          VARCHAR(128),
                predicate        VARCHAR(64),
                subject          VARCHAR(256),
                obligation       VARCHAR(32),
                constraint_type  VARCHAR(64),
                constraint_value TEXT,           -- JSON: full constraint object
                raw_source       VARCHAR(512),   -- original _raw_source
                dsl_atom         TEXT,           -- JSON DSL atom tree
                dsl_form         VARCHAR(32),    -- 'Form_A' | 'Form_B'
                irred_class      VARCHAR(64),     -- if Form_B: reason class
                created_at      TIMESTAMPTZ DEFAULT NOW(),
                UNIQUE(lint_name)
            )
        """)
        print("  [OK] Table created")

        # Indexes
        cur.execute("CREATE INDEX idx_zlint_dsl_source ON zlint_lint_dsl(source)")
        cur.execute("CREATE INDEX idx_zlint_dsl_form ON zlint_lint_dsl(dsl_form)")
        cur.execute("CREATE INDEX idx_zlint_dsl_predicate ON zlint_lint_dsl(predicate)")
        print("  [OK] Indexes created")

        conn.commit()
        print("Migration done.\n")

    except Exception as e:
        conn.rollback()
        print(f"Migration failed: {e}")
        raise
    finally:
        cur.close()
        conn.close()


def rollback_migration():
    conn = psycopg2.connect(DATABASE_URL)
    cur = conn.cursor()
    try:
        cur.execute("DROP TABLE IF EXISTS zlint_lint_dsl CASCADE")
        conn.commit()
        print("Rollback done.")
    except Exception as e:
        conn.rollback()
        print(f"Rollback failed: {e}")
        raise
    finally:
        cur.close()
        conn.close()


if __name__ == '__main__':
    if len(sys.argv) > 1 and sys.argv[1] == 'rollback':
        rollback_migration()
    else:
        run_migration()