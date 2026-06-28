"""
Database migration: Add standard_relationships table
"""
import sys
from pathlib import Path

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from sqlalchemy import create_engine, text
from app.core.config import settings
from app.core.logging_config import app_logger


def upgrade():
    """Create standard_relationships table"""
    engine = create_engine(settings.database_url)

    with engine.connect() as conn:
        # Check if table exists
        result = conn.execute(text("""
            SELECT EXISTS (
                SELECT FROM information_schema.tables
                WHERE table_schema = 'public'
                AND table_name = 'standard_relationships'
            );
        """))

        if result.fetchone()[0]:
            app_logger.info("Table 'standard_relationships' already exists")
            return

        # Create table
        conn.execute(text("""
            CREATE TABLE standard_relationships (
                id SERIAL PRIMARY KEY,
                source_standard_id INTEGER NOT NULL REFERENCES standards(id) ON DELETE CASCADE,
                target_standard_id INTEGER NOT NULL REFERENCES standards(id) ON DELETE CASCADE,
                relationship_type VARCHAR(50) NOT NULL,
                description TEXT,
                section VARCHAR(100),
                confidence FLOAT DEFAULT 1.0,
                extraction_method VARCHAR(50) DEFAULT 'manual',
                metadata_json TEXT,
                is_active BOOLEAN DEFAULT TRUE,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
        """))

        # Create indexes
        conn.execute(text("""
            CREATE INDEX idx_std_rel_source ON standard_relationships(source_standard_id);
        """))

        conn.execute(text("""
            CREATE INDEX idx_std_rel_target ON standard_relationships(target_standard_id);
        """))

        conn.execute(text("""
            CREATE INDEX idx_std_rel_type ON standard_relationships(relationship_type);
        """))

        conn.execute(text("""
            CREATE INDEX idx_std_rel_active ON standard_relationships(is_active);
        """))

        conn.commit()

        app_logger.info("Created table 'standard_relationships' with indexes")


def downgrade():
    """Drop standard_relationships table"""
    engine = create_engine(settings.database_url)

    with engine.connect() as conn:
        conn.execute(text("DROP TABLE IF EXISTS standard_relationships CASCADE;"))
        conn.commit()
        app_logger.info("Dropped table 'standard_relationships'")


if __name__ == '__main__':
    import argparse

    parser = argparse.ArgumentParser(description='Database migration for standard_relationships')
    parser.add_argument('action', choices=['upgrade', 'downgrade'],
                       help='Migration action: upgrade or downgrade')

    args = parser.parse_args()

    if args.action == 'upgrade':
        app_logger.info("Running migration: add standard_relationships table")
        upgrade()
        app_logger.info("Migration completed successfully")
    elif args.action == 'downgrade':
        app_logger.info("Running downgrade: remove standard_relationships table")
        downgrade()
        app_logger.info("Downgrade completed successfully")
