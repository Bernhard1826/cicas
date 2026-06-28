#!/usr/bin/env python3
"""
Migration script to update CABF source names to be more specific
Changes CABF to CABF_SERVER, CABF_SMIME, CABF_EV, CABF_NETSEC based on file path
"""
import sys
from pathlib import Path

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from app.models.models import Standard
from app.core.config import settings
from app.core.logging_config import app_logger


def update_cabf_sources():
    """Update CABF source names based on file paths"""

    # Create database connection
    engine = create_engine(settings.database_url)
    SessionLocal = sessionmaker(bind=engine)
    db = SessionLocal()

    try:
        # Get all CABF standards
        cabf_standards = db.query(Standard).filter(
            Standard.source.like('CABF%')
        ).all()

        app_logger.info(f"Found {len(cabf_standards)} CABF standards to update")

        updated_count = 0

        for standard in cabf_standards:
            old_source = standard.source
            new_source = None

            # Determine new source based on file path
            if standard.file_path:
                file_path = standard.file_path.lower()

                if 'cabf-server' in file_path or '/br-v' in file_path or 'baseline-requirements' in file_path:
                    new_source = 'CABF_SERVER'
                elif 'cabf-smime' in file_path or 'smime-br' in file_path:
                    new_source = 'CABF_SMIME'
                elif 'cabf-ev' in file_path or '/ev-v' in file_path or 'ev-guidelines' in file_path:
                    new_source = 'CABF_EV'
                elif 'cabf-netsec' in file_path or 'netsec-v' in file_path:
                    new_source = 'CABF_NETSEC'
                elif 'cabf-codesigning' in file_path or 'cs-br' in file_path or 'code-signing' in file_path:
                    new_source = 'CABF_CODESIGNING'

            # Fallback: check title
            if not new_source and standard.title:
                title = standard.title.lower()
                if 's/mime' in title or 'smime' in title:
                    new_source = 'CABF_SMIME'
                elif 'extended validation' in title or 'ev guideline' in title:
                    new_source = 'CABF_EV'
                elif 'network' in title and 'security' in title:
                    new_source = 'CABF_NETSEC'
                elif 'code signing' in title:
                    new_source = 'CABF_CODESIGNING'
                elif 'baseline requirement' in title:
                    new_source = 'CABF_SERVER'

            # Update if we determined a new source
            if new_source and new_source != old_source:
                standard.source = new_source
                updated_count += 1
                app_logger.info(f"Updated standard {standard.id}: {old_source} -> {new_source} ({standard.title[:50]}...)")

        # Commit changes
        db.commit()
        app_logger.info(f"Successfully updated {updated_count} standards")

        # Print summary
        print(f"\n=== Migration Summary ===")
        print(f"Total CABF standards found: {len(cabf_standards)}")
        print(f"Standards updated: {updated_count}")

        # Count by new source
        source_counts = {}
        for standard in db.query(Standard).filter(Standard.source.like('CABF%')).all():
            source_counts[standard.source] = source_counts.get(standard.source, 0) + 1

        print(f"\nCurrent distribution:")
        for source, count in sorted(source_counts.items()):
            print(f"  {source}: {count}")

        return updated_count

    except Exception as e:
        db.rollback()
        app_logger.error(f"Error updating CABF sources: {e}")
        raise
    finally:
        db.close()


if __name__ == "__main__":
    print("Starting CABF source migration...")
    updated = update_cabf_sources()
    print(f"\n[OK] Migration completed successfully! Updated {updated} standards.")
