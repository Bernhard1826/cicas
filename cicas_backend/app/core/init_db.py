"""
Database initialization script
Creates database and enables pgvector extension
"""
import psycopg2
from psycopg2.extensions import ISOLATION_LEVEL_AUTOCOMMIT
from app.core.config import settings
from app.core.logging_config import app_logger
from app.core.database import init_db, engine
from app.models.models import Base
import sys


def create_database():
    """Create database if it doesn't exist"""
    try:
        # Connect to default postgres database
        conn = psycopg2.connect(
            host=settings.db_host,
            port=settings.db_port,
            user=settings.db_user,
            password=settings.db_password,
            database="postgres"
        )
        conn.set_isolation_level(ISOLATION_LEVEL_AUTOCOMMIT)
        cursor = conn.cursor()

        # Check if database exists
        cursor.execute(f"SELECT 1 FROM pg_database WHERE datname = '{settings.db_name}'")
        exists = cursor.fetchone()

        if not exists:
            cursor.execute(f"CREATE DATABASE {settings.db_name}")
            app_logger.info(f"Database '{settings.db_name}' created successfully")
        else:
            app_logger.info(f"Database '{settings.db_name}' already exists")

        cursor.close()
        conn.close()

    except Exception as e:
        app_logger.error(f"Error creating database: {e}")
        raise


def enable_pgvector():
    """Enable pgvector extension"""
    try:
        conn = psycopg2.connect(
            host=settings.db_host,
            port=settings.db_port,
            user=settings.db_user,
            password=settings.db_password,
            database=settings.db_name
        )
        conn.set_isolation_level(ISOLATION_LEVEL_AUTOCOMMIT)
        cursor = conn.cursor()

        # Enable pgvector extension
        cursor.execute("CREATE EXTENSION IF NOT EXISTS vector")
        app_logger.info("pgvector extension enabled")

        cursor.close()
        conn.close()

    except Exception as e:
        app_logger.error(f"Error enabling pgvector: {e}")
        raise


def create_tables():
    """Create all tables"""
    try:
        Base.metadata.create_all(bind=engine)
        app_logger.info("All tables created successfully")
    except Exception as e:
        app_logger.error(f"Error creating tables: {e}")
        raise


def initialize_database():
    """Full database initialization"""
    try:
        app_logger.info("Starting database initialization...")

        # Step 1: Create database
        create_database()

        # Step 2: Enable pgvector
        enable_pgvector()

        # Step 3: Create tables
        create_tables()

        app_logger.info("Database initialization completed successfully!")
        return True

    except Exception as e:
        app_logger.error(f"Database initialization failed: {e}")
        return False


if __name__ == "__main__":
    success = initialize_database()
    sys.exit(0 if success else 1)
