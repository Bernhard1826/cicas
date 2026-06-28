"""
Database connection and session management
"""
from sqlalchemy import create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, Session
from contextlib import contextmanager
from typing import Generator
from app.core.config import settings
from app.core.logging_config import app_logger

# Create SQLAlchemy engine
# Optimized for Celery multi-worker architecture:
# - 12 Celery workers (16 cores - 4 reserved)
# - Each worker needs database connection
# - API server also needs connections
# - pool_size=30: Base pool (12 workers + 18 for API/other)
# - max_overflow=50: Burst capacity for peak load
# - Total max: 80 concurrent connections (within PostgreSQL default limit of 100)
engine = create_engine(
    settings.database_url,
    pool_pre_ping=True,
    pool_size=30,
    max_overflow=50,
    echo=False,
    pool_recycle=3600,  # Recycle connections after 1 hour (prevent stale connections)
    pool_timeout=30  # Wait up to 30 seconds for available connection
)

# Create SessionLocal class
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

# Create Base class for models
Base = declarative_base()


def get_db() -> Generator[Session, None, None]:
    """
    Dependency function for FastAPI to get database session

    Yields:
        Session: SQLAlchemy database session
    """
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


@contextmanager
def get_db_context():
    """
    Context manager for database session

    Usage:
        with get_db_context() as db:
            # do something with db
    """
    db = SessionLocal()
    try:
        yield db
        db.commit()
    except Exception as e:
        db.rollback()
        app_logger.error(f"Database error: {e}")
        raise
    finally:
        db.close()


def init_db():
    """Initialize database - create all tables"""
    try:
        Base.metadata.create_all(bind=engine)
        app_logger.info("Database initialized successfully")
    except Exception as e:
        app_logger.error(f"Failed to initialize database: {e}")
        raise
