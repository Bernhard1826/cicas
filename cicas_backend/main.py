"""
Main entry point script
Initializes database and starts the application
"""
import asyncio
import sys
from pathlib import Path

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from app.core.init_db import initialize_database
from app.core.logging_config import app_logger
from app.core.config import settings


async def main():
    """Main entry point"""
    app_logger.info("=" * 60)
    app_logger.info("PKI Standards Management System")
    app_logger.info("=" * 60)

    # Step 1: Initialize database
    app_logger.info("Step 1: Initializing database...")
    if not initialize_database():
        app_logger.error("Database initialization failed!")
        return 1

    # Step 2: Copy .env.example to .env if it doesn't exist
    env_file = Path(__file__).parent.parent / ".env"
    env_example = Path(__file__).parent.parent / ".env.example"

    if not env_file.exists() and env_example.exists():
        app_logger.info("Step 2: Creating .env file from .env.example...")
        import shutil
        shutil.copy(env_example, env_file)
        app_logger.warning(
            "Please configure your .env file with proper API keys and settings!"
        )
    else:
        app_logger.info("Step 2: .env file already exists")

    # Step 3: Show next steps
    app_logger.info("")
    app_logger.info("Initialization complete!")
    app_logger.info("")
    app_logger.info("Next steps:")
    app_logger.info("1. Configure your .env file with API keys")
    app_logger.info("2. Run: python -m app.main  (to start the API server)")
    app_logger.info("3. Or run: python scripts/test_crawl.py  (to test crawling)")
    app_logger.info("")
    app_logger.info(f"API will be available at: http://{settings.api_host}:{settings.api_port}")
    app_logger.info(f"API docs will be at: http://{settings.api_host}:{settings.api_port}/docs")
    app_logger.info("")

    return 0


if __name__ == "__main__":
    exit_code = asyncio.run(main())
    sys.exit(exit_code)
