"""
Logging configuration using loguru
"""
from loguru import logger
from pathlib import Path
import sys
from app.core.config import settings


def setup_logging():
    """Configure application logging with loguru"""

    # Remove default handler
    logger.remove()

    # Console handler with color
    logger.add(
        sys.stdout,
        format="<green>{time:YYYY-MM-DD HH:mm:ss}</green> | <level>{level: <8}</level> | <cyan>{name}</cyan>:<cyan>{function}</cyan>:<cyan>{line}</cyan> - <level>{message}</level>",
        level=settings.log_level,
        colorize=True
    )

    # File handler - all logs
    log_path = Path(settings.logs_path)
    logger.add(
        log_path / "app_{time:YYYY-MM-DD}.log",
        rotation="00:00",
        retention="30 days",
        compression="zip",
        format="{time:YYYY-MM-DD HH:mm:ss} | {level: <8} | {name}:{function}:{line} - {message}",
        level="DEBUG"
    )

    # Error log handler
    logger.add(
        log_path / "error_{time:YYYY-MM-DD}.log",
        rotation="00:00",
        retention="90 days",
        compression="zip",
        format="{time:YYYY-MM-DD HH:mm:ss} | {level: <8} | {name}:{function}:{line} - {message}",
        level="ERROR"
    )

    # Crawler specific log
    logger.add(
        log_path / "crawler_{time:YYYY-MM-DD}.log",
        rotation="00:00",
        retention="30 days",
        compression="zip",
        format="{time:YYYY-MM-DD HH:mm:ss} | {level: <8} | {message}",
        level="INFO",
        filter=lambda record: "crawler" in record["extra"].get("module", "")
    )

    return logger


# Initialize logger
app_logger = setup_logging()
