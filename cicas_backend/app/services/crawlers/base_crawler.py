"""
Base crawler class with common functionality
"""
import aiohttp
import asyncio
import hashlib
from pathlib import Path
from typing import Optional, Dict, Any
from datetime import datetime
from tenacity import retry, stop_after_attempt, wait_exponential
from app.core.config import settings
from app.core.logging_config import app_logger


class BaseCrawler:
    """Base class for all crawlers with common functionality"""

    def __init__(self):
        self.session: Optional[aiohttp.ClientSession] = None
        self.headers = {
            "User-Agent": settings.user_agent,
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.5",
        }

    async def __aenter__(self):
        """Async context manager entry"""
        self.session = aiohttp.ClientSession(
            headers=self.headers,
            timeout=aiohttp.ClientTimeout(total=settings.request_timeout)
        )
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Async context manager exit"""
        if self.session:
            await self.session.close()

    @retry(
        stop=stop_after_attempt(3),
        wait=wait_exponential(multiplier=1, min=2, max=10)
    )
    async def fetch_url(self, url: str) -> Optional[str]:
        """
        Fetch content from URL with retry logic

        Args:
            url: URL to fetch

        Returns:
            Content as string or None if failed
        """
        try:
            app_logger.info(f"Fetching URL: {url}", extra={"module": "crawler"})

            if not self.session:
                raise RuntimeError("Session not initialized. Use async with statement.")

            async with self.session.get(url) as response:
                response.raise_for_status()
                content = await response.text()

                app_logger.info(
                    f"Successfully fetched {len(content)} bytes from {url}",
                    extra={"module": "crawler"}
                )

                # Rate limiting
                await asyncio.sleep(settings.rate_limit_delay)

                return content

        except aiohttp.ClientError as e:
            app_logger.error(f"HTTP error fetching {url}: {e}", extra={"module": "crawler"})
            raise
        except Exception as e:
            app_logger.error(f"Error fetching {url}: {e}", extra={"module": "crawler"})
            raise

    @retry(
        stop=stop_after_attempt(3),
        wait=wait_exponential(multiplier=1, min=2, max=10)
    )
    async def download_file(self, url: str, save_path: Path) -> bool:
        """
        Download file from URL and save to disk

        Args:
            url: URL to download from
            save_path: Path to save file

        Returns:
            True if successful, False otherwise
        """
        try:
            app_logger.info(f"Downloading file from {url}", extra={"module": "crawler"})

            if not self.session:
                raise RuntimeError("Session not initialized. Use async with statement.")

            # Ensure directory exists
            save_path.parent.mkdir(parents=True, exist_ok=True)

            async with self.session.get(url) as response:
                response.raise_for_status()

                # Write file in chunks
                with open(save_path, 'wb') as f:
                    async for chunk in response.content.iter_chunked(8192):
                        f.write(chunk)

                app_logger.info(
                    f"Successfully downloaded file to {save_path}",
                    extra={"module": "crawler"}
                )

                # Rate limiting
                await asyncio.sleep(settings.rate_limit_delay)

                return True

        except Exception as e:
            app_logger.error(f"Error downloading {url}: {e}", extra={"module": "crawler"})
            return False

    @staticmethod
    def calculate_file_hash(file_path: Path) -> str:
        """
        Calculate SHA-256 hash of file

        Args:
            file_path: Path to file

        Returns:
            Hex digest of file hash
        """
        sha256_hash = hashlib.sha256()
        with open(file_path, "rb") as f:
            for byte_block in iter(lambda: f.read(4096), b""):
                sha256_hash.update(byte_block)
        return sha256_hash.hexdigest()

    @staticmethod
    def calculate_text_hash(text: str) -> str:
        """
        Calculate SHA-256 hash of text

        Args:
            text: Text to hash

        Returns:
            Hex digest of text hash
        """
        return hashlib.sha256(text.encode('utf-8')).hexdigest()

    def get_save_path(self, source: str, filename: str) -> Path:
        """
        Get standardized save path for downloaded files

        Args:
            source: Source name (e.g., 'rfc', 'cabf')
            filename: Filename

        Returns:
            Path object for save location (absolute path)
        """
        base_path = Path(settings.data_raw_path)
        source_path = base_path / source
        source_path.mkdir(parents=True, exist_ok=True)
        return source_path / filename

    def get_relative_path(self, source: str, filename: str) -> str:
        """
        Get relative path for file storage in database

        This returns a path relative to the backend directory, ensuring
        cross-platform compatibility (Windows/Linux/WSL).

        Args:
            source: Source name (e.g., 'rfc', 'cabf')
            filename: Filename

        Returns:
            Relative path string (e.g., 'data/raw/rfc/rfc5280.txt')
        """
        # Always use forward slashes for cross-platform compatibility
        relative = f"{settings.data_raw_path}/{source}/{filename}"
        return relative.replace('\\', '/')

    async def check_url_modified(self, url: str, last_checked: Optional[datetime] = None) -> bool:
        """
        Check if URL has been modified since last check

        Args:
            url: URL to check
            last_checked: Last check timestamp

        Returns:
            True if modified or unable to determine, False otherwise
        """
        try:
            if not self.session:
                return True

            async with self.session.head(url, allow_redirects=True) as response:
                if last_checked and 'Last-Modified' in response.headers:
                    last_modified = datetime.strptime(
                        response.headers['Last-Modified'],
                        '%a, %d %b %Y %H:%M:%S %Z'
                    )
                    return last_modified > last_checked

                # If we can't determine, assume it's modified
                return True

        except Exception as e:
            app_logger.warning(f"Could not check modification time for {url}: {e}")
            return True
