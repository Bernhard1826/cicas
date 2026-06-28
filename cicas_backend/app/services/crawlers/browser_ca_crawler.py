"""
Browser CA policy crawler
Crawls CA policies from major browsers (Chrome, Mozilla, Apple, Microsoft)
"""
import re
from pathlib import Path
from typing import Optional, Dict, Any, List
from datetime import datetime
from bs4 import BeautifulSoup
from app.services.crawlers.base_crawler import BaseCrawler
from app.core.config import settings
from app.core.logging_config import app_logger


class BrowserCACrawler(BaseCrawler):
    """Crawler for browser CA policies"""

    def __init__(self):
        super().__init__()

        # Browser sources - URLs loaded from configuration
        self.BROWSER_SOURCES = {
            "mozilla": {
                "name": "Mozilla CA Certificate Policy",
                "url": settings.mozilla_ca_url,
            },
            "chrome": {
                "name": "Chrome Root Program Policy",
                "url": settings.chrome_ca_url,
            },
            "apple": {
                "name": "Apple Root Certificate Program",
                "url": settings.apple_ca_url,
            },
            "microsoft": {
                "name": "Microsoft Trusted Root Program Requirements",
                "url": settings.microsoft_ca_url,
            }
        }

    async def crawl_browser_policy(self, browser: str) -> Optional[List[Dict[str, Any]]]:
        """
        Crawl a specific browser's CA policy (all PDF versions)

        Args:
            browser: Browser name (mozilla, chrome, apple, microsoft)

        Returns:
            List of dictionaries with policy metadata and content, or None if failed
        """
        try:
            if browser not in self.BROWSER_SOURCES:
                app_logger.error(f"Unknown browser: {browser}")
                return None

            source_info = self.BROWSER_SOURCES[browser]
            app_logger.info(f"Crawling {browser} CA policy (all versions)", extra={"module": "crawler"})

            # Fetch the policy page
            html_content = await self.fetch_url(source_info["url"])
            if not html_content:
                app_logger.error(f"Failed to fetch {browser} CA policy page")
                return None

            # Save raw HTML
            html_path = self.get_save_path(f"browser_ca/{browser}", "policy.html")
            html_path.parent.mkdir(parents=True, exist_ok=True)

            with open(html_path, 'w', encoding='utf-8') as f:
                f.write(html_content)

            # Parse the HTML to extract policy content
            policy_content = self._extract_policy_content(html_content, browser)

            # Extract metadata including dates and version
            metadata = self._extract_metadata(html_content, browser)

            # Look for linked PDF documents
            pdf_links = self._extract_pdf_links(html_content, source_info["url"])

            # Download all PDFs
            pdfs_to_download = pdf_links if pdf_links else []
            app_logger.info(f"Found {len(pdfs_to_download)} PDF(s) to download for {browser}")

            # Download PDFs
            downloaded_pdfs = []
            for idx, pdf_link in enumerate(pdfs_to_download):
                pdf_filename = f"{browser}_{Path(pdf_link['url']).name}"
                pdf_path = self.get_save_path(f"browser_ca/{browser}", pdf_filename)

                if await self.download_file(pdf_link['url'], pdf_path):
                    downloaded_pdfs.append({
                        "url": pdf_link['url'],
                        "path": str(pdf_path),
                        "hash": self.calculate_file_hash(pdf_path),
                        "is_latest": (idx == 0)  # First PDF is considered latest
                    })

            # Calculate content hash
            content_hash = self.calculate_text_hash(html_content)

            # Create separate entries for each PDF version
            results = []

            if downloaded_pdfs:
                # Create separate entries for each PDF version
                for pdf_info in downloaded_pdfs:
                    result = {
                        "source": f"Browser_CA_{browser.upper()}",
                        "browser": browser,
                        "title": source_info["name"],
                        "url": pdf_info['url'],
                        "file_path": pdf_info['path'],
                        "content_hash": pdf_info['hash'],
                        "is_latest": pdf_info['is_latest'],
                        "policy_content": policy_content,
                        "crawled_at": datetime.now().isoformat(),
                        "publish_date": metadata.get("publish_date"),
                        "effective_date": metadata.get("effective_date"),
                        "document_last_updated": metadata.get("document_last_updated"),
                        "version": metadata.get("version"),
                        "metadata": {
                            "browser": browser,
                            "last_updated": metadata.get("last_updated"),
                            "effective_date_str": metadata.get("effective_date_str"),
                            "policy_page_url": source_info["url"]  # 政策页面 URL 保存在 metadata 中
                        }
                    }
                    results.append(result)
            else:
                # No PDFs found, create single HTML entry
                result = {
                    "source": f"Browser_CA_{browser.upper()}",
                    "browser": browser,
                    "title": source_info["name"],
                    "url": source_info["url"],
                    "file_path": str(html_path),
                    "content_hash": content_hash,
                    "is_latest": True,
                    "policy_content": policy_content,
                    "crawled_at": datetime.now().isoformat(),
                    "publish_date": metadata.get("publish_date"),
                    "effective_date": metadata.get("effective_date"),
                    "document_last_updated": metadata.get("document_last_updated"),
                    "version": metadata.get("version"),
                    "metadata": {
                        "browser": browser,
                        "last_updated": metadata.get("last_updated"),
                        "effective_date_str": metadata.get("effective_date_str"),
                        "policy_page_url": source_info["url"]  # 政策页面 URL 保存在 metadata 中
                    }
                }
                results.append(result)

            app_logger.info(
                f"Successfully crawled {browser} CA policy: {len(results)} result(s), {len(downloaded_pdfs)} PDF(s)",
                extra={"module": "crawler"}
            )

            return results

        except Exception as e:
            app_logger.error(f"Error crawling {browser} CA policy: {e}", extra={"module": "crawler"})
            return None

    def _extract_policy_content(self, html_content: str, browser: str) -> str:
        """
        Extract main policy content from HTML

        Args:
            html_content: HTML content
            browser: Browser name

        Returns:
            Extracted text content
        """
        try:
            soup = BeautifulSoup(html_content, 'html.parser')

            # Remove script and style elements
            for element in soup(['script', 'style', 'nav', 'footer', 'header']):
                element.decompose()

            # Get text content
            text = soup.get_text(separator='\n', strip=True)

            # Clean up extra whitespace
            lines = [line.strip() for line in text.split('\n') if line.strip()]
            return '\n'.join(lines)

        except Exception as e:
            app_logger.error(f"Error extracting policy content: {e}")
            return ""

    def _extract_pdf_links(self, html_content: str, base_url: str) -> List[Dict[str, str]]:
        """
        Extract PDF links from HTML

        Args:
            html_content: HTML content
            base_url: Base URL for resolving relative links

        Returns:
            List of PDF link dictionaries
        """
        try:
            soup = BeautifulSoup(html_content, 'html.parser')
            pdf_links = []

            for link in soup.find_all('a', href=True):
                href = link['href']

                if href.lower().endswith('.pdf'):
                    # Make absolute URL
                    if not href.startswith('http'):
                        from urllib.parse import urljoin
                        href = urljoin(base_url, href)

                    pdf_links.append({
                        "url": href,
                        "text": link.get_text(strip=True)
                    })

            return pdf_links

        except Exception as e:
            app_logger.error(f"Error extracting PDF links: {e}")
            return []

    async def crawl_all_browser_policies(self) -> List[Dict[str, Any]]:
        """
        Crawl all browser CA policies (all versions)

        Returns:
            List of policy data dictionaries
        """
        results = []

        app_logger.info(
            f"Starting crawl of {len(self.BROWSER_SOURCES)} browser CA policies (all versions)",
            extra={"module": "crawler"}
        )

        for browser in self.BROWSER_SOURCES.keys():
            result_list = await self.crawl_browser_policy(browser)
            if result_list:
                results.extend(result_list)

        app_logger.info(
            f"Completed crawling {len(results)} browser CA policy versions across {len(self.BROWSER_SOURCES)} browsers",
            extra={"module": "crawler"}
        )

        return results

    def _extract_metadata(self, html_content: str, browser: str) -> Dict[str, Any]:
        """
        Extract metadata including dates and version from browser CA policy page

        Args:
            html_content: HTML content of the policy page
            browser: Browser name

        Returns:
            Dictionary with extracted metadata
        """
        try:
            soup = BeautifulSoup(html_content, 'html.parser')
            metadata = {}

            # Get all text content for pattern matching
            page_text = soup.get_text()

            # Effective date patterns (生效时间) - highest priority
            effective_date_patterns = [
                (r'(?:comes\s+into\s+)?effect(?:ive)?(?:\s+date)?:\s*([A-Za-z]+\s+\d{1,2},?\s+\d{4})', "%B %d, %Y"),
                (r'(?:comes\s+into\s+)?effect(?:ive)?(?:\s+date)?:\s*(\d{4}-\d{2}-\d{2})', "%Y-%m-%d"),
                (r'(?:comes\s+into\s+)?effect(?:ive)?\s+([A-Za-z]+\s+\d{1,2},?\s+\d{4})', "%B %d, %Y"),
            ]

            # Try to find effective date first
            for pattern, date_format in effective_date_patterns:
                match = re.search(pattern, page_text, re.IGNORECASE)
                if match:
                    try:
                        date_str = match.group(1)
                        parsed_date = datetime.strptime(date_str, date_format)
                        metadata["effective_date"] = parsed_date
                        metadata["effective_date_str"] = date_str
                        # Also set as publish_date for backward compatibility
                        metadata["publish_date"] = parsed_date
                        break
                    except ValueError:
                        continue

            # Last updated / document update patterns (文档更新时间)
            update_date_patterns = [
                # "Last Updated: January 1, 2024" or "Updated: 2024-01-01"
                (r'(?:Last\s+)?Updated?:\s*([A-Za-z]+\s+\d{1,2},?\s+\d{4})', "%B %d, %Y"),
                (r'(?:Last\s+)?Updated?:\s*(\d{4}-\d{2}-\d{2})', "%Y-%m-%d"),
                (r'(?:Last\s+)?Updated?:\s*(\d{1,2}/\d{1,2}/\d{4})', "%m/%d/%Y"),
                # "Version X.X (January 2024)" or "v1.0 - 2024-01-01"
                (r'Version\s+[\d.]+\s*\(?([A-Za-z]+\s+\d{4})\)?', "%B %Y"),
                (r'v?[\d.]+\s*-\s*(\d{4}-\d{2}-\d{2})', "%Y-%m-%d"),
                # Mozilla specific: "This policy was last updated on ..."
                (r'last\s+updated\s+on\s+([A-Za-z]+\s+\d{1,2},?\s+\d{4})', "%B %d, %Y"),
                # Published date patterns
                (r'(?:Published|Release)\s+Date:\s*([A-Za-z]+\s+\d{1,2},?\s+\d{4})', "%B %d, %Y"),
                (r'(?:Published|Release)\s+Date:\s*(\d{4}-\d{2}-\d{2})', "%Y-%m-%d"),
            ]

            # Try to find document last updated date
            for pattern, date_format in update_date_patterns:
                match = re.search(pattern, page_text, re.IGNORECASE)
                if match:
                    try:
                        date_str = match.group(1)
                        parsed_date = datetime.strptime(date_str, date_format)
                        metadata["document_last_updated"] = parsed_date
                        metadata["last_updated"] = date_str
                        break
                    except ValueError:
                        continue

            # Version patterns
            version_patterns = [
                r'Version\s+([\d.]+)',
                r'v([\d.]+)',
                r'Revision\s+([\d.]+)',
            ]

            for pattern in version_patterns:
                match = re.search(pattern, page_text, re.IGNORECASE)
                if match:
                    metadata["version"] = match.group(1)
                    break

            # Browser-specific metadata extraction
            if browser == "mozilla":
                # Mozilla often uses specific meta tags
                meta_date = soup.find('meta', {'property': 'article:modified_time'})
                if meta_date and meta_date.get('content'):
                    try:
                        date_str = meta_date.get('content').split('T')[0]
                        parsed_date = datetime.fromisoformat(date_str)
                        metadata["document_last_updated"] = parsed_date
                        if not metadata.get("publish_date"):
                            metadata["publish_date"] = parsed_date
                    except:
                        pass

            elif browser == "apple":
                # Apple may have copyright year at the bottom
                copyright_match = re.search(r'Copyright\s+©\s+(\d{4})', page_text)
                if copyright_match and not metadata.get("publish_date"):
                    try:
                        year = int(copyright_match.group(1))
                        # Use January 1st of that year as a fallback
                        metadata["publish_date"] = datetime(year, 1, 1)
                    except:
                        pass

            return metadata

        except Exception as e:
            app_logger.warning(f"Error extracting metadata from {browser} policy: {e}")
            return {}
