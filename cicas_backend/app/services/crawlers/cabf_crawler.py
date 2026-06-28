"""
CA/Browser Forum document crawler
Crawls CA/B Forum Baseline Requirements and other standards
"""
import re
from pathlib import Path
from typing import Optional, Dict, Any, List
from datetime import datetime
from bs4 import BeautifulSoup
from app.services.crawlers.base_crawler import BaseCrawler
from app.core.config import settings
from app.core.logging_config import app_logger
from app.services.parsers.pdf_parser import PDFParser


class CABFCrawler(BaseCrawler):
    """Crawler for CA/Browser Forum documents"""

    def __init__(self):
        super().__init__()
        self.base_url = settings.cabf_base_url
        self.pdf_parser = PDFParser()

        # Known CA/B Forum documents - URLs loaded from configuration
        # Each document type has a corresponding subdirectory for better organization
        self.CABF_DOCUMENTS = {
            "baseline_requirements": {
                "name": "Baseline Requirements for the Issuance and Management of Publicly-Trusted Certificates",
                "url": settings.cabf_br_url,
                "subdir": "cabf-server",  # Server Certificate WG
            },
            "ev_guidelines": {
                "name": "Guidelines for the Issuance and Management of Extended Validation Certificates",
                "url": settings.cabf_ev_url,
                "subdir": "cabf-ev",  # EV Guidelines
            },
            "smime": {
                "name": "S/MIME Baseline Requirements",
                "url": settings.cabf_smime_url,
                "subdir": "cabf-smime",  # S/MIME Certificate WG
            },
            "network_security": {
                "name": "Network and Certificate System Security Requirements",
                "url": settings.cabf_netsec_url,
                "subdir": "cabf-netsec",  # Network Security
            },
            "code_signing": {
                "name": "Baseline Requirements for the Issuance and Management of Publicly-Trusted Code Signing Certificates",
                "url": settings.cabf_cs_url,
                "subdir": "cabf-cs",  # Code Signing Certificate WG
            }
        }

    async def crawl_cabf_document(self, doc_type: str) -> Optional[List[Dict[str, Any]]]:
        """
        Crawl a specific CA/B Forum document (latest version only)

        Args:
            doc_type: Type of document (e.g., 'baseline_requirements')

        Returns:
            List with single dictionary containing latest document metadata and content, or None if failed
        """
        try:
            if doc_type not in self.CABF_DOCUMENTS:
                app_logger.error(f"Unknown CA/B Forum document type: {doc_type}")
                return None

            doc_info = self.CABF_DOCUMENTS[doc_type]
            app_logger.info(f"Crawling CA/B Forum document: {doc_type} (latest version only)", extra={"module": "crawler"})

            # Fetch the documents page
            html_content = await self.fetch_url(doc_info["url"])
            if not html_content:
                app_logger.error(f"Failed to fetch CA/B Forum page for {doc_type}")
                return None

            # Parse the page to find PDF links
            pdf_links = self._extract_pdf_links(html_content, doc_info["url"])

            if not pdf_links:
                app_logger.warning(f"No PDF links found for {doc_type}")
                return None

            # Only crawl the latest version
            latest_pdf = self._select_latest_pdf(pdf_links)
            if not latest_pdf:
                app_logger.warning(f"Could not determine latest version for {doc_type}")
                return None

            app_logger.info(f"Crawling latest version only for {doc_type}: v{latest_pdf.get('version', 'Unknown')}")

            # Download latest PDF only
            result = await self._download_and_process_pdf(latest_pdf, doc_type, doc_info, pdf_links)

            if result:
                app_logger.info(
                    f"Successfully crawled latest version for {doc_type}: v{result.get('version')}",
                    extra={"module": "crawler"}
                )
                return [result]  # Return list with single item for consistency
            else:
                return None

        except Exception as e:
            app_logger.error(f"Error crawling CA/B Forum document {doc_type}: {e}", extra={"module": "crawler"})
            return None

    async def _download_and_process_pdf(
        self,
        pdf_link: Dict[str, Any],
        doc_type: str,
        doc_info: Dict[str, Any],
        all_pdf_links: List[Dict[str, Any]]
    ) -> Optional[Dict[str, Any]]:
        """
        Download and process a single PDF

        Args:
            pdf_link: PDF link dictionary
            doc_type: Document type
            doc_info: Document info dictionary
            all_pdf_links: All PDF links for this document type

        Returns:
            Dictionary with document metadata and content, or None if failed
        """
        try:
            # Download the PDF
            pdf_filename = self._get_pdf_filename(pdf_link["url"], doc_type, pdf_link.get("version"))
            subdir = doc_info.get("subdir", "cabf")  # Use specific subdir for better organization
            pdf_path = self.get_save_path(subdir, pdf_filename)

            success = await self.download_file(pdf_link["url"], pdf_path)

            if not success:
                app_logger.error(f"Failed to download CA/B Forum PDF: {pdf_link['url']}")
                return None

            # Calculate file hash
            file_hash = self.calculate_file_hash(pdf_path)

            # Extract metadata from PDF file
            pdf_metadata = self.pdf_parser.extract_metadata(pdf_path)
            app_logger.info(f"Extracted PDF metadata: {pdf_metadata}")

            # Merge metadata from HTML link and PDF content
            # Prioritize PDF metadata for dates and version
            effective_date = pdf_metadata.get('effective_date') or pdf_link.get("date")
            publish_date = pdf_metadata.get('publish_date') or pdf_link.get("date")

            # Get version from PDF first, then from URL
            raw_version = pdf_metadata.get('version') or pdf_link.get("version", "Unknown")
            # Clean version string: remove trailing dots and whitespace
            version = self._clean_version_string(raw_version)

            # Log version extraction for debugging
            if raw_version != version:
                app_logger.info(f"Cleaned version string: '{raw_version}' -> '{version}'")

            # Determine if this is the latest version
            latest_pdf = self._select_latest_pdf(all_pdf_links)
            is_latest = (pdf_link == latest_pdf) if latest_pdf else False

            # Generate standardized source name
            # Format: CABF-Server, CABF-EV, CABF-S/MIME, CABF-NetSec
            source_mapping = {
                "cabf-server": "CABF-Server",
                "cabf-ev": "CABF-EV",
                "cabf-smime": "CABF-S/MIME",
                "cabf-netsec": "CABF-NetSec",
                "cabf-cs": "CABF-CS",
            }
            source = source_mapping.get(subdir, subdir.upper())

            result = {
                "source": source,
                "doc_type": doc_type,
                "title": doc_info["name"],
                "version": version,
                "url": pdf_link["url"],  # 使用实际的 PDF URL 而不是文档列表页面
                "pdf_url": pdf_link["url"],
                "file_path": str(pdf_path),
                "file_hash": file_hash,
                "effective_date": effective_date,  # 生效日期
                "publish_date": publish_date,
                "document_last_updated": effective_date or publish_date,
                "is_latest": is_latest,  # Mark if this is the latest version
                "metadata": {
                    "doc_type": doc_type,
                    "working_group": subdir,  # Store the working group/subdirectory
                    "documents_list_url": doc_info["url"],  # 文档列表页面 URL 保存在 metadata 中
                    "all_versions": all_pdf_links,
                    "pdf_metadata": pdf_metadata
                }
            }

            app_logger.info(
                f"Successfully processed CA/B Forum document: {doc_type} v{version} (is_latest={is_latest})",
                extra={"module": "crawler"}
            )

            return result

        except Exception as e:
            app_logger.error(f"Error processing CA/B Forum PDF {pdf_link.get('url', 'unknown')}: {e}", extra={"module": "crawler"})
            return None

    def _extract_pdf_links(self, html_content: str, base_url: str) -> List[Dict[str, Any]]:
        """
        Extract PDF links from CA/B Forum page (只提取正式版本)

        Args:
            html_content: HTML content
            base_url: Base URL for resolving relative links

        Returns:
            List of PDF link dictionaries (已过滤掉redlined、draft、errata、非英文版本)
        """
        try:
            soup = BeautifulSoup(html_content, 'html.parser')
            pdf_links = []
            filtered_count = 0

            # Find all links
            for link in soup.find_all('a', href=True):
                href = link['href']

                # Check if it's a PDF link
                if href.lower().endswith('.pdf'):
                    # Make absolute URL
                    if not href.startswith('http'):
                        from urllib.parse import urljoin
                        href = urljoin(base_url, href)

                    # Try to extract version from link text or URL
                    link_text = link.get_text(strip=True)

                    # ========== 过滤逻辑：只提取正式版本的英文文档 ==========
                    # 1. 过滤redlined版本（对比版本）
                    if 'redline' in href.lower() or 'redline' in link_text.lower():
                        app_logger.debug(f"Skipping redlined version: {href}")
                        filtered_count += 1
                        continue

                    # 2. 过滤draft草稿版本
                    if 'draft' in href.lower() or 'draft' in link_text.lower():
                        app_logger.debug(f"Skipping draft version: {href}")
                        filtered_count += 1
                        continue

                    # 3. 过滤errata勘误表（单独文档）
                    if 'errata' in href.lower() or 'errata' in link_text.lower():
                        app_logger.debug(f"Skipping errata document: {href}")
                        filtered_count += 1
                        continue

                    # 4. 过滤RFC比较表等辅助文档
                    if 'comparison' in href.lower() or 'comparison' in link_text.lower():
                        app_logger.debug(f"Skipping comparison table: {href}")
                        filtered_count += 1
                        continue

                    # 通过所有过滤条件，提取此PDF
                    version = self._extract_version(link_text + " " + href)
                    date = self._extract_date_from_text(link_text + " " + href)

                    pdf_links.append({
                        "url": href,
                        "text": link_text,
                        "version": version,
                        "date": date
                    })

            app_logger.info(
                f"Found {len(pdf_links)} valid PDF links (filtered {filtered_count} unwanted versions)",
                extra={"module": "crawler"}
            )
            return pdf_links

        except Exception as e:
            app_logger.error(f"Error extracting PDF links: {e}")
            return []

    def _clean_version_string(self, version: str) -> str:
        """
        Clean version string by removing trailing dots and whitespace

        Args:
            version: Raw version string

        Returns:
            Cleaned version string
        """
        if not version or version == "Unknown":
            return version

        # Remove leading and trailing whitespace, then trailing dots
        cleaned = version.strip().rstrip('.')

        # Remove leading 'v' or 'V' if present
        if cleaned.lower().startswith('v'):
            cleaned = cleaned[1:].lstrip('. ')

        return cleaned if cleaned else version

    def _extract_version(self, text: str) -> Optional[str]:
        """
        Extract version number from text

        Args:
            text: Text to search

        Returns:
            Version string or None
        """
        # Try different version patterns
        patterns = [
            r'v\.?(\d+\.\d+\.\d+)',  # v1.9.5 or v.1.9.5
            r'version\s+(\d+\.\d+\.\d+)',  # version 1.9.5
            r'(\d+\.\d+\.\d+)',  # 1.9.5
            r'v\.?(\d+\.\d+)',  # v1.9
        ]

        for pattern in patterns:
            match = re.search(pattern, text, re.IGNORECASE)
            if match:
                # Clean the extracted version
                return self._clean_version_string(match.group(1))

        return None

    def _extract_date_from_text(self, text: str) -> Optional[datetime]:
        """
        Extract date from text

        Args:
            text: Text to search

        Returns:
            datetime object or None
        """
        # Try to find date patterns
        date_patterns = [
            (r'(\d{4}-\d{2}-\d{2})', "%Y-%m-%d"),  # 2024-01-15
            (r'(\d{2}/\d{2}/\d{4})', "%m/%d/%Y"),  # 01/15/2024
            (r'(\w+ \d{1,2},? \d{4})', "%B %d, %Y"),  # January 15, 2024
        ]

        for pattern, fmt in date_patterns:
            match = re.search(pattern, text)
            if match:
                try:
                    return datetime.strptime(match.group(1), fmt)
                except:
                    continue

        return None

    def _select_latest_pdf(self, pdf_links: List[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
        """
        Select the latest PDF from a list

        Args:
            pdf_links: List of PDF link dictionaries

        Returns:
            Latest PDF dictionary or None
        """
        if not pdf_links:
            return None

        # Sort by version (if available), then by date
        def sort_key(link):
            version = link.get("version", "0.0.0")
            date = link.get("date")
            
            # Use datetime.min if date is None
            if date is None:
                date = datetime.min

            # Convert version to tuple for comparison
            try:
                version_tuple = tuple(map(int, version.split('.')))
            except:
                version_tuple = (0, 0, 0)

            return (version_tuple, date)

        sorted_links = sorted(pdf_links, key=sort_key, reverse=True)
        return sorted_links[0]

    def _get_pdf_filename(self, url: str, doc_type: str, version: Optional[str] = None) -> str:
        """
        Generate a standardized filename for PDF

        Args:
            url: PDF URL
            doc_type: Document type
            version: Version string (optional)

        Returns:
            Filename string
        """
        # Try to get filename from URL
        from urllib.parse import urlparse
        parsed = urlparse(url)
        filename = Path(parsed.path).name

        if not filename or not filename.lower().endswith('.pdf'):
            # Generate filename with version if available
            timestamp = datetime.now().strftime("%Y%m%d")
            version_suffix = f"_v{version.replace('.', '_')}" if version else ""
            filename = f"cabf_{doc_type}{version_suffix}_{timestamp}.pdf"

        return filename

    async def crawl_all_cabf_documents(self) -> List[Dict[str, Any]]:
        """
        Crawl all CA/B Forum documents (all versions)

        Returns:
            List of document data dictionaries
        """
        results = []

        app_logger.info(
            f"Starting crawl of {len(self.CABF_DOCUMENTS)} CA/B Forum documents (all versions)",
            extra={"module": "crawler"}
        )

        for doc_type in self.CABF_DOCUMENTS.keys():
            result_list = await self.crawl_cabf_document(doc_type)
            if result_list:
                results.extend(result_list)

        app_logger.info(
            f"Completed crawling {len(results)} CA/B Forum document versions across {len(self.CABF_DOCUMENTS)} document types",
            extra={"module": "crawler"}
        )

        return results
