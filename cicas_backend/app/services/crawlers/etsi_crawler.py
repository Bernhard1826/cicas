"""
ETSI (European Telecommunications Standards Institute) document crawler
Crawls ETSI standards related to PKI, eIDAS, and trust services
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
from app.services.crawlers.etsi_pdf_finder import ETSIPDFFinder


class ETSICrawler(BaseCrawler):
    """Crawler for ETSI standards documents"""

    # Key PKI and trust services-related ETSI standards
    DEFAULT_ETSI_STANDARDS = [
        # eIDAS related standards
        "TS_119_612",  # Electronic Signatures and Infrastructures (ESI); Trusted Lists
        "EN_319_401",  # General Policy Requirements for Trust Service Providers
        "EN_319_411-1",  # Policy and security requirements for Trust Service Providers - Part 1: General requirements
        "EN_319_411-2",  # Policy and security requirements for Trust Service Providers - Part 2: Requirements for trust service providers issuing EU qualified certificates
        "EN_319_412-1",  # Certificate Profiles - Part 1: Overview and common data structures
        "EN_319_412-2",  # Certificate Profiles - Part 2: Certificate profile for certificates issued to natural persons
        "EN_319_412-3",  # Certificate Profiles - Part 3: Certificate profile for certificates issued to legal persons
        "EN_319_412-4",  # Certificate Profiles - Part 4: Certificate profile for web site certificates
        "EN_319_412-5",  # Certificate Profiles - Part 5: QCStatements

        # Certificate validation and trust services
        "TS_119_615",  # ESI; Trusted Lists
        "EN_319_102-1",  # Procedures for Creation and Validation of AdES Digital Signatures
        "TS_102_042",  # Policy requirements for certification authorities issuing public key certificates

        # Time-stamping protocols
        "EN_319_421",  # Policy and Security Requirements for Trust Service Providers issuing Time-Stamps
        "EN_319_422",  # Time-stamping protocol and time-stamp token profiles
    ]

    def __init__(self):
        super().__init__()
        self.base_url = settings.etsi_base_url
        self.search_url = settings.etsi_en_base_url
        self.ts_search_url = settings.etsi_ts_base_url
        self.pdf_parser = PDFParser()
        self.pdf_finder = ETSIPDFFinder()

    async def crawl_etsi_standard(self, standard_id: str) -> Optional[List[Dict[str, Any]]]:
        """
        Crawl a specific ETSI standard document (latest version only)

        Args:
            standard_id: ETSI standard identifier (e.g., "EN_319_412-2", "TS_119_612")

        Returns:
            List with single dictionary containing latest standard metadata and content, or None if failed
        """
        try:
            app_logger.info(f"Crawling ETSI standard {standard_id} (latest version only)", extra={"module": "crawler"})

            # Use PDF finder to get all PDF URLs
            pdf_info_list = await self.pdf_finder.find_pdf_url(standard_id, self.session)

            if not pdf_info_list:
                app_logger.error(f"Failed to find PDF URLs for ETSI {standard_id}")
                return None

            app_logger.info(f"Found {len(pdf_info_list)} version(s) for {standard_id}")

            # Find the latest version (should be marked by pdf_finder)
            latest_pdf = None
            for pdf_info in pdf_info_list:
                if pdf_info.get('is_latest', False):
                    latest_pdf = pdf_info
                    break

            # If no version marked as latest, use the first one (pdf_finder sorts by version)
            if not latest_pdf and pdf_info_list:
                latest_pdf = pdf_info_list[0]
                latest_pdf['is_latest'] = True

            if not latest_pdf:
                app_logger.error(f"Could not determine latest version for ETSI {standard_id}")
                return None

            app_logger.info(f"Crawling latest version only for {standard_id}: v{latest_pdf.get('version', 'Unknown')}")

            # Process only the latest version
            result = await self._download_and_process_pdf(standard_id, latest_pdf)

            if result:
                app_logger.info(
                    f"Successfully crawled latest version for ETSI {standard_id}: v{result.get('version')}",
                    extra={"module": "crawler"}
                )
                return [result]  # Return list with single item for consistency
            else:
                return None

        except Exception as e:
            app_logger.error(f"Error crawling ETSI {standard_id}: {e}", extra={"module": "crawler"})
            import traceback
            traceback.print_exc()
            return None

    async def _download_and_process_pdf(self, standard_id: str, pdf_info: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """
        Download and process a single ETSI PDF

        Args:
            standard_id: Standard identifier
            pdf_info: PDF information dict with url, version, title

        Returns:
            Dictionary with standard metadata and content, or None if failed
        """
        try:
            pdf_url = pdf_info['url']
            version = pdf_info.get('version')
            is_latest = pdf_info.get('is_latest', False)

            app_logger.info(f"Downloading ETSI {standard_id} version {version} from {pdf_url}")

            # Download PDF
            # Include version in filename
            filename = f"{standard_id}_v{version.replace('.', '_')}.pdf" if version else f"{standard_id}.pdf"
            pdf_path = self.get_save_path("etsi", filename)
            success = await self.download_file(pdf_url, pdf_path)

            if not success:
                app_logger.error(f"Failed to download ETSI {standard_id} v{version} from {pdf_url}")
                return None

            # Calculate file hash
            file_hash = self.calculate_file_hash(pdf_path)

            # Extract metadata from PDF file
            pdf_metadata = self.pdf_parser.extract_metadata(pdf_path)
            app_logger.info(f"Extracted PDF metadata: {pdf_metadata}")

            # Parse standard ID
            standard_type, standard_number = self._parse_standard_id(standard_id)

            # Use effective_date if available, otherwise fall back to publish_date
            effective_date = pdf_metadata.get('effective_date')
            publish_date = pdf_metadata.get('publish_date')
            pdf_version = pdf_metadata.get('version') or version

            result = {
                "source": "ETSI",
                "standard_id": standard_id,
                "standard_type": standard_type,
                "standard_number": standard_number,
                "title": pdf_metadata.get("title") or pdf_info.get("title") or f"ETSI {standard_id}",
                "url": pdf_url,  # 使用实际的 PDF URL 而不是标准页面
                "pdf_url": pdf_url,
                "file_path": str(pdf_path),
                "file_hash": file_hash,
                "effective_date": effective_date,  # 生效日期
                "publish_date": publish_date,
                "document_last_updated": effective_date or publish_date,
                "version": pdf_version,
                "status": "Published",
                "is_latest": is_latest,  # Mark if this is the latest version
                "abstract": pdf_metadata.get("abstract", ""),
                "keywords": pdf_metadata.get("keywords", []),
                "metadata": {
                    **pdf_metadata,
                    "standards_page_url": f"https://www.etsi.org/standards/{standard_id}"  # 标准页面 URL 保存在 metadata 中
                }
            }

            app_logger.info(
                f"Successfully processed ETSI {standard_id} v{pdf_version} (is_latest={is_latest})",
                extra={"module": "crawler"}
            )

            return result

        except Exception as e:
            app_logger.error(f"Error processing ETSI PDF {standard_id}: {e}", extra={"module": "crawler"})
            import traceback
            traceback.print_exc()
            return None

    def _parse_standard_id(self, standard_id: str) -> tuple:
        """
        Parse ETSI standard ID into type and number

        Args:
            standard_id: e.g., "EN_319_412-2", "TS_119_612"

        Returns:
            Tuple of (standard_type, standard_number)
        """
        # Pattern: TYPE_NUMBER-PART or TYPE_NUMBER
        match = re.match(r'(EN|TS|TR|ES|EG|SR)_(\d{3}_\d{3}(?:-\d+)?)', standard_id)
        if match:
            return match.group(1), match.group(2)
        return None, None

    def _construct_pdf_url(self, standard_type: str, standard_number: str, standard_id: str) -> str:
        """
        Construct PDF download URL for ETSI standard

        ETSI URL structure varies, this attempts the most common patterns
        """
        # Convert underscores to proper format
        # EN_319_412-2 -> 319412/v02.04.01 (example version)
        number_parts = standard_number.split('_')
        if len(number_parts) >= 2:
            series = number_parts[0]  # e.g., "319"
            base_num = number_parts[1].split('-')[0]  # e.g., "412"
            part = ""
            if '-' in standard_number:
                part = f"0{standard_number.split('-')[1]}"  # e.g., "02"

            # Common ETSI URL pattern (may need adjustment for specific standards)
            # Example: https://www.etsi.org/deliver/etsi_en/319400_319499/31941202/02.04.01_60/en_31941202v020401p.pdf
            range_start = (int(base_num) // 100) * 100
            range_end = range_start + 99

            if standard_type == "EN":
                return f"{self.base_url}/deliver/etsi_en/{series}{range_start}_{series}{range_end}/{series}{base_num}{part}/latest/en_{series}{base_num}{part}v_latest.pdf"
            elif standard_type == "TS":
                return f"{self.base_url}/deliver/etsi_ts/{series}{range_start}_{series}{range_end}/{series}{base_num}{part}/latest/ts_{series}{base_num}{part}v_latest.pdf"

        # Fallback generic URL
        return f"{self.base_url}/deliver/etsi_{standard_type.lower()}/{standard_id.replace('_', '')}.pdf"

    def _construct_alternative_pdf_url(self, standard_type: str, standard_number: str, standard_id: str) -> str:
        """
        Construct alternative PDF URL pattern
        """
        # Try a simpler pattern
        clean_id = standard_id.replace('_', '').replace('-', '')
        return f"{self.base_url}/standards-search/downloadable/{clean_id}.pdf"

    def _construct_metadata_url(self, standard_type: str, standard_number: str, standard_id: str) -> str:
        """
        Construct URL for standard metadata page
        """
        return f"{self.base_url}/standards/{standard_id}"

    async def _fetch_metadata(self, metadata_url: str, standard_id: str) -> Dict[str, Any]:
        """
        Fetch and parse metadata for ETSI standard

        Args:
            metadata_url: URL to metadata page
            standard_id: Standard identifier

        Returns:
            Dictionary with metadata
        """
        try:
            html_content = await self.fetch_url(metadata_url)
            if not html_content:
                app_logger.warning(f"Could not fetch metadata for {standard_id}")
                return {}

            soup = BeautifulSoup(html_content, 'html.parser')
            metadata = {}

            # Try to extract title
            title_elem = soup.find('h1')
            if title_elem:
                metadata["title"] = title_elem.get_text(strip=True)

            # Try to extract publication date
            date_elem = soup.find('meta', {'name': 'DC.date'})
            if date_elem and date_elem.get('content'):
                try:
                    date_str = date_elem.get('content')
                    metadata["publish_date"] = datetime.fromisoformat(date_str.split('T')[0])
                except:
                    pass

            # Try to extract version
            version_elem = soup.find('span', class_='version')
            if version_elem:
                metadata["version"] = version_elem.get_text(strip=True)

            # Try to extract abstract
            abstract_elem = soup.find('div', class_='abstract')
            if abstract_elem:
                metadata["abstract"] = abstract_elem.get_text(strip=True)

            # Try to extract keywords
            keywords_elem = soup.find('meta', {'name': 'keywords'})
            if keywords_elem and keywords_elem.get('content'):
                metadata["keywords"] = [k.strip() for k in keywords_elem.get('content').split(',')]

            return metadata

        except Exception as e:
            app_logger.warning(f"Error fetching ETSI metadata: {e}")
            return {}

    async def crawl_all_default_standards(self) -> List[Dict[str, Any]]:
        """
        Crawl all default ETSI PKI-related standards (all versions)

        Returns:
            List of ETSI standard data dictionaries
        """
        results = []

        app_logger.info(
            f"Starting crawl of {len(self.DEFAULT_ETSI_STANDARDS)} default ETSI standards (all versions)",
            extra={"module": "crawler"}
        )

        for standard_id in self.DEFAULT_ETSI_STANDARDS:
            result_list = await self.crawl_etsi_standard(standard_id)
            if result_list:
                results.extend(result_list)

        app_logger.info(
            f"Completed crawling {len(results)} ETSI standard versions across {len(self.DEFAULT_ETSI_STANDARDS)} standards",
            extra={"module": "crawler"}
        )

        return results

    async def search_etsi_by_keyword(self, keyword: str) -> List[str]:
        """
        Search for ETSI standards by keyword

        Args:
            keyword: Search keyword

        Returns:
            List of standard IDs
        """
        try:
            search_url = f"{self.base_url}/standards-search?search={keyword}&page=1"

            app_logger.info(f"Searching ETSI for keyword: {keyword}")

            html_content = await self.fetch_url(search_url)
            if not html_content:
                return []

            soup = BeautifulSoup(html_content, 'html.parser')

            # Parse search results
            standard_ids = []
            results = soup.find_all('div', class_='search-result')

            for result in results:
                # Try to extract standard ID from result
                title_elem = result.find('a', class_='title')
                if title_elem:
                    title = title_elem.get_text(strip=True)
                    # Extract standard ID from title (e.g., "ETSI EN 319 412-2")
                    match = re.search(r'(EN|TS|TR|ES)\s*(\d{3})\s*(\d{3})(?:-(\d+))?', title)
                    if match:
                        std_type = match.group(1)
                        series = match.group(2)
                        number = match.group(3)
                        part = match.group(4) if match.group(4) else ""

                        std_id = f"{std_type}_{series}_{number}"
                        if part:
                            std_id += f"-{part}"

                        standard_ids.append(std_id)

            app_logger.info(f"Found {len(standard_ids)} ETSI standards for keyword '{keyword}'")
            return standard_ids

        except Exception as e:
            app_logger.error(f"Error searching ETSI: {e}")
            return []
