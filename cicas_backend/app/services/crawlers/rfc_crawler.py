"""
RFC document crawler
Crawls RFC documents from IETF datatracker
"""
import re
from pathlib import Path
from typing import Optional, Dict, Any, List
from datetime import datetime
from bs4 import BeautifulSoup
from app.services.crawlers.base_crawler import BaseCrawler
from app.core.config import settings
from app.core.logging_config import app_logger


class RFCCrawler(BaseCrawler):
    """Crawler for RFC documents"""

    # RFC 5280 reference chain (depth=1): systematic selection methodology
    # Root: RFC 5280 (Internet X.509 PKI Certificate and CRL Profile)
    # All RFCs referenced in §11.1 (Normative) and §11.2 (Informative) of RFC 5280
    DEFAULT_RFC_LIST = [
        # Root
        5280,  # Internet X.509 PKI Certificate and CRL Profile

        # §11.1 Normative References (18)
        791,   # Internet Protocol
        1034,  # Domain Names - Concepts and Facilities
        1123,  # Requirements for Internet Hosts
        2119,  # Key words for use in RFCs (BCP 14)
        2460,  # Internet Protocol, Version 6 (IPv6)
        2585,  # Internet X.509 PKI Operational Protocols: FTP and HTTP
        2616,  # Hypertext Transfer Protocol -- HTTP/1.1
        2797,  # Certificate Management Messages over CMS
        2821,  # Simple Mail Transfer Protocol
        3454,  # Preparation of Internationalized Strings (stringprep)
        3490,  # Internationalizing Domain Names in Applications (IDNA)
        3629,  # UTF-8, a transformation format of ISO 10646
        3986,  # Uniform Resource Identifier (URI): Generic Syntax
        3987,  # Internationalized Resource Identifiers (IRIs)
        4516,  # LDAP Uniform Resource Locator
        4518,  # LDAP Internationalized String Preparation
        4523,  # LDAP Schema Definitions for X.509 Certificates
        4632,  # Classless Inter-domain Routing (CIDR)

        # §11.2 Informative References (18)
        1422,  # Privacy Enhancement for Internet Electronic Mail (PEM)
        2277,  # IETF Policy on Character Sets and Languages
        2459,  # Internet X.509 PKI Certificate and CRL Profile (predecessor)
        2560,  # X.509 Internet PKI Online Certificate Status Protocol - OCSP
        2985,  # PKCS #9: Selected Object Classes and Attribute Types
        3161,  # Internet X.509 PKI Time-Stamp Protocol (TSP)
        3279,  # Algorithms and Identifiers for PKI
        3280,  # Internet X.509 PKI Certificate and CRL Profile (predecessor)
        4055,  # Additional Algorithms for RSA Cryptography in PKIX
        4120,  # The Kerberos Network Authentication Service (V5)
        4210,  # Internet X.509 PKI Certificate Management Protocol (CMP)
        4325,  # Internet X.509 PKI Authority Information Access CRL Extension
        4491,  # Using the GOST Algorithms with X.509
        4510,  # LDAP Technical Specification Road Map
        4512,  # LDAP Directory Information Models
        4514,  # LDAP String Representation of Distinguished Names
        4519,  # LDAP Schema for User Applications
        4630,  # Update to DirectoryString Processing in RFC 2849
    ]

    def __init__(self):
        super().__init__()
        self.base_url = settings.rfc_base_url
        self.text_base_url = settings.rfc_text_base_url

    async def crawl_rfc(self, rfc_number: int) -> Optional[Dict[str, Any]]:
        """
        Crawl a specific RFC document

        Args:
            rfc_number: RFC number to crawl

        Returns:
            Dictionary with RFC metadata and content, or None if failed
        """
        try:
            # Construct URLs from configuration
            html_url = f"{self.base_url}/rfc{rfc_number}"
            txt_url = f"{self.text_base_url}/rfc{rfc_number}.txt"

            app_logger.info(f"Crawling RFC {rfc_number}", extra={"module": "crawler"})

            # Fetch HTML page to get metadata
            html_content = await self.fetch_url(html_url)
            if not html_content:
                app_logger.error(f"Failed to fetch RFC {rfc_number} HTML")
                return None

            # Parse metadata from HTML
            metadata = self._parse_rfc_metadata(html_content, rfc_number)

            # Download text version
            txt_path = self.get_save_path("rfc", f"rfc{rfc_number}.txt")
            success = await self.download_file(txt_url, txt_path)

            if not success:
                app_logger.error(f"Failed to download RFC {rfc_number} text")
                return None

            # Calculate file hash
            file_hash = self.calculate_file_hash(txt_path)

            # Read text content and extract metadata from it
            with open(txt_path, 'r', encoding='utf-8', errors='ignore') as f:
                text_content = f.read()

            # Extract metadata from text file header (more reliable than HTML)
            text_metadata = self._parse_text_metadata(text_content, rfc_number)

            # Merge text metadata with HTML metadata (text takes priority)
            metadata.update(text_metadata)

            result = {
                "source": "RFC",
                "rfc_number": rfc_number,
                "title": metadata.get("title", f"RFC {rfc_number}"),
                "url": html_url,
                "txt_url": txt_url,
                "file_path": self.get_relative_path("rfc", f"rfc{rfc_number}.txt"),
                "file_hash": file_hash,
                "publish_date": metadata.get("publish_date"),
                "document_last_updated": metadata.get("publish_date"),  # For RFCs, last_updated is same as publish_date since RFCs don't update
                "authors": metadata.get("authors", []),
                "abstract": metadata.get("abstract", ""),
                "text_content": text_content,
                "metadata": metadata
            }

            app_logger.info(
                f"Successfully crawled RFC {rfc_number}: {result['title']}",
                extra={"module": "crawler"}
            )

            return result

        except Exception as e:
            app_logger.error(f"Error crawling RFC {rfc_number}: {e}", extra={"module": "crawler"})
            return None

    def _parse_rfc_metadata(self, html_content: str, rfc_number: int) -> Dict[str, Any]:
        """
        Parse metadata from RFC HTML page

        Args:
            html_content: HTML content
            rfc_number: RFC number

        Returns:
            Dictionary with metadata
        """
        try:
            soup = BeautifulSoup(html_content, 'html.parser')

            metadata = {
                "rfc_number": rfc_number
            }

            # Try to extract title
            # First try to find h1 with id="title"
            title_elem = soup.find('h1', {'id': 'title'})
            if not title_elem:
                # Fallback: find first h1 that doesn't contain only "RFC XXXX"
                for h1 in soup.find_all('h1'):
                    h1_text = h1.get_text(strip=True)
                    # Skip h1 tags that only contain "RFC XXXX"
                    if not re.match(r'^RFC\s*\d+$', h1_text, re.IGNORECASE):
                        title_elem = h1
                        break

            if title_elem:
                title_text = title_elem.get_text(strip=True)
                # Remove RFC number prefix if present
                title_match = re.search(r'RFC\s*\d+\s*[:-]\s*(.+)', title_text, re.IGNORECASE)
                if title_match:
                    metadata["title"] = title_match.group(1).strip()
                else:
                    metadata["title"] = title_text

            # Try to extract publication date
            # Look for date patterns
            date_patterns = [
                r'(\w+\s+\d{4})',  # "January 2024"
                r'(\d{1,2}\s+\w+\s+\d{4})',  # "15 January 2024"
            ]

            for pattern in date_patterns:
                date_match = re.search(pattern, html_content)
                if date_match:
                    try:
                        date_str = date_match.group(1)
                        # Try to parse the date
                        metadata["publish_date"] = self._parse_date(date_str)
                        break
                    except:
                        pass

            # Try to extract authors
            authors = []
            author_section = soup.find('meta', {'name': 'author'})
            if author_section:
                authors.append(author_section.get('content', ''))
            metadata["authors"] = authors

            # Try to extract abstract
            abstract_elem = soup.find('div', {'id': 'abstract'})
            if abstract_elem:
                metadata["abstract"] = abstract_elem.get_text(strip=True)

            # Extract obsoleted_by information (失效信息)
            obsoleted_by = None

            # Look for "Obsoleted by RFC XXXX" in divs
            for div in soup.find_all('div'):
                div_text = div.get_text(strip=True)
                if 'Obsoleted by' in div_text:
                    # Extract RFC number(s)
                    obsoleted_match = re.search(r'Obsoleted by.*?RFC\s*(\d+)', div_text, re.IGNORECASE)
                    if obsoleted_match:
                        obsoleted_by = f"RFC {obsoleted_match.group(1)}"
                        app_logger.info(f"RFC {rfc_number} is obsoleted by {obsoleted_by}")
                    break

            # Also check meta description
            if not obsoleted_by:
                meta_desc = soup.find('meta', {'name': 'description'})
                if meta_desc:
                    desc_content = meta_desc.get('content', '')
                    if 'obsoleted by' in desc_content.lower():
                        obsoleted_match = re.search(r'obsoleted by RFC\s*(\d+)', desc_content, re.IGNORECASE)
                        if obsoleted_match:
                            obsoleted_by = f"RFC {obsoleted_match.group(1)}"
                            app_logger.info(f"RFC {rfc_number} is obsoleted by {obsoleted_by}")

            metadata["obsoleted_by"] = obsoleted_by

            # Extract "Obsoletes" information (此RFC废弃了哪些RFC)
            obsoletes = []
            for div in soup.find_all('div'):
                div_text = div.get_text(strip=True)
                if div_text.startswith('Obsoletes'):
                    # Extract all RFC numbers
                    obsolete_matches = re.findall(r'RFC\s*(\d+)', div_text, re.IGNORECASE)
                    obsoletes = [f"RFC {num}" for num in obsolete_matches]
                    if obsoletes:
                        app_logger.info(f"RFC {rfc_number} obsoletes: {', '.join(obsoletes)}")
                    break

            metadata["obsoletes"] = obsoletes

            return metadata

        except Exception as e:
            app_logger.warning(f"Error parsing RFC metadata: {e}")
            return {"rfc_number": rfc_number}

    def _parse_date(self, date_str: str) -> Optional[datetime]:
        """
        Parse date string to datetime

        Args:
            date_str: Date string

        Returns:
            datetime object or None
        """
        date_formats = [
            "%B %Y",  # "January 2024"
            "%d %B %Y",  # "15 January 2024"
            "%Y-%m-%d",  # "2024-01-15"
        ]

        for fmt in date_formats:
            try:
                return datetime.strptime(date_str, fmt)
            except:
                continue

        return None

    def _parse_text_metadata(self, text_content: str, rfc_number: int) -> Dict[str, Any]:
        """
        Parse metadata from RFC text file header

        Args:
            text_content: RFC text content
            rfc_number: RFC number

        Returns:
            Dictionary with metadata extracted from text
        """
        metadata = {}

        try:
            # Get first 50 lines which usually contain metadata
            lines = text_content.split('\n')[:50]
            header_text = '\n'.join(lines)

            # Extract publish date - look for month and year pattern
            # Example: "May 2008"
            date_match = re.search(r'\b(January|February|March|April|May|June|July|August|September|October|November|December)\s+(\d{4})\b', header_text)
            if date_match:
                month_year = f"{date_match.group(1)} {date_match.group(2)}"
                parsed_date = self._parse_date(month_year)
                if parsed_date:
                    metadata["publish_date"] = parsed_date
                    app_logger.info(f"RFC {rfc_number} publish date: {month_year}")

            # Extract obsoleted information from "Obsoleted by:" line
            # Example: "Obsoleted by: 5280"
            obsoleted_match = re.search(r'Obsoleted\s+by:\s*(\d+(?:\s*,\s*\d+)*)', header_text, re.IGNORECASE)
            if obsoleted_match:
                obsoleted_nums = re.findall(r'\d+', obsoleted_match.group(1))
                if obsoleted_nums:
                    metadata["obsoleted_by"] = f"RFC {obsoleted_nums[0]}"
                    # 标记此RFC已被废弃，但具体废弃日期需要从替代RFC获取
                    # 这里我们设置一个标记，表示此RFC已失效
                    metadata["is_obsoleted"] = True
                    app_logger.info(f"RFC {rfc_number} is obsoleted by: RFC {obsoleted_nums[0]}")

            # Extract "Obsoletes:" information (此RFC废弃了哪些RFC)
            # Example: "Obsoletes: 3280, 4325, 4630"
            obsoletes_match = re.search(r'Obsoletes:\s*(\d+(?:\s*,\s*\d+)*)', header_text, re.IGNORECASE)
            if obsoletes_match:
                obsolete_nums = re.findall(r'\d+', obsoletes_match.group(1))
                obsoletes_list = [f"RFC {num}" for num in obsolete_nums]
                metadata["obsoletes"] = obsoletes_list
                app_logger.info(f"RFC {rfc_number} obsoletes: {', '.join(obsoletes_list)}")

        except Exception as e:
            app_logger.warning(f"Error parsing text metadata for RFC {rfc_number}: {e}")

        return metadata

    async def crawl_all_default_rfcs(self) -> List[Dict[str, Any]]:
        """
        Crawl all default PKI-related RFCs

        Returns:
            List of RFC data dictionaries
        """
        results = []

        app_logger.info(
            f"Starting crawl of {len(self.DEFAULT_RFC_LIST)} default RFCs",
            extra={"module": "crawler"}
        )

        for rfc_number in self.DEFAULT_RFC_LIST:
            result = await self.crawl_rfc(rfc_number)
            if result:
                results.append(result)

        app_logger.info(
            f"Completed crawling {len(results)}/{len(self.DEFAULT_RFC_LIST)} RFCs",
            extra={"module": "crawler"}
        )

        return results

    async def search_rfc_by_keyword(self, keyword: str) -> List[int]:
        """
        Search for RFCs by keyword (placeholder - would need IETF API)

        Args:
            keyword: Search keyword

        Returns:
            List of RFC numbers
        """
        # This is a placeholder. In a real implementation, you would:
        # 1. Use IETF Datatracker API to search
        # 2. Parse search results
        # 3. Return RFC numbers

        app_logger.warning("RFC search not yet implemented")
        return []
