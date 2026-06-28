"""
ETSI PDF Finder - 从ETSI网站查找真实的PDF下载链接

ETSI的PDF URL模式非常复杂，需要知道确切的版本号和范围。
这个模块通过访问ETSI的deliver目录来查找可用的PDF版本。
"""

import re
import aiohttp
from bs4 import BeautifulSoup
from typing import Optional, Dict, List
from app.core.logging_config import app_logger


class ETSIPDFFinder:
    """Helper class to find ETSI PDF download links"""

    def __init__(self):
        self.base_deliver_url = "https://www.etsi.org/deliver"

    async def find_pdf_url(self, standard_id: str, session: aiohttp.ClientSession) -> Optional[List[Dict[str, str]]]:
        """
        查找ETSI标准的PDF下载链接（所有版本）

        Args:
            standard_id: 标准ID，如 "EN_319_412-2" 或 "TS_119_612"
            session: aiohttp session

        Returns:
            List of dicts with 'url', 'version', 'title' or None
        """
        # 解析标准ID
        parts = self._parse_standard_id(standard_id)
        if not parts:
            app_logger.error(f"Failed to parse standard ID: {standard_id}")
            return None

        # 查找所有版本的PDF
        pdf_info_list = await self._find_all_pdfs(parts, session)
        return pdf_info_list

    def _parse_standard_id(self, standard_id: str) -> Optional[Dict[str, str]]:
        """
        解析标准ID

        Examples:
            "EN_319_412-2" -> {"type": "EN", "series": "319", "number": "412-2", "full_number": "31941202"}
            "TS_119_612" -> {"type": "TS", "series": "119", "number": "612", "full_number": "119612"}
        """
        # Pattern: TYPE_SERIES_NUMBER
        pattern = r'([A-Z]+)_(\d{3})_(\d{3}(?:-\d+)?)'
        match = re.match(pattern, standard_id)

        if not match:
            return None

        std_type, series, number = match.groups()

        # Convert number with dash to continuous digits
        # "412-2" -> "41202" or "412-2" -> "31941202" (with series prefix)
        if '-' in number:
            parts = number.split('-')
            main = parts[0]  # "412"
            sub = parts[1].zfill(2)  # "2" -> "02"
            full_number = f"{series}{main}{sub}"  # "31941202"
        else:
            full_number = f"{series}{number}"  # "119612"

        return {
            "type": std_type,
            "series": series,
            "number": number,
            "full_number": full_number,
            "type_lower": std_type.lower()
        }

    async def _find_all_pdfs(self, parts: Dict[str, str], session: aiohttp.ClientSession) -> Optional[List[Dict[str, str]]]:
        """
        从ETSI deliver目录查找所有版本的PDF

        URL pattern: /deliver/{etsi_type}/{range}/{number}/{version}_{suffix}/{filename}.pdf
        Example: /deliver/etsi_en/319400_319499/31941202/02.04.01_60/en_31941202v020401p.pdf

        Args:
            parts: 解析后的标准ID信息
            session: aiohttp session
        """
        # 构造deliver目录URL
        std_type = parts["type_lower"]
        full_number = parts["full_number"]  # e.g., "31941202" or "119612"

        # Calculate range (e.g., 319400-319499)
        # Extract first 4 digits for range calculation
        range_prefix = full_number[:4]  # "3194" or "1196"
        range_start = f"{range_prefix}00"  # e.g., "319400"
        range_end = f"{range_prefix}99"    # e.g., "319499"
        range_str = f"{range_start}_{range_end}"

        # 构造目录URL
        dir_url = f"{self.base_deliver_url}/etsi_{std_type}/{range_str}/{full_number}/"

        app_logger.info(f"Trying to access ETSI deliver directory: {dir_url}")

        try:
            async with session.get(dir_url, allow_redirects=True) as response:
                if response.status != 200:
                    app_logger.warning(f"Failed to access {dir_url}: {response.status}")
                    return None

                html = await response.text()
                soup = BeautifulSoup(html, 'html.parser')

                # 查找版本目录链接 (e.g., "02.04.01_60/")
                version_links = []
                for link in soup.find_all('a', href=True):
                    href = link['href']
                    # Match version pattern in full path or relative path
                    # Pattern: /path/XX.XX.XX_XX/ or XX.XX.XX_XX/
                    version_match = re.search(r'(\d{2}\.\d{2}\.\d{2}_\d{2})/?$', href)
                    if version_match:
                        version_links.append(version_match.group(1))

                if not version_links:
                    app_logger.warning(f"No version directories found at {dir_url}")
                    return None

                # 排序版本列表，处理所有版本
                sorted_versions = sorted(version_links)
                versions_to_process = sorted_versions
                app_logger.info(f"Found {len(versions_to_process)} version(s) to process")

                # 处理每个版本
                results = []
                for version_str in versions_to_process:
                    # 构造PDF URL
                    # 文件名格式: en_31941202v020401p.pdf
                    version_clean = version_str.split('_')[0].replace('.', '')  # 020401
                    filename = f"{std_type}_{full_number}v{version_clean}p.pdf"
                    pdf_url = f"{dir_url}{version_str}/{filename}"

                    # 提取版本号 (e.g., "2.4.1")
                    version_match = re.match(r'(\d{2})\.(\d{2})\.(\d{2})', version_str)
                    if version_match:
                        major, minor, patch = version_match.groups()
                        version = f"{int(major)}.{int(minor)}.{int(patch)}"
                    else:
                        version = version_str

                    # 判断是否为最新版本
                    is_latest = (version_str == sorted_versions[-1])

                    results.append({
                        "url": pdf_url,
                        "version": version,
                        "title": f"{parts['type']} {parts['series']} {parts['number']}",
                        "is_latest": is_latest
                    })

                app_logger.info(f"Found {len(results)} PDF(s) for standard")
                return results

        except Exception as e:
            app_logger.error(f"Error finding ETSI PDF: {e}")
            return None
