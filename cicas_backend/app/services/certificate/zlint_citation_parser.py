"""
ZLint Citation Parser
解析 zlint 源码中的 Citation 和 Description 字段

用途：
1. 扫描所有 zlint .go 文件
2. 提取 LintMetadata 中的 Name, Description, Citation, Source
3. 建立 Citation 映射（BRs → CABF-BR, EVGs → CABF-EV 等）
4. 用于基于 Citation 的 zlint 覆盖检测
"""

import os
import re
from typing import List, Dict, Optional
from dataclasses import dataclass
from pathlib import Path
from app.core.logging_config import app_logger


@dataclass
class ZLintMetadata:
    """ZLint lint 元数据"""
    lint_name: str
    description: str
    citation: str
    source: str
    package: str  # cabf_br, rfc, etsi, etc.
    file_path: str

    # 解析后的 Citation 信息
    citation_entries: List[Dict[str, str]] = None  # [{"doc": "CABF-BR", "section": "7.1.2.1"}, ...]


class ZLintCitationParser:
    """ZLint Citation 解析器"""

    # 文档缩写映射（Citation中的缩写 → 系统中的标准来源）
    CITATION_TO_SOURCE_MAPPING = {
        # CABF 系列
        'BRs': 'CABF-BR',           # Baseline Requirements
        'EVGs': 'CABF-EV',          # EV Guidelines
        'CS_BRs': 'CABF-CS',        # Code Signing BRs
        'SMIMEBRs': 'CABF-SMIME',   # S/MIME BRs

        # RFC 系列（格式：RFC XXXX）
        'RFC': 'RFC',

        # ETSI 系列
        'ETSI': 'ETSI',

        # Browser Root Programs
        'Apple': 'Apple',
        'Mozilla': 'Mozilla',

        # 其他可能的缩写
        'CAB': 'CABF',
        'CABF': 'CABF',
    }

    # ZLint Source 常量映射（系统中的来源 → zlint 的 Source 常量）
    # 注意：这个映射表用于精确匹配，不常见的变体会通过 _normalize_and_map_source 方法处理
    SOURCE_TO_ZLINT_SOURCE_MAPPING = {
        # CABF 系列
        'CABF-BR': 'lint.CABFBaselineRequirements',
        'CABF-EV': 'lint.CABFEVGuidelines',
        'CABF-CS': 'lint.CABFCSBaselineRequirements',
        'CABF-SMIME': 'lint.CABFSMIMEBaselineRequirements',

        # RFC 系列
        'RFC': 'lint.RFC5280',  # 默认映射到 RFC 5280（最常用）

        # ETSI
        'ETSI': 'lint.EtsiEsi',

        # Browser Root Programs
        'Apple': 'lint.AppleRootStorePolicy',
        'Mozilla': 'lint.MozillaRootStorePolicy',

        # Community
        'Community': 'lint.Community',
    }

    def __init__(self, zlint_root: str = None):
        """
        初始化解析器

        Args:
            zlint_root: zlint 源码根目录（默认：iccas_backend/zlint/v3/lints）
        """
        if zlint_root is None:
            # 默认路径：相对于当前文件的位置
            backend_root = Path(__file__).parent.parent.parent.parent
            zlint_root = backend_root / "zlint" / "v3" / "lints"

        self.zlint_root = Path(zlint_root)

        if not self.zlint_root.exists():
            app_logger.warning(f"[ZLintCitationParser] zlint root not found: {self.zlint_root}")

        app_logger.info(f"[ZLintCitationParser] Initialized with root: {self.zlint_root}")

    def parse_all_lints(self) -> List[ZLintMetadata]:
        """
        解析所有 zlint .go 文件，提取元数据

        Returns:
            ZLintMetadata 列表
        """
        all_metadata = []

        if not self.zlint_root.exists():
            app_logger.error(f"[ZLintCitationParser] zlint root not found: {self.zlint_root}")
            return []

        # 遍历所有 package 目录
        for package_dir in self.zlint_root.iterdir():
            if not package_dir.is_dir():
                continue

            package_name = package_dir.name

            # 跳过非 lint package
            if package_name in ['template_test.go']:
                continue

            app_logger.debug(f"[ZLintCitationParser] Scanning package: {package_name}")

            # 遍历该 package 下的所有 .go 文件
            for go_file in package_dir.glob("*.go"):
                # 跳过测试文件
                if go_file.name.endswith("_test.go"):
                    continue

                try:
                    metadata = self._parse_go_file(go_file, package_name)
                    if metadata:
                        all_metadata.append(metadata)
                except Exception as e:
                    app_logger.debug(f"[ZLintCitationParser] Failed to parse {go_file}: {e}")

        app_logger.info(f"[ZLintCitationParser] Parsed {len(all_metadata)} lints from zlint source")
        return all_metadata

    def _parse_go_file(self, go_file: Path, package_name: str) -> Optional[ZLintMetadata]:
        """
        解析单个 .go 文件，提取 LintMetadata

        Args:
            go_file: .go 文件路径
            package_name: package 名称（如 cabf_br）

        Returns:
            ZLintMetadata 或 None
        """
        try:
            with open(go_file, 'r', encoding='utf-8') as f:
                content = f.read()
        except Exception as e:
            app_logger.debug(f"Failed to read {go_file}: {e}")
            return None

        # 查找 LintMetadata 结构（使用正则匹配）
        # 示例：
        # LintMetadata: lint.LintMetadata{
        #     Name:          "e_ca_is_ca",
        #     Description:   "Root and Sub CA Certificate: The CA field MUST be set to true.",
        #     Citation:      "BRs: 7.1.2.1, BRs: 7.1.2.2",
        #     Source:        lint.CABFBaselineRequirements,
        #     EffectiveDate: util.CABEffectiveDate,
        # },

        metadata_pattern = re.compile(
            r'LintMetadata:\s*lint\.LintMetadata\s*\{([^}]+)\}',
            re.DOTALL
        )

        match = metadata_pattern.search(content)
        if not match:
            # 没有找到 LintMetadata，可能不是 lint 文件
            return None

        metadata_block = match.group(1)

        # 提取各字段
        name = self._extract_field(metadata_block, 'Name')
        description = self._extract_field(metadata_block, 'Description')
        citation = self._extract_field(metadata_block, 'Citation')

        # 提取 Source（特殊处理：Source 不是字符串，而是常量，如 lint.CABFBaselineRequirements）
        source = self._extract_source_field(metadata_block)

        if not name:
            # Name 是必需的
            return None

        # 解析 Citation
        citation_entries = self._parse_citation(citation) if citation else []

        metadata = ZLintMetadata(
            lint_name=name,
            description=description or '',
            citation=citation or '',
            source=source or '',
            package=package_name,
            file_path=str(go_file),
            citation_entries=citation_entries
        )

        return metadata

    def _extract_field(self, metadata_block: str, field_name: str) -> Optional[str]:
        """
        从 metadata block 中提取字段值

        Args:
            metadata_block: LintMetadata 内容块
            field_name: 字段名（如 Name, Description, Citation）

        Returns:
            字段值或 None
        """
        # 匹配模式：FieldName: "value" 或 FieldName: `value`
        pattern = re.compile(
            rf'{field_name}:\s*["`]([^"`]+)["`]',
            re.IGNORECASE
        )

        match = pattern.search(metadata_block)
        if match:
            return match.group(1).strip()

        return None

    def _extract_source_field(self, metadata_block: str) -> Optional[str]:
        """
        从 metadata block 中提取 Source 字段（特殊处理）

        Source 不是字符串，而是 Go 常量，如：
        Source: lint.CABFBaselineRequirements

        Args:
            metadata_block: LintMetadata 内容块

        Returns:
            Source 常量字符串（如 "lint.CABFBaselineRequirements"）或 None
        """
        # 匹配模式：Source: lint.XXX
        pattern = re.compile(
            r'Source:\s*(lint\.\w+)',
            re.IGNORECASE
        )

        match = pattern.search(metadata_block)
        if match:
            return match.group(1).strip()

        return None

    def _parse_citation(self, citation: str) -> List[Dict[str, str]]:
        """
        解析 Citation 字符串为结构化数据

        支持的格式：
        - 标准格式: "BRs: 7.1.2.1", "RFC 5280: 4.2.1.3"
        - 附录引用: "RFC 5280: Appendix A", "EVGs: Appendix F"
        - §符号: "RFC5280 §5.1.2.6", "CABF BRs §7.1.2"
        - Section关键词: "RFC 4055, Section 1.2", "Mozilla Root Store Policy / Section 5.1"
        - ETSI格式: "ETSI EN 319 412 - 5 V2.2.1 (2017 - 11) / Section 4.2.1"
        - Ballot引用: "CABF Ballot 144", "BRs: Ballot 201"
        - 字母后缀: "BRs: 7.1.2.3e", "S/MIME BRs: 7.1.4.2.2a"
        - URL引用: "https://support.apple.com/..."

        Args:
            citation: Citation 字符串

        Returns:
            Citation 条目列表 [{"doc": "CABF-BR", "section": "7.1.2.1"}, ...]
        """
        if not citation:
            return []

        entries = []

        # 先尝试整体解析特殊格式，再按逗号分割
        # ETSI格式: "ETSI EN 319 412 - 5 V2.2.1 (2017 - 11) / Section 4.2.1"
        etsi_match = re.match(
            r'ETSI\s+EN\s+[\d\s\-]+.*?/\s*Section\s*([\d.]+)',
            citation, re.IGNORECASE
        )
        if etsi_match:
            entries.append({
                'doc': 'ETSI',
                'section': etsi_match.group(1).strip(),
                'original': citation
            })
            return entries

        # Mozilla格式: "Mozilla Root Store Policy / Section 5.1"
        mozilla_match = re.match(
            r'Mozilla\s+Root\s+Store\s+Policy\s*/\s*Section\s*([\d.]+)',
            citation, re.IGNORECASE
        )
        if mozilla_match:
            entries.append({
                'doc': 'Mozilla',
                'section': mozilla_match.group(1).strip(),
                'original': citation
            })
            return entries

        # URL-only citations: extract doc from URL pattern
        url_match = re.match(r'(https?://\S+)', citation)
        if url_match and not re.search(r'[A-Z]{2,}.*:\s*\d', citation):
            url = url_match.group(1)
            doc = 'URL'
            if 'apple.com' in url:
                doc = 'Apple'
            elif 'cabforum' in url:
                doc = 'CABF-BR'
            elif 'mozilla' in url:
                doc = 'Mozilla'
            entries.append({
                'doc': doc,
                'section': '',
                'original': citation
            })
            return entries

        # 按逗号分割（但不分割ETSI版本号中的逗号）
        parts = re.split(r',\s*(?=[A-Za-z]|\d+\.)', citation)
        if len(parts) == 1:
            parts = citation.split(',')

        for part in parts:
            part = part.strip()
            if not part:
                continue

            parsed = self._parse_citation_part(part)
            entries.append(parsed)

        return entries

    def _parse_citation_part(self, part: str) -> Dict[str, str]:
        """解析单个 Citation 片段"""

        # Pattern 1: 标准格式 "DocAbbrev: X.Y.Z" (with optional letter suffix)
        match = re.match(
            r'([A-Za-z_][A-Za-z0-9\s_/]*?)\s*:\s*([\d.]+[a-z]?(?:\s|$))',
            part
        )
        if match:
            return self._build_entry(match.group(1).strip(), match.group(2).strip(), part)

        # Pattern 2: §符号 "DocAbbrev §X.Y.Z"
        match = re.match(
            r'([A-Za-z_][A-Za-z0-9\s_/]*?)\s*§\s*([\d.]+[a-z]?)',
            part
        )
        if match:
            return self._build_entry(match.group(1).strip(), match.group(2).strip(), part)

        # Pattern 3: "Section X.Y.Z" with preceding doc name
        match = re.match(
            r'([A-Za-z_][A-Za-z0-9\s_/.-]*?)\s+[Ss]ection\s+([\d.]+[a-z]?)',
            part
        )
        if match:
            return self._build_entry(match.group(1).strip(), match.group(2).strip(), part)

        # Pattern 4: Appendix reference "DocAbbrev: Appendix X"
        match = re.match(
            r'([A-Za-z_][A-Za-z0-9\s_]*?)\s*:\s*Appendix\s+([A-Z](?:\.\d+)?)',
            part, re.IGNORECASE
        )
        if match:
            return self._build_entry(
                match.group(1).strip(),
                f"Appendix {match.group(2).strip()}",
                part
            )

        # Pattern 5: "DocAbbrev Appendix X" (without colon)
        match = re.match(
            r'([A-Za-z_][A-Za-z0-9\s_]*?)\s+Appendix\s+([A-Z](?:\.\d+)?)',
            part, re.IGNORECASE
        )
        if match:
            return self._build_entry(
                match.group(1).strip(),
                f"Appendix {match.group(2).strip()}",
                part
            )

        # Pattern 6: Bare "DocAbbrev X.Y.Z" (no colon, no §)
        # e.g. "BR 7.1.4.2.1", "BRs 7.1.4.2", "EVGs 9.2.8"
        match = re.match(
            r'([A-Za-z_][A-Za-z0-9\s_/]*?)\s+([\d]+\.[\d.]+[a-z]?)\b',
            part
        )
        if match:
            return self._build_entry(match.group(1).strip(), match.group(2).strip(), part)

        # Pattern 7: Ballot reference
        match = re.match(
            r'(?:CABF\s+)?Ballot\s+(\w+)',
            part, re.IGNORECASE
        )
        if match:
            return {
                'doc': 'CABF-BR',
                'section': f"Ballot {match.group(1)}",
                'original': part
            }

        # Pattern 8: URL
        url_match = re.match(r'(https?://\S+)', part)
        if url_match:
            doc = 'URL'
            url = url_match.group(1)
            if 'apple.com' in url:
                doc = 'Apple'
            elif 'cabforum' in url:
                doc = 'CABF-BR'
            return {'doc': doc, 'section': '', 'original': part}

        # Pattern 9: Bare section number (e.g. "7.1.2.3.e" in comma-separated list)
        match = re.match(r'^([\d]+\.[\d.]+[a-z]?)\s*$', part)
        if match:
            return {'doc': 'INHERIT', 'section': match.group(1).strip(), 'original': part}

        # Fallback: try to extract any section number from the text
        sec_match = re.search(r'(\d+\.\d+(?:\.\d+)*[a-z]?)', part)
        if sec_match:
            # Try to identify the document
            doc = self._guess_doc_from_text(part)
            return {'doc': doc, 'section': sec_match.group(1), 'original': part}

        # Cannot parse
        app_logger.debug(f"[ZLintCitationParser] Failed to parse citation part: {part}")
        return {'doc': 'UNKNOWN', 'section': '', 'original': part}

    def _build_entry(self, doc_abbrev: str, section: str, original: str) -> Dict[str, str]:
        """构建 Citation 条目，处理文档缩写规范化"""
        # 清理文档缩写中的尾部标点和噪声词
        doc_abbrev = re.sub(r'\s*(?:v\d+\.\d+.*|Version\s+\d+.*)$', '', doc_abbrev, flags=re.IGNORECASE)
        doc_abbrev = doc_abbrev.rstrip(' /')

        # RFC 系列规范化
        if re.match(r'RFC\s*\d+', doc_abbrev, re.IGNORECASE):
            doc_abbrev = 'RFC'
        # CABF BR 变体规范化
        elif re.match(r'(?:CABF\s+)?(?:TLS\s+)?BRs?$', doc_abbrev, re.IGNORECASE):
            doc_abbrev = 'BRs'
        elif re.match(r'(?:CABF\s+)?(?:TLS\s+)?BR\b', doc_abbrev, re.IGNORECASE):
            doc_abbrev = 'BRs'
        elif re.match(r'CA/Browser\s+Forum\s+BRs?', doc_abbrev, re.IGNORECASE):
            doc_abbrev = 'BRs'
        elif re.match(r'CABF\s+BRs?\s+section', doc_abbrev, re.IGNORECASE):
            doc_abbrev = 'BRs'
        # CABF EV 变体
        elif re.match(r'(?:CABF\s+)?EV\s+Guidelines?', doc_abbrev, re.IGNORECASE):
            doc_abbrev = 'EVGs'
        elif re.match(r'CA/Browser\s+Forum\s+EV', doc_abbrev, re.IGNORECASE):
            doc_abbrev = 'EVGs'
        # CABF CS 变体
        elif re.match(r'(?:CABF\s+)?CS\s+BRs?', doc_abbrev, re.IGNORECASE):
            doc_abbrev = 'CS_BRs'
        # S/MIME 变体
        elif re.match(r'(?:CABF\s+)?S/?MIME\s+BRs?', doc_abbrev, re.IGNORECASE):
            doc_abbrev = 'SMIMEBRs'
        # Section prefix in doc name (e.g. "BRs: Section 7.1.2")
        elif re.match(r'(BRs?|EVGs?)\s+Section', doc_abbrev, re.IGNORECASE):
            base = re.match(r'(BRs?|EVGs?)', doc_abbrev, re.IGNORECASE).group(1)
            doc_abbrev = 'BRs' if base.upper().startswith('BR') else 'EVGs'

        # 映射缩写到系统中的标准来源
        doc_source = self.CITATION_TO_SOURCE_MAPPING.get(doc_abbrev, doc_abbrev)

        return {
            'doc': doc_source,
            'section': section,
            'original': original
        }

    def _guess_doc_from_text(self, text: str) -> str:
        """根据文本内容猜测文档来源"""
        text_upper = text.upper()
        if 'RFC' in text_upper:
            return 'RFC'
        if 'ETSI' in text_upper:
            return 'ETSI'
        if 'MOZILLA' in text_upper:
            return 'Mozilla'
        if 'APPLE' in text_upper:
            return 'Apple'
        if 'EVG' in text_upper or 'EV GUIDELINE' in text_upper:
            return 'CABF-EV'
        if 'SMIME' in text_upper or 'S/MIME' in text_upper:
            return 'CABF-SMIME'
        if 'BR' in text_upper or 'CABF' in text_upper or 'BASELINE' in text_upper:
            return 'CABF-BR'
        if 'CS' in text_upper and 'CODE' in text_upper:
            return 'CABF-CS'
        return 'UNKNOWN'

    def find_lints_by_citation(
        self,
        doc_source: str,
        section: str,
        all_metadata: List[ZLintMetadata]
    ) -> List[ZLintMetadata]:
        """
        根据 Citation 查找匹配的 lints

        Args:
            doc_source: 文档来源（如 CABF-BR）
            section: 章节号（如 7.1.2.1）
            all_metadata: 所有 lint 元数据列表

        Returns:
            匹配的 ZLintMetadata 列表
        """
        matches = []

        for metadata in all_metadata:
            if not metadata.citation_entries:
                continue

            for entry in metadata.citation_entries:
                # 检查文档来源和章节号是否匹配
                if entry['doc'] == doc_source and entry['section'] == section:
                    matches.append(metadata)
                    break  # 一个 lint 只添加一次

        return matches

    def _normalize_and_map_source(self, rule_source: str) -> Optional[str]:
        """
        规范化并映射规则来源到 zlint Source 常量

        处理各种变体：
        - RFC5280, RFC 5280, RFC-5280, RFC5246 等 → lint.RFC5280
        - CABF-Server, CABF-BR → lint.CABFBaselineRequirements

        Args:
            rule_source: 规则来源（如 "RFC5280", "CABF-Server"）

        Returns:
            zlint Source 常量或 None
        """
        if not rule_source:
            return None

        # 尝试直接查找映射表
        if rule_source in self.SOURCE_TO_ZLINT_SOURCE_MAPPING:
            return self.SOURCE_TO_ZLINT_SOURCE_MAPPING[rule_source]

        # 规范化：去除空格、连字符等
        normalized = rule_source.replace(' ', '').replace('-', '').upper()

        # RFC 系列：匹配 RFC + 数字
        if normalized.startswith('RFC'):
            # 所有RFC都映射到 lint.RFC5280（zlint主要支持RFC5280）
            return self.SOURCE_TO_ZLINT_SOURCE_MAPPING.get('RFC')

        # CABF 系列：匹配各种CABF变体
        if 'CABF' in normalized or 'CAB' in normalized:
            # 根据关键词判断具体类型
            # CABF-Server（Server Certificate Baseline Requirements）→ CABF-BR
            if 'SERVER' in normalized or 'BASELINE' in normalized or normalized == 'CABFBR':
                return self.SOURCE_TO_ZLINT_SOURCE_MAPPING.get('CABF-BR')
            elif 'EV' in normalized:
                return self.SOURCE_TO_ZLINT_SOURCE_MAPPING.get('CABF-EV')
            elif 'CS' in normalized or 'CODESIGNING' in normalized:
                return self.SOURCE_TO_ZLINT_SOURCE_MAPPING.get('CABF-CS')
            elif 'SMIME' in normalized:
                return self.SOURCE_TO_ZLINT_SOURCE_MAPPING.get('CABF-SMIME')
            # 默认CABF映射到Baseline Requirements
            return self.SOURCE_TO_ZLINT_SOURCE_MAPPING.get('CABF-BR')

        # 无法识别
        app_logger.debug(f"[ZLintCitationParser] Cannot normalize source: {rule_source}")
        return None

    def find_lints_by_source_and_section(
        self,
        rule_source: str,
        rule_section: str,
        all_metadata: List[ZLintMetadata]
    ) -> List[ZLintMetadata]:
        """
        根据 Source + Section 查找匹配的 lints（三层验证的前两层）

        Args:
            rule_source: 规则来源（如 "CABF-BR", "RFC5280", "RFC"）
            rule_section: 规则章节号（如 "7.1.2.1"）
            all_metadata: 所有 lint 元数据列表

        Returns:
            匹配的 ZLintMetadata 列表
        """
        # 第1层：Source 过滤
        # 将规则来源映射到 zlint Source 常量
        expected_zlint_source = self._normalize_and_map_source(rule_source)

        if not expected_zlint_source:
            app_logger.debug(f"[ZLintCitationParser] No zlint Source mapping for: {rule_source}")
            return []

        # 过滤：只保留 Source 匹配的 lints
        source_filtered = [
            m for m in all_metadata
            if m.source == expected_zlint_source
        ]

        app_logger.debug(
            f"[ZLintCitationParser] Source filter: {rule_source} → {expected_zlint_source} → {len(source_filtered)} lints"
        )

        # 第2层：Citation 章节号匹配
        # 使用鲁棒方式：从 Citation 原始字符串中提取所有 X.Y.Z 形式的章节号
        # 也处理§符号、Section关键词、letter suffix等非标准格式
        citation_matches = []
        rule_section_base = re.sub(r'[a-z]$', '', rule_section)  # strip letter suffix

        for metadata in source_filtered:
            if not metadata.citation:
                continue

            # 从原始 Citation 中提取所有章节号模式（如 7.1.2.3, 4.2.1.9）
            sections_in_citation = re.findall(r'\d+(?:\.\d+)+', metadata.citation)
            # Also extract §-notation and Section keyword sections
            sect_sections = re.findall(r'[§]\s*(\d+(?:\.\d+)*)', metadata.citation)
            kw_sections = re.findall(r'(?:Section|Sec\.?)\s*(\d+(?:\.\d+)*)', metadata.citation, re.IGNORECASE)
            all_sections = list(set(sections_in_citation + sect_sections + kw_sections))

            # Strip letter suffixes for matching
            all_sections_base = [re.sub(r'[a-z]$', '', s) for s in all_sections]

            # Check exact match or parent/child relationship
            for s in all_sections_base:
                if (s == rule_section_base or
                    s.startswith(rule_section_base + ".") or
                    rule_section_base.startswith(s + ".")):
                    citation_matches.append(metadata)
                    break

        app_logger.debug(
            f"[ZLintCitationParser] Citation filter: section={rule_section} → {len(citation_matches)} lints"
        )

        return citation_matches

    def get_metadata_dict(self, all_metadata: List[ZLintMetadata]) -> Dict[str, ZLintMetadata]:
        """
        将元数据列表转换为字典（以 lint_name 为 key）

        Args:
            all_metadata: ZLintMetadata 列表

        Returns:
            {lint_name: ZLintMetadata} 字典
        """
        return {m.lint_name: m for m in all_metadata}


# ========== 示例用法 ==========

if __name__ == '__main__':
    """测试 Citation 解析器"""

    parser = ZLintCitationParser()
    all_lints = parser.parse_all_lints()

    print(f"\n找到 {len(all_lints)} 个 lints\n")

    # 打印前 10 个示例
    for i, lint in enumerate(all_lints[:10], 1):
        print(f"{i}. {lint.lint_name}")
        print(f"   Package: {lint.package}")
        print(f"   Description: {lint.description[:80]}...")
        print(f"   Citation: {lint.citation}")
        print(f"   Parsed Citations: {lint.citation_entries}")
        print()

    # 测试 Citation 查找
    print("\n=== 测试 Citation 查找 ===")
    matches = parser.find_lints_by_citation('CABF-BR', '7.1.2.1', all_lints)
    print(f"\n找到 {len(matches)} 个匹配 'CABF-BR: 7.1.2.1' 的 lints:")
    for lint in matches:
        print(f"  - {lint.lint_name}: {lint.description[:60]}...")
