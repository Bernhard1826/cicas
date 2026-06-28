"""
Document parser for RFC text files
Extracts structured rules and sections from RFC documents
"""
import re
from typing import List, Dict, Any, Optional
from pathlib import Path
from app.core.logging_config import app_logger
from app.services.parsers.rule_field_extractor import RuleFieldExtractor


class RFCParser:
    """Parser for RFC text documents"""

    # Default keywords indicating normative requirements
    DEFAULT_NORMATIVE_KEYWORDS = [
        "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT",
        "SHOULD", "SHOULD NOT", "RECOMMENDED", "MAY", "OPTIONAL"
    ]

    def __init__(self, use_llm_validation: bool = False, custom_keywords: Optional[List[str]] = None):
        """
        初始化RFC解析器

        Args:
            use_llm_validation: 是否使用LLM进行规则语义验证（已废弃，仅保留接口兼容）
            custom_keywords: 自定义关键词列表（会添加到默认关键词之上）
        """
        self.field_extractor = RuleFieldExtractor()
        # LLM验证已废弃，在后续Layer中进行
        self.llm_validator = None
        self.use_llm_validation = False

        # 设置规范性关键词（默认 + 自定义）
        self.normative_keywords = self.DEFAULT_NORMATIVE_KEYWORDS.copy()
        if custom_keywords:
            # 添加自定义关键词（避免重复）
            for keyword in custom_keywords:
                keyword_upper = keyword.upper()
                if keyword_upper not in self.normative_keywords:
                    self.normative_keywords.append(keyword_upper)
            app_logger.info(f"Added {len(custom_keywords)} custom keywords: {custom_keywords}")

    def parse_rfc(self, file_path) -> List[Dict[str, Any]]:
        """
        Parse RFC file and extract text chunks (sections)

        Args:
            file_path: Path to RFC text file (str or Path)

        Returns:
            List of text chunk dictionaries (not rules - rules will be extracted by LLM in Layer 2)
        """
        try:
            # Convert to Path object if string
            if isinstance(file_path, str):
                file_path = Path(file_path)

            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()

            # Extract sections (文本分块)
            sections = self._extract_sections(content)

            # ========== Layer 1 只做文本分块，不提取规则 ==========
            # 将所有文本块交给Layer 2的LLM处理，避免Regex漏掉规则
            # 每个section作为一个候选块返回
            chunks = []
            for section in sections:
                chunk = {
                    'section': section['section'],
                    'title': section['title'],
                    'text': section['content'],  # 完整内容，不做关键词过滤
                    'line_number': section.get('line_number', 0)
                }
                chunks.append(chunk)

            app_logger.info(f"Parsed RFC: {file_path.name}, extracted {len(chunks)} text chunks (no keyword filtering)")

            return chunks

        except Exception as e:
            app_logger.error(f"Error parsing RFC {file_path}: {e}")
            return []

    def _extract_sections(self, content: str) -> List[Dict[str, Any]]:
        """
        Extract sections from RFC content

        Args:
            content: RFC text content

        Returns:
            List of section dictionaries
        """
        sections = []

        # RFC section pattern: number followed by period(s) and title
        # Example: "4.2.1.  Subject Alternative Name"
        # Must have at least one period after the section number
        # IMPORTANT: Must be at line start (no leading spaces) to avoid matching:
        # - Reference numbers like "   3143 [RFC3143]."
        # - Address numbers like "   487 E. Middlefield Road"
        section_pattern = r'^(\d+(?:\.\d+)*)\.\s+(.+)$'

        lines = content.split('\n')
        current_section = None
        current_content = []

        for i, line in enumerate(lines):
            # Skip lines with leading whitespace (not section headers)
            # This filters out TOC entries, reference numbers, addresses, etc.
            if line and line[0].isspace():
                if current_section:
                    current_content.append(line)
                continue

            match = re.match(section_pattern, line.strip())

            if match:
                section_num = match.group(1)
                section_title = match.group(2).strip()

                # Skip table of contents entries (contain dots for page alignment)
                # Example: "Introduction ....................................................4"
                if '...' in section_title or section_title.count('.') > 5:
                    continue

                # Skip if title ends with a page number (likely TOC)
                # Example: "Introduction                                          4"
                if re.search(r'\s+\d+$', section_title):
                    continue

                # Skip if section number is too long (likely not a real section)
                # Real sections: "1", "7.1.2", but not "3143"
                if len(section_num.replace('.', '')) > 4:
                    continue

                # Skip if title starts with [RFC or looks like a reference
                if section_title.startswith('[RFC') or section_title.startswith('['):
                    continue

                # Save previous section
                if current_section:
                    current_section['content'] = '\n'.join(current_content)
                    sections.append(current_section)

                # Start new section
                current_section = {
                    'section': section_num,
                    'title': section_title,
                    'line_number': i
                }
                current_content = []

            elif current_section:
                current_content.append(line)

        # Add last section
        if current_section:
            current_section['content'] = '\n'.join(current_content)
            sections.append(current_section)

        return sections

    def _extract_rules_from_section(self, section: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Extract normative rules from a section

        Args:
            section: Section dictionary

        Returns:
            List of rule dictionaries with structured fields
        """
        rules = []
        content = section['content']

        # Split content into sentences
        sentences = self._split_into_sentences(content)

        for i, sentence in enumerate(sentences):
            # Skip sentences that look like HTML or other invalid content
            if self._is_invalid_rule_text(sentence):
                continue

            # Check if sentence contains normative keywords
            rule_type = self._identify_rule_type(sentence)

            if rule_type:
                # ========== LLM语义验证 (可选) ==========
                # 在关键词检测之后，使用LLM判断是否真正表达规范要求
                llm_validation_result = None
                if self.use_llm_validation:
                    llm_validation_result = self.llm_validator.is_valid_normative_rule(
                        sentence.strip(),
                        rule_type
                    )

                    # 如果LLM判断不是有效规则，跳过
                    if not llm_validation_result['is_valid']:
                        app_logger.info(
                            f"LLM filtered out invalid rule: '{sentence[:60]}...' "
                            f"Reason: {llm_validation_result['reason']}"
                        )
                        continue  # 跳过这个伪规则

                # Extract context (surrounding sentences)
                context_start = max(0, i - 1)
                context_end = min(len(sentences), i + 2)
                context = ' '.join(sentences[context_start:context_end])

                # 使用字段提取器提取结构化信息
                extracted_fields = self.field_extractor.extract_fields(sentence.strip(), context)

                # 验证提取质量
                validation = self.field_extractor.validate_extraction(extracted_fields)

                # 组合规则信息
                rule = {
                    'section': section['section'],
                    'subsection': None,
                    'title': section['title'],
                    'text': sentence.strip(),
                    'rule_type': rule_type,
                    'context': context.strip(),
                    # 结构化字段
                    'affected_field': extracted_fields['affected_field'],
                    'operation': extracted_fields['operation'],
                    'expected_value': extracted_fields['expected_value'],
                    'condition': extracted_fields['condition'],
                    # 质量信息
                    'extraction_method': extracted_fields['extraction_method'],
                    'validation_passed': validation['is_valid'],
                    'validation_issues': validation['issues'] if not validation['is_valid'] else [],
                    # LLM验证信息 (如果启用)
                    'llm_validated': llm_validation_result is not None,
                    'llm_validation_confidence': llm_validation_result['confidence'] if llm_validation_result else None,
                    'llm_validation_reason': llm_validation_result['reason'] if llm_validation_result else None
                }

                # 只保留至少提取到了字段的规则
                if extracted_fields['affected_field']:
                    rules.append(rule)
                else:
                    app_logger.debug(f"Skipped rule without affected_field: {sentence[:80]}...")

        return rules

    def _is_invalid_rule_text(self, text: str) -> bool:
        """
        Check if text contains invalid content (HTML, JavaScript, etc.)

        Args:
            text: Text to validate

        Returns:
            True if text is invalid
        """
        text_lower = text.lower()

        # Check for HTML tags
        html_indicators = [
            '<html', '<head', '<body', '<div', '<span', '<script',
            '</html', '</head', '</body', '</div', '</span', '</script',
            'href=', 'src=', 'class=', 'onclick=', '<!doctype'
        ]

        for indicator in html_indicators:
            if indicator in text_lower:
                return True

        # Check for excessive special characters (indicator of corrupted text)
        special_char_ratio = sum(1 for c in text if not c.isalnum() and not c.isspace()) / max(len(text), 1)
        if special_char_ratio > 0.4:  # More than 40% special characters
            return True

        return False

    def _split_into_sentences(self, text: str) -> List[str]:
        """
        Split text into sentences

        Args:
            text: Text to split

        Returns:
            List of sentences
        """
        # Simple sentence splitting (can be improved with nltk)
        # Split on period, exclamation, question mark followed by space
        sentences = re.split(r'(?<=[.!?])\s+', text)

        # Filter out very short sentences and clean up
        sentences = [s.strip() for s in sentences if len(s.strip()) > 20]

        return sentences

    def _identify_rule_type(self, sentence: str) -> Optional[str]:
        """
        Identify the type of normative rule in a sentence with enhanced context checking

        This method now distinguishes between:
        - Actual RFC 2119 normative keywords (uppercase in original text)
        - Past tense verbs like "required" (lowercase in original text)
        - Negated statements like "not required"
        - Conditional statements like "may be required"

        Args:
            sentence: Sentence to analyze

        Returns:
            Rule type (MUST, SHOULD, etc.) or None
        """
        sentence_upper = sentence.upper()

        # Check for each keyword in priority order
        for keyword in self.normative_keywords:
            keyword_pattern = r'\b' + keyword + r'\b'

            # First check if keyword exists at all (case-insensitive)
            if not re.search(keyword_pattern, sentence_upper):
                continue

            # ========== 检查1: 排除否定句 ==========
            # Examples: "not required", "are not required", "is not required"
            negation_patterns = [
                r'\b(?:NOT|NO)\s+' + keyword + r'\b',
                r'\b(?:ARE|IS|WAS|WERE)\s+NOT\s+' + keyword + r'\b',
                r'\b(?:DOES|DO|DID)\s+NOT\s+' + keyword + r'\b',
                r'\b(?:NEED\s+NOT(?:\s+BE)?)\s+' + keyword + r'\b',
            ]

            is_negated = False
            for neg_pattern in negation_patterns:
                if re.search(neg_pattern, sentence_upper):
                    is_negated = True
                    break

            if is_negated:
                continue  # Skip negated statements

            # ========== 检查2: 大小写区分 ==========
            # RFC 2119 keywords should appear in UPPERCASE in the original text
            # Check if keyword appears in uppercase in original sentence
            if re.search(keyword_pattern, sentence):
                # Found in original case - this is likely a true RFC 2119 keyword
                return keyword

            # ========== 检查3: 排除过去时和条件句 ==========
            # If keyword is lowercase in original, check for problematic patterns
            sentence_lower = sentence.lower()

            # Past tense patterns
            past_tense_patterns = [
                r'\bv\d+\s+' + keyword.lower() + r'\b',  # "v1 required"
                r'\b(?:have|has|had)\s+' + keyword.lower() + r'\b',  # "have required"
                r'\b' + keyword.lower() + r'\s+(?:imposition|implementation)\b',  # "required imposition"
            ]

            # Conditional patterns
            conditional_patterns = [
                r'\b(?:may|might|could)\s+be\s+' + keyword.lower() + r'\b',  # "may be required"
                r'\b(?:if|when|where)\s+(?:\w+[\w-]*\s+){0,8}' + keyword.lower() + r'\b',  # "if ... required" (allow up to 8 words)
                r'\bas\s+' + keyword.lower() + r'\b',  # "as required"
                r'\b' + keyword.lower() + r'\s+to\s+(?:operate|function|work|respond)\b',  # "required to operate"
                r'\bthe\s+' + keyword.lower() + r'\s+(?:checks?|fields?|items?|elements?)\b',  # "the required checks" (adjective usage)
            ]

            # Passive voice patterns (often not normative)
            passive_patterns = [
                r'\bis\s+' + keyword.lower() + r'\s+by\b',  # "is required by" (required by other docs)
                r'\b(?:was|were)\s+' + keyword.lower() + r'\s+by\b',  # "was required by"
            ]

            # Special handling for "MAY" keyword appearing in conditional phrases
            # E.g., "may be required" should not be treated as MAY keyword
            if keyword == "MAY":
                # Check if "may" is followed by "be" + another keyword
                if re.search(r'\bmay\s+be\s+(?:required|needed|necessary|mandatory)\b', sentence_lower):
                    continue  # Skip - this is "may be required", not the MAY keyword

            # Descriptive patterns (not normative)
            descriptive_patterns = [
                r'\b(?:three|two|several|multiple|various)\s+' + keyword.lower() + r'\s+fields?\b',  # "three required fields"
                r'\bis\s+a\s+\w+\s+of\s+(?:three|two|several)\s+' + keyword.lower() + r'\b',  # "is a SEQUENCE of three required"
            ]

            # Check all problematic patterns
            all_patterns = past_tense_patterns + conditional_patterns + descriptive_patterns + passive_patterns
            is_problematic = False
            for pattern in all_patterns:
                if re.search(pattern, sentence_lower):
                    is_problematic = True
                    break

            if is_problematic:
                continue  # Skip past tense, conditional, descriptive, or passive usage

            # ========== 检查4: 被动语态验证 ==========
            # If keyword is lowercase and passes above checks, it might be passive voice
            # Example: "Conforming CRL issuers are required to include..."
            # We allow this, but it should be validated by having an affected_field later
            # So we return the keyword, but the extraction will be flagged if no field is found

            return keyword

        return None

    def extract_metadata(self, content: str) -> Dict[str, Any]:
        """
        Extract metadata from RFC header

        Args:
            content: RFC content

        Returns:
            Dictionary with metadata
        """
        metadata = {}

        # Extract RFC number
        rfc_match = re.search(r'RFC\s+(\d+)', content, re.IGNORECASE)
        if rfc_match:
            metadata['rfc_number'] = int(rfc_match.group(1))

        # Extract title (usually after RFC number)
        title_pattern = r'RFC\s+\d+\s+(.+?)(?:\n|Category:)'
        title_match = re.search(title_pattern, content, re.IGNORECASE | re.DOTALL)
        if title_match:
            metadata['title'] = title_match.group(1).strip()

        # Extract authors
        author_pattern = r'^([A-Z][a-z]+(?:\s+[A-Z][a-z]+)+)$'
        lines = content.split('\n')[:50]  # Check first 50 lines
        authors = []
        for line in lines:
            if re.match(author_pattern, line.strip()):
                authors.append(line.strip())
        metadata['authors'] = authors

        return metadata
