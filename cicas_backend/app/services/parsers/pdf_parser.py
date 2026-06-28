"""
PDF document parser
Extracts structured rules and sections from PDF documents
"""
import re
from typing import List, Dict, Any, Optional, Set, Tuple
from pathlib import Path
from datetime import datetime
import fitz  # PyMuPDF
from app.core.logging_config import app_logger
from app.services.parsers.rule_field_extractor import RuleFieldExtractor


def _overlaps_any_table(block_rect, table_rects, threshold=0.5):
    """
    Check if a text block overlaps with any table region.

    Args:
        block_rect: (x0, y0, x1, y1) of the text block
        table_rects: list of (x0, y0, x1, y1) table bounding boxes
        threshold: minimum overlap ratio to consider the block as inside a table

    Returns:
        True if the block overlaps with any table region
    """
    bx0, by0, bx1, by1 = block_rect
    block_area = max((bx1 - bx0) * (by1 - by0), 1e-6)

    for tx0, ty0, tx1, ty1 in table_rects:
        # Calculate intersection
        ix0 = max(bx0, tx0)
        iy0 = max(by0, ty0)
        ix1 = min(bx1, tx1)
        iy1 = min(by1, ty1)

        if ix0 < ix1 and iy0 < iy1:
            intersection_area = (ix1 - ix0) * (iy1 - iy0)
            if intersection_area / block_area >= threshold:
                return True

    return False


class PDFParser:
    """Parser for PDF documents"""

    NORMATIVE_KEYWORDS = [
        "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT",
        "SHOULD", "SHOULD NOT", "RECOMMENDED", "MAY", "OPTIONAL",
        "REQUIRED", "PROHIBITED",
        # ETSI commonly uses lowercase modal verbs
        "must", "must not", "shall", "shall not",
        "should", "should not", "may", "required", "prohibited"
    ]

    def __init__(self):
        self.field_extractor = RuleFieldExtractor()
        self.detected_headers: Set[str] = set()
        self.detected_footers: Set[str] = set()

    def _extract_text_by_page(self, file_path: Path) -> List[str]:
        """
        Extract text from PDF page by page with table-aware extraction.

        Shared implementation used by both extract_text() and parse_pdf().

        Args:
            file_path: Path to PDF file

        Returns:
            List of per-page text strings, empty list on failure
        """
        try:
            with open(file_path, 'rb') as f:
                header = f.read(5)
                if header != b'%PDF-':
                    app_logger.error(f"File {file_path} is not a valid PDF (header: {header})")
                    f.seek(0)
                    first_line = f.read(100).decode('utf-8', errors='ignore').lower()
                    if 'html' in first_line or '<!doctype' in first_line:
                        app_logger.error(f"File {file_path} appears to be an HTML file, not a PDF.")
                    return []

            doc = fitz.open(file_path)
            pages_text = []

            for page_num in range(len(doc)):
                page = doc[page_num]
                text = self._extract_text_from_page_table_aware(page)
                pages_text.append(text)

            doc.close()
            return pages_text

        except Exception as e:
            app_logger.error(f"Error extracting text from PDF: {e}")
            return []

    def extract_text(self, file_path: Path) -> Tuple[str, int]:
        """
        Extract text content from a PDF file with table-aware extraction.

        Public entry point for external callers (e.g. FullPipelineExtractor).

        Args:
            file_path: Path to PDF file

        Returns:
            Tuple of (text_content, page_count)
        """
        pages_text = self._extract_text_by_page(file_path)
        if not pages_text:
            return "", 0

        text_content = '\n'.join(pages_text)
        page_count = len(pages_text)
        app_logger.info(f"Extracted text from PDF: {file_path} ({page_count} pages, {len(text_content)} chars)")
        return text_content, page_count

    def _extract_text_from_page_table_aware(self, page) -> str:
        """
        Extract text from a single PDF page with table-aware processing.

        Uses PyMuPDF's find_tables() to detect tables, renders them as markdown,
        and merges with non-table text blocks in reading order (by y-coordinate).

        Args:
            page: PyMuPDF page object

        Returns:
            Page text with tables rendered as markdown
        """
        # 1. Detect tables
        try:
            tabs = page.find_tables()
            tables = tabs.tables if tabs else []
        except Exception:
            return page.get_text()  # Fall back on detection failure

        if not tables:
            return page.get_text()  # No tables, use standard extraction

        # 2. Collect table bounding boxes and markdown representations
        table_rects = []
        for t in tables:
            try:
                md = t.to_markdown()
            except Exception:
                # Fallback: build markdown from extracted rows
                try:
                    rows = t.extract()
                    md = self._rows_to_markdown(rows)
                except Exception:
                    continue
            if md and md.strip():
                table_rects.append((t.bbox, md))

        if not table_rects:
            return page.get_text()  # No valid table output, fall back

        # 3. Get text blocks with positions
        blocks = page.get_text("blocks")  # (x0, y0, x1, y1, text, block_no, type)

        # 4. Filter out text blocks that overlap with table regions
        non_table_blocks = []
        table_bboxes = [r[0] for r in table_rects]
        for b in blocks:
            if b[6] != 0:
                continue  # Skip image blocks
            if not _overlaps_any_table(b[:4], table_bboxes):
                text = b[4].strip()
                if text:
                    non_table_blocks.append({'y0': b[1], 'text': text, 'type': 'text'})

        # 5. Merge text blocks and markdown tables, sort by y-coordinate
        items = non_table_blocks + [
            {'y0': bbox[1], 'text': md, 'type': 'table'}
            for bbox, md in table_rects
        ]
        items.sort(key=lambda x: x['y0'])

        # 6. Join
        return '\n'.join(item['text'] for item in items)

    def _rows_to_markdown(self, rows: List[List]) -> str:
        """
        Convert table rows (from table.extract()) to markdown format.

        Fallback when table.to_markdown() fails.

        Args:
            rows: List of rows, each row is a list of cell values

        Returns:
            Markdown table string
        """
        if not rows:
            return ""

        # Sanitize None cells to empty strings
        sanitized = []
        for row in rows:
            sanitized.append([str(cell) if cell is not None else "" for cell in row])

        lines = []
        # Header row
        lines.append("| " + " | ".join(sanitized[0]) + " |")
        # Separator
        lines.append("| " + " | ".join("---" for _ in sanitized[0]) + " |")
        # Data rows
        for row in sanitized[1:]:
            lines.append("| " + " | ".join(row) + " |")

        return '\n'.join(lines)

    def parse_pdf(self, file_path: Path) -> List[Dict[str, Any]]:
        """
        Parse PDF file and extract structured rules

        Args:
            file_path: Path to PDF file

        Returns:
            List of rule dictionaries
        """
        try:
            # Extract text page by page for header/footer detection
            pages_text = self._extract_text_by_page(file_path)

            if not pages_text:
                app_logger.error(f"No text extracted from PDF: {file_path}")
                return []

            # Detect repeating page headers and footers
            self._detect_headers_footers(pages_text)
            app_logger.info(f"Detected {len(self.detected_headers)} headers, {len(self.detected_footers)} footers")

            # Join pages and extract sections (with h/f filtering)
            text_content = '\n'.join(pages_text)
            sections = self._extract_sections(text_content)

            # Validate sections
            valid_sections = self._validate_sections(sections)

            # ========== Layer 1 只做文本分块，不提取规则 ==========
            # 将所有文本块交给Layer 2的LLM处理，避免Regex漏掉规则
            # 每个section作为一个候选块返回
            chunks = []
            for section in valid_sections:
                chunk = {
                    'section': section['section'],
                    'title': section['title'],
                    'text': section['content'],  # 完整内容，不做关键词过滤
                    'line_number': section.get('line_number', 0)
                }
                chunks.append(chunk)

            app_logger.info(f"Parsed PDF: {file_path.name}, extracted {len(chunks)} valid chunks")

            return chunks

        except Exception as e:
            app_logger.error(f"Error parsing PDF {file_path}: {e}")
            return []

    def _extract_text_from_pdf(self, file_path: Path) -> str:
        """
        Extract text content from PDF

        Args:
            file_path: Path to PDF file

        Returns:
            Extracted text content
        """
        pages_text = self._extract_text_by_page(file_path)
        return '\n'.join(pages_text)

    def _detect_headers_footers(self, pages_text: List[str]):
        """
        Detect repeating page headers and footers.

        Looks at the first/last 3 lines of each page and finds text that
        appears on at least 30% of pages (minimum 3 pages).

        Args:
            pages_text: List of per-page text strings
        """
        self.detected_headers = set()
        self.detected_footers = set()

        if len(pages_text) < 3:
            return

        header_candidates = {}
        footer_candidates = {}

        for page_text in pages_text:
            lines = [l.strip() for l in page_text.split('\n') if l.strip()]

            if len(lines) < 5:
                continue

            for line in lines[:3]:
                if line and len(line) > 5:
                    header_candidates[line] = header_candidates.get(line, 0) + 1

            for line in lines[-3:]:
                if line and len(line) > 5:
                    if not re.match(r'^pg\.\s*\d+$', line, re.IGNORECASE) and not re.match(r'^\d+$', line):
                        footer_candidates[line] = footer_candidates.get(line, 0) + 1

        threshold = max(3, len(pages_text) * 0.3)

        for text, count in header_candidates.items():
            if count >= threshold:
                self.detected_headers.add(text)
                app_logger.debug(f"Detected header: {text[:50]}... (appears {count} times)")

        for text, count in footer_candidates.items():
            if count >= threshold:
                self.detected_footers.add(text)
                app_logger.debug(f"Detected footer: {text[:50]}... (appears {count} times)")

    def _is_header_or_footer(self, text: str) -> bool:
        """Check if text matches a detected header or footer"""
        text_stripped = text.strip()

        if text_stripped in self.detected_headers or text_stripped in self.detected_footers:
            return True

        for header in self.detected_headers:
            if header in text_stripped:
                return True

        for footer in self.detected_footers:
            if footer in text_stripped:
                return True

        return False

    def _looks_like_toc_entry(self, title: str) -> bool:
        """Return whether a candidate section title looks like a table-of-contents entry."""
        normalized = " ".join((title or "").split())
        if not normalized:
            return False

        if normalized.lower() in {"contents", "table of contents"}:
            return True

        # Dot leaders plus a trailing page number are a strong TOC signal,
        # e.g. "Certificates following QNCP-w ........ 9"
        if re.search(r'\.{5,}\s*\d+\s*$', normalized):
            return True

        return False

    def _looks_like_inline_reference(self, title: str, previous_line: str = "") -> bool:
        """Return whether a same-line section match looks like an inline reference instead."""
        normalized = " ".join((title or "").split())
        previous = " ".join((previous_line or "").split())
        if not normalized:
            return False

        # Inline references inside enumerated lists often look like
        # "f) extKeyUsage." rather than a real section title.
        if re.match(r'^[a-z]\)', normalized):
            return True

        # ETSI/CABF inline citations often appear after list markers such as
        # "a)", "b)", etc. Those are not real section starts.
        if re.match(r'^[a-z]\)$', previous, re.IGNORECASE):
            return True

        return False

    def _extract_sections(self, content: str) -> List[Dict[str, Any]]:
        """
        Extract sections from document content

        Supports two formats:
        1. CA/B Forum: "3.2.1 Section Title" (number and title on same line)
        2. ETSI: "3.2.1" on one line, "Section Title" on next line

        Args:
            content: Document text content

        Returns:
            List of section dictionaries
        """
        sections = []

        # Section patterns for same-line format (CA/B Forum)
        # Pattern 1: "3.2.1 Section Title"
        # Pattern 2: "3.2.1. Section Title"
        same_line_patterns = [
            r'^(\d+(?:\.\d+)+)\s+(.+)$',  # 3.2.1 Title
            r'^(\d+(?:\.\d+)+)\.\s+(.+)$',  # 3.2.1. Title
        ]

        # Section number pattern for separate-line format (ETSI)
        # Pattern: "3.2.1" or "3" alone on a line
        section_num_pattern = r'^(\d+(?:\.\d+)*)$'

        lines = content.split('\n')
        current_section = None
        current_section_number = "1"  # ✅ 新增：跟踪当前章节号
        current_content = []

        i = 0
        while i < len(lines):
            line_stripped = lines[i].strip()

            # Skip empty lines
            if not line_stripped:
                i += 1
                continue

            # Skip detected headers/footers
            if self._is_header_or_footer(line_stripped):
                i += 1
                continue

            # Skip page number lines
            if re.match(r'^pg\.\s*\d+$', line_stripped, re.IGNORECASE) or re.match(r'^\d+$', line_stripped):
                i += 1
                continue

            matched = False

            # Try to match same-line patterns first (CA/B Forum)
            for pattern in same_line_patterns:
                match = re.match(pattern, line_stripped)
                if match:
                    section_num = match.group(1)
                    section_title = match.group(2).strip()

                    # Reject OID-like numbers: any component >= 100
                    components = section_num.split('.')
                    if any(int(c) >= 100 for c in components):
                        current_content.append(line_stripped)
                        i += 1
                        matched = True
                        break

                    # Reject section title that is a header/footer, TOC entry,
                    # or inline list/reference text mistakenly matching a section pattern
                    if (
                        self._is_header_or_footer(section_title)
                        or self._looks_like_toc_entry(section_title)
                        or self._looks_like_inline_reference(
                            section_title,
                            lines[i - 1].strip() if i > 0 else "",
                        )
                    ):
                        i += 1
                        continue

                    # Save previous section
                    if current_section:
                        current_section['content'] = '\n'.join(current_content)
                        sections.append(current_section)

                    current_section_number = section_num  # ✅ 更新当前章节号

                    current_section = {
                        'section': section_num,
                        'title': section_title,
                        'line_number': i
                    }
                    current_content = []
                    matched = True
                    break

            # If not matched, try ETSI format (number on one line, title on next)
            if not matched:
                num_match = re.match(section_num_pattern, line_stripped)
                if num_match and i + 1 < len(lines):
                    candidate_num = num_match.group(1)
                    # Reject OID-like numbers: any component >= 100
                    # (real section numbers have small components like 7.1.4.2)
                    components = candidate_num.split('.')
                    is_oid = any(int(c) >= 100 for c in components)

                    # Also reject if first component regresses from current section
                    # (e.g., seeing "2.5.4.6" while in section "7.1.4.2" means it's an OID)
                    if not is_oid and current_section_number:
                        current_first = int(current_section_number.split('.')[0])
                        candidate_first = int(candidate_num.split('.')[0])
                        if candidate_first < current_first - 1:
                            is_oid = True

                    if not is_oid:
                        # Check if next line could be a title (non-empty, not another section number)
                        next_line = lines[i + 1].strip()
                        if (
                            next_line and
                            not re.match(section_num_pattern, next_line) and
                            not self._looks_like_toc_entry(next_line)
                        ):
                            # This looks like ETSI format
                            if current_section:
                                current_section['content'] = '\n'.join(current_content)
                                sections.append(current_section)

                            section_num = candidate_num
                            section_title = next_line
                            current_section_number = section_num  # ✅ 更新当前章节号

                            current_section = {
                                'section': section_num,
                                'title': section_title,
                                'line_number': i
                            }
                            current_content = []
                            matched = True
                            i += 1  # Skip the title line

            # If still not matched and we have a current section, add to content
            if not matched and current_section:
                current_content.append(lines[i])

            i += 1

        # Add last section
        if current_section:
            current_section['content'] = '\n'.join(current_content)
            sections.append(current_section)

        # ✅ 新增：记录章节统计信息用于调试
        app_logger.info(f"Extracted {len(sections)} sections from PDF")
        if sections:
            section_numbers = [s['section'] for s in sections[:10]]
            app_logger.debug(f"First 10 sections: {section_numbers}")

        return sections

    def _validate_sections(self, sections: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Validate sections and filter out invalid ones"""
        valid_sections = []

        for section in sections:
            section_num = section['section']

            # Reject single-level section numbers (likely parsing errors)
            if '.' not in section_num:
                app_logger.warning(f"Rejecting section without proper numbering: {section_num}")
                continue

            title = section['title']

            if self._looks_like_toc_entry(title):
                app_logger.warning(f"Rejecting TOC-style section title: {title}")
                continue

            if self._is_header_or_footer(title):
                app_logger.warning(f"Rejecting section with header/footer title: {title}")
                continue

            if len(title) < 3:
                app_logger.warning(f"Rejecting section with too-short title: {title}")
                continue

            # Reject titles with repeating halves
            words = title.lower().split()
            if len(words) > 2:
                half = len(words) // 2
                if words[:half] == words[half:2*half]:
                    app_logger.warning(f"Rejecting section with repeating title: {title}")
                    continue

            content = section.get('content', '')
            if len(content.strip()) < 20:
                app_logger.warning(f"Rejecting section {section_num} with insufficient content")
                continue

            valid_sections.append(section)

        app_logger.info(f"Validated {len(valid_sections)} out of {len(sections)} sections")
        return valid_sections

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
                    'validation_issues': validation['issues'] if not validation['is_valid'] else []
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
        # Split on period, exclamation, question mark followed by space or newline
        sentences = re.split(r'(?<=[.!?])\s+', text)

        # Filter out very short sentences and clean up
        sentences = [s.strip() for s in sentences if len(s.strip()) > 15]

        return sentences

    def _identify_rule_type(self, sentence: str) -> Optional[str]:
        """
        Identify the type of normative rule in a sentence

        Args:
            sentence: Sentence to analyze

        Returns:
            Rule type (MUST, SHOULD, etc.) or None
        """
        # Check for each keyword in priority order (case-insensitive)
        for keyword in self.NORMATIVE_KEYWORDS:
            # Use word boundaries to avoid false matches, case-insensitive
            pattern = r'\b' + re.escape(keyword) + r'\b'
            if re.search(pattern, sentence, re.IGNORECASE):
                # Return the uppercased form for consistency
                return keyword.upper()

        return None

    def extract_metadata(self, file_path: Path) -> Dict[str, Any]:
        """
        Extract metadata from PDF

        Args:
            file_path: Path to PDF file

        Returns:
            Dictionary with metadata
        """
        metadata = {}

        try:
            doc = fitz.open(file_path)

            # Extract PDF metadata
            pdf_metadata = doc.metadata

            if pdf_metadata:
                metadata['title'] = pdf_metadata.get('title', '')
                metadata['author'] = pdf_metadata.get('author', '')
                metadata['subject'] = pdf_metadata.get('subject', '')
                metadata['creator'] = pdf_metadata.get('creator', '')
                metadata['producer'] = pdf_metadata.get('producer', '')
                metadata['creation_date'] = pdf_metadata.get('creationDate', '')

            metadata['page_count'] = len(doc)

            # Extract dates from first page content (for CAB/F documents)
            dates = self._extract_dates_from_first_page(doc)
            metadata.update(dates)

            doc.close()

        except Exception as e:
            app_logger.error(f"Error extracting PDF metadata: {e}")

        return metadata

    def _extract_dates_from_first_page(self, doc) -> Dict[str, Optional[datetime]]:
        """
        Extract effective date and version from the first page of PDF
        Used for CAB/F documents which typically show dates on the cover page

        Args:
            doc: PyMuPDF document object

        Returns:
            Dictionary with effective_date, publish_date, and version
        """
        dates = {
            'effective_date': None,
            'publish_date': None,
            'version': None
        }

        try:
            if len(doc) == 0:
                return dates

            # Get first page text
            first_page = doc[0]
            text = first_page.get_text()

            # Clean text: remove special characters that may interfere with date parsing
            # Replace special characters like '\x0c', '\xa0', etc. with space
            import re
            text = re.sub(r'[\x00-\x1f\x7f-\x9f\xa0]', ' ', text)
            # Remove Unicode replacement character (�) and surrounding backslashes
            text = text.replace('\ufffd', '')
            text = text.replace('\\', '')

            # Normalize various types of hyphens/dashes to ASCII hyphen (-)
            # U+2010 (hyphen), U+2011 (non-breaking hyphen), U+2012 (figure dash)
            # U+2013 (en dash), U+2014 (em dash), U+2212 (minus sign)
            hyphen_chars = ['\u2010', '\u2011', '\u2012', '\u2013', '\u2014', '\u2212']
            for hyphen in hyphen_chars:
                text = text.replace(hyphen, '-')

            # Normalize whitespace
            text = re.sub(r'\s+', ' ', text)

            # Extract version
            # Pattern: "Version 3.73.x.0" or "v3.73.x.0" or "V12.6.0 (2014-10)" (ETSI format) or "v. 1.0" (NetSec format)
            version_patterns = [
                r'Version\s+(\d+\.\d+(?:\.\w+)?(?:\.\d+)?)',
                r'v\.\s+(\d+\.\d+(?:\.\d+)?)',  # NetSec format: "v. 1.0"
                r'v\.?\s*(\d+\.\d+(?:\.\w+)?(?:\.\d+)?)',
                r'V\s*(\d+\.\d+\.\d+)',  # ETSI format like V12.6.0
            ]

            for pattern in version_patterns:
                match = re.search(pattern, text, re.IGNORECASE)
                if match:
                    dates['version'] = match.group(1)
                    app_logger.debug(f"Extracted version from PDF: {dates['version']}")
                    break

            # Extract dates
            # CAB/F documents typically show dates in formats like:
            # "February 28 XXXX XX, 2024" (draft version with placeholders)
            # "February 28, 2024" (final version)
            # "Effective Date: February 28, 2024"
            # ETSI documents use format like "V12.6.0 (2014-10)" where (YYYY-MM) is the date

            date_patterns = [
                # ETSI format: V12.6.0 (2014-10) or similar
                (r'\((\d{4})-(\d{2})\)', 'publish_date'),

                # NetSec format: "Effective on 1/1/2013"
                (r'Effective\s+on\s+(\d{1,2}/\d{1,2}/\d{4})', 'effective_date'),

                # With "Effective" label
                (r'Effective\s+Date:\s*(\w+\s+\d{1,2},?\s+\d{4})', 'effective_date'),
                (r'Effective:\s*(\w+\s+\d{1,2},?\s+\d{4})', 'effective_date'),

                # With "Published" or "Publication" label
                (r'Publish(?:ed|ation)\s+Date:\s*(\w+\s+\d{1,2},?\s+\d{4})', 'publish_date'),
                (r'Publish(?:ed|ation):\s*(\w+\s+\d{1,2},?\s+\d{4})', 'publish_date'),

                # Date with dashes: "25-August-2025" or "25-Aug-2025" (common in CABF documents)
                (r'(\d{1,2}-\w+-\d{4})', 'publish_date'),

                # European format: "6 May, 2024" (day before month, CABF style)
                (r'(\d{1,2}\s+\w+,?\s+\d{4})', 'publish_date'),

                # US format: "February 28, 2024" (month before day)
                # Match dates like "February 28, 2024" but skip placeholders like "XXXX XX"
                (r'(\w+\s+\d{1,2},?\s+\d{4})(?!\s*XXX)', 'effective_date'),
            ]

            for pattern, date_type in date_patterns:
                matches = re.finditer(pattern, text, re.IGNORECASE)
                for match in matches:
                    # Check if this is ETSI format (YYYY-MM)
                    if len(match.groups()) == 2 and match.group(1).isdigit() and match.group(2).isdigit():
                        # ETSI format: (2014-10)
                        year = match.group(1)
                        month = match.group(2)
                        date_str = f"{year}-{month}-01"  # Set to first day of month
                        parsed_date = self._parse_date_string(date_str)
                        if parsed_date and not dates.get(date_type):
                            dates[date_type] = parsed_date
                            app_logger.debug(f"Extracted {date_type} from PDF (ETSI format): {parsed_date}")
                        break
                    else:
                        # Standard format
                        date_str = match.group(1)
                        # Skip dates with placeholder text
                        if 'XXX' in date_str or 'xx' in date_str.lower():
                            continue

                        parsed_date = self._parse_date_string(date_str)
                        if parsed_date and not dates.get(date_type):
                            dates[date_type] = parsed_date
                            app_logger.debug(f"Extracted {date_type} from PDF: {parsed_date}")
                        break

        except Exception as e:
            app_logger.error(f"Error extracting dates from first page: {e}")

        return dates

    def _parse_date_string(self, date_str: str) -> Optional[datetime]:
        """
        Parse various date string formats

        Args:
            date_str: Date string to parse

        Returns:
            datetime object or None
        """
        # Common date formats
        date_formats = [
            "%B %d, %Y",      # February 28, 2024
            "%B %d %Y",       # February 28 2024
            "%b %d, %Y",      # Feb 28, 2024
            "%b %d %Y",       # Feb 28 2024
            "%d %B, %Y",      # 6 May, 2024 (European/CABF format)
            "%d %b, %Y",      # 6 May, 2024 (short month)
            "%d %B %Y",       # 6 May 2024 (no comma)
            "%d %b %Y",       # 6 May 2024 (short, no comma)
            "%d-%B-%Y",       # 25-August-2025
            "%d-%b-%Y",       # 25-Aug-2025
            "%Y-%m-%d",       # 2024-02-28
            "%m/%d/%Y",       # 02/28/2024
            "%d/%m/%Y",       # 28/02/2024
        ]

        for fmt in date_formats:
            try:
                return datetime.strptime(date_str.strip(), fmt)
            except ValueError:
                continue

        app_logger.warning(f"Could not parse date string: {date_str}")
        return None
