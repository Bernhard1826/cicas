"""
结构化文档分块器
将文档拆分成类型化的 chunks，避免破坏规则完整性
"""
import re
from typing import List, Optional, Tuple
from .chunk_types import (
    StructuredChunk,
    ChunkType,
    ExtractorType,
    CHUNK_EXTRACTOR_MAPPING,
    DO_NOT_EXTRACT_MARKERS,
    REQUIREMENT_KEYWORDS,
    REQUIREMENT_KEYWORD_REGEX,
    contains_requirement_keyword,
    DEFINITION_KEYWORDS,
)


class StructuredChunker:
    """结构化文档分块器"""

    def __init__(self,
                 context_lines: int = 3,
                 min_chunk_size: int = 10,
                 max_chunk_size: int = 2000):
        """
        初始化分块器

        Args:
            context_lines: 上下文行数
            min_chunk_size: 最小块大小（字符数）
            max_chunk_size: 最大块大小（字符数）
        """
        self.context_lines = context_lines
        self.min_chunk_size = min_chunk_size
        self.max_chunk_size = max_chunk_size

        # 编译正则模式
        self._compile_patterns()

    def _compile_patterns(self):
        """编译所有正则模式"""
        # 章节标记 - 改进版：区分章节标题和列表项
        # 章节标题特征：
        #   1. 全大写："1. INTRODUCTION"
        #   2. Title Case多词："3.2.1 Certificate Content"
        #   3. 单词标题："1.1 Overview"
        #   4. 驼峰命名："3.2.2.9 MultiPerspective Issuance"
        # 列表项特征：
        #   "1. The CA SHALL..." - 第一个词后跟"the/a/an"等冠词
        self.section_pattern = re.compile(
            r'^(\d+\.?)+\s+(?:'  # Section number
            r'[A-Z][A-Z\s]+(?:\s|$)|'   # 全大写标题（如 "INTRODUCTION"）
            r'[A-Z][a-z]+(?:[A-Z][a-z]+)*(?:\s+[A-Z][a-z]+(?:[A-Z][a-z]+)*)*'  # Title Case 或驼峰（如 "Certificate Content" 或 "MultiPerspective"）
            r')(?:\s|\.\.+|$)',  # 后跟空格、省略号或行尾
            re.MULTILINE
        )

        # ABNF 定义
        self.abnf_pattern = re.compile(r'::=')

        # 表格标记（简单检测）
        self.table_pattern = re.compile(
            r'(\|.*\|)|(\+[-+]+\+)',  # |col1|col2| or +---+---+
            re.MULTILINE
        )

        # 列表标记
        self.list_pattern = re.compile(
            r'^[\s]*[\*\-\+\d]+[\.\)]\s+',
            re.MULTILINE
        )

        # 编译 Do-Not-Extract 模式
        self.non_normative_patterns = {}
        for category, patterns in DO_NOT_EXTRACT_MARKERS.items():
            self.non_normative_patterns[category] = [
                re.compile(p, re.IGNORECASE) for p in patterns
            ]

        # 编译需求关键词（re.IGNORECASE 覆盖 ETSI 等用小写关键词的文档）
        self.requirement_keyword_regex = REQUIREMENT_KEYWORD_REGEX
        # 编译定义关键词
        self.definition_patterns = [
            re.compile(p, re.IGNORECASE) for p in DEFINITION_KEYWORDS
        ]

    def _merge_broken_lines(self, lines: List[str]) -> List[str]:
        """
        合并被PDF破坏的句子

        规则：
        1. 短行（<50字符）且以小写开头 → 可能是续行，合并到前一行
        2. 以MUST/SHALL等关键词开头 → 新规则开始，不合并
        3. 以句号结尾 → 句子结束
        4. 表格行（以|开头）→ 不合并

        Args:
            lines: 原始行列表

        Returns:
            合并后的行列表
        """
        merged = []
        buffer = ""
        requirement_keywords = self.requirement_keyword_regex

        for line in lines:
            line = line.strip()

            # 跳过空行
            if not line:
                if buffer:
                    merged.append(buffer)
                    buffer = ""
                continue

            # 表格行不合并
            if line.startswith('|'):
                if buffer:
                    merged.append(buffer)
                    buffer = ""
                merged.append(line)
                continue

            # 检查是否是新规则开始
            is_new_requirement = requirement_keywords.search(line)

            # 检查是否是续行（短行且以小写开头，且不是新规则）
            is_continuation = (
                buffer and
                len(line) < 50 and
                line[0].islower() and
                not is_new_requirement
            )

            if is_continuation:
                # 合并到buffer
                buffer += " " + line
            else:
                # 开始新句子
                if buffer:
                    merged.append(buffer)
                buffer = line

            # 如果以句号结尾，结束当前句子
            if line.endswith('.'):
                if buffer:
                    merged.append(buffer)
                    buffer = ""

        # 添加最后的buffer
        if buffer:
            merged.append(buffer)

        return merged

    def chunk_document(self, text: str, document_id: str = "doc") -> List[StructuredChunk]:
        """
        将文档分块为结构化 chunks

        Args:
            text: 文档文本
            document_id: 文档标识

        Returns:
            结构化 chunk 列表
        """
        lines = text.split('\n')

        # ✅ 合并被PDF破坏的句子（关键修复）
        lines = self._merge_broken_lines(lines)

        chunks = []
        current_section = None
        current_title = None  # ✅ 新增：跟踪当前章节标题
        i = 0

        while i < len(lines):
            # 检测章节开始
            if self._is_section_start(lines[i]):
                # 提取section号和title
                current_section = self._extract_section_number(lines[i])
                current_title = self._extract_section_title(lines[i])  # ✅ 新增：提取章节标题

                # 章节标题作为单独 chunk
                chunk = self._create_chunk(
                    lines=[lines[i]],
                    start_line=i,
                    chunk_type=ChunkType.SECTION_CHUNK,
                    section=current_section,
                    title=current_title,  # ✅ 新增：传递title
                    document_id=document_id,
                    lines_context=lines,
                )
                chunks.append(chunk)
                i += 1
                continue

            # 检测内容块
            chunk_lines, chunk_type, end_line = self._extract_content_chunk(
                lines, i
            )

            if chunk_lines:
                chunk = self._create_chunk(
                    lines=chunk_lines,
                    start_line=i,
                    chunk_type=chunk_type,
                    section=current_section,
                    title=current_title,  # ✅ 新增：传递title
                    document_id=document_id,
                    lines_context=lines,
                )
                chunks.append(chunk)
                i = end_line + 1
            else:
                i += 1

        return chunks

    def _is_section_start(self, line: str) -> bool:
        """
        判断是否为章节开始

        区分真正的章节标题和编号列表项：
        - 章节标题："1. INTRODUCTION", "3.2.1 Certificate Content"
        - 列表项："1. The CA SHALL...", "2. Meet the qualification..."
        """
        line_stripped = line.strip()

        # 首先检查基本模式
        if not self.section_pattern.match(line_stripped):
            return False

        # 额外验证：排除列表项
        # 列表项特征：第一个词后跟着小写冠词或常见连接词
        # 提取section号后的文本
        match = re.match(r'^(\d+(?:\.\d+)*)[.\)]\s+(.+)', line_stripped)
        if match:
            after_number = match.group(2)
            # 检查是否以常见小写词开头的句子（列表项特征）
            # 第一个词后紧跟小写词（如"The the", "Meet the", "Ensure proper"）
            words = after_number.split()
            if len(words) >= 2:
                first_word = words[0]
                second_word = words[1]

                # 如果第二个词是小写冠词/介词/连词，很可能是列表项
                lowercase_markers = {
                    'the', 'a', 'an', 'of', 'in', 'to', 'for', 'with', 'on', 'at',
                    'from', 'by', 'as', 'is', 'are', 'was', 'were', 'be', 'been',
                    'have', 'has', 'had', 'do', 'does', 'did', 'will', 'would',
                    'should', 'could', 'may', 'might', 'must', 'shall', 'can'
                }

                # 规范性关键词（如果第二个词是这些，很可能是列表项）
                normative_keywords = {'MUST', 'SHALL', 'SHOULD', 'MAY', 'REQUIRED', 'RECOMMENDED'}

                # 检查第二个词
                if second_word.lower() in lowercase_markers or second_word.upper() in normative_keywords:
                    # 很可能是列表项，如："1. The CA SHALL..."
                    return False

                # 如果第二个词是2-4个字母的全大写缩写（如CA, TLS），也可能是列表项
                if len(second_word) >= 2 and len(second_word) <= 4 and second_word.isupper():
                    # 很可能是列表项，如："1. The CA SHALL..."
                    return False

                # 如果第一个词全小写（除首字母），第二个词也小写，也可能是列表项
                if first_word[1:].islower() and second_word.islower():
                    return False

        return True

    def _extract_section_number(self, line: str) -> str:
        """
        从章节行中提取章节号

        Examples:
            "7.1.2.4 Random Value" → "7.1.2.4"
            "1. The Request Token" → "1"
            "1.2 Relevant Dates" → "1.2"

        Returns:
            Section number string, or empty string if not found
        """
        import re
        from app.core.logging_config import app_logger
        # Match the section number pattern at the start of the line
        # Captures: "7.1.2.4" or "1.2" or "1"
        match = re.match(r'^((?:\d+\.)*\d+)', line.strip())
        if match:
            result = match.group(1)

            # 排除日期格式（4位数字开头，如"2026"或"2026.03.15"）
            if re.match(r'^[12]\d{3}(?:\.|$)', result):
                return ""

            # 排除过长的section号（超过5级，如"1.2.3.4.5.6"）
            if result.count('.') > 5:
                return ""

            # DEBUG: Log first 50 section extractions to debug truncation bug
            if not hasattr(self, '_debug_count'):
                self._debug_count = 0
            if self._debug_count < 50:
                app_logger.info(f"[DEBUG StructuredChunker] Line: '{line[:80]}' -> Section: '{result}'")
                self._debug_count += 1
            return result
        return ""

    def _extract_section_title(self, line: str) -> str:
        """
        从章节行中提取章节标题

        Examples:
            "7.1.2.4 Random Value" → "Random Value"
            "1. INTRODUCTION" → "INTRODUCTION"
            "3.2.1 Certificate Content" → "Certificate Content"

        Returns:
            Section title string, or empty string if not found
        """
        import re
        # 提取section号后面的文本作为title
        # 匹配: "数字.数字.数字 标题文本" 或 "数字. 标题文本"
        match = re.match(r'^(?:\d+\.?)+\s+(.+)', line.strip())
        if match:
            title = match.group(1).strip()
            # 移除末尾的省略号
            title = re.sub(r'\.+$', '', title)
            return title
        return ""

    def _extract_content_chunk(
        self, lines: List[str], start: int
    ) -> Tuple[List[str], ChunkType, int]:
        """
        提取内容块

        Returns:
            (chunk_lines, chunk_type, end_line_index)
        """
        if start >= len(lines):
            return [], ChunkType.UNKNOWN_CHUNK, start

        # 跳过空行
        while start < len(lines) and not lines[start].strip():
            start += 1

        if start >= len(lines):
            return [], ChunkType.UNKNOWN_CHUNK, start

        # 检测块类型
        chunk_type = self._detect_chunk_type(lines, start)

        # 根据类型提取块
        if chunk_type == ChunkType.TABLE_CHUNK:
            return self._extract_table_chunk(lines, start)
        elif chunk_type == ChunkType.LIST_CHUNK:
            return self._extract_list_chunk(lines, start)
        elif chunk_type == ChunkType.DEFINITION_CHUNK:
            return self._extract_definition_chunk(lines, start)
        else:
            return self._extract_paragraph_chunk(lines, start)

    def _detect_chunk_type(self, lines: List[str], start: int) -> ChunkType:
        """检测 chunk 类型"""
        # 检查前20行（扩大检测范围，避免错过后面的MUST/SHALL）
        lookahead = min(20, len(lines) - start)
        preview_text = '\n'.join(lines[start:start + lookahead])

        # 检测非规范内容（优先级最高）
        if self._is_non_normative(preview_text):
            return ChunkType.NON_NORMATIVE_CHUNK

        # 检测表格
        if self.table_pattern.search(preview_text):
            return ChunkType.TABLE_CHUNK

        # 检测列表
        if self.list_pattern.match(lines[start]):
            return ChunkType.LIST_CHUNK

        # 检测定义
        if self._contains_definition(preview_text):
            return ChunkType.DEFINITION_CHUNK

        # 检测需求
        if self._contains_requirement(preview_text):
            return ChunkType.REQUIREMENT_CHUNK

        return ChunkType.UNKNOWN_CHUNK

    def _is_non_normative(self, text: str) -> bool:
        """检测是否为非规范内容"""
        for category, patterns in self.non_normative_patterns.items():
            for pattern in patterns:
                if pattern.search(text):
                    return True
        return False

    def _contains_requirement(self, text: str) -> bool:
        """检测是否包含需求关键词"""
        return contains_requirement_keyword(text)

    def _contains_definition(self, text: str) -> bool:
        """检测是否包含定义"""
        for pattern in self.definition_patterns:
            if pattern.search(text):
                return True
        return False

    def _extract_table_chunk(
        self, lines: List[str], start: int
    ) -> Tuple[List[str], ChunkType, int]:
        """提取表格块"""
        end = start
        while end < len(lines):
            line = lines[end]
            # 表格结束条件：空行或非表格行
            if not line.strip():
                break
            if not self.table_pattern.search(line) and not line.startswith(' '):
                break
            end += 1

        return lines[start:end], ChunkType.TABLE_CHUNK, end - 1

    def _extract_list_chunk(
        self, lines: List[str], start: int
    ) -> Tuple[List[str], ChunkType, int]:
        """提取列表块"""
        end = start
        base_indent = len(lines[start]) - len(lines[start].lstrip())

        while end < len(lines):
            line = lines[end]
            if not line.strip():
                # 允许列表内空行
                if end + 1 < len(lines) and self.list_pattern.match(lines[end + 1]):
                    end += 1
                    continue
                break

            # 检查是否为列表项或续行
            current_indent = len(line) - len(line.lstrip())
            if current_indent < base_indent and line.strip():
                break

            end += 1

        return lines[start:end], ChunkType.LIST_CHUNK, end - 1

    def _extract_definition_chunk(
        self, lines: List[str], start: int
    ) -> Tuple[List[str], ChunkType, int]:
        """提取定义块"""
        # 定义通常是短段落，遇到空行或下一个章节停止
        end = start
        while end < len(lines):
            line = lines[end]
            if not line.strip() or self._is_section_start(line):
                break
            end += 1

        return lines[start:end], ChunkType.DEFINITION_CHUNK, end - 1

    def _extract_paragraph_chunk(
        self, lines: List[str], start: int
    ) -> Tuple[List[str], ChunkType, int]:
        """提取段落块"""
        end = start
        chunk_chars = 0

        while end < len(lines):
            line = lines[end]

            # 停止条件
            if not line.strip():
                break
            if self._is_section_start(line):
                break
            if chunk_chars > self.max_chunk_size:
                break

            chunk_chars += len(line)
            end += 1

            # 检查是否达到最小块大小
            if chunk_chars >= self.min_chunk_size:
                # 尝试在句子边界停止
                if line.strip().endswith(('.', '!', '?')):
                    break

        # 判断类型
        chunk_text = '\n'.join(lines[start:end])
        if self._contains_requirement(chunk_text):
            chunk_type = ChunkType.REQUIREMENT_CHUNK
        elif self._is_non_normative(chunk_text):
            chunk_type = ChunkType.NON_NORMATIVE_CHUNK
        else:
            chunk_type = ChunkType.UNKNOWN_CHUNK

        return lines[start:end], chunk_type, end - 1

    def _create_chunk(
        self,
        lines: List[str],
        start_line: int,
        chunk_type: ChunkType,
        section: Optional[str],
        title: Optional[str],
        document_id: str,
        lines_context: List[str],
    ) -> StructuredChunk:
        """创建结构化 chunk"""
        text = '\n'.join(lines)
        end_line = start_line + len(lines) - 1

        # 提取上下文
        context_before = self._get_context(
            lines_context, start_line - self.context_lines, start_line
        )
        context_after = self._get_context(
            lines_context, end_line + 1, end_line + 1 + self.context_lines
        )

        # 检测非规范标记
        non_normative_markers = self._detect_non_normative_markers(text)

        # 判断是否应该提取
        is_normative = chunk_type != ChunkType.NON_NORMATIVE_CHUNK
        should_extract = is_normative and chunk_type != ChunkType.SECTION_CHUNK

        # 获取推荐的提取器
        extractor_type = CHUNK_EXTRACTOR_MAPPING.get(
            chunk_type, ExtractorType.LLM
        )

        # 检测特征
        contains_requirement = self._contains_requirement(text)
        contains_definition = self._contains_definition(text)

        chunk_id = f"{document_id}:chunk:{start_line}-{end_line}"

        return StructuredChunk(
            chunk_id=chunk_id,
            chunk_type=chunk_type,
            text=text,
            line_start=start_line,
            line_end=end_line,
            section=section,
            title=title,
            context_before=context_before,
            context_after=context_after,
            extractor_type=extractor_type,
            should_extract=should_extract,
            is_normative=is_normative,
            contains_requirement=contains_requirement,
            contains_definition=contains_definition,
            non_normative_markers=non_normative_markers,
        )

    def _get_context(
        self, lines: List[str], start: int, end: int
    ) -> Optional[str]:
        """获取上下文"""
        start = max(0, start)
        end = min(len(lines), end)
        if start >= end:
            return None
        context_lines = lines[start:end]
        return '\n'.join(context_lines) if context_lines else None

    def _detect_non_normative_markers(self, text: str) -> List[str]:
        """检测非规范标记"""
        markers = []
        for category, patterns in self.non_normative_patterns.items():
            for pattern in patterns:
                if pattern.search(text):
                    markers.append(category)
                    break
        return markers
