"""
Layer1: Regex Chunk Processor
文档预处理器 + 分块器 (chunker)

任务：
1. 找出文档中可能包含规则的"锚点句"（anchors）
2. 为每个anchor抽取上下文窗口（chunk）
3. 自动过滤无效段落（Noise Filtering）
4. 输出chunk（作为LLM的输入，不是规则！）

禁止：
- 不要生成规则
- 不要提取规则含义
- 不要做规则去重
- 不要输出任何"规范化后的规则文本"
- 不要做语义解释
- 不要做推理
"""

import re
from typing import List, Dict, Any, Optional
from app.core.logging_config import app_logger


class RegexChunkProcessor:
    """
    Layer1: 文档预处理 + Chunk切分器

    只负责：
    1. 定位规则候选位置（anchor）
    2. 提取上下文窗口（chunk）
    3. 过滤噪音
    """

    # 规范性关键词（锚点）
    ANCHOR_KEYWORDS = [
        "MUST", "MUST NOT",
        "SHALL", "SHALL NOT",
        "SHOULD", "SHOULD NOT",
        "REQUIRED", "NOT RECOMMENDED",
        "MAY", "OPTIONAL"
    ]

    # 噪音标记（需要过滤的段落）
    NOISE_MARKERS = [
        "NOTE", "Notes", "Note:",
        "EXAMPLE", "Example:", "Examples:",
        "Figure", "Table",
        "Definitions",
        "Motivation", "Rationale",
        "Background", "Introduction",
        "Copyright", "Status of",
        "Table of Contents",
        "Acknowledgment"
    ]

    # ASN.1 语法块特征（用于过滤 ASN.1 结构定义产生的假阳性）
    ASN1_PATTERNS = [
        re.compile(r'^\s*\w+\s*::=\s*', re.MULTILINE),          # ::= 定义符
        re.compile(r'\bSEQUENCE\s*\{'),                          # SEQUENCE { ... }
        re.compile(r'\bCHOICE\s*\{'),                             # CHOICE { ... }
        re.compile(r'\bOPTIONAL\b.*\bOPTIONAL\b'),              # 多个 OPTIONAL 字段
        re.compile(r'\[\d+\]\s+\w+\s+OPTIONAL'),                # [0] Type OPTIONAL
        re.compile(r'INTEGER\s*\(\d+\.\.\.?\d*\)'),             # INTEGER (0..MAX)
    ]

    def __init__(
        self,
        context_lines: int = 3,
        max_chunk_chars: int = 1000,
        custom_keywords: Optional[List[str]] = None
    ):
        """
        初始化Chunk处理器

        Args:
            context_lines: 上下文行数（默认3行）
            max_chunk_chars: 单个chunk最大字符数
            custom_keywords: 自定义关键词（补充到默认锚点）
        """
        self.context_lines = context_lines
        self.max_chunk_chars = max_chunk_chars

        # 合并自定义关键词
        self.anchor_keywords = self.ANCHOR_KEYWORDS.copy()
        if custom_keywords:
            for kw in custom_keywords:
                kw_upper = kw.upper()
                if kw_upper not in self.anchor_keywords:
                    self.anchor_keywords.append(kw_upper)
            app_logger.info(f"Added {len(custom_keywords)} custom anchor keywords")

    def process_document(
        self,
        text: str,
        doc_id: str = "unknown",
        section_hint: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        """
        处理文档，提取chunks

        Args:
            text: 文档原文
            doc_id: 文档ID（用于标识来源）
            section_hint: 章节提示（如"RFC5280 4.2.1.6"）

        Returns:
            List[Dict]: chunks列表
        """
        # 分行处理
        lines = text.split('\n')

        # 1. 找到所有锚点位置
        anchors = self._find_anchors(lines)

        app_logger.info(f"Found {len(anchors)} anchor points in document {doc_id}")

        # 2. 为每个锚点提取chunk
        chunks = []
        for i, anchor_info in enumerate(anchors):
            chunk = self._extract_chunk(
                lines=lines,
                anchor_line_idx=anchor_info['line_idx'],
                anchor_keyword=anchor_info['keyword'],
                chunk_id=f"{doc_id}_chunk_{i+1:03d}"
            )

            if chunk and not self._is_noise(chunk['text']):
                chunk['doc_id'] = doc_id
                chunk['section'] = section_hint or "unknown"
                chunks.append(chunk)

        app_logger.info(f"Extracted {len(chunks)} valid chunks from {doc_id}")

        return chunks

    def _find_anchors(self, lines: List[str]) -> List[Dict[str, Any]]:
        """
        找到所有锚点（包含规范性关键词的行）

        Returns:
            List[Dict]: [{'line_idx': int, 'keyword': str, 'line_text': str}]
        """
        anchors = []

        for line_idx, line in enumerate(lines):
            for keyword in self.anchor_keywords:
                # 使用词边界匹配，避免误匹配（如"MUST"不匹配"MUSTANG"）
                pattern = r'\b' + re.escape(keyword) + r'\b'
                if re.search(pattern, line, re.IGNORECASE):
                    anchors.append({
                        'line_idx': line_idx,
                        'keyword': keyword,
                        'line_text': line.strip()
                    })
                    break  # 每行只记录一次

        return anchors

    def _extract_chunk(
        self,
        lines: List[str],
        anchor_line_idx: int,
        anchor_keyword: str,
        chunk_id: str
    ) -> Optional[Dict[str, Any]]:
        """
        为单个锚点提取上下文chunk

        Args:
            lines: 文档行列表
            anchor_line_idx: 锚点所在行索引
            anchor_keyword: 锚点关键词
            chunk_id: chunk唯一ID

        Returns:
            Dict: chunk信息，或None（如果提取失败）
        """
        # 计算上下文窗口范围
        start_line = max(0, anchor_line_idx - self.context_lines)
        end_line = min(len(lines), anchor_line_idx + self.context_lines + 1)

        # 优化：扩展到段落边界
        start_line = self._expand_to_paragraph_start(lines, start_line, anchor_line_idx)
        end_line = self._expand_to_paragraph_end(lines, end_line, anchor_line_idx)

        # 提取文本
        chunk_lines = lines[start_line:end_line]
        chunk_text = '\n'.join(chunk_lines).strip()

        # 检查长度限制
        if len(chunk_text) > self.max_chunk_chars:
            # 截断到最大长度（保留完整句子）
            chunk_text = self._truncate_to_sentence(chunk_text, self.max_chunk_chars)

        if not chunk_text:
            return None

        return {
            'id': chunk_id,
            'start_line': start_line + 1,  # 1-indexed
            'end_line': end_line,           # 1-indexed
            'anchor': anchor_keyword,
            'text': chunk_text
        }

    def _expand_to_paragraph_start(
        self,
        lines: List[str],
        start_line: int,
        anchor_line: int
    ) -> int:
        """向上扩展到段落开始（遇到空行停止）"""
        # 最多向上扩展10行
        max_expand = 10
        for i in range(start_line, max(0, start_line - max_expand), -1):
            if not lines[i].strip():  # 空行 = 段落边界
                return i + 1
        return max(0, start_line - max_expand)

    def _expand_to_paragraph_end(
        self,
        lines: List[str],
        end_line: int,
        anchor_line: int
    ) -> int:
        """向下扩展到段落结束（遇到空行停止）"""
        # 最多向下扩展10行
        max_expand = 10
        for i in range(end_line, min(len(lines), end_line + max_expand)):
            if not lines[i].strip():  # 空行 = 段落边界
                return i
        return min(len(lines), end_line + max_expand)

    def _truncate_to_sentence(self, text: str, max_chars: int) -> str:
        """截断到最大长度，保留完整句子"""
        if len(text) <= max_chars:
            return text

        # 在max_chars附近找句号
        truncated = text[:max_chars]
        last_period = max(
            truncated.rfind('.'),
            truncated.rfind('!'),
            truncated.rfind('?')
        )

        if last_period > max_chars * 0.7:  # 至少保留70%
            return truncated[:last_period + 1]
        else:
            return truncated + "..."

    def _is_noise(self, text: str) -> bool:
        """
        判断chunk是否为噪音（需要过滤）

        噪音包括：
        - NOTE / EXAMPLE
        - 引言 / 背景
        - 图表标题
        - 版权声明
        - ASN.1 语法定义块
        """
        # 检查前100个字符（通常噪音标记在开头）
        text_preview = text[:100].strip()

        for noise_marker in self.NOISE_MARKERS:
            if noise_marker.lower() in text_preview.lower():
                app_logger.debug(f"Filtered noise chunk (marker: {noise_marker})")
                return True

        # 过滤过短的chunk（少于20个字符）
        if len(text.strip()) < 20:
            app_logger.debug("Filtered chunk: too short")
            return True

        # 过滤 ASN.1 语法定义块（会产生假阳性规则，如 RFC 4.2.1.10 的 SEQUENCE/OPTIONAL 行）
        for pattern in self.ASN1_PATTERNS:
            if pattern.search(text):
                app_logger.debug("Filtered ASN.1 syntax chunk")
                return True

        return False

    def get_chunk_statistics(self, chunks: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        获取chunk统计信息（用于质量评估）

        Returns:
            Dict: 统计信息
        """
        if not chunks:
            return {
                'total_chunks': 0,
                'avg_chunk_length': 0,
                'anchor_distribution': {}
            }

        # 统计anchor分布
        anchor_counts = {}
        total_length = 0

        for chunk in chunks:
            anchor = chunk.get('anchor', 'unknown')
            anchor_counts[anchor] = anchor_counts.get(anchor, 0) + 1
            total_length += len(chunk.get('text', ''))

        return {
            'total_chunks': len(chunks),
            'avg_chunk_length': total_length / len(chunks) if chunks else 0,
            'anchor_distribution': anchor_counts
        }
