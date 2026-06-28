"""
智能内容定位切分器

策略：
1. 跳过文档前置内容（版权、目录等）
2. 定位规则密集区域
3. 按语义边界切分
"""

from typing import List, Dict, Tuple
import re


class ContentAwareChunker:
    """内容感知的智能切分器"""

    def __init__(self, chunk_size: int = 10000):
        self.chunk_size = chunk_size

    def chunk_document(self, text: str, doc_type: str = 'auto') -> List[Dict]:
        """
        智能切分文档

        Returns:
            List[Dict]: [{'text': str, 'section': str, 'priority': int, 'start_pos': int}]
        """
        # 1. 检测文档类型
        if doc_type == 'auto':
            doc_type = self._detect_document_type(text)

        # 2. 定位内容起点（跳过前置内容）
        content_start = self._find_content_start(text, doc_type)

        # 3. 提取章节边界
        sections = self._extract_sections(text[content_start:], doc_type)

        # 4. 按优先级切分
        chunks = self._split_by_priority(text, sections, content_start)

        return chunks

    def _detect_document_type(self, text: str) -> str:
        """检测文档类型"""
        if 'Request for Comments' in text[:1000] or 'RFC' in text[:500]:
            return 'rfc'
        elif 'X.509' in text[:2000] or 'ITU-T' in text[:2000]:
            return 'x509'
        elif text.count('\n\n') < 10:  # PDF通常缺少段落分隔
            return 'pdf'
        else:
            return 'generic'

    def _find_content_start(self, text: str, doc_type: str) -> int:
        """
        定位实质内容的起点（跳过前置内容）

        策略：
        1. 跳过版权、摘要、目录
        2. 查找第一个包含规范性关键词的章节
        """
        # 明显的非内容章节标题
        skip_sections = [
            r'status of this memo',
            r'copyright notice',
            r'abstract',
            r'table of contents',
            r'introduction',  # 引言通常也不包含规则
            r'terminology',   # 术语定义
            r'conventions',   # 约定说明
        ]

        # RFC风格：查找第一个不在跳过列表的章节
        if doc_type == 'rfc':
            # 匹配章节：4.  Certificate and Certificate Extensions Profile
            section_pattern = r'\n(\d+)\.\s+([^\n]{5,100})\n'
            matches = list(re.finditer(section_pattern, text, re.IGNORECASE))

            for match in matches:
                section_num = int(match.group(1))
                section_title = match.group(2).lower()

                # 跳过前3个章节（通常是引言、术语等）
                if section_num <= 3:
                    continue

                # 检查是否在跳过列表
                if any(skip in section_title for skip in skip_sections):
                    continue

                # 检查是否包含证书相关术语
                chunk_preview = text[match.start():match.start() + 500].lower()
                if any(kw in chunk_preview for kw in ['certificate', 'extension', 'field', 'must', 'shall']):
                    return match.start()

        # 通用策略：查找第一个包含"MUST"或"SHALL"的段落
        normative_pattern = r'.{0,200}(MUST|SHALL|REQUIRED).{0,500}'
        match = re.search(normative_pattern, text)
        if match:
            # 往回找到段落开头
            start = max(0, match.start() - 500)
            return start

        # 保底：跳过前20%
        return int(len(text) * 0.2)

    def _extract_sections(self, text: str, doc_type: str) -> List[Dict]:
        """
        提取章节信息

        Returns:
            [{'start': int, 'title': str, 'level': int, 'priority': int}]
        """
        sections = []

        if doc_type == 'rfc':
            # RFC章节：4.  Title 或 4.2.1  Subsection
            pattern = r'\n(\d+(?:\.\d+)*)\.\s+([^\n]{5,100})\n'
            for match in re.finditer(pattern, text):
                section_num = match.group(1)
                title = match.group(2)
                level = section_num.count('.')

                # 计算优先级（包含关键词的章节优先）
                priority = self._calculate_section_priority(title, text[match.start():match.start()+1000])

                sections.append({
                    'start': match.start(),
                    'number': section_num,
                    'title': title,
                    'level': level,
                    'priority': priority
                })

        elif doc_type == 'pdf':
            # PDF：尝试多种章节模式
            patterns = [
                r'\n(\d+(?:\.\d+)*)\s+([A-Z][^\n]{5,80})\n',  # "4.2 Key Usage"
                r'\n([A-Z][^\n]{5,80})\n(?=[A-Z])',            # 全大写标题
            ]
            for pattern in patterns:
                for match in re.finditer(pattern, text):
                    sections.append({
                        'start': match.start(),
                        'title': match.group(0).strip(),
                        'level': 0,
                        'priority': self._calculate_section_priority(match.group(0), text[match.start():match.start()+1000])
                    })

        # 按位置排序
        sections.sort(key=lambda x: x['start'])
        return sections

    def _calculate_section_priority(self, title: str, content_preview: str) -> int:
        """
        计算章节优先级 (0-100)

        高优先级关键词：
        - certificate, extension, field
        - must, shall, required
        """
        priority = 50  # 基础分

        title_lower = title.lower()
        preview_lower = content_preview.lower()

        # 标题包含高价值关键词
        high_value_keywords = ['certificate', 'extension', 'profile', 'field', 'policy', 'constraint']
        for kw in high_value_keywords:
            if kw in title_lower:
                priority += 10

        # 内容预览包含规范性关键词
        if 'must' in preview_lower or 'shall' in preview_lower:
            priority += 20

        # 内容预览包含证书术语
        cert_terms = ['keyusage', 'basicconstraints', 'subjectalternativename', 'validity', 'issuer']
        if any(term in preview_lower for term in cert_terms):
            priority += 15

        return min(priority, 100)

    def _split_by_priority(
        self,
        text: str,
        sections: List[Dict],
        content_start: int
    ) -> List[Dict]:
        """
        按优先级切分

        策略：
        1. 高优先级章节（priority >= 70）：每个章节单独成块
        2. 中优先级章节（50-69）：合并成chunk_size大小
        3. 低优先级章节（< 50）：可选处理
        """
        chunks = []

        # 按优先级分组
        high_priority = [s for s in sections if s.get('priority', 50) >= 70]
        medium_priority = [s for s in sections if 50 <= s.get('priority', 50) < 70]

        # 处理高优先级章节
        for i, section in enumerate(high_priority):
            start = content_start + section['start']
            # 找到下一个章节的起点作为结束位置
            if i + 1 < len(high_priority):
                end = content_start + high_priority[i + 1]['start']
            else:
                end = min(start + self.chunk_size * 2, len(text))

            chunks.append({
                'text': text[start:end],
                'section': section.get('title', 'Unknown'),
                'priority': section.get('priority', 50),
                'start_pos': start,
                'type': 'high_priority'
            })

        # 处理中优先级章节（合并成标准大小）
        current_chunk = []
        current_size = 0
        current_sections = []

        for section in medium_priority:
            start = content_start + section['start']
            # 估算章节大小（到下一章节或文档末尾）
            next_section_start = self._find_next_section_start(sections, section)
            if next_section_start:
                end = content_start + next_section_start
            else:
                end = min(start + self.chunk_size, len(text))

            section_text = text[start:end]
            section_size = len(section_text)

            if current_size + section_size > self.chunk_size and current_chunk:
                # 提交当前chunk
                chunks.append({
                    'text': ''.join(current_chunk),
                    'section': ', '.join(current_sections),
                    'priority': 60,
                    'start_pos': start - current_size,
                    'type': 'medium_priority'
                })
                current_chunk = [section_text]
                current_size = section_size
                current_sections = [section.get('title', 'Unknown')]
            else:
                current_chunk.append(section_text)
                current_size += section_size
                current_sections.append(section.get('title', 'Unknown'))

        # 提交最后一个chunk
        if current_chunk:
            chunks.append({
                'text': ''.join(current_chunk),
                'section': ', '.join(current_sections),
                'priority': 60,
                'start_pos': len(text) - current_size,
                'type': 'medium_priority'
            })

        return chunks

    def _find_next_section_start(self, sections: List[Dict], current_section: Dict) -> int:
        """找到下一个章节的起始位置"""
        current_idx = sections.index(current_section)
        if current_idx + 1 < len(sections):
            return sections[current_idx + 1]['start']
        return None


# ========== 使用示例 ==========

def chunk_rfc_intelligently(text: str) -> List[Dict]:
    """
    智能切分RFC文档

    返回按优先级排序的chunks，优先处理高价值内容
    """
    chunker = ContentAwareChunker(chunk_size=10000)
    chunks = chunker.chunk_document(text, doc_type='rfc')

    # 按优先级排序（高优先级优先处理）
    chunks.sort(key=lambda x: x['priority'], reverse=True)

    return chunks
