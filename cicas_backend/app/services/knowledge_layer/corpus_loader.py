"""
语料库加载器 (Corpus Loader)

职责：
1. 加载 RFC/CABF/ETSI 文档
2. 解析文档结构（章节、段落）
3. 提供统一的文档访问接口

设计原则：
- 系统启动时加载语料库
- 支持增量加载新文档
- 文档结构化存储
"""
import os
import re
from typing import List, Dict, Any, Optional, Iterator
from dataclasses import dataclass, field
from pathlib import Path
from datetime import datetime
from enum import Enum

from app.core.logging_config import app_logger


class DocumentType(str, Enum):
    """文档类型"""
    RFC = "RFC"
    CABF_BR = "CABF_BR"          # Baseline Requirements
    CABF_EVG = "CABF_EVG"        # EV Guidelines
    CABF_SMIME = "CABF_SMIME"    # S/MIME BR
    ETSI = "ETSI"
    MOZILLA = "Mozilla"
    OTHER = "Other"


@dataclass
class Section:
    """文档章节"""
    section_id: str            # 如 "4.2.1"
    title: str
    content: str
    level: int                 # 章节层级（1, 2, 3...）
    parent_id: Optional[str] = None
    children: List[str] = field(default_factory=list)
    line_start: Optional[int] = None
    line_end: Optional[int] = None


@dataclass
class Document:
    """规范文档"""
    doc_id: str               # 如 "RFC5280"
    doc_type: DocumentType
    title: str
    version: Optional[str] = None
    effective_date: Optional[datetime] = None
    sections: Dict[str, Section] = field(default_factory=dict)
    raw_text: str = ""
    metadata: Dict[str, Any] = field(default_factory=dict)
    file_path: Optional[str] = None

    def get_section(self, section_id: str) -> Optional[Section]:
        """获取章节"""
        return self.sections.get(section_id)

    def get_all_sections(self) -> List[Section]:
        """获取所有章节"""
        return list(self.sections.values())

    def iter_sections(self, min_level: int = 1, max_level: int = 10) -> Iterator[Section]:
        """迭代章节"""
        for section in self.sections.values():
            if min_level <= section.level <= max_level:
                yield section


class CorpusLoader:
    """
    语料库加载器

    职责：
    1. 加载规范文档
    2. 解析文档结构
    3. 管理文档集合
    """

    # RFC 章节模式
    RFC_SECTION_PATTERN = re.compile(
        r'^(\d+(?:\.\d+)*)\s+(.+)$',
        re.MULTILINE
    )

    # CABF 章节模式
    CABF_SECTION_PATTERN = re.compile(
        r'^(\d+(?:\.\d+)*)\s+(.+)$',
        re.MULTILINE
    )

    def __init__(self, data_dir: Optional[str] = None):
        """
        初始化语料库加载器

        Args:
            data_dir: 数据目录路径
        """
        self.data_dir = Path(data_dir) if data_dir else None
        self.documents: Dict[str, Document] = {}

    def load_document(
        self,
        file_path: str,
        doc_type: Optional[DocumentType] = None
    ) -> Optional[Document]:
        """
        加载单个文档

        Args:
            file_path: 文件路径
            doc_type: 文档类型（如果不提供，将自动检测）

        Returns:
            Document 或 None
        """
        path = Path(file_path)
        if not path.exists():
            app_logger.error(f"文件不存在: {file_path}")
            return None

        # 读取文件内容
        try:
            with open(path, 'r', encoding='utf-8') as f:
                raw_text = f.read()
        except Exception as e:
            app_logger.error(f"读取文件失败: {e}")
            return None

        # 自动检测文档类型
        if doc_type is None:
            doc_type = self._detect_document_type(path.name, raw_text)

        # 提取文档 ID
        doc_id = self._extract_doc_id(path.name, raw_text, doc_type)

        # 解析文档结构
        sections = self._parse_sections(raw_text, doc_type)

        # 提取标题
        title = self._extract_title(raw_text, doc_type)

        # 创建文档对象
        doc = Document(
            doc_id=doc_id,
            doc_type=doc_type,
            title=title,
            sections=sections,
            raw_text=raw_text,
            file_path=str(path),
        )

        # 缓存文档
        self.documents[doc_id] = doc

        app_logger.info(f"加载文档: {doc_id} ({len(sections)} 章节)")
        return doc

    def load_directory(
        self,
        dir_path: str,
        recursive: bool = True
    ) -> List[Document]:
        """
        加载目录下的所有文档

        Args:
            dir_path: 目录路径
            recursive: 是否递归加载子目录

        Returns:
            Document 列表
        """
        path = Path(dir_path)
        if not path.exists() or not path.is_dir():
            app_logger.error(f"目录不存在: {dir_path}")
            return []

        documents = []
        pattern = "**/*" if recursive else "*"

        for file_path in path.glob(pattern):
            if file_path.is_file() and file_path.suffix in ['.txt', '.md', '.rst', '.html']:
                doc = self.load_document(str(file_path))
                if doc:
                    documents.append(doc)

        app_logger.info(f"从目录加载 {len(documents)} 个文档: {dir_path}")
        return documents

    def get_document(self, doc_id: str) -> Optional[Document]:
        """获取已加载的文档"""
        return self.documents.get(doc_id)

    def get_all_documents(self) -> List[Document]:
        """获取所有已加载的文档"""
        return list(self.documents.values())

    def _detect_document_type(self, filename: str, content: str) -> DocumentType:
        """检测文档类型"""
        filename_lower = filename.lower()
        content_lower = content[:2000].lower()  # 只检查开头部分

        if 'rfc' in filename_lower or 'rfc' in content_lower:
            return DocumentType.RFC
        elif 'baseline' in filename_lower or 'baseline requirements' in content_lower:
            return DocumentType.CABF_BR
        elif 'ev' in filename_lower or 'extended validation' in content_lower:
            return DocumentType.CABF_EVG
        elif 'smime' in filename_lower or 's/mime' in content_lower:
            return DocumentType.CABF_SMIME
        elif 'etsi' in filename_lower or 'etsi' in content_lower:
            return DocumentType.ETSI
        elif 'mozilla' in filename_lower or 'mozilla' in content_lower:
            return DocumentType.MOZILLA
        else:
            return DocumentType.OTHER

    def _extract_doc_id(self, filename: str, content: str, doc_type: Optional[DocumentType] = None) -> str:
        """提取文档 ID

        For CABF/RFC documents the id must be the CANONICAL spec id the rest of
        the system keys on (rule.source / GraphRAG section nodes `section:<id>:<sec>`),
        not the raw filename stem. e.g. BR.md -> "CABF-BR" (so GraphRAG can resolve
        `section:CABF-BR:7.1.2.x`), not "BR".
        """
        # Canonical ids by document type (align with rules.source / KG node ids)
        canonical = {
            DocumentType.CABF_BR: "CABF-BR",
            DocumentType.CABF_EVG: "CABF-EV",
            DocumentType.CABF_SMIME: "CABF-SMIME",
        }
        if doc_type in canonical:
            return canonical[doc_type]

        # 尝试从文件名提取
        rfc_match = re.search(r'rfc(\d+)', filename, re.IGNORECASE)
        if rfc_match:
            return f"RFC{rfc_match.group(1)}"

        # 尝试从内容提取
        rfc_match = re.search(r'RFC\s*(\d+)', content[:1000])
        if rfc_match:
            return f"RFC{rfc_match.group(1)}"

        # 使用文件名作为 ID
        return Path(filename).stem.upper()

    def _extract_title(self, content: str, doc_type: DocumentType) -> str:
        """提取文档标题"""
        lines = content.split('\n')[:50]

        for line in lines:
            line = line.strip()
            # 跳过空行和短行
            if len(line) < 10:
                continue
            # 跳过数字开头的行（可能是章节号）
            if line[0].isdigit():
                continue
            # 返回第一个看起来像标题的行
            if len(line) < 200:
                return line

        return "Unknown Title"

    def _parse_sections(
        self,
        content: str,
        doc_type: DocumentType
    ) -> Dict[str, Section]:
        """解析文档章节"""
        sections = {}

        if doc_type == DocumentType.RFC:
            sections = self._parse_rfc_sections(content)
        elif doc_type in [DocumentType.CABF_BR, DocumentType.CABF_EVG, DocumentType.CABF_SMIME]:
            sections = self._parse_cabf_sections(content)
        else:
            sections = self._parse_generic_sections(content)

        return sections

    def _parse_rfc_sections(self, content: str) -> Dict[str, Section]:
        """解析 RFC 文档章节"""
        sections = {}
        lines = content.split('\n')
        current_section_id = None
        current_content = []
        current_title = ""
        current_line_start = 0

        for i, line in enumerate(lines):
            # 检测章节标题
            match = re.match(r'^(\d+(?:\.\d+)*)\.\s+(.+)$', line.strip())
            if match:
                # 保存前一个章节
                if current_section_id:
                    sections[current_section_id] = Section(
                        section_id=current_section_id,
                        title=current_title,
                        content='\n'.join(current_content),
                        level=current_section_id.count('.') + 1,
                        line_start=current_line_start,
                        line_end=i - 1,
                    )

                # 开始新章节
                current_section_id = match.group(1)
                current_title = match.group(2)
                current_content = []
                current_line_start = i
            else:
                current_content.append(line)

        # 保存最后一个章节
        if current_section_id:
            sections[current_section_id] = Section(
                section_id=current_section_id,
                title=current_title,
                content='\n'.join(current_content),
                level=current_section_id.count('.') + 1,
                line_start=current_line_start,
                line_end=len(lines) - 1,
            )

        return sections

    def _parse_cabf_sections(self, content: str) -> Dict[str, Section]:
        """解析 CABF 文档章节。

        CABF BR.md 使用 Markdown ATX 标题（如 `#### 7.1.2.1 Root CA Certificate
        Profile` / `##### 7.1.2.1.3 ...`），其中章节号嵌在标题文本里、号后无点。
        旧实现复用 RFC 解析（要求行首是带点的数字，如 "7.1.2.1. "），完全匹配不到这些
        标题（只剩 16 个杂项段），导致 KG 没有 7.1.2.x 节点、GraphRAG 无法解析
        CABF 引用。优先按 Markdown 标题解析；若文档没有 Markdown 标题再回退。
        """
        if re.search(r'(?m)^#{1,6}\s+\d', content):
            return self._parse_markdown_sections(content)
        return self._parse_rfc_sections(content)

    def _parse_markdown_sections(self, content: str) -> Dict[str, Section]:
        """解析 Markdown ATX 标题，章节号嵌在标题文本里：
        `#### 7.1.2.1 Title` / `# 1. INTRODUCTION` (号后点号可选)。"""
        sections: Dict[str, Section] = {}
        lines = content.split('\n')
        # `#`+ 空格 + 章节号(7.1.2.1) + 可选点 + 空格 + 标题
        header = re.compile(r'^#{1,6}\s+(\d+(?:\.\d+)*)\.?\s+(.+?)\s*$')
        cur_id = None
        cur_title = ""
        cur_content: List[str] = []
        cur_start = 0
        for i, line in enumerate(lines):
            m = header.match(line)
            if m:
                if cur_id:
                    sections[cur_id] = Section(
                        section_id=cur_id, title=cur_title,
                        content='\n'.join(cur_content),
                        level=cur_id.count('.') + 1,
                        line_start=cur_start, line_end=i - 1,
                    )
                cur_id = m.group(1)
                cur_title = m.group(2)
                cur_content = []
                cur_start = i
            else:
                cur_content.append(line)
        if cur_id:
            sections[cur_id] = Section(
                section_id=cur_id, title=cur_title,
                content='\n'.join(cur_content),
                level=cur_id.count('.') + 1,
                line_start=cur_start, line_end=len(lines) - 1,
            )
        return sections

    def _parse_generic_sections(self, content: str) -> Dict[str, Section]:
        """解析通用格式章节"""
        sections = {}

        # 简单分段：按空行分割
        paragraphs = re.split(r'\n\s*\n', content)

        for i, para in enumerate(paragraphs):
            if para.strip():
                section_id = str(i + 1)
                sections[section_id] = Section(
                    section_id=section_id,
                    title=f"Paragraph {i + 1}",
                    content=para.strip(),
                    level=1,
                )

        return sections
