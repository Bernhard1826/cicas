"""
语料库索引器 (Corpus Indexer)

职责：
1. 为文档建立索引
2. 支持快速检索
3. 管理索引版本

设计原则：
- 索引与文档分离
- 支持增量更新
- 多种索引类型（关键词、向量等）
"""
from typing import List, Dict, Any, Optional, Set
from dataclasses import dataclass, field
from collections import defaultdict
import re

from app.core.logging_config import app_logger
from .corpus_loader import Document, Section


@dataclass
class IndexEntry:
    """索引条目"""
    term: str
    doc_id: str
    section_id: str
    frequency: int = 1
    positions: List[int] = field(default_factory=list)


@dataclass
class SearchResult:
    """搜索结果"""
    doc_id: str
    section_id: str
    score: float
    snippet: str = ""
    metadata: Dict[str, Any] = field(default_factory=dict)


class CorpusIndexer:
    """
    语料库索引器

    提供多种索引类型：
    1. 倒排索引（关键词 → 文档/章节）
    2. 术语索引（定义术语 → 定义位置）
    3. 引用索引（引用 → 被引用位置）
    """

    # 停用词
    STOP_WORDS = {
        'the', 'a', 'an', 'and', 'or', 'but', 'in', 'on', 'at', 'to', 'for',
        'of', 'with', 'by', 'from', 'as', 'is', 'was', 'are', 'were', 'been',
        'be', 'have', 'has', 'had', 'do', 'does', 'did', 'will', 'would',
        'could', 'should', 'may', 'might', 'can', 'this', 'that', 'these',
        'those', 'it', 'its', 'if', 'when', 'where', 'which', 'who', 'what',
    }

    def __init__(self):
        """初始化索引器"""
        # 倒排索引：term → [(doc_id, section_id, frequency), ...]
        self.inverted_index: Dict[str, List[IndexEntry]] = defaultdict(list)

        # 术语索引：term → definition location
        self.term_index: Dict[str, List[Dict[str, Any]]] = defaultdict(list)

        # 引用索引：doc_id → [(referencing_doc, section), ...]
        self.reference_index: Dict[str, List[Dict[str, Any]]] = defaultdict(list)

        # 已索引文档集合
        self.indexed_docs: Set[str] = set()

    def index_document(self, doc: Document) -> int:
        """
        索引单个文档

        Args:
            doc: 文档对象

        Returns:
            索引的术语数量
        """
        if doc.doc_id in self.indexed_docs:
            app_logger.warning(f"文档已索引: {doc.doc_id}，跳过")
            return 0

        term_count = 0

        # 索引每个章节
        for section_id, section in doc.sections.items():
            term_count += self._index_section(doc.doc_id, section)

        # 索引引用
        self._index_references(doc)

        # 索引术语定义
        self._index_definitions(doc)

        self.indexed_docs.add(doc.doc_id)
        app_logger.info(f"索引文档: {doc.doc_id} ({term_count} 术语)")

        return term_count

    def _index_section(self, doc_id: str, section: Section) -> int:
        """索引章节"""
        # 提取词项
        words = self._tokenize(section.content)

        # 统计词频
        word_freq = defaultdict(int)
        for word in words:
            word_freq[word] += 1

        # 添加到倒排索引
        for word, freq in word_freq.items():
            entry = IndexEntry(
                term=word,
                doc_id=doc_id,
                section_id=section.section_id,
                frequency=freq,
            )
            self.inverted_index[word].append(entry)

        return len(word_freq)

    def _index_references(self, doc: Document) -> None:
        """索引引用关系"""
        # 查找对其他文档的引用
        patterns = [
            r'RFC\s*(\d+)',           # RFC references
            r'Section\s+(\d+(?:\.\d+)*)',  # Section references
            r'\[([A-Z]+\d+)\]',       # Bracket references like [RFC5280]
        ]

        for section in doc.sections.values():
            for pattern in patterns:
                matches = re.findall(pattern, section.content)
                for match in matches:
                    ref_id = f"RFC{match}" if match.isdigit() else match
                    self.reference_index[ref_id].append({
                        "referencing_doc": doc.doc_id,
                        "section": section.section_id,
                    })

    def _index_definitions(self, doc: Document) -> None:
        """索引术语定义"""
        # 查找定义模式
        patterns = [
            r'"([^"]+)"\s+(?:means|refers to|is defined as)',
            r'([A-Z][a-z]+(?:\s+[A-Z][a-z]+)*)\s*:\s+',
            r'Definition:\s*([^\n]+)',
        ]

        for section in doc.sections.values():
            for pattern in patterns:
                matches = re.findall(pattern, section.content)
                for term in matches:
                    self.term_index[term.lower()].append({
                        "doc_id": doc.doc_id,
                        "section_id": section.section_id,
                        "term": term,
                    })

    def _tokenize(self, text: str) -> List[str]:
        """分词"""
        # 转小写
        text = text.lower()

        # 提取单词
        words = re.findall(r'\b[a-z]+\b', text)

        # 过滤停用词和短词
        words = [w for w in words if w not in self.STOP_WORDS and len(w) > 2]

        return words

    def search(
        self,
        query: str,
        max_results: int = 10,
        doc_filter: Optional[Set[str]] = None
    ) -> List[SearchResult]:
        """
        搜索

        Args:
            query: 搜索查询
            max_results: 最大结果数
            doc_filter: 文档过滤器（只在这些文档中搜索）

        Returns:
            SearchResult 列表
        """
        # 分词
        query_terms = self._tokenize(query)

        if not query_terms:
            return []

        # 收集匹配结果
        doc_section_scores: Dict[tuple, float] = defaultdict(float)

        for term in query_terms:
            if term in self.inverted_index:
                for entry in self.inverted_index[term]:
                    # 应用文档过滤器
                    if doc_filter and entry.doc_id not in doc_filter:
                        continue

                    key = (entry.doc_id, entry.section_id)
                    # TF-IDF 简化版：使用词频
                    doc_section_scores[key] += entry.frequency

        # 排序
        sorted_results = sorted(
            doc_section_scores.items(),
            key=lambda x: x[1],
            reverse=True
        )[:max_results]

        # 构建结果
        results = []
        for (doc_id, section_id), score in sorted_results:
            results.append(SearchResult(
                doc_id=doc_id,
                section_id=section_id,
                score=score,
            ))

        return results

    def find_definitions(self, term: str) -> List[Dict[str, Any]]:
        """查找术语定义"""
        return self.term_index.get(term.lower(), [])

    def find_references_to(self, doc_id: str) -> List[Dict[str, Any]]:
        """查找引用指定文档的位置"""
        return self.reference_index.get(doc_id, [])

    def get_statistics(self) -> Dict[str, Any]:
        """获取索引统计信息"""
        return {
            "indexed_documents": len(self.indexed_docs),
            "total_terms": len(self.inverted_index),
            "total_definitions": sum(len(v) for v in self.term_index.values()),
            "total_references": sum(len(v) for v in self.reference_index.values()),
        }
