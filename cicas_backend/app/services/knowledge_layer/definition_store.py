"""
定义存储器 (Definition Store)

职责：
1. 存储和管理术语定义
2. 支持定义检索
3. 处理定义冲突

设计原则：
- 定义来源于规范文档
- 支持多规范的定义共存
- 优先级：RFC > CABF > 其他
"""
from typing import List, Dict, Any, Optional
from dataclasses import dataclass, field
from enum import Enum

from app.core.logging_config import app_logger


class DefinitionSource(str, Enum):
    """定义来源"""
    RFC = "RFC"
    CABF = "CABF"
    ETSI = "ETSI"
    CUSTOM = "CUSTOM"


@dataclass
class Definition:
    """术语定义"""
    term: str
    definition: str
    source: DefinitionSource
    doc_id: str
    section_id: str
    aliases: List[str] = field(default_factory=list)
    priority: int = 0  # 数字越大优先级越高


class DefinitionStore:
    """
    定义存储器

    管理 PKI 相关的术语定义。
    当同一术语有多个定义时，根据优先级选择。
    """

    # 来源优先级
    SOURCE_PRIORITY = {
        DefinitionSource.RFC: 100,
        DefinitionSource.CABF: 80,
        DefinitionSource.ETSI: 60,
        DefinitionSource.CUSTOM: 40,
    }

    def __init__(self):
        """初始化定义存储器"""
        # 主存储：term -> List[Definition]
        self._definitions: Dict[str, List[Definition]] = {}

        # 别名映射：alias -> term
        self._aliases: Dict[str, str] = {}

    def add_definition(
        self,
        term: str,
        definition: str,
        source: DefinitionSource,
        doc_id: str,
        section_id: str,
        aliases: Optional[List[str]] = None
    ) -> None:
        """
        添加定义

        Args:
            term: 术语
            definition: 定义内容
            source: 来源
            doc_id: 来源文档 ID
            section_id: 来源章节 ID
            aliases: 别名列表
        """
        # 规范化术语
        normalized_term = self._normalize_term(term)

        # 计算优先级
        priority = self.SOURCE_PRIORITY.get(source, 0)

        # 创建定义对象
        defn = Definition(
            term=term,
            definition=definition,
            source=source,
            doc_id=doc_id,
            section_id=section_id,
            aliases=aliases or [],
            priority=priority,
        )

        # 添加到主存储
        if normalized_term not in self._definitions:
            self._definitions[normalized_term] = []
        self._definitions[normalized_term].append(defn)

        # 按优先级排序
        self._definitions[normalized_term].sort(
            key=lambda d: d.priority,
            reverse=True
        )

        # 添加别名映射
        for alias in (aliases or []):
            normalized_alias = self._normalize_term(alias)
            self._aliases[normalized_alias] = normalized_term

        app_logger.debug(f"添加定义: {term} (来源: {source.value})")

    def get_definition(
        self,
        term: str,
        source_filter: Optional[DefinitionSource] = None
    ) -> Optional[Definition]:
        """
        获取定义（返回优先级最高的）

        Args:
            term: 术语
            source_filter: 来源过滤器

        Returns:
            Definition 或 None
        """
        normalized_term = self._normalize_term(term)

        # 检查别名
        if normalized_term in self._aliases:
            normalized_term = self._aliases[normalized_term]

        if normalized_term not in self._definitions:
            return None

        definitions = self._definitions[normalized_term]

        if source_filter:
            definitions = [d for d in definitions if d.source == source_filter]

        return definitions[0] if definitions else None

    def get_all_definitions(self, term: str) -> List[Definition]:
        """
        获取术语的所有定义

        Args:
            term: 术语

        Returns:
            Definition 列表
        """
        normalized_term = self._normalize_term(term)

        # 检查别名
        if normalized_term in self._aliases:
            normalized_term = self._aliases[normalized_term]

        return self._definitions.get(normalized_term, [])

    def search_definitions(self, query: str) -> List[Definition]:
        """
        搜索定义

        Args:
            query: 搜索查询

        Returns:
            匹配的 Definition 列表
        """
        query_lower = query.lower()
        results = []

        for term, definitions in self._definitions.items():
            if query_lower in term:
                results.extend(definitions)
            else:
                for defn in definitions:
                    if query_lower in defn.definition.lower():
                        results.append(defn)

        # 按优先级排序
        results.sort(key=lambda d: d.priority, reverse=True)
        return results

    def has_definition(self, term: str) -> bool:
        """检查术语是否有定义"""
        normalized_term = self._normalize_term(term)

        if normalized_term in self._aliases:
            normalized_term = self._aliases[normalized_term]

        return normalized_term in self._definitions

    def get_all_terms(self) -> List[str]:
        """获取所有术语"""
        return list(self._definitions.keys())

    def export_definitions(self) -> Dict[str, Any]:
        """导出所有定义"""
        export = {}
        for term, definitions in self._definitions.items():
            export[term] = [
                {
                    "term": d.term,
                    "definition": d.definition,
                    "source": d.source.value,
                    "doc_id": d.doc_id,
                    "section_id": d.section_id,
                    "priority": d.priority,
                }
                for d in definitions
            ]
        return export

    def import_definitions(self, data: Dict[str, Any]) -> int:
        """
        导入定义

        Args:
            data: 导出的定义数据

        Returns:
            导入的定义数量
        """
        count = 0
        for term, definitions in data.items():
            for d in definitions:
                self.add_definition(
                    term=d["term"],
                    definition=d["definition"],
                    source=DefinitionSource(d["source"]),
                    doc_id=d["doc_id"],
                    section_id=d["section_id"],
                )
                count += 1
        return count

    def _normalize_term(self, term: str) -> str:
        """规范化术语"""
        return term.lower().strip()

    def get_statistics(self) -> Dict[str, Any]:
        """获取统计信息"""
        total_definitions = sum(
            len(defs) for defs in self._definitions.values()
        )

        source_counts = {}
        for definitions in self._definitions.values():
            for defn in definitions:
                source = defn.source.value
                source_counts[source] = source_counts.get(source, 0) + 1

        return {
            "total_terms": len(self._definitions),
            "total_definitions": total_definitions,
            "total_aliases": len(self._aliases),
            "by_source": source_counts,
        }
