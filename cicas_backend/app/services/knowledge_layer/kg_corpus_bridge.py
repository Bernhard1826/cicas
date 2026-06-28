"""
KG-Corpus 桥接器 (KG Corpus Bridge)

职责：
1. 连接知识图谱与语料库
2. 将文档结构映射到 KG 节点
3. 同步更新 KG 和索引

设计原则：
- KG 存储结构化知识（节点、边）
- Corpus 存储原始文本
- Bridge 负责两者的一致性
"""
from __future__ import annotations

import re
from typing import List, Dict, Any, Optional, Tuple, TYPE_CHECKING
from datetime import datetime

if TYPE_CHECKING:
    from .definition_store import DefinitionStore

from app.core.logging_config import app_logger
from .corpus_loader import Document, Section, CorpusLoader
from .corpus_indexer import CorpusIndexer


class KGCorpusBridge:
    """
    KG-Corpus 桥接器

    职责：
    1. 将文档结构同步到知识图谱
    2. 从 KG 检索时关联语料库内容
    3. 维护两者的一致性
    """

    # KG 节点类型常量
    NODE_TYPE_SPECIFICATION = "Specification"
    NODE_TYPE_SECTION = "Section"
    NODE_TYPE_DEFINITION = "Definition"
    NODE_TYPE_REQUIREMENT = "Requirement"
    NODE_TYPE_FIELD = "Field"

    # KG 边类型常量
    EDGE_TYPE_CONTAINS = "CONTAINS"
    EDGE_TYPE_DEFINES = "DEFINES"
    EDGE_TYPE_DERIVED_FROM = "DERIVED_FROM"
    EDGE_TYPE_REFERENCES = "REFERENCES"
    EDGE_TYPE_APPLIES_TO = "APPLIES_TO"
    EDGE_TYPE_OVERRIDES = "OVERRIDES"

    def __init__(
        self,
        knowledge_graph,
        corpus_loader: CorpusLoader,
        corpus_indexer: CorpusIndexer
    ):
        """
        初始化桥接器

        Args:
            knowledge_graph: 知识图谱实例
            corpus_loader: 语料库加载器
            corpus_indexer: 语料库索引器
        """
        self.kg = knowledge_graph
        self.loader = corpus_loader
        self.indexer = corpus_indexer

    def sync_document_to_kg(self, doc: Document) -> int:
        """
        将文档同步到知识图谱

        Args:
            doc: 文档对象

        Returns:
            创建的节点数量
        """
        nodes_created = 0

        # 创建规范节点
        spec_node_id = f"spec:{doc.doc_id}"
        self.kg.add_node(
            spec_node_id,
            self.NODE_TYPE_SPECIFICATION,
            {
                "doc_id": doc.doc_id,
                "title": doc.title,
                "doc_type": doc.doc_type.value,
                "version": doc.version,
            }
        )
        nodes_created += 1

        # 创建章节节点
        for section_id, section in doc.sections.items():
            section_node_id = f"section:{doc.doc_id}:{section_id}"
            self.kg.add_node(
                section_node_id,
                self.NODE_TYPE_SECTION,
                {
                    "section_id": section_id,
                    "title": section.title,
                    "level": section.level,
                    "doc_id": doc.doc_id,
                }
            )
            nodes_created += 1

            # 创建 CONTAINS 边
            self.kg.add_edge(
                spec_node_id,
                section_node_id,
                self.EDGE_TYPE_CONTAINS,
                {"order": section_id}
            )

            # 创建父子章节关系
            if section.parent_id:
                parent_node_id = f"section:{doc.doc_id}:{section.parent_id}"
                self.kg.add_edge(
                    parent_node_id,
                    section_node_id,
                    self.EDGE_TYPE_CONTAINS,
                    {"type": "subsection"}
                )

        app_logger.info(f"同步文档到 KG: {doc.doc_id} ({nodes_created} 节点)")
        return nodes_created

    def sync_definition_to_kg(
        self,
        term: str,
        definition: str,
        doc_id: str,
        section_id: str
    ) -> str:
        """
        将定义同步到知识图谱

        Args:
            term: 术语
            definition: 定义内容
            doc_id: 来源文档 ID
            section_id: 来源章节 ID

        Returns:
            定义节点 ID
        """
        def_node_id = f"def:{term.lower().replace(' ', '_')}"

        self.kg.add_node(
            def_node_id,
            self.NODE_TYPE_DEFINITION,
            {
                "term": term,
                "definition": definition,
                "source_doc": doc_id,
                "source_section": section_id,
            }
        )

        # 创建到章节的边（Section --DEFINES--> Definition，与 definition_expander 统一）
        section_node_id = f"section:{doc_id}:{section_id}"
        self.kg.add_edge(
            section_node_id,
            def_node_id,
            self.EDGE_TYPE_DEFINES,
            {"type": "definition"}
        )

        return def_node_id

    def get_section_content(
        self,
        doc_id: str,
        section_id: str
    ) -> Optional[str]:
        """
        获取章节内容

        Args:
            doc_id: 文档 ID
            section_id: 章节 ID

        Returns:
            章节内容或 None
        """
        doc = self.loader.get_document(doc_id)
        if not doc:
            return None

        section = doc.get_section(section_id)
        if not section:
            return None

        return section.content

    def get_context_for_section(
        self,
        doc_id: str,
        section_id: str,
        include_definitions: bool = True,
        max_tokens: int = 2000
    ) -> Dict[str, Any]:
        """
        获取章节的上下文（用于 LLM 提示词）

        Args:
            doc_id: 文档 ID
            section_id: 章节 ID
            include_definitions: 是否包含相关定义
            max_tokens: 最大 token 数（粗略估计）

        Returns:
            上下文字典
        """
        context = {
            "doc_id": doc_id,
            "section_id": section_id,
            "content": "",
            "definitions": [],
            "related_sections": [],
        }

        # 获取章节内容
        doc = self.loader.get_document(doc_id)
        if not doc:
            return context

        section = doc.get_section(section_id)
        if not section:
            return context

        context["content"] = section.content[:max_tokens * 4]  # 粗略估计

        # 获取相关定义
        if include_definitions:
            section_node_id = f"section:{doc_id}:{section_id}"
            neighbors = self.kg.get_neighbors(
                section_node_id,
                relation_type=self.EDGE_TYPE_DEFINES,
                direction="out"
            )

            for neighbor_id, neighbor_data in neighbors:
                if neighbor_data.get("node_type") == self.NODE_TYPE_DEFINITION:
                    props = neighbor_data.get("properties", {})
                    context["definitions"].append({
                        "term": props.get("term"),
                        "definition": props.get("definition"),
                    })

        return context

    def link_ir_to_section(
        self,
        ir_id: str,
        doc_id: str,
        section_id: str
    ) -> None:
        """
        将 IR 链接到来源章节

        Args:
            ir_id: IR 节点 ID
            doc_id: 文档 ID
            section_id: 章节 ID
        """
        section_node_id = f"section:{doc_id}:{section_id}"
        self.kg.add_edge(
            ir_id,
            section_node_id,
            self.EDGE_TYPE_DERIVED_FROM,
            {"timestamp": datetime.now().isoformat()}
        )

    def find_related_sections(
        self,
        text: str,
        max_results: int = 5
    ) -> List[Dict[str, Any]]:
        """
        查找与文本相关的章节

        Args:
            text: 搜索文本
            max_results: 最大结果数

        Returns:
            相关章节列表
        """
        results = self.indexer.search(text, max_results=max_results)

        sections = []
        for result in results:
            content = self.get_section_content(result.doc_id, result.section_id)
            sections.append({
                "doc_id": result.doc_id,
                "section_id": result.section_id,
                "score": result.score,
                "content": content[:500] if content else "",
            })

        return sections

    # ====================================================================
    # Cross-reference edge building
    # ====================================================================

    _TERM_NOISE_BLOCKLIST = frozenset({
        # Document structure words
        "note", "notes", "contents", "certificate field", "table",
        "appendix", "section", "status", "abstract", "introduction",
        "overview", "references", "description", "requirement",
        "requirements",
        # RFC 2119 keywords (not domain terms)
        "must", "shall", "should", "may", "required", "recommended",
        "optional", "must not", "shall not", "should not",
        # Ultra-generic words that match almost every section
        "certificate", "value", "subject", "format", "encoding",
        "example", "examples", "presence", "control", "generation",
        "country", "internet", "syntax", "client", "failed",
        "conversion", "information",
        # Noisy phrases from definition extraction artifacts
        "for example", "in addition", "in particular", "ca shall",
        "the ca shall", "in order", "as well",
    })

    _SECTION_CITATION_RE = re.compile(
        r'(?:Section|Sect\.|sect\.)\s+(\d+(?:\.\d+)*)'
    )

    _CERTIFICATE_FIELDS = [
        ("field:version", "version"),
        ("field:serialNumber", "serialNumber"),
        ("field:signature", "signature"),
        ("field:signatureAlgorithm", "signatureAlgorithm"),
        ("field:issuer", "issuer"),
        ("field:validity", "validity"),
        ("field:subject", "subject"),
        ("field:subjectPublicKeyInfo", "subjectPublicKeyInfo"),
        # "extensions" skipped — too generic
        ("field:extensions.basicConstraints", "basicConstraints"),
        ("field:extensions.keyUsage", "keyUsage"),
        ("field:extensions.extendedKeyUsage", "extendedKeyUsage"),
        ("field:extensions.subjectAltName", "subjectAltName"),
        ("field:extensions.certificatePolicies", "certificatePolicies"),
        ("field:extensions.cRLDistributionPoints", "cRLDistributionPoints"),
        ("field:extensions.authorityInfoAccess", "authorityInfoAccess"),
        ("field:extensions.subjectKeyIdentifier", "subjectKeyIdentifier"),
        ("field:extensions.authorityKeyIdentifier", "authorityKeyIdentifier"),
    ]

    def build_cross_reference_edges(
        self, documents: List[Document], definition_store: DefinitionStore
    ) -> int:
        """Build cross-reference REFERENCES edges between sections and
        definitions, other sections, and certificate fields."""
        term_matchers = self._build_term_matchers(definition_store)
        field_matchers = self._build_field_matchers()
        section_index = self._build_section_index(documents)

        app_logger.info(
            f"Building cross-reference edges: "
            f"{len(term_matchers)} term matchers, "
            f"{len(field_matchers)} field matchers, "
            f"{len(section_index)} documents indexed"
        )

        total = 0
        for doc in documents:
            for section_id, section in doc.sections.items():
                text = section.content
                if not text:
                    continue
                section_node_id = f"section:{doc.doc_id}:{section_id}"
                total += self._link_section_to_definitions(
                    section_node_id, doc.doc_id, section_id, text, term_matchers
                )
                total += self._link_section_to_sections(
                    section_node_id, doc.doc_id, section_id, text, section_index
                )
                total += self._link_section_to_fields(
                    section_node_id, text, field_matchers
                )

        app_logger.info(f"Cross-reference edges created: {total}")
        return total

    # --- Term matchers (Section → Definition) ---

    def _build_term_matchers(
        self, definition_store: DefinitionStore
    ) -> List[Tuple[re.Pattern, str, str]]:
        """Build regex matchers for defined terms.

        Returns:
            List of (compiled_pattern, def_node_id, term) sorted longest-first.
        """
        matchers: List[Tuple[re.Pattern, str, str]] = []
        for term in definition_store.get_all_terms():
            # term is already normalized (lowercase)
            if term in self._TERM_NOISE_BLOCKLIST:
                continue

            words = term.split()
            if len(words) == 1 and len(term) < 5:
                # Allow uppercase acronyms >= 3 chars (e.g. CRL, OCSP)
                # but exclude RFC 2119 keywords that happen to be uppercase
                _RFC2119 = {"must", "shall", "should", "may", "not"}
                if term.lower() in _RFC2119:
                    continue
                defs = definition_store.get_all_definitions(term)
                is_acronym = any(
                    d.term.isupper() and len(d.term) >= 3 for d in defs
                )
                if not is_acronym:
                    continue

            def_node_id = f"def:{term.replace(' ', '_')}"
            pattern = re.compile(
                r'\b' + re.escape(term) + r'\b', re.IGNORECASE
            )
            matchers.append((pattern, def_node_id, term))

        matchers.sort(key=lambda m: len(m[2]), reverse=True)
        return matchers

    def _link_section_to_definitions(
        self,
        section_node_id: str,
        doc_id: str,
        section_id: str,
        text: str,
        matchers: List[Tuple[re.Pattern, str, str]],
    ) -> int:
        """Create REFERENCES edges from a section to mentioned definitions.

        Cap: 15 edges per section.
        """
        text_lower = text.lower()
        count = 0
        seen: set[str] = set()

        for pattern, def_node_id, term in matchers:
            if count >= 15:
                break
            if def_node_id in seen:
                continue

            # Skip self-section (definition extracted from same section)
            node_data = self.kg.graph.nodes.get(def_node_id)
            if node_data:
                props = node_data.get("properties", {})
                if (props.get("source_doc") == doc_id
                        and props.get("source_section") == section_id):
                    continue

            # Fast pre-check before running regex
            if term not in text_lower:
                continue

            if pattern.search(text):
                if def_node_id in self.kg.graph:
                    self.kg.add_edge(
                        section_node_id,
                        def_node_id,
                        self.EDGE_TYPE_REFERENCES,
                        {"type": "term_mention", "term": term},
                    )
                    seen.add(def_node_id)
                    count += 1

        return count

    # --- Section citation matchers (Section → Section) ---

    def _build_section_index(
        self, documents: List[Document]
    ) -> Dict[str, Dict[str, str]]:
        """Build doc_id → {section_id: node_id} mapping."""
        index: Dict[str, Dict[str, str]] = {}
        for doc in documents:
            doc_sections: Dict[str, str] = {}
            for section_id in doc.sections:
                doc_sections[section_id] = f"section:{doc.doc_id}:{section_id}"
            index[doc.doc_id] = doc_sections
        return index

    def _link_section_to_sections(
        self,
        section_node_id: str,
        doc_id: str,
        section_id: str,
        text: str,
        index: Dict[str, Dict[str, str]],
    ) -> int:
        """Create REFERENCES edges from section citations (same document only).

        Cap: 10 edges per section.
        """
        doc_sections = index.get(doc_id)
        if not doc_sections:
            return 0

        matches = self._SECTION_CITATION_RE.findall(text)
        if not matches:
            return 0

        count = 0
        seen: set[str] = set()

        for cited_section_id in matches:
            if count >= 10:
                break
            if cited_section_id == section_id:
                continue
            if cited_section_id in seen:
                continue

            target_node_id = doc_sections.get(cited_section_id)
            if target_node_id and target_node_id in self.kg.graph:
                self.kg.add_edge(
                    section_node_id,
                    target_node_id,
                    self.EDGE_TYPE_REFERENCES,
                    {"type": "section_citation", "cited_section": cited_section_id},
                )
                seen.add(cited_section_id)
                count += 1

        return count

    # --- Field matchers (Section → CertificateField) ---

    @staticmethod
    def _camel_to_words(name: str) -> List[str]:
        """Split camelCase into words: 'keyUsage' → ['key', 'Usage'],
        'cRLDistributionPoints' → ['CRL', 'Distribution', 'Points']."""
        s = re.sub(r'([a-z])([A-Z])', r'\1 \2', name)
        s = re.sub(r'([A-Z]+)([A-Z][a-z])', r'\1 \2', s)
        words = s.split()
        # Merge single-char prefix with next uppercase word
        if len(words) >= 2 and len(words[0]) == 1 and words[1].isupper():
            words = [words[0].upper() + words[1]] + words[2:]
        return words

    def _build_field_matchers(self) -> List[Tuple[re.Pattern, str]]:
        """Build regex matchers for certificate field names.

        Returns:
            List of (compiled_pattern, field_node_id).
        """
        matchers: List[Tuple[re.Pattern, str]] = []
        for field_node_id, field_name in self._CERTIFICATE_FIELDS:
            if field_node_id not in self.kg.graph:
                continue

            words = self._camel_to_words(field_name)

            # Alternatives: exact camelCase + space-separated words
            alternatives = [re.escape(field_name)]
            if len(words) > 1:
                space_form = r'\s+'.join(re.escape(w) for w in words)
                alternatives.append(space_form)

            combined = '|'.join(alternatives)
            pattern = re.compile(r'\b(?:' + combined + r')\b', re.IGNORECASE)
            matchers.append((pattern, field_node_id))

        return matchers

    def _link_section_to_fields(
        self,
        section_node_id: str,
        text: str,
        matchers: List[Tuple[re.Pattern, str]],
    ) -> int:
        """Create REFERENCES edges from section to certificate fields.

        Cap: 8 edges per section.
        """
        count = 0
        seen: set[str] = set()

        for pattern, field_node_id in matchers:
            if count >= 8:
                break
            if field_node_id in seen:
                continue

            if pattern.search(text):
                self.kg.add_edge(
                    section_node_id,
                    field_node_id,
                    self.EDGE_TYPE_REFERENCES,
                    {"type": "field_mention"},
                )
                seen.add(field_node_id)
                count += 1

        return count
