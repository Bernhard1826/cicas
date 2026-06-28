"""
动态上下文构建器
为每条规则骨架构建适当的上下文，用于 LLM 理解

设计原则：
- 上下文扩展必须是纵向的（单条规则的上下文）
- 禁止横向合并多条规则的上下文
- 动态扩展基于特征触发（条件、指代、列表、引用）
- 动态batch size基于模型上下文窗口
- GraphRAG 集成：基于知识图谱提供语义上下文
"""
import re
from typing import List, Dict, Any, Optional, Tuple
from dataclasses import dataclass
from app.services.extraction.rule_discovery import RuleSkeleton
from app.services.extraction.section_topics import section_topics_kb
from app.services.extraction.field_resolver import get_field_resolver
from app.core.logging_config import app_logger
from app.core.config import settings


@dataclass
class RuleContext:
    """规则上下文"""
    skeleton: RuleSkeleton              # 原始规则骨架
    base_context: Dict[str, Any]        # 基础上下文
    extended_context: Dict[str, Any]    # 扩展上下文
    complexity_score: int               # 复杂度评分（用于 batch 调度）


class ContextBuilder:
    """
    动态上下文构建器

    职责：
    1. 为每条规则骨架构建基础上下文
    2. 基于特征动态扩展上下文
    3. 计算规则复杂度评分
    """

    # 特征检测模式
    CONDITION_PATTERNS = [
        r'\bif\b', r'\bunless\b', r'\bexcept\b',
        r'\bonly if\b', r'\bwhen\b', r'\bwhere\b'
    ]

    PRONOUN_PATTERNS = [
        r'\bthis\b', r'\bthese\b', r'\bthose\b', r'\bsuch\b',
        r'\babove\b', r'\bbelow\b', r'\bpreceding\b', r'\bfollowing\b'
    ]

    REFERENCE_PATTERNS = [
        r'\b(?:Section|Appendix|Chapter)\s+\d+(?:\.\d+)*\b',
        r'\bRFC\s*\d+\b',
        r'\b(?:see|refer to|as defined in|according to)\s+'
    ]

    LIST_MARKERS = [
        r'^\s*[\*\-\+]\s+',              # - item, * item, + item
        r'^\s*\([a-z]\)\s+',             # (a) item
        r'^\s*[a-z]\)\s+',               # a) item
        r'^\s*\d+\)\s+',                 # 1) item
    ]

    def __init__(self, document_text: str, document_id: str = "unknown", standard: str = None):
        """
        初始化上下文构建器

        Args:
            document_text: 完整文档文本
            document_id: 文档标识
            standard: 标准名称（如 "RFC5280"），用于查询 section topics 知识库
        """
        self.document_text = document_text
        self.document_id = document_id
        self.standard = standard

        # 从配置读取模型的上下文窗口
        self.context_window = settings.llm_context_window

        # 计算batch的输入token预算（60%用于输入上下文，30%输出，10%系统prompt）
        self.max_tokens_per_batch = int(self.context_window * 0.6)

        # 预处理：按句子索引构建查找表
        self.sentences = self._split_into_sentences(document_text)

        # 编译正则模式
        self.condition_regex = [re.compile(p, re.IGNORECASE) for p in self.CONDITION_PATTERNS]
        self.pronoun_regex = [re.compile(p, re.IGNORECASE) for p in self.PRONOUN_PATTERNS]
        self.reference_regex = [re.compile(p, re.IGNORECASE) for p in self.REFERENCE_PATTERNS]
        self.list_regex = [re.compile(p, re.MULTILINE) for p in self.LIST_MARKERS]

        app_logger.info(
            f"[ContextBuilder] Initialized with {len(self.sentences)} sentences, "
            f"context_window={self.context_window}, max_batch_tokens={self.max_tokens_per_batch}, "
            f"standard={standard}"
        )

    def build_context(self, skeleton: RuleSkeleton) -> RuleContext:
        """
        为规则骨架构建上下文

        Args:
            skeleton: 规则骨架

        Returns:
            规则上下文
        """
        # 1. 构建基础上下文
        base_context = self._build_base_context(skeleton)

        # 2. 动态扩展上下文
        extended_context = self._build_extended_context(skeleton)

        # 3. 计算复杂度评分
        complexity_score = self._calculate_complexity(skeleton, extended_context)

        return RuleContext(
            skeleton=skeleton,
            base_context=base_context,
            extended_context=extended_context,
            complexity_score=complexity_score
        )

    def _build_base_context(self, skeleton: RuleSkeleton) -> Dict[str, Any]:
        """
        构建基础上下文（必选）

        包含：
        - 原始句子
        - section 标题
        - section 层级路径
        - Enhanced IR: keyword_source, parent_rule_id, scope_block_id
        """
        base_context = {
            'sentence': skeleton.sentence,
            'section': skeleton.section,
            'section_title': skeleton.section_title,
            'section_path': self._get_section_path(skeleton.section),
            'keyword': skeleton.keyword,
            'document_id': self.document_id,
        }

        # Enhanced IR Extraction: Add scope inheritance info
        if hasattr(skeleton, 'keyword_source'):
            base_context['keyword_source'] = skeleton.keyword_source
        if hasattr(skeleton, 'parent_rule_id') and skeleton.parent_rule_id:
            base_context['parent_rule_id'] = skeleton.parent_rule_id
        if hasattr(skeleton, 'scope_block_id') and skeleton.scope_block_id:
            base_context['scope_block_id'] = skeleton.scope_block_id
        if hasattr(skeleton, 'pattern_type') and skeleton.pattern_type:
            base_context['pattern_type'] = skeleton.pattern_type

        return base_context

    def _build_extended_context(self, skeleton: RuleSkeleton) -> Dict[str, Any]:
        """
        动态扩展上下文（按需）

        特征触发规则：
        - 所有规则 → 基础上下文（周围句子）
        - 条件词 → 前后 ±2-3 句（扩展）
        - 指代词 → 向前扩展（简化：±3 句）
        - 列表 → 段落上下文
        - 引用 → 记录引用信息（实际解析由后续阶段处理）
        - Enhanced IR: 继承关键词 → 父规则上下文
        """
        extended = {}
        sentence = skeleton.sentence
        sent_idx = skeleton.sentence_index

        # 0. 为所有规则生成基础通用上下文（NEW！）
        # 这确保即使没有特殊特征（条件词、指代等）的规则也有上下文信息
        general_context = self._build_general_context(skeleton)
        if general_context:
            extended['general_context'] = general_context

        # 0.5 Enhanced IR: 为继承关键词的规则添加父规则上下文
        scope_context = self._build_scope_block_context(skeleton)
        if scope_context:
            extended['scope_block_context'] = scope_context
            extended['has_inherited_keyword'] = True

        # 1. 提取 section 主题
        section_topic = self._extract_section_topic(
            skeleton.section_title,
            skeleton.section
        )
        if section_topic:
            extended['section_topic'] = section_topic

        # 1.5 提取 canonical subject（Fix #5: Subject 漂移修复）
        canonical_subject = self._get_canonical_subject(skeleton.section)
        if canonical_subject:
            extended['canonical_subject'] = canonical_subject

        # 2. 检测条件
        if self._has_condition(sentence):
            extended['condition_context'] = self._get_surrounding_sentences(
                sent_idx, window=3
            )
            extended['has_condition'] = True

        # 3. 检测指代
        if self._has_pronoun(sentence):
            extended['pronoun_context'] = self._get_surrounding_sentences(
                sent_idx, window=3, direction='before'
            )
            extended['has_pronoun'] = True

        # 4. 检测列表
        if self._is_in_list(skeleton):
            extended['list_context'] = skeleton.paragraph_text
            extended['is_in_list'] = True

        # 5. 检测引用
        if self._has_reference(sentence):
            extended['reference_markers'] = self._extract_references(sentence)
            extended['has_reference'] = True

        # 6. GraphRAG 上下文
        if self.standard:
            graphrag_context = self._build_graphrag_context(skeleton)
            if graphrag_context:
                extended['graphrag_context'] = graphrag_context

        return extended

    def _build_scope_block_context(self, skeleton: RuleSkeleton) -> Optional[str]:
        """
        为 scope block 中的规则构建父级上下文。

        适用于：
        - keyword_source = inherited 的 child assertion
        - 有 direct keyword 但属于同一个 scope block 的 child assertion
        """
        scope_block_id = getattr(skeleton, 'scope_block_id', None)
        if not scope_block_id:
            return None

        context_parts = []
        keyword_source = getattr(skeleton, 'keyword_source', 'direct')

        parent_rule_id = getattr(skeleton, 'parent_rule_id', None)
        if parent_rule_id:
            context_parts.append(f"[Parent rule: {parent_rule_id}]")

        context_parts.append(f"[Scope block: {scope_block_id}]")
        context_parts.append(f"[Keyword source: {keyword_source}]")

        if skeleton.paragraph_text:
            context_parts.append(f"Parent context: {skeleton.paragraph_text[:400]}")

        if keyword_source == 'inherited':
            context_parts.append(
                f"Note: This rule inherits '{skeleton.keyword}' obligation from its parent sentence. "
                f"The keyword_source is 'inherited', meaning the obligation level comes from the parent rule."
            )
        else:
            context_parts.append(
                "Note: This rule is a child assertion inside a scoped clarification/modification block. "
                "Interpret it using the parent context instead of treating it as a standalone certificate rule."
            )

        return " | ".join(context_parts)

    def _build_general_context(self, skeleton: RuleSkeleton) -> Optional[str]:
        """
        为所有规则构建通用基础上下文

        策略：
        1. 优先使用章节标题作为上下文前缀
        2. 如果可用，添加周围1-2句话作为额外上下文
        3. 如果章节有段落文本，使用段落片段

        Args:
            skeleton: 规则骨架

        Returns:
            通用上下文字符串，如果无法生成则返回 None
        """
        context_parts = []

        # Part 1: 章节标题（提供主题上下文）
        if skeleton.section_title:
            context_parts.append(f"[Section: {skeleton.section_title}]")

        # Part 2: 段落上下文（如果可用）
        if skeleton.paragraph_text:
            # 保留完整的段落上下文（不截断）
            paragraph_preview = skeleton.paragraph_text.strip()
            if paragraph_preview and paragraph_preview != skeleton.sentence.strip():
                context_parts.append(f"Context: {paragraph_preview}")

        # Part 3: 周围句子（如果可用）
        sent_idx = skeleton.sentence_index
        if sent_idx is not None and sent_idx >= 0:
            surrounding = self._get_surrounding_sentences(sent_idx, window=1, direction='before')
            if surrounding and len(surrounding) > 20:  # 至少有一些有意义的内容
                # 保留完整的周围句子（不截断）
                context_parts.append(f"Previous: {surrounding}")

        # 合并上下文
        if context_parts:
            return " ".join(context_parts)

        return None

    def _build_graphrag_context(self, skeleton: RuleSkeleton) -> Optional[str]:
        """
        使用 GraphRAG 构建语义上下文

        由于 KG 中 Section 节点没有直接边连接到 Definition/Field 节点，
        我们使用基于 section_topic 的查找策略：
        1. 从 section_topic 获取相关的证书字段
        2. 从 DefinitionStore 查找相关定义
        3. 组装最小上下文

        Args:
            skeleton: 规则骨架

        Returns:
            格式化的 GraphRAG 上下文字符串，如果无法提取则返回 None
        """
        try:
            section = skeleton.section
            if not section:
                return None

            # 获取 section_topic（如 keyUsage, basicConstraints 等）
            section_topic = self._extract_section_topic(
                skeleton.section_title,
                skeleton.section
            )

            from app.services.knowledge_layer import get_knowledge_graph, get_definition_store
            from app.services.graph_retrieval.context_assembler import MinimalContext

            kg = get_knowledge_graph()
            definition_store = get_definition_store()

            context = MinimalContext()
            context.spec_family = "RFC" if self.standard.startswith("RFC") else "Other"
            context.spec_id = self.standard
            context.section_id = section

            # 1. 查找相关的证书字段（基于 section_topic）
            if section_topic and kg:
                # 处理复杂的 section_topic 格式
                # 例如 "extensions.subjectAltName.dNSName" -> ["subjectAltName", "dNSName"]
                topic_parts = section_topic.split('.')

                # 构建可能的字段节点 ID（尝试多种变体）
                field_candidates = []

                # 1. 完整路径
                field_candidates.append(f"field:extensions.{section_topic}")
                field_candidates.append(f"field:{section_topic}")

                # 2. 提取核心字段名（跳过 "extensions" 前缀）
                for part in topic_parts:
                    if part != 'extensions' and len(part) > 2:
                        field_candidates.append(f"field:extensions.{part}")
                        field_candidates.append(f"field:{part}")

                for field_id in field_candidates:
                    node_data = kg.get_node(field_id)
                    if node_data and node_data.get('node_type') == 'CertificateField':
                        props = node_data.get('properties', {})
                        field_name = props.get('name', section_topic)
                        field_desc = props.get('description', '')
                        if not field_desc:
                            # 如果没有描述，使用节点 ID 作为描述
                            field_desc = f"Certificate field related to {field_name}"
                        context.fields.append({
                            'name': field_name,
                            'description': field_desc[:200]
                        })
                        break

            # 2. 从 DefinitionStore 查找相关定义
            if section_topic and definition_store:
                # 搜索与 section_topic 的每个部分相关的定义
                search_terms = set()
                search_terms.add(section_topic)
                for part in section_topic.split('.'):
                    if part != 'extensions' and len(part) > 2:
                        search_terms.add(part)

                seen_terms = set()
                for search_term in search_terms:
                    related_definitions = definition_store.search_definitions(search_term)
                    for defn in related_definitions[:2]:
                        if defn.term.lower() not in seen_terms:
                            context.definitions.append({
                                'term': defn.term,
                                'definition': defn.definition[:200]
                            })
                            seen_terms.add(defn.term.lower())
                    if len(context.definitions) >= 3:
                        break

            # 3. 如果还没有找到任何字段或定义，尝试从 section_title 提取
            if not context.fields and not context.definitions and skeleton.section_title:
                # 从 section_title 提取关键词
                title_words = skeleton.section_title.split()
                for word in title_words:
                    if len(word) > 3 and definition_store:
                        definitions = definition_store.search_definitions(word)
                        for defn in definitions[:2]:
                            if defn.term.lower() not in [d['term'].lower() for d in context.definitions]:
                                context.definitions.append({
                                    'term': defn.term,
                                    'definition': defn.definition[:200]
                                })
                        if len(context.definitions) >= 3:
                            break

            # 只有当找到了有意义的上下文时才返回
            if context.definitions or context.fields:
                return context.to_prompt_string()

            return None

        except Exception as e:
            app_logger.debug(f"[ContextBuilder] GraphRAG failed for section {skeleton.section}: {e}")
            return None

    def _extract_section_topic(
        self,
        section_title: Optional[str],
        section: Optional[str]
    ) -> Optional[str]:
        """
        从 section 标题中提取主题关键词

        提取策略（优先级从高到低）：
        1. 查询 Section Topics 知识库（高置信度）
        2. 使用正则模式识别 X.509 字段名
        3. 识别 extension 名称
        4. 识别其他 PKI 概念

        Args:
            section_title: Section 标题（如 "4.2.1.6 Subject Alternative Name"）
            section: Section 号（如 "4.2.1.6"）

        Examples:
            "4.2.1.6 Subject Alternative Name" → "subjectAltName"
            "4.2.1.3 Key Usage" → "keyUsage"
            "4.1.2.5 Validity" → "validity"

        Returns:
            规范化的字段/主题名称，如果无法识别则返回 None
        """
        if not section_title:
            return None

        # ===== 策略1: 查询知识库（最高优先级）=====
        if self.standard and section:
            # 先尝试获取默认 affected_field
            default_field = section_topics_kb.get_default_affected_field(self.standard, section)
            if default_field:
                app_logger.debug(
                    f"[ContextBuilder] Found default_affected_field from KB: "
                    f"{self.standard} {section} → {default_field}"
                )
                return default_field

            # 如果没有默认字段，尝试获取主要主题列表
            primary_topics = section_topics_kb.get_primary_topics(self.standard, section)
            if primary_topics:
                # 返回第一个主要主题
                topic = primary_topics[0]
                app_logger.debug(
                    f"[ContextBuilder] Found primary_topics from KB: "
                    f"{self.standard} {section} → {topic}"
                )
                return topic

        # ===== 策略2: 正则模式提取（回退策略）=====
        # 移除章节号，只保留标题文本
        # 例如: "4.2.1.6 Subject Alternative Name" → "Subject Alternative Name"
        title_text = re.sub(r'^\d+(?:\.\d+)*\s+', '', section_title).strip()

        if not title_text:
            return None

        # 定义字段名模式（优先级从高到低）
        # 1. X.509 GeneralName 类型（SubjectAltName 中的具体类型）
        general_name_patterns = {
            r'\bdNSName\b': 'dNSName',
            r'\biPAddress\b': 'iPAddress',
            r'\brfc822Name\b': 'rfc822Name',
            r'\buniformResourceIdentifier\b': 'uniformResourceIdentifier',
            r'\bdirectoryName\b': 'directoryName',
            r'\bregisteredID\b': 'registeredID',
            r'\botherName\b': 'otherName',
        }

        for pattern, field_name in general_name_patterns.items():
            if re.search(pattern, title_text, re.IGNORECASE):
                return field_name

        # 2. X.509 Extension 名称
        extension_patterns = {
            r'Subject\s+Alternative\s+Name': 'subjectAltName',
            r'Issuer\s+Alternative\s+Name': 'issuerAltName',
            r'Key\s+Usage': 'keyUsage',
            r'Extended\s+Key\s+Usage': 'extendedKeyUsage',
            r'Basic\s+Constraints': 'basicConstraints',
            r'Certificate\s+Policies': 'certificatePolicies',
            r'Policy\s+Constraints': 'policyConstraints',
            r'Name\s+Constraints': 'nameConstraints',
            r'Subject\s+Key\s+Identifier': 'subjectKeyIdentifier',
            r'Authority\s+Key\s+Identifier': 'authorityKeyIdentifier',
            r'CRL\s+Distribution\s+Points': 'cRLDistributionPoints',
            r'Authority\s+Information\s+Access': 'authorityInfoAccess',
            r'Subject\s+Information\s+Access': 'subjectInfoAccess',
        }

        for pattern, field_name in extension_patterns.items():
            if re.search(pattern, title_text, re.IGNORECASE):
                return field_name

        # 3. 证书核心字段
        core_field_patterns = {
            r'\bValidity\b': 'validity',
            r'\bSubject\b(?!\s+Alternative)(?!\s+Key)(?!\s+Information)': 'subject',
            r'\bIssuer\b(?!\s+Alternative)(?!\s+Key)': 'issuer',
            r'\bSerial\s+Number\b': 'serialNumber',
            r'\bSignature\b': 'signature',
            r'\bVersion\b': 'version',
            r'\bPublic\s+Key\b': 'subjectPublicKeyInfo',
        }

        for pattern, field_name in core_field_patterns.items():
            if re.search(pattern, title_text, re.IGNORECASE):
                return field_name

        # 4. 特殊情况：如果标题包含多个已知字段，返回第一个匹配的
        # 例如："Subject and Issuer" → "subject"

        app_logger.debug(f"[ContextBuilder] Could not extract topic from section title: '{title_text}'")
        return None

    def _get_canonical_subject(self, section: Optional[str]) -> Optional[Dict[str, Any]]:
        """
        获取章节的 canonical subject（规范主体）

        Uses FieldResolver (data-driven, from X.509 field schema) instead of
        hard-coded section_topics_kb mappings. This works across all specification
        documents without per-section configuration.

        Args:
            section: 章节号（如 "7.2"）

        Returns:
            包含以下字段的字典：
            - path: 规范路径（如 "extensions.nameconstraints"）
            - aliases: 别名列表
            - subtree_paths: 有效子路径列表
            - instruction: 给 LLM 的使用指示

            如果该章节没有可识别的 canonical subject，返回 None
        """
        if not section:
            return None

        # Get the section title from the skeleton context
        # Try section_topics_kb first for title (it still has useful metadata)
        section_title = None
        if self.standard:
            section_info = section_topics_kb.get_section_info(self.standard, section)
            if section_info:
                section_title = section_info.get('title')

        # Fallback: look up title from corpus (works for CABF, ETSI, etc.)
        if not section_title and self.document_id:
            try:
                from app.services.knowledge_layer import get_corpus_loader
                loader = get_corpus_loader()
                if loader:
                    doc = loader.get_document(self.document_id)
                    if doc and section in doc.sections:
                        section_title = doc.sections[section].title
            except Exception:
                pass

        if not section_title:
            return None

        # Use FieldResolver for data-driven canonical subject resolution
        field_resolver = get_field_resolver()
        result = field_resolver.resolve_section_subject(
            section_title=section_title,
            section_id=section,
        )

        if result:
            app_logger.debug(
                f"[ContextBuilder] FieldResolver resolved §{section} '{section_title}' "
                f"→ '{result['path']}'"
            )
            return result

        return None

    def _has_condition(self, sentence: str) -> bool:
        """检测是否包含条件词"""
        for pattern in self.condition_regex:
            if pattern.search(sentence):
                return True
        return False

    def _has_pronoun(self, sentence: str) -> bool:
        """检测是否包含指代词"""
        for pattern in self.pronoun_regex:
            if pattern.search(sentence):
                return True
        return False

    def _has_reference(self, sentence: str) -> bool:
        """检测是否包含引用"""
        for pattern in self.reference_regex:
            if pattern.search(sentence):
                return True
        return False

    def _is_in_list(self, skeleton: RuleSkeleton) -> bool:
        """检测是否在列表中"""
        # 简化版：检查段落文本是否包含列表标记
        if skeleton.paragraph_text:
            for pattern in self.list_regex:
                if pattern.search(skeleton.paragraph_text):
                    return True
        return False

    def _extract_references(self, sentence: str) -> List[str]:
        """提取引用标记"""
        references = []
        for pattern in self.reference_regex:
            matches = pattern.finditer(sentence)
            for match in matches:
                references.append(match.group(0))
        return references

    def _get_surrounding_sentences(
        self,
        sent_idx: int,
        window: int = 3,
        direction: str = 'both'
    ) -> str:
        """
        获取周围句子

        Args:
            sent_idx: 句子索引
            window: 窗口大小
            direction: 'both', 'before', 'after'

        Returns:
            上下文文本
        """
        if direction == 'before':
            start = max(0, sent_idx - window)
            end = sent_idx
        elif direction == 'after':
            start = sent_idx + 1
            end = min(len(self.sentences), sent_idx + 1 + window)
        else:  # both
            start = max(0, sent_idx - window)
            end = min(len(self.sentences), sent_idx + 1 + window)

        context_sentences = self.sentences[start:end]
        return ' '.join(context_sentences)

    def _get_section_path(self, section: Optional[str]) -> List[str]:
        """
        获取 section 层级路径

        例如：
        - "4.2.1.6" → ["4", "4.2", "4.2.1", "4.2.1.6"]
        """
        if not section:
            return []

        parts = section.split('.')
        path = []
        for i in range(1, len(parts) + 1):
            path.append('.'.join(parts[:i]))

        return path

    def _calculate_complexity(
        self,
        skeleton: RuleSkeleton,
        extended_context: Dict[str, Any]
    ) -> int:
        """
        计算规则复杂度评分

        评分规则（参考设计文档）：
        +2 if contains condition words
        +2 if contains reference
        +1 if contains pronoun
        +1 if in list

        复杂度用于后续 batch 调度：
        - 低复杂度（0-2）：batch_size = 30-40
        - 中复杂度（3-4）：batch_size = 15-25
        - 高复杂度（5+）：batch_size = 5-10
        """
        score = 0

        if extended_context.get('has_condition'):
            score += 2
        if extended_context.get('has_reference'):
            score += 2
        if extended_context.get('has_pronoun'):
            score += 1
        if extended_context.get('is_in_list'):
            score += 1

        return score

    def _split_into_sentences(self, text: str) -> List[str]:
        """分句（与 RuleDiscovery 一致）"""
        sentences = re.split(r'[.!?](?:\s+|$)', text)
        return [s.strip() for s in sentences if s.strip()]

    def _stable_batch_sort_key(self, ctx: RuleContext) -> Tuple[str, str, int, int, str]:
        """Deterministic ordering key for batch construction."""
        skeleton = ctx.skeleton
        canonical_subject = (ctx.extended_context or {}).get('canonical_subject') or {}
        canonical_path = canonical_subject.get('path') or ''
        return (
            skeleton.section or '',
            canonical_path,
            skeleton.sentence_index if skeleton.sentence_index is not None else -1,
            getattr(skeleton, 'assertion_index_within_sentence', 0),
            skeleton.rule_id or '',
        )

    def batch_by_complexity(
        self,
        contexts: List[RuleContext]
    ) -> List[List[RuleContext]]:
        """
        按复杂度分组 + 动态计算batch size + Subject Grouping (for Compose)

        Args:
            contexts: 规则上下文列表

        Returns:
            分批后的上下文列表

        设计原则：
        1. **NEW**: 先按 subject 预分组，确保同 subject 的规则在同一 batch（支持 compose）
        2. 然后按复杂度分组（低/中/高）- 保证调度顺序
        3. 每组内动态计算batch size - 根据实际上下文长度填充
        4. 不使用固定batch size - 充分利用模型上下文窗口
        """
        if not contexts:
            return []

        # ========== NEW: Step 0 - Stable ordering + Subject Grouping（支持 Compose）==========
        from collections import defaultdict

        contexts = sorted(contexts, key=self._stable_batch_sort_key)

        subject_groups = defaultdict(list)
        subject_order = []
        for ctx in contexts:
            canonical_subject = (ctx.extended_context or {}).get('canonical_subject') or {}
            canonical_path = canonical_subject.get('path')

            # 优先使用 canonical subject，其次回退到 sentence heuristic，最后使用 section
            if canonical_path:
                group_key = f"canonical:{canonical_path}"
            else:
                sentence = ctx.skeleton.sentence.lower()
                potential_subjects = [
                    'certificatepolicies', 'crldistributionpoints', 'authoritykeyidentifier',
                    'subjectkeyidentifier', 'subjectaltname', 'basicconstraints',
                    'extendedkeyusage', 'keyusage', 'nameconstraints', 'policyconstraints',
                    'serialnumber', 'validity', 'notafter', 'notbefore'
                ]

                detected_subject = None
                for subject_keyword in potential_subjects:
                    if subject_keyword in sentence:
                        detected_subject = subject_keyword
                        break

                group_key = f"heuristic:{detected_subject}" if detected_subject else f"section:{ctx.base_context.get('section') or 'unknown'}"

            if group_key not in subject_groups:
                subject_order.append(group_key)
            subject_groups[group_key].append(ctx)

        contexts_regrouped = []
        for group_key in sorted(subject_order):
            group_contexts = sorted(subject_groups[group_key], key=self._stable_batch_sort_key)
            contexts_regrouped.extend(group_contexts)

        contexts = contexts_regrouped
        # ========== End Stable ordering + Subject Grouping ==========

        # 步骤1: 按复杂度分组
        low_complexity = []   # 0-2
        mid_complexity = []   # 3-4
        high_complexity = []  # 5+

        for ctx in contexts:
            score = ctx.complexity_score
            if score <= 2:
                low_complexity.append(ctx)
            elif score <= 4:
                mid_complexity.append(ctx)
            else:
                high_complexity.append(ctx)

        # 步骤2: 每组内动态填充batch
        batches = []
        batches.extend(self._create_dynamic_batches(low_complexity, group_name='low'))
        batches.extend(self._create_dynamic_batches(mid_complexity, group_name='mid'))
        batches.extend(self._create_dynamic_batches(high_complexity, group_name='high'))

        # 统计信息
        batch_sizes = [len(b) for b in batches]
        avg_size = sum(batch_sizes) / len(batches) if batches else 0

        app_logger.info(
            f"[ContextBuilder] Created {len(batches)} batches (complexity-grouped + dynamic size): "
            f"low={len(low_complexity)}, mid={len(mid_complexity)}, high={len(high_complexity)}, "
            f"avg_batch_size={avg_size:.1f}, max_tokens_per_batch={self.max_tokens_per_batch}"
        )

        return batches

    def _create_dynamic_batches(
        self,
        contexts: List[RuleContext],
        group_name: str = ''
    ) -> List[List[RuleContext]]:
        """
        为一组规则动态创建batches（按上下文长度填充）

        Args:
            contexts: 同一复杂度组的规则上下文
            group_name: 组名（用于日志）

        Returns:
            batch列表
        """
        if not contexts:
            return []

        batches = []
        current_batch = []
        current_tokens = 0

        # 动态计算 max_rules_per_batch：根据上下文窗口推算输出容量上限
        # 每条规则的 IR JSON 输出实际约 1200-1500 tokens（含所有字段）
        # ⭐ 推理模型(GLM-Z1 等)在输出 JSON 前会消耗大量 thinking tokens（trivial 输入都 ~1163），
        # 大批(12)会让 thinking+JSON 超出 max_tokens 导致截断/空响应→拆分重试→限流→卡死。
        # 故对召回稳定性优先，硬上限降到 4 条/批。
        max_rules_per_batch = 4

        app_logger.debug(
            f"[ContextBuilder] max_rules_per_batch={max_rules_per_batch}"
        )

        for ctx in contexts:
            # 计算此规则的上下文总长度
            context_length = self._estimate_context_length(ctx)
            context_tokens = context_length // 4  # 1 token ≈ 4 chars

            # 如果添加此规则会超过token限制或规则数限制，先保存当前batch
            if current_batch and (
                current_tokens + context_tokens > self.max_tokens_per_batch or
                len(current_batch) >= max_rules_per_batch
            ):
                batches.append(current_batch)
                current_batch = [ctx]
                current_tokens = context_tokens
            else:
                current_batch.append(ctx)
                current_tokens += context_tokens

        # 添加最后一个batch
        if current_batch:
            batches.append(current_batch)

        if batches:
            batch_sizes = [len(b) for b in batches]
            app_logger.debug(
                f"[ContextBuilder] {group_name} complexity: {len(contexts)} rules → "
                f"{len(batches)} batches, sizes={batch_sizes}"
            )

        return batches

    def _estimate_context_length(self, ctx: RuleContext) -> int:
        """
        估算规则上下文的总字符长度

        包括：
        - 原始句子
        - 扩展上下文（条件、指代、列表、引用）
        """
        total_length = 0

        # Base context (use `or ''` because values may be None even if key exists)
        total_length += len(ctx.base_context.get('sentence', '') or '')
        total_length += len(ctx.base_context.get('section_title', '') or '')

        # Extended context
        ext = ctx.extended_context or {}
        if ext.get('condition_context'):
            total_length += len(ext['condition_context'])
        if ext.get('pronoun_context'):
            total_length += len(ext['pronoun_context'])
        if ext.get('list_context'):
            total_length += len(ext['list_context'])

        return total_length
