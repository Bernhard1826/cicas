"""
阶段 A：确定性规则发现层
Regex 决定规则召回率上限，LLM 决定 IR 语义质量下限。

职责：
1. 扫描全文，逐句枚举所有 RFC2119 规范性关键词
2. 拆分复合句规则（一句中多个 MUST/SHALL）
3. 保留精确定位信息（section, sentence index, position）
4. 允许误报，但绝不允许漏报
5. **Enhanced**: Detect scope inheritance structures (parent-child)
6. **Enhanced**: Detect normative patterns without RFC2119 keywords

禁止：
- 在此阶段做任何语义理解、过滤、合并
- 基于上下文判断是否提取
- 使用 LLM 参与规则发现
- 做任何形式的 chunk / batch 截断
"""
import re
from typing import List, Dict, Any, Optional, Tuple
from dataclasses import dataclass
from app.core.logging_config import app_logger
from app.services.extraction.rfc_text_cleaner import clean_rfc_text


@dataclass
class RuleSkeleton:
    """规则骨架 - assertion 级最小发现单位"""
    rule_id: str                      # 唯一标识，如 "rfc5280-4.2.1.6-001"
    section: Optional[str]            # 章节号，如 "4.2.1.6"
    sentence: str                     # 当前 assertion 文本（向后兼容字段）
    keyword: str                      # RFC2119 关键词（MUST/SHALL等）
    keyword_position: int             # 关键词在 assertion 中的位置
    sentence_index: int               # 源句子在文档中的索引
    line_number: Optional[int] = None # 原始行号（如果可用）

    # assertion 级 provenance
    source_sentence: Optional[str] = None              # 原始完整句子
    assertion_text: Optional[str] = None               # assertion 原子文本
    assertion_index_within_sentence: int = 0           # assertion 在源句中的顺序

    # 上下文信息（用于后续阶段构建动态上下文）
    paragraph_text: Optional[str] = None  # 所在段落文本
    section_title: Optional[str] = None   # 章节标题

    # Compose相关字段（标记合并规则）
    is_composed: bool = False                       # 是否为合并规则
    original_rule_ids: Optional[List[str]] = None   # 原始规则ID列表
    original_sentences: Optional[List[str]] = None  # 原始规则文本列表
    compose_reason: Optional[str] = None            # 合并原因（如 "same_subject"）

    # === Enhanced IR Extraction: Scope Inheritance Tracking ===
    keyword_source: str = "direct"                  # How keyword was obtained: direct|inherited|normative_pattern
    parent_rule_id: Optional[str] = None            # Parent rule ID if keyword inherited
    scope_block_id: Optional[str] = None            # Scope block ID for grouped rules
    pattern_type: Optional[str] = None              # For normative_pattern sources: definitional|equivalence|etc.


class RuleDiscovery:
    """
    阶段 A：确定性规则发现

    设计原则：
    - 宁可误报（允许非规范性语句），不可漏报（必须捕获所有规范性语句）
    - 只做枚举，不做理解
    - 保证规则召回率（Recall）
    """

    # RFC2119 规范性关键词（优先级顺序：先匹配多词模式）
    RFC2119_KEYWORDS = [
        'MUST NOT',
        'SHALL NOT',
        'SHOULD NOT',
        'MUST',
        'SHALL',
        'REQUIRED',
        'SHOULD',
        'RECOMMENDED',
        'MAY',
        'OPTIONAL',
    ]

    def __init__(self):
        """初始化规则发现器"""
        # 默认：只召回大写 RFC2119 关键词（RFC5280 / CABF 等）。
        # 仅 ETSI 特殊：MUST/SHALL/SHOULD/MAY 大小写不敏感（ETSI 用小写 "may" 表规范）。
        # discover_rules() 会按 document_id 判定来源，必要时切到 ETSI 模式。
        self._etsi_mode = False
        self._build_keyword_patterns(etsi_mode=False)

        # 章节号模式（匹配 1, 1.2, 1.2.3, A, A.1, Appendix A 等）
        # 支持正文章节（数字）和附录章节（字母 A-Z）
        self.section_pattern = re.compile(
            r'^(?:(\d+(?:\.\d+)*)|([A-Z])(?:\.\d+)?|Appendix\s+([A-Z]))\s+',
            re.MULTILINE
        )

        # Initialize structural analyzer for scope inheritance detection
        # Lazy import to avoid circular dependencies
        self._structural_analyzer = None
        self._normative_scanner = None

        app_logger.info("[RuleDiscovery] Initialized with RFC2119 keyword patterns")

    def _build_keyword_patterns(self, etsi_mode: bool) -> None:
        """构建 RFC2119 关键词正则。

        - 默认（非 ETSI，如 RFC5280 / CABF）：全部**大写敏感** —— 只召回大写关键词。
          小写 must/may/should 等是普通英语词，不召回（除 ETSI 外）。
        - ETSI：MUST/SHALL/SHOULD/MAY **大小写不敏感**（ETSI 用小写表规范）；
          OPTIONAL/REQUIRED/RECOMMENDED 仍大写敏感。
        """
        case_insensitive_keywords = (
            {'MUST NOT', 'SHALL NOT', 'SHOULD NOT', 'MUST', 'SHALL', 'SHOULD', 'MAY'}
            if etsi_mode else set()
        )
        self.keyword_patterns = []
        for keyword in self.RFC2119_KEYWORDS:
            # 使用词边界确保精确匹配
            flags = re.IGNORECASE if keyword in case_insensitive_keywords else 0
            pattern = re.compile(rf'\b{re.escape(keyword)}\b', flags)
            self.keyword_patterns.append((keyword, pattern))
        self._etsi_mode = etsi_mode

    @property
    def structural_analyzer(self):
        """Lazy initialization of structural analyzer."""
        if self._structural_analyzer is None:
            from app.services.extraction.structural_analyzer import StructuralAnalyzer
            self._structural_analyzer = StructuralAnalyzer()
        return self._structural_analyzer
    @property
    def normative_scanner(self):
        """Lazy initialization of normative pattern scanner."""
        if self._normative_scanner is None:
            from app.services.extraction.normative_pattern_scanner import NormativePatternScanner
            self._normative_scanner = NormativePatternScanner()
        return self._normative_scanner


    def _clone_skeleton_with_assertion(
        self,
        skeleton: RuleSkeleton,
        assertion_text: str,
        assertion_index: int,
        keyword: Optional[str] = None,
        keyword_position: Optional[int] = None,
        keyword_source: Optional[str] = None,
    ) -> RuleSkeleton:
        """Clone a sentence-level skeleton into an assertion-level skeleton."""
        text = assertion_text.strip()
        effective_keyword = keyword or skeleton.keyword
        if keyword_position is None:
            match = re.search(rf'\b{re.escape(effective_keyword)}\b', text, re.IGNORECASE)
            keyword_position = match.start() if match else 0

        return RuleSkeleton(
            rule_id=skeleton.rule_id,
            section=skeleton.section,
            sentence=text,
            keyword=effective_keyword,
            keyword_position=keyword_position,
            sentence_index=skeleton.sentence_index,
            line_number=skeleton.line_number,
            source_sentence=skeleton.source_sentence or skeleton.sentence,
            assertion_text=text,
            assertion_index_within_sentence=assertion_index,
            paragraph_text=skeleton.paragraph_text,
            section_title=skeleton.section_title,
            is_composed=skeleton.is_composed,
            original_rule_ids=skeleton.original_rule_ids,
            original_sentences=skeleton.original_sentences,
            compose_reason=skeleton.compose_reason,
            keyword_source=keyword_source or skeleton.keyword_source,
            parent_rule_id=skeleton.parent_rule_id,
            scope_block_id=skeleton.scope_block_id,
            pattern_type=skeleton.pattern_type,
        )

    def _split_rfc2119_assertions(self, sentence: str) -> List[Tuple[str, str, int]]:
        """Split one sentence into RFC2119 assertion-level fragments."""
        matches: List[Tuple[str, int, int]] = []
        occupied: List[Tuple[int, int]] = []
        for keyword, pattern in self.keyword_patterns:
            for match in pattern.finditer(sentence):
                start, end = match.start(), match.end()
                overlapping = any(not (end <= s or start >= e) for s, e in occupied)
                if overlapping:
                    continue
                occupied.append((start, end))
                matches.append((keyword, start, end))

        matches.sort(key=lambda item: item[1])
        if not matches:
            return []

        segments = []
        clause_delimiters = ';:.!?\n'
        for idx, (keyword, start, end) in enumerate(matches):
            seg_start = 0
            for pos in range(start - 1, -1, -1):
                if sentence[pos] in clause_delimiters:
                    seg_start = pos + 1
                    break
            # Clamp to the boundary AFTER the previous keyword: a compound sentence
            # like "... MUST contain a single X, which MUST contain Y" has no clause
            # delimiter (only a comma) between the two MUSTs, so the backward scan
            # would run past the first MUST to position 0 and make this fragment the
            # WHOLE sentence — leaving each split assertion carrying the full compound
            # text (so its single-constraint tree reads as under-claiming the rule).
            # Keep each assertion's text to its own clause: start no earlier than the
            # split point between the previous keyword and this one (a delimiter in
            # between, else this keyword's own start).
            if idx > 0:
                prev_end = matches[idx - 1][2]
                prev_boundary = start
                for pos in range(prev_end, start):
                    if sentence[pos] in clause_delimiters:
                        prev_boundary = pos + 1
                        break
                seg_start = max(seg_start, prev_boundary)

            seg_end = len(sentence)
            if idx + 1 < len(matches):
                next_start = matches[idx + 1][1]
                split_pos = next_start
                for pos in range(end, next_start):
                    if sentence[pos] in ';:.!?\n':
                        split_pos = pos + 1
                        break
                seg_end = split_pos
            else:
                for pos in range(end, len(sentence)):
                    if sentence[pos] in ';.!?\n':
                        seg_end = pos + 1
                        break

            fragment = sentence[seg_start:seg_end].strip(' ;,\n\t')
            if not fragment:
                continue
            rel_match = re.search(rf'\b{re.escape(keyword)}\b', fragment, re.IGNORECASE)
            rel_pos = rel_match.start() if rel_match else 0
            segments.append((fragment, keyword, rel_pos))

        return segments

    def _explode_sentence_skeletons_to_assertions(self, skeletons: List[RuleSkeleton]) -> List[RuleSkeleton]:
        """Convert sentence-level RFC2119 skeletons into assertion-level skeletons."""
        assertion_skeletons: List[RuleSkeleton] = []
        emitted_keys = set()

        for skeleton in skeletons:
            if skeleton.keyword_source != 'direct':
                text = skeleton.sentence.strip()
                cloned = self._clone_skeleton_with_assertion(skeleton, text, 0)
                key = (
                    cloned.section,
                    cloned.sentence_index,
                    cloned.assertion_index_within_sentence,
                    cloned.keyword,
                    cloned.sentence,
                    cloned.keyword_source,
                )
                if key not in emitted_keys:
                    emitted_keys.add(key)
                    assertion_skeletons.append(cloned)
                continue

            fragments = self._split_rfc2119_assertions(skeleton.sentence)
            if not fragments:
                cloned = self._clone_skeleton_with_assertion(skeleton, skeleton.sentence.strip(), 0)
                key = (
                    cloned.section,
                    cloned.sentence_index,
                    cloned.assertion_index_within_sentence,
                    cloned.keyword,
                    cloned.sentence,
                    cloned.keyword_source,
                )
                if key not in emitted_keys:
                    emitted_keys.add(key)
                    assertion_skeletons.append(cloned)
                continue

            for assertion_index, (fragment, keyword, rel_pos) in enumerate(fragments):
                cloned = self._clone_skeleton_with_assertion(
                    skeleton,
                    fragment,
                    assertion_index,
                    keyword=keyword,
                    keyword_position=rel_pos,
                    keyword_source='direct',
                )
                key = (
                    cloned.section,
                    cloned.sentence_index,
                    cloned.assertion_index_within_sentence,
                    cloned.keyword,
                    cloned.sentence,
                    cloned.keyword_source,
                )
                if key in emitted_keys:
                    continue
                emitted_keys.add(key)
                assertion_skeletons.append(cloned)

        return assertion_skeletons

    def discover_rules(
        self,
        document_text: str,
        document_id: str = "unknown",
        pre_parsed_sections: Optional[List[Dict[str, Any]]] = None
    ) -> List[RuleSkeleton]:
        """
        从文档中发现所有规则骨架

        Args:
            document_text: 完整文档文本
            document_id: 文档标识符
            pre_parsed_sections: 预解析的章节列表（PDF文档使用），格式
                [{'section_id': '7.1.4', 'title': 'Name Forms', 'text': '...'}]
                如果提供，跳过内部文档结构解析

        Returns:
            规则骨架列表
        """
        app_logger.info(f"[RuleDiscovery] Starting rule discovery for document: {document_id}")

        # 关键词大小写模式：默认只召回大写；仅 ETSI 文档启用小写匹配
        _etsi = 'ETSI' in (document_id or '').upper()
        if _etsi != self._etsi_mode:
            self._build_keyword_patterns(etsi_mode=_etsi)
            app_logger.info(
                f"[RuleDiscovery] keyword case mode = "
                f"{'ETSI (case-insensitive MUST/SHALL/SHOULD/MAY)' if _etsi else 'uppercase-only'}"
            )

        # 第0步：清理RFC文本（移除页脚、页眉、分页符）
        document_text = clean_rfc_text(document_text)
        app_logger.info(f"[RuleDiscovery] RFC text cleaned (footers, headers, form feeds removed)")

        # 第1步：文档预处理
        if pre_parsed_sections is not None:
            sections = pre_parsed_sections
            app_logger.info(f"[RuleDiscovery] Using {len(sections)} pre-parsed sections")
        else:
            sections = self._parse_document_structure(document_text)

        # 第2步：逐句扫描（增加去重逻辑）
        all_skeletons = []
        sentence_global_index = 0
        # 位置感知去重：记录句子及其最后出现的位置
        # 相同句子如果间隔超过阈值，则认为是不同上下文中的重复，应保留
        seen_sentences: Dict[str, int] = {}  # normalized -> last_seen_index
        DUPLICATE_DISTANCE_THRESHOLD = 10  # 相同句子间隔超过10句则认为是不同上下文
        duplicate_count = 0

        # 全量召回原则（label-don't-drop）：定义/术语章节（如 ETSI "Modal verbs
        # terminology"、CABF §1.6.1 Definitions、RFC5280 §2 Requirements Terminology）
        # 仍可能含带 RFC2119 关键词的句子。这些句子即便多为 noise 也必须入库，以保证
        # 召回分母完整、统计可信；是否 noise 交由 Layer 2 LLM/分类阶段判定。
        # Layer 1 不再按章节标题预先整节丢弃（原 _DEFINITION_TITLE_PATTERNS skip 已移除）。
        for section_info in sections:
            section_id = section_info['section_id']
            section_title = section_info['title']
            section_text = section_info['text']

            # 分句
            sentences = self._split_sentences(section_text)

            for sent_idx, sentence in enumerate(sentences):
                # 规范化句子用于去重检测
                normalized = re.sub(r'[^\w\s]', '', sentence.lower())
                normalized = ' '.join(normalized.split())

                # 位置感知去重：
                # - 如果完全相同的句子在近距离（<10句）内出现，跳过
                # - 如果相同句子间隔较远（>=10句），认为是不同上下文，保留
                # 这解决了 RFC 5280 §7.2 中 MUST 和 SHOULD 两个 scope block
                # 都有相同 step 1 内容的问题
                if normalized in seen_sentences:
                    last_idx = seen_sentences[normalized]
                    distance = sentence_global_index - last_idx

                    if distance < DUPLICATE_DISTANCE_THRESHOLD:
                        # 近距离重复，跳过
                        duplicate_count += 1
                        app_logger.debug(
                            f"[RuleDiscovery] Skipping duplicate sentence (distance={distance}) "
                            f"at index {sentence_global_index}: {sentence[:60]}..."
                        )
                        sentence_global_index += 1
                        continue
                    else:
                        # 远距离重复，保留（可能是不同上下文）
                        app_logger.debug(
                            f"[RuleDiscovery] Keeping distant duplicate (distance={distance}) "
                            f"at index {sentence_global_index}: {sentence[:60]}..."
                        )

                # 跳过关键词定义性句子（如 ETSI 模态动词说明章节）
                # 特征：RFC2119关键词出现在引号内或紧跟 "means"/"is used"/"are to be interpreted" 等
                _kw_def_pat = re.compile(
                    r'["\u201c][A-Z][^"\u201d]*(?:MUST|SHALL|SHOULD|MAY)[^"\u201d]*["\u201d]|'
                    r'(?:MUST|SHALL|SHOULD|MAY).*?(?:are to be interpreted|is used to|means that|indicates that)',
                    re.IGNORECASE
                )
                # label-don't-drop（全量召回）：原此处 _kw_def_pat 命中即 continue 丢弃
                # RFC2119 boilerplate / 定义句，违背“含关键词句必入库”，且其关键词清单只含
                # MUST/SHALL/SHOULD/MAY，会漏标 boilerplate 里的 OPTIONAL/REQUIRED 片段。
                # 已移除该丢弃：这些句照常成骨架入库，noise 判定交 Layer 2 LLM。
                # （上方 _kw_def_pat 定义现已不再使用。）

                # 在单个句子中查找所有关键词
                skeletons = self._extract_skeletons_from_sentence(
                    sentence=sentence,
                    document_id=document_id,
                    section_id=section_id,
                    section_title=section_title,
                    sentence_index=sentence_global_index,
                    paragraph_text=section_text[:500]
                )

                # 如果成功提取到规则骨架，更新该句子的最后出现位置
                if skeletons:
                    seen_sentences[normalized] = sentence_global_index
                    all_skeletons.extend(skeletons)

                sentence_global_index += 1

        app_logger.info(
            f"[RuleDiscovery] Discovered {len(all_skeletons)} rule skeletons "
            f"from {sentence_global_index} sentences "
            f"({len(seen_sentences)} unique, {duplicate_count} duplicates skipped)"
        )

        # 第3步：骨架级别去重（去除完全相同的规则骨架）
        # 策略：提取包含RFC2119关键词的核心子句进行去重，而不是比较整个句子
        # 这样可以去除因列表项拼接导致的伪重复
        # 注意：不同位置的相同句子应该保留（如 RFC 5280 §7.2 中 MUST 和 SHOULD
        #       两个 scope block 都有相同的 step 1 内容）
        unique_skeletons = []
        seen_skeleton_texts: Dict[str, int] = {}  # key -> sentence_index
        SKELETON_DISTANCE_THRESHOLD = 5  # 相同骨架间隔超过5则保留
        skeleton_duplicate_count = 0

        for skeleton in all_skeletons:
            # 提取核心子句：基于句子分隔符（分号、冒号、逗号）智能切分
            core_clause = self._extract_core_clause(
                skeleton.sentence,
                skeleton.keyword,
                skeleton.keyword_position
            )

            # 规范化核心子句（去除标点和空格，转小写）
            normalized_core = re.sub(r'[^\w\s]', '', core_clause.lower())
            normalized_core = ' '.join(normalized_core.split())

            # 创建唯一键：规范化核心文本 + 关键词 + 章节
            skeleton_key = f"{normalized_core}|{skeleton.keyword}|{skeleton.section}"

            # 位置感知去重：相同骨架在不同上下文（距离较远）中应保留
            if skeleton_key in seen_skeleton_texts:
                last_idx = seen_skeleton_texts[skeleton_key]
                distance = skeleton.sentence_index - last_idx

                if distance < SKELETON_DISTANCE_THRESHOLD:
                    # 近距离重复，跳过
                    skeleton_duplicate_count += 1
                    app_logger.debug(
                        f"[RuleDiscovery] Skipping duplicate skeleton (distance={distance}): "
                        f"keyword={skeleton.keyword}, core={core_clause[:60]}..."
                    )
                    continue
                else:
                    # 远距离重复，保留（可能是不同上下文）
                    app_logger.debug(
                        f"[RuleDiscovery] Keeping distant duplicate skeleton (distance={distance}): "
                        f"keyword={skeleton.keyword}, core={core_clause[:60]}..."
                    )

            unique_skeletons.append(skeleton)
            seen_skeleton_texts[skeleton_key] = skeleton.sentence_index

        if skeleton_duplicate_count > 0:
            app_logger.info(
                f"[RuleDiscovery] Removed {skeleton_duplicate_count} duplicate skeletons "
                f"(final count: {len(unique_skeletons)})"
            )

        unique_skeletons = self._explode_sentence_skeletons_to_assertions(unique_skeletons)
        app_logger.info(
            f"[RuleDiscovery] Assertion segmentation produced {len(unique_skeletons)} skeletons"
        )

        # ========== Pass 2: Scope Inheritance Analysis (Enhanced IR Extraction) ==========
        # Detect parent-child structures where bullet items inherit MUST from parent
        scope_skeletons = self._discover_scope_inherited_rules(
            sections=sections,
            document_id=document_id,
            existing_skeletons=unique_skeletons,
            base_sentence_index=sentence_global_index
        )

        if scope_skeletons:
            app_logger.info(
                f"[RuleDiscovery] Pass 2 (Scope Inheritance): Found {len(scope_skeletons)} "
                f"rules with inherited keywords"
            )
            unique_skeletons.extend(scope_skeletons)

        # ========== Pass 2.5: Continuation Sentence Assignment ==========
        # Handle sentences like "That is, X" that follow a scoped sentence but
        # weren't included in the scope block analysis
        continuation_count = self._assign_continuation_sentences(unique_skeletons)
        if continuation_count > 0:
            app_logger.info(
                f"[RuleDiscovery] Pass 2.5: Assigned {continuation_count} continuation sentences to scope blocks"
            )

        # ========== Pass 3: Normative Pattern Scanning (Enhanced IR Extraction) ==========
        # Detect normative statements without RFC2119 keywords
        normative_skeletons = self._discover_normative_pattern_rules(
            sections=sections,
            document_id=document_id,
            existing_skeletons=unique_skeletons,
            base_sentence_index=sentence_global_index + len(scope_skeletons)
        )

        if normative_skeletons:
            app_logger.info(
                f"[RuleDiscovery] Pass 3 (Normative Patterns): Found {len(normative_skeletons)} "
                f"rules without explicit RFC2119 keywords"
            )
            unique_skeletons.extend(normative_skeletons)

        # Final summary
        app_logger.info(
            f"[RuleDiscovery] Total rules discovered: {len(unique_skeletons)} "
            f"(RFC2119: {len(unique_skeletons) - len(scope_skeletons) - len(normative_skeletons)}, "
            f"Inherited: {len(scope_skeletons)}, Normative Patterns: {len(normative_skeletons)})"
        )

        return unique_skeletons

    def _discover_scope_inherited_rules(
        self,
        sections: List[Dict[str, Any]],
        document_id: str,
        existing_skeletons: List[RuleSkeleton],
        base_sentence_index: int
    ) -> List[RuleSkeleton]:
        """
        Pass 2: Discover rules with inherited keywords from scope blocks.

        Finds parent sentences with RFC2119 keywords followed by clarification
        lists, where child items inherit the parent's obligation.

        IMPORTANT: This pass also UPDATES existing skeletons that were captured
        in Pass 1 with scope block metadata (scope_block_id, parent_rule_id),
        even if they have their own direct keywords.

        Args:
            sections: Parsed document sections
            document_id: Document identifier
            existing_skeletons: Already discovered skeletons (for parent rule ID lookup)
            base_sentence_index: Starting sentence index

        Returns:
            List of RuleSkeletons with inherited keywords (new skeletons only)
        """
        inherited_skeletons = []

        # Build lookup for parent rule IDs
        parent_lookup = {}
        for skeleton in existing_skeletons:
            # Normalize sentence for matching
            norm_sentence = re.sub(r'[^\w\s]', '', skeleton.sentence.lower())
            norm_sentence = ' '.join(norm_sentence.split())[:100]
            parent_lookup[norm_sentence] = skeleton.rule_id

        # Build index of existing skeletons for updating scope metadata
        # Store normalized sentences for substring matching
        existing_skeleton_index = []
        for skeleton in existing_skeletons:
            norm_sentence = re.sub(r'[^\w\s]', '', skeleton.sentence.lower())
            norm_sentence = ' '.join(norm_sentence.split())
            existing_skeleton_index.append((norm_sentence, skeleton))

        # Track which skeletons have already been assigned to a scope block
        # This prevents duplicate assignments when multiple blocks have identical children
        assigned_skeleton_ids: set = set()

        sentence_idx = base_sentence_index
        updated_count = 0

        for section_info in sections:
            section_id = section_info['section_id']
            section_title = section_info['title']
            section_text = section_info['text']

            if not section_text:
                continue

            # Analyze section for scope blocks
            scope_blocks = self.structural_analyzer.analyze(section_text, section_id)

            for block in scope_blocks:
                # Try to find parent rule ID
                parent_norm = re.sub(r'[^\w\s]', '', block.parent_sentence.lower())
                parent_norm = ' '.join(parent_norm.split())[:100]
                parent_rule_id = parent_lookup.get(parent_norm)

                # Set scope_block_id on the PARENT skeleton too (needed for aggregation)
                if parent_rule_id:
                    for _, skeleton in existing_skeleton_index:
                        if skeleton.rule_id == parent_rule_id:
                            skeleton.scope_block_id = block.block_id
                            break

                # Get inherited rules from this block
                inherited_rules = self.structural_analyzer.get_inherited_rules(
                    block, document_id
                )

                for rule_info in inherited_rules:
                    # Normalize sentence for matching
                    child_norm = re.sub(r'[^\w\s]', '', rule_info['sentence'].lower())
                    child_norm = ' '.join(child_norm.split())

                    # Find matching existing skeleton using prefix comparison
                    # Logic: if the shorter sentence is a prefix of the longer one, they match
                    # This handles different splitting: "in step 1..." vs "in step 1... That is..."
                    # IMPORTANT: Skip skeletons already assigned to avoid overwriting when
                    # multiple scope blocks have identical children (e.g., step 1 in MUST vs SHOULD blocks)
                    existing_skeleton = None
                    for existing_norm, skeleton in existing_skeleton_index:
                        # Skip already assigned skeletons
                        if skeleton.rule_id in assigned_skeleton_ids:
                            continue
                        shorter, longer = sorted([existing_norm, child_norm], key=len)
                        # Check if shorter is a prefix of longer
                        if longer.startswith(shorter):
                            existing_skeleton = skeleton
                            break

                    if existing_skeleton:
                        # Check if keyword actually exists in sentence text
                        keyword_in_sentence = re.search(
                            r'\b' + re.escape(existing_skeleton.keyword) + r'\b',
                            existing_skeleton.sentence,
                            re.IGNORECASE
                        ) if existing_skeleton.keyword else False

                        # UPDATE existing skeleton with scope metadata
                        existing_skeleton.scope_block_id = block.block_id
                        existing_skeleton.parent_rule_id = parent_rule_id or rule_info.get('parent_rule_id')

                        # Mark this skeleton as assigned to prevent reassignment
                        assigned_skeleton_ids.add(existing_skeleton.rule_id)

                        # If keyword not actually in sentence, it was inherited from detection context
                        if not keyword_in_sentence:
                            existing_skeleton.keyword_source = 'inherited'

                        updated_count += 1

                    if rule_info['keyword_source'] == 'direct' and existing_skeleton:
                        # Already handled above
                        continue

                    if rule_info['keyword_source'] == 'direct':
                        # Has direct keyword but not found in existing (shouldn't happen often)
                        # Skip to avoid duplicates
                        continue

                    # Create skeleton for inherited rule (no direct keyword)
                    rule_id = self._generate_rule_id(
                        document_id=document_id,
                        section_id=section_id,
                        sentence_index=sentence_idx,
                        keyword_position=0
                    )

                    skeleton = RuleSkeleton(
                        rule_id=rule_id,
                        section=section_id,
                        sentence=rule_info['sentence'],
                        keyword=rule_info['keyword'],
                        keyword_position=0,
                        sentence_index=sentence_idx,
                        line_number=None,
                        source_sentence=rule_info['sentence'],
                        assertion_text=rule_info['sentence'],
                        assertion_index_within_sentence=0,
                        paragraph_text=block.parent_sentence,
                        section_title=section_title,
                        keyword_source='inherited',
                        parent_rule_id=parent_rule_id or rule_info.get('parent_rule_id'),
                        scope_block_id=block.block_id
                    )

                    inherited_skeletons.append(skeleton)
                    sentence_idx += 1

        if updated_count > 0:
            app_logger.info(
                f"[RuleDiscovery] Pass 2: Updated {updated_count} existing skeletons with scope metadata"
            )

        return inherited_skeletons

    def _assign_continuation_sentences(self, skeletons: List[RuleSkeleton]) -> int:
        """
        Pass 2.5: Assign continuation sentences to the same scope block as their predecessors.

        Handles cases like:
            "in step 1, the domain name SHALL be considered a stored string."  → in scope
            "That is, the AllowUnassigned flag SHALL NOT be set;"              → orphan (should be in same scope)

        Continuation phrases: "That is,", "Specifically,", "In other words,", "That means,"

        Args:
            skeletons: List of all discovered skeletons (modified in place)

        Returns:
            Number of skeletons assigned to scope blocks
        """
        # Continuation phrase patterns that indicate the sentence is a clarification
        # of the preceding sentence
        # NOTE: Do NOT include "Note:" - it often introduces NEW information
        continuation_patterns = [
            r'^that\s+is\s*,',
            r'^specifically\s*,',
            r'^in\s+other\s+words\s*,',
            r'^that\s+means\s*,',
            r'^i\.e\.\s*,',
            r'^namely\s*,',
        ]
        continuation_regex = re.compile(
            '|'.join(continuation_patterns),
            re.IGNORECASE
        )

        # Sort skeletons by sentence_index to ensure proper ordering
        sorted_skeletons = sorted(skeletons, key=lambda s: s.sentence_index)
        assigned_count = 0

        for i, skeleton in enumerate(sorted_skeletons):
            # Skip if already has scope_block_id
            if skeleton.scope_block_id:
                continue

            # Check if sentence starts with continuation phrase
            sentence_start = skeleton.sentence.strip()[:50]
            if not continuation_regex.match(sentence_start):
                continue

            # Look for the closest preceding skeleton with scope_block_id
            for j in range(i - 1, -1, -1):
                prev_skeleton = sorted_skeletons[j]
                if prev_skeleton.scope_block_id:
                    # Found a scoped predecessor - assign same scope
                    skeleton.scope_block_id = prev_skeleton.scope_block_id
                    skeleton.parent_rule_id = prev_skeleton.parent_rule_id or prev_skeleton.rule_id

                    app_logger.debug(
                        f"[RuleDiscovery] Pass 2.5: Assigned continuation sentence "
                        f"'{skeleton.sentence[:40]}...' to scope {skeleton.scope_block_id}"
                    )
                    assigned_count += 1
                    break

        return assigned_count

    def _discover_normative_pattern_rules(
        self,
        sections: List[Dict[str, Any]],
        document_id: str,
        existing_skeletons: List[RuleSkeleton],
        base_sentence_index: int
    ) -> List[RuleSkeleton]:
        """
        Pass 3: Discover rules using normative patterns without RFC2119 keywords.

        Finds sentences that express normative requirements through definitional
        or semantic patterns rather than explicit MUST/SHALL/SHOULD.

        Args:
            sections: Parsed document sections
            document_id: Document identifier
            existing_skeletons: Already discovered skeletons (for duplicate checking)
            base_sentence_index: Starting sentence index

        Returns:
            List of RuleSkeletons with normative pattern keywords
        """
        normative_skeletons = []

        # Build set of already discovered sentences for deduplication
        existing_sentences = set()
        for skeleton in existing_skeletons:
            norm_sentence = re.sub(r'[^\w\s]', '', skeleton.sentence.lower())
            norm_sentence = ' '.join(norm_sentence.split())
            existing_sentences.add(norm_sentence)

        sentence_idx = base_sentence_index

        for section_info in sections:
            section_id = section_info['section_id']
            section_title = section_info['title']
            section_text = section_info['text']

            if not section_text:
                continue

            # Scan section for normative patterns
            matches = self.normative_scanner.scan(
                section_text=section_text,
                section_id=section_id,
                section_title=section_title,
                base_sentence_index=sentence_idx
            )

            for match in matches:
                # Check for duplicates
                norm_sentence = re.sub(r'[^\w\s]', '', match.sentence.lower())
                norm_sentence = ' '.join(norm_sentence.split())

                if norm_sentence in existing_sentences:
                    continue

                existing_sentences.add(norm_sentence)

                # Create a skeleton for a non-keyword candidate. It must be
                # promoted later only if an explicit parent/table obligation is
                # recorded; otherwise it remains noise.
                rule_id = self._generate_rule_id(
                    document_id=document_id,
                    section_id=section_id,
                    sentence_index=sentence_idx,
                    keyword_position=match.match_position
                )

                skeleton = RuleSkeleton(
                    rule_id=rule_id,
                    section=section_id,
                    sentence=match.sentence,
                    keyword="NOISE_CANDIDATE",
                    keyword_position=match.match_position,
                    sentence_index=sentence_idx,
                    line_number=None,
                    source_sentence=match.sentence,
                    assertion_text=match.sentence,
                    assertion_index_within_sentence=0,
                    paragraph_text=match.paragraph_text,
                    section_title=section_title,
                    keyword_source='normative_pattern',
                    pattern_type=match.pattern_type
                )

                normative_skeletons.append(skeleton)
                sentence_idx += 1

        return normative_skeletons

    def _parse_document_structure(
        self,
        document_text: str
    ) -> List[Dict[str, Any]]:
        """
        解析文档结构（章节）

        Returns:
            [{'section_id': '4.2', 'title': 'Certificate Extensions', 'text': '...'}, ...]
        """
        sections = []
        lines = document_text.split('\n')

        current_section = None
        current_title = None
        current_text = []

        # Markdown 文档（如 CABF-BR BR.md）用显式 '#' 标记章节，应以其为权威边界。
        # 阈值 >=5 个标题，避免纯文本（RFC .txt）里偶发的 '#' 被误判为 markdown。
        is_markdown = len(re.findall(r'(?m)^\s{0,3}#{1,6}\s', document_text)) >= 5

        for line in lines:
            # markdown 模式下：仅 '#' 开头的行可作为章节标题；形如 "12. What
            # constitutes..." 的裸编号行是列表项（内容），不能当标题——否则会把后续
            # 低编号的真标题（5.x/6.x…）经回退拒识全部吞进一个巨段（实测曾塌成 182k）。
            if is_markdown and not re.match(r'^\s{0,3}#{1,6}\s', line):
                current_text.append(line)
                continue

            # 检测章节开始
            section_match = self._detect_section_header(line)

            if section_match:
                # Reject if section number regresses significantly
                # (e.g., seeing 2.5.4.8 when current section is 7.x → likely an OID)
                # 仅对纯文本（标题有歧义）启用；markdown 的 '#' 是权威边界，不做回退拒识。
                candidate_id = section_match['section_id']
                if current_section is not None and not is_markdown:
                    try:
                        current_first = int(current_section.split('.')[0])
                        candidate_first = int(candidate_id.split('.')[0])
                        if candidate_first <= current_first - 1:
                            # Section regression → reject. Use <= not <:
                            current_text.append(line)
                            continue
                    except ValueError:
                        # Letter section (A.1, B.2) — don't reject as regression
                        # 这些是附录章节，在数字章节之后合法出现
                        pass

                # Fix: 第一个检测到的 section 如果是多段编号（如 "4.2.1.15"），
                # 说明是 TOC 条目，不是正文第一 section（正文必须从 "1"/"2"/"3" 等
                # 单段编号开始）。此时拒绝，继续累积 content，等正文出现真标题。
                # 不硬编码"编号>3"：任何文档的正文首节都是单段，TOC 条目才是多段。
                # 更新：也允许单字母前缀的多段（如 A.1, B.2）作为附录起始。
                if current_section is None and not is_markdown:
                    segments = candidate_id.split('.')
                    if len(segments) >= 2:
                        # 多段：拒绝（TOC），除非第一段是单个字母（附录如 A.1）
                        if not (len(segments[0]) == 1 and segments[0].isalpha()):
                            current_text.append(line)
                            continue

                # 保存前一个章节
                if current_section is not None:
                    sections.append({
                        'section_id': current_section,
                        'title': current_title or '',
                        'text': '\n'.join(current_text)
                    })

                # 开始新章节
                current_section = section_match['section_id']
                current_title = section_match['title']
                current_text = []
            else:
                # 累积当前章节的文本
                current_text.append(line)

        # 保存最后一个章节
        if current_section is not None:
            sections.append({
                'section_id': current_section,
                'title': current_title or '',
                'text': '\n'.join(current_text)
            })

        # 如果没有检测到章节，整个文档作为一个章节
        if not sections:
            sections.append({
                'section_id': None,
                'title': None,
                'text': document_text
            })

        app_logger.debug(f"[RuleDiscovery] Parsed {len(sections)} sections")
        return sections

    def _detect_section_header(self, line: str) -> Optional[Dict[str, str]]:
        """
        检测章节标题

        Returns:
            {'section_id': '4.2.1', 'title': 'Standard Extensions'}
            或 None
        """
        line_stripped = line.strip()

        # Markdown 文档（如 CABF-BR BR.md）的标题形如 "## 1.2.2 Relevant Dates"。
        # clean_rfc_text 不会移除 '#'，而下面的编号正则以 \d 开头会被前缀的 '#' 卡住，
        # 导致整个 markdown 文档塌成少数巨段。这里先剥掉 markdown 标题前缀再做匹配；
        # 纯文本文档（RFC .txt 无 '#'）不受影响。
        md_header = re.match(r'^(#{1,6})\s+(.*)$', line_stripped)
        if md_header:
            line_stripped = md_header.group(2).strip()

        # 匹配章节号 + 标题模式
        # 例如：
        # - "4.2.1 Standard Extensions"
        # - "1. INTRODUCTION"
        # - "7.1.2.4 Random Value"
        match = re.match(
            r'^(\d+(?:\.\d+)*)[.\s]+(.+?)(?:\s*$)',
            line_stripped
        )

        if match:
            section_id = match.group(1)
            title = match.group(2).strip()

            # Reject OID-like numbers: any component >= 100 (e.g., 0.9.2342.19200300.100.1)
            components = section_id.split('.')
            if any(int(c) >= 100 for c in components):
                return None

            # 使用智能判断来区分真实标题和误识别的规则文本
            if not self._is_valid_section_title(title):
                return None

            return {
                'section_id': section_id,
                'title': title
            }

        # ==== Branch 2: Letter-prefixed sections (e.g., "A.1", "B.2.3", "X.1 Title") ====
        # 例如：
        # - "A.1.  Explicitly Tagged Module"
        # - "B.2 Implicitly Tagged"
        # - "X.1 Title"
        # 先重新剥 markdown 前缀（如果上面 digit 分支没匹配，说明不是数字开头）
        md_header = re.match(r'^(#{1,6})\s+(.*)$', line_stripped)
        if md_header:
            line_stripped = md_header.group(2).strip()

        letter_match = re.match(
            r'^([A-Za-z](?:\.\d+)*)[.\s]+(.+?)(?:\s*$)',
            line_stripped
        )

        if letter_match:
            section_id = letter_match.group(1).upper()  # Normalize to uppercase: A.1, B.2 -> A.1, B.2
            title = letter_match.group(2).strip()

            # 如果标题为空，使用 section 作为标题
            if not title:
                title = section_id

            # Reject non-section-like IDs: e.g. "X.509" (second component too large to be a section number)
            # 真实附录子编号通常是 A.1, A.2, B.1, B.2 等小数字；
            # "X.509" 是技术术语前缀，不是章节号。
            comps = section_id.split('.')
            if len(comps) > 1:
                for c in comps[1:]:  # 从第二个组件开始校验（首字母后才是子编号）
                    try:
                        if int(c) > 50:
                            # 第二及后续组件大于 50 → 可能是技术术语（如 X.509 中的 509）
                            return None
                    except ValueError:
                        pass  # 非数字组件忽略

            # 单字母章节（A, B, C ...）必须有实质性标题
            # 过滤：作者名（S. Farrell）、单字符（V）、无意义标题
            if len(comps[0]) == 1 and len(title) < 3:
                return None

            # 过滤正文句子：标题以小写字母开头 → 是句子，不是章节标题
            # 形如 "certificate is...", "CRL is..." → 正文句子，拒绝
            if title and title[0].islower():
                return None

            # 过滤单字母章节后的句子：标题以大写字母开头 + 小写字母开头
            # 形如 "CRL is...", "Certificate contains..." → 正文句子，拒绝
            # 真实附录标题通常以名词/形容词开头（如 "ASN.1 Notes"、"Pseudo-ASN.1"）
            if len(comps[0]) == 1 and len(title) > 3:
                # 过滤正文句子：单字母章节后的正文句子
                # 形如 "A CRL is a time-stamped list" → 正文句子，拒绝
                # 真实附录标题通常是：名词短语、或含数字/连字符
                title_lower = title.lower()
                sentence_indicators = [' is ', ' are ', ' was ', ' were ', ' has ', ' have ',
                                       ' contains ', ' includes ', ' provides ', ' describes ',
                                       ' been ', ' being ', ' used ', ' defined ']
                if any(indicator in title_lower for indicator in sentence_indicators):
                    # 包含句子结构，拒绝
                    return None

                # 过滤算法步骤：RFC 5280 第 6 章中的算法步骤形如
                # "A.  Set P-Q to...", "B.  For each P-OID...", "C.  Delete the node..."
                # 这些不是附录章节，是正文中的算法步骤
                algorithm_keywords = ['set p-', 'set p-q', 'for each', 'delete the node',
                                      'if there is', 'else if', 'else,', 'return ']
                if any(title_lower.startswith(kw) for kw in algorithm_keywords):
                    return None

            # 过滤作者名模式：如 "S. Farrell" → title 仅含字母/点/空格（短标题）
            # 区分方式：真实附录标题通常含数字/连字符/介词短语
            if len(comps[0]) == 1 and len(title) < 10:
                import re as _re
                if _re.fullmatch(r'[A-Za-z.\s]+', title):
                    # 短标题且仅含字母/点/空格 → 疑似作者名，拒绝
                    return None

            # 过滤 ASCII art / 表格字符（如 "V   |" 在 RFC 5280 ASCII 图中）
            if '|' in title or '+' in title or '=' in title or title.strip() != title:
                return None

            # 使用智能判断来区分真实标题和误识别的规则文本
            if self._is_valid_section_title(title):
                return {
                    'section_id': section_id,
                    'title': title
                }

        # ==== Branch 3: "Appendix A." or "APPENDIX B.1" (with required delimiter) ====
        # 例如：
        # - "Appendix A.  Pseudo-ASN.1 Structures and OIDs"  ← 真实附录标题(RFC,句点)
        # - "Appendix B: ASN.1 Notes"                          ← 真实附录标题(冒号)
        # - "APPENDIX C."                                    ← 真实附录标题（只有句点）
        # - "Appendix A – CAA Contact Tag"                   ← CABF BR(en-dash U+2013)
        # 不匹配 "Appendix A, in order to..." (逗号后是正文，不是标题)
        # 分隔符类必须涵盖 en-dash(–,–)/em-dash(—,—)：CABF-BR 的 markdown
        # 附录标题 "# Appendix A – …"/"# Appendix B – …" 用 en-dash 连接标题，'# ' 前缀
        # 已在上面剥除，但旧的 [.:-] 只认 ASCII 连字符，导致整段附录(含 .onion 的
        # "CA MUST verify…")塌进前一个数字节(实测错挂到 §9.17)，附录 section 计数=0。
        appendix_match = re.match(
            r'^appendix\s+([A-Za-z](?:\.\d+)*)\s*[.:–—-]\s*(.*)$',
            line_stripped,
            re.IGNORECASE
        )

        if appendix_match:
            section_id = appendix_match.group(1).upper()  # A -> A, B.1 -> B.1
            title = appendix_match.group(2).strip()

            # 如果标题为空，使用 "Appendix {section}" 作为标题
            if not title:
                title = f"Appendix {section_id}"

            # 附录标题验证：只接受符合以下条件的标题：
            # 1. 是 "Appendix {Letter}" 格式（标题就是附录标识）
            # 2. 是简短的描述性标题（不含完整句子）
            # 不接受正文中的句子（如 "Appendix C.1 contains..."）

            # 过滤正文句子：包含完整句子的开头（动词不定式短语）
            if re.match(r'^\d+\s+\w+', title):
                # 形如 "1 contains...", "2 describes..." → 正文句子，拒绝
                pass
            elif self._is_valid_section_title(title):
                return {
                    'section_id': section_id,
                    'title': title
                }

        return None

    def _is_valid_section_title(self, title: str) -> bool:
        """
        智能判断文本是否是真正的章节标题（而非被误识别的规则文本）

        章节标题特征：
        - 名词短语或简短描述性文本
        - 不包含完整的主谓宾句子结构
        - 不包含规范性关键词（MUST, SHALL等）
        - 不包含列表项编号
        - 基于语言学特征而非长度判断

        Args:
            title: 候选标题文本

        Returns:
            True: 是有效的章节标题
            False: 可能是误识别的规则文本
        """
        title_lower = title.lower()

        # 规则0a: 标题只是数字 → 可能是OID最后一段（如 2.5.4.6 → title="6"）
        if re.match(r'^\d+$', title.strip()):
            return False

        # 规则0b: TOC条目 → 包含连续的点号（如 "OCSP extensions .........."）
        if '...' in title:
            return False

        # 规则0: 包含列表项编号 → 这是列表项，不是章节标题
        # 匹配: "2)", "a)", "(1)", "[RFC3279]", "1.", "a."
        list_item_patterns = [
            r'^\d+\)',  # 1), 2), 10)
            r'^[a-z]\)',  # a), b), c)
            r'^\([a-z0-9]+\)',  # (a), (1), (i)
            r'^\[[A-Z]+\d*\]',  # [RFC3279], [CABF], [A]
            r'^\d+\.',  # 1., 2., 10.
            r'^[a-z]\.',  # a., b., c.
        ]
        if any(re.search(pattern, title) for pattern in list_item_patterns):
            app_logger.debug(f"[RuleDiscovery] Rejected title (list item): {title[:60]}...")
            return False

        # 规则1: 包含规范性关键词 → 极可能是规则文本
        normative_keywords = ['must', 'shall', 'should', 'may', 'must not', 'shall not', 'should not', 'may not']
        if any(kw in title_lower for kw in normative_keywords):
            return False

        # 规则2: 包含完整句子的标志（主语+动词结构）
        # 检查是否以冠词+名词+动词开头（典型的句子模式）
        sentence_pattern = r'^(the|a|an|this|these|those|all|each|every)\s+\w+\s+(is|are|was|were|has|have|will|can|may|must|shall|should|do|does)'
        if re.search(sentence_pattern, title_lower):
            return False

        # 规则3: 包含常见的规则动作动词 → 可能是规则
        # 但要区分：标题可能包含动词（如"Validating Domain Names"），这是可以的
        # 真正的问题是：完整的动词短语（如"MUST validate"）
        rule_action_patterns = [
            r'\b(verify|validate|check|ensure|confirm|perform|conduct|execute|implement|enforce)\s+(the|that|all|each)',
            r'\b(generate|create|produce|issue|revoke|sign|encode|decode)\s+(a|an|the|all)',
            r'\b(include|contain|comprise|have|possess)\s+(a|an|the|all)',
        ]
        if any(re.search(pattern, title_lower) for pattern in rule_action_patterns):
            return False

        # 规则4: 复杂从句结构分析（基于语言学特征，不依赖长度）
        # 检查从句标志的多样性和密度
        clause_markers = {
            'coordination': [' and ', ' or '],  # 并列连词
            'subordination': [' unless ', ' except ', ' if ', ' when ', ' where '],  # 从属连词
            'relative': [' that ', ' which ', ' who ']  # 关系代词
        }

        marker_categories_found = 0
        total_marker_count = 0

        for category, markers in clause_markers.items():
            category_count = sum(1 for marker in markers if marker in title_lower)
            if category_count > 0:
                marker_categories_found += 1
                total_marker_count += category_count

        # 如果包含2个以上类别的从句标志，或者单一类别出现3次以上 → 复杂句子
        if marker_categories_found >= 2 or total_marker_count >= 3:
            return False

        # 规则5: 检查是否包含典型的规则文本结构特征
        # 如：包含"in accordance with", "as specified in", "as described in"
        reference_phrases = ['in accordance with', 'as specified in', 'as described in', 'pursuant to', 'subject to']
        if any(phrase in title_lower for phrase in reference_phrases):
            return False

        # 规则6: 条件从句标志检测（无长度限制）
        # 条件结构是规则文本的强特征，标题很少使用条件结构
        conditional_patterns = [
            r'\bif\s+',
            r'\bunless\s+',
            r'\bexcept\s+(when|where|if)',
            r'\bprovided\s+that',
            r'\bin\s+cases?\s+where'
        ]
        if any(re.search(pattern, title_lower) for pattern in conditional_patterns):
            return False

        # 规则7: 检查是否是列表项（以数字或字母开头后跟冠词）
        # 例如："1. The CA MUST..."（这应该已经在外层过滤了，但双保险）
        if re.match(r'^(\d+[.)]\s+)?(the|a|an)\s+\w+\s+(must|shall|should|may)', title_lower):
            return False

        # 规则8: 动词密度分析（句子包含更多动词）
        # 统计主要动作动词数量
        main_verbs = [
            r'\b(is|are|was|were|be|been|being)\b',  # be动词
            r'\b(has|have|had)\b',  # have动词
            r'\b(do|does|did|done)\b',  # do动词
            r'\b(verify|validate|check|ensure|confirm|perform|generate|create|produce|issue|revoke|sign|encode|decode|include|contain|implement|enforce|conduct|execute)\b',  # 动作动词
        ]

        verb_count = sum(1 for pattern in main_verbs if re.search(pattern, title_lower))

        # 如果包含2个以上主要动词 → 可能是完整句子
        # 标题通常只有1个动词（如"Validating Domains"）或0个（如"Certificate Extensions"）
        if verb_count >= 2:
            return False

        # 规则9: 标点符号模式分析
        # 句子特征：包含逗号、分号、句号、冒号后跟完整句子
        # 标题特征：简单结构，可能有冒号但后面是短语

        # 检查是否包含分号（分号连接独立句子，标题不会用）
        if ';' in title:
            return False

        # 检查是否以句号结尾（标题不以句号结尾）
        if title.rstrip().endswith('.'):
            return False

        # 检查逗号数量（多个逗号通常表示复杂句子结构）
        comma_count = title.count(',')
        if comma_count >= 3:  # 3个以上逗号 → 复杂句子
            return False

        # 如果通过所有检查，认为是有效的章节标题
        return True

    def _extract_markdown_table_rows(self, text: str) -> tuple:
        """
        Extract per-row normative sentences from markdown pipe-delimited tables.

        Markdown tables use:
            | col1 | col2 | col3 |
            |------|------|------|
            | val1 | val2 | val3 |
            ...

        The default sentence splitter has no `|` awareness, so an entire table
        is collapsed into a single non-bullet "sentence" and Layer 2 ends up with
        a multi-field merged rule. This pre-processor:

          - Finds blocks of >= 3 consecutive pipe-prefixed lines.
          - Skips the alignment line (e.g., `|---|---|`).
          - Skips header rows (no normative keyword AND not visible in row body).
          - For each data row, emits one virtual sentence "col1 | col2 | ... | colN"
            (without leading/trailing pipes) so the row is treated as a single
            atomic skeleton in Layer 1.
          - Leaves table-row lines in the remaining text consumed (replaced with
            blank lines) to preserve line numbers but avoid double-counting.

        A row qualifies as "data" if it contains an RFC2119 keyword OR a Y/N
        column marker (common in CABF tables for mandatory/optional flags).

        Returns:
            (table_row_sentences, remaining_text)
        """
        rfc2119_re = re.compile(
            r'\b(?:MUST(?:\s+NOT)?|SHALL(?:\s+NOT)?|SHOULD(?:\s+NOT)?|'
            r'REQUIRED|RECOMMENDED|PROHIBITED|NOT\s+RECOMMENDED|MAY|OPTIONAL)\b'
        )
        # Y/N single-letter columns (with surrounding whitespace) marking
        # mandatory / forbidden in CABF profile tables.
        yn_marker_re = re.compile(r'\|\s*[YNyn]\s*\|')
        alignment_re = re.compile(r'^\s*\|?\s*:?-{2,}:?\s*(\|\s*:?-{2,}:?\s*)+\|?\s*$')

        lines = text.split('\n')
        n = len(lines)
        consumed = set()
        table_rows: List[str] = []

        i = 0
        while i < n:
            line = lines[i]
            if line.lstrip().startswith('|'):
                start = i
                while i < n and lines[i].lstrip().startswith('|'):
                    i += 1
                end = i
                block_len = end - start
                if block_len < 3:
                    continue  # too short to be a table
                # Inspect block: header (first row), optional alignment row, then data rows
                block_lines = lines[start:end]
                # Drop the alignment row if present
                data_rows = []
                header_seen = False
                for idx, raw in enumerate(block_lines):
                    if alignment_re.match(raw):
                        continue  # skip ----|---- separator
                    if not header_seen:
                        header_seen = True
                        continue  # skip header
                    data_rows.append((start + idx, raw))

                # Only treat as a real table if at least one data row carries a
                # normative marker; otherwise leave the block alone (e.g., decorative
                # ASCII art).
                if not any(rfc2119_re.search(r) or yn_marker_re.search(r)
                           for _, r in data_rows):
                    continue

                for line_idx, raw in data_rows:
                    # Convert "| `field` | MUST NOT be present | ... |" into
                    # "`field` | MUST NOT be present | ..." (strip outer pipes,
                    # keep inner ones as readable separators)
                    cleaned = raw.strip()
                    if cleaned.startswith('|'):
                        cleaned = cleaned[1:]
                    if cleaned.endswith('|'):
                        cleaned = cleaned[:-1]
                    cleaned = cleaned.strip()
                    if not cleaned:
                        continue
                    # Only keep rows that themselves carry a normative marker.
                    # (A pure descriptive row inside an otherwise-normative table
                    # would otherwise produce an unfiltered IR.)
                    if not (rfc2119_re.search(cleaned) or yn_marker_re.search('|' + cleaned + '|')):
                        continue
                    table_rows.append(cleaned)
                    consumed.add(line_idx)
                continue
            i += 1

        if not table_rows:
            return [], text

        # Replace consumed lines with blank lines to preserve line numbering
        remaining_lines = [
            ('' if idx in consumed else lines[idx])
            for idx in range(n)
        ]
        remaining_text = '\n'.join(remaining_lines)

        app_logger.info(
            f"[RuleDiscovery] Extracted {len(table_rows)} markdown table-row sentences"
        )
        return table_rows, remaining_text

    def _extract_table_encoding_sentences(self, text: str) -> tuple:
        """
        Extract normative encoding statements from inline table data.

        When PyMuPDF fails to detect PDF tables (e.g., CABF BR Table 85/86),
        the table content is rendered as column-interleaved plain text:

            domainComponent
            0.9.2342.19200300.100.1.25
            RFC 4519
            MUST use IA5String
            63

        This method detects such patterns and reconstructs proper sentences
        like "domainComponent MUST use IA5String (max 63)".

        Returns:
            (table_sentences, remaining_text)
        """
        # Known X.500/X.520 attribute names from CABF BR Table 85/86
        known_attributes = {
            'domainComponent', 'countryName', 'stateOrProvinceName',
            'localityName', 'postalCode', 'streetAddress',
            'organizationName', 'surname', 'givenName',
            'organizationalUnitName', 'commonName', 'businessCategory',
            'jurisdictionCountry', 'jurisdictionStateOrProvince',
            'jurisdictionLocality', 'serialNumber', 'organizationIdentifier',
        }

        lines = text.split('\n')
        table_sentences = []
        consumed_lines = set()  # line indices consumed by table extraction
        rfc2119_re = re.compile(
            r'^(MUST(?:\s+NOT)?|SHALL(?:\s+NOT)?)\s+(?:use|be)\b',
            re.IGNORECASE,
        )
        oid_re = re.compile(r'^\d+(?:\.\d+){3,}$')  # e.g. 2.5.4.6

        i = 0
        while i < len(lines):
            line = lines[i].strip()

            # Check if this line is a known attribute name (exact match)
            if line in known_attributes:
                attr_name = line
                consumed = [i]

                # Look ahead: expect OID, spec, encoding requirement, max length
                j = i + 1
                encoding_parts = []
                max_length = None
                found_encoding = False

                while j < len(lines) and j <= i + 10:
                    ahead = lines[j].strip()
                    if not ahead:
                        j += 1
                        continue

                    # Stop if we hit the next attribute name
                    if ahead in known_attributes:
                        break

                    # Stop if we hit a section header (e.g. "7.1.4.2 Title")
                    # but NOT an OID (e.g. "0.9.2342.19200300.100.1.25")
                    # Section headers have digits.digits followed by a space and text
                    if (re.match(r'^\d+\.\d+(?:\.\d+)*\s+[A-Z]', ahead) or
                            ahead.startswith('Table ')):
                        break

                    consumed.append(j)

                    if rfc2119_re.match(ahead):
                        # Start of encoding requirement
                        found_encoding = True
                        encoding_parts.append(ahead)
                    elif ahead == 'None':
                        # Explicit "no max length" marker
                        max_length = 'None'
                        break
                    elif found_encoding and re.match(r'^\d+', ahead):
                        # Max length (possibly with footnote number appended)
                        # e.g. "63", "6416" (64 + footnote 16), "2"
                        max_length = ahead
                        break
                    elif found_encoding and not re.match(r'^\d+$', ahead):
                        # Continuation of encoding requirement (e.g., "PrintableString")
                        # but not a number (which would be max length)
                        encoding_parts.append(ahead)

                    j += 1

                if found_encoding and encoding_parts:
                    encoding = ' '.join(encoding_parts)
                    if max_length and max_length != 'None':
                        # Handle footnote numbers: if length > 3 digits,
                        # only first few digits are the actual length
                        length_str = max_length
                        if len(length_str) > 3:
                            # Heuristic: common max lengths are 2, 40, 63, 64, 128
                            for known_len in ['128', '64', '63', '40']:
                                if length_str.startswith(known_len):
                                    length_str = known_len
                                    break
                        sentence = f"{attr_name} {encoding} (max {length_str})"
                    elif max_length == 'None':
                        sentence = f"{attr_name} {encoding}"
                    else:
                        sentence = f"{attr_name} {encoding}"
                    table_sentences.append(sentence)
                    consumed_lines.update(consumed)
                    app_logger.debug(
                        f"[RuleDiscovery] Extracted table encoding: {sentence}"
                    )

            i += 1

        if not table_sentences:
            return [], text

        # Rebuild text without consumed lines
        remaining_lines = [
            lines[i] for i in range(len(lines)) if i not in consumed_lines
        ]
        remaining_text = '\n'.join(remaining_lines)

        app_logger.info(
            f"[RuleDiscovery] Extracted {len(table_sentences)} encoding rules "
            f"from inline table data"
        )
        return table_sentences, remaining_text

    def _split_sentences(self, text: str) -> List[str]:
        """
        分句策略

        策略：
        - 预处理：从内联表格数据中提取编码约束语句
        - 首先按 bullet 标记分割（保留列表项结构）
        - 然后按句号、问号、感叹号分割
        - 对包含多个RFC2119关键字的句子，尝试按分隔符切分：
          1. 分号 (;)
          2. 带逗号的连接词 (, and / , or) - 优先
          3. 不带逗号的连接词 ( and / or ) - 备选
        - 验证：每个部分都有关键字则保持切分
        - 合并破碎片段（以and/or/but开头或使用代词的不完整句子）
        - 支持文本末尾的句子
        """
        # ========== Stage 0a: Extract per-row sentences from markdown pipe-tables ==========
        md_table_sentences, text = self._extract_markdown_table_rows(text)

        # ========== Stage 0b: Extract encoding rules from inline table data (PDF artefact) ==========
        table_sentences, text = self._extract_table_encoding_sentences(text)
        # Markdown table rows are pre-formed sentences; merge them with PDF table sentences.
        table_sentences = md_table_sentences + table_sentences

        # ========== Stage 0c: protect dotted-numeric sequences from period-splitting ==========
        # OIDs ("2.23.140.1.2.3") and section refs ("7.1.2.7.9") contain interior
        # periods. The downstream sentence/assertion splitters break on '.', which
        # mid-truncates these tokens ("...of `2.23.140.1.2") and loses the rest of
        # the rule — leaving an un-judgeable fragment. Mask the period BETWEEN digits
        # with a sentinel before splitting and restore it on the way out; the splitter
        # then only ever breaks on real sentence-ending periods. General + sound:
        # a period flanked by digits is never an English sentence boundary.
        text = re.sub(r'(?<=\d)\.(?=\d)', '\x00', text)
        table_sentences = [re.sub(r'(?<=\d)\.(?=\d)', '\x00', s) for s in table_sentences]

        # ========== Stage 0.5: 预处理 ETSI WEB/SEC/GEN-X.X.X-N: 标记 ==========
        # ETSI 规则 ID 标记视为新句子开始，在其前插入换行
        text = re.sub(
            r'(?<=[^\n])\s*((?:WEB|SEC|GEN|NAT|LEI|EVG|QWEB)-\d+(?:\.\d+)*-\d+:)',
            r'\n\1', text
        )

        # ========== Enhanced: 首先识别并保留 bullet 列表项 ==========
        # 匹配 bullet 标记的模式（含 ETSI WEB-/SEC-/GEN- 规则ID标记）
        bullet_pattern = re.compile(
            r'^\s*[*\-+•]\s+|'           # *, -, +, • 开头
            r'^\s*\([a-z]\)\s+|'         # (a), (b), (c)
            r'^\s*[a-z]\)\s+|'           # a), b), c)
            r'^\s*\d+\)\s+|'             # 1), 2), 3)
            r'^\s*\d+\.\s+|'             # 1., 2., 3.
            r'^\s*[ivxIVX]+\)\s+|'       # i), ii), iii)
            r'^\s*\([ivxIVX]+\)\s+|'     # (i), (ii), (iii)
            r'^\s*In step \d+|'          # "In step 1, ..."
            r'^\s*(?:WEB|SEC|GEN|NAT|LEI|EVG|QWEB)-\d+(?:\.\d+)*-\d+:',  # ETSI rule IDs
            re.MULTILINE
        )

        # 按行分割，识别 bullet 项
        lines = text.split('\n')
        pre_sentences = []
        current_non_bullet = []

        # ========== site-3: ASN.1 感知分句 ==========
        # RFC 5280 Appendix A 等区块用 `Name ::= SEQUENCE { … }` 描述结构：字段以
        # 裸逗号分隔、规范约束写在 `-- … MUST …` 注释里。沿用散文逻辑会把整块用空格
        # 拼成一个巨块（实测单句长达 9191 字符），导致 ① OPTIONAL 字段被埋进噪声骨架、
        # ② 附录独有的 `-- MUST` 注释（authorityCertIssuer 配对 / PrivateKeyUsagePeriod）
        # 在后续按 ' or ' 切分时整句丢失（probe COVERED=0）。
        # 修复：在 ASN.1 块内逐行成句、把跨行 `--` 注释拼回单句；散文区逻辑完全不变
        # ——仅 `::=` / 花括号 / 行首 `--` 触发，散文不含这些 ASN.1/BNF 记号。
        asn1_depth = 0       # 花括号嵌套深度，>0 表示当前仍在 ASN.1 块内
        comment_buf = []     # 连续 `--` 注释行（同一条注释常跨行，需拼回再成句）

        def _flush_comment():
            """把累积的跨行 `--` 注释拼成一句加入 pre_sentences。"""
            if comment_buf:
                merged = ' '.join(comment_buf).strip()
                if merged:
                    pre_sentences.append(merged)
                comment_buf.clear()

        for line in lines:
            line = line.strip()
            if not line:
                # 空行结束一条跨行 ASN.1 注释；散文累积沿用原行为（空行不 flush）
                _flush_comment()
                continue

            # ---- ASN.1 注释行（`-- …`）：自成一类，跨行拼回单句 ----
            # 散文不会以 `--` 起行；markdown frontmatter/分隔线 `---` 去标记后为空，自动忽略。
            # 单破折号 bullet（`- foo`）不会进入此分支（其后是空白而非 `-`）。
            if line.startswith('--'):
                comment_text = re.sub(r'\s*--\s*$', '', line.lstrip('-').strip())
                if comment_text:
                    comment_buf.append(comment_text)
                continue
            # 抵达非注释行，先收尾未完成的注释
            _flush_comment()

            # ---- ASN.1 结构/字段行：`Name ::= …` 或仍处于花括号块内 ----
            # `::=` 是纯 ASN.1/BNF 记号、散文绝不出现；据此 + 花括号配对限定作用域。
            # 块内每行单独成句（使每个 OPTIONAL 字段成为独立骨架），且先于 bullet 判定，
            # 避免把 ASN.1 字段行误判为列表项。
            if '::=' in line or asn1_depth > 0:
                if current_non_bullet:
                    pre_sentences.append(' '.join(current_non_bullet))
                    current_non_bullet = []
                asn1_depth += line.count('{') - line.count('}')
                if asn1_depth < 0:
                    asn1_depth = 0
                pre_sentences.append(line)
                continue

            if bullet_pattern.match(line):
                # 遇到 bullet 项，先保存之前的非 bullet 文本
                if current_non_bullet:
                    combined = ' '.join(current_non_bullet)
                    pre_sentences.append(combined)
                    current_non_bullet = []
                # 保存 bullet 项（去除 bullet 标记），并追加后续 continuation 行
                clean_line = re.sub(r'^\s*[*\-+•]\s+', '', line)
                clean_line = re.sub(r'^\s*\([a-z]\)\s+', '', clean_line)
                clean_line = re.sub(r'^\s*[a-z]\)\s+', '', clean_line)
                clean_line = re.sub(r'^\s*\d+[.)]\s+', '', clean_line)
                clean_line = re.sub(r'^\s*[ivxIVX]+\)\s+', '', clean_line)
                clean_line = re.sub(r'^\s*\([ivxIVX]+\)\s+', '', clean_line)
                # Strip ETSI rule ID labels (e.g., "WEB-4.3.1-1:", "SEC-5.2.3-2:")
                clean_line = re.sub(r'^\s*(?:WEB|SEC|GEN|NAT|LEI|EVG|QWEB)-\d+(?:\.\d+)*-\d+:\s*', '', clean_line)
                # 将 bullet 项放入 current_non_bullet，后续行作为 continuation
                current_non_bullet = [clean_line.strip()]
            else:
                current_non_bullet.append(line)

        # 收尾：剩余 ASN.1 注释 + 非 bullet 文本
        _flush_comment()
        # 保存剩余的非 bullet 文本
        if current_non_bullet:
            combined = ' '.join(current_non_bullet)
            pre_sentences.append(combined)

        # ========== 第一步：按句号、问号、感叹号分割 ==========
        sentences = []
        for pre_sent in pre_sentences:
            # (?:\s+|$) 表示：空格 或 文本末尾
            parts = re.split(r'[.!?](?:\s+|$)', pre_sent)
            parts = [p.strip() for p in parts if p.strip()]
            sentences.extend(parts)

        # RFC2119关键字模式
        rfc2119_pattern = r'\b(?:MUST(?:\s+NOT)?|SHALL(?:\s+NOT)?|SHOULD(?:\s+NOT)?|MAY|REQUIRED|RECOMMENDED|OPTIONAL)\b'

        # 第二步：对包含多个RFC2119关键字的句子，尝试按分隔符切分
        final_sentences = []
        for sentence in sentences:
            sentence = sentence.strip()
            if not sentence:
                continue

            # 统计RFC2119关键字数量
            keywords_count = len(re.findall(rfc2119_pattern, sentence))

            if keywords_count > 1:
                # 尝试多种分隔符（按优先级排序）
                split_patterns = [
                    (';', r';'),  # 分号分隔
                    (', and', r',\s+and\s+'),  # ", and" 分隔（带逗号，优先）
                    (', or', r',\s+or\s+'),  # ", or" 分隔（带逗号，优先）
                    (', but', r',\s+but\s+'),  # ", but" 分隔（对比关系）
                    (' and ', r'\s+and\s+'),  # " and " 分隔（不带逗号，备选）
                    (' or ', r'\s+or\s+'),  # " or " 分隔（不带逗号，备选）
                    (' but ', r'\s+but\s+'),  # " but " 分隔（不带逗号，备选）
                ]

                split_success = False
                for delimiter_name, delimiter_pattern in split_patterns:
                    if re.search(delimiter_pattern, sentence):
                        # 按分隔符切分
                        parts = re.split(delimiter_pattern, sentence)
                        parts = [p.strip() for p in parts if p.strip()]

                        # 验证：每个部分是否包含RFC2119关键字
                        valid_parts = []
                        for part in parts:
                            if re.search(rfc2119_pattern, part):
                                valid_parts.append(part)
                            else:
                                # 如果某个部分没有RFC2119关键字，说明分隔符不是规则分隔符
                                # 保留原句子不切分
                                valid_parts = []
                                break

                        if len(valid_parts) > 1:
                            # 成功按分隔符切分，每个部分都有RFC2119关键字
                            # 跳过合并检查，直接加入结果
                            final_sentences.extend(valid_parts)
                            split_success = True
                            app_logger.debug(
                                f"[RuleDiscovery] Split by '{delimiter_name}' into {len(valid_parts)} parts"
                            )
                            break

                if split_success:
                    continue

                # Try period-based splitting FIRST for multi-sentence text
                # This handles cases like "When comparing DNS names for equality, MUST...MUST..."
                # where two distinct sentences are joined but should be separate rules
                # Note: Use regex to handle multiple spaces after periods (e.g., "field.  Specifically")
                if re.search(r'\.\s+', sentence):
                    # Split by period + one or more whitespace (sentence boundary)
                    period_parts = []
                    for part in re.split(r'\.\s+', sentence):
                        part = part.strip()
                        if part:
                            period_parts.append(part)

                    # Validate each part has a keyword
                    valid_period_parts = []
                    for part in period_parts:
                        if re.search(rfc2119_pattern, part):
                            valid_period_parts.append(part)

                    # If period-based split successfully separates all keywords, use it
                    if len(valid_period_parts) >= keywords_count:
                        final_sentences.extend(valid_period_parts)
                        app_logger.debug(
                            f"[RuleDiscovery] Split by period into {len(valid_period_parts)} parts "
                            f"(keywords_count: {keywords_count})"
                        )
                        continue

                # 最后备选：如果句子包含多个相同的RFC2119关键词，尝试按逗号拆分
                # 条件：至少有2个相同的关键词，且每个逗号分隔的部分都包含该关键词
                keywords = re.findall(rfc2119_pattern, sentence)
                if len(keywords) >= 2 and len(set(keywords)) == 1:  # 所有关键词相同
                    # 尝试按逗号拆分
                    comma_parts = [p.strip() for p in sentence.split(',') if p.strip()]

                    # 验证每个部分是否包含RFC2119关键字
                    valid_comma_parts = []
                    for part in comma_parts:
                        if re.search(rfc2119_pattern, part):
                            valid_comma_parts.append(part)

                    # 如果拆分后的部分数等于关键词数，说明这是并列的独立规则
                    if len(valid_comma_parts) == len(keywords):
                        final_sentences.extend(valid_comma_parts)
                        app_logger.debug(
                            f"[RuleDiscovery] Split by comma into {len(valid_comma_parts)} parts "
                            f"(all parts have same keyword: {keywords[0]})"
                        )
                        continue

            # 没有按任何方式切分，保留原句
            final_sentences.append(sentence)

        # 第三步：合并破碎片段
        final_sentences = self._merge_incomplete_fragments(final_sentences)

        # 第四步：将表格提取的编码约束语句加入结果
        if table_sentences:
            final_sentences.extend(table_sentences)

        # Restore the dotted-numeric periods masked in Stage 0c (OIDs / section refs).
        final_sentences = [s.replace('\x00', '.') for s in final_sentences]

        return final_sentences

    def _merge_incomplete_fragments(self, sentences: List[str]) -> List[str]:
        """
        合并破碎的句子片段（compose应该在这里进行）

        检测不完整的片段并与前一句合并：
        1. 以连接词开头且没有主语："and MUST...", "or MUST...", "but MUST..."
        2. 以代词开头："It MUST...", "They MUST...", "This MUST..."
        3. 缺少主语的从句

        **重要：如果当前句和前一句都包含RFC2119关键字，不合并（独立规则）**

        Args:
            sentences: 初步分割的句子列表

        Returns:
            合并后的句子列表
        """
        if not sentences:
            return sentences

        # RFC2119关键字模式（用于检查独立规则）
        rfc2119_pattern = r'\b(?:MUST(?:\s+NOT)?|SHALL(?:\s+NOT)?|SHOULD(?:\s+NOT)?|MAY|REQUIRED|RECOMMENDED|OPTIONAL)\b'

        merged = []
        i = 0

        while i < len(sentences):
            current = sentences[i].strip()

            # ⭐ 关键检查：如果当前句和前一句都包含RFC2119关键字，不合并
            if merged:
                previous = merged[-1]
                current_has_keyword = bool(re.search(rfc2119_pattern, current))
                previous_has_keyword = bool(re.search(rfc2119_pattern, previous))

                if current_has_keyword and previous_has_keyword:
                    # 两个独立的规则，不合并
                    merged.append(current)
                    i += 1
                    continue

            # 检查当前句子是否是破碎片段
            is_fragment = self._is_incomplete_fragment(current)

            if is_fragment and merged:
                # 是破碎片段，且前面有句子 → 合并到前一句
                merged[-1] = merged[-1] + '; ' + current
                app_logger.debug(
                    f"[RuleDiscovery] Merged fragment '{current[:50]}...' "
                    f"into previous sentence"
                )
            else:
                # 不是破碎片段 或 是第一句 → 作为独立句子
                merged.append(current)

            i += 1

        return merged

    def _is_incomplete_fragment(self, sentence: str) -> bool:
        """
        判断句子是否是不完整的片段（需要与前句合并）

        核心判断逻辑：
        1. 以连接词开头 → 依赖前句，是片段
        2. 以代词开头 → 指代不明，是片段
        3. 包含RFC2119关键词但缺少明确主语 → 是片段

        Args:
            sentence: 句子文本

        Returns:
            True: 是破碎片段，需要合并
            False: 是完整句子，可以独立
        """
        sentence_stripped = sentence.strip()
        sentence_lower = sentence_stripped.lower()

        # 规则1: 以连接词开头（表示依赖前句的延续）
        # 例如: "and be marked critical", "or include digitalSignature"
        if re.match(r'^(and|or|but)\s+', sentence_lower):
            app_logger.debug(f"[Fragment Detection] Starts with conjunction: {sentence[:60]}...")
            return True

        # 规则2: 以代词开头（指代不明确，需要前句提供上下文）
        # 例如: "It MUST include...", "This SHALL be...", "They SHOULD..."
        # 但排除正常的陈述句，如 "It is recommended that..."
        if re.match(r'^(it|this|that|these|those|they)\s+', sentence_lower):
            # 进一步检查：代词后是否直接跟动词/关键词（而不是"is/are/was/were"等系动词）
            # 如果是 "It MUST", "This SHALL" → 破碎片段
            # 如果是 "It is recommended" → 完整句子
            has_immediate_action = re.match(
                r'^(it|this|that|these|those|they)\s+('
                r'must|shall|should|may|must\s+not|shall\s+not|should\s+not|'
                r'verify|validate|check|ensure|include|contain'
                r')\s+',
                sentence_lower
            )
            if has_immediate_action:
                app_logger.debug(f"[Fragment Detection] Pronoun with immediate action: {sentence[:60]}...")
                return True

        # ETSI/CABF delegation scaffolds often produce clause fragments like
        # "following requirements shall apply" after punctuation splitting.
        # Keep them attached to the preceding sentence so downstream extraction
        # sees the real subject/reference anchor instead of a bare modal clause.
        if re.match(
            r'^(following\s+requirements\s+shall\s+apply|'
            r'clause\s+\d+(?:\.\d+)*\s+shall\s+apply|'
            r'\d+(?:\.\d+)*\s+shall\s+apply|'
            r'and\s+extensions\s+shall\s+comply\b)',
            sentence_lower,
            re.IGNORECASE,
        ):
            app_logger.debug(f"[Fragment Detection] Delegation scaffold fragment: {sentence[:60]}...")
            return True

        # Cross-sentence carry-over fragments such as "The following certificate
        # profile requirements ... shall apply" or "3 of the present document..."
        # depend on the preceding sentence to recover the referenced clause.
        if re.match(
            r'^(the\s+following\s+certificate\s+profile\s+requirements\b|'
            r'\d+\s+of\s+the\s+present\s+document\s+shall\s+apply\b)',
            sentence_lower,
            re.IGNORECASE,
        ):
            app_logger.debug(f"[Fragment Detection] Cross-sentence carry-over fragment: {sentence[:60]}...")
            return True

        # Rules that only say "as defined in ... the following requirements shall apply"
        # are not standalone constraints; they should stay with the surrounding anchor.
        if re.search(r'as defined in .*the following requirements shall apply', sentence_lower):
            app_logger.debug(f"[Fragment Detection] Definition scaffold fragment: {sentence[:60]}...")
            return True

        # 规则3: Check for common RFC subjects that are valid (not fragments)
        # Sentences starting with "Implementations", "Conforming implementations", "CAs", "Relying parties"
        # are complete subjects and should NOT be merged with previous sentences
        if re.match(r'^(Implementations?|Conforming\s+implementations?|CAs?|Relying\s+parties?)\s+', sentence, re.I):
            app_logger.debug(f"[Fragment Detection] Has explicit RFC subject: {sentence[:60]}...")
            return False  # Not a fragment - has explicit subject

        # 规则4: 包含RFC2119关键词但缺少明确主语
        # 检查句子中是否包含任何RFC2119关键词
        has_rfc2119_keyword = False
        keyword_position = -1

        for keyword, pattern in self.keyword_patterns:
            match = pattern.search(sentence)
            if match:
                has_rfc2119_keyword = True
                keyword_position = match.start()
                break

        if has_rfc2119_keyword and keyword_position >= 0:
            # 提取关键词前面的文本
            text_before_keyword = sentence[:keyword_position].strip().lower()

            # 检查关键词前是否有明确的主语
            # 明确主语的模式：
            # - "the/a/an + 名词短语"（支持多个单词，允许末尾标点）
            # - 专有名词: "CA", "Issuing CA", "Subscriber"
            # - 证书相关术语: "certificate", "extension", "field", "value"
            has_explicit_subject = bool(re.search(
                r'(the|a|an)\s+[\w\s"\'()@.,-]{1,150}$|'
                r'\b(ca|issuing\s+ca|subordinate\s+ca|root\s+ca|subscriber|applicant|relying\s+party)\s*["\']?\s*$|'
                r'\b(implementations?|conforming\s+implementations?|certificate|extension|field|attribute|value|key|signature|issuer|subject|name|address|identit(?:y|ies)|use|representation)\s*["\']?\s*$',
                text_before_keyword,
                re.IGNORECASE
            ))

            if not has_explicit_subject:
                # 关键词前没有明确主语，可能是破碎片段
                # 但要排除以关键词开头的完整祈使句（如果整个文档风格都是这样）
                if keyword_position <= 2:
                    app_logger.debug(f"[Fragment Detection] Starts with RFC2119 keyword (may be imperative style): {sentence[:60]}...")
                    if len(sentence_stripped) < 30:
                        return True
                    else:
                        return False
                else:
                    app_logger.debug(f"[Fragment Detection] RFC2119 keyword without subject: {sentence[:60]}...")
                    return True

        # 默认：认为是完整句子
        return False

    def _extract_skeletons_from_sentence(
        self,
        sentence: str,
        document_id: str,
        section_id: Optional[str],
        section_title: Optional[str],
        sentence_index: int,
        paragraph_text: str
    ) -> List[RuleSkeleton]:
        """
        从单个句子中提取规则骨架

        关键：一个句子可能包含多个规范性关键词，需要全部提取
        例如：
        - "The CA MUST verify X and MUST NOT accept Y"
          → 2 个骨架（MUST, MUST NOT）
        """
        skeletons = []

        # === 快速过滤：跳过明显的非规则内容 ===
        sentence_lower = sentence.lower()
        sentence_upper = sentence.upper()

        # 1. RFC 2119 术语定义句（"The key words \"MUST\", \"SHALL\", ... are to be
        #    interpreted as described in [RFC2119]"）—— label-don't-drop（全量召回纪律
        #    [[feedback_no_filtering_all_noise_to_db]]）：不再整句丢弃。
        #    这类句虽多为 noise，但含 RFC2119 关键词，必须照常成骨架入库，以保证召回
        #    分母完整、可审计；is_noise 判定交由后续 Layer 2 LLM/分类阶段。
        #    pattern_type='rfc2119_terminology' 作为确定性 noise 标记下传，供分类阶段直接判 noise。
        #    （原 'the key words'/'keywords' + >=3 关键词 即 `return []` 的丢弃已移除。）
        _is_rfc2119_terminology = (
            ('the key words' in sentence_lower or 'keywords' in sentence_lower)
            and sum(1 for kw, _ in self.keyword_patterns if kw in sentence) >= 3
        )

        # 2. 跳过纯页眉/页脚/元数据（这些不包含任何有意义的内容）
        metadata_patterns = [
            r'^\s*\[?Page\s+\d+\]?',
            r'^\s*\d+\s+of\s+\d+',
            r'^\s*\d{4}-\d{2}-\d{2}',
        ]
        if any(re.match(pattern, sentence, re.IGNORECASE) for pattern in metadata_patterns):
            app_logger.debug(f"[RuleDiscovery] Skipping metadata: {sentence[:80]}...")
            return []

        # 注意：不再在此阶段过滤以下内容，因为它们违反了规则发现层的原则：
        # - Introduction/Overview章节的文本
        # - 定义性句子
        # - 结构性句子
        # - 审计流程要求
        # 这些应该在后续的LLM阶段或字段提取阶段进行过滤

        # 查找所有关键词匹配（避免重复匹配重叠位置）
        matched_positions = set()

        for keyword, pattern in self.keyword_patterns:
            for match in pattern.finditer(sentence):
                position = match.start()
                end_position = match.end()

                is_overlapping = any(
                    start <= position < end or start < end_position <= end
                    for start, end in matched_positions
                )

                if is_overlapping:
                    app_logger.debug(
                        f"[RuleDiscovery] Skipping overlapping keyword '{keyword}' "
                        f"at position {position} (already matched by longer keyword)"
                    )
                    continue

                matched_positions.add((position, end_position))

                rule_id = self._generate_rule_id(
                    document_id=document_id,
                    section_id=section_id,
                    sentence_index=sentence_index,
                    keyword_position=position
                )

                cleaned_sentence = self._clean_header_footer(sentence)
                cleaned_sentence = self._clean_table_prefix(cleaned_sentence)
                cleaned_sentence = self._clean_trailing_date(cleaned_sentence)

                skeleton = RuleSkeleton(
                    rule_id=rule_id,
                    section=section_id,
                    sentence=cleaned_sentence,
                    keyword=keyword,
                    keyword_position=position,
                    sentence_index=sentence_index,
                    line_number=None,
                    source_sentence=cleaned_sentence,
                    assertion_text=cleaned_sentence,
                    assertion_index_within_sentence=0,
                    paragraph_text=paragraph_text,
                    section_title=section_title,
                    # label-don't-drop: RFC2119 术语定义句不丢弃，带确定性标记下传供 Layer 2 判 noise
                    pattern_type='rfc2119_terminology' if _is_rfc2119_terminology else None,
                )

                skeletons.append(skeleton)

        return skeletons

    def _clean_trailing_date(self, text: str) -> str:
        """
        清理文本末尾的日期戳

        某些文档（特别是表格格式）在 PDF 解析时，日期列会被附加到规则文本末尾。
        例如："underscore characters MUST NOT be present in dNSName entries 2019-06-01"

        此函数移除末尾的日期格式：YYYY-MM-DD 或 YYYY/MM/DD

        Args:
            text: 原始文本

        Returns:
            清理后的文本
        """
        # 匹配末尾的日期模式（允许前面有空格、逗号、破折号等分隔符）
        date_patterns = [
            r'[,\s\-–—]+\d{4}[-‐/]\d{2}[-‐/]\d{2}\s*$',  # 末尾日期：YYYY-MM-DD 或 YYYY/MM/DD
            r'\s+\d{4}[-‐/]\d{2}[-‐/]\d{2}\s*$',         # 仅空格分隔的日期
        ]

        cleaned_text = text
        for pattern in date_patterns:
            cleaned_text = re.sub(pattern, '', cleaned_text)

        # 如果清理后文本变化了，记录日志
        if cleaned_text != text:
            app_logger.debug(f"[RuleDiscovery] Cleaned trailing date from: {text[:100]}... -> {cleaned_text[:100]}...")

        return cleaned_text.strip()

    def _clean_table_prefix(self, text: str) -> str:
        """
        清理文本开头的表格标题和列标题

        .. deprecated::
            With table-aware PDF extraction (PDFParser._extract_text_from_page_table_aware),
            tables are now rendered as markdown with proper column structure. This method
            is retained as a safety net but should trigger far less frequently.

        某些文档（特别是表格格式）在 PDF 解析时，表格标题和列标题会被合并到规则文本中。
        例如："Table 82: GeneralName requirements for the base field Name Type Presence Permitted Subtrees Excluded Subtrees dNSName MAY The CA MUST confirm..."

        此函数的策略：
        1. 移除 "Table XX:" 格式的明确表格标题
        2. 如果文本包含 RFC 2119 关键词，只保留从第一个关键词开始到结尾的部分（跳过列标题）

        Args:
            text: 原始文本

        Returns:
            清理后的文本
        """
        original_text = text

        # 步骤1: 移除明确的表格标题前缀 "Table XX:" 或 "表 XX："
        table_title_patterns = [
            r'^Table\s+\d+\s*:\s*[^.!?]*?(?=\s+[A-Z])',  # "Table 82: GeneralName requirements..."
            r'^表\s+\d+\s*[：:]\s*[^。！？]*?(?=\s+)',      # 中文表格标题
        ]

        for pattern in table_title_patterns:
            text = re.sub(pattern, '', text, flags=re.IGNORECASE)

        # 步骤2: 检测是否包含 RFC 2119 关键词，如果有，只保留从第一个关键词开始的文本
        # 这样可以跳过表格列标题（如 "Name Type Presence Permitted Subtrees Excluded Subtrees"）

        # 找到第一个 RFC 2119 关键词的位置
        first_keyword_pos = -1
        first_keyword = None

        for keyword, pattern in self.keyword_patterns:
            match = pattern.search(text)
            if match:
                pos = match.start()
                if first_keyword_pos == -1 or pos < first_keyword_pos:
                    first_keyword_pos = pos
                    first_keyword = keyword

        # 如果找到了 RFC 2119 关键词
        if first_keyword_pos > 0:
            # 检查关键词前面的文本是否看起来像表格列标题
            # 特征：多个大写单词，没有完整句子结构
            prefix = text[:first_keyword_pos].strip()

            # 如果前缀包含多个大写开头的单词（可能是列标题），则移除它们
            # 例如："Name Type Presence Permitted Subtrees Excluded Subtrees dNSName MAY..."
            # 保留 "dNSName" 作为第一个实际内容词
            words = prefix.split()
            if len(words) >= 3:
                # 检查是否大部分都是大写开头的单词（列标题特征）
                capital_words = sum(1 for w in words if w and w[0].isupper())
                if capital_words / len(words) > 0.6:  # 60%以上是大写开头
                    # 从最后一个单词开始保留（通常是实际内容的开始）
                    # 例如保留 "dNSName" 但移除 "Name Type Presence..."
                    text = words[-1] + ' ' + text[first_keyword_pos:]
                    app_logger.debug(f"[RuleDiscovery] Detected and removed table column headers: {prefix}")

        # 清理多余空格
        text = re.sub(r'\s+', ' ', text).strip()

        # 如果清理后文本变化了，记录日志
        if text != original_text:
            app_logger.debug(f"[RuleDiscovery] Cleaned table prefix from: {original_text[:100]}... -> {text[:100]}...")

        return text

    def _clean_header_footer(self, text: str) -> str:
        """
        清理文本中的页眉页脚信息

        RFC 文档在 PDF 解析时，页眉页脚会被合并到规则文本中。
        例如："Leontiev & Shefanovski Standards Track [Page 8] RFC 4491 Using GOST with PKIX May 2006 The GOST R 34.10-2001 public key MUST be..."

        此函数识别并移除：
        1. 作者名 + "Standards Track" 或类似文档类型
        2. 页码标记 [Page XX] 或 Page XX
        3. RFC/ETSI/TS 文档编号 + 标题 + 日期
        4. 其他页眉页脚模式

        策略：如果文本前面部分匹配页眉模式，且包含RFC关键词，则从第一个RFC关键词开始保留。

        Args:
            text: 原始文本

        Returns:
            清理后的文本
        """
        original_text = text

        # 模式1: 移除明确的页码标记
        # 例如："[Page 8]", "Page 8", "[第8页]"
        text = re.sub(r'\[?Page\s+\d+\]?', '', text, flags=re.IGNORECASE)
        text = re.sub(r'\[?第\s*\d+\s*页\]?', '', text)

        # 模式2: RFC/ETSI 文档页眉模式
        # 格式：作者 + 文档类型 + RFC编号 + 标题 + 日期
        # 例如："Leontiev & Shefanovski Standards Track RFC 4491 Using GOST with PKIX May 2006"
        rfc_header_patterns = [
            # RFC 页眉：作者 + Standards Track/Informational + RFC编号 + 标题 + 日期
            r'^.{0,100}?\b(Standards\s+Track|Informational|Experimental|Best\s+Current\s+Practice)\s+RFC\s+\d+\s+.{0,80}?\d{4}\s+',
            # ETSI 页眉：ETSI + 文档编号 + 标题 + 日期
            r'^.{0,100}?\bETSI\s+(EN|TS|ES)\s+\d+\s+.{0,80}?\d{4}\s+',
            # 简化模式：RFC编号 + 一些文字 + 4位年份
            r'^.{0,50}?\bRFC\s+\d+\s+.{10,60}?\d{4}\s+',
        ]

        for pattern in rfc_header_patterns:
            match = re.match(pattern, text, flags=re.IGNORECASE)
            if match:
                text = text[match.end():].strip()
                app_logger.debug(f"[RuleDiscovery] Removed RFC header: {match.group()[:80]}")
                break

        # 模式3: 如果前面还有残留的页眉信息（人名、文档类型等），且找到了RFC关键词，从关键词开始保留
        # 这一步作为兜底，处理上面模式未能匹配的情况
        first_keyword_pos = -1
        for keyword, pattern in self.keyword_patterns:
            match = pattern.search(text)
            if match:
                pos = match.start()
                if first_keyword_pos == -1 or pos < first_keyword_pos:
                    first_keyword_pos = pos

        if first_keyword_pos > 50:  # 如果关键词前面有超过50个字符
            prefix = text[:first_keyword_pos].strip()

            # 检查前缀是否包含页眉特征词
            header_indicators = [
                'standards track', 'informational', 'experimental',
                'rfc ', 'etsi ', 'draft', 'copyright',
                'page ', '& ', 'et al'  # 作者名特征
            ]

            has_header_indicators = any(
                indicator in prefix.lower()
                for indicator in header_indicators
            )

            if has_header_indicators:
                # 尝试找到最后一个句号或者实际内容的开始
                # 保留关键词前的最后一个完整词作为上下文
                words = prefix.split()
                if len(words) > 3:
                    # 保留最后1-2个单词 + 关键词之后的内容
                    text = ' '.join(words[-2:]) + ' ' + text[first_keyword_pos:]
                    app_logger.debug(f"[RuleDiscovery] Removed residual header: {prefix[:80]}")

        # 清理多余空格
        text = re.sub(r'\s+', ' ', text).strip()

        # 如果清理后文本变化了，记录日志
        if text != original_text and len(original_text) - len(text) > 10:  # 至少减少10个字符才记录
            app_logger.debug(f"[RuleDiscovery] Cleaned header/footer from: {original_text[:100]}... -> {text[:100]}...")

        return text

    def _extract_core_clause(
        self,
        sentence: str,
        keyword: str,
        keyword_position: int
    ) -> str:
        """
        智能提取包含RFC2119关键词的核心子句

        策略：
        1. 找到关键词位置
        2. 向前查找子句起始边界（分号、冒号、句号、列表符号）
        3. 向后查找子句结束边界（分号、句号）
        4. 返回核心子句

        这样可以提取最小的语义单元，避免包含无关的列表项

        Args:
            sentence: 完整句子
            keyword: RFC2119关键词
            keyword_position: 关键词在句子中的位置

        Returns:
            核心子句文本
        """
        # 边界检查
        if keyword_position < 0 or keyword_position >= len(sentence):
            app_logger.warning(
                f"[RuleDiscovery] Invalid keyword position {keyword_position} "
                f"for sentence length {len(sentence)}, returning full sentence"
            )
            return sentence.strip()

        # 子句分隔符（优先级从高到低）
        # 分号和句号是强分隔符，冒号和逗号是弱分隔符
        strong_delimiters = [';', '.', '!', '?']
        weak_delimiters = [':', ',']
        list_markers = ['*', '-', '•']  # 列表项标记

        # 1. 向前查找起始位置
        start_pos = 0

        # 先找最近的强分隔符
        for i in range(min(keyword_position - 1, len(sentence) - 1), -1, -1):
            if sentence[i] in strong_delimiters:
                start_pos = i + 1
                break
            # 如果遇到列表标记，也作为起始边界
            if sentence[i] in list_markers and (i == 0 or sentence[i-1] in ['\n', ' ']):
                start_pos = i + 1
                break

        # 如果没有找到强分隔符，尝试找弱分隔符（但要确保不会切得太短）
        if start_pos == 0:
            for i in range(min(keyword_position - 1, len(sentence) - 1), max(0, keyword_position - 100), -1):
                if i < len(sentence) and sentence[i] in weak_delimiters:
                    # 确保从弱分隔符到关键词之间有足够的内容（至少20个字符）
                    if keyword_position - i >= 20:
                        start_pos = i + 1
                        break

        # 2. 向后查找结束位置
        end_pos = len(sentence)

        # 先找最近的强分隔符
        keyword_end = min(keyword_position + len(keyword), len(sentence))
        for i in range(keyword_end, len(sentence)):
            if sentence[i] in strong_delimiters:
                end_pos = i + 1  # 包含分隔符
                break
            # 如果遇到列表标记（在新行或前面有多个空格），作为结束边界
            if sentence[i] in list_markers and i > 0 and (
                sentence[i-1] in ['\n'] or
                (i >= 2 and sentence[i-2:i] == '  ')
            ):
                end_pos = i
                break

        # 3. 提取核心子句
        core_clause = sentence[start_pos:end_pos].strip()

        # 4. 清理前缀（列表符号、空格等）
        core_clause = re.sub(r'^[*\-•\s]+', '', core_clause)

        return core_clause

    def _generate_rule_id(
        self,
        document_id: str,
        section_id: Optional[str],
        sentence_index: int,
        keyword_position: int
    ) -> str:
        """
        生成规则ID

        格式：{doc_id}-{section}-{sent_idx:04d}-{pos:03d}
        例如：rfc5280-4.2.1.6-0012-045
        """
        section_part = section_id if section_id else "unknown"
        # 替换点号为下划线，避免ID中有歧义
        section_part = section_part.replace('.', '_')

        return f"{document_id}-{section_part}-{sentence_index:04d}-{keyword_position:03d}"

    def get_statistics(self, skeletons: List[RuleSkeleton]) -> Dict[str, Any]:
        """获取统计信息"""
        keyword_counts = {}
        section_counts = {}

        for skeleton in skeletons:
            # 统计关键词
            keyword_counts[skeleton.keyword] = keyword_counts.get(skeleton.keyword, 0) + 1

            # 统计章节
            section = skeleton.section or "unknown"
            section_counts[section] = section_counts.get(section, 0) + 1

        return {
            'total_skeletons': len(skeletons),
            'by_keyword': keyword_counts,
            'by_section': section_counts,
            'unique_sentences': len(set(s.sentence for s in skeletons))
        }
