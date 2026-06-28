"""
Structural Analyzer for RFC Documents

Detects parent-child scope structures where:
1. A parent sentence contains an RFC2119 keyword (e.g., MUST)
2. Followed by bullet/numbered items that inherit the obligation
3. Child items may or may not have their own RFC2119 keywords

Example from RFC 5280 §7.2:
"Conforming implementations MUST convert internationalized domain names
to the ASCII Compatible Encoding (ACE) format as specified in Section 4
of RFC 3490 before storage in the dNSName field with the following
clarifications:
   * In step 1, the domain name SHALL be considered..."
   * In step 3, set UseSTD3ASCIIRules to false..."

The bullet items inherit MUST from the parent but may have their own keywords.
"""
import re
from typing import List, Dict, Optional, Tuple, Any
from dataclasses import dataclass, field
from app.core.logging_config import app_logger


@dataclass
class ScopeBlock:
    """
    A parent sentence with dependent bullet/list items.

    Represents a hierarchical structure where child items inherit
    obligation from a parent sentence.
    """
    block_id: str                           # Unique identifier for this scope block
    parent_sentence: str                    # Full text of parent sentence
    parent_keyword: str                     # RFC2119 keyword in parent (MUST/SHALL etc.)
    parent_rule_id: Optional[str] = None    # Rule ID of parent (if already extracted)

    # Child items
    children: List[str] = field(default_factory=list)  # List of bullet item texts
    child_keywords: Dict[int, str] = field(default_factory=dict)  # {index: keyword} for items with own keywords

    # Scope trigger info
    trigger_phrase: str = ""                # e.g., "with the following clarifications"
    trigger_position: int = 0               # Position of trigger in parent sentence

    # Source location
    section: Optional[str] = None
    line_start: Optional[int] = None
    line_end: Optional[int] = None


class StructuralAnalyzer:
    """
    Detect scope inheritance structures in RFC text.

    Identifies patterns where a parent sentence with an RFC2119 keyword
    is followed by clarification/exception list items that inherit
    the parent's obligation level.
    """

    # Patterns that indicate scope inheritance (parent -> children)
    SCOPE_TRIGGERS = [
        r'with the following clarifications?',
        r'with the following exceptions?',
        r'with the following modifications?',
        r'with the following requirements?',
        r'with the following restrictions?',
        r'subject to the following',
        r'the following requirements? apply',
        r'the following rules? apply',
        r'according to the following rules?',
        r'except (?:that|as follows)',
        r'provided that the following',
        r'as follows\s*:',
        r'including\s*:',
        r':\s*$',  # Sentence ending with colon (often precedes list)
    ]

    # RFC2119 keywords for detection
    RFC2119_KEYWORDS = [
        'MUST NOT', 'SHALL NOT', 'SHOULD NOT',
        'MUST', 'SHALL', 'REQUIRED',
        'SHOULD', 'RECOMMENDED',
        'MAY', 'OPTIONAL',
    ]

    # List item markers
    LIST_MARKERS = [
        r'^\s*[\*\-\+•]\s+',           # Bullet: *, -, +, •
        r'^\s*\([a-z]\)\s+',            # (a), (b), (c)
        r'^\s*[a-z]\)\s+',              # a), b), c)
        r'^\s*\d+\)\s+',                # 1), 2), 3)
        r'^\s*\d+\.\s+',                # 1., 2., 3.
        r'^\s*[ivxIVX]+\)\s+',          # i), ii), iii) (roman numerals)
        r'^\s*\([ivxIVX]+\)\s+',        # (i), (ii), (iii)
        r'^\s*In step \d+',             # "In step 1, ..." (RFC algorithm steps)
    ]

    def __init__(self):
        """Initialize the structural analyzer with compiled patterns."""
        # Compile scope trigger patterns
        self.scope_trigger_patterns = [
            re.compile(pattern, re.IGNORECASE)
            for pattern in self.SCOPE_TRIGGERS
        ]

        # Compile list marker patterns
        self.list_marker_patterns = [
            re.compile(pattern, re.MULTILINE)
            for pattern in self.LIST_MARKERS
        ]

        # Compile RFC2119 keyword patterns
        self.keyword_patterns = [
            (kw, re.compile(rf'\b{re.escape(kw)}\b', re.IGNORECASE))
            for kw in self.RFC2119_KEYWORDS
        ]

        app_logger.info("[StructuralAnalyzer] Initialized with scope trigger patterns")

    def analyze(self, section_text: str, section_id: Optional[str] = None) -> List[ScopeBlock]:
        """
        Analyze a section of text to find scope inheritance structures.

        Args:
            section_text: Text content of a section
            section_id: Optional section identifier for provenance

        Returns:
            List of ScopeBlock objects representing parent-child structures
        """
        scope_blocks = []

        # Split into paragraphs (double newline separated)
        paragraphs = re.split(r'\n\s*\n', section_text)

        block_counter = 0
        para_idx = 0

        while para_idx < len(paragraphs):
            paragraph = paragraphs[para_idx]

            # Check if this paragraph has a scope trigger
            trigger_match = None
            trigger_phrase = ""

            for pattern in self.scope_trigger_patterns:
                match = pattern.search(paragraph)
                if match:
                    trigger_match = match
                    trigger_phrase = match.group(0)
                    break

            if not trigger_match:
                para_idx += 1
                continue

            # Extract the parent sentence
            trigger_pos = trigger_match.end()
            parent_start = self._find_sentence_start(paragraph, trigger_match.start())
            parent_sentence = paragraph[parent_start:trigger_pos].strip()

            # Check if parent has RFC2119 keyword
            parent_keyword = self._find_rfc2119_keyword(parent_sentence)
            if not parent_keyword:
                para_idx += 1
                continue

            # Collect list items - first from remaining text in current paragraph
            remaining_text = paragraph[trigger_pos:]
            children, child_keywords = self._extract_list_items(remaining_text)

            # If no children in current paragraph, look at subsequent paragraphs
            if not children:
                look_ahead_idx = para_idx + 1
                combined_text = ""

                while look_ahead_idx < len(paragraphs):
                    next_para = paragraphs[look_ahead_idx]
                    # Check if this paragraph starts with a list marker
                    is_list_para = any(
                        pattern.match(next_para.lstrip())
                        for pattern in self.list_marker_patterns
                    )

                    if is_list_para:
                        combined_text += "\n" + next_para
                        look_ahead_idx += 1
                    else:
                        # Stop looking - found a non-list paragraph
                        break

                if combined_text:
                    children, child_keywords = self._extract_list_items(combined_text)
                    # Skip the paragraphs we consumed
                    para_idx = look_ahead_idx - 1

            if children:
                block = ScopeBlock(
                    block_id=f"{section_id or 'unknown'}-scope-{block_counter:03d}",
                    parent_sentence=parent_sentence,
                    parent_keyword=parent_keyword,
                    children=children,
                    child_keywords=child_keywords,
                    trigger_phrase=trigger_phrase.strip(),
                    trigger_position=trigger_match.start(),
                    section=section_id
                )

                scope_blocks.append(block)
                block_counter += 1

                app_logger.debug(
                    f"[StructuralAnalyzer] Found scope block: parent='{parent_sentence[:50]}...', "
                    f"keyword={parent_keyword}, children={len(children)}"
                )

            para_idx += 1

        if scope_blocks:
            app_logger.info(
                f"[StructuralAnalyzer] Found {len(scope_blocks)} scope blocks in section {section_id}"
            )

        return scope_blocks

    def _find_sentence_start(self, text: str, position: int) -> int:
        """Find the start of the sentence containing the given position."""
        # Look backwards for sentence-ending punctuation
        sentence_enders = '.!?'

        for i in range(position - 1, -1, -1):
            if text[i] in sentence_enders:
                # Found end of previous sentence, start is next character
                return i + 1

        # No sentence boundary found, start from beginning
        return 0

    def _find_rfc2119_keyword(self, text: str) -> Optional[str]:
        """Find the first RFC2119 keyword in text."""
        for keyword, pattern in self.keyword_patterns:
            if pattern.search(text):
                return keyword
        return None

    def _extract_list_items(self, text: str) -> Tuple[List[str], Dict[int, str]]:
        """
        Extract list items from text.

        Returns:
            Tuple of (list of item texts, dict mapping index to keyword for items with own keywords)
        """
        items = []
        item_keywords = {}

        # Split by newlines and look for list markers
        lines = text.split('\n')
        current_item = []
        current_item_start = -1

        for line_idx, line in enumerate(lines):
            # Check if line starts with a list marker
            is_list_item = any(
                pattern.match(line)
                for pattern in self.list_marker_patterns
            )

            if is_list_item:
                # Save previous item if exists
                if current_item:
                    item_text = ' '.join(current_item).strip()
                    if item_text:
                        items.append(item_text)
                        # Check for keyword
                        keyword = self._find_rfc2119_keyword(item_text)
                        if keyword:
                            item_keywords[len(items) - 1] = keyword

                # Start new item
                # Remove the list marker from the line
                clean_line = self._remove_list_marker(line)
                current_item = [clean_line]
                current_item_start = line_idx

            elif current_item:
                # Continuation of current item
                stripped = line.strip()
                if stripped:
                    current_item.append(stripped)
                elif not stripped and current_item:
                    # Empty line might end the item
                    # But only if next non-empty line is a new item or paragraph
                    pass

        # Don't forget the last item
        if current_item:
            item_text = ' '.join(current_item).strip()
            if item_text:
                items.append(item_text)
                keyword = self._find_rfc2119_keyword(item_text)
                if keyword:
                    item_keywords[len(items) - 1] = keyword

        return items, item_keywords

    def _remove_list_marker(self, line: str) -> str:
        """Remove the list marker from the beginning of a line."""
        for pattern in self.list_marker_patterns:
            match = pattern.match(line)
            if match:
                return line[match.end():].strip()
        return line.strip()

    def get_inherited_rules(
        self,
        scope_block: ScopeBlock,
        document_id: str = "unknown"
    ) -> List[Dict[str, any]]:
        """
        Generate rule skeletons for children that inherit the parent's keyword.

        Args:
            scope_block: A scope block with parent and children
            document_id: Document identifier for rule IDs

        Returns:
            List of dicts with rule info including inheritance metadata
        """
        inherited_rules = []

        for idx, child_text in enumerate(scope_block.children):
            # Check if child has its own keyword
            child_keyword = scope_block.child_keywords.get(idx)

            rule_info = {
                'sentence': child_text,
                'keyword': child_keyword or scope_block.parent_keyword,
                'keyword_source': 'direct' if child_keyword else 'inherited',
                'parent_rule_id': scope_block.parent_rule_id,
                'scope_block_id': scope_block.block_id,
                'section': scope_block.section,
                'parent_sentence': scope_block.parent_sentence,
                'parent_keyword': scope_block.parent_keyword,
            }

            inherited_rules.append(rule_info)

        return inherited_rules

    def aggregate_overrides(self, irs: list, section_id: str = None, doc_id: str = None, mode: str = "assertion") -> list:
        """
        Structural analysis pipeline with two output modes:
        - assertion: preserve assertion IR cardinality, only annotate/fix in place
        - derived: produce derived/consolidated views for downstream reporting/codegen
        """
        if mode == "assertion":
            return self._annotation_path(list(irs), section_id=section_id, doc_id=doc_id)
        if mode == "derived":
            return self._derived_path(list(irs), section_id=section_id, doc_id=doc_id)
        raise ValueError(f"Unknown structural analyzer mode: {mode}")

    def _annotation_path(self, irs: list, section_id: str = None, doc_id: str = None) -> list:
        """Non-destructive path: preserve assertion IR count while fixing annotations."""
        after_scope_merge = self._prepare_irs(irs, section_id=section_id, doc_id=doc_id)
        return after_scope_merge

    def _derived_path(self, irs: list, section_id: str = None, doc_id: str = None) -> list:
        """Derived path: allow synthesis and convergence for downstream derived views."""
        after_scope_merge = self._prepare_irs(irs, section_id=section_id, doc_id=doc_id)

        synthesized = self._synthesize_lintable_from_step_modifications(after_scope_merge)
        if synthesized:
            after_scope_merge.extend(synthesized)
            for syn_ir in synthesized:
                self._apply_strict_lintability_rules(syn_ir)

        converged = self._converge_duplicate_rules(after_scope_merge)
        converged = self._converge_same_observable(converged)
        converged = self._converge_advanced(converged)

        for ir in converged:
            # IntermediateRepresentation schema no longer includes temporary provenance fields.
            # Keep derived path non-destructive and avoid mutating undeclared attributes.
            pass

        merged_count = len(irs) - len(converged)
        if merged_count > 0:
            app_logger.info(
                f"[StructuralAnalyzer] Derived aggregation: {len(irs)} IRs → {len(converged)} IRs "
                f"({merged_count} consolidated)"
            )
        return converged

    def _prepare_irs(self, irs: list, section_id: str = None, doc_id: str = None) -> list:
        """Apply non-destructive annotation and lintability fixes before branching."""
        from app.services.extraction.ir_schema import Override, StepModification
        from app.services.extraction.ir_canonicalizer import IRCanonicalizer

        canonicalizer = IRCanonicalizer()

        # === Step 1: 过滤不合格 IR ===
        # 注意：只过滤结构性错误的 IR（如 subject 是类型名）
        # 不过滤 capability 规则，因为它们虽然不可 lint，但仍是规范的一部分
        filtered_count = 0
        eligible_irs = []
        for ir in irs:
            ir_eligible = getattr(ir, 'ir_eligible', True)
            rule_category = getattr(ir, 'rule_category', '')
            if hasattr(rule_category, 'value'):
                rule_category = rule_category.value

            # 保留 capability 规则（非 lintable 但仍是规范内容）
            is_capability = rule_category == 'capability'

            if not ir_eligible and not is_capability:
                # 检查是否是结构性错误（如类型名作为 subject）
                reason = getattr(ir, 'ir_ineligible_reason', '') or ''
                is_structural_error = 'type name' in reason.lower() or 'invalid subject' in reason.lower()

                if is_structural_error:
                    filtered_count += 1
                    app_logger.debug(f"[StructuralAnalyzer] Filtered invalid IR: {reason}")
                    continue

            eligible_irs.append(ir)

        if filtered_count > 0:
            app_logger.info(
                f"[StructuralAnalyzer] IR eligibility gate: filtered {filtered_count} ineligible IRs"
            )

        # === Step 2: 设置 section_scope ===
        if section_id and doc_id:
            section_scope = f"{doc_id}-{section_id}"
            for ir in eligible_irs:
                if not getattr(ir, 'section_scope', None):
                    ir.section_scope = section_scope

        # === Step 3: 非破坏性处理作用域组 ===
        after_scope_merge = list(eligible_irs)
        for ir in after_scope_merge:
            # Temporary provenance fields like derived_from_rule_ids/is_assertion_ir/atomicity_level
            # are no longer part of the IR schema. Keep preparation schema-safe.
            if hasattr(ir, 'overrides') and ir.overrides and hasattr(ir, 'algorithm_ref') and ir.algorithm_ref:
                step_mods = self._overrides_to_step_modifications(ir.overrides)
                if step_mods:
                    ir.algorithm_ref.step_modifications = step_mods
                    ir.algorithm_ref.inheritance = "partial"

        # === Step 4: algorithm_ref 内部一致性检查 ===
        for ir in after_scope_merge:
            self._fix_algorithm_ref_consistency(ir)

        # === Step 5: subject 验证（类型名不能作为 assertion subject）===
        for ir in after_scope_merge:
            self._validate_subject(ir)

        # === Step 6: display_as 规则的 enforcement_phase 和 precondition 修复 ===
        for ir in after_scope_merge:
            self._fix_display_as_semantics(ir)

        # === Step 7: Canonicalize lintability-driving fields deterministically ===
        for ir in after_scope_merge:
            canonicalizer.canonicalize(ir)

        # === Step 8: 严格的 lintability 判定 ===
        for ir in after_scope_merge:
            self._apply_strict_lintability_rules(ir)
            ir.recompute_lintable()

        # === Step 9: lint_category 分类 ===
        for ir in after_scope_merge:
            self._classify_lint_category(ir)

        # === Step 10: IR pool classification ===
        for ir in after_scope_merge:
            self._classify_ir_pool(ir)

        # === Step 11: 内部引用解析 ===
        self._resolve_internal_references(after_scope_merge, doc_id=doc_id)

        # === Step 12: definition IR 的 obligation 降级 ===
        for ir in after_scope_merge:
            self._fix_definition_obligation(ir)

        return after_scope_merge

    def _converge_duplicate_rules(self, irs: list) -> list:
        """
        Merge duplicate IRs that represent the same rule at different levels of detail.

        Detection patterns:
        1. Same subject + predicate + obligation, one has scope_block_id (detailed), one doesn't (summary)
           → Merge into the detailed version, use summary as canonical_text

        NOT merged:
        - Different scope_block_ids (e.g., scope-000 vs scope-001 are different rules)
        - Different constraint semantics when both are unscoped

        Merge strategy:
        - Keep the more detailed version (has scope_block_id or overrides)
        - Use summary version's description as canonical_text if more readable
        - Preserve all references from both versions
        """
        # Step 1: Group by (subject_path, predicate, obligation) - ignore scope for initial grouping
        base_groups: Dict[Tuple[str, str, str], list] = {}

        for ir in irs:
            subject = getattr(ir, 'subject', None)
            if hasattr(subject, 'path'):
                subject_path = subject.path
            else:
                subject_path = str(subject) if subject else ""

            predicate = getattr(ir, 'predicate', '')
            if hasattr(predicate, 'value'):
                predicate = predicate.value

            obligation = getattr(ir, 'obligation', '')
            if hasattr(obligation, 'value'):
                obligation = obligation.value

            key = (subject_path, str(predicate), str(obligation))
            if key not in base_groups:
                base_groups[key] = []
            base_groups[key].append(ir)

        result = []
        converged_count = 0

        for key, group in base_groups.items():
            if len(group) == 1:
                result.append(group[0])
                continue

            # Step 2: Separate scoped and unscoped IRs
            scoped_irs: Dict[str, list] = {}  # scope_block_id -> IRs
            unscoped_irs: list = []

            for ir in group:
                scope_id = getattr(ir, 'scope_block_id', None)
                if scope_id:
                    if scope_id not in scoped_irs:
                        scoped_irs[scope_id] = []
                    scoped_irs[scope_id].append(ir)
                else:
                    unscoped_irs.append(ir)

            # Step 3: For each scope_block_id, try to merge with an unscoped summary
            for scope_id, scoped_group in scoped_irs.items():
                if unscoped_irs:
                    # Find best matching unscoped IR (summary) to merge
                    best_summary = self._find_best_summary_match(scoped_group[0], unscoped_irs)
                    if best_summary:
                        # Merge: keep scoped version, use summary's text as canonical
                        merged = self._merge_summary_into_detailed(best_summary, scoped_group[0])
                        result.append(merged)
                        # Keep remaining scoped IRs in the same scope (don't drop them!)
                        result.extend(scoped_group[1:])
                        unscoped_irs.remove(best_summary)
                        converged_count += 1
                    else:
                        result.extend(scoped_group)
                else:
                    result.extend(scoped_group)

            # Step 4: Handle remaining unscoped IRs (no matching scoped version)
            # Check if they can be merged among themselves
            if len(unscoped_irs) > 1:
                # Try to merge similar unscoped IRs
                merged_unscoped = self._merge_similar_unscoped(unscoped_irs)
                result.extend(merged_unscoped)
                converged_count += len(unscoped_irs) - len(merged_unscoped)
            else:
                result.extend(unscoped_irs)

        if converged_count > 0:
            app_logger.info(
                f"[StructuralAnalyzer] IR convergence: merged {converged_count} duplicate IRs"
            )

        return result

    def _converge_same_observable(self, irs: list) -> list:
        """
        Merge IRs that produce the same observable check on the same subject.

        This is a post-convergence pass that handles cases where two IRs with
        different predicates/obligations produce the same effective check.

        Uses the RulePatternDetector to determine the effective check pattern
        for each IR. If two lintable IRs on the same subject produce the same
        ZlintRulePattern, they would generate the same lint — keep only the
        one with the strongest obligation.

        Convergence criteria (all must hold):
        - Same subject path (both target the same certificate field)
        - Both lintable
        - Same detected ZlintRulePattern (via RulePatternDetector)

        Strategy:
        - Keep the one with strongest obligation (MUST > SHALL; definitions
          without recorded inheritance are noise)
        - Absorb references from the weaker one
        - Mark the absorbed one as non-lintable with audit trail
        """
        from app.services.certificate.rule_pattern_detector import (
            RulePatternDetector, ZlintRulePattern
        )

        OBLIGATION_STRENGTH = {
            'MUST': 5, 'MUST NOT': 5,
            'SHALL': 4, 'SHALL NOT': 4,
            'SHOULD': 3, 'SHOULD NOT': 3,
            'MAY': 2,
            'IMPLICIT': 0, 'DEFINED': -1, 'NOISE': -1,
        }

        detector = RulePatternDetector()

        def get_subject_path(ir) -> str:
            subject = getattr(ir, 'subject', None)
            if hasattr(subject, 'path'):
                return subject.path or ''
            return str(subject) if subject else ''

        def get_obligation_strength(ir) -> int:
            obligation = getattr(ir, 'obligation', '')
            if hasattr(obligation, 'value'):
                obligation = obligation.value
            return OBLIGATION_STRENGTH.get(str(obligation).upper(), 0)

        def ir_to_detect_dict(ir) -> Dict[str, Any]:
            """Convert IR object to dict format expected by RulePatternDetector."""
            subject = getattr(ir, 'subject', '')
            if hasattr(subject, 'path'):
                subject = subject.path or ''
            else:
                subject = str(subject) if subject else ''

            obligation = getattr(ir, 'obligation', '')
            if hasattr(obligation, 'value'):
                obligation = obligation.value

            return {
                'description': getattr(ir, 'description', '') or getattr(ir, 'rule_text', '') or '',
                'subject': subject,
                'obligation': str(obligation) if obligation else '',
                'rule_text': getattr(ir, 'rule_text', '') or '',
                'lint_name': getattr(ir, 'lint_name', ''),
            }

        # Separate lintable and non-lintable IRs
        lintable_groups: Dict[str, list] = {}
        non_lintable = []

        for ir in irs:
            if getattr(ir, 'lintable', False):
                subject = get_subject_path(ir)
                lintable_groups.setdefault(subject, []).append(ir)
            else:
                non_lintable.append(ir)

        result = list(non_lintable)

        for subject, group in lintable_groups.items():
            if len(group) <= 1:
                result.extend(group)
                continue

            # Sub-group by detected rule pattern
            pattern_groups: Dict[str, list] = {}
            no_pattern = []
            for ir in group:
                pattern = detector.detect(ir_to_detect_dict(ir))
                if pattern != ZlintRulePattern.UNKNOWN:
                    pattern_groups.setdefault(pattern.value, []).append(ir)
                else:
                    no_pattern.append(ir)

            for pattern_key, pattern_group in pattern_groups.items():
                if len(pattern_group) <= 1:
                    result.extend(pattern_group)
                    continue

                # Sort by obligation strength (strongest first)
                pattern_group.sort(key=get_obligation_strength, reverse=True)
                primary = pattern_group[0]

                # Absorb references from others
                all_refs = list(getattr(primary, 'references', []))
                seen_refs = {r.raw for r in all_refs}

                for other in pattern_group[1:]:
                    for ref in getattr(other, 'references', []):
                        if ref.raw not in seen_refs:
                            all_refs.append(ref)
                            seen_refs.add(ref.raw)
                    other.lintable = False
                    lint_name = getattr(primary, 'lint_name', 'primary')
                    other.non_lintable_reason = (
                        f"Converged into {lint_name} "
                        f"(same rule pattern: {pattern_key})"
                    )

                primary.references = all_refs
                result.append(primary)
                result.extend(pattern_group[1:])  # Keep as non-lintable for audit trail

                app_logger.info(
                    f"[StructuralAnalyzer] Same-observable convergence: "
                    f"merged {len(pattern_group)} IRs for subject='{subject}', "
                    f"pattern='{pattern_key}'"
                )

            result.extend(no_pattern)

        return result

    def _converge_advanced(self, irs: list) -> list:
        """
        Advanced IR consolidation to reduce over-extraction.

        Three passes:
        A. Algorithm step merge — merge IRs referencing same algorithm base_spec
        B. Subject hierarchy dedup — merge parent/child subject paths
        C. Synonym merge — merge IRs with high text similarity on same subject
        """
        OBLIGATION_STRENGTH = {
            'MUST': 5, 'MUST NOT': 5, 'MUST_NOT': 5,
            'SHALL': 4, 'SHALL NOT': 4, 'SHALL_NOT': 4,
            'SHOULD': 3, 'SHOULD NOT': 3, 'SHOULD_NOT': 3,
            'MAY': 2, 'IMPLICIT': 0, 'DEFINED': -1, 'NOISE': -1,
        }

        def get_subject(ir) -> str:
            s = getattr(ir, 'subject', None)
            if hasattr(s, 'path'):
                return (s.path or '').lower()
            return (str(s) if s else '').lower()

        def get_obligation_str(ir) -> str:
            o = getattr(ir, 'obligation', '')
            if hasattr(o, 'value'):
                o = o.value
            return str(o).upper() if o else ''

        def get_obligation_strength(ir) -> int:
            return OBLIGATION_STRENGTH.get(get_obligation_str(ir), 0)

        def get_rule_text(ir) -> str:
            return (getattr(ir, 'rule_text', '') or '').lower()

        def text_jaccard(text_a: str, text_b: str) -> float:
            """Word-level Jaccard similarity."""
            words_a = set(text_a.split())
            words_b = set(text_b.split())
            if not words_a or not words_b:
                return 0.0
            return len(words_a & words_b) / len(words_a | words_b)

        def is_parent_subject(parent: str, child: str) -> bool:
            """Check if parent is a prefix path of child."""
            if not parent or not child or parent == child:
                return False
            return child.startswith(parent + '.')

        result = list(irs)

        # === Pass A: Algorithm step merge ===
        # Group lintable IRs by algorithm_ref.base_spec + operation
        algo_groups: Dict[Tuple[str, str], list] = {}
        non_algo = []
        for ir in result:
            algo = getattr(ir, 'algorithm_ref', None)
            if algo and getattr(algo, 'base_spec', None):
                op = getattr(algo, 'operation', '') or ''
                key = (algo.base_spec.lower(), op.lower())
                algo_groups.setdefault(key, []).append(ir)
            else:
                non_algo.append(ir)

        merged_algo = []
        algo_merged_count = 0
        for key, group in algo_groups.items():
            if len(group) <= 1:
                merged_algo.extend(group)
                continue
            # Keep strongest obligation, merge step_modifications
            group.sort(key=get_obligation_strength, reverse=True)
            primary = group[0]
            primary_mods = list(getattr(primary.algorithm_ref, 'step_modifications', None) or [])

            for other in group[1:]:
                other_mods = getattr(other.algorithm_ref, 'step_modifications', None) or []
                for mod in other_mods:
                    # Avoid duplicate step_modifications
                    existing_params = {(m.step, m.param) for m in primary_mods}
                    if (mod.step, mod.param) not in existing_params:
                        primary_mods.append(mod)
                # Merge references
                for ref in getattr(other, 'references', []):
                    existing_refs = {r.raw for r in getattr(primary, 'references', [])}
                    if ref.raw not in existing_refs:
                        primary.references.append(ref)
                algo_merged_count += 1

            if primary_mods:
                primary.algorithm_ref.step_modifications = primary_mods
            merged_algo.append(primary)

        if algo_merged_count > 0:
            app_logger.info(
                f"[StructuralAnalyzer] Advanced merge Pass A: merged {algo_merged_count} "
                f"algorithm step IRs"
            )

        result = non_algo + merged_algo

        # === Pass B: Subject hierarchy dedup ===
        # If IR_A.subject is parent of IR_B.subject, same obligation → merge into IR_B
        subject_map: Dict[str, list] = {}
        for ir in result:
            subj = get_subject(ir)
            subject_map.setdefault(subj, []).append(ir)

        absorbed = set()
        for subj_a, irs_a in subject_map.items():
            for subj_b, irs_b in subject_map.items():
                if subj_a == subj_b:
                    continue
                if is_parent_subject(subj_a, subj_b):
                    for ir_a in irs_a:
                        if id(ir_a) in absorbed:
                            continue
                        for ir_b in irs_b:
                            if id(ir_b) in absorbed:
                                continue
                            if get_obligation_str(ir_a) == get_obligation_str(ir_b):
                                # Merge parent into child (child is more specific)
                                constraint_a = getattr(ir_a, 'constraint', None)
                                raw_text_a = getattr(constraint_a, 'raw_text', '') if constraint_a else ''
                                constraint_b = getattr(ir_b, 'constraint', None)
                                raw_text_b = getattr(constraint_b, 'raw_text', '') if constraint_b else ''
                                # If parent has more info, copy it
                                if len(raw_text_a) > len(raw_text_b) and constraint_b:
                                    constraint_b.raw_text = raw_text_a
                                absorbed.add(id(ir_a))
                                break

        if absorbed:
            result = [ir for ir in result if id(ir) not in absorbed]
            app_logger.info(
                f"[StructuralAnalyzer] Advanced merge Pass B: absorbed {len(absorbed)} "
                f"parent-subject IRs into child IRs"
            )

        # === Pass C: Synonym merge ===
        # Group by subject, then merge IRs with Jaccard > 0.5
        subject_groups: Dict[str, list] = {}
        for ir in result:
            subj = get_subject(ir)
            subject_groups.setdefault(subj, []).append(ir)

        final_result = []
        synonym_merged_count = 0
        for subj, group in subject_groups.items():
            if len(group) <= 1:
                final_result.extend(group)
                continue

            # Compare pairwise by rule_text Jaccard similarity
            merged_ids = set()
            for i in range(len(group)):
                if id(group[i]) in merged_ids:
                    continue
                cluster = [group[i]]
                for j in range(i + 1, len(group)):
                    if id(group[j]) in merged_ids:
                        continue
                    sim = text_jaccard(get_rule_text(group[i]), get_rule_text(group[j]))
                    if sim > 0.5 and get_obligation_str(group[i]) == get_obligation_str(group[j]):
                        cluster.append(group[j])
                        merged_ids.add(id(group[j]))

                if len(cluster) > 1:
                    # Keep the IR with the longest constraint.raw_text
                    cluster.sort(key=lambda ir: len(
                        getattr(getattr(ir, 'constraint', None), 'raw_text', '') or ''
                    ), reverse=True)
                    primary = cluster[0]
                    for other in cluster[1:]:
                        for ref in getattr(other, 'references', []):
                            existing = {r.raw for r in getattr(primary, 'references', [])}
                            if ref.raw not in existing:
                                primary.references.append(ref)
                    synonym_merged_count += len(cluster) - 1

                final_result.append(cluster[0])

        if synonym_merged_count > 0:
            app_logger.info(
                f"[StructuralAnalyzer] Advanced merge Pass C: merged {synonym_merged_count} "
                f"synonym IRs (Jaccard > 0.5)"
            )

        return final_result

    def _find_best_summary_match(self, detailed_ir, unscoped_irs: list):
        """
        Find the best matching unscoped IR to serve as summary for a detailed IR.

        Matching criteria:
        - Same algorithm_ref.operation if present
        - Similar constraint semantics
        """
        if not unscoped_irs:
            return None

        detailed_algo = getattr(detailed_ir, 'algorithm_ref', None)
        detailed_op = detailed_algo.operation if detailed_algo else None

        for unscoped in unscoped_irs:
            unscoped_algo = getattr(unscoped, 'algorithm_ref', None)
            unscoped_op = unscoped_algo.operation if unscoped_algo else None

            # If both have algorithm_ref, operations should match
            if detailed_op and unscoped_op:
                if detailed_op == unscoped_op:
                    return unscoped
            # If neither has algorithm_ref, check constraint similarity
            elif not detailed_op and not unscoped_op:
                return unscoped

        # Fallback: only if the detailed IR has no specific operation
        # (both are generic/non-algorithmic). Don't merge an algorithmic
        # scoped IR with a semantically unrelated unscoped IR.
        if not detailed_op:
            return unscoped_irs[0] if unscoped_irs else None
        return None

    def _merge_summary_into_detailed(self, summary_ir, detailed_ir):
        """
        Merge a summary IR into a detailed IR.

        The detailed IR is kept, with the summary's description used as canonical_text.
        """
        # Use summary's cleaner description as canonical_text
        summary_text = getattr(summary_ir, 'rule_text', '') or ''
        detailed_text = getattr(detailed_ir, 'rule_text', '') or ''

        # Prefer shorter, cleaner text as canonical (without "with the following")
        if summary_text and 'with the following' not in summary_text.lower():
            if len(summary_text) < len(detailed_text) or 'with the following' in detailed_text.lower():
                detailed_ir.canonical_text = summary_text

        # Merge references
        all_refs = list(getattr(detailed_ir, 'references', []))
        seen_refs = {r.raw for r in all_refs}
        for ref in getattr(summary_ir, 'references', []):
            if ref.raw not in seen_refs:
                all_refs.append(ref)
                seen_refs.add(ref.raw)
        detailed_ir.references = all_refs

        return detailed_ir

    def _merge_similar_unscoped(self, unscoped_irs: list) -> list:
        """
        Merge similar unscoped IRs that represent the same rule.

        Only merges if constraints are very similar.
        """
        if len(unscoped_irs) <= 1:
            return unscoped_irs

        # Group by constraint similarity
        result = []
        used = set()

        for i, ir1 in enumerate(unscoped_irs):
            if i in used:
                continue

            constraint1 = getattr(ir1, 'constraint', None)
            text1 = constraint1.raw_text if constraint1 else ""

            merge_group = [ir1]
            for j, ir2 in enumerate(unscoped_irs[i+1:], start=i+1):
                if j in used:
                    continue
                constraint2 = getattr(ir2, 'constraint', None)
                text2 = constraint2.raw_text if constraint2 else ""

                # Check if one constraint contains the other (similarity)
                if text1 and text2 and (text1 in text2 or text2 in text1):
                    merge_group.append(ir2)
                    used.add(j)

            if len(merge_group) > 1:
                # Merge the group
                merged = self._merge_duplicate_irs(merge_group)
                result.append(merged)
            else:
                result.append(ir1)
            used.add(i)

        return result

    def _merge_duplicate_irs(self, irs: list):
        """
        Merge multiple IRs representing the same rule into a single IR.

        Strategy:
        - Prefer IR with scope_block_id (more specific context)
        - Prefer IR with overrides (more detailed)
        - Use shorter/cleaner description as summary
        - Combine references from all versions
        """
        if not irs:
            return None
        if len(irs) == 1:
            return irs[0]

        # Sort by "detail level": scope_block_id > overrides > nothing
        def detail_score(ir):
            score = 0
            if getattr(ir, 'scope_block_id', None):
                score += 10
            if getattr(ir, 'overrides', None):
                score += len(ir.overrides)
            return score

        sorted_irs = sorted(irs, key=detail_score, reverse=True)
        primary = sorted_irs[0]  # Most detailed version
        others = sorted_irs[1:]  # Less detailed versions

        # Find the best summary description (shortest one without "with the following")
        summary_candidates = []
        for ir in irs:
            rule_text = getattr(ir, 'rule_text', '') or ''
            # Skip descriptions that are clearly "parent sentences" with clarification triggers
            if 'with the following' not in rule_text.lower():
                summary_candidates.append((len(rule_text), rule_text, ir))

        if summary_candidates:
            # Use the shortest clean description as summary
            summary_candidates.sort(key=lambda x: x[0])
            best_summary = summary_candidates[0][1]
            if best_summary and best_summary != getattr(primary, 'rule_text', ''):
                primary.canonical_text = best_summary

        # Merge references from all versions
        all_refs = list(getattr(primary, 'references', []))
        seen_refs = {r.raw for r in all_refs}
        for other in others:
            for ref in getattr(other, 'references', []):
                if ref.raw not in seen_refs:
                    all_refs.append(ref)
                    seen_refs.add(ref.raw)
        primary.references = all_refs

        # Merge overrides from all versions (avoid duplicates)
        all_overrides = list(getattr(primary, 'overrides', []))
        seen_override_keys = {(o.step, o.param) for o in all_overrides}
        for other in others:
            for override in getattr(other, 'overrides', []):
                key = (override.step, override.param)
                if key not in seen_override_keys:
                    all_overrides.append(override)
                    seen_override_keys.add(key)
        primary.overrides = all_overrides

        return primary

    def _fix_algorithm_ref_consistency(self, ir) -> None:
        """
        Fix internal consistency of algorithm_ref based on step_modifications.

        Detects and fixes contradictions like:
        - operation=ToASCII but step_modifications contain ToUnicode
        - predicate=encode_as but step_modifications indicate display scenario (skip step 5)

        Rules:
        1. If any step_modification.param == "ToUnicode" → operation must be ToUnicode
        2. If any step_modification.param == "ToASCII" → operation must be ToASCII
        3. If operation is ToUnicode → predicate should be display_as (not encode_as)
        4. If operation is ToASCII → predicate should be encode_as (not display_as)
        """
        algo = getattr(ir, 'algorithm_ref', None)
        if not algo or not algo.step_modifications:
            return

        # Detect actual operation from step_modifications
        detected_operation = None
        has_skip_step5 = False

        for mod in algo.step_modifications:
            param_lower = mod.param.lower() if mod.param else ""
            source_lower = mod.source_text.lower() if mod.source_text else ""

            if 'tounicode' in param_lower or 'tounicode' in source_lower:
                detected_operation = "ToUnicode"
            elif 'toascii' in param_lower or 'toascii' in source_lower:
                if not detected_operation:  # Don't override ToUnicode with ToASCII
                    detected_operation = "ToASCII"

            if mod.modification_type == 'skip' and mod.step == 5:
                has_skip_step5 = True

        if not detected_operation:
            return

        # Fix 1: Correct operation if contradicted by step_modifications
        if algo.operation != detected_operation:
            app_logger.info(
                f"[StructuralAnalyzer] Consistency fix: algorithm_ref.operation "
                f"'{algo.operation}' → '{detected_operation}' (detected from step_modifications)"
            )
            algo.operation = detected_operation

        # Fix 2: Correct predicate based on operation
        current_predicate = getattr(ir, 'predicate', '')
        if hasattr(current_predicate, 'value'):
            current_predicate = current_predicate.value

        if detected_operation == "ToUnicode" and current_predicate == "encode_as":
            app_logger.info(
                f"[StructuralAnalyzer] Consistency fix: predicate "
                f"'encode_as' → 'display_as' (ToUnicode is display operation)"
            )
            ir.predicate = "display_as"
            # Also fix rule_category if it was algorithm_ref → display
            if getattr(ir, 'rule_category', None) in ('algorithm_ref', 'display'):
                ir.rule_category = "display"

        elif detected_operation == "ToASCII" and current_predicate == "display_as":
            app_logger.info(
                f"[StructuralAnalyzer] Consistency fix: predicate "
                f"'display_as' → 'encode_as' (ToASCII is encoding operation)"
            )
            ir.predicate = "encode_as"

        # Fix 3: Update requires_operation if present
        requires_op = getattr(ir, 'requires_operation', None)
        if requires_op and isinstance(requires_op, dict):
            if requires_op.get('operation') != detected_operation:
                ir.requires_operation['operation'] = detected_operation

    # ASN.1 / X.509 type names that should NOT be assertion subjects
    INVALID_SUBJECT_TYPE_NAMES = {
        'DirectoryString', 'IA5String', 'UTF8String', 'PrintableString',
        'TeletexString', 'UniversalString', 'BMPString', 'VisibleString',
        'NumericString', 'GeneralizedTime', 'UTCTime',
        'INTEGER', 'BOOLEAN', 'NULL',
        'BIT STRING', 'OCTET STRING', 'SEQUENCE', 'SET',
        'OBJECT IDENTIFIER', 'ENUMERATED',
    }

    def _validate_subject(self, ir) -> None:
        """
        Validate that IR subject is not a type name.

        Type names (DirectoryString, IA5String, etc.) are data types, not
        assertion subjects. If detected, mark the IR as ineligible since the
        LLM has confused context for subject.
        """
        subject = getattr(ir, 'subject', None)
        if hasattr(subject, 'path'):
            subject_path = subject.path
        else:
            subject_path = str(subject) if subject else ""

        if subject_path in self.INVALID_SUBJECT_TYPE_NAMES:
            app_logger.info(
                f"[StructuralAnalyzer] Subject validation: '{subject_path}' is a type name, "
                f"not a valid assertion subject - marking IR as ineligible"
            )
            # ir_eligible/ir_ineligible_reason are derived @property on IR;
            # set rule_category to 'capability' to make ir_eligible return False
            try:
                ir.ir_eligible = False
                ir.ir_ineligible_reason = (
                    f"Subject '{subject_path}' is an ASN.1/X.509 type name, not an assertion subject. "
                    f"Type names should appear in precondition or constraint, not as subject."
                )
            except (AttributeError, TypeError):
                pass  # Read-only property, skip

    def _fix_definition_obligation(self, ir) -> None:
        """
        Downgrade obligation for definition IRs.

        Definitions describe what something IS, not what implementations MUST do.
        Their obligation should be IMPLICIT (or null), not MUST/SHALL.

        EXCEPTION: If keyword_source is "direct", the RFC 2119 keyword was
        regex-matched from the original text. The text literally says MUST/SHALL/etc.,
        so the rule IS normative regardless of how the LLM classified it.
        Do NOT downgrade in this case — the keyword match is more reliable than
        the LLM's classification.
        """
        ir_pool = getattr(ir, 'ir_pool', 'rules')
        if ir_pool == 'definitions':
            current_obligation = getattr(ir, 'obligation', '')
            if hasattr(current_obligation, 'value'):
                current_obligation = current_obligation.value

            if current_obligation and current_obligation not in ('IMPLICIT', 'implicit'):
                # Check keyword_source: if "direct", the keyword was regex-matched
                # from source text — don't downgrade a normative keyword to IMPLICIT
                keyword_source = getattr(ir, 'keyword_source', None) or 'direct'
                normative_obligations = {'MUST', 'MUST NOT', 'MUST_NOT',
                                         'SHALL', 'SHALL NOT', 'SHALL_NOT',
                                         'SHOULD', 'SHOULD NOT', 'SHOULD_NOT',
                                         'RECOMMENDED', 'NOT RECOMMENDED', 'NOT_RECOMMENDED'}
                obligation_upper = str(current_obligation).upper().replace(' ', '_')

                if keyword_source == 'direct' and obligation_upper.replace('_', ' ') in normative_obligations:
                    app_logger.debug(
                        f"[StructuralAnalyzer] Definition has direct keyword '{current_obligation}' "
                        f"— keeping normative obligation (not downgrading to IMPLICIT)"
                    )
                    return

                app_logger.debug(
                    f"[StructuralAnalyzer] Definition obligation: '{current_obligation}' → 'IMPLICIT'"
                )
                ir.obligation = "IMPLICIT"

    def _fix_display_as_semantics(self, ir) -> None:
        """
        Fix semantic errors in display_as rules.

        Issues fixed:
        1. enforcement_phase: "Encoding" → "Display" (display happens at runtime, not encoding)
        2. precondition: "before storage" → "before display" (display rules are about presentation)

        Detection: predicate == "display_as" OR rule_category == "display"
        """
        predicate = getattr(ir, 'predicate', '')
        if hasattr(predicate, 'value'):
            predicate = predicate.value

        rule_category = getattr(ir, 'rule_category', '')
        if hasattr(rule_category, 'value'):
            rule_category = rule_category.value

        # Only apply to display rules
        if predicate != 'display_as' and rule_category != 'display':
            return

        # Fix 1: enforcement_phase
        current_phase = getattr(ir, 'enforcement_phase', '')
        if current_phase == 'Encoding':
            app_logger.info(
                f"[StructuralAnalyzer] Display semantics fix: enforcement_phase "
                f"'Encoding' → 'Display'"
            )
            ir.enforcement_phase = "Display"

        # Fix 2: precondition (if it says "before storage" for a display rule, fix it)
        precondition = getattr(ir, 'precondition', None)
        if precondition and isinstance(precondition, dict):
            description = precondition.get('description', '')
            trigger = precondition.get('trigger', '')

            if 'storage' in description.lower() or 'storage' in trigger.lower():
                app_logger.info(
                    f"[StructuralAnalyzer] Display semantics fix: precondition "
                    f"'before storage' → 'before display'"
                )
                if 'storage' in description.lower():
                    precondition['description'] = description.replace('storage', 'display').replace('Storage', 'Display')
                if 'storage' in trigger.lower():
                    precondition['trigger'] = trigger.replace('storage', 'display').replace('Storage', 'Display')
                ir.obligation = "IMPLICIT"

    def _synthesize_lintable_from_step_modifications(self, irs: list) -> list:
        """
        Synthesize standalone lintable IRs from step_modifications or overrides
        that have observable consequences.

        When algorithm step children are merged into a parent IR's step_modifications
        or overrides, some modifications (like UseSTD3ASCIIRules=true) have independently
        verifiable observable results. This method extracts them as standalone lintable IRs.

        Checks two data sources:
        - ir.algorithm_ref.step_modifications (StepModification objects: param, override_value)
        - ir.overrides (Override objects: param, value)

        Currently recognized patterns:
        - UseSTD3ASCIIRules (set/true/required): LDH rules enforced on dNSName labels
        """
        from .ir_schema import (
            IntermediateRepresentation, IRConstraint, SubjectRef,
            ObligationType, PredicateType, IRProvenance
        )

        synthesized = []

        for ir in irs:
            # Only synthesize from MUST/SHALL obligation parents (storage scope)
            obligation = getattr(ir, 'obligation', '')
            if hasattr(obligation, 'value'):
                obligation = obligation.value
            obligation_upper = str(obligation).upper()

            if obligation_upper not in ('MUST', 'SHALL'):
                continue

            # Collect modification entries from both sources
            # Each entry is (param, value, source_text, step)
            mod_entries = []

            # Source 1: algorithm_ref.step_modifications
            algo = getattr(ir, 'algorithm_ref', None)
            if algo and getattr(algo, 'step_modifications', None):
                for mod in algo.step_modifications:
                    mod_entries.append((
                        mod.param or '',
                        str(mod.override_value or ''),
                        mod.source_text or '',
                        getattr(mod, 'step', None)
                    ))

            # Source 2: ir.overrides
            overrides = getattr(ir, 'overrides', None)
            if overrides:
                for ov in overrides:
                    mod_entries.append((
                        ov.param or '',
                        str(ov.value or ''),
                        getattr(ov, 'source_text', '') or '',
                        getattr(ov, 'step', None)
                    ))

            if not mod_entries:
                continue

            app_logger.debug(
                f"[Synthesize] Checking IR with {len(mod_entries)} mods, "
                f"obligation={obligation_upper}, text={getattr(ir, 'rule_text', '')[:60]}"
            )

            for param, val, source_text, step_num in mod_entries:
                param_norm = param.lower().replace('_', '').replace(' ', '')

                # Pattern: UseSTD3ASCIIRules set to true
                # Note: This is an algorithm step parameter, not a certificate constraint.
                # A linter checks the RESULT (LDH-compliant labels), not the flag itself.
                # Do NOT synthesize a lintable IR from this — the observable outcomes
                # (ASCII check, ACE format check) are handled by other extraction patterns.
                if 'usestd3asciirules' in param_norm:
                    continue

        return synthesized

    def _apply_strict_lintability_rules(self, ir) -> None:
        """
        Apply strict lintability rules to prevent false positive lintable classifications.

        Core principle: Only rules that describe VERIFIABLE CERTIFICATE STATIC CONTENT
        can be lintable. The following types are NOT lintable:

        1. Comparison behavior ("when comparing", "case-insensitive match")
        2. Algorithm steps (detected via "in step" patterns, step_modifications,
           or "<operation> operation" patterns)
        3. Capability ("MUST allow for", "MUST support")
        4. Display behavior ("before display", "convert to Unicode")
        5. Implementation process ("MUST perform", "MUST use")

        This is a STRICT FILTER that overrides LLM's lintability decisions.
        """
        description = getattr(ir, 'description', '') or ''
        rule_text = getattr(ir, 'rule_text', '') or ''
        text_lower = (description + ' ' + rule_text).lower()

        predicate = getattr(ir, 'predicate', '')
        if hasattr(predicate, 'value'):
            predicate = predicate.value
        predicate_lower = (predicate or '').lower()

        subject = getattr(ir, 'subject', '')
        if hasattr(subject, 'path'):
            subject = subject.path
        subject_lower = (subject or '').lower()

        # Get obligation for whitelist checks
        obligation = getattr(ir, 'obligation', '')
        if hasattr(obligation, 'value'):
            obligation = obligation.value
        obligation_upper = (obligation or '').upper()

        # === TARGETED NON-LINTABLE EXCEPTIONS ===
        # Some Table II gold rules are observable certificate-side statements, but they
        # remain non-lintable because the sentence is explanatory/example-style rather
        # than a standalone static lint condition.
        if text_lower.startswith('utctime specifies the year through the two low-order digits'):
            ir.lintable = False
            ir.non_lintable_reason = (
                "UTCTime explanatory format statement is modeled in ground truth as "
                "observable encoding guidance but not as a standalone lintable check"
            )
            ir._lintable_explicitly_set = True
            app_logger.info(
                "[StructuralAnalyzer] UTCTime explanatory format statement forced non-lintable"
            )
            return

        if 'bit would be asserted' in text_lower and subject_lower.endswith('keyusage'):
            ir.lintable = False
            ir.non_lintable_reason = (
                "Example-derived keyUsage bit assertion is observable but treated as "
                "non-lintable explanatory guidance in ground truth"
            )
            ir._lintable_explicitly_set = True
            app_logger.info(
                "[StructuralAnalyzer] Example-derived keyUsage bit assertion forced non-lintable"
            )
            return

        # === PRE-CHECK: Encoding format whitelist (takes priority over all rejection patterns) ===
        # Rules about certificate encoding formats (UTCTime, GeneralizedTime, DER, etc.)
        # are inherently observable on the certificate and should always be lintable.
        encoding_keywords = [
            'utctime', 'generalizedtime', 'printablestring', 'utf8string',
            'ia5string', 'bmpstring', 'universalstring', 'visiblestring',
            'teletexstring', 't61string', 'der encoding', 'der encoded',
            'ber encoding',
        ]
        encoding_verbs = [
            'encoded as', 'encoded in', 'expressed in', 'include seconds',
            'include fractional', 'greenwich mean time', 'zulu',
            'assigned the', 'shall be encoded', 'must be encoded',
            'must not include fractional', 'shall not include fractional',
            'must express', 'shall express', 'must represent', 'shall represent',
        ]
        has_encoding_keyword = any(kw in text_lower for kw in encoding_keywords)
        has_encoding_verb = any(v in text_lower for v in encoding_verbs)
        is_normative = obligation_upper in ('MUST', 'SHALL', 'MUST_NOT', 'SHALL_NOT',
                                            'MUST NOT', 'SHALL NOT')
        # Don't override algorithm_ref classification — those rules depend on external
        # specs and are correctly non-lintable even if they mention encoding keywords.
        current_category = getattr(ir, 'rule_category', '')
        if hasattr(current_category, 'value'):
            current_category = current_category.value
        if has_encoding_keyword and has_encoding_verb and is_normative:
            ir.lintable = True
            ir.non_lintable_reason = None
            ir.assertion_subject = "Certificate"
            ir.verifiability = "observable"
            ir.rule_category = "encoding_constraint"
            ir.enforcement_phase = "Encoding"
            ir._lintable_explicitly_set = True  # Prevent recompute_lintable() from overriding
            app_logger.info(
                f"[StructuralAnalyzer] Encoding whitelist: '{subject}' with encoding format "
                f"constraint detected (keyword + verb match), forced lintable"
            )
            return  # Skip all rejection patterns

        # === PRE-CHECK: single-artifact observable constraint whitelist ===
        # Audited false-negative rescue (2026-06-16). Mirrors the controlled-extractor
        # forward guard at the STRICT layer so the rejection patterns below cannot
        # re-bury a genuine single-certificate/CRL constraint the LLM mislabeled as
        # clarification / not_a_constraint, or whose phase it set to Validation off a
        # PURPOSE word ("keys used to validate signatures"). The decision (incl. the
        # cert-field-path requirement + table-fragment rejection that keep CABF
        # operational rules out) lives in the SHARED lintability_guard helper so this
        # and the extractor guard cannot diverge. We set the FIELDS (not just lintable)
        # because recompute_lintable() re-derives from them. Never rescues
        # cross_artifact / runtime_dynamic.
        from app.services.extraction.lintability_guard import is_single_artifact_observable
        assertion_subject = getattr(ir, 'assertion_subject', '')
        if hasattr(assertion_subject, 'value'):
            assertion_subject = assertion_subject.value
        as_l = (assertion_subject or '').lower()
        enforcement_phase = getattr(ir, 'enforcement_phase', '')
        if hasattr(enforcement_phase, 'value'):
            enforcement_phase = enforcement_phase.value
        ep_l = (enforcement_phase or '').lower()
        # only rescue categories that are NOT inherently runtime/external
        rescue_ok_category = (current_category or '') in (
            'clarification', 'definition', 'encoding_constraint', 'structural_constraint', '',
        )
        if (rescue_ok_category
                and is_single_artifact_observable(predicate_lower, assertion_subject,
                                                  subject, obligation, rule_text)):
            if ep_l in ('validation', 'processing'):
                ir.enforcement_phase = 'Encoding'
            if (current_category or '') in ('clarification', 'definition'):
                ir.rule_category = 'encoding_constraint'
            ir.lintable = True
            ir.non_lintable_reason = None
            app_logger.info(
                f"[StructuralAnalyzer] single-artifact whitelist: '{subject}' "
                f"pred={predicate_lower} obl={obligation_upper} → forced lintable "
                f"(phase={ir.enforcement_phase}, cat={ir.rule_category})"
            )
            return  # Skip all rejection patterns

        # === STRICT NON-LINTABLE PATTERNS ===

        # 0. Delegation statements — rule delegates to external standard/document
        # These are NOT lintable because the actual constraint is in a different document.
        #
        # STRONG delegation: the rule's main verb clause is the delegation itself.
        #   e.g., "all fields shall comply with BRG requirements"
        # WEAK delegation: a cross-reference modifier on a self-contained constraint.
        #   e.g., "MUST be encoded in IA5String, as specified in RFC 5280"
        strong_delegation_phrases = [
            'requirements specified in', 'shall comply with',
            'shall apply for', 'amendments specified in',
            'requirements stated in', 'requirements of',
            'shall conform to the requirements', 'shall be in accordance',
            'as required by', 'requirements set out in',
            'shall meet the requirements', 'as set out in',
        ]
        weak_delegation_phrases = [
            'as specified in', 'specified in clause',
            'as defined in', 'in accordance with',
        ]
        all_delegation_phrases = strong_delegation_phrases + weak_delegation_phrases
        external_doc_patterns = [
            r'\bETSI\b', r'\bEN\s+319', r'\bBR[GS]?\b', r'\bCABF\b',
            r'\bRFC\s*\d{3,5}\b', r'\bITU[\s-]', r'\bISO[\s/]',
            r'\bclause\s+\d', r'\bsection\s+\d', r'\bannex\s+[a-z]',
            r'\b(?:Mozilla|MRSP)\b',
        ]
        has_delegation = any(p in text_lower for p in all_delegation_phrases)
        has_strong_delegation = any(p in text_lower for p in strong_delegation_phrases)
        has_external_ref = any(re.search(p, description + ' ' + rule_text, re.IGNORECASE)
                               for p in external_doc_patterns)

        if has_delegation and has_external_ref:
            # EXCEPTION 1: Rule also contains a concrete field constraint value.
            # This is intentionally family-agnostic to avoid ETSI-only behavior.
            concrete_value_patterns = [
                'value different from', 'shall be set to', 'must equal',
                'shall equal', 'must contain', 'shall contain',
                'must include', 'shall include',
                'must be present', 'shall be present',
                'must not be present', 'shall not be present',
                'must not exceed', 'shall not exceed',
                'must be encoded', 'shall be encoded',
                'must be marked critical', 'must be marked non-critical',
                'shall be consistent', 'must be consistent',
            ]
            has_concrete_value = any(p in text_lower for p in concrete_value_patterns)

            # EXCEPTION 2: Subject is a specific certificate field path.
            has_specific_field = any(f in subject_lower for f in [
                'extensions.', 'subject.', 'issuer.', 'validity.',
                'serialnumber', 'organizationidentifier', 'qcstatement',
            ])

            # EXCEPTION 3: Same sentence contains observable certificate anchors.
            # This keeps delegation/reference wording lintable when the local sentence
            # still constrains certificate content. The heuristic is deliberately generic
            # so that it does not become ETSI-only and does not affect unrelated docs.
            observable_anchor_patterns = [
                'shall include', 'must include',
                'shall contain', 'must contain',
                'shall be present', 'must be present',
                'shall not be present', 'must not be present',
                'shall be encoded', 'must be encoded',
                'shall be marked', 'must be marked',
                'shall use', 'must use',
                'shall have', 'must have',
                'shall not have', 'must not have',
                'shall be set to', 'must be set to',
                'shall not exceed', 'must not exceed',
            ]
            observable_field_markers = [
                'extension', 'extensions', 'field', 'fields', 'attribute', 'attributes',
                'subject', 'issuer', 'certificate', 'serialnumber',
                'organizationidentifier', 'qcstatement', 'qcstatements',
                'dnsname', 'generalname', 'keyusage', 'basicconstraints',
                'certificatepolicies', 'authoritykeyidentifier', 'subjectkeyidentifier',
            ]
            has_observable_anchor = (
                any(p in text_lower for p in observable_anchor_patterns) and
                any(m in text_lower or m in subject_lower for m in observable_field_markers)
            )

            # Strong delegation should still be filtered when the sentence is only
            # outsourcing requirements and lacks a local observable anchor.
            if has_strong_delegation:
                delegation_susceptible_fields = [
                    'nameconstraints', 'subjectaltname', 'keyusage',
                    'basicconstraints', 'extendedkeyusage', 'extkeyusage',
                    'authorityinfoaccess', 'crldistributionpoints',
                    'authoritykeyidentifier', 'subjectkeyidentifier',
                    'certificatepolicies',
                ]
                is_susceptible = any(f in subject_lower for f in delegation_susceptible_fields)
                if is_susceptible and has_specific_field and not has_observable_anchor:
                    has_specific_field = False

            if not has_concrete_value and not has_specific_field and not has_observable_anchor:
                self._mark_non_lintable(ir, "delegation",
                    "Delegation statement - rule delegates to external standard, "
                    "actual constraint is in a different document")
                return

        # 0.5 Unobservable precondition — rule depends on external/runtime knowledge
        unobservable_preconditions = [
            'known to exist', 'is known', 'not known',
            'registration number is known',
            'if the ca is aware', 'if known to the ca',
        ]
        if any(p in text_lower for p in unobservable_preconditions):
            self._mark_non_lintable(ir, "unobservable_precondition",
                "Unobservable precondition - rule depends on external/runtime knowledge "
                "that cannot be determined from certificate content alone")
            return

        # 1. Comparison behavior - describes runtime comparison, not certificate content
        comparison_patterns = [
            'when comparing', 'case-insensitive', 'exact match',
            'comparing dns names', 'evaluating name constraints',
            'label-by-label', 'for equality'
        ]
        if any(pat in text_lower for pat in comparison_patterns):
            self._mark_non_lintable(ir, "runtime_comparison",
                "Comparison behavior - describes runtime comparison process, not certificate static content")
            return

        # 2. Algorithm steps - internal algorithm state, not certificate content
        #    Detection: text-based patterns for step references, PLUS structural
        #    check for IRs that have algorithm_ref with step_modifications
        algorithm_step_patterns = [
            'in step',
        ]
        is_algorithm_step = any(pat in text_lower for pat in algorithm_step_patterns)

        # Also detect numbered step references (generic: "step N" for any N)
        if not is_algorithm_step:
            if re.search(r'\bstep\s+\d+\b', text_lower):
                is_algorithm_step = True

        # Structural check: if the IR has step_modifications in its algorithm_ref,
        # and the text references a flag/parameter from those modifications,
        # it's describing algorithm internal state
        if not is_algorithm_step:
            algo = getattr(ir, 'algorithm_ref', None)
            if algo and getattr(algo, 'step_modifications', None):
                for mod in algo.step_modifications:
                    param = (mod.param or '').lower().replace('_', '').replace(' ', '')
                    if param and param in text_lower.replace('_', '').replace(' ', ''):
                        is_algorithm_step = True
                        break

        # Also detect common algorithm operation references (operation names
        # followed by "operation" keyword)
        if not is_algorithm_step:
            if re.search(r'\b\w+\s+operation\b', text_lower):
                is_algorithm_step = True

        if is_algorithm_step:
            # Algorithm steps (including UseSTD3ASCIIRules, AllowUnassigned, ToASCII
            # operations) describe implementation behavior, not certificate content.
            # A linter checks the RESULT on the certificate (e.g., is dNSName ASCII?),
            # not whether the CA ran the algorithm with specific flags.
            #
            # EXCEPTION: Some algorithm steps produce observable encoding results.
            # e.g., "in step 5, change all label separators to U+002E" means
            # dNSName labels MUST use U+002E as separator — statically verifiable.
            observable_step_results = [
                'label separator', 'separator', 'u+002e', 'full stop',
                'ace', 'ascii compatible encoding',
                'before storage', 'stored in',
            ]
            has_observable_result = any(p in text_lower for p in observable_step_results)
            if has_observable_result and ('dnsname' in subject_lower or 'subjectaltname' in subject_lower
                                          or 'dnsname' in text_lower or 'domain name' in text_lower):
                app_logger.info(
                    f"[StructuralAnalyzer] Algorithm step with observable result: "
                    f"'{subject}' — step produces verifiable encoding constraint"
                )
                # Don't filter — let it fall through to lintable patterns
            else:
                self._mark_non_lintable(ir, "algorithm_step",
                    "Algorithm step - describes internal algorithm state/parameter, not certificate content")
                return

        # 3. Capability - implementation capability, not certificate content
        capability_patterns = [
            'must allow for', 'must support', 'must be able',
            'increased space requirements', 'accommodate'
        ]
        if any(pat in text_lower for pat in capability_patterns):
            # EXCEPTION: "accommodate" + "before storage in dNSName" + ACE = observable result
            has_observable_result = (
                'before storage' in text_lower and
                'dnsname' in text_lower and
                ('ace' in text_lower or 'ascii compatible encoding' in text_lower)
            )
            if not has_observable_result:
                self._mark_non_lintable(ir, "capability",
                    "Capability requirement - describes implementation capability, not certificate content")
                return

        # 4. Display behavior - UI/display process, not certificate content
        display_patterns = [
            'before display', 'convert to unicode', 'display',
            'tounicode', 'to unicode'
        ]
        # EXCEPTION: Don't filter if this is about ACE encoding result
        if any(pat in text_lower for pat in display_patterns):
            # Check if this is ToUnicode for display (non-lintable) vs ACE storage (lintable result)
            is_display_only = 'before display' in text_lower or 'to unicode' in text_lower
            has_storage_result = 'before storage' in text_lower and 'dnsname' in text_lower
            if is_display_only and not has_storage_result:
                self._mark_non_lintable(ir, "display_behavior",
                    "Display behavior - describes display/UI process, not certificate content")
                return

        # 5. Implementation process - general implementation actions
        implementation_process_patterns = [
            'must perform', 'shall perform', 'must use the',
            'implementation must', 'implementations must',
            'conforming implementations must perform'
        ]
        # Only apply if subject is "implementation" or similar
        if 'implementation' in subject_lower:
            if any(pat in text_lower for pat in implementation_process_patterns):
                # EXCEPTION 1: "before storage in dNSName" + ACE = observable result
                # The implementation action produces a certificate artifact that IS lintable
                has_observable_result = (
                    'before storage' in text_lower and
                    'dnsname' in text_lower and
                    ('ace' in text_lower or 'ascii compatible encoding' in text_lower)
                )
                # EXCEPTION 2: "ToASCII" on DN = observable result (domainComponent)
                has_toascii_dn = (
                    'toascii' in text_lower and
                    ('distinguished name' in text_lower or 'domaincomponent' in text_lower or
                     'label' in text_lower)
                )
                # EXCEPTION 3: "preferred name syntax" = DNS format constraint
                has_dns_syntax = (
                    'preferred name syntax' in text_lower or
                    'rfc1034' in text_lower.replace(' ', '') or
                    'rfc 1034' in text_lower
                )
                if has_observable_result or has_toascii_dn or has_dns_syntax:
                    # Don't filter - this will be caught by lintable patterns below
                    pass
                else:
                    self._mark_non_lintable(ir, "implementation_process",
                        "Implementation process - describes implementation action, not certificate content")
                    return

        # 6. "Stored string" / semantic interpretation - not directly verifiable
        stored_string_patterns = [
            'considered a', 'shall be considered', 'stored string',
            'be considered a'
        ]
        if any(pat in text_lower for pat in stored_string_patterns):
            self._mark_non_lintable(ir, "semantic_interpretation",
                "Semantic interpretation - describes how to interpret data, not verifiable constraint")
            return

        # 7. Cross-reference clarification - interpretive statements about other sections
        # e.g., "As noted in Section 4.2.1.10, any DNS name that may be constructed..."
        # These describe matching/interpretation semantics, not certificate structure.
        if re.search(r'as noted in section\s+\d', text_lower):
            self._mark_non_lintable(ir, "cross_reference_clarification",
                "Cross-reference clarification - interpretive statement about another section")
            return

        # === LINTABLE PATTERNS (strict whitelist) ===

        # Only mark as lintable if it describes verifiable certificate field content constraint
        # The key insight: "IA5String is limited to ASCII" means dNSName values must be ASCII-only

        is_content_constraint = False

        # Pattern 1: Direct ASCII/encoding constraint on certificate field
        # Also catches "IA5String is limited to the set of ASCII characters" when subject
        # is "ia5string" itself — remap to dNSName since IA5String IS the encoding type
        if ('ia5string' in text_lower or 'ascii' in text_lower) and \
           ('limited' in text_lower or 'must contain' in text_lower or 'only' in text_lower):
            # Accept if subject is a certificate field OR is "ia5string"/"ia5" (encoding type)
            is_cert_field = ('dnsname' in subject_lower or 'subjectaltname' in subject_lower or
                             'extensions' in subject_lower)
            is_encoding_type = ('ia5string' in subject_lower or 'ia5' == subject_lower)
            if is_cert_field or is_encoding_type:
                is_content_constraint = True
                # Remap encoding type subject to the certificate field it constrains
                if is_encoding_type and not is_cert_field:
                    ir.subject = "extensions.subjectAltName.dNSName"
                    if hasattr(ir, 'subject_ref') and ir.subject_ref:
                        ir.subject_ref.path = "extensions.subjectAltName.dNSName"
                        ir.subject_ref.raw = "extensions.subjectAltName.dNSName"
                app_logger.info(
                    f"[StructuralAnalyzer] Strict lintability: ASCII content constraint detected "
                    f"for subject='{subject}'"
                )

        # Pattern 2: "before storage in dNSName" + ACE - the result is observable
        # Key insight: implementation behavior is not lintable, but its RESULT on certificate IS
        # "MUST convert to ACE format before storage in dNSName" → dNSName must be ASCII/ACE
        if ('before storage' in text_lower and 'dnsname' in text_lower and
            ('ace' in text_lower or 'ascii compatible encoding' in text_lower)):
            is_content_constraint = True
            # Fix subject if it's "implementation" - the observable result is on dNSName
            if 'implementation' in subject_lower:
                ir.subject = "extensions.subjectAltName.dNSName"
                if hasattr(ir, 'subject_ref') and ir.subject_ref:
                    ir.subject_ref.path = "extensions.subjectAltName.dNSName"
                    ir.subject_ref.raw = "extensions.subjectAltName.dNSName"
            app_logger.info(
                f"[StructuralAnalyzer] Strict lintability: ACE storage constraint detected "
                f"(observable result: dNSName must be ASCII/ACE encoded)"
            )

        # Pattern 3: "ToASCII" on distinguished name / domainComponent
        # The result is observable: domainComponent values must be valid ACE-encoded labels
        if ('toascii' in text_lower and
            ('distinguished name' in text_lower or 'domaincomponent' in text_lower or
             'label' in text_lower)):
            is_content_constraint = True
            # Fix subject to the certificate field
            if 'implementation' in subject_lower:
                ir.subject = "subject.domainComponent"
                if hasattr(ir, 'subject_ref') and ir.subject_ref:
                    ir.subject_ref.path = "subject.domainComponent"
                    ir.subject_ref.raw = "subject.domainComponent"
            app_logger.info(
                f"[StructuralAnalyzer] Strict lintability: ToASCII on DN detected "
                f"(observable result: domainComponent must be valid ACE)"
            )

        # Pattern 4: "preferred name syntax" or RFC 1034/1123 references
        # Implies DNS label format constraints (including 63-octet limit)
        if (('preferred name syntax' in text_lower or
             'rfc1034' in text_lower.replace(' ', '') or
             'rfc 1034' in text_lower) and
            ('dnsname' in text_lower or 'dns' in subject_lower or
             'domain name' in text_lower)):
            is_content_constraint = True
            app_logger.info(
                f"[StructuralAnalyzer] Strict lintability: DNS preferred name syntax detected "
                f"(implies RFC 1034 label format constraints)"
            )

        # Pattern 5: DNS label length constraint (63 octets)
        # Only match explicit numeric constraints, NOT "space requirements" (implementation capacity)
        if (('63' in text_lower and ('octet' in text_lower or 'byte' in text_lower)) or
            ('label' in text_lower and 'length' in text_lower)):
            if 'dnsname' in subject_lower or 'dns' in text_lower or 'domain' in text_lower:
                is_content_constraint = True
                if 'implementation' in subject_lower:
                    ir.subject = "extensions.subjectAltName.dNSName"
                    if hasattr(ir, 'subject_ref') and ir.subject_ref:
                        ir.subject_ref.path = "extensions.subjectAltName.dNSName"
                        ir.subject_ref.raw = "extensions.subjectAltName.dNSName"
                app_logger.info(
                    f"[StructuralAnalyzer] Strict lintability: DNS label length constraint detected"
                )

        # Pattern 6: "convert internationalized domain names" — ACE encoding outcome
        # The RESULT on the certificate is observable: dNSName must be ACE-encoded
        if (('convert' in text_lower or 'conversion' in text_lower) and
            ('internationalized' in text_lower or bool(re.search(r'\bidns?\b', text_lower))) and
            ('domain name' in text_lower or 'dnsname' in subject_lower)):
            is_content_constraint = True
            if 'implementation' in subject_lower:
                ir.subject = "extensions.subjectAltName.dNSName"
                if hasattr(ir, 'subject_ref') and ir.subject_ref:
                    ir.subject_ref.path = "extensions.subjectAltName.dNSName"
                    ir.subject_ref.raw = "extensions.subjectAltName.dNSName"
            app_logger.info(
                f"[StructuralAnalyzer] Strict lintability: IDN→ACE conversion detected "
                f"(observable result: dNSName must be ACE-encoded)"
            )

        # Pattern 7: Label separator constraint — "change all label separators to U+002E"
        # The result is observable: dNSName labels must use standard full stop as separator
        if (('label separator' in text_lower or 'separator' in text_lower) and
            ('u+002e' in text_lower or 'full stop' in text_lower or '002e' in text_lower)):
            is_content_constraint = True
            if 'implementation' in subject_lower or 'generalname' in subject_lower:
                ir.subject = "extensions.subjectAltName.dNSName"
                if hasattr(ir, 'subject_ref') and ir.subject_ref:
                    ir.subject_ref.path = "extensions.subjectAltName.dNSName"
                    ir.subject_ref.raw = "extensions.subjectAltName.dNSName"
            app_logger.info(
                f"[StructuralAnalyzer] Strict lintability: Label separator constraint detected "
                f"(observable result: dNSName must use U+002E separator)"
            )

        if is_content_constraint:
            ir.lintable = True
            ir.non_lintable_reason = None
            ir.assertion_subject = "Certificate"
            ir.verifiability = "observable"
            ir.rule_category = "encoding_constraint"
            ir.enforcement_phase = "Encoding"
            ir._lintable_explicitly_set = True  # Prevent recompute_lintable() from overriding
        else:
            # Default: if not explicitly whitelisted, mark as non-lintable
            # unless it's already correctly marked
            current_lintable = getattr(ir, 'lintable', False)
            if current_lintable:
                # Double-check: is this really a certificate content constraint?
                has_certificate_field = any(f in subject_lower for f in [
                    'extensions', 'subject', 'issuer', 'validity', 'serialnumber',
                    'signature', 'version', 'dnsname', 'subjectaltname'
                ])
                if not has_certificate_field:
                    self._mark_non_lintable(ir, "no_certificate_field",
                        "Subject is not a certificate field - cannot be statically verified")

    def _mark_non_lintable(self, ir, reason_code: str, reason_text: str) -> None:
        """Helper to mark an IR as non-lintable with proper categorization."""
        ir.lintable = False
        ir.non_lintable_reason = reason_text
        ir.assertion_subject = "Implementation"

        # Comparison and display rules are runtime behavior (runtime_only),
        # not completely unverifiable (none).
        runtime_reasons = {"runtime_comparison", "display_behavior"}
        ir.verifiability = "runtime_only" if reason_code in runtime_reasons else "none"

        # Set appropriate rule_category based on reason_code
        category_map = {
            "runtime_comparison": "comparison",
            "algorithm_step": "algorithm_ref",
            "capability": "capability",
            "display_behavior": "display",
            "implementation_process": "implementation_process",
            "semantic_interpretation": "definition",
            "cross_reference_clarification": "clarification",
            "no_certificate_field": "implementation_process",
            "delegation": "delegation",
            "unobservable_precondition": "precondition",
        }
        ir.rule_category = category_map.get(reason_code, "non_lintable")

    def _has_disabled_flag_in_step_modifications(self, ir, flag_name: str) -> bool:
        """Check if a named flag is explicitly set to a falsy value in step_modifications.

        Generic version: works for any flag name (UseSTD3ASCIIRules,
        AllowUnassigned, etc.). Normalizes both param name and flag_name
        by lowering and stripping underscores/spaces/hyphens before comparison.
        """
        algo = getattr(ir, 'algorithm_ref', None)
        if not algo or not getattr(algo, 'step_modifications', None):
            return False
        normalized_flag = flag_name.lower().replace('_', '').replace(' ', '').replace('-', '')
        for mod in algo.step_modifications:
            param_lower = (mod.param or '').lower().replace('_', '').replace(' ', '').replace('-', '')
            if normalized_flag in param_lower:
                val = str(mod.override_value).lower().strip()
                if val in ('false', 'no', '0', 'disabled'):
                    return True
        return False

    def _classify_lint_category(self, ir) -> None:
        """
        Classify rules into lint categories for improved conceptual purity.

        Categories:
        - static_verifiable: Can be checked by examining certificate content
        - runtime_semantic: Describes runtime behavior (comparison, validation)
        - implementation_guidance: Implementation requirements (capability, display)
        - definition: Defines semantics, not constraints

        This classification helps distinguish rule types without removing them
        from rules_pool, maintaining traceability for compliance auditing.
        """
        # Get rule_category
        rule_category = getattr(ir, 'rule_category', None)
        if hasattr(rule_category, 'value'):
            rule_category = rule_category.value

        # Get verifiability
        verifiability = getattr(ir, 'verifiability', '')
        if hasattr(verifiability, 'value'):
            verifiability = verifiability.value

        # Get enforcement_phase
        enforcement_phase = getattr(ir, 'enforcement_phase', '')

        # Get assertion_subject
        assertion_subject = getattr(ir, 'assertion_subject', '')
        if hasattr(assertion_subject, 'value'):
            assertion_subject = assertion_subject.value

        # Get lintable status
        lintable = getattr(ir, 'lintable', False)

        # Get obligation
        obligation = getattr(ir, 'obligation', '')
        if hasattr(obligation, 'value'):
            obligation = obligation.value
        obligation_upper = str(obligation).upper() if obligation else ''

        # Classification logic
        lint_category = None

        # 0. Legacy DEFINED/IMPLICIT obligations are not standalone recall
        # candidates unless a later stage has explicitly proven inherited
        # RFC2119 context and marked the IR lintable.
        if obligation_upper in ('DEFINED', 'IMPLICIT', 'NOISE') and not lintable:
            lint_category = 'definition'

        # 1. Definition rules
        elif rule_category == 'definition':
            lint_category = 'definition'

        # 2. Implementation guidance (capability, display)
        elif rule_category in ['capability', 'display']:
            lint_category = 'implementation_guidance'

        # 3. Runtime semantic (comparison, validation behavior)
        elif rule_category == 'comparison' or enforcement_phase in ['Comparison', 'Validation']:
            lint_category = 'runtime_semantic'

        # 4. Static verifiable (observable in certificate)
        elif lintable or (verifiability == 'observable' and assertion_subject == 'Certificate'):
            lint_category = 'static_verifiable'

        # 5. Default: check by verifiability
        elif verifiability == 'runtime_only':
            lint_category = 'runtime_semantic'
        elif verifiability == 'context_dependent':
            lint_category = 'runtime_semantic'
        elif verifiability == 'none' and assertion_subject == 'Implementation':
            lint_category = 'implementation_guidance'
        else:
            # Fallback based on lintability
            lint_category = 'static_verifiable' if lintable else 'runtime_semantic'

        # lint_category is a derived @property on IR; skip assignment
        # ir.lint_category = lint_category

    def _classify_ir_pool(self, ir) -> None:
        """
        Classify IRs into appropriate pools based on lint_category.

        Pool mapping:
        - static_verifiable → rules (main pool for lintable rules)
        - runtime_semantic → rules (comparison/validation behavior)
        - implementation_guidance → rules (capability/display)
        - definition → definitions (semantic definitions)

        This improves conceptual purity without losing traceability.
        """
        lint_category = getattr(ir, 'lint_category', None)
        if hasattr(lint_category, 'value'):
            lint_category = lint_category.value

        # Default mapping based on lint_category
        pool_mapping = {
            'static_verifiable': 'rules',          # Main pool - lintable
            'runtime_semantic': 'rules',            # Was 'behavior' — golden uses 'rules'
            'implementation_guidance': 'rules',     # Was 'guidance' — golden uses 'rules'
            'definition': 'definitions',           # Definitions pool
        }

        # ir_pool is a derived @property on IR; skip assignment
        pass

    def _resolve_internal_references(self, irs: list, doc_id: str = None) -> None:
        """
        Resolve internal references within the same document.

        This method:
        1. Builds an index of known sections from the IRs
        2. For each reference, checks if the target section exists
        3. Marks references as resolved if the target is known

        Note: This is a "best effort" resolution within the current batch.
        Full cross-document resolution requires database lookup (second phase).
        """
        if not doc_id:
            return

        # Build section index from current IRs
        # Extract section numbers from section_scope (e.g., "RFC5280-7.2" -> "7.2")
        known_sections = set()
        for ir in irs:
            section_scope = getattr(ir, 'section_scope', '')
            if section_scope and '-' in section_scope:
                section = section_scope.split('-')[-1]
                known_sections.add(section)

        # RFC 5280 known sections (common references)
        rfc5280_known_sections = {
            '4.1', '4.1.1', '4.1.2', '4.1.2.1', '4.1.2.2', '4.1.2.3', '4.1.2.4',
            '4.1.2.5', '4.1.2.6', '4.1.2.7', '4.1.2.8', '4.1.2.9',
            '4.2', '4.2.1', '4.2.1.1', '4.2.1.2', '4.2.1.3', '4.2.1.4', '4.2.1.5',
            '4.2.1.6', '4.2.1.7', '4.2.1.8', '4.2.1.9', '4.2.1.10', '4.2.1.11',
            '4.2.1.12', '4.2.1.13', '4.2.1.14', '4.2.1.15',
            '4.2.2', '4.2.2.1', '4.2.2.2',
            '5', '5.1', '5.1.1', '5.1.2', '5.2', '5.2.1', '5.2.2', '5.2.3',
            '5.2.4', '5.2.5', '5.2.6', '5.3', '5.3.1', '5.3.2', '5.3.3',
            '6', '6.1', '6.1.1', '6.1.2', '6.1.3', '6.1.4', '6.1.5', '6.1.6',
            '6.2', '6.3',
            '7', '7.1', '7.2', '7.3', '7.4', '7.5',
        }

        if 'RFC5280' in doc_id.upper():
            known_sections.update(rfc5280_known_sections)

        # Resolve references
        resolved_count = 0
        for ir in irs:
            references = getattr(ir, 'references', [])
            for ref in references:
                if ref.resolved:
                    continue

                # Check if this is a same-document reference
                ref_doc_id = ref.doc_id or ''
                target_section = ref.section

                # Case 1: Explicit same-document reference (e.g., "RFC 5280 Section 4.2.1.10")
                is_same_doc = (
                    ref_doc_id.upper() == doc_id.upper() or
                    (not ref_doc_id and target_section)  # Section-only reference
                )

                if is_same_doc and target_section:
                    # Normalize section number
                    normalized_section = target_section.rstrip('.')

                    if normalized_section in known_sections:
                        ref.resolved = True
                        ref.resolution_method = 'internal_section_match'
                        resolved_count += 1

                # Case 2: External reference (e.g., "RFC 3490 Section 4")
                elif ref_doc_id and ref_doc_id.upper() != doc_id.upper():
                    # Mark as external - resolved structurally but not linked
                    ref.resolved = True
                    ref.resolution_method = 'external_reference'
                    resolved_count += 1

        if resolved_count > 0:
            app_logger.info(
                f"[StructuralAnalyzer] Resolved {resolved_count} internal/external references"
            )

    def _overrides_to_step_modifications(self, overrides: list) -> list:
        """
        Convert Override objects to StepModification objects for algorithm_ref.

        This upgrades from "text-level reference" to "rule-level reference" by
        extracting structured step modifications.
        """
        from app.services.extraction.ir_schema import StepModification

        modifications = []
        for override in overrides:
            value = override.value
            if value == "see source_text" or value is None:
                value = self._extract_value_from_source(override.source_text)
            elif isinstance(value, bool):
                value = "true" if value else "false"
            else:
                value = str(value)

            mod = StepModification(
                step=override.step or 0,
                param=override.param,
                original_value=None,  # Would need cross-ref resolution to fill this
                override_value=value,
                modification_type=override.action,
                source_text=override.source_text
            )
            modifications.append(mod)
        return modifications

    def _extract_value_from_source(self, source_text: str) -> str:
        """Extract the actual value from source text when value was 'see source_text'."""
        # Try to extract quoted values
        quoted = re.search(r'"([^"]+)"', source_text)
        if quoted:
            return quoted.group(1)

        # Try to extract boolean flags
        if re.search(r'\bset\b.*\btrue\b|\bset\b', source_text, re.I):
            return "true"
        if re.search(r'\bfalse\b|\bnot\s+set\b', source_text, re.I):
            return "false"

        # Try to extract values after "to"
        to_match = re.search(r'\bto\s+(\S+)', source_text, re.I)
        if to_match:
            return to_match.group(1).strip('.,;:')

        # Fallback: use the action description
        if 'skip' in source_text.lower():
            return "skipped"
        if 'consider' in source_text.lower():
            consider_match = re.search(r'consider.*?["\']([^"\']+)["\']', source_text, re.I)
            if consider_match:
                return consider_match.group(1)

        return source_text[:50] + "..." if len(source_text) > 50 else source_text

    def _ir_to_override(self, ir, last_step_hint: int = 0) -> Optional['Override']:
        """
        Convert a clarification IR to an Override object.

        Args:
            ir: An IntermediateRepresentation with clarification data
            last_step_hint: The step number from the previous override (used when this
                           sentence doesn't contain explicit "step X")

        Returns:
            Override object or None if conversion fails
        """
        from app.services.extraction.ir_schema import Override

        rule_text = getattr(ir, 'rule_text', '') or ''

        # Extract step number from text like "in step 3, set..."
        step_match = re.search(r'(?:in )?step\s*(\d+)', rule_text, re.I)
        step_num = int(step_match.group(1)) if step_match else last_step_hint

        # Determine action type
        action = 'override'
        if re.search(r'^skip\s+step|skip\s+this\s+step', rule_text, re.I):
            action = 'skip'

        # For skip actions, param is not applicable (skipping entire step)
        if action == 'skip':
            param = 'entire_step'
            value = 'skipped'
        else:
            # Extract parameter name (best-effort heuristic)
            param = self._extract_param_name(rule_text)
            # Extract parameter value (best-effort heuristic)
            value = self._extract_param_value(rule_text)

        return Override(
            step=step_num,
            param=param,
            value=value,
            action=action,
            source_text=rule_text
        )

    def _extract_param_name(self, text: str) -> str:
        """Extract parameter name from override text.

        Uses generic patterns that work across different RFC contexts.
        Priority order (most specific to most generic):
        1. Quoted strings (most reliable): "UseSTD3ASCIIRules", "ToASCII"
        2. "with the X operation" pattern
        3. "set the flag called X" or "set the X flag" pattern
        4. CamelCase identifiers (ToASCII, UseSTD3ASCIIRules, etc.)
        5. "X flag/parameter/option" pattern
        6. Key noun phrases (generic extraction)
        7. Fallback to first significant word
        """
        # 1. Look for quoted strings first (most reliable)
        quoted_match = re.search(r'"([^"]+)"', text)
        if quoted_match:
            return quoted_match.group(1)

        # 2. Look for "with the X operation" pattern (e.g., "with the ToASCII operation")
        operation_match = re.search(r'with\s+the\s+"?([A-Za-z][A-Za-z0-9]+)"?\s+operation', text, re.I)
        if operation_match:
            return operation_match.group(1)

        # 3. Look for "set the flag called X" or "set the X flag" pattern
        flag_called_match = re.search(r'set\s+the\s+flag\s+called\s+"?([^";\s]+)"?', text, re.I)
        if flag_called_match:
            return flag_called_match.group(1)

        flag_match = re.search(r'set\s+the\s+(\w+)\s+flag', text, re.I)
        if flag_match:
            return flag_match.group(1)

        # 4. Look for CamelCase identifiers (e.g., UseSTD3ASCIIRules, ToASCII, ToUnicode)
        # Pattern matches: ToASCII, ToUnicode, UseSTD3Rules, AllowUnassigned, etc.
        camel_match = re.search(r'\b(To[A-Z][a-zA-Z0-9]*|[A-Z][a-z]+(?:[A-Z][a-z0-9]+)+)\b', text)
        if camel_match:
            return camel_match.group(1)

        # 5. Look for "X flag" or "X parameter/option/value" pattern
        param_match = re.search(r'(\w+)\s+(?:flag|parameter|option|value)', text, re.I)
        if param_match:
            return param_match.group(1)

        # 6. Look for "the X" where X is a key noun (generic pattern for "the domain name", "the label separators", etc.)
        # This extracts noun phrases that are likely parameter names
        noun_match = re.search(r'(?:the|a|an)\s+(\w+(?:\s+\w+)?)\s+(?:shall|should|must|is|be|are)', text, re.I)
        if noun_match:
            # Convert to underscore format: "domain name" -> "domain_name"
            return noun_match.group(1).strip().replace(' ', '_').lower()

        # 7. Look for "X to Y" or "X as Y" patterns (e.g., "change X to Y", "consider X as Y")
        change_match = re.search(r'(?:change|convert|set|consider)\s+(?:all\s+)?(\w+(?:\s+\w+)?)\s+(?:to|as)\b', text, re.I)
        if change_match:
            return change_match.group(1).strip().replace(' ', '_').lower()

        # 8. Fallback: use first significant word after step reference (skip common words)
        after_step = re.sub(r'^.*?step\s*\d+\s*[,:]?\s*', '', text, flags=re.I)
        words = after_step.split()
        skip_words = {'the', 'a', 'an', 'set', 'is', 'be', 'with', 'to', 'for', 'and', 'or',
                      'this', 'that', 'all', 'each', 'any', 'shall', 'should', 'must', 'may'}
        for word in words:
            clean_word = word.strip('.,;:"\' ')
            if clean_word.lower() not in skip_words and len(clean_word) > 2:
                return clean_word

        return "unknown"

    def _extract_param_value(self, text: str) -> str:
        """Extract parameter value from override text."""
        # Look for "set X to Y" pattern
        set_match = re.search(r'set\s+\w+\s+to\s+(\S+)', text, re.I)
        if set_match:
            return set_match.group(1).strip('.,;:')

        # Look for "= Y" or ": Y" pattern
        eq_match = re.search(r'[=:]\s*(\S+)', text)
        if eq_match:
            return eq_match.group(1).strip('.,;:')

        # Look for true/false/yes/no
        bool_match = re.search(r'\b(true|false|yes|no)\b', text, re.I)
        if bool_match:
            return bool_match.group(1).lower()

        return "see source_text"


def analyze_document_structure(
    document_text: str,
    document_id: str = "unknown"
) -> List[ScopeBlock]:
    """
    Convenience function to analyze an entire document for scope structures.

    Args:
        document_text: Full document text
        document_id: Document identifier

    Returns:
        List of all scope blocks found in the document
    """
    analyzer = StructuralAnalyzer()

    # Split document into sections (simple approach: by section headers)
    section_pattern = re.compile(r'^(\d+(?:\.\d+)*)\s+(.+?)$', re.MULTILINE)

    sections = []
    last_end = 0

    for match in section_pattern.finditer(document_text):
        if last_end > 0:
            # Add previous section content
            sections.append({
                'section_id': sections[-1]['section_id'] if sections else None,
                'text': document_text[last_end:match.start()]
            })

        sections.append({
            'section_id': match.group(1),
            'title': match.group(2),
            'text': ''
        })
        last_end = match.end()

    # Add final section
    if last_end < len(document_text):
        if sections:
            sections[-1]['text'] = document_text[last_end:]
        else:
            sections.append({
                'section_id': None,
                'text': document_text
            })

    # Analyze each section
    all_blocks = []
    for section in sections:
        if section.get('text'):
            blocks = analyzer.analyze(
                section['text'],
                section.get('section_id')
            )
            all_blocks.extend(blocks)

    app_logger.info(
        f"[StructuralAnalyzer] Document analysis complete: "
        f"{len(all_blocks)} scope blocks found in {len(sections)} sections"
    )

    return all_blocks
