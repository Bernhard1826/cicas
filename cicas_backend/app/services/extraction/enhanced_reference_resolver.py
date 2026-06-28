"""
增强的引用解析器
支持显式引用、隐式引用、上下文推断

重构后：
- 输出 ReferenceFact 格式（用于 Rule Reasoning Service）
- 使用 structural_rule_id（仅结构映射，无语义推理）
"""
from typing import List, Optional, Dict, Any, Tuple
from sqlalchemy.orm import Session
import re
from .ir_schema import IntermediateRepresentation, IRReference
from app.core.logging_config import app_logger


class EnhancedReferenceResolver:
    """增强的引用解析器"""

    def __init__(
        self,
        db: Optional[Session] = None,
        kg_client=None,
        standards_index: Dict[str, Any] = None
    ):
        """
        初始化解析器

        Args:
            db: 数据库会话（用于查找 structural_rule_id）
            kg_client: 知识图谱客户端（可选）
            standards_index: 标准文档索引（可选）
        """
        self.db = db
        self.kg_client = kg_client
        self.standards_index = standards_index or {}

        # 编译引用模式
        self._compile_patterns()

    def _compile_patterns(self):
        """编译引用检测模式"""
        # 显式引用模式
        self.explicit_patterns = {
            'rfc_section': re.compile(
                r'\b(RFC\s+\d+)\s*,?\s*[Ss]ection\s+([\d.]+)',
                re.IGNORECASE
            ),
            'rfc_only': re.compile(
                r'\b(RFC\s+\d+)\b',
                re.IGNORECASE
            ),
            'cabf_section': re.compile(
                r'\b(CA/Browser Forum|CABF)\s+.*?[Ss]ection\s+([\d.]+)',
                re.IGNORECASE
            ),
        }

        # 隐式引用模式
        self.implicit_patterns = {
            'section_only': re.compile(
                r'\b[Ss]ection\s+([\d.]+)\b',
            ),
            'see_section': re.compile(
                r'\b[Ss]ee\s+[Ss]ection\s+([\d.]+)\b',
            ),
            'as_defined_in': re.compile(
                r'\bas\s+defined\s+in\s+[Ss]ection\s+([\d.]+)\b',
            ),
        }

    def resolve_references(
        self, ir: IntermediateRepresentation, context: Optional[Dict[str, Any]] = None
    ) -> IntermediateRepresentation:
        """
        解析 IR 中的引用

        Args:
            ir: 中间表示
            context: 上下文信息（如当前文档、最近引用等）

        Returns:
            解析后的 IR
        """
        if not ir.rule_text:
            return ir

        # 提取引用
        references = self._extract_references(ir.rule_text, context)

        # 解析引用
        resolved_references = []
        for ref in references:
            resolved_ref = self._resolve_reference(ref, context)
            resolved_references.append(resolved_ref)

        # 更新 IR
        ir.references.extend(resolved_references)

        return ir

    def _extract_references(
        self, text: str, context: Optional[Dict[str, Any]]
    ) -> List[IRReference]:
        """提取文本中的引用"""
        references = []

        # 1. 提取显式引用
        explicit_refs = self._extract_explicit_references(text)
        references.extend(explicit_refs)

        # 2. 提取隐式引用（需要上下文）
        if context:
            implicit_refs = self._extract_implicit_references(text, context)
            references.extend(implicit_refs)

        return references

    def _extract_explicit_references(self, text: str) -> List[IRReference]:
        """提取显式引用"""
        references = []

        # RFC + Section
        for match in self.explicit_patterns['rfc_section'].finditer(text):
            rfc = match.group(1)
            section = match.group(2)

            # 规范化 RFC 编号
            rfc_number = re.search(r'\d+', rfc).group(0)
            doc_id = f"RFC{rfc_number}"

            ref = IRReference(
                raw=match.group(0),
                doc_id=doc_id,
                section=section,
                resolved=True,
                resolution_method='explicit',
            )
            references.append(ref)

        # RFC only
        for match in self.explicit_patterns['rfc_only'].finditer(text):
            rfc = match.group(1)
            rfc_number = re.search(r'\d+', rfc).group(0)
            doc_id = f"RFC{rfc_number}"

            # 检查是否已经在 rfc_section 中匹配
            if not any(r.doc_id == doc_id and r.section for r in references):
                ref = IRReference(
                    raw=match.group(0),
                    doc_id=doc_id,
                    section=None,
                    resolved=True,
                    resolution_method='explicit',
                )
                references.append(ref)

        # CABF sections
        for match in self.explicit_patterns['cabf_section'].finditer(text):
            section = match.group(2)

            ref = IRReference(
                raw=match.group(0),
                doc_id='CABF',
                section=section,
                resolved=True,
                resolution_method='explicit',
            )
            references.append(ref)

        return references

    def _extract_implicit_references(
        self, text: str, context: Dict[str, Any]
    ) -> List[IRReference]:
        """提取隐式引用（需要上下文）"""
        references = []

        # Section only（如 "see Section 4.2"）
        for match in self.implicit_patterns['section_only'].finditer(text):
            section = match.group(1)

            # 从上下文推断文档
            doc_id = self._infer_document(section, context)

            if doc_id:
                ref = IRReference(
                    raw=match.group(0),
                    doc_id=doc_id,
                    section=section,
                    resolved=True,
                    resolution_method='implicit:context',
                )
                references.append(ref)
            else:
                # 无法解析
                ref = IRReference(
                    raw=match.group(0),
                    doc_id=None,
                    section=section,
                    resolved=False,
                    unresolved=True,
                    resolution_method='implicit:failed',
                )
                references.append(ref)

        return references

    def _infer_document(
        self, section: str, context: Dict[str, Any]
    ) -> Optional[str]:
        """从上下文推断文档ID"""
        # 策略1：使用最近的文档引用
        if 'recent_document' in context:
            return context['recent_document']

        # 策略2：使用当前规则所属文档
        if 'current_document' in context:
            return context['current_document']

        # 策略3：通过章节号匹配
        if self.standards_index:
            for doc_id, doc_info in self.standards_index.items():
                # 检查该文档是否有此章节
                sections = doc_info.get('sections', [])
                if section in sections or any(section in s for s in sections):
                    return doc_id

        # 策略4：使用 KG 查询
        if self.kg_client:
            result = self.kg_client.find_document_by_section(section)
            if result:
                return result['doc_id']

        return None

    def _resolve_reference(
        self, ref: IRReference, context: Optional[Dict[str, Any]]
    ) -> IRReference:
        """解析单个引用（验证其存在性）"""
        app_logger.debug(
            f"[Stage C Verify] Checking reference: raw='{ref.raw}', "
            f"doc_id={ref.doc_id}, section={ref.section}, resolved={ref.resolved}"
        )

        # 如果 doc_id 为 None 但有 section，使用当前文档ID（内部引用）
        effective_doc_id = ref.doc_id
        effective_standard_id = None  # 用于内部引用的standard_id

        if not effective_doc_id and ref.section and context:
            effective_doc_id = context.get('current_document')
            # 对于内部引用，直接获取standard_id用于验证
            effective_standard_id = context.get('standard_id')

            if effective_doc_id:
                app_logger.info(
                    f"[Stage C Verify] Internal reference detected: using current_document={effective_doc_id} "
                    f"(standard_id={effective_standard_id}) for section={ref.section}"
                )

        # 如果引用已有doc_id，检查是否是当前文档的内部引用（如RFC_154）
        elif effective_doc_id and context:
            current_doc = context.get('current_document')
            if current_doc and effective_doc_id == current_doc:
                # 这是内部引用（已被预解析），获取standard_id
                effective_standard_id = context.get('standard_id')
                app_logger.debug(
                    f"[Stage C Verify] Pre-resolved internal reference: doc_id={effective_doc_id}, standard_id={effective_standard_id}"
                )

        # 验证任何有 doc_id 和 section 的引用（不管初始 resolved 状态）
        if effective_doc_id and ref.section:
            # 验证引用是否真实存在
            exists = self._verify_reference_exists(
                effective_doc_id,
                ref.section,
                standard_id=effective_standard_id  # 传递standard_id用于内部引用
            )

            app_logger.debug(
                f"[Stage C Verify] Verification result for {effective_doc_id}:{ref.section} = {exists}"
            )

            if exists:
                # 更新引用的 doc_id（如果原来是 None）
                if not ref.doc_id and effective_doc_id:
                    ref.doc_id = effective_doc_id
                ref.resolved = True
                ref.unresolved = False
                app_logger.info(
                    f"[Stage C Verify] ✓ Marked as RESOLVED: {effective_doc_id}:{ref.section}"
                )
            else:
                ref.resolved = False
                ref.unresolved = True
                app_logger.info(
                    f"[Stage C Verify] ✗ Marked as UNRESOLVED: {ref.raw}"
                )
        else:
            app_logger.debug(
                f"[Stage C Verify] Skipped verification (missing doc_id or section): "
                f"doc_id={effective_doc_id}, section={ref.section}"
            )
            ref.resolved = False
            ref.unresolved = True

        return ref

    def _verify_reference_exists(
        self,
        doc_id: str,
        section: str,
        standard_id: Optional[int] = None
    ) -> bool:
        """
        验证引用是否存在

        Args:
            doc_id: 文档标识符（如 "RFC_154", "CABF" 等）
            section: 章节号
            standard_id: 可选的标准ID（内部引用时直接使用数据库ID）

        策略：使用数据库查询验证（优先），其次KG和索引
        """
        app_logger.info(
            f"[Stage C DB Verify] Starting verification for doc_id='{doc_id}', section='{section}', standard_id={standard_id}"
        )

        # 优先：使用数据库查询（与 _find_rule_by_section 逻辑一致）
        if self.db:
            app_logger.debug(f"[Stage C DB Verify] Database session available: {self.db}")
            try:
                from app.models.models import Rule, Standard

                # 查找标准（支持多种格式）
                standard = None

                # 如果提供了 standard_id，直接使用（内部引用的情况）
                if standard_id:
                    app_logger.info(
                        f"[Stage C DB Verify] Using provided standard_id={standard_id} for direct lookup"
                    )
                    standard = self.db.query(Standard).filter(Standard.id == standard_id).first()

                    if standard:
                        app_logger.info(
                            f"[Stage C DB Verify] ✓ Found standard by ID: id={standard.id}, "
                            f"source='{standard.source}', title='{standard.title}'"
                        )
                    else:
                        app_logger.warning(
                            f"[Stage C DB Verify] ✗ No standard found with id={standard_id}"
                        )

                # RFC 格式处理 (如果没有standard_id)
                elif doc_id.startswith('RFC'):
                    app_logger.debug(f"[Stage C DB Verify] Testing RFC format: doc_id='{doc_id}'")
                    rfc_match = re.match(r'RFC[_-]?(\d+)', doc_id)
                    app_logger.debug(f"[Stage C DB Verify] Regex match result: {rfc_match}")
                    if rfc_match:
                        rfc_number = rfc_match.group(1)
                        app_logger.info(
                            f"[Stage C DB Verify] RFC format detected: RFC{rfc_number}, "
                            f"querying Standard.source='RFC' AND title LIKE '%{rfc_number}%'"
                        )
                        standard = self.db.query(Standard).filter(
                            Standard.source == 'RFC',
                            Standard.title.like(f'%{rfc_number}%')
                        ).first()

                        if standard:
                            app_logger.info(
                                f"[Stage C DB Verify] ✓ Found standard: id={standard.id}, "
                                f"source='{standard.source}', title='{standard.title}'"
                            )
                        else:
                            app_logger.warning(
                                f"[Stage C DB Verify] ✗ No standard found for RFC{rfc_number}"
                            )
                    else:
                        app_logger.info(
                            f"[Stage C DB Verify] RFC without number, querying Standard.source='RFC'"
                        )
                        standard = self.db.query(Standard).filter(
                            Standard.source == 'RFC'
                        ).first()

                # CABF 格式处理
                elif doc_id == 'CABF':
                    app_logger.info(
                        f"[Stage C DB Verify] CABF format detected, "
                        f"querying Standard.source='CABF-Server'"
                    )
                    standard = self.db.query(Standard).filter(
                        Standard.source == 'CABF-Server'
                    ).first()

                    if standard:
                        app_logger.info(
                            f"[Stage C DB Verify] ✓ Found CABF-Server standard: id={standard.id}"
                        )
                    else:
                        app_logger.warning(
                            f"[Stage C DB Verify] ✗ No CABF-Server standard found"
                        )

                # 其他直接匹配
                else:
                    app_logger.info(
                        f"[Stage C DB Verify] Direct match, querying Standard.source='{doc_id}'"
                    )
                    standard = self.db.query(Standard).filter(
                        Standard.source == doc_id
                    ).first()

                # 如果找到标准，检查是否有该章节的规则
                if standard:
                    app_logger.info(
                        f"[Stage C DB Verify] Querying Rule.standard_id={standard.id} AND section='{section}'"
                    )
                    rule = self.db.query(Rule).filter(
                        Rule.standard_id == standard.id,
                        Rule.section == section
                    ).first()

                    if rule:
                        app_logger.info(
                            f"[Stage C DB Verify] ✓✓ VERIFICATION SUCCESS: "
                            f"{doc_id}:{section} → rule_id={rule.id}"
                        )
                        return True
                    else:
                        app_logger.warning(
                            f"[Stage C DB Verify] ⚠ Standard found but no rule with section '{section}'. "
                            f"Checking what sections exist..."
                        )
                        # 查询该标准的所有章节号（调试用）
                        all_sections = self.db.query(Rule.section).filter(
                            Rule.standard_id == standard.id
                        ).distinct().limit(10).all()
                        section_samples = [s[0] for s in all_sections]
                        app_logger.warning(
                            f"[Stage C DB Verify] Sample sections in standard {standard.id}: {section_samples}"
                        )

                        # 标准存在但没有该章节的规则，也算验证通过（引用是有效的）
                        app_logger.info(
                            f"[Stage C DB Verify] ✓ VERIFICATION SUCCESS (standard exists): {doc_id}:{section}"
                        )
                        return True
                else:
                    app_logger.warning(
                        f"[Stage C DB Verify] ✗ No standard found for doc_id='{doc_id}'"
                    )

            except Exception as e:
                app_logger.error(
                    f"[Stage C DB Verify] ✗✗ Database verification EXCEPTION for {doc_id}:{section}: {e}",
                    exc_info=True
                )
        else:
            app_logger.warning(
                f"[Stage C DB Verify] ✗ No database session available (self.db is None)"
            )

        # 备选：从 KG 验证
        if self.kg_client:
            app_logger.debug(f"[Stage C KG Verify] Trying KG verification...")
            node_id = f"standard_section:{doc_id}:{section}"
            node = self.kg_client.get_node(node_id)
            if node:
                app_logger.info(f"[Stage C KG Verify] ✓ Found in KG: {node_id}")
                return True

        # 备选：从索引验证
        if doc_id in self.standards_index:
            app_logger.debug(f"[Stage C Index Verify] Trying index verification...")
            doc_info = self.standards_index[doc_id]
            sections = doc_info.get('sections', [])
            if section in sections:
                app_logger.info(f"[Stage C Index Verify] ✓ Found in index: {doc_id}:{section}")
                return True

        app_logger.warning(
            f"[Stage C FINAL] ✗✗ VERIFICATION FAILED: {doc_id}:{section} (no DB/KG/Index match)"
        )
        return False

    def resolve_batch(
        self,
        irs: List[IntermediateRepresentation],
        global_context: Optional[Dict[str, Any]] = None,
    ) -> List[IntermediateRepresentation]:
        """
        批量解析引用

        Args:
            irs: IR 列表
            global_context: 全局上下文

        Returns:
            解析后的 IR 列表
        """
        context = global_context or {}

        for i, ir in enumerate(irs):
            # 更新上下文
            if ir.provenance:
                context['current_document'] = ir.provenance[0].source_id

            # 从前一个 IR 更新最近文档
            if i > 0 and irs[i - 1].references:
                for ref in irs[i - 1].references:
                    if ref.doc_id:
                        context['recent_document'] = ref.doc_id
                        break

            # 解析当前 IR
            irs[i] = self.resolve_references(ir, context)

        return irs

    def get_unresolved_references(
        self, irs: List[IntermediateRepresentation]
    ) -> List[Dict[str, Any]]:
        """获取所有未解析的引用"""
        unresolved = []

        for ir in irs:
            for ref in ir.references:
                if ref.unresolved or not ref.resolved:
                    unresolved.append({
                        'rule_id': ir.rule_id,
                        'reference': ref,
                        'rule_text': ir.rule_text,
                    })

        return unresolved

    # =========================================================================
    # 重构后：ReferenceFact 输出（用于 Rule Reasoning Service）
    # =========================================================================

    def extract_reference_facts(
        self,
        irs: List[IntermediateRepresentation]
    ) -> List[Dict[str, Any]]:
        """
        从 IR 列表中提取 ReferenceFact

        这是 Stage C 的新输出格式，用于 Rule Reasoning Service

        ReferenceFact 格式：
        {
            'source_rule_id': int,
            'structural_rule_id': Optional[int],  # 仅结构映射（索引查找）
            'resolution_method': str,  # 'structural_match_only', 'contextual', etc.
            'raw_reference_text': str,
            'target_section': str,
            'target_doc_id': str,
            'confidence': float
        }

        ⚠️ 约束：
        - structural_rule_id 只能通过数据库索引查找获得
        - 不允许任何语义推理
        - 如果找不到精确匹配的规则，structural_rule_id = None
        """
        if not self.db:
            app_logger.warning(
                "[Stage C] No database session provided, "
                "cannot lookup structural_rule_id"
            )
            return []

        reference_facts = []

        # 调试统计
        total_irs = len(irs)
        irs_with_refs = 0
        irs_without_rule_id = 0
        refs_unresolved = 0
        refs_resolved = 0

        for ir in irs:
            if not ir.references:
                continue

            irs_with_refs += 1

            # 获取 source_rule_id（从 IR 的 rule_id 提取）
            source_rule_id = self._extract_rule_id_from_ir(ir)
            if not source_rule_id:
                irs_without_rule_id += 1
                app_logger.debug(
                    f"[Stage C] IR has references but no rule_id: {ir.rule_text[:50]}..."
                )
                continue

            for ref in ir.references:
                if not ref.resolved or not ref.doc_id or not ref.section:
                    # 跳过未解析的引用
                    refs_unresolved += 1
                    app_logger.debug(
                        f"[Stage C] Unresolved reference: resolved={ref.resolved}, "
                        f"doc_id={ref.doc_id}, section={ref.section}, raw={ref.raw}"
                    )
                    continue

                refs_resolved += 1

                # 查找 structural_rule_id（纯索引查找）
                structural_rule_id = self._find_rule_by_section(
                    ref.doc_id,
                    ref.section
                )

                # 创建 ReferenceFact
                fact = {
                    'source_rule_id': source_rule_id,
                    'structural_rule_id': structural_rule_id,
                    'resolution_method': self._get_resolution_method(ref, structural_rule_id),
                    'raw_reference_text': ref.raw,
                    'target_section': ref.section,
                    'target_doc_id': ref.doc_id
                }

                reference_facts.append(fact)

        app_logger.info(
            f"[Stage C] Extracted {len(reference_facts)} reference facts "
            f"from {len(irs)} IRs: "
            f"irs_with_refs={irs_with_refs}, "
            f"irs_without_rule_id={irs_without_rule_id}, "
            f"refs_resolved={refs_resolved}, "
            f"refs_unresolved={refs_unresolved}"
        )

        return reference_facts

    def extract_reference_facts_from_saved_rules(
        self,
        standard_id: int,
        resolved_irs: List[IntermediateRepresentation]
    ) -> List[Dict]:
        """
        从已保存到数据库的规则中提取 ReferenceFact

        这个方法在规则保存后调用，通过匹配section来找到对应的数据库ID

        Args:
            standard_id: 标准ID
            resolved_irs: 已解析引用的IR列表（保存前的IRs，包含resolved references）

        Returns:
            ReferenceFact 列表
        """
        from app.models.models import Rule, Standard

        if not self.db:
            app_logger.warning(
                "[Stage C Post-Save] No database session, cannot extract reference facts"
            )
            return []

        reference_facts = []

        # 获取这个标准的所有已保存规则（按section索引）
        saved_rules = self.db.query(Rule).filter(Rule.standard_id == standard_id).all()

        # 创建section到规则列表的映射（FIX: 一个section可能有多条规则）
        section_to_rules = {}
        for rule in saved_rules:
            if rule.section:
                if rule.section not in section_to_rules:
                    section_to_rules[rule.section] = []
                section_to_rules[rule.section].append(rule)

        app_logger.info(
            f"[Stage C Post-Save] Building reference facts from {len(resolved_irs)} IRs "
            f"with {len(saved_rules)} saved rules in {len(section_to_rules)} sections"
        )

        # 统计
        irs_with_refs = 0
        irs_matched = 0
        refs_resolved = 0
        refs_unresolved = 0

        for ir in resolved_irs:
            if not ir.references or len(ir.references) == 0:
                continue

            irs_with_refs += 1

            # 通过provenance的section匹配找到数据库ID（FIX: 使用文本相似度匹配）
            source_rule_id = None
            if ir.provenance and len(ir.provenance) > 0:
                source_section = ir.provenance[0].section
                candidate_rules = section_to_rules.get(source_section, [])

                if len(candidate_rules) == 0:
                    app_logger.debug(
                        f"[Stage C Post-Save] No saved rules found for section={source_section}"
                    )
                    continue
                elif len(candidate_rules) == 1:
                    # 只有一条规则，直接使用
                    source_rule_id = candidate_rules[0].id
                else:
                    # 多条规则，使用文本相似度匹配
                    best_match = None
                    best_score = 0

                    for candidate in candidate_rules:
                        # 计算IR规则文本和候选规则的相似度
                        score = self._text_similarity(ir.rule_text, candidate.text)
                        if score > best_score:
                            best_score = score
                            best_match = candidate

                    if best_match and best_score > 0.5:  # 相似度阈值
                        source_rule_id = best_match.id
                        app_logger.debug(
                            f"[Stage C Post-Save] Matched IR to rule {best_match.id} "
                            f"with similarity {best_score:.2f} (section {source_section} has {len(candidate_rules)} rules)"
                        )
                    else:
                        app_logger.warning(
                            f"[Stage C Post-Save] Cannot match IR to any rule in section {source_section} "
                            f"(best_score={best_score:.2f}, candidates={len(candidate_rules)})"
                        )
                        continue

            if not source_rule_id:
                app_logger.debug(
                    f"[Stage C Post-Save] Cannot find saved rule for IR section={ir.provenance[0].section if ir.provenance else 'N/A'}"
                )
                continue

            irs_matched += 1

            for ref in ir.references:
                if not ref.resolved or not ref.doc_id or not ref.section:
                    refs_unresolved += 1
                    continue

                refs_resolved += 1

                # 查找structural_rule_id
                structural_rule_id = self._find_rule_by_section(
                    ref.doc_id,
                    ref.section
                )

                fact = {
                    'source_rule_id': source_rule_id,
                    'structural_rule_id': structural_rule_id,
                    'resolution_method': self._get_resolution_method(ref, structural_rule_id),
                    'raw_reference_text': ref.raw,
                    'target_section': ref.section,
                    'target_doc_id': ref.doc_id
                }

                reference_facts.append(fact)

        app_logger.info(
            f"[Stage C Post-Save] Extracted {len(reference_facts)} reference facts: "
            f"irs_with_refs={irs_with_refs}, irs_matched={irs_matched}, "
            f"refs_resolved={refs_resolved}, refs_unresolved={refs_unresolved}"
        )

        return reference_facts

    def _extract_rule_id_from_ir(self, ir: IntermediateRepresentation) -> Optional[int]:
        """
        从 IR 中提取 rule_id

        假设 IR 已保存到数据库，且有 rule_id 字段
        """
        # 如果 IR 还没有保存到数据库，rule_id 可能是字符串格式
        # 这里假设在调用 extract_reference_facts 之前，
        # IR 已经保存到数据库，并且 rule_id 已更新为数据库 ID

        if hasattr(ir, 'db_id') and ir.db_id:
            return ir.db_id

        # 如果 rule_id 是整数，直接返回
        if isinstance(ir.rule_id, int):
            return ir.rule_id

        # 如果 rule_id 是字符串形式的整数，转换后返回
        if isinstance(ir.rule_id, str):
            try:
                return int(ir.rule_id)
            except (ValueError, TypeError):
                pass

        # 否则返回 None（需要先保存规则）
        return None

    def _find_rule_by_section(
        self,
        doc_id: str,
        section: str
    ) -> Optional[int]:
        """
        通过 doc_id + section 查找规则 ID

        ⚠️ 这是纯索引查找，不做任何语义推理

        Args:
            doc_id: 文档ID（如 "RFC5280", "CABF", "CABF-Server"）
            section: 章节号（如 "4.2.1.3"）

        Returns:
            规则ID（如果找到），否则 None
        """
        if not self.db:
            return None

        try:
            from app.models.models import Rule, Standard

            # 1. 查找标准（支持多种格式）
            standard = None

            # RFC 格式: "RFC5280" or "RFC_154" → 查找 source="RFC" AND title LIKE "%5280%" or "%154%"
            if doc_id.startswith('RFC'):
                app_logger.debug(f"[Stage C] Testing RFC format in _find_rule_by_section: doc_id='{doc_id}'")
                rfc_match = re.match(r'RFC[_-]?(\d+)', doc_id)
                app_logger.debug(f"[Stage C] Regex match result: {rfc_match}")
                if rfc_match:
                    rfc_number = rfc_match.group(1)
                    standard = self.db.query(Standard).filter(
                        Standard.source == 'RFC',
                        Standard.title.like(f'%{rfc_number}%')
                    ).first()

                    if not standard:
                        app_logger.debug(
                            f"[Stage C] No standard found for RFC {rfc_number}"
                        )
                else:
                    # "RFC" without number → try direct match
                    standard = self.db.query(Standard).filter(
                        Standard.source == 'RFC'
                    ).first()

            # CABF 格式: "CABF" → 需要从context推断具体文档
            # 默认尝试 CABF-Server（最常见）
            elif doc_id == 'CABF':
                standard = self.db.query(Standard).filter(
                    Standard.source == 'CABF-Server'
                ).first()

                if not standard:
                    app_logger.debug(
                        "[Stage C] Generic CABF reference, tried CABF-Server but not found"
                    )

            # 其他格式: 直接匹配 source（如 "CABF-Server", "CABF-EV", "ETSI"）
            else:
                standard = self.db.query(Standard).filter(
                    Standard.source == doc_id
                ).first()

            if not standard:
                app_logger.debug(
                    f"[Stage C] No standard found for doc_id={doc_id}"
                )
                return None

            # 2. 查找规则（section 精确匹配）
            rule = self.db.query(Rule).filter(
                Rule.standard_id == standard.id,
                Rule.section == section
            ).first()

            if rule:
                app_logger.debug(
                    f"[Stage C] Found rule {rule.id} for {doc_id}:{section}"
                )
                return rule.id
            else:
                app_logger.debug(
                    f"[Stage C] No rule found with section={section} in standard {standard.id} ({standard.source})"
                )

            return None

        except Exception as e:
            app_logger.warning(
                f"[Stage C] Failed to lookup rule for {doc_id}:{section}: {e}"
            )
            return None

    def _text_similarity(self, text1: str, text2: str) -> float:
        """
        计算两个文本的相似度（Jaccard similarity）

        Args:
            text1: 第一个文本
            text2: 第二个文本

        Returns:
            相似度分数 (0.0 - 1.0)
        """
        if not text1 or not text2:
            return 0.0

        # 转为小写并分词
        words1 = set(text1.lower().split())
        words2 = set(text2.lower().split())

        if not words1 or not words2:
            return 0.0

        # Jaccard相似度：交集/并集
        intersection = len(words1 & words2)
        union = len(words1 | words2)

        return intersection / union if union > 0 else 0.0

    def _get_resolution_method(
        self,
        ref: IRReference,
        structural_rule_id: Optional[int]
    ) -> str:
        """
        确定解析方法

        规则：
        - 如果找到了 structural_rule_id，则为 'structural_match_only'
        - 否则，使用引用原始的 resolution_method
        """
        if structural_rule_id:
            return 'structural_match_only'
        else:
            # 没有找到规则，可能是引用了章节但该章节没有规则
            return ref.resolution_method or 'no_rule_found'
