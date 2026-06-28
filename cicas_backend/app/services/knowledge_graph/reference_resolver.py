"""
跨文档引用解析器
处理规则中的跨文档引用，构建完整的验证规则链
"""
import re
from typing import List, Dict, Optional, Tuple
from sqlalchemy.orm import Session

from app.models.models import Standard, Rule, StandardRelationship
from app.core.logging_config import app_logger


class ReferenceResolver:
    """
    引用解析器

    功能：
    1. 识别规则中的跨文档引用（如 "RFC 5280, Section 4.2.1.9"）
    2. 解析并加载被引用的规则
    3. 构建引用链（rule A → rule B → rule C）
    4. 检测循环引用
    5. 生成完整的验证规则集
    """

    # 引用模式正则表达式（增强版，与UniversalReferenceDetector保持一致）
    REFERENCE_PATTERNS = [
        # ========== RFC 引用模式（优先级从高到低）==========

        # 模式1: 多RFC并列引用
        # 示例: RFC 5280 and RFC 6125, RFC 5280, RFC 6125, RFC5280/RFC6125
        (r'\bRFC[-\s]?(\d{3,5})\s*(?:,|and|/|&)\s*RFC[-\s]?(\d{3,5})', 'RFC_MULTIPLE'),

        # 模式2: [RFC<number> Section X.Y.Z] - 方括号内带章节
        # 示例: [RFC5280 Section 4.2.1.9], [RFC 5280 Section 4.2.1]
        (r'\[RFC[-\s]?(\d{3,5})\s+Section\s+(\d+(?:\.\d+)*)\]', 'RFC_BRACKET_WITH_SECTION'),

        # 模式3: [RFC<number>] - 纯方括号格式
        # 示例: [RFC5280], [RFC 5280]
        (r'\[RFC[-\s]?(\d{3,5})\]', 'RFC_BRACKET'),

        # 模式4: RFC <number> Section X.Y.Z - 标准格式
        # 支持: RFC 5280 Section 4.2, RFC-5280 Section 4.2, RFC5280 Section 4.2
        (r'\bRFC[-\s]?(\d{3,5})\s*,?\s+[Ss]ection\s+(\d+(?:\.\d+)*)', 'RFC_WITH_SECTION'),

        # 模式5: RFC <number> Sec. X.Y.Z / RFC <number> Sec X.Y.Z - Sec缩写
        # 示例: RFC 5280 Sec. 4.2.1, RFC 5280 Sec 4.2.1
        (r'\bRFC[-\s]?(\d{3,5})\s*,?\s+[Ss]ec\.?\s+(\d+(?:\.\d+)*)', 'RFC_WITH_SEC'),

        # 模式6: RFC <number> Clause X.Y.Z
        # 示例: RFC 5280 Clause 4.2.1
        (r'\bRFC[-\s]?(\d{3,5})\s*,?\s+[Cc]lause\s+(\d+(?:\.\d+)*)', 'RFC_WITH_CLAUSE'),

        # 模式7: RFC <number> Appendix X
        # 示例: RFC 5280 Appendix A, RFC 5280 Appendix B.1
        (r'\bRFC[-\s]?(\d{3,5})\s+[Aa]ppendix\s+([A-Z](?:\.\d+)*)', 'RFC_WITH_APPENDIX'),

        # 模式8: RFC <number> - 纯RFC编号（支持多种格式）
        # 示例: RFC 5280, RFC-5280, RFC5280
        (r'\bRFC[-\s]?(\d{3,5})\b', 'RFC_ONLY'),

        # ========== CABF 引用模式 ==========
        # CABF 引用: "CA/Browser Forum Baseline Requirements", "BR Section 7.1.2.3"
        (r'(?:CA/?Browser\s+Forum\s+)?(?:Baseline\s+Requirements|BR)(?:\s+[Ss]ection\s+([\d.]+))?', 'CABF'),

        # ========== ETSI 引用模式 ==========
        # ETSI 引用: "ETSI EN 319 411-1", "ETSI EN 319 411-1 Section 5.2"
        (r'ETSI\s+EN\s+([\d\s-]+)(?:\s+[Ss]ection\s+([\d.]+))?', 'ETSI'),

        # ========== 独立章节/条款/附录引用（需要上下文）==========
        # Section 引用: "Section 4.2.1.9", "section 4.2"
        (r'\b[Ss]ection\s+(\d+(?:\.\d+)*)', 'SECTION_ONLY'),

        # Sec 缩写: "Sec. 4.2.1", "Sec 4.2"
        (r'\b[Ss]ec\.?\s+(\d+(?:\.\d+)*)', 'SEC_ONLY'),

        # Clause 引用: "Clause 7.1.2", "clause 7.1"
        (r'\b[Cc]lause\s+(\d+(?:\.\d+)*)', 'CLAUSE_ONLY'),

        # Appendix 引用: "Appendix A", "Appendix B.1"
        (r'\b[Aa]ppendix\s+([A-Z](?:\.\d+)*)', 'APPENDIX_ONLY'),
    ]

    def __init__(self, db: Session):
        self.db = db
        self._reference_cache = {}  # 缓存已解析的引用

    def resolve_all_references(self, rule_candidates: list = None) -> Dict:
        """
        解析规则中的跨文档引用

        Args:
            rule_candidates: 待处理的规则列表。如果提供，只处理这些规则；
                           如果为None，则查询数据库中所有规则。

        Returns:
            引用解析报告
        """
        # 使用传入的规则列表，或查询全部
        if rule_candidates is not None:
            all_rules = rule_candidates
            app_logger.info(
                f"[ReferenceResolver] Starting reference resolution for {len(all_rules)} rules (scoped)"
            )
        else:
            all_rules = self.db.query(Rule).filter(
            ).all()
            app_logger.info(
                f"[ReferenceResolver] Starting cross-document reference resolution for {len(all_rules)} rules (all)"
            )

        references_found = 0
        references_resolved = 0
        resolution_details = []
        unresolved_docs = {}  # 汇总未解析的外部文档 {doc_name: count}

        # 2. 扫描每条规则的引用
        for rule in all_rules:
            refs = self._extract_references(rule)

            if refs:
                references_found += len(refs)
                app_logger.debug(
                    f"[ReferenceResolver] Found {len(refs)} references in rule {rule.id} "
                    f"from {rule.standard.title}"
                )

                # 3. 解析每个引用
                for ref in refs:
                    resolved = self._resolve_reference(rule, ref)
                    if resolved:
                        references_resolved += 1
                        resolution_details.append(resolved)
                    else:
                        # 汇总未解析的文档引用
                        doc_name = ref.get('document', 'unknown')
                        unresolved_docs[doc_name] = unresolved_docs.get(doc_name, 0) + 1

                # 4. 更新规则的引用元数据
                self._update_rule_references(rule, refs)

        # 汇总日志：未解析的外部文档
        if unresolved_docs:
            sorted_docs = sorted(unresolved_docs.items(), key=lambda x: x[1], reverse=True)
            top_docs = sorted_docs[:10]
            summary = ", ".join(f"{name} ×{count}" for name, count in top_docs)
            if len(sorted_docs) > 10:
                summary += f", ... ({len(sorted_docs) - 10} more)"
            app_logger.warning(
                f"[ReferenceResolver] {sum(unresolved_docs.values())} references to "
                f"{len(unresolved_docs)} external documents could not be resolved: {summary}"
            )

        app_logger.info(
            f"[ReferenceResolver] Resolved {references_resolved}/{references_found} references"
        )

        return {
            'total_references_found': references_found,
            'references_resolved': references_resolved,
            'resolution_details': resolution_details,
            'unresolved_documents': unresolved_docs
        }

    def _extract_references(self, rule: Rule) -> List[Dict]:
        """
        从规则文本中提取所有引用（使用增强模式）

        Returns:
            引用列表，每个引用包含：
            - raw_text: 原始引用文本
            - document: 被引用文档（如 "RFC 5280"）
            - section: 章节号（如 "4.2.1.9"）
            - match_type: 匹配类型（RFC, CABF, ETSI, etc.）
            - pattern_name: 匹配的模式名称
        """
        references = []
        # FIX: 只扫描 rule.text，不扫描 rule.context
        # context 可能包含表格数据，表格中的"See Section X.Y.Z"不是真实引用
        # 真实的跨规则引用应该出现在规则正文（text）中
        text = rule.text

        if not text:
            return references

        # 用于上下文绑定（记录最近的RFC编号）
        last_rfc_number = None

        for pattern_tuple in self.REFERENCE_PATTERNS:
            pattern, pattern_name = pattern_tuple
            matches = re.finditer(pattern, text, re.IGNORECASE)

            for match in matches:
                # 特殊处理：多RFC并列引用
                if pattern_name == 'RFC_MULTIPLE':
                    rfc1 = match.group(1)
                    rfc2 = match.group(2)

                    # 添加两个独立引用
                    ref1 = {
                        'raw_text': f"RFC {rfc1}",
                        'document': f'RFC {rfc1}',
                        'section': None,
                        'match_type': 'RFC',
                        'pattern_name': pattern_name,
                        'document_identifier': f'RFC{rfc1}'
                    }
                    ref2 = {
                        'raw_text': f"RFC {rfc2}",
                        'document': f'RFC {rfc2}',
                        'section': None,
                        'match_type': 'RFC',
                        'pattern_name': pattern_name,
                        'document_identifier': f'RFC{rfc2}'
                    }

                    if ref1 not in references:
                        references.append(ref1)
                    if ref2 not in references:
                        references.append(ref2)

                    last_rfc_number = rfc2
                    continue

                # 常规引用处理
                ref = self._parse_reference_match(match, pattern_name)
                if ref:
                    # 上下文绑定：如果是独立的Section/Clause/Appendix，绑定到最近的RFC
                    if pattern_name in ['SECTION_ONLY', 'SEC_ONLY', 'CLAUSE_ONLY', 'APPENDIX_ONLY']:
                        if last_rfc_number:
                            ref['document'] = f'RFC {last_rfc_number}'
                            ref['document_identifier'] = f'RFC{last_rfc_number}'
                            ref['context_bound'] = True

                    if ref not in references:
                        references.append(ref)

                    # 更新最近的RFC编号
                    if ref.get('match_type') == 'RFC' and 'document_identifier' in ref:
                        rfc_num = ref['document_identifier'].replace('RFC', '')
                        last_rfc_number = rfc_num

        return references

    def _parse_reference_match(self, match: re.Match, pattern_name: str) -> Optional[Dict]:
        """
        解析正则匹配结果为引用对象（增强版）

        Args:
            match: 正则匹配对象
            pattern_name: 模式名称

        Returns:
            引用字典或None
        """
        full_text = match.group(0)
        groups = match.groups()

        # RFC 相关引用
        if pattern_name.startswith('RFC_'):
            # 提取RFC编号（第一个捕获组）
            rfc_number = groups[0] if groups else None
            # 提取章节号（第二个捕获组，如果有）
            section = groups[1] if len(groups) > 1 and groups[1] else None

            if rfc_number:
                return {
                    'raw_text': full_text,
                    'document': f'RFC {rfc_number}',
                    'section': section,
                    'match_type': 'RFC',
                    'pattern_name': pattern_name,
                    'document_identifier': f'RFC{rfc_number}'
                }

        # CABF 引用
        elif pattern_name == 'CABF':
            section = groups[0] if groups and groups[0] else None
            return {
                'raw_text': full_text,
                'document': 'CA/Browser Forum Baseline Requirements',
                'section': section,
                'match_type': 'CABF',
                'pattern_name': pattern_name,
                'document_identifier': 'CABF-BR'
            }

        # ETSI 引用
        elif pattern_name == 'ETSI':
            etsi_number = groups[0] if groups else None
            section = groups[1] if len(groups) > 1 and groups[1] else None

            if etsi_number:
                return {
                    'raw_text': full_text,
                    'document': f'ETSI EN {etsi_number}',
                    'section': section,
                    'match_type': 'ETSI',
                    'pattern_name': pattern_name,
                    'document_identifier': f'ETSI-EN-{etsi_number.replace(" ", "")}'
                }

        # 独立章节/条款/附录引用（需要上下文绑定）
        elif pattern_name in ['SECTION_ONLY', 'SEC_ONLY', 'CLAUSE_ONLY', 'APPENDIX_ONLY']:
            section = groups[0] if groups else None
            if section:
                return {
                    'raw_text': full_text,
                    'document': None,  # 需要上下文绑定
                    'section': section,
                    'match_type': pattern_name.replace('_ONLY', ''),
                    'pattern_name': pattern_name,
                    'document_identifier': None,  # 需要上下文绑定
                    'requires_context': True
                }

        return None

    def _resolve_reference(self, source_rule: Rule, reference: Dict) -> Optional[Dict]:
        """
        解析单个引用，找到被引用的规则

        Args:
            source_rule: 包含引用的源规则
            reference: 引用信息

        Returns:
            解析结果
        """
        # 1. 找到被引用的文档
        target_standard = self._find_referenced_standard(
            reference['document'],
            reference['document_identifier'],
            source_rule.standard
        )

        if not target_standard:
            # 不在此处打 WARNING，由 resolve_all_references 汇总输出
            app_logger.debug(
                f"Cannot find referenced document: {reference['document']} "
                f"from rule {source_rule.id}"
            )
            return None

        # 2. 找到被引用的规则（如果指定了section）
        target_rules = []
        if reference['section']:
            target_rules = self._find_rules_by_section(
                target_standard,
                reference['section']
            )

            # Fallback: 如果在目标文档中找不到规则，且引用是通过上下文绑定的，
            # 尝试在当前文档（source_standard）中查找
            if not target_rules and reference.get('context_bound'):
                app_logger.debug(
                    f"Context-bound reference not found in {target_standard.title}, "
                    f"trying current document {source_rule.standard.title}"
                )

                # 尝试在当前文档中查找
                fallback_rules = self._find_rules_by_section(
                    source_rule.standard,
                    reference['section']
                )

                if fallback_rules:
                    # 找到了！使用当前文档的规则
                    target_standard = source_rule.standard
                    target_rules = fallback_rules
                    app_logger.debug(
                        f"Found {len(fallback_rules)} rules in current document "
                        f"for section {reference['section']}"
                    )

        if not target_rules:
            # 没有找到特定规则，返回文档级引用
            app_logger.debug(
                f"Referenced document {target_standard.title} but no specific rules found "
                f"for section {reference['section']}"
            )

        # 3. 创建引用链
        return {
            'source_rule_id': source_rule.id,
            'source_standard': source_rule.standard.title,
            'reference_text': reference['raw_text'],
            'target_standard_id': target_standard.id,
            'target_standard': target_standard.title,
            'target_section': reference['section'],
            'target_rules': [
                {
                    'id': rule.id,
                    'section': rule.section,
                    'text': rule.text[:100]
                }
                for rule in target_rules
            ],
            'resolved': len(target_rules) > 0
        }

    def _find_referenced_standard(
        self,
        document_name: Optional[str],
        document_identifier: Optional[str],
        source_standard: Standard
    ) -> Optional[Standard]:
        """
        查找被引用的标准文档

        策略：
        0. 如果两个参数都是 None，返回 source_standard（文档内部引用）
        1. 精确匹配 document_identifier
        2. 模糊匹配 document_name
        3. 检查已知的文档关系
        """
        # 策略0: 文档内部引用（没有文档名称，默认指向当前文档）
        if not document_name and not document_identifier:
            app_logger.debug(
                f"Internal reference detected (no document name), "
                f"assuming reference to current document: {source_standard.title}"
            )
            return source_standard

        # 检查缓存
        cache_key = f"{document_identifier or document_name}"
        if cache_key in self._reference_cache:
            return self._reference_cache[cache_key]

        # 策略1: 精确匹配标题
        if document_name:
            standard = self.db.query(Standard).filter(
                Standard.title.like(f'%{document_name}%'),
                Standard.is_latest == True
            ).first()

            if standard:
                self._reference_cache[cache_key] = standard
                return standard

        # 策略2: 检查文档关系
        # 查询源文档引用的所有文档
        relationships = self.db.query(StandardRelationship).filter(
            StandardRelationship.source_standard_id == source_standard.id,
            StandardRelationship.relationship_type.in_(['references', 'depends_on']),
            StandardRelationship.is_active == True
        ).all()

        for rel in relationships:
            target_std = self.db.query(Standard).filter(
                Standard.id == rel.target_standard_id
            ).first()

            if target_std and document_name:
                if document_name.upper() in target_std.title.upper():
                    self._reference_cache[cache_key] = target_std
                    return target_std

        # 策略3: 按文档类型和标识符查找
        if document_identifier:
            if document_identifier.startswith('RFC'):
                rfc_num = document_identifier.replace('RFC', '')
                standard = self.db.query(Standard).filter(
                    Standard.source == 'RFC',
                    Standard.title.like(f'%{rfc_num}%'),
                    Standard.is_latest == True
                ).first()

                if standard:
                    self._reference_cache[cache_key] = standard
                    return standard

            elif document_identifier.startswith('CABF'):
                # 修复：CABF标准的source是'CABF-Server', 'CABF-EV'等，需要用LIKE匹配
                standard = self.db.query(Standard).filter(
                    Standard.source.like('CABF%'),
                    Standard.is_latest == True
                ).first()

                if standard:
                    self._reference_cache[cache_key] = standard
                    return standard

        return None

    def _find_rules_by_section(
        self,
        standard: Standard,
        section: str
    ) -> List[Rule]:
        """
        在标准文档中查找特定章节的规则

        支持模糊匹配（如 "4.2.1.9" 可以匹配 "4.2.1.9.1"）
        """
        # 精确匹配
        exact_match = self.db.query(Rule).filter(
            Rule.standard_id == standard.id,
            Rule.section == section
        ).all()

        if exact_match:
            return exact_match

        # 模糊匹配（章节前缀）
        prefix_match = self.db.query(Rule).filter(
            Rule.standard_id == standard.id,
            Rule.section.like(f'{section}.%')
        ).all()

        return prefix_match

    def _update_rule_references(self, rule: Rule, references: List[Dict]) -> None:
        """更新规则的引用元数据"""
        import json

        metadata = json.loads(rule.ir_data) if rule.ir_data else {}

        metadata['references'] = [
            {
                'raw_text': ref['raw_text'],
                'document': ref['document'],
                'section': ref['section'],
                'match_type': ref['match_type']
            }
            for ref in references
        ]

        rule.ir_data = json.dumps(metadata, ensure_ascii=False)
        self.db.commit()

    def get_rule_with_references(self, rule_id: int) -> Dict:
        """
        获取规则及其所有被引用的规则

        Returns:
            包含规则本身和所有被引用规则的完整信息
        """
        rule = self.db.query(Rule).filter(Rule.id == rule_id).first()

        if not rule:
            return {'error': 'Rule not found'}

        # 提取引用
        references = self._extract_references(rule)

        # 解析所有引用
        referenced_rules = []
        for ref in references:
            resolved = self._resolve_reference(rule, ref)
            if resolved and resolved['resolved']:
                referenced_rules.extend(resolved['target_rules'])

        return {
            'rule': {
                'id': rule.id,
                'standard': rule.standard.title,
                'section': rule.section,
                'text': rule.text,
                'affected_field': rule.subject,
                'operation': rule.predicate,
                'expected_value': rule.constraint_value
            },
            'references': [
                {
                    'reference_text': ref['raw_text'],
                    'document': ref['document'],
                    'section': ref['section']
                }
                for ref in references
            ],
            'referenced_rules': referenced_rules
        }

    def detect_circular_references(self) -> List[Dict]:
        """
        检测循环引用

        Returns:
            循环引用链列表
        """
        app_logger.info("[ReferenceResolver] Detecting circular references")

        # 构建引用图
        reference_graph = {}

        all_rules = self.db.query(Rule).filter(
        ).all()

        for rule in all_rules:
            refs = self._extract_references(rule)
            reference_graph[rule.id] = []

            for ref in refs:
                resolved = self._resolve_reference(rule, ref)
                if resolved and resolved['resolved']:
                    for target_rule in resolved['target_rules']:
                        reference_graph[rule.id].append(target_rule['id'])

        # 使用DFS检测环
        circular_chains = []
        visited = set()

        def dfs(node, path):
            if node in path:
                # 找到环
                cycle_start = path.index(node)
                cycle = path[cycle_start:]
                circular_chains.append(cycle + [node])
                return

            if node in visited:
                return

            visited.add(node)
            path.append(node)

            for neighbor in reference_graph.get(node, []):
                dfs(neighbor, path.copy())

        for rule_id in reference_graph:
            dfs(rule_id, [])

        if circular_chains:
            app_logger.warning(
                f"[ReferenceResolver] Found {len(circular_chains)} circular reference chains"
            )

        return circular_chains
