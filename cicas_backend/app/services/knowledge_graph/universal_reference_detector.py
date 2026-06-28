"""
通用引用检测器（Universal Reference Detector）

实现文档无关的引用检测系统，遵循以下原则：
1. 不区分 CABF→RFC、RFC→RFC、ETSI→RFC 等文档类型
2. 统一的引用识别和解析流程
3. 引用分类而不展开
4. 可扩展的文档类型支持

设计规范：
- 引用是规则间的关系，而不是文档间的特例行为
- 禁止基于文档类型的 if-else 特判
- 所有引用检测基于可配置的模式匹配
"""

from typing import Dict, List, Optional, Tuple, Set
from sqlalchemy.orm import Session
from app.models.models import Rule, Standard
from app.core.unified_abstractions import (
    RuleReference, ReferenceType, ReferenceRelationship,
    DocumentType, DOCUMENT_TYPE_REGISTRY
)
from app.core.logging_config import app_logger
import re
from dataclasses import dataclass


# ============================================================
# 引用模式定义（可配置）
# ============================================================

@dataclass
class ReferencePattern:
    """
    引用模式定义

    每种文档类型都可以定义多个引用模式
    """
    name: str  # 模式名称，如 "RFC_WITH_SECTION"
    regex: re.Pattern  # 正则表达式
    doc_type: DocumentType  # 目标文档类型
    capture_groups: Dict[str, int]  # 捕获组映射，如 {"doc_id": 1, "section": 2}
    priority: int  # 优先级（数值越大优先级越高）
    requires_context: bool = False  # 是否需要上下文验证


class ReferencePatternRegistry:
    """
    引用模式注册表

    管理所有文档类型的引用模式，替代硬编码
    """

    def __init__(self):
        self.patterns: List[ReferencePattern] = []
        self._initialize_default_patterns()

    def _initialize_default_patterns(self):
        """初始化默认引用模式"""

        # ========== RFC 引用模式（优先级从高到低）==========

        # 模式0: 多RFC并列引用（最高优先级，单独处理）
        # 示例: RFC 5280 and RFC 6125, RFC 5280, RFC 6125, RFC5280/RFC6125
        # 注意：这个模式会被特殊处理，拆分成多个独立引用
        self.add_pattern(ReferencePattern(
            name="RFC_MULTIPLE",
            regex=re.compile(
                r'\bRFC[-\s]?(\d{3,5})\s*(?:,|and|/|&)\s*RFC[-\s]?(\d{3,5})',
                re.IGNORECASE
            ),
            doc_type=DocumentType.RFC,
            capture_groups={"doc_number": 1, "doc_number_2": 2},  # 捕获两个RFC编号
            priority=115  # 比所有其他模式都高
        ))

        # 模式1: [RFC<number> Section X.Y.Z] - 方括号内带章节（最高优先级）
        # 示例: [RFC5280 Section 4.2.1.9], [RFC 5280 Section 4.2.1]
        self.add_pattern(ReferencePattern(
            name="RFC_BRACKET_WITH_SECTION",
            regex=re.compile(r'\[RFC[-\s]?(\d{3,5})\s+Section\s+(\d+(?:\.\d+)*)\]', re.IGNORECASE),
            doc_type=DocumentType.RFC,
            capture_groups={"doc_number": 1, "section": 2},
            priority=110  # 最高优先级
        ))

        # 模式2: [RFC<number>] - 纯方括号格式
        # 示例: [RFC5280], [RFC 5280]
        self.add_pattern(ReferencePattern(
            name="RFC_BRACKET_ONLY",
            regex=re.compile(r'\[RFC[-\s]?(\d{3,5})\]', re.IGNORECASE),
            doc_type=DocumentType.RFC,
            capture_groups={"doc_number": 1},
            priority=105
        ))

        # 模式3: RFC <number> Section X.Y.Z - 标准格式带章节
        # 支持: RFC 5280 Section 4.2, RFC 5280, Section 4.2, RFC-5280 Section 4.2, RFC5280 Section 4.2
        self.add_pattern(ReferencePattern(
            name="RFC_WITH_SECTION",
            regex=re.compile(r'\bRFC[-\s]?(\d{3,5})\s*,?\s+[Ss]ection\s+(\d+(?:\.\d+)*)', re.IGNORECASE),
            doc_type=DocumentType.RFC,
            capture_groups={"doc_number": 1, "section": 2},
            priority=100
        ))

        # 模式4: RFC <number> Sec. X.Y.Z / RFC <number> Sec X.Y.Z - Sec缩写格式
        # 示例: RFC 5280 Sec. 4.2.1, RFC 5280 Sec 4.2.1
        self.add_pattern(ReferencePattern(
            name="RFC_WITH_SEC_ABBR",
            regex=re.compile(r'\bRFC[-\s]?(\d{3,5})\s*,?\s+[Ss]ec\.?\s+(\d+(?:\.\d+)*)', re.IGNORECASE),
            doc_type=DocumentType.RFC,
            capture_groups={"doc_number": 1, "section": 2},
            priority=95
        ))

        # 模式5: RFC <number> Clause X.Y.Z - 条款格式
        # 示例: RFC 5280 Clause 4.2.1
        self.add_pattern(ReferencePattern(
            name="RFC_WITH_CLAUSE",
            regex=re.compile(r'\bRFC[-\s]?(\d{3,5})\s*,?\s+[Cc]lause\s+(\d+(?:\.\d+)*)', re.IGNORECASE),
            doc_type=DocumentType.RFC,
            capture_groups={"doc_number": 1, "section": 2},
            priority=95
        ))

        # 模式6: RFC <number> Appendix X - 附录格式
        # 示例: RFC 5280 Appendix A, RFC 5280 Appendix B.1
        self.add_pattern(ReferencePattern(
            name="RFC_WITH_APPENDIX",
            regex=re.compile(r'\bRFC[-\s]?(\d{3,5})\s+[Aa]ppendix\s+([A-Z](?:\.\d+)*)', re.IGNORECASE),
            doc_type=DocumentType.RFC,
            capture_groups={"doc_number": 1, "section": 2},
            priority=95
        ))

        # 模式7: RFC <number> - 纯RFC编号（支持多种格式）
        # 示例: RFC 5280, RFC-5280, RFC5280
        self.add_pattern(ReferencePattern(
            name="RFC_ONLY",
            regex=re.compile(r'\bRFC[-\s]?(\d{3,5})\b', re.IGNORECASE),
            doc_type=DocumentType.RFC,
            capture_groups={"doc_number": 1},
            priority=80
        ))

        # ========== CABF BR 引用模式 ==========
        self.add_pattern(ReferencePattern(
            name="CABF_BR_WITH_SECTION",
            regex=re.compile(
                r'\b(?:CABF\s+)?(?:Baseline\s+Requirements?|BR)\s+[Ss]ection\s+(\d+(?:\.\d+)*)',
                re.IGNORECASE
            ),
            doc_type=DocumentType.CABF_BR,
            capture_groups={"section": 1},
            priority=90
        ))

        self.add_pattern(ReferencePattern(
            name="CABF_BR_ONLY",
            regex=re.compile(
                r'\b(?:CABF\s+)?Baseline\s+Requirements?\b',
                re.IGNORECASE
            ),
            doc_type=DocumentType.CABF_BR,
            capture_groups={},
            priority=70
        ))

        # ========== ETSI 引用模式 ==========
        self.add_pattern(ReferencePattern(
            name="ETSI_WITH_SECTION",
            regex=re.compile(
                r'\bETSI\s+(?:EN|TS)\s+(\d+(?:-\d+)*)\s+[Ss]ection\s+(\d+(?:\.\d+)*)',
                re.IGNORECASE
            ),
            doc_type=DocumentType.ETSI_EN,  # 或 ETSI_TS，需要进一步区分
            capture_groups={"doc_number": 1, "section": 2},
            priority=90
        ))

        self.add_pattern(ReferencePattern(
            name="ETSI_ONLY",
            regex=re.compile(
                r'\bETSI\s+(?:EN|TS)\s+(\d+(?:-\d+)*)\b',
                re.IGNORECASE
            ),
            doc_type=DocumentType.ETSI_EN,
            capture_groups={"doc_number": 1},
            priority=70
        ))

        # ========== 独立章节/条款/附录引用模式（需要上下文） ==========

        # 模式1: Section X.Y.Z - 独立章节引用
        # 示例: Section 4.2.1.9, section 4.2
        self.add_pattern(ReferencePattern(
            name="SECTION_ONLY",
            regex=re.compile(r'\b[Ss]ection\s+(\d+(?:\.\d+)*)'),
            doc_type=None,  # 需要从上下文推断
            capture_groups={"section": 1},
            priority=50,
            requires_context=True
        ))

        # 模式2: Sec. X.Y.Z / Sec X.Y.Z - Sec缩写独立引用
        # 示例: Sec. 4.2.1, Sec 4.2
        self.add_pattern(ReferencePattern(
            name="SEC_ABBR_ONLY",
            regex=re.compile(r'\b[Ss]ec\.?\s+(\d+(?:\.\d+)*)'),
            doc_type=None,
            capture_groups={"section": 1},
            priority=48,
            requires_context=True
        ))

        # 模式3: Clause X.Y.Z - 独立条款引用
        # 示例: Clause 7.1.2.3, clause 7.1
        self.add_pattern(ReferencePattern(
            name="CLAUSE_ONLY",
            regex=re.compile(r'\b[Cc]lause\s+(\d+(?:\.\d+)*)'),
            doc_type=None,
            capture_groups={"section": 1},
            priority=48,
            requires_context=True
        ))

        # 模式4: Appendix X - 独立附录引用
        # 示例: Appendix A, Appendix B.1
        self.add_pattern(ReferencePattern(
            name="APPENDIX_ONLY",
            regex=re.compile(r'\b[Aa]ppendix\s+([A-Z](?:\.\d+)*)'),
            doc_type=None,
            capture_groups={"section": 1},
            priority=48,
            requires_context=True
        ))

        # ========== Mozilla Policy 引用模式 ==========
        self.add_pattern(ReferencePattern(
            name="MOZILLA_POLICY",
            regex=re.compile(
                r'\bMozilla\s+(?:Root\s+Store\s+)?Policy\s+[Ss]ection\s+(\d+(?:\.\d+)*)',
                re.IGNORECASE
            ),
            doc_type=DocumentType.MOZILLA,
            capture_groups={"section": 1},
            priority=85
        ))

    def add_pattern(self, pattern: ReferencePattern):
        """添加引用模式"""
        self.patterns.append(pattern)
        # 按优先级排序（降序）
        self.patterns.sort(key=lambda p: p.priority, reverse=True)

    def get_patterns(self) -> List[ReferencePattern]:
        """获取所有模式（按优先级排序）"""
        return self.patterns


# ============================================================
# 引用检测器
# ============================================================

class UniversalReferenceDetector:
    """
    通用引用检测器

    核心原则：
    1. 引用是规则间的关系，不区分文档类型
    2. 所有引用检测基于可配置的模式
    3. 不自动展开引用内容
    """

    def __init__(self, db: Session, kg):
        self.db = db
        self.kg = kg
        self.pattern_registry = ReferencePatternRegistry()
        self.references_found = 0
        self.references_added = 0

        # 统计信息
        self.stats = {
            "total_rules_processed": 0,
            "references_by_type": {},
            "references_by_source_doc": {},
            "unresolved_references": []
        }

    def detect_references(
        self,
        rules: List[Rule],
        standards: Dict[int, Standard]
    ) -> int:
        """
        检测所有规则之间的引用关系

        Args:
            rules: 规则列表（所有文档类型）
            standards: {standard_id: Standard} 映射

        Returns:
            检测到的引用数量
        """
        app_logger.info(f"Starting universal reference detection for {len(rules)} rules...")

        # 重置统计
        self.references_found = 0
        self.references_added = 0
        self.stats["total_rules_processed"] = len(rules)

        # 处理所有规则（不区分文档类型）
        for rule in rules:
            if not rule.text:
                continue

            self._detect_rule_references(rule, standards)

        # 输出统计信息
        self._log_statistics()

        app_logger.info(
            f"Reference detection complete: "
            f"{self.references_added}/{self.references_found} references added"
        )

        return self.references_added

    def _detect_rule_references(
        self,
        rule: Rule,
        standards: Dict[int, Standard]
    ):
        """
        检测单条规则的所有引用

        Step 1: 显式引用识别
        Step 2: 引用目标解析
        Step 3: 引用分类
        """
        text = rule.text
        source_standard = standards.get(rule.standard_id)

        if not source_standard:
            return

        # Step 1: 识别所有可能的引用（按优先级）
        detected_references = []

        # 用于跟踪最近引用的RFC（上下文绑定）
        last_rfc_number = None

        for pattern in self.pattern_registry.get_patterns():
            matches = pattern.regex.finditer(text)

            for match in matches:
                # 特殊处理：多RFC并列引用
                if pattern.name == "RFC_MULTIPLE":
                    # 拆分成两个独立的引用
                    rfc1 = match.group(1)
                    rfc2 = match.group(2)

                    # 添加第一个RFC引用
                    ref_info1 = {
                        "pattern_name": "RFC_ONLY",
                        "reference_text": f"RFC {rfc1}",
                        "doc_type": DocumentType.RFC,
                        "captures": {"doc_number": rfc1},
                        "match_start": match.start(),
                        "match_end": match.end()
                    }
                    detected_references.append(ref_info1)

                    # 添加第二个RFC引用
                    ref_info2 = {
                        "pattern_name": "RFC_ONLY",
                        "reference_text": f"RFC {rfc2}",
                        "doc_type": DocumentType.RFC,
                        "captures": {"doc_number": rfc2},
                        "match_start": match.start(),
                        "match_end": match.end()
                    }
                    detected_references.append(ref_info2)

                    # 更新上下文
                    last_rfc_number = rfc2
                    continue

                # 提取引用信息
                reference_info = self._extract_reference_info(
                    match, pattern, text, rule, source_standard
                )

                if reference_info:
                    detected_references.append(reference_info)

                    # 更新上下文：如果是RFC引用，记录RFC编号
                    if pattern.doc_type == DocumentType.RFC and "doc_number" in reference_info["captures"]:
                        last_rfc_number = reference_info["captures"]["doc_number"]

        # Step 2 & 3: 解析和分类引用（带上下文）
        for ref_info in detected_references:
            # 如果需要上下文但没有doc_type，尝试使用last_rfc_number
            if ref_info["doc_type"] is None and last_rfc_number:
                ref_info["doc_type"] = DocumentType.RFC
                ref_info["captures"]["doc_number"] = last_rfc_number
                ref_info["context_bound"] = True  # 标记为上下文绑定

            self._resolve_and_classify_reference(
                ref_info, rule, standards
            )

    def _extract_reference_info(
        self,
        match: re.Match,
        pattern: ReferencePattern,
        text: str,
        rule: Rule,
        source_standard: Standard
    ) -> Optional[Dict]:
        """
        提取引用信息

        Returns:
            引用信息字典，如果无效则返回 None
        """
        self.references_found += 1

        # 提取捕获组
        captures = {}
        for name, group_idx in pattern.capture_groups.items():
            captures[name] = match.group(group_idx)

        reference_text = match.group(0)

        # 如果需要上下文验证
        if pattern.requires_context:
            context_doc_type = self._infer_doc_type_from_context(
                text, match.start()
            )
            if not context_doc_type:
                app_logger.debug(
                    f"Skipping context-dependent reference (no context): {reference_text}"
                )
                return None

            # 使用推断的文档类型
            doc_type = context_doc_type
        else:
            doc_type = pattern.doc_type

        return {
            "pattern_name": pattern.name,
            "reference_text": reference_text,
            "doc_type": doc_type,
            "captures": captures,
            "match_start": match.start(),
            "match_end": match.end()
        }

    def _infer_doc_type_from_context(
        self,
        text: str,
        match_start: int,
        context_window: int = 300
    ) -> Optional[DocumentType]:
        """
        从上下文推断文档类型

        用于处理 "Section X.Y.Z" 这种没有文档类型前缀的引用
        """
        # 提取上下文（前N个字符）
        start_pos = max(0, match_start - context_window)
        context = text[start_pos:match_start]

        # 检查上下文中提到的文档类型（按优先级）
        if re.search(r'\bRFC\s+\d+', context, re.IGNORECASE):
            # 提取RFC编号
            rfc_match = re.search(r'\bRFC\s+(\d+)', context, re.IGNORECASE)
            if rfc_match:
                return DocumentType.RFC

        if re.search(r'\bETSI\s+(?:EN|TS)', context, re.IGNORECASE):
            return DocumentType.ETSI_EN

        if re.search(r'\b(?:CABF|Baseline\s+Requirements?)', context, re.IGNORECASE):
            return DocumentType.CABF_BR

        if re.search(r'\bMozilla.*Policy', context, re.IGNORECASE):
            return DocumentType.MOZILLA

        # 默认返回 None（无法推断）
        return None

    def _resolve_and_classify_reference(
        self,
        ref_info: Dict,
        source_rule: Rule,
        standards: Dict[int, Standard]
    ):
        """
        Step 2 & 3: 解析引用目标并分类

        Args:
            ref_info: 引用信息
            source_rule: 源规则
            standards: 标准映射
        """
        doc_type = ref_info["doc_type"]
        captures = ref_info["captures"]
        reference_text = ref_info["reference_text"]

        # Step 2: 解析目标文档和规则
        target_standard = self._find_target_standard(
            doc_type, captures, standards
        )

        if not target_standard:
            self.stats["unresolved_references"].append({
                "source_rule_id": source_rule.id,
                "reference_text": reference_text,
                "reason": "target_standard_not_found"
            })
            return

        # 避免自引用
        if target_standard.id == source_rule.standard_id:
            return

        # 查找目标规则
        target_rule = self._find_target_rule(
            target_standard.id,
            captures.get("section")
        )

        if not target_rule:
            self.stats["unresolved_references"].append({
                "source_rule_id": source_rule.id,
                "reference_text": reference_text,
                "target_standard_id": target_standard.id,
                "target_section": captures.get("section"),
                "reason": "target_rule_not_found"
            })
            return

        # Step 3: 分类引用类型
        reference_type = self._classify_reference_type(
            source_rule, target_rule, reference_text
        )

        # 添加引用关系
        self._add_reference_edge(
            source_rule.id,
            target_rule.id,
            target_standard.id,
            reference_text,
            captures.get("section"),
            reference_type
        )

        # 更新统计
        source_standard = standards.get(source_rule.standard_id)
        if source_standard:
            source_key = source_standard.source
            self.stats["references_by_source_doc"][source_key] = \
                self.stats["references_by_source_doc"].get(source_key, 0) + 1

        self.stats["references_by_type"][reference_type] = \
            self.stats["references_by_type"].get(reference_type, 0) + 1

        self.references_added += 1

    def _find_target_standard(
        self,
        doc_type: DocumentType,
        captures: Dict[str, str],
        standards: Dict[int, Standard]
    ) -> Optional[Standard]:
        """
        查找目标标准文档

        Args:
            doc_type: 文档类型
            captures: 捕获组（如 {"doc_number": "5280", "section": "4.2"}）
            standards: 标准映射

        Returns:
            目标标准，未找到返回 None
        """
        doc_number = captures.get("doc_number")

        for standard in standards.values():
            # 匹配文档类型
            if not self._match_doc_type(standard, doc_type):
                continue

            # 如果有文档编号，则精确匹配
            if doc_number:
                if self._match_doc_number(standard, doc_number):
                    return standard
            else:
                # 无文档编号，返回第一个匹配类型的文档
                return standard

        return None

    def _match_doc_type(self, standard: Standard, doc_type: DocumentType) -> bool:
        """
        判断 standard 是否属于 doc_type

        WARNING: 这是唯一允许检查文档类型的地方，但仅用于匹配，不做业务逻辑判断
        """
        if doc_type == DocumentType.RFC:
            return standard.source == "RFC"
        elif doc_type == DocumentType.CABF_BR:
            return standard.source.startswith("CABF") and "Baseline" in standard.title
        elif doc_type == DocumentType.CABF_EV:
            return standard.source.startswith("CABF") and "EV" in standard.title
        elif doc_type == DocumentType.ETSI_EN:
            return standard.source.startswith("ETSI") and "EN" in standard.title
        elif doc_type == DocumentType.ETSI_TS:
            return standard.source.startswith("ETSI") and "TS" in standard.title
        elif doc_type == DocumentType.MOZILLA:
            return "Mozilla" in standard.source or "Mozilla" in standard.title
        elif doc_type == DocumentType.APPLE:
            return "Apple" in standard.source or "Apple" in standard.title
        elif doc_type == DocumentType.MICROSOFT:
            return "Microsoft" in standard.source or "Microsoft" in standard.title
        elif doc_type == DocumentType.CHROME:
            return "Chrome" in standard.source or "Chrome" in standard.title
        else:
            return False

    def _match_doc_number(self, standard: Standard, doc_number: str) -> bool:
        """判断 standard 是否匹配文档编号"""
        return doc_number in standard.title or doc_number in standard.source

    def _find_target_rule(
        self,
        standard_id: int,
        section: Optional[str]
    ) -> Optional[Rule]:
        """
        查找目标规则（按优先级）

        优先级：
        1. 精确匹配 section
        2. 前缀匹配 section LIKE 'X.Y%'
        3. 无 section，返回任意规则
        """
        if section:
            # 精确匹配
            target_rule = self.db.query(Rule).filter(
                Rule.standard_id == standard_id,
                Rule.section == section
            ).first()

            if target_rule:
                return target_rule

            # 前缀匹配
            target_rule = self.db.query(Rule).filter(
                Rule.standard_id == standard_id,
                Rule.section.like(f'{section}%')
            ).first()

            return target_rule
        else:
            # 返回任意规则
            return self.db.query(Rule).filter(
                Rule.standard_id == standard_id
            ).first()

    def _classify_reference_type(
        self,
        source_rule: Rule,
        target_rule: Rule,
        reference_text: str
    ) -> str:
        """
        Step 3: 分类引用类型

        基于引用文本的语义特征分类，而非LLM判断

        WARNING: 禁止在此阶段展开被引用规则的内容
        """
        text_lower = source_rule.text.lower()
        ref_lower = reference_text.lower()

        # 关键词检测（基于规则的分类）
        override_keywords = [
            "instead of", "replace", "supersede", "override",
            "rather than", "in place of"
        ]

        restriction_keywords = [
            "must not", "shall not", "prohibited",
            "forbidden", "except", "unless",
            "more restrictive", "additional requirement"
        ]

        restatement_keywords = [
            "as specified in", "as defined in", "as described in",
            "in accordance with", "per", "following"
        ]

        # 判断类型
        if any(kw in text_lower for kw in override_keywords):
            return ReferenceType.REFERENCE_WITH_OVERRIDE

        if any(kw in text_lower for kw in restriction_keywords):
            return ReferenceType.REFERENCE_WITH_RESTRICTION

        if any(kw in text_lower for kw in restatement_keywords):
            return ReferenceType.REFERENCE_WITH_RESTATEMENT

        # 默认为纯引用
        return ReferenceType.REFERENCE_ONLY

    def _add_reference_edge(
        self,
        source_rule_id: int,
        target_rule_id: int,
        target_standard_id: int,
        reference_text: str,
        section: Optional[str],
        reference_type: str
    ):
        """
        添加引用边到知识图谱（带去重）

        Args:
            source_rule_id: 源规则ID
            target_rule_id: 目标规则ID
            target_standard_id: 目标标准ID
            reference_text: 引用文本
            section: 章节号
            reference_type: 引用类型
        """
        source_node = f'rule:{source_rule_id}'
        target_node = f'rule:{target_rule_id}'

        # 去重检查
        if self.kg.graph.has_edge(source_node, target_node):
            edge_data = self.kg.graph.get_edge_data(source_node, target_node)
            if edge_data and edge_data.get('relation_type') == 'refers_to':
                return  # 已存在，跳过

        # 添加边
        self.kg.add_edge(
            source_node,
            target_node,
            'refers_to',
            {
                'reference_text': reference_text,
                'reference_type': reference_type,
                'target_section': section,
                'target_standard_id': target_standard_id
            }
        )

        app_logger.debug(
            f"Reference added: Rule {source_rule_id} -> Rule {target_rule_id} "
            f"(type: {reference_type}, text: {reference_text})"
        )

    def _log_statistics(self):
        """输出统计信息"""
        app_logger.info("=" * 60)
        app_logger.info("Reference Detection Statistics")
        app_logger.info("=" * 60)
        app_logger.info(f"Total rules processed: {self.stats['total_rules_processed']}")
        app_logger.info(f"References found: {self.references_found}")
        app_logger.info(f"References added: {self.references_added}")
        app_logger.info(f"Unresolved references: {len(self.stats['unresolved_references'])}")

        app_logger.info("\nReferences by source document:")
        for source, count in sorted(
            self.stats["references_by_source_doc"].items(),
            key=lambda x: x[1],
            reverse=True
        ):
            app_logger.info(f"  {source}: {count}")

        app_logger.info("\nReferences by type:")
        for ref_type, count in sorted(
            self.stats["references_by_type"].items(),
            key=lambda x: x[1],
            reverse=True
        ):
            app_logger.info(f"  {ref_type}: {count}")

        if self.stats["unresolved_references"]:
            app_logger.info("\nSample unresolved references (first 5):")
            for unresolved in self.stats["unresolved_references"][:5]:
                app_logger.info(
                    f"  Rule {unresolved['source_rule_id']}: "
                    f"{unresolved['reference_text']} "
                    f"(reason: {unresolved['reason']})"
                )

        app_logger.info("=" * 60)
