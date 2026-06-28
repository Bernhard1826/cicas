"""
Rule Reasoning Service - 唯一允许进行规则推理的模块

职责：
1. 从 ReferenceFact 推断依赖关系（DEPENDS_ON）
2. 检测规则冲突（CONFLICTS_WITH）
3. 检测不确定关系（POSSIBLE_CONFLICT）
4. 记录推理失败（REASONING_FAILED）

核心原则：
- 系统中只有这个模块可以生成 Rule → Rule 边
- 所有输出都有 algorithm_version, confidence, reason
- 支持不确定和失败的建模
"""
from typing import List, Dict, Any, Optional
from sqlalchemy.orm import Session
from dataclasses import dataclass
from enum import Enum

from app.core.logging_config import app_logger
from app.models.models import Rule


# =============================================================================
# 输出数据结构
# =============================================================================

class RelationType(Enum):
    """关系类型（确定的推理结果）"""
    CITES = "CITES"  # 引用（结构映射，Layer 0）
    DEPENDS_ON = "DEPENDS_ON"  # 依赖（语义推理，Layer 1）
    CONFLICTS_WITH = "CONFLICTS_WITH"  # 冲突（语义推理，Layer 2）
    STRICTER_THAN = "STRICTER_THAN"  # 更严格
    OVERRIDES = "OVERRIDES"  # 覆盖


class UncertainRelationType(Enum):
    """不确定关系类型"""
    POSSIBLE_CONFLICT = "POSSIBLE_CONFLICT"
    POSSIBLE_DEPENDENCY = "POSSIBLE_DEPENDENCY"


@dataclass
class RelationResult:
    """确定的关系结果"""
    source_rule_id: int
    target_rule_id: int
    relation_type: RelationType
    reason: Dict[str, Any]  # 结构化原因
    algorithm_version: str
    confidence: float = 1.0


@dataclass
class UncertainRelation:
    """不确定的关系"""
    source_rule_id: int
    target_rule_id: int
    relation_type: UncertainRelationType
    missing_dimensions: List[str]  # ['scope', 'condition', 'value']
    confidence: float
    algorithm_version: str


@dataclass
class ReasoningFailure:
    """推理失败记录"""
    source_rule_id: int
    target_rule_id: Optional[int]
    stage: str  # 'conflict_detection', 'dependency_inference'
    error_type: str
    message: str
    algorithm_version: str


# =============================================================================
# Rule Reasoning Service
# =============================================================================

class RuleReasoningService:
    """
    规则推理服务 - 唯一允许创建规则关系的模块

    设计理念：
    - KG 不推理，只存储
    - Stage C 不推理，只提取事实
    - 这里是唯一的推理位置
    """

    VERSION = "reasoning_v2.0"

    def __init__(self, db: Session):
        """
        初始化推理服务

        Args:
            db: 数据库会话
        """
        self.db = db
        self.results: List[RelationResult] = []
        self.uncertain: List[UncertainRelation] = []
        self.failures: List[ReasoningFailure] = []

    # =========================================================================
    # Layer 0: 结构映射（最浅层，无语义）
    # =========================================================================

    def create_structural_citations(
        self,
        reference_facts: List[Dict[str, Any]]
    ) -> List[RelationResult]:
        """
        Layer 0: 将 Stage C 的 structural_rule_id 转换为 CITES 边

        注意：这仍然是 Reasoning Service 的一部分
        只是把 structural mapping 包装了一层

        Args:
            reference_facts: Stage C 输出的 ReferenceFact 列表
                格式: {
                    'source_rule_id': int,
                    'structural_rule_id': Optional[int],
                    'resolution_method': str,
                    'raw_reference_text': str,
                    'confidence': float
                }

        Returns:
            RelationResult 列表（CITES 类型）
        """
        app_logger.info(
            f"[Layer 0: Structural Citations] "
            f"Processing {len(reference_facts)} reference facts..."
        )

        results = []

        for fact in reference_facts:
            # 只处理有 structural_rule_id 的引用
            if not fact.get('structural_rule_id'):
                continue

            # 必须是 structural_match_only 方法
            if fact.get('resolution_method') != 'structural_match_only':
                app_logger.warning(
                    f"[Layer 0] Skipping non-structural reference: "
                    f"method={fact.get('resolution_method')}"
                )
                continue

            result = RelationResult(
                source_rule_id=fact['source_rule_id'],
                target_rule_id=fact['structural_rule_id'],
                relation_type=RelationType.CITES,
                reason={
                    'type': 'structural_mapping',
                    'raw_reference': fact.get('raw_reference_text', '')
                },
                algorithm_version=f"{self.VERSION}_layer0",
                confidence=fact.get('confidence', 1.0)
            )
            results.append(result)

        app_logger.info(f"[Layer 0] Created {len(results)} CITES relations")
        self.results.extend(results)
        return results

    # =========================================================================
    # Layer 1: 浅层语义推理
    # =========================================================================

    def infer_dependencies(
        self,
        rules: List[Rule],
        citations: List[RelationResult]
    ) -> List[RelationResult]:
        """
        Layer 1: 从 CITES 推断 DEPENDS_ON（需要语义分析）

        判断逻辑：
        - 如果 rule_a CITES rule_b
        - 且 rule_a 的约束依赖 rule_b 的定义
        - 则 rule_a DEPENDS_ON rule_b

        Args:
            rules: 所有规则列表
            citations: Layer 0 生成的 CITES 关系

        Returns:
            RelationResult 列表（DEPENDS_ON 类型）
        """
        app_logger.info(
            f"[Layer 1: Dependency Inference] "
            f"Processing {len(citations)} citations..."
        )

        results = []
        rules_dict = {r.id: r for r in rules}

        for citation in citations:
            source_rule = rules_dict.get(citation.source_rule_id)
            target_rule = rules_dict.get(citation.target_rule_id)

            if not source_rule or not target_rule:
                continue

            # 语义判断：是否真的依赖？
            is_dependent, reason = self._check_semantic_dependency(
                source_rule,
                target_rule
            )

            if is_dependent:
                result = RelationResult(
                    source_rule_id=source_rule.id,
                    target_rule_id=target_rule.id,
                    relation_type=RelationType.DEPENDS_ON,
                    reason=reason,
                    algorithm_version=f"{self.VERSION}_layer1",
                    confidence=reason.get('confidence', 0.8)
                )
                results.append(result)

        app_logger.info(f"[Layer 1] Inferred {len(results)} DEPENDS_ON relations")
        self.results.extend(results)
        return results

    def _check_semantic_dependency(
        self,
        source_rule: Rule,
        target_rule: Rule
    ) -> tuple[bool, Dict[str, Any]]:
        """
        检查语义依赖

        Returns:
            (is_dependent, reason)
        """
        # 简化逻辑：如果引用了规范性章节，视为依赖
        # TODO: 更复杂的语义分析

        if not source_rule.text or not target_rule.text:
            return False, {}

        # 如果 source 说"as specified in"，通常是依赖
        dependency_phrases = [
            'as specified in',
            'as defined in',
            'according to',
            'in accordance with'
        ]

        source_text_lower = source_rule.text.lower()
        for phrase in dependency_phrases:
            if phrase in source_text_lower:
                return True, {
                    'cause': 'explicit_reference',
                    'phrase': phrase,
                    'confidence': 0.9
                }

        return False, {}

    # =========================================================================
    # Layer 2: 深层语义推理（冲突检测）
    # =========================================================================

    def detect_conflicts(
        self,
        rules: List[Rule]
    ) -> List[RelationResult]:
        """
        Layer 2: 检测规则冲突（复杂语义分析）

        冲突定义：
        - 不存在任何实例可同时满足两条规则

        Args:
            rules: 所有规则列表

        Returns:
            RelationResult 列表（CONFLICTS_WITH 类型）
        """
        app_logger.info(
            f"[Layer 2: Conflict Detection] "
            f"Processing {len(rules)} rules..."
        )

        results = []

        # 按 affected_field 分组
        field_rules = self._group_by_field(rules)

        for field, field_rules_list in field_rules.items():
            # 只检测跨文档冲突
            for i, rule_a in enumerate(field_rules_list):
                for rule_b in field_rules_list[i+1:]:
                    if rule_a.standard_id == rule_b.standard_id:
                        continue  # 跳过同文档规则

                    conflict = self._check_conflict(rule_a, rule_b, field)
                    if conflict:
                        results.append(conflict)

        app_logger.info(f"[Layer 2] Detected {len(results)} CONFLICTS_WITH relations")
        self.results.extend(results)
        return results

    def _group_by_field(self, rules: List[Rule]) -> Dict[str, List[Rule]]:
        """按 affected_field 分组规则"""
        field_rules = {}
        for rule in rules:
            field = rule.subject
            if not field:
                continue
            if field not in field_rules:
                field_rules[field] = []
            field_rules[field].append(rule)
        return field_rules

    def _check_conflict(
        self,
        rule_a: Rule,
        rule_b: Rule,
        field: str
    ) -> Optional[RelationResult]:
        """
        检查两条规则是否冲突

        Returns:
            RelationResult if conflict, else None
        """
        # 值冲突检测
        if rule_a.expected_value and rule_b.expected_value:
            if rule_a.expected_value != rule_b.expected_value:
                # 尝试数值比较
                val_a = self._parse_numeric(rule_a.expected_value)
                val_b = self._parse_numeric(rule_b.expected_value)

                if val_a is not None and val_b is not None and val_a != val_b:
                    return RelationResult(
                        source_rule_id=rule_a.id,
                        target_rule_id=rule_b.id,
                        relation_type=RelationType.CONFLICTS_WITH,
                        reason={
                            'type': 'value_conflict',
                            'field': field,
                            'value_a': rule_a.expected_value,
                            'value_b': rule_b.expected_value,
                            'explanation': f"Field {field}: {rule_a.expected_value} vs {rule_b.expected_value}"
                        },
                        algorithm_version=f"{self.VERSION}_layer2",
                        confidence=0.85
                    )

        # 操作冲突检测
        if rule_a.operation and rule_b.operation:
            conflicting_ops = [
                ('must_be_present', 'must_not_be_present'),
                ('must_be_present', 'must_be_absent'),
            ]

            for op_pair in conflicting_ops:
                if (rule_a.operation, rule_b.operation) == op_pair or \
                   (rule_b.operation, rule_a.operation) == op_pair:
                    return RelationResult(
                        source_rule_id=rule_a.id,
                        target_rule_id=rule_b.id,
                        relation_type=RelationType.CONFLICTS_WITH,
                        reason={
                            'type': 'operation_conflict',
                            'field': field,
                            'operation_a': rule_a.operation,
                            'operation_b': rule_b.operation
                        },
                        algorithm_version=f"{self.VERSION}_layer2",
                        confidence=0.95
                    )

        return None

    def _parse_numeric(self, value_str: str) -> Optional[float]:
        """解析数值"""
        import re
        try:
            match = re.search(r'(\d+(?:\.\d+)?)', str(value_str))
            if match:
                return float(match.group(1))
        except (ValueError, AttributeError):
            pass
        return None

    # =========================================================================
    # 不确定和失败建模
    # =========================================================================

    def detect_uncertain_conflicts(
        self,
        rules: List[Rule]
    ) -> List[UncertainRelation]:
        """
        检测不确定的冲突

        当规则可能冲突，但缺少信息无法确定时
        """
        app_logger.info("[Uncertain Detection] Starting...")

        results = []

        field_rules = self._group_by_field(rules)

        for field, field_rules_list in field_rules.items():
            for i, rule_a in enumerate(field_rules_list):
                for rule_b in field_rules_list[i+1:]:
                    if rule_a.standard_id == rule_b.standard_id:
                        continue

                    # 检查是否缺少关键维度
                    missing = []
                    if not rule_a.condition or not rule_b.condition:
                        missing.append('condition')
                    if not rule_a.expected_value or not rule_b.expected_value:
                        missing.append('value')

                    if missing and field == rule_b.affected_field:
                        uncertain = UncertainRelation(
                            source_rule_id=rule_a.id,
                            target_rule_id=rule_b.id,
                            relation_type=UncertainRelationType.POSSIBLE_CONFLICT,
                            missing_dimensions=missing,
                            confidence=0.5,
                            algorithm_version=self.VERSION
                        )
                        results.append(uncertain)

        app_logger.info(f"[Uncertain Detection] Found {len(results)} uncertain relations")
        self.uncertain.extend(results)
        return results

    # =========================================================================
    # 统一执行接口
    # =========================================================================

    def run_all_reasoning(
        self,
        rules: List[Rule],
        reference_facts: List[Dict[str, Any]]
    ) -> Dict[str, Any]:
        """
        执行所有推理层

        Returns:
            {
                'certain_relations': List[RelationResult],
                'uncertain_relations': List[UncertainRelation],
                'failures': List[ReasoningFailure]
            }
        """
        app_logger.info(
            f"[Rule Reasoning Service] Starting for {len(rules)} rules, "
            f"{len(reference_facts)} reference facts"
        )

        # Layer 0: 结构映射
        citations = self.create_structural_citations(reference_facts)

        # Layer 1: 依赖推断
        dependencies = self.infer_dependencies(rules, citations)

        # Layer 2: 冲突检测
        conflicts = self.detect_conflicts(rules)

        # 不确定检测
        uncertain = self.detect_uncertain_conflicts(rules)

        app_logger.info(
            f"[Rule Reasoning Service] Complete: "
            f"{len(self.results)} certain relations, "
            f"{len(self.uncertain)} uncertain relations, "
            f"{len(self.failures)} failures"
        )

        return {
            'certain_relations': self.results,
            'uncertain_relations': self.uncertain,
            'failures': self.failures,
            'statistics': {
                'total_rules': len(rules),
                'total_relations': len(self.results),
                'by_type': self._count_by_type(self.results),
                'uncertain_count': len(self.uncertain),
                'failure_count': len(self.failures)
            }
        }

    def _count_by_type(self, results: List[RelationResult]) -> Dict[str, int]:
        """统计各类型关系数量"""
        counts = {}
        for result in results:
            rel_type = result.relation_type.value
            counts[rel_type] = counts.get(rel_type, 0) + 1
        return counts
