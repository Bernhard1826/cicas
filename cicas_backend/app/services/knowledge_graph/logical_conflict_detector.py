"""
逻辑冲突检测器（Logical Conflict Detector）

基于四层过滤器的高效冲突检测系统

设计原则：
1. 冲突判定基于逻辑可满足性
2. 采用四层过滤器逐步筛选，避免不必要的计算
3. 不做任何智能过滤、LLM二次判断或经验规则
4. 冲突检测器只负责发现和解释冲突，不做裁决或修改

四层过滤器架构：
┌──────────────────────────────────────────────────────┐
│ 第1层：加载条件（从 IR）                               │
│   - 从规则 IR 的 conditions 字段加载结构化条件          │
│   - 无需白名单，直接使用 LLM 提取的 ConditionSet       │
└────────────────────┬─────────────────────────────────┘
                     ↓
┌──────────────────────────────────────────────────────┐
│ 第2层：条件交集检查                                    │
│   - 检查两条规则的触发条件是否有交集                   │
│   - 无交集 → 永远不会同时触发 → 不冲突（跳过）         │
└────────────────────┬─────────────────────────────────┘
                     ↓
┌──────────────────────────────────────────────────────┐
│ 第3层：作用域检查                                      │
│   - 判断两条规则约束的字段是否在同一层级                │
│   - SAME → 可比较 → 继续                              │
│   - REFINEMENT/DISJOINT/INCOMPARABLE → 不冲突（跳过）  │
└────────────────────┬─────────────────────────────────┘
                     ↓
┌──────────────────────────────────────────────────────┐
│ 第4层：谓词冲突检查                                    │
│   - 检查具体的操作是否存在逻辑矛盾                     │
│   - 存在性冲突、值冲突、范围冲突等                     │
└──────────────────────────────────────────────────────┘

性能优化：
- 按字段分组，减少比较次数（O(n²) → O(sum(group_i²))）
- 四层过滤逐步筛选，避免大量不必要的Z3调用
- 预期性能：1000条规则 2-5秒（vs 未优化的1-7小时）
"""

from typing import Dict, List, Optional, Set, Tuple, Any
from sqlalchemy.orm import Session
from app.models.models import Rule, Standard, ExceptionRule
from app.core.unified_abstractions import (
    ConditionSet, ConflictType, ConflictSeverity,
    RuleConflict, ExceptionPattern, ExceptionEffect, ExceptionScope
)
from app.core.logging_config import app_logger
from app.services.knowledge_graph.scope_checker import get_scope_checker
from datetime import datetime
import re
import json

# 【Phase 1】导入新的条件可满足性判断器
from app.services.ir.condition_satisfiability import ConditionSatisfiability
from app.services.ir.condition_set import ConditionSet as IRConditionSet


# ============================================================
# 四层过滤器实现
# ============================================================

class LogicalConflictDetector:
    """
    逻辑冲突检测器

    采用四层过滤器架构：
    1. 条件解析
    2. 条件交集检查
    3. 作用域检查
    4. 谓词冲突检查
    """

    def __init__(self, db: Session, kg):
        self.db = db
        self.kg = kg

        # 获取单例工具
        self.scope_checker = get_scope_checker()

        # 【Phase 1】初始化条件可满足性判断器
        self.satisfiability_checker = ConditionSatisfiability()

        # 统计信息（详细追踪每层过滤效果）
        self.stats = {
            "total_rule_pairs_checked": 0,
            "layer1_loaded": 0,                    # 第1层：成功加载条件的规则数
            "layer2_filtered": 0,                  # 第2层：条件无交集，过滤掉的规则对数
            "layer2_passed": 0,                    # 第2层：通过的规则对数
            "layer3_filtered": 0,                  # 第3层：作用域不可比，过滤掉的规则对数
            "layer3_passed": 0,                    # 第3层：通过的规则对数
            "layer4_checked": 0,                   # 第4层：进入谓词检查的规则对数
            "conflicts_found": 0,                  # 发现的冲突总数
            "conflicts_by_type": {},               # 按类型分类的冲突数
            "conflicts_by_severity": {},           # 按严重程度分类的冲突数
            "exception_resolved_conflicts": 0,     # ⭐ 被例外规则消解的冲突数
        }

    def detect_conflicts(
        self,
        rules: List[Rule],
        standards: Dict[int, Standard]
    ) -> int:
        """
        检测所有规则之间的冲突

        Args:
            rules: 规则列表（所有文档类型）
            standards: {standard_id: Standard} 映射

        Returns:
            检测到的冲突数量
        """
        app_logger.info(f"Starting 4-layer conflict detection for {len(rules)} rules...")

        # Step 1: 预处理规则（解析条件、归一化字段）
        processed_rules = self._preprocess_rules(rules, standards)

        app_logger.info(f"Preprocessed {len(processed_rules)} rules")

        # Step 2: 按 affected_field 分组（性能优化）
        field_groups = self._group_by_field(processed_rules)

        app_logger.info(f"Grouped rules into {len(field_groups)} field groups")

        # Step 3: 对每个字段组内的规则进行两两比较
        conflicts_found = 0
        for field, group_rules in field_groups.items():
            app_logger.debug(f"Checking field group '{field}' with {len(group_rules)} rules")
            conflicts_found += self._detect_conflicts_in_group(
                group_rules, field
            )

        # Step 4: 输出统计信息
        self._log_statistics()

        app_logger.info(
            f"4-layer conflict detection complete: {conflicts_found} conflicts found"
        )

        return conflicts_found

    def _preprocess_rules(
        self,
        rules: List[Rule],
        standards: Dict[int, Standard]
    ) -> List[Dict[str, Any]]:
        """
        预处理规则：加载条件、归一化字段、加载例外规则

        Returns:
            处理后的规则列表，每个规则包含：
            {
                'db_rule': Rule,
                'rule_id': str,
                'field': str,
                'operation': str,
                'expected_value': str,
                'rule_type': str,
                'text': str,
                'condition_set': ConditionSet,
                'standard': Standard,
                'exception_rules': List[ExceptionRule]
            }
        """
        processed = []

        for rule in rules:
            if not rule.subject:
                continue

            # 第1层：从 IR 加载条件（而非白名单解析）
            condition_set = self._load_condition_from_ir(rule)

            self.stats["layer1_loaded"] += 1

            # ⭐ 加载例外规则
            exception_rules = self.db.query(ExceptionRule).filter(
                ExceptionRule.target_rule_id == rule.id
            ).all()

            # 构建处理后的规则对象
            processed_rule = {
                'db_rule': rule,
                'rule_id': str(rule.id),
                'field': self._normalize_field(rule.subject),
                'operation': rule.predicate,
                'expected_value': rule.constraint_value,
                'rule_type': rule.rule_type,
                'text': rule.text,
                'condition_set': condition_set,
                'standard': standards.get(rule.standard_id),
                'exception_rules': exception_rules
            }

            processed.append(processed_rule)

        return processed

    def _load_condition_from_ir(self, rule: Rule) -> IRConditionSet:
        """
        从规则 IR 的 conditions 字段加载 ConditionSet

        【Phase 1重构】使用新的IRConditionSet数据结构

        Args:
            rule: 数据库规则对象

        Returns:
            IRConditionSet 对象
        """
        # 如果规则没有 conditions 字段，返回空条件集
        if not rule.conditions:
            return IRConditionSet(conditions=[], logic="AND")

        try:
            # 解析 JSON 格式的 conditions 字段
            conditions_data = json.loads(rule.conditions)

            # 支持两种格式:
            # 1. 列表格式: [{"type": "field", "field": "...", ...}, ...]
            # 2. 字典格式: {"conditions": [...], "logic": "AND"}
            if isinstance(conditions_data, list):
                # 列表格式，直接使用
                return IRConditionSet(
                    conditions=conditions_data,
                    logic="AND"
                )
            elif isinstance(conditions_data, dict):
                # 字典格式，使用from_ir_json方法
                return IRConditionSet.from_ir_json(conditions_data)
            else:
                app_logger.warning(
                    f"Rule {rule.id} conditions format invalid, treating as empty"
                )
                return IRConditionSet(conditions=[], logic="AND")

        except json.JSONDecodeError as e:
            app_logger.warning(
                f"Failed to parse conditions for Rule {rule.id}: {e}, treating as empty"
            )
            return IRConditionSet(conditions=[], logic="AND")
        except Exception as e:
            app_logger.warning(
                f"Failed to load ConditionSet for Rule {rule.id}: {e}, treating as empty"
            )
            return IRConditionSet(conditions=[], logic="AND")

    def _normalize_field(self, field: str) -> str:
        """归一化字段名（小写、去空格）"""
        if not field:
            return ""
        return field.lower().strip().replace(" ", "_")

    def _group_by_field(
        self,
        rules: List[Dict[str, Any]]
    ) -> Dict[str, List[Dict[str, Any]]]:
        """
        按字段分组规则（性能优化）

        只有约束同一字段的规则才可能冲突，所以先分组可以大幅减少比较次数
        """
        groups = {}

        for rule in rules:
            field = rule['field']

            # 获取基础字段（用于分组）
            # 例如：extensions.basicConstraints.cA → extensions.basicConstraints
            base_field = self._get_base_field(field)

            if base_field not in groups:
                groups[base_field] = []

            groups[base_field].append(rule)

        return groups

    def _get_base_field(self, field: str) -> str:
        """
        获取基础字段（用于分组）

        策略：取前两级路径
        例如：
        - extensions.basicConstraints.cA → extensions.basicConstraints
        - validity.notBefore → validity.notBefore
        - subject → subject
        """
        parts = field.split('.')
        if len(parts) > 2:
            return '.'.join(parts[:2])
        else:
            return field

    def _detect_conflicts_in_group(
        self,
        rules: List[Dict[str, Any]],
        field: str
    ) -> int:
        """
        检测同一字段组内的冲突

        对每一对规则应用四层过滤器
        """
        conflicts = 0

        for i in range(len(rules)):
            for j in range(i + 1, len(rules)):
                rule_a = rules[i]
                rule_b = rules[j]

                self.stats["total_rule_pairs_checked"] += 1

                # ========== 第1.5层：跳过同一文档内的规则对 ==========
                # 同一文档内的"冲突"通常是针对不同场景/证书类型的正常业务规则
                # 例如：RFC 5280 中针对CA证书和终端实体证书的不同要求
                if rule_a['rule'].standard_id == rule_b['rule'].standard_id:
                    continue

                # ========== 第2层：条件交集检查 ==========
                if not self._check_condition_intersection(rule_a, rule_b):
                    self.stats["layer2_filtered"] += 1
                    continue

                self.stats["layer2_passed"] += 1

                # ========== 第3层：作用域检查 ==========
                if not self._check_scope_compatibility(rule_a, rule_b):
                    self.stats["layer3_filtered"] += 1
                    continue

                self.stats["layer3_passed"] += 1

                # ========== 第4层：谓词冲突检查 ==========
                self.stats["layer4_checked"] += 1

                conflict = self._check_predicate_conflict(rule_a, rule_b)

                if conflict:
                    self._add_conflict_edge(conflict)
                    conflicts += 1

        return conflicts

    def _check_condition_intersection(
        self,
        rule_a: Dict[str, Any],
        rule_b: Dict[str, Any]
    ) -> bool:
        """
        第2层：条件交集检查

        【Phase 1重构】使用新的ConditionSatisfiability判断器

        判断两条规则的触发条件是否有交集

        逻辑：
        - 使用区间数学和集合运算判断条件是否可同时满足
        - 支持FieldCondition, RangeCondition, SetCondition
        - 有交集 → 可能冲突 → 需要继续检查
        - 无交集 → 永远不会同时触发 → 不冲突

        Returns:
            True 表示有交集（需要继续检查），False 表示无交集（跳过）
        """
        cond_a = rule_a['condition_set']
        cond_b = rule_b['condition_set']

        try:
            # 使用新的ConditionSatisfiability判断器
            can_intersect, reason = self.satisfiability_checker.can_intersect(cond_a, cond_b)

            if not can_intersect:
                app_logger.debug(
                    f"Layer 2 filtered: Rule {rule_a['rule_id']} and {rule_b['rule_id']} "
                    f"have disjoint conditions - {reason}"
                )
                return False

            app_logger.debug(
                f"Layer 2 passed: Rule {rule_a['rule_id']} and {rule_b['rule_id']} "
                f"conditions can intersect - {reason}"
            )
            return True

        except Exception as e:
            app_logger.warning(
                f"Layer 2 check failed for Rule {rule_a['rule_id']} and {rule_b['rule_id']}: {e}, "
                f"conservatively assuming intersection exists"
            )
            # 失败时保守认为有交集，继续后续检查
            return True

    def _check_scope_compatibility(
        self,
        rule_a: Dict[str, Any],
        rule_b: Dict[str, Any]
    ) -> bool:
        """
        第3层：作用域检查

        判断两条规则约束的字段是否在同一层级（是否可比较）

        使用 ScopeChecker.is_comparable() 方法：
        - SAME → 可比较 → 返回 True
        - REFINEMENT/DISJOINT/INCOMPARABLE → 不可比较 → 返回 False

        Returns:
            True 表示可比较（需要继续检查），False 表示不可比较（跳过）
        """
        field_a = rule_a['field']
        field_b = rule_b['field']

        is_comparable = self.scope_checker.is_comparable(field_a, field_b)

        if not is_comparable:
            # 获取详细信息用于调试
            scope_info = self.scope_checker.get_scope_info(field_a, field_b)
            app_logger.debug(
                f"Layer 3 filtered: Rule {rule_a['rule_id']} and {rule_b['rule_id']} "
                f"- {scope_info['reason']}"
            )

        return is_comparable

    def _check_predicate_conflict(
        self,
        rule_a: Dict[str, Any],
        rule_b: Dict[str, Any]
    ) -> Optional[RuleConflict]:
        """
        第4层：谓词冲突检查（例外感知）

        检查具体的操作是否存在逻辑矛盾，并考虑例外规则的影响

        设计原则：EffectiveRule = NormalRule ∧ ¬ ExceptionRule
        如果Rule A和Rule B看似冲突，但Rule A有例外在Rule B的条件下不适用，
        则它们实际上是兼容的。

        支持的冲突类型：
        1. 存在性冲突：MUST_BE_PRESENT vs MUST_NOT_BE_PRESENT
        2. Critical冲突：MUST_BE_CRITICAL vs MUST_NOT_BE_CRITICAL
        3. 值冲突：MUST_EQUAL(x) vs MUST_EQUAL(y), x ≠ y（已禁用，见详解文档FAQ）
        4. 包含冲突：MUST_INCLUDE(x) vs MUST_NOT_INCLUDE(x)

        Returns:
            RuleConflict 对象（如果发现冲突），否则返回 None
        """
        op_a = rule_a['operation']
        op_b = rule_b['operation']
        val_a = rule_a['expected_value']
        val_b = rule_b['expected_value']

        # 归一化操作名（小写、去空格）
        op_a_norm = op_a.lower().strip() if op_a else ""
        op_b_norm = op_b.lower().strip() if op_b else ""

        # 检测到的冲突（初始状态）
        detected_conflict = None

        # ========== 冲突类型1：存在性冲突 ==========
        if (
            op_a_norm == "must_be_present" and op_b_norm == "must_not_be_present"
        ) or (
            op_a_norm == "must_not_be_present" and op_b_norm == "must_be_present"
        ):
            detected_conflict = self._create_conflict(
                rule_a, rule_b,
                conflict_type=ConflictType.HARD_CONFLICT,
                severity=ConflictSeverity.CRITICAL,
                reason="Presence conflict: One rule requires field presence (MUST_BE_PRESENT), "
                       "another requires absence (MUST_NOT_BE_PRESENT)",
                dimension="presence"
            )

        # ========== 冲突类型2：Critical标记冲突 ==========
        elif (
            op_a_norm == "must_be_critical" and op_b_norm == "must_not_be_critical"
        ) or (
            op_a_norm == "must_not_be_critical" and op_b_norm == "must_be_critical"
        ):
            detected_conflict = self._create_conflict(
                rule_a, rule_b,
                conflict_type=ConflictType.HARD_CONFLICT,
                severity=ConflictSeverity.CRITICAL,
                reason="Critical flag conflict: One rule requires CRITICAL, "
                       "another requires NON-CRITICAL",
                dimension="critical_flag"
            )

        # ========== 冲突类型3：值约束冲突（已禁用）==========
        # 原因见《冲突和引用处理算法详解.md》FAQ第4条
        # 待规则提取质量改进后可重新启用

        # ========== 冲突类型4：包含冲突 ==========
        elif op_a_norm == "must_contain" and op_b_norm == "must_not_contain":
            if val_a and val_b and self._normalize_value(val_a) == self._normalize_value(val_b):
                detected_conflict = self._create_conflict(
                    rule_a, rule_b,
                    conflict_type=ConflictType.HARD_CONFLICT,
                    severity=ConflictSeverity.HIGH,
                    reason=f"Inclusion conflict: One rule requires MUST_CONTAIN '{val_a}', "
                           f"another requires MUST_NOT_CONTAIN '{val_b}'",
                    dimension="inclusion"
                )

        # ========== ⭐ 例外感知检查 ==========
        # 如果检测到冲突，检查是否有例外规则使其兼容
        if detected_conflict:
            if self._has_exception_making_compatible(rule_a, rule_b, detected_conflict):
                app_logger.info(
                    f"Conflict between Rule {rule_a['rule_id']} and Rule {rule_b['rule_id']} "
                    f"resolved by exception rule (dimension: {detected_conflict.conflicting_dimension})"
                )
                self.stats["exception_resolved_conflicts"] += 1
                return None  # 例外消解了冲突

        # 没有发现冲突或例外已消解
        return detected_conflict

    def _has_exception_making_compatible(
        self,
        rule_a: Dict[str, Any],
        rule_b: Dict[str, Any],
        conflict: RuleConflict
    ) -> bool:
        """
        检查是否有例外规则使看似冲突的两条规则实际上兼容

        设计原则：EffectiveRule = NormalRule ∧ ¬ ExceptionRule

        检查逻辑：
        1. 检查 rule_a 的例外规则：
           - 如果 rule_a 有例外，且例外条件与 rule_b 的约束匹配
           - 则 rule_a 在 rule_b 的条件下不适用 → 兼容

        2. 检查 rule_b 的例外规则：
           - 同样的逻辑

        真实示例：
        - Rule A: "subject MUST be present" (rfc5280-4.1.2.6-001)
        - Exception A: "unless subjectAltName is present and critical" (rfc5280-4.1.2.6-ex1)
        - Rule B: "subjectAltName MUST be present and critical" (derived)
        → Rule A 和 Rule B 看似冲突（subject vs subjectAltName）
        → 但 Exception A 说：当 subjectAltName present+critical 时，subject 不需要存在
        → 因此 Rule B 成立时，Rule A 自动豁免 → 兼容

        Args:
            rule_a: 第一条规则
            rule_b: 第二条规则
            conflict: 检测到的冲突对象

        Returns:
            True 表示有例外消解了冲突，False 表示冲突无法消解
        """
        # 检查 rule_a 的例外规则
        for exception in rule_a.get('exception_rules', []):
            if self._exception_resolves_conflict(
                exception, rule_a, rule_b, conflict, "rule_a"
            ):
                return True

        # 检查 rule_b 的例外规则
        for exception in rule_b.get('exception_rules', []):
            if self._exception_resolves_conflict(
                exception, rule_b, rule_a, conflict, "rule_b"
            ):
                return True

        return False

    def _exception_resolves_conflict(
        self,
        exception: ExceptionRule,
        owning_rule: Dict[str, Any],
        other_rule: Dict[str, Any],
        conflict: RuleConflict,
        owner_label: str
    ) -> bool:
        """
        检查单个例外规则是否能消解冲突

        Args:
            exception: 例外规则
            owning_rule: 拥有该例外的规则
            other_rule: 另一条规则
            conflict: 冲突对象
            owner_label: 拥有者标签（"rule_a" 或 "rule_b"）

        Returns:
            True 如果例外消解了冲突
        """
        # 只有 NEGATE 效果的例外才能完全消解冲突
        # （其他效果如 RELAX, RESTRICT 需要更复杂的逻辑，暂不支持）
        if exception.effect != ExceptionEffect.NEGATE.value:
            return False

        # 解析例外的条件集
        try:
            condition_data = json.loads(exception.condition_set) if exception.condition_set else {}
            exception_conditions = condition_data.get('conditions', [])
        except (json.JSONDecodeError, TypeError):
            app_logger.warning(
                f"Failed to parse condition_set for exception {exception.exception_id}"
            )
            return False

        if not exception_conditions:
            return False

        # 检查例外条件是否与另一条规则的约束匹配
        # 简化实现：检查是否有条件提到相同的字段
        other_field = other_rule['field']

        for condition in exception_conditions:
            condition_field = condition.get('field', '')
            condition_predicate = condition.get('predicate', '')

            # 归一化字段名以便比较
            condition_field_norm = self._normalize_field(condition_field)

            # 如果例外条件的字段与另一条规则的字段相关
            if self._fields_are_related(condition_field_norm, other_field):
                # 进一步检查：条件的谓词是否与另一条规则的操作一致
                # 例如：exception条件说 "subjectAltName must_be_present"
                #      other_rule 说 "subjectAltName MUST_BE_PRESENT"
                # → 匹配！

                other_op_norm = other_rule['operation'].lower().strip() if other_rule['operation'] else ""

                if condition_predicate.lower() == other_op_norm:
                    app_logger.debug(
                        f"Exception {exception.exception_id} resolves conflict: "
                        f"{owning_rule['rule_id']} has exception matching {other_rule['rule_id']}'s constraint"
                    )
                    return True

        return False

    def _fields_are_related(self, field_a: str, field_b: str) -> bool:
        """
        判断两个字段是否相关（用于例外条件匹配）

        策略：
        - 完全相同 → 相关
        - 父子关系 → 相关（例如 "extensions.subjectAltName" 和 "extensions.subjectAltName.critical"）
        - 否则 → 不相关

        Args:
            field_a: 第一个字段
            field_b: 第二个字段

        Returns:
            True 如果相关
        """
        if not field_a or not field_b:
            return False

        # 完全相同
        if field_a == field_b:
            return True

        # 检查包含关系（父子关系）
        if field_a.startswith(field_b + '.') or field_b.startswith(field_a + '.'):
            return True

        return False

    def _normalize_value(self, value: str) -> str:
        """归一化值（小写、去空格、去引号）"""
        if not value:
            return ""
        return value.lower().strip().strip('"').strip("'")

    def _create_conflict(
        self,
        rule_a: Dict[str, Any],
        rule_b: Dict[str, Any],
        conflict_type: ConflictType,
        severity: ConflictSeverity,
        reason: str,
        dimension: str
    ) -> RuleConflict:
        """
        创建冲突对象

        Args:
            rule_a, rule_b: 冲突的两条规则
            conflict_type: 冲突类型
            severity: 严重程度
            reason: 冲突原因描述
            dimension: 冲突维度（presence/critical_flag/value/inclusion等）

        Returns:
            RuleConflict 对象
        """
        conflict = RuleConflict(
            rule_a_id=rule_a['rule_id'],
            rule_b_id=rule_b['rule_id'],
            conflict_type=conflict_type,
            severity=severity,
            unsatisfiability_reason=reason,
            conflicting_dimension=dimension,
            conflict_details={
                'rule_a_field': rule_a['field'],
                'rule_b_field': rule_b['field'],
                'rule_a_operation': rule_a['operation'],
                'rule_b_operation': rule_b['operation'],
                'rule_a_expected_value': rule_a['expected_value'],
                'rule_b_expected_value': rule_b['expected_value'],
                'rule_a_text': rule_a['text'][:100],  # 截断避免过长
                'rule_b_text': rule_b['text'][:100],
            },
            satisfiable=False,
            counterexample={'type': dimension}
        )

        # 更新统计
        self.stats["conflicts_found"] += 1
        self.stats["conflicts_by_type"][conflict_type] = \
            self.stats["conflicts_by_type"].get(conflict_type, 0) + 1
        self.stats["conflicts_by_severity"][severity] = \
            self.stats["conflicts_by_severity"].get(severity, 0) + 1

        app_logger.debug(
            f"Conflict detected: Rule {rule_a['rule_id']} <-> Rule {rule_b['rule_id']} "
            f"(type: {conflict_type}, severity: {severity}, dimension: {dimension})"
        )

        return conflict

    def _add_conflict_edge(self, conflict: RuleConflict):
        """
        添加冲突边到知识图谱

        Args:
            conflict: 冲突对象
        """
        node_a = f'rule:{conflict.rule_a_id}'
        node_b = f'rule:{conflict.rule_b_id}'

        # 去重检查
        if self.kg.graph.has_edge(node_a, node_b):
            edge_data = self.kg.graph.get_edge_data(node_a, node_b)
            if edge_data and edge_data.get('relation_type') == 'conflicts_with':
                return  # 已存在，跳过

        # 添加边
        self.kg.add_edge(
            node_a,
            node_b,
            'conflicts_with',
            {
                'conflict_type': conflict.conflict_type,
                'severity': conflict.severity,
                'reason': conflict.unsatisfiability_reason,
                'dimension': conflict.conflicting_dimension,
                'details': conflict.conflict_details
            }
        )

        app_logger.debug(
            f"Conflict edge added to KG: {node_a} <-> {node_b}"
        )

    def _log_statistics(self):
        """输出四层过滤器的统计信息"""
        app_logger.info("=" * 70)
        app_logger.info("4-Layer Conflict Detection Statistics (Exception-Aware)")
        app_logger.info("=" * 70)

        app_logger.info(f"Total rule pairs checked: {self.stats['total_rule_pairs_checked']}")
        app_logger.info("")

        # 第1层统计
        app_logger.info("Layer 1 (Loading Conditions from IR):")
        app_logger.info(f"  Rules loaded: {self.stats['layer1_loaded']}")
        app_logger.info("")

        # 第2层统计
        app_logger.info("Layer 2 (Condition Intersection):")
        app_logger.info(f"  Filtered (no intersection): {self.stats['layer2_filtered']}")
        app_logger.info(f"  Passed: {self.stats['layer2_passed']}")
        filter_rate_2 = (self.stats['layer2_filtered'] / self.stats['total_rule_pairs_checked'] * 100) \
            if self.stats['total_rule_pairs_checked'] > 0 else 0
        app_logger.info(f"  Filter rate: {filter_rate_2:.1f}%")
        app_logger.info("")

        # 第3层统计
        app_logger.info("Layer 3 (Scope Checking):")
        app_logger.info(f"  Filtered (not comparable): {self.stats['layer3_filtered']}")
        app_logger.info(f"  Passed: {self.stats['layer3_passed']}")
        filter_rate_3 = (self.stats['layer3_filtered'] / self.stats['layer2_passed'] * 100) \
            if self.stats['layer2_passed'] > 0 else 0
        app_logger.info(f"  Filter rate: {filter_rate_3:.1f}%")
        app_logger.info("")

        # 第4层统计
        app_logger.info("Layer 4 (Predicate Conflict Checking - Exception-Aware):")
        app_logger.info(f"  Pairs checked: {self.stats['layer4_checked']}")
        app_logger.info(f"  Conflicts found: {self.stats['conflicts_found']}")
        app_logger.info(f"  Conflicts resolved by exceptions: {self.stats['exception_resolved_conflicts']}")  # ⭐ 新增
        conflict_rate = (self.stats['conflicts_found'] / self.stats['layer4_checked'] * 100) \
            if self.stats['layer4_checked'] > 0 else 0
        app_logger.info(f"  Conflict rate: {conflict_rate:.1f}%")
        app_logger.info("")

        # 冲突类型分布
        app_logger.info("Conflicts by type:")
        for conf_type, count in sorted(
            self.stats["conflicts_by_type"].items(),
            key=lambda x: x[1],
            reverse=True
        ):
            app_logger.info(f"  {conf_type}: {count}")
        app_logger.info("")

        # 冲突严重程度分布
        app_logger.info("Conflicts by severity:")
        for severity, count in sorted(
            self.stats["conflicts_by_severity"].items(),
            key=lambda x: x[1],
            reverse=True
        ):
            app_logger.info(f"  {severity}: {count}")

        # 总体过滤效果
        total_filtered = self.stats['layer2_filtered'] + self.stats['layer3_filtered']
        total_filter_rate = (total_filtered / self.stats['total_rule_pairs_checked'] * 100) \
            if self.stats['total_rule_pairs_checked'] > 0 else 0
        app_logger.info("")
        app_logger.info(f"Overall filter effectiveness: {total_filter_rate:.1f}% pairs filtered out")
        app_logger.info(f"Performance gain: ~{100 / (100 - total_filter_rate):.1f}x speedup")

        # ⭐ 例外规则效果
        if self.stats['exception_resolved_conflicts'] > 0:
            app_logger.info("")
            app_logger.info(f"Exception Rules Impact:")
            app_logger.info(f"  {self.stats['exception_resolved_conflicts']} conflicts resolved by exception rules")
            resolution_rate = (self.stats['exception_resolved_conflicts'] /
                             (self.stats['conflicts_found'] + self.stats['exception_resolved_conflicts']) * 100) \
                if (self.stats['conflicts_found'] + self.stats['exception_resolved_conflicts']) > 0 else 0
            app_logger.info(f"  Exception resolution rate: {resolution_rate:.1f}%")

        app_logger.info("=" * 70)


# ============================================================
# 单例获取函数
# ============================================================

_conflict_detector = None

def get_conflict_detector(db: Session, kg) -> LogicalConflictDetector:
    """获取冲突检测器实例（非严格单例，允许每次创建新实例）"""
    return LogicalConflictDetector(db, kg)
