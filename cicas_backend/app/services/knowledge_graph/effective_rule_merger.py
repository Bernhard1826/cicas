"""
有效规则合并器 (Effective Rule Merger)
功能：
1. 合并引用链（BR → RFC → CPS）
2. 应用范围收紧策略（选择更严格的规则）
3. 生成最终有效规则集
4. 保留所有来源证据
"""
from typing import List, Dict, Optional, Tuple
from sqlalchemy.orm import Session
import json
from datetime import datetime

from app.models.models import Rule, Standard
from app.core.logging_config import app_logger


class EffectiveRuleMerger:
    """
    有效规则合并器

    策略：
    1. 对于同一字段的多条规则，合并成一条最严格的有效规则
    2. 保留所有来源证据（证据链）
    3. 范围收紧：数值取最小/最严格
    4. 布尔合并：forbid > allow
    """

    def __init__(self, db: Session):
        self.db = db

    def merge_rules_by_field(self, rules: List[Rule]) -> List[Dict]:
        """
        按 affected_field 分组并合并规则

        Args:
            rules: 规则列表（已经过冲突解决，只包含active状态）

        Returns:
            合并后的有效规则列表
        """
        app_logger.info(f"[EffectiveRuleMerger] Merging {len(rules)} rules by field...")

        # 1. 按字段分组
        field_groups = self._group_by_field(rules)

        # 2. 对每组规则进行合并
        effective_rules = []
        for field, field_rules in field_groups.items():
            if len(field_rules) == 1:
                # 单条规则，直接转为有效规则
                effective_rule = self._single_rule_to_effective(field_rules[0])
            else:
                # 多条规则，需要合并
                effective_rule = self._merge_field_rules(field, field_rules)

            effective_rules.append(effective_rule)

        app_logger.info(
            f"[EffectiveRuleMerger] Generated {len(effective_rules)} effective rules "
            f"from {len(rules)} input rules"
        )

        return effective_rules

    def _group_by_field(self, rules: List[Rule]) -> Dict[str, List[Rule]]:
        """按 affected_field 分组"""
        field_map = {}
        for rule in rules:
            field = rule.subject or 'general'
            if field not in field_map:
                field_map[field] = []
            field_map[field].append(rule)

        return field_map

    def _single_rule_to_effective(self, rule: Rule) -> Dict:
        """将单条规则转为有效规则格式"""
        return {
            'effective_rule': {
                'affected_field': rule.subject,
                'operation': rule.predicate,
                'expected_value': rule.constraint_value,
                'rule_type': rule.rule_type,
                'severity': rule.severity,
                'text': rule.text
            },
            'source_chain': [
                {
                    'rule_id': rule.id,
                    'standard': rule.standard.title,
                    'section': rule.section,
                    'priority': self._get_document_priority(rule.standard),
                }
            ],
            'merge_strategy': 'single_source',
            'conflict_notes': [],
        }

    def _merge_field_rules(self, field: str, rules: List[Rule]) -> Dict:
        """
        合并同一字段的多条规则

        策略：
        1. 范围收紧（numeric range）：取最小值
        2. 布尔合并（forbid/allow）：forbid 优先
        3. 必须/应该合并（MUST/SHOULD）：MUST 优先
        4. 保留所有来源证据
        """
        app_logger.debug(f"[EffectiveRuleMerger] Merging {len(rules)} rules for field: {field}")

        # 按优先级排序（高优先级在前）
        sorted_rules = sorted(
            rules,
            key=lambda r: self._get_document_priority(r.standard),
            reverse=True
        )

        # 确定合并策略
        operations = [r.predicate for r in sorted_rules if r.predicate]

        if any(op in ['minimum', 'maximum', 'exact_length'] for op in operations):
            # 数值范围合并 - 范围收紧策略
            return self._merge_numeric_range(field, sorted_rules)

        elif any(op in ['must_be_present', 'must_not_be_present'] for op in operations):
            # 存在性合并 - 更严格的规则优先
            return self._merge_presence(field, sorted_rules)

        elif any(op in ['must_be_critical', 'must_not_be_critical'] for op in operations):
            # Critical标记合并
            return self._merge_critical(field, sorted_rules)

        else:
            # 默认：优先级最高的规则作为基准
            return self._merge_by_priority(field, sorted_rules)

    def _merge_numeric_range(self, field: str, rules: List[Rule]) -> Dict:
        """
        合并数值范围规则 - 范围收紧策略

        例如：
        - RFC 5280: maxPathLen ≤ 10
        - CABF BR: maxPathLen ≤ 5
        → 有效规则: maxPathLen ≤ 5 (更严格)

        - RFC 5280: validity ≤ 825 days
        - CABF BR: validity ≤ 398 days
        → 有效规则: validity ≤ 398 days (更严格)
        """
        # 收集所有数值约束
        min_values = []
        max_values = []
        exact_values = []

        for rule in rules:
            value = self._parse_numeric_value(rule.constraint_value)
            if value is None:
                continue

            if rule.predicate == 'minimum':
                min_values.append((value, rule))
            elif rule.predicate == 'maximum':
                max_values.append((value, rule))
            elif rule.predicate == 'exact_length':
                exact_values.append((value, rule))

        # 范围收紧：
        # - minimum: 取最大的 minimum（更严格的下限）
        # - maximum: 取最小的 maximum（更严格的上限）
        # - exact: 如果有exact，使用exact

        conflict_notes = []

        if exact_values:
            # 有精确值要求，使用最高优先级的精确值
            strictest_value, strictest_rule = exact_values[0]
            operation = 'exact_length'
            expected_value = str(strictest_value)
            conflict_notes.append(f"Exact value {strictest_value} from {strictest_rule.standard.title}")

        elif min_values and max_values:
            # 同时有上下限
            strictest_min, min_rule = max(min_values, key=lambda x: x[0])  # 最大的下限
            strictest_max, max_rule = min(max_values, key=lambda x: x[0])  # 最小的上限

            if strictest_min > strictest_max:
                # 范围冲突（下限 > 上限）
                app_logger.warning(
                    f"Range conflict for {field}: min={strictest_min} > max={strictest_max}"
                )
                conflict_notes.append(
                    f"Range conflict: minimum {strictest_min} > maximum {strictest_max}"
                )
                # 使用更严格的那个
                if self._get_document_priority(min_rule.standard) > self._get_document_priority(max_rule.standard):
                    operation = 'minimum'
                    expected_value = str(strictest_min)
                else:
                    operation = 'maximum'
                    expected_value = str(strictest_max)
            else:
                # 正常范围，同时记录上下限
                operation = 'range'
                expected_value = f"[{strictest_min}, {strictest_max}]"
                conflict_notes.append(
                    f"Range tightened: {strictest_min} (from {min_rule.standard.title}) "
                    f"to {strictest_max} (from {max_rule.standard.title})"
                )

        elif min_values:
            # 只有下限
            strictest_value, strictest_rule = max(min_values, key=lambda x: x[0])
            operation = 'minimum'
            expected_value = str(strictest_value)
            conflict_notes.append(f"Minimum tightened to {strictest_value} from {strictest_rule.standard.title}")

        elif max_values:
            # 只有上限
            strictest_value, strictest_rule = min(max_values, key=lambda x: x[0])
            operation = 'maximum'
            expected_value = str(strictest_value)
            conflict_notes.append(f"Maximum tightened to {strictest_value} from {strictest_rule.standard.title}")

        else:
            # 无法解析数值，使用优先级最高的规则
            return self._merge_by_priority(field, rules)

        # 构建源链
        source_chain = [
            {
                'rule_id': r.id,
                'standard': r.standard.title,
                'section': r.section,
                'priority': self._get_document_priority(r.standard),
                'operation': r.predicate,
                'value': r.constraint_value,
            }
            for r in rules
        ]

        return {
            'effective_rule': {
                'affected_field': field,
                'operation': operation,
                'expected_value': expected_value,
                'rule_type': rules[0].rule_type,  # 使用最高优先级的rule_type
                'severity': 'high',  # 范围收紧后通常是严格要求
                'text': f"Merged numeric range constraint: {operation} {expected_value}"
            },
            'source_chain': source_chain,
            'merge_strategy': 'range_tightening',
            'conflict_notes': conflict_notes
        }

    def _merge_presence(self, field: str, rules: List[Rule]) -> Dict:
        """
        合并存在性规则

        策略：forbid (must_not_be_present) > allow (must_be_present)
        因为禁止通常是安全要求，优先级更高
        """
        conflict_notes = []

        # 检查是否有冲突
        has_must_present = any(r.predicate == 'must_be_present' for r in rules)
        has_must_not_present = any(r.predicate == 'must_not_be_present' for r in rules)

        if has_must_present and has_must_not_present:
            # 存在性冲突 - forbid 优先
            forbid_rule = next(r for r in rules if r.predicate == 'must_not_be_present')
            conflict_notes.append(
                f"Presence conflict resolved: forbid from {forbid_rule.standard.title} "
                f"overrides allow requirements"
            )
            effective_operation = 'must_not_be_present'
            effective_value = None
        elif has_must_not_present:
            effective_operation = 'must_not_be_present'
            effective_value = None
        else:
            effective_operation = 'must_be_present'
            # 如果有expected_value，使用最高优先级的
            effective_value = rules[0].expected_value

        source_chain = [
            {
                'rule_id': r.id,
                'standard': r.standard.title,
                'section': r.section,
                'priority': self._get_document_priority(r.standard),
                'operation': r.predicate,
            }
            for r in rules
        ]

        return {
            'effective_rule': {
                'affected_field': field,
                'operation': effective_operation,
                'expected_value': effective_value,
                'rule_type': rules[0].rule_type,
                'severity': 'high' if effective_operation == 'must_not_be_present' else 'medium',
                'text': f"Merged presence requirement: {effective_operation}"
            },
            'source_chain': source_chain,
            'merge_strategy': 'presence_merge',
            'conflict_notes': conflict_notes
        }

    def _merge_critical(self, field: str, rules: List[Rule]) -> Dict:
        """
        合并 Critical 标记规则

        策略：must_be_critical > must_not_be_critical
        （Critical通常是安全要求）
        """
        conflict_notes = []

        has_must_critical = any(r.predicate == 'must_be_critical' for r in rules)
        has_must_not_critical = any(r.predicate == 'must_not_be_critical' for r in rules)

        if has_must_critical and has_must_not_critical:
            # Critical标记冲突 - must_be_critical 优先
            critical_rule = next(r for r in rules if r.predicate == 'must_be_critical')
            conflict_notes.append(
                f"Critical flag conflict resolved: must_be_critical from {critical_rule.standard.title} "
                f"overrides must_not_be_critical"
            )
            effective_operation = 'must_be_critical'
        elif has_must_critical:
            effective_operation = 'must_be_critical'
        else:
            effective_operation = 'must_not_be_critical'

        source_chain = [
            {
                'rule_id': r.id,
                'standard': r.standard.title,
                'section': r.section,
                'priority': self._get_document_priority(r.standard),
                'operation': r.predicate,
            }
            for r in rules
        ]

        return {
            'effective_rule': {
                'affected_field': field,
                'operation': effective_operation,
                'expected_value': None,
                'rule_type': rules[0].rule_type,
                'severity': 'high',
                'text': f"Merged critical requirement: {effective_operation}"
            },
            'source_chain': source_chain,
            'merge_strategy': 'critical_merge',
            'conflict_notes': conflict_notes
        }

    def _merge_by_priority(self, field: str, rules: List[Rule]) -> Dict:
        """
        默认合并策略：使用最高优先级的规则作为基准
        保留其他规则作为证据链
        """
        # 最高优先级规则
        primary_rule = rules[0]

        source_chain = [
            {
                'rule_id': r.id,
                'standard': r.standard.title,
                'section': r.section,
                'priority': self._get_document_priority(r.standard),
                'operation': r.predicate,
                'expected_value': r.constraint_value,
            }
            for r in rules
        ]

        return {
            'effective_rule': {
                'affected_field': field,
                'operation': primary_rule.operation,
                'expected_value': primary_rule.expected_value,
                'rule_type': primary_rule.rule_type,
                'severity': primary_rule.severity,
                'text': primary_rule.text
            },
            'source_chain': source_chain,
            'merge_strategy': 'priority_based',
            'conflict_notes': [
                f"Using highest priority rule from {primary_rule.standard.title}"
            ]
        }

    def _get_document_priority(self, standard: Standard) -> int:
        """获取文档优先级（与 ConflictResolver 保持一致）"""
        from app.services.knowledge_graph.conflict_resolver import ConflictResolver
        return ConflictResolver.DOCUMENT_PRIORITY.get(
            standard.source,
            ConflictResolver.DOCUMENT_PRIORITY['DEFAULT']
        )

    def _parse_numeric_value(self, value_str: Optional[str]) -> Optional[float]:
        """从值字符串中解析数值"""
        if not value_str:
            return None

        import re
        match = re.search(r'(\d+(?:\.\d+)?)', str(value_str))
        if match:
            return float(match.group(1))

        return None

    def get_effective_rules_report(self, effective_rules: List[Dict]) -> Dict:
        """
        生成有效规则报告

        Returns:
            包含统计信息的报告
        """
        total_rules = len(effective_rules)

        # 统计合并策略
        strategy_counts = {}
        for er in effective_rules:
            strategy = er['merge_strategy']
            strategy_counts[strategy] = strategy_counts.get(strategy, 0) + 1

        # 统计冲突
        total_conflicts = sum(len(er['conflict_notes']) for er in effective_rules)

        # 统计源规则数量
        total_source_rules = sum(len(er.get('source_chain', [])) for er in effective_rules)

        return {
            'total_effective_rules': total_rules,
            'total_source_rules': total_source_rules,
            'reduction_rate': (total_source_rules - total_rules) / total_source_rules if total_source_rules > 0 else 0,
            'total_conflicts_resolved': total_conflicts,
            'merge_strategies': strategy_counts,
            'timestamp': datetime.now().isoformat()
        }
