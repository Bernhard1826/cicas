"""
条件可满足性判断器
判断两个条件集是否可同时满足（用于冲突检测Layer 2）
"""
import math
from typing import Tuple, Optional, Set
from app.services.ir.condition_set import (
    ConditionSet, FieldCondition, RangeCondition, SetCondition, Condition
)
from app.core.logging_config import app_logger


class ConditionSatisfiability:
    """条件可满足性判断器"""

    def can_intersect(self, cond_a: ConditionSet, cond_b: ConditionSet) -> Tuple[bool, str]:
        """
        判断两个条件集是否可同时满足

        Args:
            cond_a: 条件集A
            cond_b: 条件集B

        Returns:
            (can_intersect, reason)
            - can_intersect: True表示可同时满足，False表示互斥
            - reason: 判断原因
        """
        # 空条件集总是可满足
        if cond_a.is_empty() or cond_b.is_empty():
            return True, "空条件集，总是可满足"

        # 提取共同字段
        fields_a = set(cond_a.get_fields())
        fields_b = set(cond_b.get_fields())
        common_fields = fields_a & fields_b

        if not common_fields:
            return True, "无共同字段，可同时满足"

        app_logger.debug(f"检查共同字段: {common_fields}")

        # 对每个共同字段检查兼容性
        for field in common_fields:
            # 提取该字段的所有条件
            conds_a = self._get_conditions_for_field(cond_a, field)
            conds_b = self._get_conditions_for_field(cond_b, field)

            compatible, reason = self._check_field_compatibility(field, conds_a, conds_b)
            if not compatible:
                return False, f"字段 {field} 冲突: {reason}"

        return True, "所有共同字段兼容"

    def _get_conditions_for_field(self, cond_set: ConditionSet, field: str) -> list:
        """提取条件集中针对指定字段的所有条件"""
        result = []
        for cond in cond_set.conditions:
            if hasattr(cond, 'field') and cond.field == field:
                result.append(cond)
        return result

    def _check_field_compatibility(
        self,
        field: str,
        conds_a: list,
        conds_b: list
    ) -> Tuple[bool, str]:
        """
        检查同一字段的条件是否兼容

        Args:
            field: 字段名
            conds_a: 规则A对该字段的条件列表
            conds_b: 规则B对该字段的条件列表

        Returns:
            (compatible, reason)
        """
        for ca in conds_a:
            for cb in conds_b:
                # 类型1: FieldCondition vs FieldCondition
                if isinstance(ca, FieldCondition) and isinstance(cb, FieldCondition):
                    compatible, reason = self._check_field_condition_pair(ca, cb)
                    if not compatible:
                        return False, reason

                # 类型2: RangeCondition vs RangeCondition
                elif isinstance(ca, RangeCondition) and isinstance(cb, RangeCondition):
                    compatible, reason = self._check_range_intersection(ca, cb)
                    if not compatible:
                        return False, reason

                # 类型3: SetCondition vs SetCondition
                elif isinstance(ca, SetCondition) and isinstance(cb, SetCondition):
                    compatible, reason = self._check_set_intersection(ca, cb)
                    if not compatible:
                        return False, reason

                # 类型4: 不同类型条件，保守认为兼容
                else:
                    app_logger.debug(f"不同类型条件，保守认为兼容: {type(ca).__name__} vs {type(cb).__name__}")

        return True, "兼容"

    def _check_field_condition_pair(
        self,
        ca: FieldCondition,
        cb: FieldCondition
    ) -> Tuple[bool, str]:
        """
        检查两个字段条件是否兼容

        Examples:
            ca: c.IsCA == True
            cb: c.IsCA == True
            → 兼容

            ca: c.IsCA == True
            cb: c.IsCA == False
            → 不兼容
        """
        # Case 1: 存在性冲突
        if ca.operator == "EXISTS" and cb.operator == "NOT_EXISTS":
            return False, "存在性冲突: EXISTS vs NOT_EXISTS"
        if ca.operator == "NOT_EXISTS" and cb.operator == "EXISTS":
            return False, "存在性冲突: NOT_EXISTS vs EXISTS"

        # Case 2: 等值判断冲突
        if ca.operator == "==" and cb.operator == "==":
            if ca.value != cb.value:
                return False, f"值冲突: {ca.value} != {cb.value}"
            return True, f"相等: {ca.value} == {cb.value}"

        # Case 3: 等值 vs 不等值
        if ca.operator == "==" and cb.operator == "!=":
            if ca.value == cb.value:
                return False, f"矛盾: {ca.value} == {ca.value} AND {cb.value} != {cb.value}"
            return True, "兼容: 值不同"

        # Case 4: 不等值 vs 等值
        if ca.operator == "!=" and cb.operator == "==":
            if ca.value == cb.value:
                return False, f"矛盾: {ca.value} != {ca.value} AND {cb.value} == {cb.value}"
            return True, "兼容: 值不同"

        # Case 5: 比较操作符
        if ca.operator in [">", "<", ">=", "<="] and cb.operator in [">", "<", ">=", "<="]:
            # 转换为范围检查
            ca_range = RangeCondition(
                field=ca.field,
                operator=ca.operator,
                value=ca.value if isinstance(ca.value, (int, float)) else 0
            )
            cb_range = RangeCondition(
                field=cb.field,
                operator=cb.operator,
                value=cb.value if isinstance(cb.value, (int, float)) else 0
            )
            return self._check_range_intersection(ca_range, cb_range)

        # 默认：保守认为兼容
        return True, "无明显冲突"

    def _check_range_intersection(
        self,
        ca: RangeCondition,
        cb: RangeCondition
    ) -> Tuple[bool, str]:
        """
        检查范围条件是否有交集

        Examples:
            ca: validity_days <= 825
            cb: validity_days <= 398
            → 有交集 [0, 398]

            ca: validity_days > 100
            cb: validity_days < 50
            → 无交集
        """
        # 转换为区间
        interval_a = self._to_interval(ca)
        interval_b = self._to_interval(cb)

        if interval_a is None or interval_b is None:
            app_logger.warning(f"无法转换为区间: {ca} or {cb}")
            return True, "无法判断范围，保守认为兼容"

        min_a, max_a = interval_a
        min_b, max_b = interval_b

        # 计算交集
        intersection_min = max(min_a, min_b)
        intersection_max = min(max_a, max_b)

        if intersection_min <= intersection_max:
            # 有交集
            if math.isinf(intersection_max):
                interval_str = f"[{intersection_min}, ∞)"
            else:
                interval_str = f"[{intersection_min}, {intersection_max}]"
            return True, f"有交集 {interval_str}"
        else:
            # 无交集
            return False, f"范围无交集: [{min_a}, {max_a}] ∩ [{min_b}, {max_b}] = ∅"

    def _to_interval(self, cond: RangeCondition) -> Optional[Tuple[float, float]]:
        """
        将范围条件转换为区间 [min, max]

        Examples:
            <= 825 → [0, 825]
            >= 100 → [100, ∞)
            > 50 → [51, ∞)
            < 10 → [0, 9]
        """
        try:
            value = float(cond.value)

            if cond.operator == "<=":
                return (0, value)
            elif cond.operator == "<":
                return (0, value - 1)
            elif cond.operator == ">=":
                return (value, math.inf)
            elif cond.operator == ">":
                return (value + 1, math.inf)
            else:
                app_logger.warning(f"未知的范围操作符: {cond.operator}")
                return None

        except (ValueError, TypeError) as e:
            app_logger.error(f"转换区间失败: {e}")
            return None

    def _check_set_intersection(
        self,
        ca: SetCondition,
        cb: SetCondition
    ) -> Tuple[bool, str]:
        """
        检查集合条件是否有交集

        Examples:
            ca: ExtKeyUsage IN [serverAuth, clientAuth]
            cb: ExtKeyUsage IN [clientAuth, emailProtection]
            → 有交集 {clientAuth}

            ca: ExtKeyUsage IN [serverAuth]
            cb: ExtKeyUsage IN [clientAuth]
            → 无交集
        """
        set_a = set(ca.values)
        set_b = set(cb.values)

        # Case 1: 都是IN操作
        if ca.operator == "IN" and cb.operator == "IN":
            intersection = set_a & set_b
            if intersection:
                return True, f"有交集 {intersection}"
            else:
                return False, "集合无交集"

        # Case 2: 都是NOT_IN操作
        if ca.operator == "NOT_IN" and cb.operator == "NOT_IN":
            # NOT_IN的交集：两个集合的并集都不能包含
            # 示例：A NOT_IN {1,2}, B NOT_IN {2,3}
            # 可满足的值：除了{1,2,3}之外的所有值
            union = set_a | set_b
            return True, f"可满足（排除 {union}）"

        # Case 3: IN vs NOT_IN
        if ca.operator == "IN" and cb.operator == "NOT_IN":
            # A IN {1,2}, B NOT_IN {2,3}
            # 交集：{1}
            valid = set_a - set_b
            if valid:
                return True, f"可满足（值在 {valid}）"
            else:
                return False, "集合冲突: IN集合完全被NOT_IN排除"

        if ca.operator == "NOT_IN" and cb.operator == "IN":
            # 对称情况
            valid = set_b - set_a
            if valid:
                return True, f"可满足（值在 {valid}）"
            else:
                return False, "集合冲突: IN集合完全被NOT_IN排除"

        # Case 4: CONTAINS操作
        if ca.operator == "CONTAINS" and cb.operator == "CONTAINS":
            # 两个CONTAINS可以同时满足
            required = set_a | set_b
            return True, f"可满足（必须包含 {required}）"

        # 其他情况：保守认为兼容
        return True, "保守认为兼容"
