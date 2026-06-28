"""
作用域检查器

基于《冲突和引用处理算法详解.md》第3层过滤器设计
判断两条规则约束的字段是否在同一层级，是否可比较
"""
from enum import Enum
from typing import Tuple
from app.core.logging_config import app_logger


class ScopeRelation(str, Enum):
    """作用域关系类型"""
    SAME = "SAME"                    # 完全相同：都约束 "keyUsage"
    REFINEMENT = "REFINEMENT"        # 细化关系：A约束"extensions", B约束"extensions.keyUsage"
    DISJOINT = "DISJOINT"           # 完全不同：A约束"keyUsage", B约束"validity"
    INCOMPARABLE = "INCOMPARABLE"   # 无法比较：A约束整体，B约束局部


class ScopeChecker:
    """作用域检查器

    判断两个字段路径的作用域关系
    """

    @staticmethod
    def determine_scope_relation(field_a: str, field_b: str) -> ScopeRelation:
        """
        判断两个字段的作用域关系

        Args:
            field_a: 规则A的字段路径（如 "extensions.keyUsage"）
            field_b: 规则B的字段路径（如 "extensions.keyUsage.critical"）

        Returns:
            作用域关系类型

        Examples:
            >>> determine_scope_relation("keyUsage", "keyUsage")
            SAME

            >>> determine_scope_relation("extensions", "extensions.keyUsage")
            REFINEMENT

            >>> determine_scope_relation("keyUsage", "validity")
            DISJOINT

            >>> determine_scope_relation("extensions.basicConstraints", "extensions.basicConstraints.cA")
            INCOMPARABLE  # 一个约束整体存在，一个约束内部字段
        """
        if not field_a or not field_b:
            return ScopeRelation.INCOMPARABLE

        # 情况1：完全相同
        if field_a == field_b:
            return ScopeRelation.SAME

        # 情况2：一个是另一个的子路径
        if field_b.startswith(field_a + "."):
            # B 是 A 的子路径
            return ScopeRelation.REFINEMENT

        if field_a.startswith(field_b + "."):
            # A 是 B 的子路径
            return ScopeRelation.REFINEMENT

        # 情况3：完全不同的路径
        if not ScopeChecker._has_common_prefix(field_a, field_b):
            return ScopeRelation.DISJOINT

        # 情况4：有共同前缀但不是子路径关系 → 复杂情况
        # 例如：extensions.keyUsage 和 extensions.basicConstraints
        return ScopeRelation.INCOMPARABLE

    @staticmethod
    def _has_common_prefix(field_a: str, field_b: str) -> bool:
        """检查两个字段是否有共同前缀"""
        parts_a = field_a.split(".")
        parts_b = field_b.split(".")

        # 至少有一个共同的部分
        for i, (pa, pb) in enumerate(zip(parts_a, parts_b)):
            if pa == pb:
                return True
            else:
                # 第一个不同就停止
                return False

        return False

    @staticmethod
    def is_comparable(field_a: str, field_b: str) -> bool:
        """
        判断两个字段是否可比较（是否应该进行冲突检测）

        只有 SAME 关系的字段才可比较
        REFINEMENT, DISJOINT, INCOMPARABLE 都不应该进行冲突比较

        Args:
            field_a: 规则A的字段路径
            field_b: 规则B的字段路径

        Returns:
            True 表示可比较，False 表示不可比较（应跳过冲突检测）

        Reasoning:
            - SAME: 可比较（两个规则约束同一个东西）
            - REFINEMENT: 不可比较（一个约束整体，一个约束局部，不矛盾）
              例如："extensions.basicConstraints 必须存在" 和
                   "extensions.basicConstraints.cA 必须为TRUE" 不冲突
            - DISJOINT: 不可比较（约束完全不同的东西）
            - INCOMPARABLE: 不可比较（无法判断关系）
        """
        relation = ScopeChecker.determine_scope_relation(field_a, field_b)
        return relation == ScopeRelation.SAME

    @staticmethod
    def get_scope_info(field_a: str, field_b: str) -> dict:
        """
        获取详细的作用域信息（用于调试和日志）

        Returns:
            {
                "relation": ScopeRelation,
                "comparable": bool,
                "reason": str
            }
        """
        relation = ScopeChecker.determine_scope_relation(field_a, field_b)
        comparable = (relation == ScopeRelation.SAME)

        reasons = {
            ScopeRelation.SAME: f"Both rules constrain the same field: {field_a}",
            ScopeRelation.REFINEMENT: f"One field is a refinement of the other: {field_a} vs {field_b}",
            ScopeRelation.DISJOINT: f"Fields are completely different: {field_a} vs {field_b}",
            ScopeRelation.INCOMPARABLE: f"Cannot determine relationship: {field_a} vs {field_b}",
        }

        return {
            "relation": relation.value,
            "comparable": comparable,
            "reason": reasons[relation]
        }


# 全局单例
_scope_checker = None

def get_scope_checker() -> ScopeChecker:
    """获取作用域检查器单例"""
    global _scope_checker
    if _scope_checker is None:
        _scope_checker = ScopeChecker()
    return _scope_checker
