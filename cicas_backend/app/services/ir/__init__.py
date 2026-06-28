"""
IR (Intermediate Representation) 模块

提供规则的中间表示相关功能：
- condition_set: 条件集合数据结构
- llm_condition_extractor: LLM条件提取器
- condition_satisfiability: 条件可满足性判断器
- ir_error_tracker: IR错误跟踪器（Phase 3）
"""

from .condition_set import (
    FieldCondition,
    SetCondition,
    RangeCondition,
    LogicalCondition,
    Condition,
    ConditionSet
)

from .llm_condition_extractor import LLMConditionExtractor, SimpleLLMClient
from .condition_satisfiability import ConditionSatisfiability

__all__ = [
    # 条件数据结构
    "FieldCondition",
    "SetCondition",
    "RangeCondition",
    "LogicalCondition",
    "Condition",
    "ConditionSet",
    # 提取器
    "LLMConditionExtractor",
    "SimpleLLMClient",
    # 判断器
    "ConditionSatisfiability",
]
