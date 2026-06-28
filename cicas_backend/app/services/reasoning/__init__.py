"""
Reasoning Service 模块

唯一允许进行规则推理的模块
"""
from .rule_reasoning_service import (
    RuleReasoningService,
    RelationResult,
    UncertainRelation,
    ReasoningFailure,
    RelationType,
    UncertainRelationType
)

__all__ = [
    'RuleReasoningService',
    'RelationResult',
    'UncertainRelation',
    'ReasoningFailure',
    'RelationType',
    'UncertainRelationType'
]
