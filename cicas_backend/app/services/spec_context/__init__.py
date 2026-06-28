"""
Specification Context Manager

规范上下文管理器
"""
from .context_manager import (
    SpecificationContextManager,
    SpecFamily,
    Scope,
    SpecContext,
    detect_spec_family,
    get_applicable_scope,
)

__all__ = [
    "SpecificationContextManager",
    "SpecFamily",
    "Scope",
    "SpecContext",
    "detect_spec_family",
    "get_applicable_scope",
]
