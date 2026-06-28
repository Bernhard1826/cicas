"""
提取器基类
定义统一的提取器接口
"""
from abc import ABC, abstractmethod
from typing import List, Optional
from .chunk_types import StructuredChunk
from .ir_schema import ExtractionResult, IRStage


class BaseExtractor(ABC):
    """提取器基类"""

    def __init__(self, name: str, confidence_base: float = 1.0):
        """
        初始化提取器

        Args:
            name: 提取器名称
            confidence_base: 基础置信度
        """
        self.name = name
        self.confidence_base = confidence_base

    @abstractmethod
    def can_extract(self, chunk: StructuredChunk) -> bool:
        """
        判断是否可以处理该 chunk

        Args:
            chunk: 结构化 chunk

        Returns:
            是否可以提取
        """
        pass

    @abstractmethod
    def extract(self, chunk: StructuredChunk) -> List[ExtractionResult]:
        """
        从 chunk 提取规则

        Args:
            chunk: 结构化 chunk

        Returns:
            提取结果列表（raw IR）
        """
        pass

    def validate_extraction(self, result: ExtractionResult, chunk: StructuredChunk) -> bool:
        """
        验证提取结果（基础验证）

        Args:
            result: 提取结果
            chunk: 原始 chunk

        Returns:
            是否有效
        """
        # 确保是 raw IR
        if result.ir.stage != IRStage.RAW:
            return False

        # 确保必填字段存在
        if not result.ir.subject or not result.ir.obligation or not result.ir.predicate:
            return False

        # 确保约束有 raw_text
        if not result.ir.constraint.raw_text:
            return False

        return True

    def __repr__(self):
        return f"<{self.__class__.__name__}:{self.name}>"
