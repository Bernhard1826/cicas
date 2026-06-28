"""
提取器调度器
根据 chunk 类型选择合适的提取器
"""
from typing import List, Optional
from .base_extractor import BaseExtractor
from .template_extractor import TemplateExtractor
from .llm_extractor import LLMExtractor
from .chunk_types import StructuredChunk, ExtractorType
from .ir_schema import ExtractionResult


class ExtractorDispatcher:
    """提取器调度器"""

    def __init__(self, llm_client=None, enable_llm: bool = True):
        """
        初始化调度器

        Args:
            llm_client: LLM 客户端
            enable_llm: 是否启用 LLM 提取器
        """
        self.extractors: List[BaseExtractor] = [
            TemplateExtractor(),
        ]

        if enable_llm and llm_client:
            self.extractors.append(LLMExtractor(llm_client))

        self.enable_llm = enable_llm

    def dispatch(self, chunk: StructuredChunk) -> List[ExtractionResult]:
        """
        调度提取器处理 chunk

        Args:
            chunk: 结构化 chunk

        Returns:
            提取结果列表
        """
        # 检查是否应该提取
        if not chunk.should_extract:
            return []

        # 选择提取器
        selected_extractor = self._select_extractor(chunk)

        if not selected_extractor:
            return []

        # 执行提取
        try:
            results = selected_extractor.extract(chunk)
            return results
        except Exception as e:
            print(f"Extraction error with {selected_extractor.name}: {e}")
            return []

    def _select_extractor(self, chunk: StructuredChunk) -> Optional[BaseExtractor]:
        """
        选择合适的提取器

        优先级：
        1. chunk.extractor_type 指定的类型
        2. 第一个 can_extract 返回 True 的提取器

        Args:
            chunk: 结构化 chunk

        Returns:
            选中的提取器
        """
        # 优先使用推荐的提取器类型
        if chunk.extractor_type == ExtractorType.NONE:
            return None

        # 按优先级查找
        for extractor in self.extractors:
            if extractor.can_extract(chunk):
                # 检查类型匹配
                if chunk.extractor_type == ExtractorType.TEMPLATE and isinstance(extractor, TemplateExtractor):
                    return extractor
                elif chunk.extractor_type == ExtractorType.LLM and isinstance(extractor, LLMExtractor):
                    return extractor

        # 回退：返回第一个能处理的
        for extractor in self.extractors:
            if extractor.can_extract(chunk):
                return extractor

        return None

    def extract_from_chunks(
        self, chunks: List[StructuredChunk]
    ) -> List[ExtractionResult]:
        """
        批量提取

        Args:
            chunks: chunk 列表

        Returns:
            所有提取结果
        """
        all_results = []

        for chunk in chunks:
            results = self.dispatch(chunk)
            all_results.extend(results)

        return all_results

    def get_statistics(self) -> dict:
        """获取统计信息"""
        return {
            "total_extractors": len(self.extractors),
            "extractors": [
                {
                    "name": ext.name,
                    "type": ext.__class__.__name__,
                    "confidence_base": ext.confidence_base,
                }
                for ext in self.extractors
            ],
            "llm_enabled": self.enable_llm,
        }
