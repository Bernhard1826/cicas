"""
提取验证器
验证提取的规则是否真实存在，防止 LLM hallucination
"""
import re
from typing import List, Optional, Tuple
from difflib import SequenceMatcher
from .chunk_types import StructuredChunk
from .ir_schema import ExtractionResult, IntermediateRepresentation


class ExtractionVerifier:
    """提取验证器"""

    def __init__(
        self,
        similarity_threshold: float = 0.6,
        min_confidence: float = 0.5,
    ):
        """
        初始化验证器

        Args:
            similarity_threshold: 文本相似度阈值
            min_confidence: 最低置信度阈值
        """
        self.similarity_threshold = similarity_threshold
        self.min_confidence = min_confidence

    def verify(
        self,
        result: ExtractionResult,
        chunk: StructuredChunk,
    ) -> Tuple[bool, Optional[str]]:
        """
        验证提取结果

        Args:
            result: 提取结果
            chunk: 原始 chunk

        Returns:
            (is_valid, reason)
        """
        ir = result.ir

        # 1. 检查基础完整性
        if not self._check_completeness(ir):
            return False, "Incomplete IR: missing required fields"

        # 2. 检查是否错误提取了非规范内容
        if chunk.non_normative_markers:
            if self._is_from_non_normative(ir, chunk):
                return False, f"Extracted from non-normative content: {chunk.non_normative_markers}"

        # 3. 检查文本一致性（防止 hallucination）
        if not self._check_text_consistency(ir, chunk):
            return False, "Text inconsistency: rule text not found in original chunk"

        # 4. 检查义务与原文一致性
        if not self._check_obligation_consistency(ir, chunk):
            return False, "Obligation inconsistency: obligation keyword not found in chunk"

        # 5. 检查引用真实性
        if ir.references:
            if not self._check_reference_validity(ir, chunk):
                return False, "Invalid references: reference text not found in chunk"

        # 6. 检查置信度
        if result.confidence < self.min_confidence:
            return False, f"Low confidence: {result.confidence} < {self.min_confidence}"

        return True, None

    def _check_completeness(self, ir: IntermediateRepresentation) -> bool:
        """检查 IR 完整性"""
        # 必填字段
        if not ir.subject or not ir.obligation or not ir.predicate:
            return False

        # constraint 必须有 raw_text
        if not ir.constraint or not ir.constraint.raw_text:
            return False

        # provenance 必须存在
        if not ir.provenance:
            return False

        return True

    def _is_from_non_normative(
        self, ir: IntermediateRepresentation, chunk: StructuredChunk
    ) -> bool:
        """检查是否从非规范内容提取"""
        # 如果 chunk 被标记为非规范，则判定为无效
        if not chunk.is_normative:
            return True

        # 检查规则文本是否包含非规范标记
        rule_text_lower = (ir.rule_text or "").lower()
        non_normative_keywords = [
            'example', 'illustration', 'for example', 'e.g.',
            'test vector', 'sample', 'note:', 'editor\'s note'
        ]

        for keyword in non_normative_keywords:
            if keyword in rule_text_lower:
                return True

        return False

    def _check_text_consistency(
        self, ir: IntermediateRepresentation, chunk: StructuredChunk
    ) -> bool:
        """检查文本一致性"""
        if not ir.rule_text:
            return True  # 如果没有 rule_text，跳过

        # 计算相似度
        similarity = self._text_similarity(ir.rule_text, chunk.text)

        if similarity < self.similarity_threshold:
            return False

        return True

    def _text_similarity(self, text1: str, text2: str) -> float:
        """计算文本相似度"""
        # 简单的子串匹配
        text1_clean = self._clean_text(text1)
        text2_clean = self._clean_text(text2)

        if text1_clean in text2_clean:
            return 1.0

        # 使用 SequenceMatcher
        matcher = SequenceMatcher(None, text1_clean, text2_clean)
        return matcher.ratio()

    def _clean_text(self, text: str) -> str:
        """清理文本"""
        # 转小写，去除多余空格
        text = text.lower()
        text = re.sub(r'\s+', ' ', text)
        return text.strip()

    def _check_obligation_consistency(
        self, ir: IntermediateRepresentation, chunk: StructuredChunk
    ) -> bool:
        """检查义务关键词一致性"""
        obligation_keyword = ir.obligation.value

        # 在 chunk 中查找义务关键词
        chunk_text_upper = chunk.text.upper()

        if obligation_keyword in chunk_text_upper:
            return True

        # 检查规则文本
        if ir.rule_text:
            rule_text_upper = ir.rule_text.upper()
            if obligation_keyword in rule_text_upper:
                return True

        return False

    def _check_reference_validity(
        self, ir: IntermediateRepresentation, chunk: StructuredChunk
    ) -> bool:
        """检查引用有效性"""
        for ref in ir.references:
            # 检查引用文本是否在 chunk 中
            if ref.raw:
                if ref.raw not in chunk.text and ref.raw not in (ir.rule_text or ""):
                    # 宽松检查：检查文档ID
                    if ref.doc_id:
                        if ref.doc_id not in chunk.text:
                            return False
                    else:
                        return False

        return True

    def verify_batch(
        self,
        results: List[ExtractionResult],
        chunks: List[StructuredChunk],
    ) -> List[ExtractionResult]:
        """
        批量验证

        Args:
            results: 提取结果列表
            chunks: chunk 列表（必须与 results 对应）

        Returns:
            验证通过的结果列表
        """
        verified_results = []

        for result, chunk in zip(results, chunks):
            is_valid, reason = self.verify(result, chunk)

            if is_valid:
                verified_results.append(result)
            else:
                print(f"Verification failed: {reason}")

        return verified_results
