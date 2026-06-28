"""
规则组装器（Rule Assembler）
处理跨段落规则组合、条件组合、列表组合
"""
from typing import List, Optional, Dict, Any
from .ir_schema import (
    ExtractionResult,
    IntermediateRepresentation,
    IRProvenance,
)
import re


class RuleAssembler:
    """规则组装器 - 组合跨段落的规则片段"""

    def __init__(self):
        """初始化组装器"""
        # 条件关键词
        self.condition_keywords = [
            r'\bif\b', r'\bwhen\b', r'\bunless\b',
            r'\bexcept\b', r'\bprovided\s+that\b',
            r'\bin\s+case\b', r'\bwhere\b',
        ]
        self.condition_pattern = re.compile(
            '|'.join(self.condition_keywords), re.IGNORECASE
        )

        # 连接词
        self.conjunction_keywords = [
            r'\band\b', r'\bor\b', r'\bbut\b',
            r'\bhowever\b', r'\bmoreover\b',
        ]
        self.conjunction_pattern = re.compile(
            '|'.join(self.conjunction_keywords), re.IGNORECASE
        )

    def assemble(
        self, results: List[ExtractionResult]
    ) -> List[ExtractionResult]:
        """
        组装规则

        Args:
            results: 原始提取结果列表

        Returns:
            组装后的结果列表
        """
        # 第一步：识别需要组合的规则
        grouped = self._group_related_rules(results)

        # 第二步：组合每个组
        assembled = []
        for group in grouped:
            if len(group) == 1:
                # 单个规则，直接添加
                assembled.append(group[0])
            else:
                # 多个规则，尝试组合
                combined = self._combine_rules(group)
                if combined:
                    assembled.append(combined)
                else:
                    # 组合失败，保留原始规则
                    assembled.extend(group)

        return assembled

    def _group_related_rules(
        self, results: List[ExtractionResult]
    ) -> List[List[ExtractionResult]]:
        """将相关规则分组"""
        groups = []
        current_group = []

        for i, result in enumerate(results):
            if not current_group:
                current_group.append(result)
                continue

            # 检查是否应该加入当前组
            last_result = current_group[-1]
            if self._should_group(last_result, result):
                current_group.append(result)
            else:
                # 开始新组
                groups.append(current_group)
                current_group = [result]

        if current_group:
            groups.append(current_group)

        return groups

    def _should_group(
        self, result1: ExtractionResult, result2: ExtractionResult
    ) -> bool:
        """判断两个规则是否应该组合"""
        ir1 = result1.ir
        ir2 = result2.ir

        # 1. 检查 provenance 是否相邻
        if ir1.provenance and ir2.provenance:
            prov1 = ir1.provenance[0]
            prov2 = ir2.provenance[0]

            # 相同文档和连续行
            if prov1.source_id == prov2.source_id:
                if prov1.line_end and prov2.line_start:
                    if abs(prov2.line_start - prov1.line_end) <= 2:
                        return True

        # 2. 检查规则文本是否有条件关系
        if ir2.rule_text:
            # 如果规则2以条件词开头
            if self.condition_pattern.match(ir2.rule_text):
                return True

            # 如果规则2以连接词开头
            if self.conjunction_pattern.match(ir2.rule_text):
                return True

        # 3. 检查主体是否相同
        if ir1.subject == ir2.subject:
            return True

        return False

    def _combine_rules(
        self, group: List[ExtractionResult]
    ) -> Optional[ExtractionResult]:
        """组合一组规则"""
        if not group:
            return None

        if len(group) == 1:
            return group[0]

        # 使用第一个规则作为基础
        base_result = group[0]
        base_ir = base_result.ir

        # 合并规则文本
        combined_text = base_ir.rule_text or ""
        for result in group[1:]:
            if result.ir.rule_text:
                combined_text += " " + result.ir.rule_text

        # 合并条件
        combined_conditions = base_ir.conditions or []
        for result in group[1:]:
            if result.ir.conditions:
                combined_conditions.extend(result.ir.conditions)

        # 合并引用
        combined_references = list(base_ir.references)
        for result in group[1:]:
            for ref in result.ir.references:
                if ref not in combined_references:
                    combined_references.append(ref)

        # 合并 provenance
        combined_provenance = list(base_ir.provenance)
        for result in group[1:]:
            for prov in result.ir.provenance:
                if prov not in combined_provenance:
                    combined_provenance.append(prov)

        # 合并 KG 链接
        combined_kg_links = dict(base_ir.kg_links)
        for result in group[1:]:
            for key, values in result.ir.kg_links.items():
                if key in combined_kg_links:
                    combined_kg_links[key].extend(values)
                    combined_kg_links[key] = list(set(combined_kg_links[key]))
                else:
                    combined_kg_links[key] = values

        # 创建新的 IR
        combined_ir = IntermediateRepresentation(
            rule_id=base_ir.rule_id,
            stage=base_ir.stage,
            subject=base_ir.subject,
            obligation=base_ir.obligation,
            predicate=base_ir.predicate,
            constraint=base_ir.constraint,
            references=combined_references,
            provenance=combined_provenance,
            kg_links=combined_kg_links,
            rule_text=combined_text,
            conditions=combined_conditions if combined_conditions else None,
            context=base_ir.context,
        )

        combined_result = ExtractionResult(ir=combined_ir)

        return combined_result
