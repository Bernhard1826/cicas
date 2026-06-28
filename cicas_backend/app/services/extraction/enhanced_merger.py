"""
增强的规则合并和去重模块
考虑引用、provenance、kg_links 的完整性
"""
from typing import List, Optional, Set, Dict
from difflib import SequenceMatcher
from .ir_schema import (
    ExtractionResult,
    IntermediateRepresentation,
    IRReference,
    IRProvenance,
)


class EnhancedMerger:
    """增强的合并器"""

    def __init__(
        self,
        similarity_threshold: float = 0.85,
        merge_strategy: str = "strict",
    ):
        """
        初始化合并器

        Args:
            similarity_threshold: 相似度阈值
            merge_strategy: 合并策略 ('strict' 或 'lenient')
        """
        self.similarity_threshold = similarity_threshold
        self.merge_strategy = merge_strategy

    def merge_and_deduplicate(
        self, results: List[ExtractionResult]
    ) -> List[ExtractionResult]:
        """
        合并和去重

        Args:
            results: 提取结果列表

        Returns:
            去重后的结果列表
        """
        if not results:
            return []

        # 第一步：按主体分组
        groups = self._group_by_subject(results)

        # 第二步：在每个组内去重和合并
        merged_results = []
        for subject, group_results in groups.items():
            merged_group = self._merge_group(group_results)
            merged_results.extend(merged_group)

        return merged_results

    def _group_by_subject(
        self, results: List[ExtractionResult]
    ) -> Dict[str, List[ExtractionResult]]:
        """按主体分组"""
        groups = {}
        for result in results:
            subject = result.ir.subject.path if hasattr(result.ir.subject, 'path') else str(result.ir.subject)
            if subject not in groups:
                groups[subject] = []
            groups[subject].append(result)
        return groups

    def _merge_group(
        self, group: List[ExtractionResult]
    ) -> List[ExtractionResult]:
        """合并一组规则"""
        if len(group) <= 1:
            return group

        merged = []
        processed = set()

        for i, result1 in enumerate(group):
            if i in processed:
                continue

            # 查找可以合并的规则
            merge_candidates = [result1]

            for j, result2 in enumerate(group):
                if i == j or j in processed:
                    continue

                if self._can_merge(result1, result2):
                    merge_candidates.append(result2)
                    processed.add(j)

            # 合并候选规则
            if len(merge_candidates) == 1:
                merged.append(merge_candidates[0])
            else:
                merged_result = self._merge_results(merge_candidates)
                merged.append(merged_result)

            processed.add(i)

        return merged

    def _can_merge(
        self, result1: ExtractionResult, result2: ExtractionResult
    ) -> bool:
        """判断两个结果是否可以合并"""
        ir1 = result1.ir
        ir2 = result2.ir

        # 1. 主体必须相同
        subj1 = ir1.subject.path if hasattr(ir1.subject, 'path') else str(ir1.subject)
        subj2 = ir2.subject.path if hasattr(ir2.subject, 'path') else str(ir2.subject)
        if subj1 != subj2:
            return False

        # 2. 义务和谓词必须相同
        if ir1.obligation != ir2.obligation or ir1.predicate != ir2.predicate:
            return False

        # 3. 检查引用一致性（关键！）
        if not self._references_compatible(ir1.references, ir2.references):
            return False

        # 4. 检查约束相似性
        if not self._constraints_similar(ir1, ir2):
            return False

        # 5. 计算规则文本相似度
        text_similarity = self._text_similarity(
            ir1.rule_text or "", ir2.rule_text or ""
        )

        if text_similarity < self.similarity_threshold:
            return False

        return True

    def _references_compatible(
        self, refs1: List[IRReference], refs2: List[IRReference]
    ) -> bool:
        """检查引用是否兼容"""
        # 策略：如果引用不一致，则不能合并
        if not refs1 and not refs2:
            return True

        if len(refs1) != len(refs2):
            # 宽松模式：允许一个有引用，另一个没有
            if self.merge_strategy == "lenient":
                return True
            return False

        # 严格模式：检查引用是否指向相同文档和章节
        if self.merge_strategy == "strict":
            refs1_set = {(r.doc_id, r.section) for r in refs1 if r.doc_id}
            refs2_set = {(r.doc_id, r.section) for r in refs2 if r.doc_id}

            if refs1_set != refs2_set:
                return False

        return True

    def _constraints_similar(
        self, ir1: IntermediateRepresentation, ir2: IntermediateRepresentation
    ) -> bool:
        """检查约束是否相似"""
        c1 = ir1.constraint
        c2 = ir2.constraint

        # 类型相同
        if c1.type != c2.type:
            return False

        # 值相同或相似
        if c1.value != c2.value:
            # 如果都是字符串，检查相似度
            if isinstance(c1.value, str) and isinstance(c2.value, str):
                sim = self._text_similarity(c1.value, c2.value)
                if sim < self.similarity_threshold:
                    return False
            else:
                return False

        return True

    def _text_similarity(self, text1: str, text2: str) -> float:
        """计算文本相似度"""
        if not text1 or not text2:
            return 0.0

        text1 = text1.lower().strip()
        text2 = text2.lower().strip()

        if text1 == text2:
            return 1.0

        matcher = SequenceMatcher(None, text1, text2)
        return matcher.ratio()

    def _merge_results(
        self, candidates: List[ExtractionResult]
    ) -> ExtractionResult:
        """合并多个结果"""
        if len(candidates) == 1:
            return candidates[0]

        # 选择置信度最高的作为基础
        base_result = max(candidates, key=lambda r: r.confidence)
        base_ir = base_result.ir

        # 合并引用（union）
        merged_references = list(base_ir.references)
        seen_refs = {(r.doc_id, r.section) for r in merged_references if r.doc_id}

        for result in candidates:
            if result == base_result:
                continue
            for ref in result.ir.references:
                ref_key = (ref.doc_id, ref.section)
                if ref.doc_id and ref_key not in seen_refs:
                    merged_references.append(ref)
                    seen_refs.add(ref_key)

        # 合并 provenance（union）
        merged_provenance = list(base_ir.provenance)
        seen_prov = {
            (p.source_id, p.chunk_id) for p in merged_provenance
        }

        for result in candidates:
            if result == base_result:
                continue
            for prov in result.ir.provenance:
                prov_key = (prov.source_id, prov.chunk_id)
                if prov_key not in seen_prov:
                    merged_provenance.append(prov)
                    seen_prov.add(prov_key)

        # 合并 kg_links（union）
        merged_kg_links = dict(base_ir.kg_links)
        for result in candidates:
            if result == base_result:
                continue
            for key, values in result.ir.kg_links.items():
                if key in merged_kg_links:
                    # 合并而不是覆盖
                    merged_kg_links[key] = list(
                        set(merged_kg_links[key]) | set(values)
                    )
                else:
                    merged_kg_links[key] = values

        # 创建合并后的 IR
        merged_ir = IntermediateRepresentation(
            rule_id=base_ir.rule_id,
            stage=base_ir.stage,
            subject=base_ir.subject,
            obligation=base_ir.obligation,
            predicate=base_ir.predicate,
            constraint=base_ir.constraint,
            references=merged_references,
            provenance=merged_provenance,
            kg_links=merged_kg_links,
            rule_text=base_ir.rule_text,
            conditions=base_ir.conditions,
            context=base_ir.context,
        )

        merged_result = ExtractionResult(ir=merged_ir)

        return merged_result


class EnhancedDeduplicator:
    """增强的去重器"""

    def __init__(self, similarity_threshold: float = 0.95):
        """
        初始化去重器

        Args:
            similarity_threshold: 相似度阈值（用于完全重复检测）
        """
        self.similarity_threshold = similarity_threshold

    def deduplicate(
        self, results: List[ExtractionResult]
    ) -> List[ExtractionResult]:
        """
        去重

        Args:
            results: 结果列表

        Returns:
            去重后的列表
        """
        if not results:
            return []

        unique_results = []
        seen_hashes = set()

        for result in results:
            # 计算哈希（基于主要字段）
            result_hash = self._compute_hash(result.ir)

            if result_hash not in seen_hashes:
                unique_results.append(result)
                seen_hashes.add(result_hash)

        return unique_results

    def _compute_hash(self, ir: IntermediateRepresentation) -> str:
        """计算 IR 哈希"""
        # 基于关键字段生成哈希
        hash_parts = [
            ir.subject.path if hasattr(ir.subject, 'path') else str(ir.subject),
            ir.obligation.value,
            ir.predicate.value,
            ir.constraint.raw_text,
        ]

        # 添加引用信息
        for ref in sorted(ir.references, key=lambda r: r.raw):
            hash_parts.append(f"{ref.doc_id}:{ref.section}")

        hash_str = "|".join(str(p) for p in hash_parts)
        return hash_str
