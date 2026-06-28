"""
Stage C: 引用解析编排器
负责在所有规则提取完成后，统一解析和链接引用

重构后输出：
- 继续输出解析后的 IR（向后兼容）
- 新增输出 ReferenceFact 列表（用于 Rule Reasoning Service）
"""
from typing import List, Dict, Any, Optional, Tuple
from sqlalchemy.orm import Session
from app.services.extraction.ir_schema import IntermediateRepresentation, IRReference
from app.services.extraction.enhanced_reference_resolver import EnhancedReferenceResolver
from app.core.logging_config import app_logger


class ReferenceResolutionOrchestrator:
    """
    Stage C: 引用解析编排器

    设计原则：
    - 在所有规则提取完成后统一解析引用
    - 维护全局上下文（当前文档、最近文档引用）
    - 支持显式和隐式引用解析
    - 输出 ReferenceFact 格式（重构后新增）
    """

    def __init__(
        self,
        db: Optional[Session] = None,
        kg_client=None,
        standards_index: Dict[str, Any] = None,
        standard_id: Optional[int] = None  # 添加standard_id参数
    ):
        """
        初始化引用解析编排器

        Args:
            db: 数据库会话（用于查找 structural_rule_id）
            kg_client: 知识图谱客户端（可选）
            standards_index: 标准文档索引（可选）
            standard_id: 当前提取的标准ID（用于内部引用验证）
        """
        self.resolver = EnhancedReferenceResolver(
            db=db,
            kg_client=kg_client,
            standards_index=standards_index
        )

        # 全局上下文
        self.context = {
            'current_document': None,  # 当前规则所属文档
            'recent_document': None,   # 最近出现的文档引用
            'standard_id': standard_id  # 当前标准ID（用于内部引用）
        }

        app_logger.info("[ReferenceResolutionOrchestrator] Initialized Stage C")

    def resolve_all_references(
        self,
        irs: List[IntermediateRepresentation]
    ) -> List[IntermediateRepresentation]:
        """
        解析所有规则的引用

        Args:
            irs: 待解析的 IR 列表

        Returns:
            解析后的 IR 列表
        """
        if not irs:
            return []

        app_logger.info(f"[Stage C] Starting reference resolution for {len(irs)} rules")

        total_refs = sum(len(ir.references) for ir in irs)
        app_logger.info(f"[Stage C] Total references to resolve: {total_refs}")

        resolved_irs = []
        resolved_count = 0
        unresolved_count = 0

        for idx, ir in enumerate(irs, 1):
            # 更新上下文：从 provenance 获取当前文档
            if ir.provenance and len(ir.provenance) > 0:
                source_id = ir.provenance[0].source_id
                self.context['current_document'] = source_id

            # 解析引用
            resolved_ir = self.resolver.resolve_references(ir, self.context)

            # 更新上下文：记录最近的文档引用
            for ref in resolved_ir.references:
                if ref.resolved and ref.doc_id:
                    self.context['recent_document'] = ref.doc_id
                    break  # 只记录第一个已解析的引用

            # 统计
            for ref in resolved_ir.references:
                if ref.resolved:
                    resolved_count += 1
                else:
                    unresolved_count += 1

            resolved_irs.append(resolved_ir)

            # 定期日志
            if idx % 100 == 0:
                app_logger.debug(f"[Stage C] Processed {idx}/{len(irs)} rules")

        app_logger.info(
            f"[Stage C] Reference resolution completed: "
            f"{resolved_count} resolved, {unresolved_count} unresolved"
        )

        # 详细统计
        self._log_resolution_statistics(resolved_irs)

        return resolved_irs

    def _log_resolution_statistics(self, irs: List[IntermediateRepresentation]):
        """记录引用解析统计信息"""
        stats = {
            'total_rules': len(irs),
            'rules_with_references': 0,
            'total_references': 0,
            'resolved_references': 0,
            'unresolved_references': 0,
            'by_resolution_method': {},
        }

        for ir in irs:
            if ir.references:
                stats['rules_with_references'] += 1
                stats['total_references'] += len(ir.references)

                for ref in ir.references:
                    if ref.resolved:
                        stats['resolved_references'] += 1
                        method = ref.resolution_method or 'unknown'
                        stats['by_resolution_method'][method] = \
                            stats['by_resolution_method'].get(method, 0) + 1
                    else:
                        stats['unresolved_references'] += 1

        app_logger.info(f"[Stage C] Statistics: {stats}")

        # 计算解析率
        if stats['total_references'] > 0:
            resolution_rate = (stats['resolved_references'] / stats['total_references']) * 100
            app_logger.info(f"[Stage C] Resolution rate: {resolution_rate:.1f}%")

    # =========================================================================
    # 重构后：ReferenceFact 输出（用于 Rule Reasoning Service）
    # =========================================================================

    def resolve_and_extract_facts(
        self,
        irs: List[IntermediateRepresentation]
    ) -> Tuple[List[IntermediateRepresentation], List[Dict[str, Any]]]:
        """
        解析引用并提取 ReferenceFact（重构后的新接口）

        这是 Stage C 的新输出接口：
        1. 解析所有引用（填充 IR.references）
        2. 提取 ReferenceFact 列表（用于 Rule Reasoning Service）

        Args:
            irs: 待解析的 IR 列表

        Returns:
            (resolved_irs, reference_facts)
            - resolved_irs: 解析后的 IR 列表
            - reference_facts: ReferenceFact 列表
        """
        # Step 1: 解析引用（原有逻辑）
        resolved_irs = self.resolve_all_references(irs)

        # Step 2: 提取 ReferenceFact（新逻辑）
        reference_facts = self.resolver.extract_reference_facts(resolved_irs)

        app_logger.info(
            f"[Stage C] Output: {len(resolved_irs)} resolved IRs, "
            f"{len(reference_facts)} reference facts"
        )

        return resolved_irs, reference_facts
