"""
规则冲突与引用处理引擎 (Rule Conflict and Reference Engine)

统一的跨文档规则处理引擎，整合：
1. 引用解析 (ReferenceResolver)
2. 冲突检测与解决 (ConflictResolver)
3. 有效规则合并 (EffectiveRuleMerger)

用于Layer 6: KG增强阶段
"""
from typing import List, Dict, Optional
from sqlalchemy.orm import Session
from datetime import datetime

from app.models.models import Rule, Standard
from app.core.logging_config import app_logger
from app.services.knowledge_graph.reference_resolver import ReferenceResolver
from app.services.knowledge_graph.conflict_resolver import ConflictResolver
from app.services.knowledge_graph.effective_rule_merger import EffectiveRuleMerger


class RuleConflictAndReferenceEngine:
    """
    规则冲突与引用处理引擎

    核心功能：
    1. 解析跨文档引用（RFC → CABF → CPS）
    2. 检测规则冲突（存在性、范围、值约束）
    3. 解决冲突（优先级、关系、时间）
    4. 合并有效规则（范围收紧、禁止优先）
    5. 生成知识图谱关系（CITES, overrides, extends）

    适用场景：
    - 多标准文档共存（RFC + CABF + ETSI）
    - 需要生成最终有效规则集
    - 需要追溯规则来源证据链
    """

    def __init__(self, db: Session, kg=None):
        """
        Args:
            db: 数据库会话
            kg: 知识图谱实例（可选，用于写入关系边）
        """
        self.db = db
        self.kg = kg

        # 初始化三个核心模块
        self.reference_resolver = ReferenceResolver(db)
        self.conflict_resolver = ConflictResolver(db, kg)
        self.effective_merger = EffectiveRuleMerger(db)

    def run(
        self,
        rule_candidates: List[Rule],
        resolve_conflicts: bool = True,
        merge_effective: bool = True
    ) -> Dict:
        """
        执行完整的冲突与引用处理流程

        流程：
        1. 引用解析：识别规则之间的引用关系
        2. 冲突检测：检测跨文档冲突
        3. 冲突解决：基于优先级解决冲突（可选）
        4. 有效规则合并：生成最终有效规则（可选）
        5. 写入KG关系：CITES, overrides, extends

        Args:
            rule_candidates: 候选规则列表（已经过质量验证）
            resolve_conflicts: 是否自动解决冲突（默认True）
            merge_effective: 是否合并生成有效规则（默认True）

        Returns:
            处理结果，包含：
            - effective_rules: 最终有效规则列表
            - references: 引用关系列表
            - conflicts: 冲突列表及解决方案
            - statistics: 统计信息
        """
        app_logger.info(
            f"[RuleConflictAndReferenceEngine] Starting processing for {len(rule_candidates)} rules "
            f"(resolve_conflicts={resolve_conflicts}, merge_effective={merge_effective})"
        )

        start_time = datetime.now()

        # ========== Step 1: 引用解析 ==========
        app_logger.info("[Step 1/5] Resolving cross-document references...")
        reference_report = self.reference_resolver.resolve_all_references(
            rule_candidates=rule_candidates
        )

        app_logger.info(
            f"[OK] Reference resolution: {reference_report['references_resolved']}/{reference_report['total_references_found']} resolved"
        )

        # ========== Step 2: 冲突检测 ==========
        app_logger.info("[Step 2/5] Detecting cross-document conflicts...")
        conflict_report = self.conflict_resolver.resolve_all_conflicts() if resolve_conflicts else {'total_conflicts_detected': 0}

        app_logger.info(
            f"[OK] Conflict detection: {conflict_report.get('total_conflicts_detected', 0)} conflicts found"
        )

        # ========== Step 3: 冲突解决 (可选) ==========
        if resolve_conflicts:
            app_logger.info("[Step 3/5] Resolving conflicts...")
            app_logger.info(
                f"[OK] Conflict resolution: {conflict_report.get('conflicts_resolved', 0)}/{conflict_report.get('total_conflicts_detected', 0)} resolved"
            )
        else:
            app_logger.info("[Step 3/5] Conflict resolution skipped (resolve_conflicts=False)")

        # ========== Step 4: 获取active规则（用于合并） ==========
        active_rules = self.db.query(Rule).filter(
        ).all()

        app_logger.info(f"[Step 4/5] Found {len(active_rules)} active rules for merging")

        # ========== Step 5: 有效规则合并 (可选) ==========
        effective_rules = []
        merge_report = {}

        if merge_effective and active_rules:
            app_logger.info("[Step 5/5] Merging effective rules...")
            effective_rules = self.effective_merger.merge_rules_by_field(active_rules)
            merge_report = self.effective_merger.get_effective_rules_report(effective_rules)

            app_logger.info(
                f"[OK] Effective rule merging: {merge_report['total_effective_rules']} effective rules "
                f"from {merge_report['total_source_rules']} source rules "
                f"(reduction: {merge_report['reduction_rate']*100:.1f}%)"
            )
        else:
            app_logger.info("[Step 5/5] Effective rule merging skipped")

        # ========== Step 6: 写入KG关系（如果有KG实例） ==========
        kg_relations_added = 0
        if self.kg:
            app_logger.info("[Step 6/6] Writing relationships to knowledge graph...")
            kg_relations_added = self._write_kg_relations(
                reference_report.get('resolution_details', []),
                conflict_report.get('resolution_details', []),
                effective_rules
            )
            app_logger.info(f"[OK] Added {kg_relations_added} relations to KG")

        # ========== 生成最终报告 ==========
        elapsed_time = (datetime.now() - start_time).total_seconds()

        final_report = {
            'status': 'completed',
            'elapsed_time_seconds': elapsed_time,

            # 输入
            'input_rules_count': len(rule_candidates),

            # 引用解析结果
            'references': {
                'total_found': reference_report.get('total_references_found', 0),
                'resolved': reference_report.get('references_resolved', 0),
                'resolution_rate': (
                    reference_report.get('references_resolved', 0) / reference_report.get('total_references_found', 1)
                    if reference_report.get('total_references_found', 0) > 0 else 0
                ),
                'details': reference_report.get('resolution_details', [])
            },

            # 冲突检测与解决结果
            'conflicts': {
                'total_detected': conflict_report.get('total_conflicts_detected', 0),
                'resolved': conflict_report.get('conflicts_resolved', 0),
                'resolution_rate': (
                    conflict_report.get('conflicts_resolved', 0) / conflict_report.get('total_conflicts_detected', 1)
                    if conflict_report.get('total_conflicts_detected', 0) > 0 else 0
                ),
                'details': conflict_report.get('resolution_details', [])
            },

            # 有效规则合并结果
            'effective_rules': {
                'enabled': merge_effective,
                'count': len(effective_rules),
                'source_count': merge_report.get('total_source_rules', len(active_rules)),
                'reduction_rate': merge_report.get('reduction_rate', 0),
                'merge_strategies': merge_report.get('merge_strategies', {}),
                'conflicts_resolved_during_merge': merge_report.get('total_conflicts_resolved', 0),
                'rules': effective_rules
            },

            # KG关系
            'kg_relations_added': kg_relations_added,

            # 时间戳
            'timestamp': datetime.now().isoformat()
        }

        app_logger.info(
            f"[RuleConflictAndReferenceEngine] Processing complete in {elapsed_time:.2f}s: "
            f"{len(effective_rules)} effective rules, "
            f"{reference_report.get('references_resolved', 0)} references resolved, "
            f"{conflict_report.get('conflicts_resolved', 0)} conflicts resolved"
        )

        return final_report

    def _write_kg_relations(
        self,
        reference_resolutions: List[Dict],
        conflict_resolutions: List[Dict],
        effective_rules: List[Dict]
    ) -> int:
        """
        将引用、冲突、覆盖关系写入知识图谱

        关系类型：
        - CITES: 规则引用关系
        - overrides: 规则覆盖关系（优先级）
        - conflicts_with: 规则冲突（未解决）
        - extends: 规则扩展关系（补充）

        Returns:
            添加的关系数量
        """
        if not self.kg:
            return 0

        relations_added = 0

        # 1. 写入引用关系 (CITES)
        for ref in reference_resolutions:
            if ref.get('resolved'):
                # 源规则 CITES 目标规则
                source_rule_id = ref['source_rule_id']
                for target_rule in ref.get('target_rules', []):
                    target_rule_id = target_rule['id']

                    try:
                        self.kg.add_edge(
                            f"rule_{source_rule_id}",
                            f"rule_{target_rule_id}",
                            relation_type="CITES",
                            properties={
                                'reference_text': ref['reference_text'],
                                'target_section': ref['target_section']
                            }
                        )
                        relations_added += 1
                    except Exception as e:
                        app_logger.warning(f"Failed to add CITES edge: {e}")

        # 2. 写入覆盖关系 (overrides)
        for conflict in conflict_resolutions:
            if conflict.get('resolution') == 'auto_resolved':
                winner = conflict.get('winner', {})
                loser = conflict.get('loser', {})

                winner_id = winner.get('rule_id')
                loser_id = loser.get('rule_id')

                if winner_id and loser_id:
                    try:
                        self.kg.add_edge(
                            f"rule_{winner_id}",
                            f"rule_{loser_id}",
                            relation_type="overrides",
                            properties={
                                'reason': conflict.get('reason', ''),
                                'conflict_type': conflict.get('conflict', {}).get('conflict_type', ''),
                                'field': conflict.get('conflict', {}).get('field', '')
                            }
                        )
                        relations_added += 1
                    except Exception as e:
                        app_logger.warning(f"Failed to add overrides edge: {e}")

        # 3. 写入未解决冲突关系 (conflicts_with)
        for conflict in conflict_resolutions:
            if conflict.get('resolution') == 'manual_review_required':
                conflict_detail = conflict.get('conflict', {})
                rule_a_id = conflict_detail.get('rule_a', {}).get('id') if hasattr(conflict_detail.get('rule_a'), 'id') else None
                rule_b_id = conflict_detail.get('rule_b', {}).get('id') if hasattr(conflict_detail.get('rule_b'), 'id') else None

                if rule_a_id and rule_b_id:
                    try:
                        # 双向冲突边
                        self.kg.add_edge(
                            f"rule_{rule_a_id}",
                            f"rule_{rule_b_id}",
                            relation_type="conflicts_with",
                            properties={
                                'conflict_type': conflict_detail.get('conflict_type', ''),
                                'reason': conflict_detail.get('reason', ''),
                                'field': conflict_detail.get('field', ''),
                                'requires_manual_review': True
                            }
                        )
                        relations_added += 1
                    except Exception as e:
                        app_logger.warning(f"Failed to add conflicts_with edge: {e}")

        # 4. 写入有效规则的合并关系 (merged_from)
        for effective in effective_rules:
            source_chain = effective.get('source_chain', [])
            if len(source_chain) > 1:
                # 有效规则是从多个源规则合并而来
                # 创建虚拟节点表示有效规则
                effective_id = f"effective_{effective.get('effective_rule', {}).get('affected_field', 'unknown')}"

                for source in source_chain:
                    source_rule_id = source.get('rule_id')
                    if source_rule_id:
                        try:
                            self.kg.add_edge(
                                effective_id,
                                f"rule_{source_rule_id}",
                                relation_type="merged_from",
                                properties={
                                    'merge_strategy': effective.get('merge_strategy', '')
                                }
                            )
                            relations_added += 1
                        except Exception as e:
                            app_logger.warning(f"Failed to add merged_from edge: {e}")

        return relations_added

    def get_rule_with_full_context(self, rule_id: int) -> Dict:
        """
        获取规则的完整上下文，包括：
        1. 规则本身
        2. 引用的规则
        3. 冲突的规则
        4. 覆盖/被覆盖的规则
        5. 有效规则（如果是源规则）

        Args:
            rule_id: 规则ID

        Returns:
            完整上下文信息
        """
        rule = self.db.query(Rule).filter(Rule.id == rule_id).first()
        if not rule:
            return {'error': 'Rule not found'}

        # 1. 基础信息
        context = {
            'rule': {
                'id': rule.id,
                'standard': rule.standard.title,
                'section': rule.section,
                'text': rule.text,
                'affected_field': rule.subject,
                'operation': rule.predicate,
                'expected_value': rule.constraint_value,
                }
        }

        # 2. 引用的规则
        referenced_rules_data = self.reference_resolver.get_rule_with_references(rule_id)
        context['references'] = referenced_rules_data.get('references', [])
        context['referenced_rules'] = referenced_rules_data.get('referenced_rules', [])

        # 3. 冲突信息（从ir_data中获取）
        if rule.ir_data:
            import json
            try:
                metadata = json.loads(rule.ir_data)
                context['conflicts'] = metadata.get('conflicts', [])
                context['supersedes_rules'] = metadata.get('supersedes_rules', [])
            except json.JSONDecodeError:
                pass

        # 被覆盖信息已删除（status字段不再使用）

        return context

    def detect_circular_references(self) -> List[Dict]:
        """
        检测循环引用

        Returns:
            循环引用链列表
        """
        return self.reference_resolver.detect_circular_references()

    def get_conflict_report(self) -> Dict:
        """
        获取冲突报告

        Returns:
            冲突统计和详情
        """
        return self.conflict_resolver.get_conflict_report()
