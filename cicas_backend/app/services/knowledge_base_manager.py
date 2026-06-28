"""
Knowledge Base 管理系统

功能：
1. 接收和管理KB候选提案
2. 自动决策（auto_apply / manual_review）
3. KB条目的CRUD操作
4. 版本控制和回滚
"""
import json
import hashlib
from typing import Dict, List, Any, Optional
from datetime import datetime
from sqlalchemy.orm import Session
from sqlalchemy import func, desc

from app.core.logging_config import app_logger
from app.models.models import KnowledgeBaseEntry, KBCandidateProposal


class KnowledgeBaseManager:
    """
    知识库管理器

    负责管理整个知识库的生命周期：
    - 候选提案处理
    - 自动应用低风险更新
    - 人工审核高风险更新
    - 版本控制
    """

    # 自动应用的阈值
    AUTO_APPLY_THRESHOLDS = {
        'min_support_count': 8,
        'min_avg_score': 85.0,
        'min_p_value_threshold': 0.01,  # p < 0.01
        'min_effect_size': 0.25
    }

    def __init__(self, db: Session):
        self.db = db

    def process_kb_candidate(
        self,
        candidate: Dict[str, Any],
        generation_round: Optional[int] = None
    ) -> Dict[str, Any]:
        """
        处理单个KB候选提案

        Args:
            candidate: {pattern, mapping, support_count, avg_score, examples}
            generation_round: 生成该候选的演化轮次

        Returns:
            {
                'proposal_id': int,
                'decision': 'auto_apply' | 'manual_review' | 'rejected',
                'reason': str,
                'kb_entry_id': int or None
            }
        """
        app_logger.info(f"Processing KB candidate: {candidate.get('pattern', '')[:50]}...")

        # 1. 保存候选提案
        proposal = self._save_candidate_proposal(candidate, generation_round)

        # 2. 进行风险评估
        risk_assessment = self._assess_risk(candidate)

        # 3. 统计显著性检验（需要Meta-Learner实现，这里简化处理）
        statistical_test = self._statistical_test(candidate)

        # 4. 做出决策
        decision, reason = self._make_decision(candidate, risk_assessment, statistical_test)

        # 5. 更新提案记录
        proposal.decision = decision
        proposal.decision_reason = reason
        proposal.p_value = statistical_test.get('p_value')
        proposal.effect_size = statistical_test.get('effect_size')
        proposal.statistical_test_passed = statistical_test.get('passed', False)
        proposal.risk_level = risk_assessment['risk_level']

        # 6. 如果决定自动应用，则创建KB条目
        kb_entry_id = None
        if decision == 'auto_apply':
            kb_entry_id = self._apply_to_kb(candidate, proposal)
            proposal.applied_to_kb_id = kb_entry_id
            proposal.is_processed = True
            proposal.processed_at = datetime.now()

        self.db.commit()

        app_logger.info(f"KB candidate processed: decision={decision}, proposal_id={proposal.id}")

        return {
            'proposal_id': proposal.id,
            'decision': decision,
            'reason': reason,
            'kb_entry_id': kb_entry_id,
            'risk_level': risk_assessment['risk_level'],
            'statistical_test': statistical_test
        }

    def _save_candidate_proposal(
        self,
        candidate: Dict[str, Any],
        generation_round: Optional[int]
    ) -> KBCandidateProposal:
        """保存候选提案到数据库"""
        mapping_json = json.dumps(candidate.get('mapping', {}), ensure_ascii=False)
        examples_json = json.dumps(candidate.get('examples', []), ensure_ascii=False)

        proposal = KBCandidateProposal(
            pattern=candidate.get('pattern', ''),
            mapping=mapping_json,
            support_count=candidate.get('support_count', 0),
            avg_score=candidate.get('avg_score'),
            examples=examples_json,
            generated_by='challenger',
            generation_round=generation_round
        )

        self.db.add(proposal)
        self.db.flush()  # 获取ID但不提交

        return proposal

    def _assess_risk(self, candidate: Dict[str, Any]) -> Dict[str, Any]:
        """
        评估候选提案的风险等级

        Returns:
            {
                'risk_level': 'low' | 'medium' | 'high',
                'risk_factors': [...],
                'mitigation': str
            }
        """
        risk_factors = []
        support_count = candidate.get('support_count', 0)
        avg_score = candidate.get('avg_score', 0)

        # 风险因素1: 支持数量太少
        if support_count < 5:
            risk_factors.append(f"Low support count ({support_count} < 5)")

        # 风险因素2: 平均分太低
        if avg_score < 80:
            risk_factors.append(f"Low average score ({avg_score} < 80)")

        # 风险因素3: 模式过于通用
        pattern = candidate.get('pattern', '')
        if len(pattern) < 30:
            risk_factors.append("Pattern too generic (< 30 chars)")

        # 判断风险等级
        if len(risk_factors) == 0:
            risk_level = 'low'
        elif len(risk_factors) <= 1:
            risk_level = 'medium'
        else:
            risk_level = 'high'

        return {
            'risk_level': risk_level,
            'risk_factors': risk_factors,
            'mitigation': 'Require manual review' if risk_level == 'high' else 'Auto-apply safe'
        }

    def _statistical_test(self, candidate: Dict[str, Any]) -> Dict[str, Any]:
        """
        统计显著性检验

        简化实现：基于支持数量和平均分
        真实实现应该使用 scipy.stats 进行 t-test 或其他检验
        """
        support_count = candidate.get('support_count', 0)
        avg_score = candidate.get('avg_score', 0)

        # 简化的p值计算（真实应该使用统计检验）
        # 这里用启发式方法：支持数越多、分数越高，p值越小
        if support_count >= 10 and avg_score >= 90:
            p_value = 0.001
            effect_size = 0.8  # large effect
        elif support_count >= 8 and avg_score >= 85:
            p_value = 0.008
            effect_size = 0.5  # medium effect
        elif support_count >= 5 and avg_score >= 80:
            p_value = 0.03
            effect_size = 0.3  # small effect
        else:
            p_value = 0.15
            effect_size = 0.1  # very small effect

        passed = (
            p_value < self.AUTO_APPLY_THRESHOLDS['min_p_value_threshold'] and
            effect_size >= self.AUTO_APPLY_THRESHOLDS['min_effect_size'] and
            support_count >= self.AUTO_APPLY_THRESHOLDS['min_support_count']
        )

        return {
            'p_value': p_value,
            'effect_size': effect_size,
            'passed': passed,
            'method': 'heuristic_simplification'  # 标记为简化实现
        }

    def _make_decision(
        self,
        candidate: Dict[str, Any],
        risk_assessment: Dict[str, Any],
        statistical_test: Dict[str, Any]
    ) -> tuple[str, str]:
        """
        做出决策：auto_apply、manual_review 或 rejected

        决策逻辑：
        1. 统计检验未通过 -> rejected
        2. 高风险 -> manual_review
        3. 低/中风险 + 统计检验通过 -> auto_apply
        """
        # 规则1: 统计检验未通过 -> 拒绝
        if not statistical_test.get('passed', False):
            return 'rejected', f"Statistical test failed: p={statistical_test.get('p_value'):.3f}, effect_size={statistical_test.get('effect_size'):.3f}"

        # 规则2: 高风险 -> 人工审核
        if risk_assessment['risk_level'] == 'high':
            factors = ', '.join(risk_assessment['risk_factors'])
            return 'manual_review', f"High risk: {factors}"

        # 规则3: 中等风险但边界情况 -> 人工审核
        support_count = candidate.get('support_count', 0)
        avg_score = candidate.get('avg_score', 0)

        if risk_assessment['risk_level'] == 'medium':
            if support_count < 10 or avg_score < 88:
                return 'manual_review', f"Medium risk with borderline metrics (support={support_count}, avg_score={avg_score:.1f})"

        # 规则4: 低风险 + 统计显著 -> 自动应用
        return 'auto_apply', f"Low risk with strong statistical support (p={statistical_test.get('p_value'):.3f}, support={support_count})"

    def _apply_to_kb(
        self,
        candidate: Dict[str, Any],
        proposal: KBCandidateProposal
    ) -> int:
        """
        将候选应用到知识库

        创建一个新的 KnowledgeBaseEntry
        """
        pattern = candidate.get('pattern', '')
        pattern_hash = hashlib.sha256(pattern.encode()).hexdigest()

        mapping = candidate.get('mapping', {})
        entry_type = self._determine_entry_type(mapping)

        kb_entry = KnowledgeBaseEntry(
            entry_type=entry_type,
            pattern=pattern,
            pattern_hash=pattern_hash,
            operation=mapping.get('operation'),
            affected_field_hint=mapping.get('affected_field_hint'),
            support_count=candidate.get('support_count', 0),
            avg_score=candidate.get('avg_score'),
            status='active',
            confidence=self._calculate_confidence(candidate, proposal),
            examples=json.dumps(candidate.get('examples', []), ensure_ascii=False),
            p_value=proposal.p_value,
            effect_size=proposal.effect_size,
            created_by='meta_learner',
            approval_note=f'Auto-applied from proposal_id={proposal.id}',
            version=1
        )

        self.db.add(kb_entry)
        self.db.flush()

        app_logger.info(f"Applied KB candidate to knowledge base: entry_id={kb_entry.id}")
        return kb_entry.id

    def _determine_entry_type(self, mapping: Dict[str, Any]) -> str:
        """判断KB条目类型"""
        if mapping.get('affected_field_hint'):
            return 'field_mapping'
        elif mapping.get('operation'):
            return 'operation_mapping'
        else:
            return 'field_mapping'  # 默认

    def _calculate_confidence(
        self,
        candidate: Dict[str, Any],
        proposal: KBCandidateProposal
    ) -> float:
        """
        计算KB条目的置信度

        基于：
        - 支持数量
        - 平均分
        - 统计显著性
        """
        support_count = candidate.get('support_count', 0)
        avg_score = candidate.get('avg_score', 0)
        effect_size = proposal.effect_size or 0

        # 归一化支持数量（最多20个作为满分）
        support_factor = min(support_count / 20.0, 1.0)

        # 归一化平均分（0-100 -> 0-1）
        score_factor = avg_score / 100.0

        # 效应量（0-1，0.8以上为1）
        effect_factor = min(effect_size / 0.8, 1.0)

        # 综合置信度
        confidence = 0.4 * support_factor + 0.4 * score_factor + 0.2 * effect_factor

        return round(confidence, 3)

    def get_active_kb_entries(
        self,
        entry_type: Optional[str] = None,
        min_confidence: float = 0.0
    ) -> List[KnowledgeBaseEntry]:
        """
        获取激活的KB条目

        Args:
            entry_type: 条目类型过滤
            min_confidence: 最小置信度

        Returns:
            KB条目列表
        """
        query = self.db.query(KnowledgeBaseEntry).filter(
            KnowledgeBaseEntry.status == 'active',
            KnowledgeBaseEntry.confidence >= min_confidence
        )

        if entry_type:
            query = query.filter(KnowledgeBaseEntry.entry_type == entry_type)

        return query.order_by(desc(KnowledgeBaseEntry.confidence)).all()

    def rollback_kb_entry(self, entry_id: int, reason: str) -> bool:
        """
        回滚KB条目（标记为rejected）

        Args:
            entry_id: KB条目ID
            reason: 回滚原因

        Returns:
            是否成功
        """
        try:
            entry = self.db.query(KnowledgeBaseEntry).filter(
                KnowledgeBaseEntry.id == entry_id
            ).first()

            if not entry:
                app_logger.warning(f"KB entry {entry_id} not found")
                return False

            entry.status = 'rejected'
            entry.approval_note = f"Rolled back: {reason}"
            self.db.commit()

            app_logger.info(f"Rolled back KB entry {entry_id}: {reason}")
            return True

        except Exception as e:
            app_logger.error(f"Failed to rollback KB entry {entry_id}: {e}")
            self.db.rollback()
            return False

    def update_kb_entry_stats(self, entry_id: int, new_support_count: int, new_avg_score: float) -> bool:
        """
        更新KB条目的统计信息

        用于定期更新KB条目的支持数量和平均分
        """
        try:
            entry = self.db.query(KnowledgeBaseEntry).filter(
                KnowledgeBaseEntry.id == entry_id
            ).first()

            if not entry:
                return False

            entry.support_count = new_support_count
            entry.avg_score = new_avg_score

            # 重新计算置信度
            candidate = {
                'support_count': new_support_count,
                'avg_score': new_avg_score
            }
            proposal = KBCandidateProposal(
                effect_size=entry.effect_size
            )
            entry.confidence = self._calculate_confidence(candidate, proposal)

            self.db.commit()
            app_logger.info(f"Updated KB entry {entry_id} stats")
            return True

        except Exception as e:
            app_logger.error(f"Failed to update KB entry stats: {e}")
            self.db.rollback()
            return False

    def get_pending_proposals(self, decision: str = 'manual_review') -> List[KBCandidateProposal]:
        """
        获取待处理的提案

        Args:
            decision: 提案决策类型

        Returns:
            提案列表
        """
        return self.db.query(KBCandidateProposal).filter(
            KBCandidateProposal.decision == decision,
            KBCandidateProposal.is_processed == False
        ).order_by(desc(KBCandidateProposal.support_count)).all()

    def manually_approve_proposal(self, proposal_id: int, approval_note: str) -> Dict[str, Any]:
        """
        人工审批提案

        Args:
            proposal_id: 提案ID
            approval_note: 审批说明

        Returns:
            {success: bool, kb_entry_id: int or None}
        """
        try:
            proposal = self.db.query(KBCandidateProposal).filter(
                KBCandidateProposal.id == proposal_id
            ).first()

            if not proposal:
                return {'success': False, 'error': 'Proposal not found'}

            # 重构candidate
            candidate = {
                'pattern': proposal.pattern,
                'mapping': json.loads(proposal.mapping),
                'support_count': proposal.support_count,
                'avg_score': proposal.avg_score,
                'examples': json.loads(proposal.examples) if proposal.examples else []
            }

            # 应用到KB
            kb_entry_id = self._apply_to_kb(candidate, proposal)

            # 更新KB条目的审批说明
            kb_entry = self.db.query(KnowledgeBaseEntry).get(kb_entry_id)
            if kb_entry:
                kb_entry.approval_note = f"Manually approved: {approval_note}"
                kb_entry.created_by = 'manual'

            # 更新提案
            proposal.decision = 'auto_apply'  # 人工批准后标记为已应用
            proposal.is_processed = True
            proposal.processed_at = datetime.now()
            proposal.applied_to_kb_id = kb_entry_id

            self.db.commit()

            app_logger.info(f"Manually approved proposal {proposal_id}, created KB entry {kb_entry_id}")
            return {'success': True, 'kb_entry_id': kb_entry_id}

        except Exception as e:
            app_logger.error(f"Failed to manually approve proposal: {e}")
            self.db.rollback()
            return {'success': False, 'error': str(e)}

    def reject_proposal(self, proposal_id: int, reason: str) -> bool:
        """
        拒绝提案

        Args:
            proposal_id: 提案ID
            reason: 拒绝原因

        Returns:
            是否成功
        """
        try:
            proposal = self.db.query(KBCandidateProposal).filter(
                KBCandidateProposal.id == proposal_id
            ).first()

            if not proposal:
                return False

            proposal.decision = 'rejected'
            proposal.decision_reason = reason
            proposal.is_processed = True
            proposal.processed_at = datetime.now()

            self.db.commit()

            app_logger.info(f"Rejected proposal {proposal_id}: {reason}")
            return True

        except Exception as e:
            app_logger.error(f"Failed to reject proposal: {e}")
            self.db.rollback()
            return False
