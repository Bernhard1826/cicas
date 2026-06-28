"""
跨文档冲突解决器
处理多个标准文档之间的规则冲突，基于文档优先级和时效性
"""
from typing import List, Dict, Tuple, Optional
from datetime import datetime
from sqlalchemy.orm import Session

from app.models.models import Standard, Rule, StandardRelationship
from app.core.logging_config import app_logger


class ConflictResolver:
    """
    冲突解决器

    功能：
    1. 检测跨文档规则冲突
    2. 基于文档优先级解决冲突
    3. 标记被覆盖的规则
    4. 生成冲突解决报告
    """

    # 文档优先级（数字越大优先级越高）
    DOCUMENT_PRIORITY = {
        'CABF': 100,              # CA/Browser Forum Baseline Requirements（行业最高优先级，TLS证书强制标准）
        'BROWSER_ROOT': 95,       # Browser Root Program (Mozilla/Chrome/Apple)（浏览器厂商根证书要求）
        'ETSI': 90,               # ETSI 标准（欧洲标准，eIDAS合规）
        'EV_GUIDELINES': 85,      # EV Guidelines（扩展验证，CABF的细分标准）
        'RFC': 80,                # IETF RFC（基础协议标准）
        'NIST': 70,               # NIST 标准（美国政府标准）
        'ISO': 60,                # ISO 标准（国际标准）
        'CA_CPS': 40,             # CA Certification Practice Statement（CA实施细则，只能收紧不能放松基础要求）
        'DEFAULT': 30             # 其他未分类标准
    }

    # 关系类型的冲突解决规则
    RELATIONSHIP_OVERRIDE_RULES = {
        'obsoletes': 'newer_obsoletes_older',    # 新版本废弃旧版本
        'updates': 'newer_updates_older',        # 新版本更新旧版本
        'supplements': 'supplement_extends_base', # 补充性文档扩展基础文档（不覆盖）
        'depends_on': 'no_override',             # 依赖关系不产生覆盖
        'version_of': 'newer_version_overrides'  # 新版本覆盖旧版本
    }

    def __init__(self, db: Session, kg=None):
        self.db = db
        self.kg = kg  # Knowledge Graph instance (可选)

    def resolve_all_conflicts(self) -> Dict:
        """
        解决所有文档间冲突

        Returns:
            冲突解决报告
        """
        app_logger.info("[ConflictResolver] Starting cross-document conflict resolution")

        # 1. 获取所有活跃规则
        all_rules = self.db.query(Rule).filter(
        ).all()

        # 2. 按字段分组规则
        field_rules_map = self._group_rules_by_field(all_rules)

        # 3. 对每个字段检测冲突并解决
        conflicts_resolved = 0
        conflicts_detected = 0
        resolution_details = []

        for field, rules in field_rules_map.items():
            if len(rules) < 2:
                continue  # 单个规则无冲突

            # 检测此字段的冲突
            conflicts = self._detect_field_conflicts(field, rules)

            if conflicts:
                conflicts_detected += len(conflicts)
                app_logger.info(f"[ConflictResolver] Found {len(conflicts)} conflicts for field: {field}")

                # 解决冲突
                for conflict in conflicts:
                    resolution = self._resolve_conflict(conflict)
                    if resolution:
                        conflicts_resolved += 1
                        resolution_details.append(resolution)

        app_logger.info(
            f"[ConflictResolver] Resolved {conflicts_resolved}/{conflicts_detected} conflicts"
        )

        return {
            'total_conflicts_detected': conflicts_detected,
            'conflicts_resolved': conflicts_resolved,
            'resolution_details': resolution_details
        }

    def _group_rules_by_field(self, rules: List[Rule]) -> Dict[str, List[Rule]]:
        """按affected_field分组规则"""
        field_map = {}
        for rule in rules:
            if not rule.subject:
                continue

            field = rule.subject
            if field not in field_map:
                field_map[field] = []

            field_map[field].append(rule)

        return field_map

    def _detect_field_conflicts(self, field: str, rules: List[Rule]) -> List[Dict]:
        """
        检测同一字段的跨文档规则冲突

        注意：只检测不同标准文档之间的冲突，同一文档内的规则不检测冲突
        （因为同一文档内的"冲突"通常是针对不同场景/证书类型的正常业务规则）

        Returns:
            冲突列表，每个冲突包含 rule_a, rule_b, conflict_type, reason
        """
        conflicts = []

        for i, rule_a in enumerate(rules):
            for rule_b in rules[i + 1:]:
                # 【关键修复】只检测跨文档冲突，跳过同一文档内的规则比较
                if rule_a.standard_id == rule_b.standard_id:
                    continue

                conflict_type, reason = self._check_conflict(rule_a, rule_b)

                if conflict_type:
                    conflicts.append({
                        'rule_a': rule_a,
                        'rule_b': rule_b,
                        'field': field,
                        'conflict_type': conflict_type,
                        'reason': reason
                    })

        return conflicts

    def _check_conflict(self, rule_a: Rule, rule_b: Rule) -> Tuple[Optional[str], Optional[str]]:
        """
        检查两条规则是否冲突

        Returns:
            (conflict_type, reason) 或 (None, None)
        """
        op_a = rule_a.operation
        op_b = rule_b.operation

        # 冲突类型1: 存在性冲突
        if {op_a, op_b} == {'must_be_present', 'must_not_be_present'}:
            return 'presence_conflict', f"One requires {rule_a.affected_field}, other prohibits it"

        # 冲突类型2: Critical标记冲突
        if {op_a, op_b} == {'must_be_critical', 'must_not_be_critical'}:
            return 'critical_conflict', f"{rule_a.affected_field} critical flag conflict"

        # 冲突类型3: 数值范围冲突
        if op_a in ['minimum', 'maximum'] and op_b in ['minimum', 'maximum']:
            val_a = self._parse_numeric_value(rule_a.expected_value)
            val_b = self._parse_numeric_value(rule_b.expected_value)

            if val_a is not None and val_b is not None:
                if op_a == 'minimum' and op_b == 'maximum' and val_a > val_b:
                    return 'range_conflict', f"Minimum ({val_a}) > Maximum ({val_b})"
                if op_a == 'maximum' and op_b == 'minimum' and val_a < val_b:
                    return 'range_conflict', f"Maximum ({val_a}) < Minimum ({val_b})"

        # 冲突类型4: 值约束冲突（相同操作，不同值）
        if op_a == op_b and op_a in ['must_equal', 'must_contain']:
            if rule_a.expected_value and rule_b.expected_value:
                if rule_a.expected_value != rule_b.expected_value:
                    return 'value_conflict', f"Different values required: '{rule_a.expected_value}' vs '{rule_b.expected_value}'"

        return None, None

    def _resolve_conflict(self, conflict: Dict) -> Optional[Dict]:
        """
        解决单个冲突

        策略：
        1. 检查文档间关系（如 obsoletes, updates）
        2. 比较文档优先级
        3. 比较发布日期
        4. 标记被覆盖的规则

        Returns:
            解决方案详情
        """
        rule_a = conflict['rule_a']
        rule_b = conflict['rule_b']

        # 获取标准信息
        std_a = rule_a.standard
        std_b = rule_b.standard

        if not std_a or not std_b:
            app_logger.warning(f"Cannot resolve conflict: missing standard info")
            return None

        # 策略1: 检查文档间显式关系
        relationship = self._get_relationship(std_a, std_b)
        if relationship:
            winner, reason = self._apply_relationship_override(
                rule_a, rule_b, std_a, std_b, relationship
            )
            if winner:
                return self._apply_resolution(conflict, winner, reason)

        # 策略2: 比较文档优先级
        priority_a = self.DOCUMENT_PRIORITY.get(std_a.source, self.DOCUMENT_PRIORITY['DEFAULT'])
        priority_b = self.DOCUMENT_PRIORITY.get(std_b.source, self.DOCUMENT_PRIORITY['DEFAULT'])

        if priority_a != priority_b:
            winner = rule_a if priority_a > priority_b else rule_b
            loser_std = std_b.title if priority_a > priority_b else std_a.title
            winner_std = std_a.title if priority_a > priority_b else std_b.title
            reason = f"Document priority: {winner_std} ({winner.standard.source}) > {loser_std}"
            return self._apply_resolution(conflict, winner, reason)

        # 策略3: 比较发布日期（新的覆盖旧的）
        if std_a.publish_date and std_b.publish_date:
            if std_a.publish_date > std_b.publish_date:
                reason = f"Newer standard: {std_a.title} ({std_a.publish_date}) > {std_b.title} ({std_b.publish_date})"
                return self._apply_resolution(conflict, rule_a, reason)
            elif std_b.publish_date > std_a.publish_date:
                reason = f"Newer standard: {std_b.title} ({std_b.publish_date}) > {std_a.title} ({std_a.publish_date})"
                return self._apply_resolution(conflict, rule_b, reason)

        # 策略4: 无法自动解决，标记为需要人工审核
        app_logger.warning(
            f"Cannot auto-resolve conflict between {std_a.title} and {std_b.title} "
            f"for field {conflict['field']} - marking for manual review"
        )

        # 标记拒绝原因
        rule_a.rejection_reason = f"Conflict with {std_b.title}: {conflict['reason']}"
        rule_b.rejection_reason = f"Conflict with {std_a.title}: {conflict['reason']}"

        self.db.commit()

        return {
            'conflict': conflict,
            'resolution': 'manual_review_required',
            'reason': 'Unable to auto-resolve: equal priority and no date info'
        }

    def _get_relationship(self, std_a: Standard, std_b: Standard) -> Optional[StandardRelationship]:
        """获取两个标准之间的关系"""
        # 检查双向关系
        rel = self.db.query(StandardRelationship).filter(
            ((StandardRelationship.source_standard_id == std_a.id) &
             (StandardRelationship.target_standard_id == std_b.id)) |
            ((StandardRelationship.source_standard_id == std_b.id) &
             (StandardRelationship.target_standard_id == std_a.id)),
            StandardRelationship.is_active == True
        ).first()

        return rel

    def _apply_relationship_override(
        self,
        rule_a: Rule,
        rule_b: Rule,
        std_a: Standard,
        std_b: Standard,
        relationship: StandardRelationship
    ) -> Tuple[Optional[Rule], Optional[str]]:
        """
        基于文档关系应用覆盖规则

        Returns:
            (winning_rule, reason)
        """
        rel_type = relationship.relationship_type
        override_rule = self.RELATIONSHIP_OVERRIDE_RULES.get(rel_type)

        if not override_rule:
            return None, None

        # 确定方向
        is_a_to_b = (relationship.source_standard_id == std_a.id)

        if override_rule == 'newer_obsoletes_older':
            # 新版本废弃旧版本 - 新版本胜出
            winner = rule_a if is_a_to_b else rule_b
            loser_title = std_b.title if is_a_to_b else std_a.title
            return winner, f"Document relationship: {std_a.title if is_a_to_b else std_b.title} obsoletes {loser_title}"

        elif override_rule == 'newer_updates_older':
            # 新版本更新旧版本 - 新版本胜出
            winner = rule_a if is_a_to_b else rule_b
            loser_title = std_b.title if is_a_to_b else std_a.title
            return winner, f"Document relationship: {std_a.title if is_a_to_b else std_b.title} updates {loser_title}"

        elif override_rule == 'supplement_extends_base':
            # 补充性文档扩展基础文档 - 两者都保留（不产生覆盖）
            return None, "Supplement relationship: both rules preserved"

        elif override_rule == 'newer_version_overrides':
            # 新版本覆盖旧版本
            winner = rule_a if is_a_to_b else rule_b
            loser_title = std_b.title if is_a_to_b else std_a.title
            return winner, f"Version relationship: newer version overrides {loser_title}"

        return None, None

    def _apply_resolution(self, conflict: Dict, winner: Rule, reason: str) -> Dict:
        """
        应用冲突解决方案

        将失败的规则标记为 rejected 或 superseded
        """
        loser = conflict['rule_b'] if winner == conflict['rule_a'] else conflict['rule_a']

        # 标记失败规则
        loser.status = 'superseded'  # 新状态：被更高优先级文档覆盖
        loser.rejection_reason = f"Superseded by {winner.standard.title}: {reason}"

        # 在胜出规则中记录覆盖信息
        if not winner.ir_data:
            winner.ir_data = '{}'

        import json
        metadata = json.loads(winner.ir_data) if winner.ir_data else {}
        if 'supersedes_rules' not in metadata:
            metadata['supersedes_rules'] = []

        metadata['supersedes_rules'].append({
            'rule_id': loser.id,
            'standard': loser.standard.title,
            'reason': reason,
            'timestamp': datetime.now().isoformat()
        })

        winner.ir_data = json.dumps(metadata, ensure_ascii=False)

        self.db.commit()

        app_logger.info(
            f"[ConflictResolver] Resolved conflict: {winner.standard.title} rule "
            f"supersedes {loser.standard.title} rule for field {conflict['field']}"
        )

        return {
            'conflict': conflict,
            'resolution': 'auto_resolved',
            'winner': {
                'rule_id': winner.id,
                'standard': winner.standard.title,
                'text': winner.text[:100]
            },
            'loser': {
                'rule_id': loser.id,
                'standard': loser.standard.title,
                'text': loser.text[:100]
            },
            'reason': reason
        }

    def _parse_numeric_value(self, value_str: Optional[str]) -> Optional[float]:
        """从值字符串中解析数值"""
        if not value_str:
            return None

        import re
        match = re.search(r'(\d+(?:\.\d+)?)', str(value_str))
        if match:
            return float(match.group(1))

        return None

    def get_conflict_report(self) -> Dict:
        """
        生成冲突报告

        Returns:
            包含所有冲突和解决状态的报告
        """
        # 查询所有被覆盖的规则
        superseded_rules = self.db.query(Rule).filter(
        ).all()

        # 查询所有需要人工审核的冲突（有冲突原因但未被标记为superseded）
        manual_review_rules = self.db.query(Rule).filter(
            Rule.rejection_reason.like('%Conflict with%'),
            Rule.status != 'superseded'
        ).all()

        report = {
            'superseded_rules_count': len(superseded_rules),
            'manual_review_required_count': len(manual_review_rules),
            'superseded_rules': [
                {
                    'id': rule.id,
                    'standard': rule.standard.title,
                    'field': rule.subject,
                    'text': rule.text[:100],
                    'superseded_by': rule.rejection_reason
                }
                for rule in superseded_rules
            ],
            'manual_review_required': [
                {
                    'id': rule.id,
                    'standard': rule.standard.title,
                    'field': rule.subject,
                    'text': rule.text[:100],
                    'conflict_description': rule.rejection_reason
                }
                for rule in manual_review_rules
            ]
        }

        return report
