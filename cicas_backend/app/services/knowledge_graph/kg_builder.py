"""
知识图谱构建器
从数据库中的规则和标准构建知识图谱
"""
from typing import Dict, Any, List, Optional
from sqlalchemy.orm import Session
from app.models.models import Standard, Rule, ExceptionRule  # ⭐ 新增：导入ExceptionRule
from app.services.knowledge_graph.knowledge_graph import CertificateKnowledgeGraph
from app.services.embeddings.hybrid_embedding_generator import HybridEmbeddingGenerator
from app.services.knowledge_graph.logical_conflict_detector import LogicalConflictDetector
from app.services.knowledge_graph.reference_detector import ReferenceDetector
from app.core.logging_config import app_logger
import numpy as np
import json  # ⭐ 新增：用于解析JSON字段


class KnowledgeGraphBuilder:
    """
    从数据库构建知识图谱
    """

    def __init__(self, db: Session):
        self.db = db
        self.kg = CertificateKnowledgeGraph()

        # Embedding generator 设为可选（只在需要语义相似度计算时使用）
        try:
            self.embedding_generator = HybridEmbeddingGenerator()
            self.has_embedding = True
            app_logger.info("Embedding generator initialized for KG builder")
        except Exception as e:
            self.embedding_generator = None
            self.has_embedding = False
            app_logger.warning(f"Embedding generator not available, semantic similarity features disabled: {e}")

    def build_from_database(self, semantic_similarity_threshold: float = 0.75) -> CertificateKnowledgeGraph:
        """
        从数据库构建知识图谱（例外感知）

        Args:
            semantic_similarity_threshold: 语义相似度阈值，用于建立规则之间的关联

        Returns:
            构建好的知识图谱
        """
        app_logger.info("Starting knowledge graph construction from database...")

        # 1. 添加标准节点
        standards = self.db.query(Standard).all()
        app_logger.info(f"Loading {len(standards)} standards...")

        for standard in standards:
            self._add_standard_to_kg(standard)

        # 2. 添加规则节点并建立关系
        rules = self.db.query(Rule).all()
        app_logger.info(f"Loading {len(rules)} rules...")

        rule_embeddings = {}  # 存储规则嵌入向量用于后续相似度计算

        for rule in rules:
            self._add_rule_to_kg(rule)

            # 使用embedding generator生成embedding（如果需要语义关系）
            # 注意: 不再依赖rule.embedding字段

        # ⭐ 2.5 添加例外规则节点并建立关系
        exception_rules = self.db.query(ExceptionRule).all()
        app_logger.info(f"Loading {len(exception_rules)} exception rules...")

        for exception_rule in exception_rules:
            self._add_exception_rule_to_kg(exception_rule)

        # 3. 建立规则之间的语义关联（使用text相似度代替embedding）
        app_logger.info("Building semantic relationships between rules...")
        self._build_semantic_relationships(rule_embeddings, semantic_similarity_threshold)

        # 4. 解析跨文档引用（使用新的 ReferenceDetector）
        app_logger.info("Resolving cross-document references...")
        standards_dict = {s.id: s for s in standards}
        reference_detector = ReferenceDetector(self.db, self.kg)
        reference_detector.detect_references(rules, standards_dict)

        # 5. 推断冲突关系（使用逻辑冲突检测器）
        app_logger.info("Inferring conflict relationships...")
        conflict_detector = LogicalConflictDetector(self.db, self.kg)
        conflict_detector.detect_conflicts(rules, standards_dict)

        stats = self.kg.get_statistics()
        app_logger.info(f"Knowledge graph constructed: {stats['total_nodes']} nodes, {stats['total_edges']} edges")
        app_logger.info(f"Node types: {stats['node_types']}")
        app_logger.info(f"Edge types: {stats['edge_types']}")

        return self.kg

    def _add_standard_to_kg(self, standard: Standard) -> None:
        """添加标准到知识图谱（与 kg_corpus_bridge 的 Specification 节点共享 ID 前缀与类型）"""
        node_id = f'spec:{standard.id}'

        properties = {
            'standard_id': standard.id,
            'source': standard.source,
            'title': standard.title,
            'version': standard.version,
            'url': standard.url
        }

        self.kg.add_node(node_id, 'Specification', properties)

    def _add_rule_to_kg(self, rule: Rule) -> None:
        """添加规则到知识图谱并建立关系"""
        rule_id = f'rule:{rule.id}'

        properties = {
            'rule_id': rule.id,
            'text': rule.text,
            'section': rule.section,
            'rule_type': rule.rule_type,
            'affected_field': rule.subject,
            'operation': rule.predicate,
            'expected_value': rule.constraint_value,
            'severity': rule.severity
        }

        self.kg.add_node(rule_id, 'Rule', properties)

        # 关系1: Specification -> Rule (CONTAINS)
        # 注：之前用 DEFINES，与 Section->Definition 的 DEFINES 语义重载，已统一为 CONTAINS
        spec_id = f'spec:{rule.standard_id}'
        if spec_id in self.kg.graph:
            self.kg.add_edge(
                spec_id,
                rule_id,
                'CONTAINS',
                {'description': '规范包含规则', 'section': rule.section}
            )

        # 关系2: Rule -> CertificateField (AFFECTS)
        if rule.subject:
            field_id = f'field:{rule.subject}'
            # 如果字段不存在，创建它
            if field_id not in self.kg.graph:
                self.kg.add_node(field_id, 'CertificateField', {
                    'name': rule.subject,
                    'description': f'Certificate field: {rule.subject}'
                })

            self.kg.add_edge(
                rule_id,
                field_id,
                'AFFECTS',
                {'description': '规则影响字段'}
            )

        # 关系3: Rule -> Operation (REQUIRES_OPERATION)
        # 之前若 op_id 不在预注册枚举中会静默丢边；现改为动态创建并告警，避免数据丢失
        if rule.predicate:
            op_id = f'op:{rule.predicate}'
            if op_id not in self.kg.graph:
                self.kg.add_node(op_id, 'Operation', {
                    'name': rule.predicate,
                    'description': f'Auto-registered operation: {rule.predicate}',
                    'auto_registered': True,
                })
                app_logger.warning(
                    f"Operation '{rule.predicate}' 不在预注册枚举中，已自动建节点 (rule={rule.id})"
                )
            self.kg.add_edge(
                rule_id,
                op_id,
                'REQUIRES_OPERATION',
                {'description': '规则需要的操作'}
            )

        # 关系4: Rule -> Value (HAS_VALUE)
        if rule.constraint_value:
            value_id = f'value:{rule.id}:{rule.constraint_value}'
            self.kg.add_node(value_id, 'Value', {
                'value': rule.constraint_value,
                'rule_id': rule.id
            })

            self.kg.add_edge(
                rule_id,
                value_id,
                'HAS_VALUE',
                {'description': '规则关联的值'}
            )

        # 关系5: 推断证书类型（基于规则特征）
        cert_type = self._infer_certificate_type(rule)
        if cert_type:
            concept_id = f'concept:{cert_type}'
            if concept_id in self.kg.graph:
                self.kg.add_edge(
                    rule_id,
                    concept_id,
                    'APPLIES_TO',
                    {'description': f'规则适用于{cert_type}'}
                )

    def _add_exception_rule_to_kg(self, exception_rule: ExceptionRule) -> None:
        """
        添加例外规则到知识图谱并建立关系

        设计原则：EffectiveRule = NormalRule ∧ ¬ ExceptionRule

        Args:
            exception_rule: 例外规则对象
        """
        exception_id = f'exception:{exception_rule.id}'

        # 解析condition_set（JSON字段）
        condition_set_data = {}
        if exception_rule.condition_set:
            try:
                condition_set_data = json.loads(exception_rule.condition_set)
            except json.JSONDecodeError:
                app_logger.warning(
                    f"Failed to parse condition_set for exception {exception_rule.exception_id}"
                )

        # 解析source_span（JSON字段）
        source_span_data = {}
        if exception_rule.source_span:
            try:
                source_span_data = json.loads(exception_rule.source_span)
            except json.JSONDecodeError:
                app_logger.warning(
                    f"Failed to parse source_span for exception {exception_rule.exception_id}"
                )

        properties = {
            'exception_rule_id': exception_rule.id,
            'exception_id': exception_rule.exception_id,
            'pattern': exception_rule.pattern,
            'effect': exception_rule.effect,
            'scope': exception_rule.scope,
            'condition_set': condition_set_data,
            'source_span': source_span_data,
            'justification': exception_rule.justification,
            'auto_detected': exception_rule.auto_detected,
            'confidence': exception_rule.confidence,
            'document_id': exception_rule.document_id,
            'section_id': exception_rule.section_id,
        }

        self.kg.add_node(exception_id, 'ExceptionRule', properties)

        # ⭐ 关系1: ExceptionRule -> Rule (EXCEPTION_OF)
        # 这是核心关系：表示例外规则修饰哪条主规则
        target_rule_id = f'rule:{exception_rule.target_rule_id}'
        if target_rule_id in self.kg.graph:
            self.kg.add_edge(
                exception_id,
                target_rule_id,
                'EXCEPTION_OF',
                {
                    'description': f'例外规则：{exception_rule.pattern}',
                    'effect': exception_rule.effect,
                    'scope': exception_rule.scope,
                    'pattern': exception_rule.pattern
                }
            )
            app_logger.debug(
                f"Added EXCEPTION_OF edge: {exception_id} -> {target_rule_id}"
            )
        else:
            app_logger.warning(
                f"Target rule {target_rule_id} not found for exception {exception_rule.exception_id}"
            )

    def _infer_certificate_type(self, rule: Rule) -> Optional[str]:
        """从规则中推断适用的证书类型"""
        text_lower = rule.text.lower()

        # 基于关键词推断
        if 'ca certificate' in text_lower or 'ca cert' in text_lower:
            if 'root' in text_lower:
                return 'root_ca'
            elif 'intermediate' in text_lower or 'subordinate' in text_lower:
                return 'intermediate_ca'
            return 'ca_certificate'

        if 'ev certificate' in text_lower or 'extended validation' in text_lower:
            return 'ev_certificate'

        if 'dv certificate' in text_lower or 'domain validation' in text_lower:
            return 'dv_certificate'

        if 'ov certificate' in text_lower or 'organization validation' in text_lower:
            return 'ov_certificate'

        # 基于字段推断
        if rule.subject == 'extensions.basicConstraints':
            if 'ca:true' in text_lower or 'ca=true' in text_lower:
                return 'ca_certificate'

        return None

    def _build_semantic_relationships(
        self,
        rule_embeddings: Dict[str, np.ndarray],
        threshold: float
    ) -> None:
        """
        基于语义相似度建立规则之间的关联

        Args:
            rule_embeddings: {rule_id: embedding_vector}
            threshold: 相似度阈值
        """
        if not rule_embeddings:
            app_logger.warning("No rule embeddings available for semantic relationship building")
            return

        rule_ids = list(rule_embeddings.keys())
        relationships_added = 0

        for i, rule_id_1 in enumerate(rule_ids):
            for rule_id_2 in rule_ids[i+1:]:
                # 计算余弦相似度
                embedding_1 = rule_embeddings[rule_id_1]
                embedding_2 = rule_embeddings[rule_id_2]

                # 归一化
                norm_1 = np.linalg.norm(embedding_1)
                norm_2 = np.linalg.norm(embedding_2)

                if norm_1 == 0 or norm_2 == 0:
                    continue

                similarity = np.dot(embedding_1, embedding_2) / (norm_1 * norm_2)

                if similarity >= threshold:
                    # 添加语义关联
                    self.kg.add_edge(
                        rule_id_1,
                        rule_id_2,
                        'RELATED_TO',
                        {
                            'description': '语义相关',
                            'similarity': float(similarity)
                        }
                    )
                    relationships_added += 1

        app_logger.info(f"Added {relationships_added} semantic relationships (threshold={threshold})")

    def _infer_conflicts(self) -> None:
        """
        推断规则之间的冲突关系

        冲突检测规则：
        1. 相同字段，不同操作（如must_be_present vs must_not_be_present）
        2. 相同字段和操作，但不同的值约束（如 minimum 2048 vs maximum 1024）
        """
        conflicts_found = 0

        # 按字段分组规则
        field_rules = {}
        for node_id, node_data in self.kg.graph.nodes(data=True):
            if node_data.get('node_type') != 'Rule':
                continue

            affected_field = node_data.get('properties', {}).get('affected_field')
            if not affected_field:
                continue

            if affected_field not in field_rules:
                field_rules[affected_field] = []

            field_rules[affected_field].append((node_id, node_data))

        # 检测冲突
        for field, rules in field_rules.items():
            for i, (rule_id_1, rule_data_1) in enumerate(rules):
                props_1 = rule_data_1.get('properties', {})
                op_1 = props_1.get('operation')
                value_1 = props_1.get('expected_value')

                for rule_id_2, rule_data_2 in rules[i+1:]:
                    props_2 = rule_data_2.get('properties', {})
                    op_2 = props_2.get('operation')
                    value_2 = props_2.get('expected_value')

                    conflict = False
                    reason = ""

                    # 检测1: 存在性冲突（修复：需要检查expected_value语义）
                    if {op_1, op_2} == {'must_be_present', 'must_not_be_present'}:
                        # 通用存在性要求的值（表示"字段存在/不存在"，不是"字段包含某值"）
                        generic_presence_values = {
                            None, '', 'present', 'absent', 'true', 'false',
                            'True', 'False', 'PRESENT', 'ABSENT'
                        }

                        # 规范化值（去除空白，转小写）
                        norm_value_1 = str(value_1).strip().lower() if value_1 else None
                        norm_value_2 = str(value_2).strip().lower() if value_2 else None

                        # 判断是否为通用存在性要求
                        is_generic_1 = (
                            value_1 in generic_presence_values or
                            norm_value_1 in {'present', 'absent', 'true', 'false', 'none', ''}
                        )
                        is_generic_2 = (
                            value_2 in generic_presence_values or
                            norm_value_2 in {'present', 'absent', 'true', 'false', 'none', ''}
                        )

                        # 只有当两个规则都是"通用存在性要求"时才判定为冲突
                        # 如果expected_value是特定值（如"SHA-1"），则是关于值的约束，不冲突
                        if is_generic_1 and is_generic_2:
                            conflict = True
                            reason = "Presence conflict: one requires field existence, other prohibits it"

                    # 检测2: Critical标记冲突
                    elif {op_1, op_2} == {'must_be_critical', 'must_not_be_critical'}:
                        conflict = True
                        reason = "Critical flag conflict"

                    # 检测3: 值冲突（如 minimum vs maximum）
                    elif op_1 == 'minimum_value' and op_2 == 'maximum_value':
                        # 尝试解析数值
                        try:
                            min_val = self._parse_numeric_value(value_1)
                            max_val = self._parse_numeric_value(value_2)

                            if min_val is not None and max_val is not None and min_val > max_val:
                                conflict = True
                                reason = f"Value range conflict: minimum ({min_val}) > maximum ({max_val})"
                        except:
                            pass

                    # 检测4: 同一字段同一操作但值不同（暂时禁用，提取质量不足导致误报）
                    # elif op_1 == op_2 and op_1 in {'must_equal', 'must_contain', 'must_match'}:
                    #     if value_1 and value_2 and value_1 != value_2:
                    #         norm_value_1 = str(value_1).strip().lower()
                    #         norm_value_2 = str(value_2).strip().lower()
                    #         if norm_value_1 != norm_value_2:
                    #             conflict = True
                    #             reason = f"Value constraint conflict: {op_1} requires different values"

                    if conflict:
                        self.kg.add_edge(
                            rule_id_1,
                            rule_id_2,
                            'CONFLICTS_WITH',
                            {
                                'description': reason,
                                'field': field
                            }
                        )
                        conflicts_found += 1

        if conflicts_found > 0:
            app_logger.warning(f"Found {conflicts_found} potential conflicts between rules")
        else:
            app_logger.info("No conflicts detected between rules")

    def _parse_numeric_value(self, value_str: Optional[str]) -> Optional[float]:
        """从值字符串中解析数值"""
        if not value_str:
            return None

        # 尝试提取数字
        import re
        match = re.search(r'(\d+(?:\.\d+)?)', str(value_str))
        if match:
            return float(match.group(1))

        return None

    def _resolve_cross_document_references(self) -> None:
        """
        解析跨文档引用，将引用关系添加到知识图谱

        策略：
        只检测显式引用：规则文本中明确提到"RFC 5280 Section X.X.X"
        """
        import re

        # 引用模式
        reference_patterns = [
            # 显式RFC引用: "RFC 5280", "RFC 5280 Section 4.2.1.9"
            (r'RFC\s+(\d+)(?:\s+[Ss]ection\s+([\d.]+))?', 'RFC_EXPLICIT'),
            # 章节引用: "Section 4.2.1.9" (可能指RFC 5280)
            (r'[Ss]ection\s+([\d.]+)', 'SECTION'),
        ]

        references_found = 0
        references_added = 0

        # 获取RFC 5280标准（作为默认引用目标）
        rfc5280 = self.db.query(Standard).filter(
            Standard.source == 'RFC',
            Standard.title.like('%5280%')
        ).first()

        # 获取所有规则节点
        for node_id, node_data in self.kg.graph.nodes(data=True):
            if node_data.get('node_type') != 'Rule':
                continue

            rule_text = node_data.get('properties', {}).get('text', '')
            affected_field = node_data.get('properties', {}).get('affected_field', '')

            rule_id = node_data.get('properties', {}).get('rule_id')
            rule = self.db.query(Rule).filter(Rule.id == rule_id).first()
            if not rule:
                continue

            source_standard = self.db.query(Standard).filter(Standard.id == rule.standard_id).first()
            if not source_standard:
                continue

            # 只处理CABF规则（它们大量引用RFC 5280）
            if not source_standard.source.startswith('CABF'):
                continue

            # 策略1: 显式引用
            for pattern, ref_type in reference_patterns:
                matches = re.finditer(pattern, rule_text)

                for match in matches:
                    references_found += 1

                    if ref_type == 'RFC_EXPLICIT':
                        rfc_number = match.group(1)
                        section = match.group(2) if len(match.groups()) > 1 else None

                        # 查找RFC标准
                        target_standard = self.db.query(Standard).filter(
                            Standard.source == 'RFC',
                            Standard.title.like(f'%{rfc_number}%')
                        ).first()

                        if target_standard and target_standard.id != source_standard.id:
                            target_rule = self._find_target_rule(target_standard.id, section)

                            if target_rule:
                                self._add_reference_edge(rule_id, target_rule.id, match.group(0), section, 'explicit')
                                references_added += 1

        app_logger.info(
            f"Resolved {references_added}/{references_found} cross-document references (explicit only)"
        )

    def _find_target_rule(self, standard_id: int, section: Optional[str]) -> Optional[Rule]:
        """查找目标规则"""
        if section:
            # 尝试精确匹配章节
            target_rule = self.db.query(Rule).filter(
                Rule.standard_id == standard_id,
                Rule.section == section
            ).first()

            # 如果精确匹配失败，尝试前缀匹配
            if not target_rule:
                target_rule = self.db.query(Rule).filter(
                    Rule.standard_id == standard_id,
                    Rule.section.like(f'{section}%')
                ).first()

            return target_rule
        else:
            # 返回该文档的任意规则
            return self.db.query(Rule).filter(
                Rule.standard_id == standard_id
            ).first()

    def _add_reference_edge(
        self,
        source_rule_id: int,
        target_rule_id: int,
        reference_text: str,
        section: Optional[str],
        reference_type: str
    ):
        """添加引用边（避免重复）"""
        source_node = f'rule:{source_rule_id}'
        target_node = f'rule:{target_rule_id}'

        # 检查是否已存在该边
        if self.kg.graph.has_edge(source_node, target_node):
            # 检查是否已有CITES类型的边
            edge_data = self.kg.graph.get_edge_data(source_node, target_node)
            if edge_data and edge_data.get('relation_type') == 'CITES':
                return  # 已存在，跳过

        self.kg.add_edge(
            source_node,
            target_node,
            'CITES',
            {
                'reference_text': reference_text,
                'reference_type': reference_type,
                'section': section
            }
        )

    def update_rule_in_kg(self, rule: Rule) -> None:
        """更新知识图谱中的规则"""
        rule_id = f'rule:{rule.id}'

        if rule_id in self.kg.graph:
            # 移除旧节点和边
            self.kg.graph.remove_node(rule_id)

        # 重新添加
        self._add_rule_to_kg(rule)

        app_logger.info(f"Updated rule {rule.id} in knowledge graph")

    def get_kg(self) -> CertificateKnowledgeGraph:
        """获取知识图谱"""
        return self.kg


def load_semantic_annotations(
    kg: CertificateKnowledgeGraph,
    annotations_dir: str,
) -> int:
    """
    从审核通过的语义标注 JSON 文件创建 KG 节点和边。

    Args:
        kg: 知识图谱实例
        annotations_dir: 语义标注目录路径 (data/semantic_annotations/)

    Returns:
        新增节点数
    """
    from pathlib import Path
    annotations_path = Path(annotations_dir)
    if not annotations_path.exists():
        app_logger.info(f"Semantic annotations directory not found: {annotations_dir}")
        return 0

    nodes_added = 0
    edges_added = 0

    for json_file in sorted(annotations_path.glob("*.json")):
        try:
            with open(json_file, 'r', encoding='utf-8') as f:
                data = json.load(f)
        except (json.JSONDecodeError, IOError) as e:
            app_logger.warning(f"Failed to load annotation file {json_file.name}: {e}")
            continue

        annotations = data if isinstance(data, list) else data.get('annotations', [])
        file_type = data.get('type', '') if isinstance(data, dict) else ''
        doc_id = data.get('doc_id', '') if isinstance(data, dict) else ''
        section_id = data.get('section_id', '') if isinstance(data, dict) else ''

        for ann in annotations:
            if not isinstance(ann, dict):
                continue
            if ann.get('status') not in ('approved', None):
                continue

            ann_type = ann.get('annotation_type', file_type)
            ann_id = ann.get('id', f"{ann_type}_{nodes_added}")
            section_node = f"section:{ann.get('doc_id', doc_id)}:{ann.get('section_id', section_id)}"

            if ann_type == 'actor':
                node_id = f"actor_ann:{ann_id}"
                kg.add_node(node_id, 'ActorAnnotation', {
                    'actor': ann.get('actor', ''),
                    'observable_in_cert': ann.get('observable_in_cert', False),
                    'evidence': ann.get('evidence', ''),
                    'sentence': ann.get('sentence', ''),
                })
                if section_node in kg.graph:
                    kg.add_edge(section_node, node_id, 'HAS_ACTOR', {})
                    edges_added += 1
                nodes_added += 1

            elif ann_type == 'algorithm_param':
                node_id = f"algo_param:{ann_id}"
                kg.add_node(node_id, 'AlgorithmParam', {
                    'param_name': ann.get('param_name', ''),
                    'override_value': ann.get('override_value'),
                    'observable_effect': ann.get('observable_effect', ''),
                    'observable_in_cert': ann.get('observable_in_cert', False),
                    'time_dependent': ann.get('time_dependent', False),
                })
                # Link to parent SectionAlgorithm if exists
                parent_algo = ann.get('parent_algorithm_id')
                if parent_algo and f"section_algo:{parent_algo}" in kg.graph:
                    kg.add_edge(f"section_algo:{parent_algo}", node_id, 'HAS_PARAM', {})
                    edges_added += 1
                nodes_added += 1

            elif ann_type == 'storage_target':
                node_id = f"storage:{ann_id}"
                kg.add_node(node_id, 'StorageTarget', {
                    'operation': ann.get('operation', ''),
                    'target_field_path': ann.get('target_field_path', ''),
                    'encoding_type': ann.get('encoding_type', ''),
                    'observable_in_cert': ann.get('observable_in_cert', True),
                })
                # STORES_IN → CertificateField
                field_path = ann.get('target_field_path', '')
                if field_path:
                    field_id = f"field:{field_path}"
                    if field_id not in kg.graph:
                        kg.add_node(field_id, 'CertificateField', {
                            'name': field_path,
                            'description': f'Certificate field: {field_path}'
                        })
                    kg.add_edge(node_id, field_id, 'STORES_IN', {})
                    edges_added += 1
                # Link to section
                if section_node in kg.graph:
                    kg.add_edge(section_node, node_id, 'HAS_STORAGE_TARGET', {})
                    edges_added += 1
                nodes_added += 1

            elif ann_type == 'field_encoding':
                node_id = f"field_enc:{ann_id}"
                kg.add_node(node_id, 'FieldEncoding', {
                    'field_path': ann.get('field_path', ''),
                    'allowed_encodings': ann.get('allowed_encodings', []),
                    'required_criticality': ann.get('required_criticality'),
                    'max_length': ann.get('max_length'),
                })
                # REQUIRES_ENCODING from CertificateField
                field_path = ann.get('field_path', '')
                if field_path:
                    field_id = f"field:{field_path}"
                    if field_id not in kg.graph:
                        kg.add_node(field_id, 'CertificateField', {
                            'name': field_path,
                            'description': f'Certificate field: {field_path}'
                        })
                    kg.add_edge(field_id, node_id, 'REQUIRES_ENCODING', {})
                    edges_added += 1
                # Link to section
                if section_node in kg.graph:
                    kg.add_edge(section_node, node_id, 'HAS_FIELD_ENCODING', {})
                    edges_added += 1
                nodes_added += 1

            elif ann_type == 'section_algorithm':
                node_id = f"section_algo:{ann_id}"
                kg.add_node(node_id, 'SectionAlgorithm', {
                    'base_spec': ann.get('base_spec', ''),
                    'operation': ann.get('operation', ''),
                    'step_modifications': ann.get('step_modifications', []),
                })
                if section_node in kg.graph:
                    kg.add_edge(section_node, node_id, 'INVOKES_ALGORITHM', {})
                    edges_added += 1
                nodes_added += 1

    app_logger.info(
        f"Loaded semantic annotations: {nodes_added} nodes, {edges_added} edges "
        f"from {annotations_path}"
    )
    return nodes_added
