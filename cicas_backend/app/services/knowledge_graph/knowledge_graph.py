"""
知识图谱核心模块
使用 NetworkX 构建证书标准领域的知识图谱
"""
import networkx as nx
from typing import Dict, List, Any, Optional, Set, Tuple
from datetime import datetime
import pickle
from pathlib import Path
from app.core.logging_config import app_logger


class KnowledgeGraphNode:
    """知识图谱节点"""

    def __init__(
        self,
        node_id: str,
        node_type: str,
        properties: Dict[str, Any]
    ):
        self.node_id = node_id
        self.node_type = node_type
        self.properties = properties
        self.created_at = datetime.now().isoformat()

    def to_dict(self) -> Dict[str, Any]:
        return {
            'node_id': self.node_id,
            'node_type': self.node_type,
            'properties': self.properties,
            'created_at': self.created_at
        }


class KnowledgeGraphEdge:
    """知识图谱边"""

    def __init__(
        self,
        source: str,
        target: str,
        relation_type: str,
        properties: Optional[Dict[str, Any]] = None
    ):
        self.source = source
        self.target = target
        self.relation_type = relation_type
        self.properties = properties or {}
        self.created_at = datetime.now().isoformat()

    def to_dict(self) -> Dict[str, Any]:
        return {
            'source': self.source,
            'target': self.target,
            'relation_type': self.relation_type,
            'properties': self.properties,
            'created_at': self.created_at
        }


class CertificateKnowledgeGraph:
    """
    证书标准领域知识图谱

    节点类型：
    - Specification: 规范文档（RFC, CABF, ETSI等）
    - Section: 文档章节
    - CertificateField: 证书字段（validity, keyUsage等）
    - Operation: 操作类型（must_be_present, minimum_value等）
    - Value: 约束值（"2048 bits", "365 days"等）
    - Rule: 具体规则 / 提取的 IR
    - Concept: 领域概念（"CA证书", "EV证书"等）
    - Definition: 术语定义

    关系类型：
    - CONTAINS: Specification -> Section（规范包含章节）；Section -> Section（子章节）；
                Specification -> Rule（规范包含规则）
    - DEFINES: Section -> Definition（章节定义术语）
    - DERIVED_FROM: IR -> Section（IR 来源于章节）
    - REFERENCES: IR -> Definition | Section（显式引用）
    - AFFECTS: Rule -> CertificateField（规则影响字段）
    - APPLIES_TO: Rule -> Concept | Field（规则适用于）
    - REQUIRES_OPERATION: Rule -> Operation（规则需要的操作）
    - HAS_VALUE: Rule -> Value（规则关联的值）
    - PART_OF: CertificateField -> CertificateField（字段层级）
    - RELATED_TO: Rule <-> Rule（语义相关）
    - CONFLICTS_WITH: Rule <-> Rule（规则冲突）
    - OVERRIDES: Rule -> Rule（规则覆盖，由规则引擎生成，非 LLM）
    - REFINES: Rule -> Rule（规则精化）
    - IS_A: Concept -> Concept（概念层级）
    - PART_OF: CertificateField -> CertificateField（字段层级）

    语义标注节点类型（Phase: KG Enrichment）:
    - ActorAnnotation: 主体角色标注 (actor, observable_in_cert, evidence)
    - AlgorithmParam: 算法参数语义 (param_name, override_value, observable_effect, observable_in_cert, time_dependent)
    - StorageTarget: 存储目标映射 (operation, target_field_path, encoding_type, observable_in_cert)
    - FieldEncoding: 字段编码要求 (field_path, allowed_encodings, required_criticality, max_length)
    - SectionAlgorithm: 节-算法映射 (base_spec, operation, step_modifications)

    语义标注关系类型:
    - HAS_ACTOR: Section -> ActorAnnotation
    - INVOKES_ALGORITHM: Section -> SectionAlgorithm
    - HAS_PARAM: SectionAlgorithm -> AlgorithmParam
    - STORES_IN: StorageTarget -> CertificateField
    - REQUIRES_ENCODING: CertificateField -> FieldEncoding

    HARD CONSTRAINT:
    - OVERRIDES / CONFLICTS_WITH 不是 LLM 产出的
    - 全部来自规则引擎（模块 F）
    """

    def __init__(self):
        self.graph = nx.MultiDiGraph()  # 支持多重边的有向图
        self._initialize_domain_knowledge()
        app_logger.info("Knowledge graph initialized")

    def _initialize_domain_knowledge(self):
        """初始化领域知识（证书字段层级、概念层级等）"""

        # 1. 添加证书字段节点
        certificate_fields = [
            # 核心字段
            ('field:version', {'name': 'version', 'description': 'X.509 版本'}),
            ('field:serialNumber', {'name': 'serialNumber', 'description': '证书序列号'}),
            ('field:signature', {'name': 'signature', 'description': '签名'}),
            ('field:signatureAlgorithm', {'name': 'signatureAlgorithm', 'description': '签名算法'}),
            ('field:issuer', {'name': 'issuer', 'description': '颁发者'}),
            ('field:validity', {'name': 'validity', 'description': '有效期'}),
            ('field:subject', {'name': 'subject', 'description': '主体'}),
            ('field:subjectPublicKeyInfo', {'name': 'subjectPublicKeyInfo', 'description': '主体公钥信息'}),

            # 扩展字段
            ('field:extensions', {'name': 'extensions', 'description': '扩展字段'}),
            ('field:extensions.basicConstraints', {'name': 'basicConstraints', 'description': '基本约束'}),
            ('field:extensions.keyUsage', {'name': 'keyUsage', 'description': '密钥用法'}),
            ('field:extensions.extendedKeyUsage', {'name': 'extendedKeyUsage', 'description': '扩展密钥用法'}),
            ('field:extensions.subjectAltName', {'name': 'subjectAltName', 'description': '主体备用名称'}),
            ('field:extensions.certificatePolicies', {'name': 'certificatePolicies', 'description': '证书策略'}),
            ('field:extensions.cRLDistributionPoints', {'name': 'cRLDistributionPoints', 'description': 'CRL分发点'}),
            ('field:extensions.authorityInfoAccess', {'name': 'authorityInfoAccess', 'description': '颁发机构信息访问'}),
            ('field:extensions.subjectKeyIdentifier', {'name': 'subjectKeyIdentifier', 'description': '主体密钥标识符'}),
            ('field:extensions.authorityKeyIdentifier', {'name': 'authorityKeyIdentifier', 'description': '颁发机构密钥标识符'}),
        ]

        for node_id, properties in certificate_fields:
            self.add_node(node_id, 'CertificateField', properties)

        # 添加字段层级关系
        extension_fields = [
            'field:extensions.basicConstraints',
            'field:extensions.keyUsage',
            'field:extensions.extendedKeyUsage',
            'field:extensions.subjectAltName',
            'field:extensions.certificatePolicies',
            'field:extensions.cRLDistributionPoints',
            'field:extensions.authorityInfoAccess',
            'field:extensions.subjectKeyIdentifier',
            'field:extensions.authorityKeyIdentifier',
        ]

        for ext_field in extension_fields:
            self.add_edge('field:extensions', ext_field, 'PART_OF', {'description': '扩展字段的一部分'})

        # 2. 添加操作类型节点
        operations = [
            ('op:must_be_present', {'name': 'must_be_present', 'description': '必须存在'}),
            ('op:must_not_be_present', {'name': 'must_not_be_present', 'description': '不得存在'}),
            ('op:must_be_critical', {'name': 'must_be_critical', 'description': '必须标记为关键'}),
            ('op:must_not_be_critical', {'name': 'must_not_be_critical', 'description': '不得标记为关键'}),
            ('op:minimum_value', {'name': 'minimum_value', 'description': '最小值'}),
            ('op:maximum_value', {'name': 'maximum_value', 'description': '最大值'}),
            ('op:must_equal', {'name': 'must_equal', 'description': '必须等于'}),
            ('op:must_contain', {'name': 'must_contain', 'description': '必须包含'}),
            ('op:must_not_contain', {'name': 'must_not_contain', 'description': '不得包含'}),
            ('op:must_not_be_empty', {'name': 'must_not_be_empty', 'description': '不得为空'}),
        ]

        for node_id, properties in operations:
            self.add_node(node_id, 'Operation', properties)

        # 3. 添加证书类型概念
        concepts = [
            ('concept:certificate', {'name': '证书', 'level': 0}),
            ('concept:ca_certificate', {'name': 'CA证书', 'level': 1}),
            ('concept:end_entity_certificate', {'name': '终端实体证书', 'level': 1}),
            ('concept:root_ca', {'name': '根CA', 'level': 2}),
            ('concept:intermediate_ca', {'name': '中间CA', 'level': 2}),
            ('concept:ev_certificate', {'name': 'EV证书', 'level': 2}),
            ('concept:dv_certificate', {'name': 'DV证书', 'level': 2}),
            ('concept:ov_certificate', {'name': 'OV证书', 'level': 2}),
        ]

        for node_id, properties in concepts:
            self.add_node(node_id, 'Concept', properties)

        # 添加概念层级关系
        concept_hierarchy = [
            ('concept:ca_certificate', 'concept:certificate'),
            ('concept:end_entity_certificate', 'concept:certificate'),
            ('concept:root_ca', 'concept:ca_certificate'),
            ('concept:intermediate_ca', 'concept:ca_certificate'),
            ('concept:ev_certificate', 'concept:end_entity_certificate'),
            ('concept:dv_certificate', 'concept:end_entity_certificate'),
            ('concept:ov_certificate', 'concept:end_entity_certificate'),
        ]

        for child, parent in concept_hierarchy:
            self.add_edge(child, parent, 'IS_A', {'description': '是...的一种'})

        app_logger.info(f"Domain knowledge initialized: {self.graph.number_of_nodes()} nodes, {self.graph.number_of_edges()} edges")

    def add_node(
        self,
        node_id: str,
        node_type: str,
        properties: Dict[str, Any]
    ) -> None:
        """添加节点"""
        node = KnowledgeGraphNode(node_id, node_type, properties)
        self.graph.add_node(node_id, **node.to_dict())

    def add_edge(
        self,
        source: str,
        target: str,
        relation_type: str,
        properties: Optional[Dict[str, Any]] = None
    ) -> None:
        """添加边"""
        edge = KnowledgeGraphEdge(source, target, relation_type, properties)
        self.graph.add_edge(source, target, key=relation_type, **edge.to_dict())

    def get_node(self, node_id: str) -> Optional[Dict[str, Any]]:
        """获取节点"""
        if node_id in self.graph:
            return dict(self.graph.nodes[node_id])
        return None

    def get_neighbors(
        self,
        node_id: str,
        relation_type: Optional[str] = None,
        direction: str = 'out'  # 'out', 'in', 'both'
    ) -> List[Tuple[str, Dict[str, Any]]]:
        """
        获取邻居节点

        Args:
            node_id: 节点ID
            relation_type: 关系类型（可选）
            direction: 边的方向 ('out'=出边, 'in'=入边, 'both'=双向)

        Returns:
            邻居节点列表 [(node_id, node_data), ...]
        """
        if node_id not in self.graph:
            return []

        neighbors = []

        if direction in ['out', 'both']:
            # 出边（node_id -> neighbor）
            for neighbor in self.graph.successors(node_id):
                edges = self.graph[node_id][neighbor]
                for edge_data in edges.values():
                    if relation_type is None or edge_data.get('relation_type') == relation_type:
                        neighbors.append((neighbor, dict(self.graph.nodes[neighbor])))
                        break

        if direction in ['in', 'both']:
            # 入边（neighbor -> node_id）
            for neighbor in self.graph.predecessors(node_id):
                edges = self.graph[neighbor][node_id]
                for edge_data in edges.values():
                    if relation_type is None or edge_data.get('relation_type') == relation_type:
                        neighbors.append((neighbor, dict(self.graph.nodes[neighbor])))
                        break

        return neighbors

    def find_path(
        self,
        source: str,
        target: str,
        max_depth: int = 3
    ) -> Optional[List[str]]:
        """查找两个节点之间的最短路径"""
        try:
            if max_depth == 0:
                return None

            # 使用 BFS 查找最短路径
            path = nx.shortest_path(self.graph, source, target)

            if len(path) <= max_depth + 1:  # +1 因为路径包含起点和终点
                return path
            return None
        except (nx.NetworkXNoPath, nx.NodeNotFound):
            return None

    def find_related_rules(
        self,
        rule_id: str,
        relation_types: Optional[List[str]] = None,
        max_depth: int = 2
    ) -> List[Dict[str, Any]]:
        """
        查找相关规则

        Args:
            rule_id: 规则ID
            relation_types: 关系类型列表（可选）
            max_depth: 最大搜索深度

        Returns:
            相关规则列表
        """
        if rule_id not in self.graph:
            return []

        related_rules = []
        visited = {rule_id}
        queue = [(rule_id, 0)]  # (node_id, depth)

        while queue:
            current_id, depth = queue.pop(0)

            if depth >= max_depth:
                continue

            # 获取所有邻居
            neighbors = self.get_neighbors(current_id, direction='both')

            for neighbor_id, neighbor_data in neighbors:
                if neighbor_id in visited:
                    continue

                visited.add(neighbor_id)

                # 如果是规则节点，添加到结果
                if neighbor_data.get('node_type') == 'Rule':
                    # 获取边的关系类型
                    edge_data = None
                    if self.graph.has_edge(current_id, neighbor_id):
                        edges = self.graph[current_id][neighbor_id]
                        edge_data = list(edges.values())[0]
                    elif self.graph.has_edge(neighbor_id, current_id):
                        edges = self.graph[neighbor_id][current_id]
                        edge_data = list(edges.values())[0]

                    if edge_data:
                        rel_type = edge_data.get('relation_type')
                        if relation_types is None or rel_type in relation_types:
                            related_rules.append({
                                'rule_id': neighbor_id,
                                'rule_data': neighbor_data,
                                'relation_type': rel_type,
                                'depth': depth + 1
                            })

                # 继续搜索
                queue.append((neighbor_id, depth + 1))

        return related_rules

    def find_conflicting_rules(self, rule_id: str) -> List[Dict[str, Any]]:
        """查找与指定规则冲突的规则"""
        return self.find_related_rules(rule_id, relation_types=['CONFLICTS_WITH'], max_depth=1)

    def get_field_context(self, field_name: str) -> Dict[str, Any]:
        """
        获取字段的上下文信息（相关规则、父字段等）

        Returns:
            {
                'field_info': {...},
                'parent_fields': [...],
                'child_fields': [...],
                'related_rules': [...]
            }
        """
        field_id = f'field:{field_name}'

        if field_id not in self.graph:
            return {
                'field_info': None,
                'parent_fields': [],
                'child_fields': [],
                'related_rules': []
            }

        field_info = self.get_node(field_id)

        # 父字段（PART_OF 的目标）
        parent_fields = self.get_neighbors(field_id, relation_type='PART_OF', direction='out')

        # 子字段（PART_OF 的源）
        child_fields = self.get_neighbors(field_id, relation_type='PART_OF', direction='in')

        # 相关规则（AFFECTS 的源）
        related_rules = self.get_neighbors(field_id, relation_type='AFFECTS', direction='in')

        return {
            'field_info': field_info,
            'parent_fields': [{'id': nid, 'data': data} for nid, data in parent_fields],
            'child_fields': [{'id': nid, 'data': data} for nid, data in child_fields],
            'related_rules': [{'id': nid, 'data': data} for nid, data in related_rules]
        }

    def get_operation_compatibility(self, operation: str, field: str) -> Dict[str, Any]:
        """
        检查操作和字段的兼容性

        Returns:
            {
                'compatible': bool,
                'reason': str,
                'examples': [...]
            }
        """
        # 获取字段类型
        field_id = f'field:{field}'
        field_data = self.get_node(field_id)

        if not field_data:
            return {
                'compatible': True,  # 未知字段，默认兼容
                'reason': 'Unknown field, cannot verify compatibility',
                'examples': []
            }

        # 检查是否有使用该操作的其他规则
        op_id = f'op:{operation}'
        if op_id not in self.graph:
            return {
                'compatible': True,
                'reason': 'Unknown operation, cannot verify compatibility',
                'examples': []
            }

        # 查找使用相同操作和字段的规则
        examples = []
        for rule_id, rule_data in self.get_neighbors(op_id, relation_type='REQUIRES_OPERATION', direction='in'):
            rule_field = rule_data.get('properties', {}).get('affected_field')
            if rule_field == field:
                examples.append({
                    'rule_id': rule_id,
                    'rule_text': rule_data.get('properties', {}).get('text', '')[:100]
                })

        return {
            'compatible': True,
            'reason': f'Found {len(examples)} examples of {operation} on {field}',
            'examples': examples[:3]  # 返回最多3个例子
        }

    def get_nodes_by_type(self, node_type: str) -> List[Tuple[str, Dict[str, Any]]]:
        """获取指定类型的所有节点"""
        results = []
        for node_id, node_data in self.graph.nodes(data=True):
            if node_data.get('node_type') == node_type:
                results.append((node_id, dict(node_data)))
        return results

    def get_semantic_annotations_for_section(
        self,
        doc_id: str,
        section_id: str
    ) -> Dict[str, List[Dict[str, Any]]]:
        """
        获取节的所有语义标注（按类型分组）

        Returns:
            {
                "actors": [...],
                "algorithm_params": [...],
                "storage_targets": [...],
                "field_encodings": [...],
                "section_algorithms": [...]
            }
        """
        section_node_id = f"section:{doc_id}:{section_id}"
        result = {
            "actors": [],
            "algorithm_params": [],
            "storage_targets": [],
            "field_encodings": [],
            "section_algorithms": [],
        }

        if section_node_id not in self.graph:
            return result

        # HAS_ACTOR → ActorAnnotation
        for neighbor_id, neighbor_data in self.get_neighbors(
            section_node_id, relation_type='HAS_ACTOR', direction='out'
        ):
            if neighbor_data.get('node_type') == 'ActorAnnotation':
                result["actors"].append(neighbor_data.get('properties', {}))

        # INVOKES_ALGORITHM → SectionAlgorithm → HAS_PARAM → AlgorithmParam
        for algo_id, algo_data in self.get_neighbors(
            section_node_id, relation_type='INVOKES_ALGORITHM', direction='out'
        ):
            if algo_data.get('node_type') == 'SectionAlgorithm':
                algo_props = algo_data.get('properties', {})
                # Collect params
                params = []
                for param_id, param_data in self.get_neighbors(
                    algo_id, relation_type='HAS_PARAM', direction='out'
                ):
                    if param_data.get('node_type') == 'AlgorithmParam':
                        params.append(param_data.get('properties', {}))
                algo_props['params'] = params
                result["section_algorithms"].append(algo_props)
                result["algorithm_params"].extend(params)

        # Find StorageTarget nodes linked to this section
        for neighbor_id, neighbor_data in self.get_neighbors(
            section_node_id, relation_type='HAS_STORAGE_TARGET', direction='out'
        ):
            if neighbor_data.get('node_type') == 'StorageTarget':
                result["storage_targets"].append(neighbor_data.get('properties', {}))

        # Find FieldEncoding nodes linked to this section
        for neighbor_id, neighbor_data in self.get_neighbors(
            section_node_id, relation_type='HAS_FIELD_ENCODING', direction='out'
        ):
            if neighbor_data.get('node_type') == 'FieldEncoding':
                result["field_encodings"].append(neighbor_data.get('properties', {}))

        return result

    def save(self, file_path: Path) -> None:
        """保存知识图谱到文件"""
        with open(file_path, 'wb') as f:
            pickle.dump(self.graph, f)
        app_logger.info(f"Knowledge graph saved to {file_path}")

    def load(self, file_path: Path) -> None:
        """从文件加载知识图谱"""
        if file_path.exists():
            with open(file_path, 'rb') as f:
                self.graph = pickle.load(f)
            app_logger.info(f"Knowledge graph loaded from {file_path}: {self.graph.number_of_nodes()} nodes")
        else:
            app_logger.warning(f"Knowledge graph file not found: {file_path}")

    def get_statistics(self) -> Dict[str, Any]:
        """获取知识图谱统计信息"""
        node_types = {}
        edge_types = {}

        for node_id, node_data in self.graph.nodes(data=True):
            node_type = node_data.get('node_type', 'Unknown')
            node_types[node_type] = node_types.get(node_type, 0) + 1

        for source, target, edge_data in self.graph.edges(data=True):
            relation_type = edge_data.get('relation_type', 'Unknown')
            edge_types[relation_type] = edge_types.get(relation_type, 0) + 1

        return {
            'total_nodes': self.graph.number_of_nodes(),
            'total_edges': self.graph.number_of_edges(),
            'node_types': node_types,
            'edge_types': edge_types,
            'density': nx.density(self.graph),
            'is_connected': nx.is_weakly_connected(self.graph)
        }
