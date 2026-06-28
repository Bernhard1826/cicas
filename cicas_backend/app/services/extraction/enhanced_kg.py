"""
知识图谱 API 增强
提供版本管理、传递推理、API 接口
"""
from typing import List, Dict, Any, Optional
from datetime import datetime
import networkx as nx


class EnhancedKnowledgeGraph:
    """增强的知识图谱"""

    def __init__(self, kg: nx.MultiDiGraph):
        """
        初始化增强KG

        Args:
            kg: NetworkX 图对象
        """
        self.kg = kg

    def add_versioned_node(
        self,
        node_id: str,
        node_type: str,
        properties: Dict[str, Any],
        version: str,
        published_date: Optional[datetime] = None,
        effective_date: Optional[datetime] = None,
        deprecated: bool = False,
        superseded_by: Optional[str] = None,
        authority_level: int = 0,
    ):
        """
        添加版本化节点

        Args:
            node_id: 节点ID
            node_type: 节点类型
            properties: 属性
            version: 版本号
            published_date: 发布日期
            effective_date: 生效日期
            deprecated: 是否废弃
            superseded_by: 被哪个节点替代
            authority_level: 权威级别 (RFC=3, CABF=2, Mozilla=1)
        """
        self.kg.add_node(
            node_id,
            node_type=node_type,
            properties=properties,
            version=version,
            published_date=published_date,
            effective_date=effective_date,
            deprecated=deprecated,
            superseded_by=superseded_by,
            authority_level=authority_level,
            created_at=datetime.now(),
        )

    def get_node(self, node_id: str) -> Optional[Dict[str, Any]]:
        """获取节点"""
        if not self.kg.has_node(node_id):
            return None

        node_data = self.kg.nodes[node_id]
        return {
            'node_id': node_id,
            **node_data,
        }

    def resolve_reference(self, rule_id: str) -> Dict[str, Any]:
        """
        解析规则的所有引用

        Args:
            rule_id: 规则ID

        Returns:
            引用信息
        """
        references = {
            'direct': [],
            'indirect': [],
        }

        # 直接引用
        if self.kg.has_node(rule_id):
            out_edges = self.kg.out_edges(rule_id, data=True)
            for source, target, data in out_edges:
                if data.get('relation_type') == 'refers_to':
                    references['direct'].append({
                        'target': target,
                        'properties': data.get('properties', {}),
                    })

        # 间接引用（传递）
        indirect = self._get_transitive_references(rule_id)
        references['indirect'] = indirect

        return references

    def _get_transitive_references(
        self, rule_id: str, max_depth: int = 3
    ) -> List[Dict[str, Any]]:
        """获取传递引用"""
        if not self.kg.has_node(rule_id):
            return []

        visited = set()
        queue = [(rule_id, 0)]
        transitive_refs = []

        while queue:
            current_id, depth = queue.pop(0)

            if depth >= max_depth:
                continue

            if current_id in visited:
                continue

            visited.add(current_id)

            # 获取直接引用
            out_edges = self.kg.out_edges(current_id, data=True)
            for source, target, data in out_edges:
                if data.get('relation_type') == 'refers_to':
                    transitive_refs.append({
                        'target': target,
                        'depth': depth + 1,
                        'path': f"{rule_id} -> {target}",
                    })
                    queue.append((target, depth + 1))

        return transitive_refs

    def expand_definition(self, rule_id: str) -> Optional[Dict[str, Any]]:
        """
        展开规则的定义

        Args:
            rule_id: 规则ID

        Returns:
            展开的定义
        """
        if not self.kg.has_node(rule_id):
            return None

        # 获取规则节点
        rule_node = self.get_node(rule_id)

        # 获取所有引用的定义
        references = self.resolve_reference(rule_id)
        definitions = []

        for ref in references['direct']:
            target_id = ref['target']
            target_node = self.get_node(target_id)

            if target_node:
                properties = target_node.get('properties', {})
                if 'definition' in properties:
                    definitions.append({
                        'source': target_id,
                        'definition': properties['definition'],
                        'type': properties.get('definition_type', 'text'),
                    })

        return {
            'rule_id': rule_id,
            'rule_properties': rule_node.get('properties', {}),
            'definitions': definitions,
        }

    def get_conflicts(self, rule_id: str) -> List[Dict[str, Any]]:
        """
        获取规则的所有冲突

        Args:
            rule_id: 规则ID

        Returns:
            冲突列表
        """
        conflicts = []

        if not self.kg.has_node(rule_id):
            return conflicts

        # 获取所有冲突边
        edges = self.kg.edges(rule_id, data=True)
        for source, target, data in edges:
            if data.get('relation_type') == 'CONFLICTS_WITH':
                conflicts.append({
                    'conflicting_rule': target if source == rule_id else source,
                    'conflict_type': data.get('properties', {}).get('type'),
                    'reason': data.get('properties', {}).get('reason'),
                    'confidence': data.get('properties', {}).get('confidence', 0.0),
                })

        return conflicts

    def similar_rules(
        self, rule_id: str, similarity_threshold: float = 0.75, top_k: int = 10
    ) -> List[Dict[str, Any]]:
        """
        查找相似规则

        Args:
            rule_id: 规则ID
            similarity_threshold: 相似度阈值
            top_k: 返回前 k 个

        Returns:
            相似规则列表
        """
        similar = []

        if not self.kg.has_node(rule_id):
            return similar

        # 获取所有相关边
        edges = self.kg.edges(rule_id, data=True)
        for source, target, data in edges:
            if data.get('relation_type') == 'RELATED_TO':
                similarity = data.get('properties', {}).get('similarity', 0.0)
                if similarity >= similarity_threshold:
                    similar.append({
                        'related_rule': target if source == rule_id else source,
                        'similarity': similarity,
                    })

        # 排序并返回前 k 个
        similar.sort(key=lambda x: x['similarity'], reverse=True)
        return similar[:top_k]

    def get_transitive_references(
        self, rule_id: str, max_depth: int = 3
    ) -> List[Dict[str, Any]]:
        """
        获取传递引用（公开API）

        Args:
            rule_id: 规则ID
            max_depth: 最大深度

        Returns:
            传递引用列表
        """
        return self._get_transitive_references(rule_id, max_depth)

    def find_document_by_section(self, section: str) -> Optional[Dict[str, Any]]:
        """
        通过章节号查找文档

        Args:
            section: 章节号

        Returns:
            文档信息
        """
        # 遍历所有标准文档节点
        for node_id, node_data in self.kg.nodes(data=True):
            if node_data.get('node_type') == 'StandardSection':
                properties = node_data.get('properties', {})
                if properties.get('section') == section:
                    return {
                        'doc_id': properties.get('standard_id'),
                        'section': section,
                        'node_id': node_id,
                    }

        return None

    def get_authority_level(self, rule_id: str) -> int:
        """
        获取规则的权威级别

        Args:
            rule_id: 规则ID

        Returns:
            权威级别 (3=RFC, 2=CABF, 1=其他)
        """
        node = self.get_node(rule_id)
        if node:
            return node.get('authority_level', 0)
        return 0

    def is_deprecated(self, rule_id: str) -> bool:
        """检查规则是否废弃"""
        node = self.get_node(rule_id)
        if node:
            return node.get('deprecated', False)
        return False

    def get_superseding_rule(self, rule_id: str) -> Optional[str]:
        """获取替代规则"""
        node = self.get_node(rule_id)
        if node:
            return node.get('superseded_by')
        return None


class GraphStoreInterface:
    """图存储接口（抽象层）"""

    def add_node(self, node_id: str, **kwargs):
        """添加节点"""
        raise NotImplementedError

    def get_node(self, node_id: str) -> Optional[Dict[str, Any]]:
        """获取节点"""
        raise NotImplementedError

    def add_edge(self, source: str, target: str, relation_type: str, **kwargs):
        """添加边"""
        raise NotImplementedError

    def query(self, **kwargs) -> List[Dict[str, Any]]:
        """查询"""
        raise NotImplementedError


class NetworkXGraphStore(GraphStoreInterface):
    """NetworkX 图存储实现"""

    def __init__(self, graph: Optional[nx.MultiDiGraph] = None):
        self.graph = graph or nx.MultiDiGraph()

    def add_node(self, node_id: str, **kwargs):
        self.graph.add_node(node_id, **kwargs)

    def get_node(self, node_id: str) -> Optional[Dict[str, Any]]:
        if not self.graph.has_node(node_id):
            return None
        return {'node_id': node_id, **self.graph.nodes[node_id]}

    def add_edge(self, source: str, target: str, relation_type: str, **kwargs):
        self.graph.add_edge(source, target, relation_type=relation_type, **kwargs)

    def query(self, **kwargs) -> List[Dict[str, Any]]:
        # 简单实现
        return []


# 使用示例：
# graph_store = NetworkXGraphStore()
# enhanced_kg = EnhancedKnowledgeGraph(graph_store.graph)
