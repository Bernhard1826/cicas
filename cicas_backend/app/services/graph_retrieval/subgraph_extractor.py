"""
子图提取器 (Subgraph Extractor)

职责：
1. 从知识图谱中提取相关子图
2. 基于起始节点的邻域扩展
3. 限制扩展深度和节点数量

设计原则：
- 只提取直接相关的节点
- 不做跨规范泛化
- 保持子图的可追溯性

HARD CONSTRAINT (GraphRAG 输出约束):
- SubgraphExtractor MUST NOT introduce derived or synthesized requirements.
- 只返回原始规范文档中的节点（Definition, Section, Field 等）
- 不返回任何推导或合成的内容
- 这确保 LLM 只能基于原始规范内容进行结构化提取
"""
from typing import List, Dict, Any, Optional, Set, Tuple
from dataclasses import dataclass, field

from app.core.logging_config import app_logger


@dataclass
class SubgraphNode:
    """子图节点"""
    node_id: str
    node_type: str
    properties: Dict[str, Any] = field(default_factory=dict)
    depth: int = 0  # 距离起始节点的深度


@dataclass
class SubgraphEdge:
    """子图边"""
    source: str
    target: str
    relation_type: str
    properties: Dict[str, Any] = field(default_factory=dict)


@dataclass
class Subgraph:
    """子图"""
    nodes: Dict[str, SubgraphNode] = field(default_factory=dict)
    edges: List[SubgraphEdge] = field(default_factory=list)
    root_node_id: Optional[str] = None

    def get_node(self, node_id: str) -> Optional[SubgraphNode]:
        """获取节点"""
        return self.nodes.get(node_id)

    def get_nodes_by_type(self, node_type: str) -> List[SubgraphNode]:
        """按类型获取节点"""
        return [n for n in self.nodes.values() if n.node_type == node_type]

    def get_edges_from(self, node_id: str) -> List[SubgraphEdge]:
        """获取从节点出发的边"""
        return [e for e in self.edges if e.source == node_id]

    def get_edges_to(self, node_id: str) -> List[SubgraphEdge]:
        """获取指向节点的边"""
        return [e for e in self.edges if e.target == node_id]


class SubgraphExtractor:
    """
    子图提取器

    从知识图谱中提取与输入相关的子图。
    使用 BFS 从起始节点扩展。
    """

    # 默认配置
    DEFAULT_MAX_DEPTH = 3
    DEFAULT_MAX_NODES = 100

    # 优先关系类型（扩展时优先考虑）
    PRIORITY_RELATIONS = [
        "CONTAINS",
        "DEFINES",
        "REFERENCES",
        "APPLIES_TO",
        "HAS_ACTOR",
        "INVOKES_ALGORITHM",
        "STORES_IN",
        "REQUIRES_ENCODING",
        "HAS_PARAM",
        "HAS_STORAGE_TARGET",
        "HAS_FIELD_ENCODING",
    ]

    def __init__(self, knowledge_graph, max_depth: int = None, max_nodes: int = None):
        """
        初始化子图提取器

        Args:
            knowledge_graph: 知识图谱实例
            max_depth: 最大扩展深度
            max_nodes: 最大节点数
        """
        self.kg = knowledge_graph
        self.max_depth = max_depth or self.DEFAULT_MAX_DEPTH
        self.max_nodes = max_nodes or self.DEFAULT_MAX_NODES

    def extract_from_section(
        self,
        doc_id: str,
        section_id: str
    ) -> Subgraph:
        """
        从章节节点提取子图

        Args:
            doc_id: 文档 ID
            section_id: 章节 ID

        Returns:
            Subgraph
        """
        section_node_id = f"section:{doc_id}:{section_id}"
        return self.extract_from_node(section_node_id)

    def extract_from_node(
        self,
        start_node_id: str,
        relation_filter: Optional[List[str]] = None
    ) -> Subgraph:
        """
        从指定节点提取子图

        Args:
            start_node_id: 起始节点 ID
            relation_filter: 关系类型过滤器

        Returns:
            Subgraph
        """
        subgraph = Subgraph(root_node_id=start_node_id)

        # 检查起始节点是否存在
        start_node_data = self.kg.get_node(start_node_id)
        if not start_node_data:
            app_logger.warning(f"起始节点不存在: {start_node_id}")
            return subgraph

        # BFS 扩展
        visited: Set[str] = set()
        queue: List[Tuple[str, int]] = [(start_node_id, 0)]  # (node_id, depth)

        while queue and len(subgraph.nodes) < self.max_nodes:
            node_id, depth = queue.pop(0)

            if node_id in visited:
                continue
            visited.add(node_id)

            # 获取节点数据
            node_data = self.kg.get_node(node_id)
            if not node_data:
                continue

            # 添加到子图
            subgraph.nodes[node_id] = SubgraphNode(
                node_id=node_id,
                node_type=node_data.get("node_type", "Unknown"),
                properties=node_data.get("properties", {}),
                depth=depth,
            )

            # 如果未达到最大深度，继续扩展
            if depth < self.max_depth:
                neighbors = self._get_neighbors(node_id, relation_filter)

                for neighbor_id, relation_type, edge_props in neighbors:
                    if neighbor_id not in visited:
                        queue.append((neighbor_id, depth + 1))

                        # 添加边
                        subgraph.edges.append(SubgraphEdge(
                            source=node_id,
                            target=neighbor_id,
                            relation_type=relation_type,
                            properties=edge_props,
                        ))

        app_logger.debug(
            f"提取子图: {len(subgraph.nodes)} 节点, {len(subgraph.edges)} 边"
        )
        return subgraph

    def extract_definitions_for_section(
        self,
        doc_id: str,
        section_id: str
    ) -> List[SubgraphNode]:
        """
        提取章节相关的定义节点

        Args:
            doc_id: 文档 ID
            section_id: 章节 ID

        Returns:
            Definition 节点列表
        """
        section_node_id = f"section:{doc_id}:{section_id}"
        subgraph = self.extract_from_node(
            section_node_id,
            relation_filter=["CONTAINS", "DEFINES"]
        )

        return subgraph.get_nodes_by_type("Definition")

    def extract_references_for_section(
        self,
        doc_id: str,
        section_id: str
    ) -> List[SubgraphNode]:
        """
        提取章节引用的节点

        Args:
            doc_id: 文档 ID
            section_id: 章节 ID

        Returns:
            被引用的节点列表
        """
        section_node_id = f"section:{doc_id}:{section_id}"
        subgraph = self.extract_from_node(
            section_node_id,
            relation_filter=["REFERENCES"]
        )

        # 返回非章节类型的被引用节点
        return [
            n for n in subgraph.nodes.values()
            if n.node_type not in ["Section"] and n.depth > 0
        ]

    def extract_semantic_context_for_section(
        self,
        doc_id: str,
        section_id: str
    ) -> Dict[str, List[SubgraphNode]]:
        """
        提取章节的语义标注节点（按类型分组）

        Returns:
            {
                "ActorAnnotation": [...],
                "AlgorithmParam": [...],
                "StorageTarget": [...],
                "FieldEncoding": [...],
                "SectionAlgorithm": [...]
            }
        """
        semantic_types = [
            "ActorAnnotation", "AlgorithmParam", "StorageTarget",
            "FieldEncoding", "SectionAlgorithm"
        ]
        section_node_id = f"section:{doc_id}:{section_id}"
        subgraph = self.extract_from_node(
            section_node_id,
            relation_filter=[
                "HAS_ACTOR", "INVOKES_ALGORITHM", "HAS_PARAM",
                "STORES_IN", "REQUIRES_ENCODING",
                "HAS_STORAGE_TARGET", "HAS_FIELD_ENCODING",
            ]
        )

        result = {t: [] for t in semantic_types}
        for node in subgraph.nodes.values():
            if node.node_type in semantic_types:
                result[node.node_type].append(node)

        return result

    def _get_neighbors(
        self,
        node_id: str,
        relation_filter: Optional[List[str]] = None
    ) -> List[Tuple[str, str, Dict[str, Any]]]:
        """
        获取节点的邻居（同时遍历出/入边，支持 MultiDiGraph 多边场景）。

        Args:
            node_id: 节点 ID
            relation_filter: 关系类型过滤器；为 None 时不过滤

        Returns:
            [(neighbor_id, relation_type, edge_props), ...]
        """
        neighbors: List[Tuple[str, str, Dict[str, Any]]] = []

        if not (hasattr(self.kg, 'graph') and node_id in self.kg.graph):
            return neighbors

        graph = self.kg.graph

        # 出边：node_id -> neighbor，按每条边的 relation_type 单独过滤
        for neighbor_id in graph.successors(node_id):
            edges = graph[node_id][neighbor_id]
            for edge_data in edges.values():
                rel = edge_data.get("relation_type", "RELATED")
                if relation_filter and rel not in relation_filter:
                    continue
                neighbors.append((neighbor_id, rel, dict(edge_data)))

        # 入边：neighbor -> node_id（用于支持 Section <- Rule(DERIVED_FROM/REFERENCES)、
        # Specification <- Section(CONTAINS) 等反向 BFS 检索）
        for neighbor_id in graph.predecessors(node_id):
            if neighbor_id == node_id:
                continue
            edges = graph[neighbor_id][node_id]
            for edge_data in edges.values():
                rel = edge_data.get("relation_type", "RELATED")
                if relation_filter and rel not in relation_filter:
                    continue
                neighbors.append((neighbor_id, rel, dict(edge_data)))

        # 去重（同一邻居经多条同类型边只保留一次）
        seen: Set[Tuple[str, str]] = set()
        deduped: List[Tuple[str, str, Dict[str, Any]]] = []
        for nb_id, rel, props in neighbors:
            key = (nb_id, rel)
            if key in seen:
                continue
            seen.add(key)
            deduped.append((nb_id, rel, props))

        # 按优先级排序
        deduped.sort(
            key=lambda x: (
                self.PRIORITY_RELATIONS.index(x[1])
                if x[1] in self.PRIORITY_RELATIONS else 999
            )
        )

        return deduped

    def _get_relation_type(self, source: str, target: str) -> str:
        """获取两个节点之间的关系类型（多边时返回首条；保留以兼容其他调用）"""
        if hasattr(self.kg, 'graph') and self.kg.graph.has_edge(source, target):
            edges = self.kg.graph[source][target]
            if edges:
                first_edge = list(edges.values())[0]
                return first_edge.get("relation_type", "RELATED")
        return "RELATED"
