"""
知识图谱API路由
提供知识图谱的可视化数据
"""
from fastapi import APIRouter, HTTPException, Depends
from sqlalchemy.orm import Session
from typing import Dict, List, Any, Optional
from app.core.database import get_db
from app.core.logging_config import app_logger
from app.services.knowledge_graph.knowledge_graph import CertificateKnowledgeGraph
from pathlib import Path

router = APIRouter()


def get_knowledge_graph() -> CertificateKnowledgeGraph:
    """获取知识图谱实例（使用 knowledge_layer 模块）"""
    from app.services.knowledge_layer import get_knowledge_graph as get_kg_from_layer

    kg = get_kg_from_layer()
    if kg is None:
        # 如果 knowledge_layer 未初始化，返回空的 KG
        app_logger.warning("Knowledge layer not initialized, returning empty KG")
        return CertificateKnowledgeGraph()

    return kg


@router.get("/kg/graph")
async def get_graph_data(
    node_types: Optional[str] = None,
    max_nodes: int = 500
):
    """
    获取知识图谱的完整数据，用于可视化

    Args:
        node_types: 节点类型过滤，逗号分隔（如: "Rule,CertificateField"）
        max_nodes: 最大节点数量限制

    Returns:
        {
            "nodes": [...],  # 节点列表
            "edges": [...],  # 边列表
            "statistics": {...}  # 统计信息
        }
    """
    try:
        kg = get_knowledge_graph()

        # 解析节点类型过滤
        filter_types = set(node_types.split(',')) if node_types else None

        # 获取所有节点
        nodes = []
        for node_id, node_data in kg.graph.nodes(data=True):
            node_type = node_data.get('node_type', 'Unknown')

            # 应用过滤
            if filter_types and node_type not in filter_types:
                continue

            nodes.append({
                'id': node_id,
                'type': node_type,
                'label': node_data.get('properties', {}).get('name', node_id),
                'properties': node_data.get('properties', {}),
                'created_at': node_data.get('created_at')
            })

            # 限制节点数量
            if len(nodes) >= max_nodes:
                app_logger.warning(f"Reached max nodes limit: {max_nodes}")
                break

        # 获取这些节点之间的边
        node_ids = {node['id'] for node in nodes}
        edges = []
        for source, target, edge_data in kg.graph.edges(data=True):
            # 只包含两个端点都在节点集合中的边
            if source in node_ids and target in node_ids:
                edges.append({
                    'source': source,
                    'target': target,
                    'type': edge_data.get('relation_type', 'Unknown'),
                    'label': edge_data.get('relation_type', 'Unknown'),
                    'properties': edge_data.get('properties', {}),
                    'created_at': edge_data.get('created_at')
                })

        # 获取统计信息
        statistics = kg.get_statistics()
        statistics['displayed_nodes'] = len(nodes)
        statistics['displayed_edges'] = len(edges)

        app_logger.info(f"Retrieved graph data: {len(nodes)} nodes, {len(edges)} edges")

        return {
            'nodes': nodes,
            'edges': edges,
            'statistics': statistics
        }

    except Exception as e:
        app_logger.error(f"Error retrieving graph data: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/kg/statistics")
async def get_kg_statistics():
    """
    获取知识图谱统计信息

    Returns:
        统计信息字典
    """
    try:
        kg = get_knowledge_graph()
        return kg.get_statistics()

    except Exception as e:
        app_logger.error(f"Error retrieving KG statistics: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/kg/node/{node_id}")
async def get_node_details(node_id: str):
    """
    获取特定节点的详细信息

    Args:
        node_id: 节点ID

    Returns:
        节点详细信息和邻居节点
    """
    try:
        kg = get_knowledge_graph()

        # 获取节点数据
        node_data = kg.get_node(node_id)
        if not node_data:
            raise HTTPException(status_code=404, detail="Node not found")

        # 获取邻居节点
        neighbors = kg.get_neighbors(node_id, direction='both')

        return {
            'node': {
                'id': node_id,
                'type': node_data.get('node_type'),
                'properties': node_data.get('properties', {}),
                'created_at': node_data.get('created_at')
            },
            'neighbors': [
                {
                    'id': neighbor_id,
                    'type': neighbor_data.get('node_type'),
                    'properties': neighbor_data.get('properties', {})
                }
                for neighbor_id, neighbor_data in neighbors
            ],
            'neighbor_count': len(neighbors)
        }

    except HTTPException:
        raise
    except Exception as e:
        app_logger.error(f"Error retrieving node details: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/kg/field-context/{field_name}")
async def get_field_context(field_name: str):
    """
    获取字段的上下文信息

    Args:
        field_name: 字段名称（如: validity, keyUsage等）

    Returns:
        字段的上下文信息，包括父字段、子字段、相关规则
    """
    try:
        kg = get_knowledge_graph()
        context = kg.get_field_context(field_name)

        return context

    except Exception as e:
        app_logger.error(f"Error retrieving field context: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/kg/related-rules/{rule_id}")
async def get_related_rules(
    rule_id: str,
    max_depth: int = 2,
    relation_types: Optional[str] = None
):
    """
    查找与指定规则相关的其他规则

    Args:
        rule_id: 规则ID（格式: rule:xxx）
        max_depth: 最大搜索深度
        relation_types: 关系类型过滤，逗号分隔

    Returns:
        相关规则列表
    """
    try:
        kg = get_knowledge_graph()

        # 解析关系类型
        filter_types = relation_types.split(',') if relation_types else None

        # 查找相关规则
        related = kg.find_related_rules(
            rule_id,
            relation_types=filter_types,
            max_depth=max_depth
        )

        return {
            'rule_id': rule_id,
            'related_rules': related,
            'total_related': len(related)
        }

    except Exception as e:
        app_logger.error(f"Error retrieving related rules: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/kg/path/{source_id}/{target_id}")
async def find_path(
    source_id: str,
    target_id: str,
    max_depth: int = 3
):
    """
    查找两个节点之间的路径

    Args:
        source_id: 源节点ID
        target_id: 目标节点ID
        max_depth: 最大路径深度

    Returns:
        路径节点列表，如果找不到则返回null
    """
    try:
        kg = get_knowledge_graph()

        path = kg.find_path(source_id, target_id, max_depth)

        if path:
            # 获取路径上每个节点的详细信息
            path_details = []
            for node_id in path:
                node_data = kg.get_node(node_id)
                path_details.append({
                    'id': node_id,
                    'type': node_data.get('node_type') if node_data else 'Unknown',
                    'properties': node_data.get('properties', {}) if node_data else {}
                })

            return {
                'found': True,
                'path': path_details,
                'length': len(path) - 1  # 路径长度（边数）
            }
        else:
            return {
                'found': False,
                'path': None,
                'message': f'No path found between {source_id} and {target_id} within depth {max_depth}'
            }

    except Exception as e:
        app_logger.error(f"Error finding path: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/kg/document-references")
async def get_document_references(
    db: Session = Depends(get_db),
    limit: int = 1000,
    offset: int = 0
):
    """
    获取文档规则引用列表（优化版：使用 JOIN 避免 N+1 查询 + 分页 + 文本截断）

    性能优化：
    - 旧版本1：重建整个 KG（5-10秒）
    - 旧版本2：N+1 查询问题（超时）
    - 旧版本3：返回全量数据（7000+条，响应超大）
    - 新版本：使用 JOIN + 分页 + 文本截断（~100ms）

    参数：
    - limit: 每页返回数量（默认1000）
    - offset: 偏移量（默认0）

    返回格式：
    {
        "references": [...],  # 引用列表
        "total": 7256,  # 总数
        "limit": 1000,  # 当前页大小
        "offset": 0  # 当前偏移
    }
    """
    try:
        from app.models.models import Rule, Standard
        from sqlalchemy import text

        # 先查询总数和各类型统计
        count_query = text("""
            SELECT COUNT(*) as total
            FROM kg_relations kr
            WHERE kr.relation_type = 'CITES'
        """)
        total_count = db.execute(count_query).scalar()

        # 统计跨文档引用数量（已解析 + 文档不同）
        cross_doc_query = text("""
            SELECT COUNT(*) as cross_doc_count
            FROM kg_relations kr
            JOIN rules sr ON kr.source_rule_id = sr.id
            LEFT JOIN rules tr ON kr.target_rule_id = tr.id
            WHERE kr.relation_type = 'CITES'
              AND kr.target_rule_id IS NOT NULL
              AND sr.standard_id != tr.standard_id
        """)
        cross_doc_count = db.execute(cross_doc_query).scalar()

        # 统计文档内部引用数量（已解析 + 文档相同）
        internal_query = text("""
            SELECT COUNT(*) as internal_count
            FROM kg_relations kr
            JOIN rules sr ON kr.source_rule_id = sr.id
            LEFT JOIN rules tr ON kr.target_rule_id = tr.id
            WHERE kr.relation_type = 'CITES'
              AND kr.target_rule_id IS NOT NULL
              AND sr.standard_id = tr.standard_id
        """)
        internal_count = db.execute(internal_query).scalar()

        # 外部引用数量 = 总数 - 跨文档 - 内部
        external_count = total_count - cross_doc_count - internal_count

        # 使用 JOIN 一次性获取分页数据，避免 N+1 查询
        query = text("""
            SELECT
                kr.id as relation_id,
                kr.raw_reference_text,
                kr.target_section,
                kr.confidence,
                kr.algorithm_version,

                -- 源规则信息（截断文本）
                sr.id as source_rule_id,
                sr.section as source_rule_section,
                sr.title as source_rule_title,
                LEFT(sr.text, 500) as source_rule_text,  -- 只取前500字符
                sr.standard_id as source_standard_id,

                -- 源标准信息
                ss.id as source_std_id,
                ss.title as source_std_title,
                ss.source as source_std_source,
                ss.version as source_std_version,

                -- 目标规则信息（可能为 NULL，截断文本）
                tr.id as target_rule_id,
                tr.section as target_rule_section,
                tr.title as target_rule_title,
                LEFT(tr.text, 500) as target_rule_text,  -- 只取前500字符
                tr.standard_id as target_standard_id,

                -- 目标标准信息（可能为 NULL）
                ts.id as target_std_id,
                ts.title as target_std_title,
                ts.source as target_std_source,
                ts.version as target_std_version

            FROM kg_relations kr
            JOIN rules sr ON kr.source_rule_id = sr.id
            JOIN standards ss ON sr.standard_id = ss.id
            LEFT JOIN rules tr ON kr.target_rule_id = tr.id
            LEFT JOIN standards ts ON tr.standard_id = ts.id
            WHERE kr.relation_type = 'CITES'
            ORDER BY kr.created_at DESC
            LIMIT :limit OFFSET :offset
        """)

        result = db.execute(query, {'limit': limit, 'offset': offset})
        rows = result.fetchall()

        references = []

        for row in rows:
            # 源规则和标准（必定存在）
            source_rule = {
                'id': row.source_rule_id,
                'section': row.source_rule_section,
                'title': row.source_rule_title,
                'text': row.source_rule_text,  # 已截断
                'standard_id': row.source_standard_id
            }

            source_standard = {
                'id': row.source_std_id,
                'title': row.source_std_title,
                'source': row.source_std_source,
                'version': row.source_std_version
            }

            # 目标规则和标准（可能为 NULL）
            if row.target_rule_id:
                # 已解析的引用
                target_rule = {
                    'id': row.target_rule_id,
                    'section': row.target_rule_section,
                    'title': row.target_rule_title,
                    'text': row.target_rule_text,  # 已截断
                    'standard_id': row.target_standard_id
                }

                target_standard = {
                    'id': row.target_std_id,
                    'title': row.target_std_title,
                    'source': row.target_std_source,
                    'version': row.target_std_version
                }

                is_cross_document = row.source_std_id != row.target_std_id
                is_external = False
            else:
                # 未解析的外部引用
                target_rule = None
                target_standard = None
                is_cross_document = True
                is_external = True

            references.append({
                'source_rule': source_rule,
                'target_rule': target_rule,
                'source_standard': source_standard,
                'target_standard': target_standard,
                'reference_text': row.raw_reference_text or '',
                'target_section': row.target_section or '',
                'confidence': row.confidence,
                'algorithm_version': row.algorithm_version,
                'is_cross_document': is_cross_document,
                'is_external': is_external
            })

        app_logger.info(
            f"[API Performance] JOIN query: found {len(references)} references (total={total_count}, limit={limit}, offset={offset})"
        )

        return {
            'references': references,
            'total': total_count,
            'cross_document_count': cross_doc_count,
            'internal_count': internal_count,
            'external_count': external_count,
            'limit': limit,
            'offset': offset
        }

    except Exception as e:
        app_logger.error(f"Error retrieving cross-document references: {e}")
        import traceback
        app_logger.error(traceback.format_exc())
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/kg/cross-document-conflicts")
async def get_cross_document_conflicts(db: Session = Depends(get_db)):
    """
    获取跨文档规则冲突列表（重构版：直接查询数据库）

    性能优化：
    - 旧版本：重建整个 KG + 实时冲突检测（5-10秒）
    - 新版本：直接查询 kg_relations 表（~50ms）

    返回格式：
    {
        "conflicts": [
            {
                "rule_a": {...},  # 规则A信息
                "rule_b": {...},  # 规则B信息
                "standard_a": {...},  # 标准A
                "standard_b": {...},  # 标准B
                "conflict_type": "...",  # 冲突类型
                "reason": "...",  # 冲突原因
            }
        ],
        "total": 5
    }
    """
    try:
        from app.models.models import Rule, Standard
        from sqlalchemy import text

        # 直接查询 kg_relations 表（CONFLICTS_WITH 类型）
        query = text("""
            SELECT
                kr.id,
                kr.source_rule_id,
                kr.target_rule_id,
                kr.relation_type,
                kr.reason,
                kr.confidence,
                kr.algorithm_version,
                kr.is_uncertain
            FROM kg_relations kr
            WHERE kr.relation_type = 'CONFLICTS_WITH'
              AND kr.target_rule_id IS NOT NULL
            ORDER BY kr.created_at DESC
        """)

        result = db.execute(query)
        relations = result.fetchall()

        conflicts = []
        processed_pairs = set()  # 避免重复

        for row in relations:
            source_rule_id = row.source_rule_id
            target_rule_id = row.target_rule_id

            # 去重（冲突是双向的）
            pair_key = tuple(sorted([source_rule_id, target_rule_id]))
            if pair_key in processed_pairs:
                continue
            processed_pairs.add(pair_key)

            # 查询规则和标准信息
            rule_a = db.query(Rule).filter(Rule.id == source_rule_id).first()
            rule_b = db.query(Rule).filter(Rule.id == target_rule_id).first()

            if rule_a and rule_b:
                standard_a = db.query(Standard).filter(
                    Standard.id == rule_a.standard_id
                ).first()
                standard_b = db.query(Standard).filter(
                    Standard.id == rule_b.standard_id
                ).first()

                # 只统计跨文档冲突（保留原有过滤逻辑）
                if standard_a and standard_b and standard_a.id != standard_b.id:
                    # 解析 reason JSON
                    import json
                    reason_data = {}
                    try:
                        if row.reason:
                            reason_data = json.loads(row.reason) if isinstance(row.reason, str) else row.reason
                    except (json.JSONDecodeError, TypeError):
                        reason_data = {'raw': str(row.reason)}

                    conflicts.append({
                        'rule_a': {
                            'id': rule_a.id,
                            'section': rule_a.section,
                            'title': rule_a.title,
                            'text': rule_a.text,
                            'affected_field': rule_a.affected_field,
                            'operation': rule_a.operation,
                            'expected_value': rule_a.expected_value,
                            'standard_id': rule_a.standard_id
                        },
                        'rule_b': {
                            'id': rule_b.id,
                            'section': rule_b.section,
                            'title': rule_b.title,
                            'text': rule_b.text,
                            'affected_field': rule_b.affected_field,
                            'operation': rule_b.operation,
                            'expected_value': rule_b.expected_value,
                            'standard_id': rule_b.standard_id
                        },
                        'standard_a': {
                            'id': standard_a.id,
                            'title': standard_a.title,
                            'source': standard_a.source,
                            'version': standard_a.version
                        },
                        'standard_b': {
                            'id': standard_b.id,
                            'title': standard_b.title,
                            'source': standard_b.source,
                            'version': standard_b.version
                        },
                        'conflict_type': reason_data.get('type', 'unknown'),
                        'reason': reason_data.get('explanation', str(row.reason)),
                        'field': reason_data.get('field', rule_a.affected_field),
                        'confidence': row.confidence,
                        'is_uncertain': row.is_uncertain or False,
                        'resolution': 'uncertain' if row.is_uncertain else 'unresolved',
                        'algorithm_version': row.algorithm_version
                    })

        app_logger.info(
            f"[API Performance] Direct DB query: found {len(conflicts)} document conflicts (cross-document only)"
        )

        return {
            'conflicts': conflicts,
            'total': len(conflicts)
        }

    except Exception as e:
        app_logger.error(f"Error retrieving cross-document conflicts: {e}")
        raise HTTPException(status_code=500, detail=str(e))
