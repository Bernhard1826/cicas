"""
语义标注加载器
从审核通过的 JSON 文件加载语义标注到知识图谱
"""
import json
from pathlib import Path
from app.services.knowledge_graph.knowledge_graph import CertificateKnowledgeGraph
from app.core.logging_config import app_logger


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
