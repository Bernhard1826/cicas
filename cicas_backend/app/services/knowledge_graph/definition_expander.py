"""
模块 C: 引用解析 - 定义展开器
实现引用定义的展开，填充 IR.constraint.expanded 字段
"""
from typing import Dict, Optional, List
from sqlalchemy.orm import Session
from app.core.logging_config import app_logger


class DefinitionExpander:
    """
    定义展开器

    功能：
    1. 从引用中提取定义（ABNF、正则表达式）
    2. 展开到 IR.constraint.expanded
    3. 支持多层级引用展开
    """

    def __init__(self, db: Session, kg):
        self.db = db
        self.kg = kg
        self._definition_cache = {}  # 缓存已展开的定义

    def expand_constraint_definition(
        self,
        ir: Dict,
        max_depth: int = 3
    ) -> Dict:
        """
        展开 IR 中的约束定义

        Args:
            ir: IR 字典
            max_depth: 最大展开深度（防止循环引用）

        Returns:
            展开后的 IR
        """
        app_logger.info(f"Expanding constraint definition for IR: {ir.get('lint_name')}")

        # 检查是否有引用
        references = ir.get('references', [])

        if not references:
            app_logger.debug("No references found, skipping expansion")
            return ir

        # 展开每个引用
        expanded_definitions = []

        for ref in references:
            if not ref.get('resolved'):
                app_logger.warning(f"Reference not resolved: {ref.get('raw')}")
                continue

            # 从 KG 中获取定义
            definition = self._fetch_definition_from_kg(
                doc_id=ref.get('doc_id'),
                section=ref.get('section')
            )

            if definition:
                expanded_definitions.append(definition)

        # 合并展开的定义
        if expanded_definitions:
            ir['constraint']['expanded'] = self._merge_definitions(
                expanded_definitions
            )
            app_logger.info(f"Expanded {len(expanded_definitions)} definitions")
        else:
            app_logger.debug("No definitions found to expand")

        return ir

    def _fetch_definition_from_kg(
        self,
        doc_id: str,
        section: str
    ) -> Optional[Dict]:
        """
        从知识图谱中获取定义

        Args:
            doc_id: 文档 ID（如 "RFC5280"）
            section: 章节号（如 "4.2.1.9"）

        Returns:
            定义字典或 None
        """
        # 检查缓存
        cache_key = f"{doc_id}:{section}"
        if cache_key in self._definition_cache:
            return self._definition_cache[cache_key]

        # 查询 KG
        definition_node_id = f"definition:{doc_id}:{section}"

        # 从 KG 中查找 Definition 节点
        if definition_node_id in self.kg.graph:
            node_data = self.kg.graph.nodes[definition_node_id]
            definition = {
                'type': node_data.get('definition_type'),  # abnf | regex | prose
                'value': node_data.get('definition_value'),
                'source': {
                    'doc_id': doc_id,
                    'section': section
                }
            }

            # 缓存
            self._definition_cache[cache_key] = definition
            return definition

        app_logger.warning(f"Definition not found in KG: {cache_key}")
        return None

    def _merge_definitions(
        self,
        definitions: List[Dict]
    ) -> Dict:
        """
        合并多个定义

        Args:
            definitions: 定义列表

        Returns:
            合并后的定义字典
        """
        if not definitions:
            return {}

        # 优先级：ABNF > Regex > Prose
        abnf_defs = [d for d in definitions if d.get('type') == 'abnf']
        regex_defs = [d for d in definitions if d.get('type') == 'regex']
        prose_defs = [d for d in definitions if d.get('type') == 'prose']

        if abnf_defs:
            # 使用第一个 ABNF 定义
            return abnf_defs[0]
        elif regex_defs:
            # 合并多个正则表达式（用 | 连接）
            merged_regex = '|'.join(d['value'] for d in regex_defs)
            return {
                'type': 'regex',
                'value': merged_regex,
                'source': [d['source'] for d in regex_defs]
            }
        elif prose_defs:
            # 使用第一个文本定义
            return prose_defs[0]

        return {}

    def expand_all_irs(
        self,
        irs: List[Dict]
    ) -> List[Dict]:
        """
        批量展开多个 IR

        Args:
            irs: IR 列表

        Returns:
            展开后的 IR 列表
        """
        app_logger.info(f"Expanding {len(irs)} IRs...")

        expanded_irs = []
        for ir in irs:
            try:
                expanded_ir = self.expand_constraint_definition(ir)
                expanded_irs.append(expanded_ir)
            except Exception as e:
                app_logger.error(f"Failed to expand IR {ir.get('lint_name')}: {e}")
                # 保留原始 IR
                expanded_irs.append(ir)

        app_logger.info(f"Successfully expanded {len(expanded_irs)} IRs")
        return expanded_irs

    def add_definition_to_kg(
        self,
        doc_id: str,
        section: str,
        definition_type: str,  # abnf | regex | prose
        definition_value: str
    ) -> str:
        """
        添加定义节点到 KG

        Args:
            doc_id: 文档 ID
            section: 章节号
            definition_type: 定义类型
            definition_value: 定义值

        Returns:
            定义节点 ID
        """
        node_id = f"definition:{doc_id}:{section}"

        # 添加 Definition 节点
        self.kg.add_node(
            node_id,
            'Definition',
            {
                'doc_id': doc_id,
                'section': section,
                'definition_type': definition_type,
                'definition_value': definition_value
            }
        )

        # 添加关系：Section -> Definition
        section_node_id = f"section:{doc_id}:{section}"
        if section_node_id in self.kg.graph:
            self.kg.add_edge(
                section_node_id,
                node_id,
                'DEFINES',
                {'type': definition_type}
            )

        app_logger.info(f"Added definition node: {node_id}")
        return node_id
