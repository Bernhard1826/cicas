"""
定义展开器（Definition Expander）
从引用文档中提取和展开定义（ABNF、字段格式、语义摘要）
"""
from typing import Dict, List, Optional, Any
from .ir_schema import IntermediateRepresentation, IRConstraint, IRReference
import re


class DefinitionExpander:
    """定义展开器"""

    def __init__(self, kg_client=None, standards_cache: Dict[str, Any] = None):
        """
        初始化展开器

        Args:
            kg_client: 知识图谱客户端
            standards_cache: 标准文档缓存
        """
        self.kg_client = kg_client
        self.standards_cache = standards_cache or {}
        self.definition_cache = {}  # 定义缓存

    def expand(
        self,
        ir: IntermediateRepresentation,
        max_depth: int = 3,
    ) -> IntermediateRepresentation:
        """
        展开 IR 中的引用定义

        Args:
            ir: 中间表示
            max_depth: 最大展开深度

        Returns:
            展开后的 IR
        """
        if not ir.references:
            return ir

        # 展开所有引用
        expanded_definitions = []

        for ref in ir.references:
            if not ref.resolved:
                continue

            definition = self._fetch_definition(ref, depth=0, max_depth=max_depth)
            if definition:
                expanded_definitions.append(definition)

        # 合并定义
        if expanded_definitions:
            merged_definition = self._merge_definitions(expanded_definitions)

            # 更新 constraint.expanded
            ir.constraint.expanded = merged_definition

        return ir

    def _fetch_definition(
        self,
        ref: IRReference,
        depth: int,
        max_depth: int,
    ) -> Optional[Dict[str, Any]]:
        """
        从引用获取定义

        Args:
            ref: 引用对象
            depth: 当前深度
            max_depth: 最大深度

        Returns:
            定义字典
        """
        if depth >= max_depth:
            return None

        # 检查缓存
        cache_key = f"{ref.doc_id}:{ref.section}"
        if cache_key in self.definition_cache:
            return self.definition_cache[cache_key]

        # 从 KG 获取定义
        definition = None
        if self.kg_client:
            definition = self._fetch_from_kg(ref)

        # 从标准文档缓存获取
        if not definition and ref.doc_id in self.standards_cache:
            definition = self._fetch_from_cache(ref)

        # 缓存结果
        if definition:
            self.definition_cache[cache_key] = definition

        return definition

    def _fetch_from_kg(self, ref: IRReference) -> Optional[Dict[str, Any]]:
        """从知识图谱获取定义"""
        if not self.kg_client:
            return None

        try:
            # 查询 KG 中的定义节点
            node_id = f"standard_section:{ref.doc_id}:{ref.section}"
            node = self.kg_client.get_node(node_id)

            if node:
                properties = node.get('properties', {})
                return {
                    'source': ref.doc_id,
                    'section': ref.section,
                    'type': properties.get('definition_type', 'text'),
                    'content': properties.get('content', ''),
                    'abnf': properties.get('abnf'),
                    'regex': properties.get('regex'),
                    'summary': properties.get('summary'),
                }

        except Exception as e:
            print(f"Error fetching from KG: {e}")
            return None

    def _fetch_from_cache(self, ref: IRReference) -> Optional[Dict[str, Any]]:
        """从标准文档缓存获取定义"""
        standard = self.standards_cache.get(ref.doc_id)
        if not standard:
            return None

        # 查找章节内容
        section_content = self._find_section(standard, ref.section)
        if not section_content:
            return None

        # 解析定义
        definition = {
            'source': ref.doc_id,
            'section': ref.section,
            'type': 'text',
            'content': section_content,
        }

        # 提取 ABNF
        abnf = self._extract_abnf(section_content)
        if abnf:
            definition['abnf'] = abnf
            definition['type'] = 'abnf'

        # 提取正则
        regex = self._extract_regex(section_content)
        if regex:
            definition['regex'] = regex

        # 生成摘要
        summary = self._generate_summary(section_content)
        if summary:
            definition['summary'] = summary

        return definition

    def _find_section(self, standard: Dict[str, Any], section: str) -> Optional[str]:
        """在标准文档中查找章节"""
        # 假设标准文档有 sections 字段
        sections = standard.get('sections', {})

        # 精确匹配
        if section in sections:
            return sections[section]

        # 模糊匹配（处理 4.2 vs 4.2.1）
        for sec_num, content in sections.items():
            if section in sec_num or sec_num in section:
                return content

        return None

    def _extract_abnf(self, text: str) -> Optional[List[str]]:
        """提取 ABNF 定义"""
        abnf_pattern = re.compile(r'([a-zA-Z0-9\-]+)\s*::=\s*(.+)', re.MULTILINE)
        matches = abnf_pattern.findall(text)

        if matches:
            return [f"{name} ::= {definition}" for name, definition in matches]

        return None

    def _extract_regex(self, text: str) -> Optional[str]:
        """从 ABNF 或文本中提取正则表达式"""
        # 简单实现：查找明确的正则模式
        regex_pattern = re.compile(r'/([^/]+)/', re.MULTILINE)
        match = regex_pattern.search(text)

        if match:
            return match.group(1)

        return None

    def _generate_summary(self, text: str, max_length: int = 200) -> str:
        """生成文本摘要"""
        # 简单截断前 N 个字符
        if len(text) <= max_length:
            return text

        return text[:max_length] + "..."

    def _merge_definitions(self, definitions: List[Dict[str, Any]]) -> Dict[str, Any]:
        """合并多个定义"""
        if not definitions:
            return {}

        if len(definitions) == 1:
            return definitions[0]

        # 合并策略
        merged = {
            'sources': [],
            'type': 'combined',
            'content': '',
            'abnf': [],
            'regex': [],
            'summary': '',
        }

        for definition in definitions:
            source = f"{definition['source']}:{definition['section']}"
            merged['sources'].append(source)

            # 合并内容
            if definition.get('content'):
                merged['content'] += f"\n\n[{source}]\n{definition['content']}"

            # 合并 ABNF
            if definition.get('abnf'):
                if isinstance(definition['abnf'], list):
                    merged['abnf'].extend(definition['abnf'])
                else:
                    merged['abnf'].append(definition['abnf'])

            # 合并正则
            if definition.get('regex'):
                merged['regex'].append(definition['regex'])

            # 合并摘要
            if definition.get('summary'):
                merged['summary'] += f" {definition['summary']}"

        # 去重
        merged['abnf'] = list(set(merged['abnf']))
        merged['regex'] = list(set(merged['regex']))

        return merged

    def expand_batch(
        self,
        irs: List[IntermediateRepresentation],
        max_depth: int = 3,
    ) -> List[IntermediateRepresentation]:
        """批量展开"""
        return [self.expand(ir, max_depth) for ir in irs]
