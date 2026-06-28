"""
上下文组装器 (Context Assembler)

职责：
1. 从子图组装最小上下文
2. 限制 token budget
3. 按优先级组装内容

设计原则：
- 限制 token budget (max 2000 tokens)
- 优先级：Definition > Field > Other rules
- 不做跨规范泛化

HARD CONSTRAINT (GraphRAG 输出约束):
- GraphRAG MUST NOT introduce derived or synthesized requirements.
- GraphRAG MUST only output verbatim definitions and structural metadata.
- 所有上下文内容必须来自原始规范文档，不得推导或合成新要求。
- 这确保 LLM 只能基于原始规范内容进行结构化提取。
"""
from typing import List, Dict, Any, Optional
from dataclasses import dataclass, field

from app.core.logging_config import app_logger
from .subgraph_extractor import Subgraph, SubgraphNode


@dataclass
class MinimalContext:
    """最小上下文"""
    # 规范信息
    spec_family: str = ""
    spec_id: str = ""
    section_id: str = ""

    # 定义
    definitions: List[Dict[str, str]] = field(default_factory=list)

    # 字段信息
    fields: List[Dict[str, str]] = field(default_factory=list)

    # 相关规则
    related_rules: List[Dict[str, str]] = field(default_factory=list)

    # 原始文本
    section_content: str = ""

    # 元数据
    token_count: int = 0
    truncated: bool = False

    def to_prompt_string(self) -> str:
        """转换为提示词字符串"""
        parts = []

        if self.spec_family:
            parts.append(f"Specification Family: {self.spec_family}")
        if self.spec_id:
            parts.append(f"Specification: {self.spec_id}")
        if self.section_id:
            parts.append(f"Section: {self.section_id}")

        if self.definitions:
            parts.append("\nRelevant Definitions:")
            for defn in self.definitions:
                parts.append(f"- {defn['term']}: {defn['definition']}")

        if self.fields:
            parts.append("\nRelevant Certificate Fields:")
            for field in self.fields:
                parts.append(f"- {field['name']}: {field.get('description', '')}")

        if self.related_rules:
            parts.append("\nRelated Rules:")
            for rule in self.related_rules[:3]:  # 最多 3 条
                parts.append(f"- {rule.get('text', '')[:100]}...")

        if self.section_content:
            parts.append("\nSource Text:")
            parts.append(self.section_content)

        return "\n".join(parts)


class ContextAssembler:
    """
    上下文组装器

    从子图组装 LLM 需要的最小上下文。
    遵循检索算法：
    1. 找到所在 Section
    2. 取该 Section 的 Definition 邻居
    3. 取显式 REFERENCES 指向的节点
    4. 限制 token budget
    5. 按优先级排序
    """

    # 默认 token budget
    DEFAULT_MAX_TOKENS = 2000

    # 每个字符约等于的 token 数（粗略估计）
    CHARS_PER_TOKEN = 4

    # 节点类型优先级（数字越小优先级越高）
    NODE_TYPE_PRIORITY = {
        "Definition": 1,
        "Field": 2,
        "CertificateField": 2,
        "Rule": 3,
        "Requirement": 3,
        "Section": 4,
        "Specification": 5,
    }

    def __init__(self, max_tokens: int = None):
        """
        初始化上下文组装器

        Args:
            max_tokens: 最大 token 数
        """
        self.max_tokens = max_tokens or self.DEFAULT_MAX_TOKENS

    def assemble(
        self,
        subgraph: Subgraph,
        section_content: Optional[str] = None,
        spec_info: Optional[Dict[str, str]] = None
    ) -> MinimalContext:
        """
        组装最小上下文

        Args:
            subgraph: 提取的子图
            section_content: 章节原始内容
            spec_info: 规范信息 {"family": ..., "id": ..., "section": ...}

        Returns:
            MinimalContext
        """
        context = MinimalContext()
        current_tokens = 0

        # 设置规范信息
        if spec_info:
            context.spec_family = spec_info.get("family", "")
            context.spec_id = spec_info.get("id", "")
            context.section_id = spec_info.get("section", "")
            current_tokens += self._estimate_tokens(
                f"{context.spec_family} {context.spec_id} {context.section_id}"
            )

        # 按优先级排序节点
        sorted_nodes = self._sort_nodes_by_priority(list(subgraph.nodes.values()))

        # 组装定义
        for node in sorted_nodes:
            if current_tokens >= self.max_tokens:
                context.truncated = True
                break

            if node.node_type == "Definition":
                term = node.properties.get("term", "")
                definition = node.properties.get("definition", "")

                if term and definition:
                    defn_tokens = self._estimate_tokens(f"{term}: {definition}")

                    if current_tokens + defn_tokens <= self.max_tokens:
                        context.definitions.append({
                            "term": term,
                            "definition": self._truncate_text(definition, 200),
                        })
                        current_tokens += defn_tokens

        # 组装字段信息
        for node in sorted_nodes:
            if current_tokens >= self.max_tokens:
                context.truncated = True
                break

            if node.node_type in ["Field", "CertificateField"]:
                name = node.properties.get("name", "")
                description = node.properties.get("description", "")

                if name:
                    field_tokens = self._estimate_tokens(f"{name}: {description}")

                    if current_tokens + field_tokens <= self.max_tokens:
                        context.fields.append({
                            "name": name,
                            "description": self._truncate_text(description, 100),
                        })
                        current_tokens += field_tokens

        # 组装相关规则（如果还有 budget）
        remaining_tokens = self.max_tokens - current_tokens
        if remaining_tokens > 100:
            for node in sorted_nodes:
                if node.node_type in ["Rule", "Requirement"]:
                    text = node.properties.get("text", "")

                    if text:
                        rule_tokens = self._estimate_tokens(text[:100])

                        if current_tokens + rule_tokens <= self.max_tokens:
                            context.related_rules.append({
                                "id": node.node_id,
                                "text": self._truncate_text(text, 100),
                            })
                            current_tokens += rule_tokens

                        if len(context.related_rules) >= 3:
                            break

        # 添加章节内容（如果还有 budget）
        if section_content and current_tokens < self.max_tokens:
            remaining = self.max_tokens - current_tokens
            max_chars = remaining * self.CHARS_PER_TOKEN
            context.section_content = self._truncate_text(section_content, int(max_chars))
            current_tokens += self._estimate_tokens(context.section_content)

        context.token_count = current_tokens
        return context

    def assemble_from_text(
        self,
        text: str,
        definitions: Optional[List[Dict[str, str]]] = None,
        spec_info: Optional[Dict[str, str]] = None
    ) -> MinimalContext:
        """
        从文本直接组装上下文（不需要子图）

        Args:
            text: 输入文本
            definitions: 相关定义列表
            spec_info: 规范信息

        Returns:
            MinimalContext
        """
        context = MinimalContext()
        current_tokens = 0

        # 设置规范信息
        if spec_info:
            context.spec_family = spec_info.get("family", "")
            context.spec_id = spec_info.get("id", "")
            context.section_id = spec_info.get("section", "")
            current_tokens += self._estimate_tokens(
                f"{context.spec_family} {context.spec_id} {context.section_id}"
            )

        # 添加定义
        if definitions:
            for defn in definitions:
                defn_tokens = self._estimate_tokens(
                    f"{defn.get('term', '')}: {defn.get('definition', '')}"
                )

                if current_tokens + defn_tokens <= self.max_tokens:
                    context.definitions.append(defn)
                    current_tokens += defn_tokens
                else:
                    break

        context.token_count = current_tokens
        return context

    def _sort_nodes_by_priority(self, nodes: List[SubgraphNode]) -> List[SubgraphNode]:
        """按优先级排序节点"""
        return sorted(
            nodes,
            key=lambda n: (
                self.NODE_TYPE_PRIORITY.get(n.node_type, 999),
                n.depth
            )
        )

    def _estimate_tokens(self, text: str) -> int:
        """估算 token 数"""
        return len(text) // self.CHARS_PER_TOKEN

    def _truncate_text(self, text: str, max_chars: int) -> str:
        """截断文本"""
        if len(text) <= max_chars:
            return text
        return text[:max_chars - 3] + "..."
