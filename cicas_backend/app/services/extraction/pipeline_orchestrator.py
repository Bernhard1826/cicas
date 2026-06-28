"""
提取流水线编排器 (Extraction Pipeline Orchestrator)

职责：
1. 协调各模块的调用顺序
2. 管理上下文流转
3. 确保职责边界清晰

关键设计原则：
- LLM Extractor = 纯 parser，只消费上下文，不决定上下文
- GraphRAG = 独立模块，可被替换
- 上下文来源可审计

调用链：
    Pipeline Orchestrator
      ├── SentencePreprocessor
      ├── SpecContextManager
      ├── GraphRAG (SubgraphExtractor + ContextAssembler)
      └── ControlledLLMExtractor(text, context)  # 只接收，不检索
"""
from typing import List, Optional, Dict, Any
from dataclasses import dataclass, field
from datetime import datetime

from app.core.logging_config import app_logger

from app.services.extraction.ir_schema import ExtractionResult
from app.services.extraction.sentence_preprocessor import (
    SentencePreprocessor,
    AtomicSentence,
)
from app.services.spec_context.context_manager import (
    SpecificationContextManager,
    SpecFamily,
)
from app.services.graph_retrieval.subgraph_extractor import SubgraphExtractor
from app.services.graph_retrieval.context_assembler import (
    ContextAssembler,
    MinimalContext,
)


@dataclass
class StructuredContext:
    """
    结构化上下文 - LLM Extractor 的输入

    这是 GraphRAG 输出的标准格式，确保：
    1. 上下文来源可审计
    2. LLM 只消费，不生成上下文
    3. 可追溯每个上下文片段的来源
    """
    # 规范体系信息
    spec_family: SpecFamily
    spec_id: Optional[str] = None
    section_id: Optional[str] = None

    # 上下文内容
    definitions: List[Dict[str, Any]] = field(default_factory=list)
    fields: List[Dict[str, Any]] = field(default_factory=list)
    related_sections: List[Dict[str, Any]] = field(default_factory=list)

    # 元信息
    token_count: int = 0
    retrieval_method: str = "graphrag"  # graphrag | fallback | manual
    retrieval_timestamp: Optional[datetime] = None

    # 审计信息
    source_nodes: List[str] = field(default_factory=list)  # KG 节点 ID 列表

    def to_prompt_string(self) -> str:
        """转换为 LLM prompt 格式"""
        lines = []

        lines.append("=== SPECIFICATION CONTEXT ===")
        lines.append(f"Spec Family: {self.spec_family.value}")
        if self.spec_id:
            lines.append(f"Document: {self.spec_id}")
        if self.section_id:
            lines.append(f"Section: {self.section_id}")
        lines.append("")

        if self.definitions:
            lines.append("=== DEFINITIONS (verbatim from specification) ===")
            for defn in self.definitions:
                term = defn.get("term", "")
                definition = defn.get("definition", "")
                source = defn.get("source", "")
                lines.append(f"- \"{term}\": {definition}")
                if source:
                    lines.append(f"  [Source: {source}]")
            lines.append("")

        if self.fields:
            lines.append("=== CERTIFICATE FIELDS ===")
            for f in self.fields:
                name = f.get("name", "")
                desc = f.get("description", "")
                lines.append(f"- {name}: {desc}")
            lines.append("")

        if not self.definitions and not self.fields:
            lines.append("No additional context provided.")

        return "\n".join(lines)


class ExtractionPipelineOrchestrator:
    """
    提取流水线编排器

    职责：
    1. 协调 Preprocessor → SpecContext → GraphRAG → LLM Extractor
    2. 确保 LLM Extractor 只是"消费者"，不做检索决策
    3. 提供可审计的上下文流转记录

    HARD CONSTRAINT:
    - LLM Extractor 签名固定为 extract(text, context) -> IR
    - 上下文由 Orchestrator 准备，不由 Extractor 自行检索
    """

    def __init__(
        self,
        knowledge_graph=None,
        use_preprocessing: bool = True,
        max_context_tokens: int = 2000,
    ):
        """
        Args:
            knowledge_graph: 知识图谱实例
            use_preprocessing: 是否启用句子预处理
            max_context_tokens: 最大上下文 token 数
        """
        self.kg = knowledge_graph
        self.use_preprocessing = use_preprocessing
        self.max_context_tokens = max_context_tokens

        # 初始化各模块（独立职责）
        self.preprocessor = SentencePreprocessor()
        self.spec_context_manager = SpecificationContextManager(
            knowledge_graph=knowledge_graph
        )
        self.subgraph_extractor = (
            SubgraphExtractor(knowledge_graph) if knowledge_graph else None
        )
        self.context_assembler = ContextAssembler(max_tokens=max_context_tokens)

        # LLM Extractor 延迟初始化（避免循环导入）
        self._llm_extractor = None

    @property
    def llm_extractor(self):
        """延迟加载 LLM Extractor"""
        if self._llm_extractor is None:
            from app.services.extraction.controlled_llm_extractor import (
                ControlledLLMExtractor,
            )
            # 注意：传入 use_internal_retrieval=False，禁用 Extractor 内部检索
            self._llm_extractor = ControlledLLMExtractor(
                knowledge_graph=self.kg,
                use_preprocessing=False,  # Orchestrator 负责预处理
                use_internal_retrieval=False,  # 禁用内部检索
            )
        return self._llm_extractor

    def extract(
        self,
        text: str,
        provenance: Optional[Dict[str, Any]] = None,
        manual_context: Optional[str] = None,
    ) -> List[ExtractionResult]:
        """
        执行完整的提取流水线

        流程：
        1. Preprocessor: 拆分多规则句子
        2. SpecContextManager: 检测规范体系
        3. GraphRAG: 检索最小上下文
        4. LLM Extractor: 结构化提取（只消费上下文）

        Args:
            text: 输入文本
            provenance: 来源信息
            manual_context: 手动提供的上下文（跳过 GraphRAG）

        Returns:
            ExtractionResult 列表
        """
        results = []

        # Step 1: 预处理（拆分多规则句子）
        if self.use_preprocessing:
            preprocess_result = self.preprocessor.preprocess(text, provenance)
            sentences = preprocess_result.sentences
        else:
            sentences = [AtomicSentence(
                text=text,
                original_text=text,
                original_index=0
            )]

        # Step 2 & 3: 对每个原子句子执行上下文检索 + LLM 提取
        for sentence in sentences:
            # 2a. 检测规范体系
            spec_family = self.spec_context_manager.detect_spec_family(sentence.text)
            spec_id = self.spec_context_manager.extract_spec_id(sentence.text)

            # 2b. 准备 provenance
            sent_provenance = sentence.provenance or provenance or {}

            # 3. 检索上下文（由 Orchestrator 负责，不是 Extractor）
            if manual_context:
                # 手动上下文模式
                structured_context = StructuredContext(
                    spec_family=spec_family,
                    spec_id=spec_id,
                    retrieval_method="manual",
                    retrieval_timestamp=datetime.now(),
                )
                context_str = manual_context
            else:
                # GraphRAG 检索模式
                structured_context = self._retrieve_context(
                    text=sentence.text,
                    spec_family=spec_family,
                    spec_id=sent_provenance.get("source_id") or spec_id,
                    section_id=sent_provenance.get("section"),
                )
                context_str = structured_context.to_prompt_string()

            # 4. 调用 LLM Extractor（只传入文本和上下文，不做检索）
            extraction_result = self.llm_extractor.extract_with_context(
                text=sentence.text,
                context=context_str,
                provenance=sent_provenance,
            )

            if extraction_result:
                results.extend(extraction_result)

            # 记录审计信息
            app_logger.debug(
                f"Pipeline: extracted {len(extraction_result) if extraction_result else 0} IRs, "
                f"context_method={structured_context.retrieval_method}, "
                f"context_tokens={structured_context.token_count}"
            )

        return results

    def _retrieve_context(
        self,
        text: str,
        spec_family: SpecFamily,
        spec_id: Optional[str],
        section_id: Optional[str],
    ) -> StructuredContext:
        """
        通过 GraphRAG 检索结构化上下文

        HARD CONSTRAINT:
        - 只检索 verbatim definitions 和 structural metadata
        - 不引入 derived 或 synthesized requirements

        Args:
            text: 输入文本
            spec_family: 规范体系
            spec_id: 规范 ID
            section_id: 章节 ID

        Returns:
            StructuredContext
        """
        structured_context = StructuredContext(
            spec_family=spec_family,
            spec_id=spec_id,
            section_id=section_id,
            retrieval_timestamp=datetime.now(),
        )

        # 尝试从 KG 检索子图
        if self.subgraph_extractor and spec_id and section_id:
            try:
                subgraph = self.subgraph_extractor.extract_from_section(
                    doc_id=spec_id,
                    section_id=section_id
                )

                if subgraph.nodes:
                    # 组装最小上下文
                    spec_info = {
                        "family": spec_family.value,
                        "id": spec_id,
                        "section": section_id,
                    }
                    minimal_context = self.context_assembler.assemble(
                        subgraph=subgraph,
                        section_content=self._get_section_content(spec_id, section_id),
                        spec_info=spec_info,
                    )

                    # 转换为 StructuredContext
                    structured_context.definitions = minimal_context.definitions
                    structured_context.fields = minimal_context.fields
                    structured_context.token_count = minimal_context.token_count
                    structured_context.source_nodes = list(subgraph.nodes.keys())
                    structured_context.retrieval_method = "graphrag"

                    app_logger.debug(
                        f"GraphRAG retrieved: {len(minimal_context.definitions)} definitions, "
                        f"{len(minimal_context.fields)} fields, "
                        f"{minimal_context.token_count} tokens"
                    )
                    return structured_context

            except Exception as e:
                app_logger.warning(f"GraphRAG retrieval failed, using fallback: {e}")

        # Fallback: 使用 SpecContextManager 的基础上下文
        fallback_context = self.spec_context_manager.get_minimal_context(text)
        if fallback_context.strip():
            structured_context.retrieval_method = "fallback"
            # 估算 token 数
            structured_context.token_count = len(fallback_context) // 4

        return structured_context

    def _get_section_content(
        self, spec_id: Optional[str], section_id: Optional[str]
    ) -> Optional[str]:
        """从语料库加载器获取章节原始内容"""
        if not spec_id or not section_id:
            return None
        try:
            from app.services.knowledge_layer.knowledge_initializer import get_corpus_loader
            loader = get_corpus_loader()
            if loader:
                doc = loader.get_document(spec_id)
                if doc:
                    section = doc.get_section(section_id)
                    if section:
                        return section.content
        except Exception:
            pass
        return None


# ======================================================================
# 便捷函数
# ======================================================================

def extract_with_pipeline(
    text: str,
    provenance: Optional[Dict[str, Any]] = None,
    knowledge_graph=None,
) -> List[ExtractionResult]:
    """
    使用流水线提取 IR（推荐入口）

    与直接调用 ControlledLLMExtractor 的区别：
    - 职责更清晰：Orchestrator 负责上下文，Extractor 只做解析
    - 可审计：上下文来源明确
    - 可替换：GraphRAG 模块可独立替换

    Args:
        text: 规范句子
        provenance: 来源信息
        knowledge_graph: 知识图谱

    Returns:
        ExtractionResult 列表
    """
    orchestrator = ExtractionPipelineOrchestrator(knowledge_graph=knowledge_graph)
    return orchestrator.extract(text, provenance=provenance)
