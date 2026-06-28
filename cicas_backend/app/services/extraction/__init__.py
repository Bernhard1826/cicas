"""
提取模块 - 初始化文件
导出所有公共接口
"""

# 核心数据结构
from .ir_schema import (
    IntermediateRepresentation,
    IRConstraint,
    IRReference,
    IRProvenance,
    ObligationType,
    PredicateType,
    ConstraintType,
    IRStage,
    ExtractionResult,
)

# Chunk 相关
from .chunk_types import (
    ChunkType,
    ExtractorType,
    StructuredChunk,
)
from .structured_chunker import StructuredChunker

# 提取器
from .base_extractor import BaseExtractor
from .template_extractor import TemplateExtractor
from .llm_extractor import LLMExtractor
from .extractor_dispatcher import ExtractorDispatcher

# 验证和处理
from .extraction_verifier import ExtractionVerifier
from .rule_assembler import RuleAssembler
from .enhanced_merger import EnhancedMerger, EnhancedDeduplicator

# IR 处理
from .ir_normalizer import IRNormalizer
from .enhanced_reference_resolver import EnhancedReferenceResolver
from .definition_expander import DefinitionExpander

# 知识图谱
from .enhanced_kg import (
    EnhancedKnowledgeGraph,
    GraphStoreInterface,
    NetworkXGraphStore,
)

# 同义词映射
from .synonym_mapper import expand_query_with_synonyms

# 新架构模块
from .rule_discovery import RuleDiscovery
from .context_builder import ContextBuilder
from .rule_skeleton_llm_extractor import RuleSkeletonLLMExtractor
from .reference_resolution_orchestrator import ReferenceResolutionOrchestrator

# 主编排器已集成到 FullPipelineExtractor，不再独立导出
# from .extraction_orchestrator import ExtractionOrchestrator

__all__ = [
    # 数据结构
    'IntermediateRepresentation',
    'IRConstraint',
    'IRReference',
    'IRProvenance',
    'ObligationType',
    'PredicateType',
    'ConstraintType',
    'IRStage',
    'ExtractionResult',
    # Chunk
    'ChunkType',
    'ExtractorType',
    'StructuredChunk',
    'StructuredChunker',
    # 提取器
    'BaseExtractor',
    'TemplateExtractor',
    'LLMExtractor',
    'ExtractorDispatcher',
    # 处理器
    'ExtractionVerifier',
    'RuleAssembler',
    'EnhancedMerger',
    'EnhancedDeduplicator',
    'IRNormalizer',
    'EnhancedReferenceResolver',
    'DefinitionExpander',
    # KG
    'EnhancedKnowledgeGraph',
    'GraphStoreInterface',
    'NetworkXGraphStore',
    # 同义词
    'expand_query_with_synonyms',
    # 新架构模块
    'RuleDiscovery',
    'ContextBuilder',
    'RuleSkeletonLLMExtractor',
    'ReferenceResolutionOrchestrator',
    # 编排器（已集成到 FullPipelineExtractor）
    # 'ExtractionOrchestrator',
]
