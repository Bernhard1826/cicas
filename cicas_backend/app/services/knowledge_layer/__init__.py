"""
Persistent Knowledge Layer

常驻知识层 - 规范知识的持久化存储和管理

设计原则：
- 规范知识不嵌入模型参数
- 更新规范不需要重新训练 LLM
- 支持版本化管理
"""
from .corpus_loader import CorpusLoader, Document
from .corpus_indexer import CorpusIndexer
from .kg_corpus_bridge import KGCorpusBridge
from .definition_store import DefinitionStore
from .update_manager import KnowledgeUpdateManager, UpdateResult
from .knowledge_initializer import (
    KnowledgeInitializer,
    initialize_knowledge_layer,
    get_knowledge_graph,
    get_knowledge_initializer,
    get_corpus_loader,
    get_corpus_indexer,
    get_definition_store,
)

__all__ = [
    "CorpusLoader",
    "Document",
    "CorpusIndexer",
    "KGCorpusBridge",
    "DefinitionStore",
    "KnowledgeUpdateManager",
    "UpdateResult",
    "KnowledgeInitializer",
    "initialize_knowledge_layer",
    "get_knowledge_graph",
    "get_knowledge_initializer",
    "get_corpus_loader",
    "get_corpus_indexer",
    "get_definition_store",
]
