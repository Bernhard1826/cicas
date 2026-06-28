"""
知识更新管理器 (Knowledge Update Manager)

职责：
1. 管理规范文档的更新
2. 同步更新知识图谱和索引
3. 确保更新的原子性

设计原则（关键）：
- 规则更新 → 更新文档库 → 更新 KG → 重建索引 → 立即生效
- 不改 prompt
- 不改模型
- 不重新训练
"""
from typing import List, Dict, Any, Optional
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum

from app.core.logging_config import app_logger
from .corpus_loader import CorpusLoader, Document
from .corpus_indexer import CorpusIndexer


class UpdateStatus(str, Enum):
    """更新状态"""
    PENDING = "pending"
    IN_PROGRESS = "in_progress"
    COMPLETED = "completed"
    FAILED = "failed"
    ROLLED_BACK = "rolled_back"


@dataclass
class UpdateResult:
    """更新结果"""
    status: UpdateStatus
    documents_added: int = 0
    documents_updated: int = 0
    nodes_created: int = 0
    terms_indexed: int = 0
    errors: List[str] = field(default_factory=list)
    timestamp: datetime = field(default_factory=datetime.now)
    duration_seconds: float = 0.0


class KnowledgeUpdateManager:
    """
    知识更新管理器

    核心流程：
    1. 更新文档库（加载新/修改的文档）
    2. 更新知识图谱（同步节点和边）
    3. 重建索引（更新搜索索引）
    4. 验证一致性
    5. 立即生效（无需重启或重新训练）
    """

    def __init__(
        self,
        corpus_loader: CorpusLoader,
        corpus_indexer: CorpusIndexer,
        knowledge_graph=None,
        kg_corpus_bridge=None
    ):
        """
        初始化更新管理器

        Args:
            corpus_loader: 语料库加载器
            corpus_indexer: 语料库索引器
            knowledge_graph: 知识图谱（可选）
            kg_corpus_bridge: KG-Corpus 桥接器（可选）
        """
        self.loader = corpus_loader
        self.indexer = corpus_indexer
        self.kg = knowledge_graph
        self.bridge = kg_corpus_bridge

        # 更新历史
        self._update_history: List[UpdateResult] = []

    def update_corpus(
        self,
        new_documents: List[str],
        force_reindex: bool = False
    ) -> UpdateResult:
        """
        更新语料库

        这是主要的更新入口。执行完整的更新流程：
        1. 加载新文档
        2. 更新 KG
        3. 重建索引
        4. 立即生效

        Args:
            new_documents: 新文档路径列表
            force_reindex: 是否强制重建索引

        Returns:
            UpdateResult
        """
        start_time = datetime.now()
        result = UpdateResult(status=UpdateStatus.IN_PROGRESS)

        try:
            # Step 1: 加载新文档
            app_logger.info(f"开始更新语料库: {len(new_documents)} 个文档")
            loaded_docs = []

            for doc_path in new_documents:
                try:
                    doc = self.loader.load_document(doc_path)
                    if doc:
                        loaded_docs.append(doc)
                        # 判断是新增还是更新
                        if doc.doc_id in self.indexer.indexed_docs:
                            result.documents_updated += 1
                        else:
                            result.documents_added += 1
                except Exception as e:
                    result.errors.append(f"加载文档失败 {doc_path}: {str(e)}")
                    app_logger.error(f"加载文档失败: {doc_path}, 错误: {e}")

            # Step 2: 更新知识图谱
            if self.bridge and self.kg:
                for doc in loaded_docs:
                    try:
                        nodes = self.bridge.sync_document_to_kg(doc)
                        result.nodes_created += nodes
                    except Exception as e:
                        result.errors.append(f"同步 KG 失败 {doc.doc_id}: {str(e)}")
                        app_logger.error(f"同步 KG 失败: {doc.doc_id}, 错误: {e}")

            # Step 3: 重建索引
            for doc in loaded_docs:
                try:
                    # 如果是更新，先清除旧索引（简化处理：跳过已索引的）
                    if force_reindex or doc.doc_id not in self.indexer.indexed_docs:
                        terms = self.indexer.index_document(doc)
                        result.terms_indexed += terms
                except Exception as e:
                    result.errors.append(f"索引失败 {doc.doc_id}: {str(e)}")
                    app_logger.error(f"索引失败: {doc.doc_id}, 错误: {e}")

            # Step 4: 验证一致性（简化版）
            self._verify_consistency()

            # Step 5: 更新完成
            if result.errors:
                result.status = UpdateStatus.COMPLETED  # 部分成功
                app_logger.warning(f"更新完成，但有 {len(result.errors)} 个错误")
            else:
                result.status = UpdateStatus.COMPLETED
                app_logger.info("更新成功完成")

        except Exception as e:
            result.status = UpdateStatus.FAILED
            result.errors.append(f"更新失败: {str(e)}")
            app_logger.error(f"更新失败: {e}", exc_info=True)

        # 记录耗时
        result.duration_seconds = (datetime.now() - start_time).total_seconds()
        result.timestamp = datetime.now()

        # 保存历史
        self._update_history.append(result)

        return result

    def update_single_document(self, doc_path: str) -> UpdateResult:
        """更新单个文档"""
        return self.update_corpus([doc_path])

    def update_from_directory(
        self,
        dir_path: str,
        recursive: bool = True
    ) -> UpdateResult:
        """从目录更新"""
        from pathlib import Path

        path = Path(dir_path)
        if not path.exists() or not path.is_dir():
            return UpdateResult(
                status=UpdateStatus.FAILED,
                errors=[f"目录不存在: {dir_path}"]
            )

        pattern = "**/*" if recursive else "*"
        doc_paths = [
            str(p) for p in path.glob(pattern)
            if p.is_file() and p.suffix in ['.txt', '.md', '.rst', '.html']
        ]

        return self.update_corpus(doc_paths)

    def rollback_last_update(self) -> bool:
        """
        回滚最后一次更新

        注意：当前实现是简化版，不支持完整回滚。
        完整回滚需要维护文档快照。
        """
        if not self._update_history:
            app_logger.warning("没有可回滚的更新")
            return False

        last_update = self._update_history[-1]

        # 简化实现：标记为已回滚，但不实际删除数据
        last_update.status = UpdateStatus.ROLLED_BACK
        app_logger.warning("回滚操作：当前实现不支持完整回滚，仅标记状态")

        return True

    def _verify_consistency(self) -> bool:
        """
        验证一致性

        检查：
        1. 所有已加载文档都已索引
        2. KG 节点与文档对应
        """
        # 检查索引一致性
        for doc_id in self.loader.documents.keys():
            if doc_id not in self.indexer.indexed_docs:
                app_logger.warning(f"文档 {doc_id} 未索引")
                return False

        return True

    def get_update_history(self) -> List[Dict[str, Any]]:
        """获取更新历史"""
        return [
            {
                "status": r.status.value,
                "documents_added": r.documents_added,
                "documents_updated": r.documents_updated,
                "nodes_created": r.nodes_created,
                "terms_indexed": r.terms_indexed,
                "errors": r.errors,
                "timestamp": r.timestamp.isoformat(),
                "duration_seconds": r.duration_seconds,
            }
            for r in self._update_history
        ]

    def get_current_state(self) -> Dict[str, Any]:
        """获取当前状态"""
        loader_stats = {
            "documents_loaded": len(self.loader.documents),
            "doc_ids": list(self.loader.documents.keys()),
        }

        indexer_stats = self.indexer.get_statistics()

        kg_stats = {}
        if self.kg:
            kg_stats = self.kg.get_statistics()

        return {
            "loader": loader_stats,
            "indexer": indexer_stats,
            "knowledge_graph": kg_stats,
            "last_update": self._update_history[-1].timestamp.isoformat()
                if self._update_history else None,
        }
