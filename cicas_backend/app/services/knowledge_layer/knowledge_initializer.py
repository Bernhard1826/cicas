"""
知识层初始化器 (Knowledge Initializer)

职责：
1. 系统启动时加载所有规范文档到知识层
2. 解析 RFC (.txt), CABF (.pdf), ETSI (.pdf) 文档
3. 构建索引、同步知识图谱、提取术语定义
4. 提供全局单例访问

初始化链路：
  系统启动
    -> 加载 data/raw/ 下的 RFC/CABF/ETSI 文档
    -> CorpusLoader 解析章节结构
    -> CorpusIndexer 建立索引
    -> KGCorpusBridge 同步到知识图谱
    -> DefinitionStore 提取术语定义
    -> 知识层就绪，GraphRAG 可检索

HARD CONSTRAINT:
- 所有规范知识通过此模块加载，不嵌入到 LLM 参数中
- 更新规范只需替换文件并重启，无需改 prompt 或重训练模型
"""
import re
import time
from typing import List, Dict, Any, Optional, Tuple
from pathlib import Path
from dataclasses import dataclass, field

from app.core.logging_config import app_logger
from app.services.knowledge_graph.knowledge_graph import CertificateKnowledgeGraph
from .corpus_loader import CorpusLoader, Document, Section, DocumentType
from .corpus_indexer import CorpusIndexer
from .kg_corpus_bridge import KGCorpusBridge
from .definition_store import DefinitionStore, DefinitionSource


@dataclass
class InitializationResult:
    """初始化结果"""
    success: bool = False
    rfc_loaded: int = 0
    cabf_loaded: int = 0
    etsi_loaded: int = 0
    total_sections: int = 0
    total_terms_indexed: int = 0
    total_kg_nodes: int = 0
    total_definitions: int = 0
    total_cross_references: int = 0
    errors: List[str] = field(default_factory=list)
    duration_seconds: float = 0.0


class KnowledgeInitializer:
    """
    知识层初始化器

    系统启动时调用 initialize()，完成以下工作：
    1. 加载 RFC .txt 文件
    2. 加载 CABF .pdf 文件（使用 PDFParser）
    3. 加载 ETSI .pdf 文件（仅保留每个标准的最新版本）
    4. 为所有文档建立索引
    5. 同步文档结构到知识图谱
    6. 提取术语定义
    """

    def __init__(self, data_dir: str):
        """
        Args:
            data_dir: 数据根目录（包含 raw/rfc/, raw/cabf-*/, raw/etsi/ 等）
        """
        self.data_dir = Path(data_dir)
        self.knowledge_graph = CertificateKnowledgeGraph()
        self.corpus_loader = CorpusLoader(data_dir)
        self.corpus_indexer = CorpusIndexer()
        self.definition_store = DefinitionStore()
        self.bridge = KGCorpusBridge(
            self.knowledge_graph,
            self.corpus_loader,
            self.corpus_indexer
        )

        self._initialized = False

    @property
    def is_initialized(self) -> bool:
        return self._initialized

    def initialize(self, use_cache: bool = True) -> InitializationResult:
        """
        执行完整初始化流程（内存优化版本）

        Args:
            use_cache: 是否使用缓存（默认 True）

        Returns:
            InitializationResult
        """
        import gc
        import pickle
        import hashlib

        start_time = time.time()
        result = InitializationResult()

        # 尝试从缓存加载
        if use_cache:
            cache_result = self._load_from_cache()
            if cache_result:
                app_logger.info("=" * 60)
                app_logger.info("Knowledge Layer Initialization - LOADED FROM CACHE")
                app_logger.info("=" * 60)
                cache_result.duration_seconds = time.time() - start_time
                self._initialized = True
                return cache_result

        app_logger.info("=" * 60)
        app_logger.info("Knowledge Layer Initialization - START (Memory Optimized)")
        app_logger.info("=" * 60)

        # 分批处理文档以减少内存峰值
        all_docs = []

        # Step 1: 加载 RFC 文档
        app_logger.info("Loading RFC documents...")
        rfc_docs = self._load_rfc_documents(result)
        result.rfc_loaded = len(rfc_docs)
        all_docs.extend(rfc_docs)

        # 处理 RFC 文档后立即进行垃圾回收
        self._process_documents_batch(rfc_docs, result)
        del rfc_docs
        gc.collect()

        # Step 2: 加载 CABF 文档
        app_logger.info("Loading CABF documents...")
        cabf_docs = self._load_cabf_documents(result)
        result.cabf_loaded = len(cabf_docs)
        all_docs.extend(cabf_docs)

        # 处理 CABF 文档后立即进行垃圾回收
        self._process_documents_batch(cabf_docs, result)
        del cabf_docs
        gc.collect()

        # Step 3: 加载 ETSI 文档（仅最新版本）
        app_logger.info("Loading ETSI documents...")
        etsi_docs = self._load_etsi_documents(result)
        result.etsi_loaded = len(etsi_docs)
        all_docs.extend(etsi_docs)

        # 处理 ETSI 文档后立即进行垃圾回收
        self._process_documents_batch(etsi_docs, result)
        del etsi_docs
        gc.collect()

        # Step 3b: 加载 Mozilla MRSP 文档
        app_logger.info("Loading Mozilla documents...")
        mozilla_docs = self._load_mozilla_documents(result)
        all_docs.extend(mozilla_docs)

        # 处理 Mozilla 文档后立即进行垃圾回收
        self._process_documents_batch(mozilla_docs, result)
        del mozilla_docs
        gc.collect()

        # Step 6: 提取术语定义（分批处理）
        app_logger.info("Extracting term definitions...")
        for i, doc in enumerate(all_docs):
            try:
                definitions = self._extract_definitions(doc)
                result.total_definitions += definitions
                app_logger.info(f"  Definitions extracted from {doc.doc_id}: {definitions}")

                # 每处理5个文档进行一次垃圾回收
                if (i + 1) % 5 == 0:
                    gc.collect()
            except Exception as e:
                result.errors.append(f"Definition extraction failed for {doc.doc_id}: {e}")
                app_logger.error(f"术语定义提取失败: {doc.doc_id}: {e}")

        # Step 7: 加载语义标注（如果存在）
        annotations_dir = self.data_dir / "semantic_annotations"
        if annotations_dir.exists() and any(annotations_dir.glob("*.json")):
            app_logger.info("Loading semantic annotations...")
            try:
                from app.services.knowledge_graph.semantic_annotation_loader import load_semantic_annotations
                n_annotations = load_semantic_annotations(
                    self.knowledge_graph, str(annotations_dir)
                )
                app_logger.info(f"  Semantic annotations loaded: {n_annotations} nodes")
            except Exception as e:
                result.errors.append(f"Semantic annotation loading failed: {e}")
                app_logger.error(f"语义标注加载失败: {e}")

        # 最终垃圾回收
        gc.collect()

        # 完成初始化
        result.success = len(result.errors) == 0
        result.duration = time.time() - start_time

        app_logger.info("=" * 60)
        app_logger.info(f"Knowledge Layer Initialization - {'SUCCESS' if result.success else 'PARTIAL'}")
        app_logger.info(f"Duration: {result.duration:.2f}s")
        app_logger.info(f"Documents: RFC={result.rfc_loaded}, CABF={result.cabf_loaded}, ETSI={result.etsi_loaded}")
        app_logger.info(f"Sections: {result.total_sections}, Terms: {result.total_terms_indexed}")
        app_logger.info(f"KG Nodes: {result.total_kg_nodes}, Definitions: {result.total_definitions}")
        if result.errors:
            app_logger.warning(f"Errors: {len(result.errors)}")
        app_logger.info("=" * 60)

        # 保存到缓存
        if use_cache and result.success:
            self._save_to_cache(result)

        self._initialized = True
        return result

    def _process_documents_batch(self, docs: List[Document], result: InitializationResult):
        """
        处理一批文档：索引 + 同步到知识图谱
        """
        import gc

        # Step 4: 索引文档
        for doc in docs:
            try:
                terms = self.corpus_indexer.index_document(doc)
                result.total_terms_indexed += terms
            except Exception as e:
                result.errors.append(f"Index failed for {doc.doc_id}: {e}")
                app_logger.error(f"索引文档失败: {doc.doc_id}: {e}")

        # Step 5: 同步到知识图谱
        for doc in docs:
            try:
                nodes = self.bridge.sync_document_to_kg(doc)
                result.total_kg_nodes += nodes
                result.total_sections += len(doc.sections)
            except Exception as e:
                result.errors.append(f"KG sync failed for {doc.doc_id}: {e}")
                app_logger.error(f"同步 KG 失败: {doc.doc_id}: {e}")

        # 批处理后垃圾回收
        gc.collect()
    # ====================================================================
    # RFC 加载
    # ====================================================================

    def _load_rfc_documents(self, result: InitializationResult) -> List[Document]:
        """加载 data/raw/rfc/ 下的必要 RFC .txt 文件（仅加载实验需要的）"""
        rfc_dir = self.data_dir / "raw" / "rfc"
        if not rfc_dir.exists():
            app_logger.warning(f"RFC directory not found: {rfc_dir}")
            return []

        # 自动加载所有RFC文档
        required_rfcs = [f.name for f in rfc_dir.glob("rfc*.txt") if f.is_file()]
        required_rfcs.sort()  # 按文件名排序

        docs = []
        for rfc_name in required_rfcs:
            txt_file = rfc_dir / rfc_name
            if txt_file.exists():
                try:
                    doc = self.corpus_loader.load_document(
                        str(txt_file),
                        doc_type=DocumentType.RFC
                    )
                    if doc:
                        docs.append(doc)
                        app_logger.info(f"  Loaded RFC: {doc.doc_id} ({len(doc.sections)} sections)")
                except Exception as e:
                    result.errors.append(f"Failed to load RFC {txt_file.name}: {e}")
                    app_logger.error(f"加载 RFC 失败: {txt_file.name}: {e}")
            else:
                app_logger.warning(f"Required RFC not found: {txt_file}")

        app_logger.info(f"RFC loading complete: {len(docs)} documents (minimal set)")
        return docs

    # ====================================================================
    # CABF 加载
    # ====================================================================

    def _load_cabf_documents(self, result: InitializationResult) -> List[Document]:
        """加载 CABF BR 文档（规则提取所用的同一来源 BR.md）。

        规则从 data/raw/cabf-server/BR.md（standards.file_path）抽取，章节号为
        Markdown 标题里的 7.1.2.x。这里用 corpus_loader.load_document 按 Markdown
        解析（doc_id 规范化为 CABF-BR），使 KG 拥有 section:CABF-BR:7.1.2.x 节点，
        GraphRAG 才能解析 CABF 引用。旧实现钉死在一个不存在的 PDF 文件名
        (CA-Browser-Forum-TLS-BR-2.2.2.pdf) → 加载 0 篇 → CABF 抽取全程缺上下文。
        """
        docs = []
        cabf_dir = self.data_dir / "raw" / "cabf-server"
        # 优先 BR.md（规则抽取的同一来源），回退到带版本号的 md
        for name in ("BR.md", "cabf-server_v2_2_6.md"):
            f = cabf_dir / name
            if not f.exists():
                continue
            try:
                doc = self.corpus_loader.load_document(str(f), doc_type=DocumentType.CABF_BR)
                if doc and doc.sections:
                    docs.append(doc)
                    self.corpus_loader.documents[doc.doc_id] = doc
                    app_logger.info(
                        f"  Loaded CABF: {doc.doc_id} from {name} ({len(doc.sections)} sections)"
                    )
                    break  # one canonical BR document is enough
            except Exception as e:
                result.errors.append(f"Failed to load CABF {name}: {e}")
                app_logger.error(f"加载 CABF 失败: {name}: {e}")

        if not docs:
            app_logger.warning(f"No CABF BR document loaded from {cabf_dir}")

        app_logger.info(f"CABF loading complete: {len(docs)} documents")
        return docs

    # ====================================================================
    # ETSI 加载（仅最新版本）
    # ====================================================================

    def _load_etsi_documents(self, result: InitializationResult) -> List[Document]:
        """加载 data/raw/etsi/ 下的必要 ETSI PDF 文件（仅实验需要的）"""
        etsi_dir = self.data_dir / "raw" / "etsi"
        if not etsi_dir.exists():
            app_logger.warning(f"ETSI directory not found: {etsi_dir}")
            return []

        # 只加载实验需要的ETSI文档
        required_etsi = ["EN_319_412-4_v1_4_1.pdf"]  # 只加载EN 319 412-4

        docs = []
        for pdf_name in required_etsi:
            pdf_file = etsi_dir / pdf_name
            if pdf_file.exists():
                try:
                    doc = self._load_pdf_as_document(pdf_file, DocumentType.ETSI)
                    if doc:
                        docs.append(doc)
                        self.corpus_loader.documents[doc.doc_id] = doc
                        app_logger.info(
                            f"  Loaded ETSI: {doc.doc_id} ({len(doc.sections)} sections)"
                        )
                except Exception as e:
                    result.errors.append(f"Failed to load ETSI {pdf_file.name}: {e}")
                    app_logger.error(f"加载 ETSI 失败: {pdf_file.name}: {e}")
            else:
                app_logger.warning(f"Required ETSI PDF not found: {pdf_file}")

        app_logger.info(f"ETSI loading complete: {len(docs)} documents (minimal set)")
        return docs

    def _load_mozilla_documents(self, result: InitializationResult) -> List[Document]:
        """加载 data/raw/browser_ca/mozilla/policy.html 作为 Mozilla MRSP 文档"""
        html_path = self.data_dir / "raw" / "browser_ca" / "mozilla" / "policy.html"
        if not html_path.exists():
            app_logger.warning(f"Mozilla MRSP not found: {html_path}")
            return []

        try:
            raw_text = html_path.read_text(encoding="utf-8")

            # 用简单的 HTML 解析提取章节
            sections = self._parse_mozilla_html(raw_text)
            if not sections:
                app_logger.warning("Mozilla MRSP: no sections extracted")
                return []

            # 生成纯文本（去除 HTML 标签）
            import html as html_mod
            clean_text = re.sub(r'<[^>]+>', '', raw_text)
            clean_text = html_mod.unescape(clean_text)
            # 合并多余空行
            clean_text = re.sub(r'\n{3,}', '\n\n', clean_text).strip()

            doc = Document(
                doc_id="Mozilla-MRSP",
                doc_type=DocumentType.MOZILLA,
                title="Mozilla Root Store Policy",
                version="latest",
                sections=sections,
                raw_text=clean_text,
                metadata={"source": str(html_path)},
                file_path=str(html_path),
            )
            self.corpus_loader.documents[doc.doc_id] = doc
            app_logger.info(
                f"  Loaded Mozilla: {doc.doc_id} ({len(doc.sections)} sections)"
            )
            return [doc]
        except Exception as e:
            result.errors.append(f"Failed to load Mozilla MRSP: {e}")
            app_logger.error(f"加载 Mozilla MRSP 失败: {e}")
            return []

    def _parse_mozilla_html(self, html_text: str) -> Dict[str, "Section"]:
        """
        解析 Mozilla MRSP HTML，提取章节结构。

        HTML 结构: <h2 id="5-certificates">5. Certificates</h2>
                   <h3 id="51-algorithms">5.1 Algorithms</h3>

        使用 BeautifulSoup 进行健壮的 HTML 解析。
        """
        try:
            from bs4 import BeautifulSoup
        except ImportError:
            app_logger.warning("BeautifulSoup not available, falling back to regex parser")
            return self._parse_mozilla_html_regex(html_text)

        sections: Dict[str, Section] = {}

        soup = BeautifulSoup(html_text, 'html.parser')

        # 找到所有标题标签 (h1-h6)
        headings = soup.find_all(['h1', 'h2', 'h3', 'h4', 'h5', 'h6'])

        for i, heading in enumerate(headings):
            # 提取章节号和标题
            heading_text = heading.get_text(strip=True)

            # 匹配章节号格式: "5. Certificates" 或 "5.1 Algorithms"
            section_match = re.match(r'^([\d.]+)\s*\.?\s*(.*?)$', heading_text)
            if not section_match:
                continue

            section_num = section_match.group(1).rstrip('.')
            title = section_match.group(2).strip()

            # 安全提取 heading level，只处理 h1-h6
            if not heading.name or not heading.name.startswith('h') or len(heading.name) != 2:
                continue
            try:
                level = int(heading.name[1])  # h2->2, h3->3, etc.
            except (ValueError, IndexError):
                continue

            # 提取内容: 从当前标题后到下一个同级或更高级标题
            content_parts = []
            current = heading.find_next_sibling()

            while current:
                # 如果遇到标题，检查是否应该停止
                if current.name and current.name.startswith('h') and len(current.name) == 2:
                    try:
                        next_level = int(current.name[1])
                        if next_level <= level:
                            break
                    except (ValueError, IndexError):
                        pass

                # 收集文本内容
                if current.name in ['p', 'ul', 'ol', 'div', 'pre', 'blockquote']:
                    text = current.get_text(separator=' ', strip=True)
                    if text:
                        content_parts.append(text)
                elif current.name and current.name.startswith('h') and len(current.name) == 2:
                    # 子标题，继续收集
                    pass

                current = current.find_next_sibling()

            content = '\n\n'.join(content_parts)

            # 确定 parent
            parent_id = None
            parts = section_num.split('.')
            if len(parts) > 1:
                parent_id = '.'.join(parts[:-1])

            sections[section_num] = Section(
                section_id=section_num,
                title=title,
                content=content,
                level=level,
                parent_id=parent_id,
            )

        return sections

    def _parse_mozilla_html_regex(self, html_text: str) -> Dict[str, "Section"]:
        """
        正则表达式版本的 Mozilla HTML 解析器（备用）。
        """
        import html as html_mod

        sections: Dict[str, Section] = {}

        # 找到所有 heading 标签及其后续内容
        heading_pattern = re.compile(
            r'<(h[1-6])[^>]*>\s*([\d.]+)\s*\.?\s*(.*?)\s*</\1>',
            re.IGNORECASE | re.DOTALL
        )

        matches = list(heading_pattern.finditer(html_text))
        for i, match in enumerate(matches):
            tag = match.group(1).lower()
            section_num = match.group(2).rstrip('.')
            title_raw = re.sub(r'<[^>]+>', '', match.group(3))
            title = html_mod.unescape(title_raw).strip()
            level = int(tag[1])  # h2->2, h3->3, etc.

            # 内容: 从当前 heading 末尾到下一个 heading 开头
            start = match.end()
            end = matches[i + 1].start() if i + 1 < len(matches) else len(html_text)
            content_html = html_text[start:end]

            # 清理 HTML 标签
            content = re.sub(r'<[^>]+>', ' ', content_html)
            content = html_mod.unescape(content)
            content = re.sub(r' +', ' ', content).strip()
            content = re.sub(r'\n +', '\n', content)

            # 确定 parent
            parent_id = None
            parts = section_num.split('.')
            if len(parts) > 1:
                parent_id = '.'.join(parts[:-1])

            sections[section_num] = Section(
                section_id=section_num,
                title=title,
                content=content,
                level=level,
                parent_id=parent_id,
            )

        return sections

    def _filter_latest_etsi(self, pdf_files: List[Path]) -> List[Path]:
        """
        过滤 ETSI 文件，仅保留每个标准编号的最新版本

        文件命名规则: EN_319_412-1_v1_6_1.pdf
        标准编号:     EN_319_412-1
        版本号:       v1_6_1 -> (1, 6, 1)
        """
        # 按标准编号分组
        grouped: Dict[str, List[Tuple[Path, Tuple[int, ...]]]] = {}

        for pdf in pdf_files:
            stem = pdf.stem  # e.g. "EN_319_412-1_v1_6_1"

            # 提取标准编号和版本号
            version_match = re.search(r'_v(\d+)_(\d+)_(\d+)$', stem)
            if version_match:
                standard_id = stem[:version_match.start()]
                version = (
                    int(version_match.group(1)),
                    int(version_match.group(2)),
                    int(version_match.group(3)),
                )
            else:
                standard_id = stem
                version = (0, 0, 0)

            if standard_id not in grouped:
                grouped[standard_id] = []
            grouped[standard_id].append((pdf, version))

        # 取每组的最新版本
        latest = []
        for standard_id, versions in grouped.items():
            versions.sort(key=lambda x: x[1], reverse=True)
            latest_file, latest_version = versions[0]
            latest.append(latest_file)

            if len(versions) > 1:
                app_logger.info(
                    f"  ETSI {standard_id}: kept v{'_'.join(map(str, latest_version))}, "
                    f"skipped {len(versions) - 1} older versions"
                )

        return sorted(latest)

    # ====================================================================
    # 缓存机制
    # ====================================================================

    def _get_cache_path(self) -> Path:
        """获取缓存文件路径"""
        cache_dir = self.data_dir / ".cache"
        cache_dir.mkdir(exist_ok=True)
        return cache_dir / "knowledge_layer.pkl"

    def _get_cache_metadata_path(self) -> Path:
        """获取缓存元数据路径"""
        cache_dir = self.data_dir / ".cache"
        cache_dir.mkdir(exist_ok=True)
        return cache_dir / "knowledge_layer_metadata.json"

    def _compute_data_hash(self) -> str:
        """
        计算数据目录的哈希值，用于检测文件变化

        只检查文件的修改时间和大小，不读取文件内容（性能优化）
        """
        import hashlib
        import json

        hash_data = {}

        # 检查 RFC 文件
        rfc_dir = self.data_dir / "raw" / "rfc"
        if rfc_dir.exists():
            for txt_file in sorted(rfc_dir.glob("*.txt")):
                stat = txt_file.stat()
                hash_data[str(txt_file.relative_to(self.data_dir))] = {
                    'mtime': stat.st_mtime,
                    'size': stat.st_size,
                }

        # 检查 CABF 文件
        for cabf_subdir in ["cabf-server", "cabf-ev", "cabf-smime", "cabf-netsec"]:
            cabf_dir = self.data_dir / "raw" / cabf_subdir
            if cabf_dir.exists():
                for pdf_file in sorted(cabf_dir.glob("*.pdf")):
                    stat = pdf_file.stat()
                    hash_data[str(pdf_file.relative_to(self.data_dir))] = {
                        'mtime': stat.st_mtime,
                        'size': stat.st_size,
                    }

        # 检查 ETSI 文件
        etsi_dir = self.data_dir / "raw" / "etsi"
        if etsi_dir.exists():
            for pdf_file in sorted(etsi_dir.glob("*.pdf")):
                stat = pdf_file.stat()
                hash_data[str(pdf_file.relative_to(self.data_dir))] = {
                    'mtime': stat.st_mtime,
                    'size': stat.st_size,
                }

        # 检查 Mozilla 文件
        mozilla_file = self.data_dir / "raw" / "browser_ca" / "mozilla" / "policy.html"
        if mozilla_file.exists():
            stat = mozilla_file.stat()
            hash_data[str(mozilla_file.relative_to(self.data_dir))] = {
                'mtime': stat.st_mtime,
                'size': stat.st_size,
            }

        # 计算哈希
        hash_str = json.dumps(hash_data, sort_keys=True)
        return hashlib.sha256(hash_str.encode()).hexdigest()

    def _save_to_cache(self, result: InitializationResult) -> bool:
        """
        保存初始化结果到缓存

        Returns:
            是否保存成功
        """
        try:
            import pickle
            import json

            cache_path = self._get_cache_path()
            metadata_path = self._get_cache_metadata_path()

            # 保存元数据
            metadata = {
                'data_hash': self._compute_data_hash(),
                'timestamp': time.time(),
                'result': {
                    'success': result.success,
                    'rfc_loaded': result.rfc_loaded,
                    'cabf_loaded': result.cabf_loaded,
                    'etsi_loaded': result.etsi_loaded,
                    'total_sections': result.total_sections,
                    'total_terms_indexed': result.total_terms_indexed,
                    'total_kg_nodes': result.total_kg_nodes,
                    'total_definitions': result.total_definitions,
                    'total_cross_references': result.total_cross_references,
                }
            }

            with open(metadata_path, 'w') as f:
                json.dump(metadata, f, indent=2)

            # 保存缓存数据
            cache_data = {
                'corpus_loader_documents': self.corpus_loader.documents,
                'corpus_indexer_inverted_index': self.corpus_indexer.inverted_index,
                'corpus_indexer_term_index': self.corpus_indexer.term_index,
                'corpus_indexer_reference_index': self.corpus_indexer.reference_index,
                'corpus_indexer_indexed_docs': self.corpus_indexer.indexed_docs,
                'definition_store_definitions': self.definition_store._definitions,
                'definition_store_by_source': self.definition_store._by_source,
                'result': result,
            }

            with open(cache_path, 'wb') as f:
                pickle.dump(cache_data, f, protocol=pickle.HIGHEST_PROTOCOL)

            app_logger.info(f"Saved knowledge layer cache to {cache_path}")
            return True

        except Exception as e:
            app_logger.warning(f"Failed to save cache: {e}")
            return False

    def _load_from_cache(self) -> Optional[InitializationResult]:
        """
        从缓存加载初始化结果

        Returns:
            InitializationResult if cache is valid, None otherwise
        """
        try:
            import pickle
            import json

            cache_path = self._get_cache_path()
            metadata_path = self._get_cache_metadata_path()

            # 检查缓存文件是否存在
            if not cache_path.exists() or not metadata_path.exists():
                return None

            # 读取元数据
            with open(metadata_path, 'r') as f:
                metadata = json.load(f)

            # 验证数据哈希
            current_hash = self._compute_data_hash()
            if metadata.get('data_hash') != current_hash:
                app_logger.info("Cache invalidated: data files have changed")
                return None

            # 加载缓存数据
            with open(cache_path, 'rb') as f:
                cache_data = pickle.load(f)

            # 恢复状态
            self.corpus_loader.documents = cache_data['corpus_loader_documents']
            self.corpus_indexer.inverted_index = cache_data['corpus_indexer_inverted_index']
            self.corpus_indexer.term_index = cache_data['corpus_indexer_term_index']
            self.corpus_indexer.reference_index = cache_data['corpus_indexer_reference_index']
            self.corpus_indexer.indexed_docs = cache_data['corpus_indexer_indexed_docs']
            self.definition_store._definitions = cache_data['definition_store_definitions']
            self.definition_store._by_source = cache_data['definition_store_by_source']

            # 重新同步到知识图谱（KG 不缓存，因为它是轻量级的）
            for doc in self.corpus_loader.documents.values():
                self.bridge.sync_document_to_kg(doc)

            result = cache_data['result']
            app_logger.info(f"Loaded knowledge layer from cache (saved at {time.ctime(metadata['timestamp'])})")

            return result

        except Exception as e:
            app_logger.warning(f"Failed to load cache: {e}")
            return None

    def clear_cache(self) -> bool:
        """
        清除缓存文件

        Returns:
            是否清除成功
        """
        try:
            cache_path = self._get_cache_path()
            metadata_path = self._get_cache_metadata_path()

            if cache_path.exists():
                cache_path.unlink()
            if metadata_path.exists():
                metadata_path.unlink()

            app_logger.info("Cache cleared")
            return True

        except Exception as e:
            app_logger.warning(f"Failed to clear cache: {e}")
            return False

    # ====================================================================
    # PDF 加载辅助
    # ====================================================================

    def _load_pdf_as_document(
        self,
        pdf_path: Path,
        doc_type: DocumentType
    ) -> Optional[Document]:
        """
        使用 PDFParser 解析 PDF，转换为 Document 对象

        Args:
            pdf_path: PDF 文件路径
            doc_type: 文档类型

        Returns:
            Document 或 None
        """
        try:
            from app.services.parsers.pdf_parser import PDFParser
        except ImportError:
            app_logger.error("PDFParser not available, cannot load PDF")
            return None

        parser = PDFParser()
        chunks = parser.parse_pdf(pdf_path)

        if not chunks:
            app_logger.warning(f"No sections extracted from PDF: {pdf_path.name}")
            return None

        # 从文件名提取文档 ID
        doc_id = self._extract_pdf_doc_id(pdf_path, doc_type)

        # 从文件名提取标题
        title = pdf_path.stem.replace("_", " ").replace("-", " ")

        # 将 chunks 转为 Section 对象
        sections: Dict[str, Section] = {}
        for chunk in chunks:
            section_id = chunk.get("section", "")
            if not section_id:
                continue

            sections[section_id] = Section(
                section_id=section_id,
                title=chunk.get("title", ""),
                content=chunk.get("text", ""),
                level=section_id.count(".") + 1,
                line_start=chunk.get("line_number"),
            )

        # 构建完整文本（用于搜索）
        raw_text = "\n\n".join(
            f"{s.section_id} {s.title}\n{s.content}"
            for s in sections.values()
        )

        doc = Document(
            doc_id=doc_id,
            doc_type=doc_type,
            title=title,
            sections=sections,
            raw_text=raw_text,
            file_path=str(pdf_path),
        )

        return doc

    def _extract_pdf_doc_id(self, pdf_path: Path, doc_type: DocumentType) -> str:
        """从 PDF 文件名提取文档 ID"""
        stem = pdf_path.stem

        if doc_type in (DocumentType.CABF_BR, DocumentType.CABF_EVG,
                        DocumentType.CABF_SMIME):
            # CA-Browser-Forum-TLS-BR-2.2.2 -> CABF-TLS-BR-2.2.2
            # CA-Browser-Forum-EV-Guidelines-2.0.1 -> CABF-EVG-2.0.1
            # CA-Browser-Forum-SMIMEBR-1.0.12 -> CABF-SMIMEBR-1.0.12
            # CA-Browser-Forum-FG-NCSSR-2.0.5 -> CABF-NCSSR-2.0.5
            cleaned = stem.replace("CA-Browser-Forum-", "CABF-")
            cleaned = cleaned.replace("FG-", "")
            return cleaned

        if doc_type == DocumentType.ETSI:
            # EN_319_412-1_v1_6_1 -> ETSI-EN-319-412-1
            # TS_102_042_v2_4_1 -> ETSI-TS-102-042
            # Remove version suffix
            no_version = re.sub(r'_v\d+_\d+_\d+$', '', stem)
            parts = no_version.split("_")
            return "ETSI-" + "-".join(parts)

        return stem.upper()

    # ====================================================================
    # 术语定义提取
    # ====================================================================

    def _extract_definitions(self, doc: Document) -> int:
        """
        从文档中提取术语定义

        查找常见的定义模式：
        - "Term" means ...
        - Term: definition
        - Term - definition
        """
        # 确定来源
        source_map = {
            DocumentType.RFC: DefinitionSource.RFC,
            DocumentType.CABF_BR: DefinitionSource.CABF,
            DocumentType.CABF_EVG: DefinitionSource.CABF,
            DocumentType.CABF_SMIME: DefinitionSource.CABF,
            DocumentType.ETSI: DefinitionSource.ETSI,
        }
        source = source_map.get(doc.doc_type, DefinitionSource.CUSTOM)

        count = 0
        definition_patterns = [
            # "term" means/refers to/is defined as ...
            re.compile(
                r'"([^"]{3,60})"\s+(?:means|refers to|is defined as)\s+(.{10,500}?)(?:\.|$)',
                re.IGNORECASE
            ),
            # Term: definition (at the start of a line, capitalized)
            re.compile(
                r'^([A-Z][A-Za-z\s]{2,40}):\s+(.{10,500}?)(?:\.|$)',
                re.MULTILINE
            ),
        ]

        for section_id, section in doc.sections.items():
            for pattern in definition_patterns:
                matches = pattern.findall(section.content)
                for term, definition in matches:
                    term = term.strip()
                    definition = definition.strip()

                    # 过滤太短或太长的定义
                    if len(definition) < 10 or len(term) < 2:
                        continue

                    self.definition_store.add_definition(
                        term=term,
                        definition=definition,
                        source=source,
                        doc_id=doc.doc_id,
                        section_id=section_id,
                    )

                    # 同步到 KG
                    try:
                        self.bridge.sync_definition_to_kg(
                            term=term,
                            definition=definition,
                            doc_id=doc.doc_id,
                            section_id=section_id,
                        )
                    except Exception:
                        pass  # 非关键操作，不阻断

                    count += 1

        return count

    def get_status(self) -> Dict[str, Any]:
        """获取知识层状态"""
        return {
            "initialized": self._initialized,
            "documents_loaded": len(self.corpus_loader.documents),
            "doc_ids": list(self.corpus_loader.documents.keys()),
            "indexer": self.corpus_indexer.get_statistics(),
            "definitions": self.definition_store.get_statistics(),
            "knowledge_graph": self.knowledge_graph.get_statistics(),
        }


# ======================================================================
# 全局单例
# ======================================================================

_global_initializer: Optional[KnowledgeInitializer] = None


def get_knowledge_initializer() -> Optional[KnowledgeInitializer]:
    """获取全局知识层初始化器实例"""
    return _global_initializer


def get_knowledge_graph() -> Optional[CertificateKnowledgeGraph]:
    """获取全局知识图谱实例"""
    if _global_initializer:
        return _global_initializer.knowledge_graph
    return None


def get_corpus_loader() -> Optional[CorpusLoader]:
    """获取全局语料库加载器"""
    if _global_initializer:
        return _global_initializer.corpus_loader
    return None


def get_corpus_indexer() -> Optional[CorpusIndexer]:
    """获取全局语料库索引器"""
    if _global_initializer:
        return _global_initializer.corpus_indexer
    return None


def get_definition_store() -> Optional[DefinitionStore]:
    """获取全局定义存储器"""
    if _global_initializer:
        return _global_initializer.definition_store
    return None


def initialize_knowledge_layer(data_dir: str, use_cache: bool = True) -> InitializationResult:
    """
    初始化知识层（系统启动时调用）

    Args:
        data_dir: 数据根目录
        use_cache: 是否使用缓存（默认 True）

    Returns:
        InitializationResult
    """
    global _global_initializer

    if _global_initializer and _global_initializer.is_initialized:
        app_logger.info("Knowledge layer already initialized, skipping")
        return InitializationResult(success=True)

    _global_initializer = KnowledgeInitializer(data_dir)
    return _global_initializer.initialize(use_cache=use_cache)
