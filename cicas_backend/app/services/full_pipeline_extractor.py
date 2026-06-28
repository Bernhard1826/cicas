"""
完整的规则提取服务 - 两层提取流程
支持前端实时进度可视化

业务逻辑的2层提取流程（面向用户）：
  Layer 1: Regex规则发现（枚举规则骨架）
  Layer 2: RAG + LLM规则理解（语义理解 + IR填充）

新架构设计原则：
- Layer 1负责规则发现（确定性枚举，保证召回率）
- Layer 2负责规则理解（语义理解，提升准确率）
- 不再有合并层（Layer 2输出的就是Layer 1规则的理解版本）
- 质量验证由LLM在Layer 2理解过程中完成，无需独立验证层
- KG Enhancement (Layer 3) 已移除，新IR schema已显式建模相关字段
"""
import asyncio
from typing import List, Dict, Any, Optional, Callable
from datetime import datetime
from pathlib import Path
from sqlalchemy.orm import Session

from app.models.models import Standard, Rule
from app.core.logging_config import app_logger
from app.core.config import settings
from app.services.parsers.pdf_parser import PDFParser
from app.services.parsers.rfc_parser import RFCParser
import httpx
import json


class FullPipelineExtractor:
    """
    两层提取流程（业务逻辑层次）

    Layer 1: Regex规则发现（对应rule_discovery）
    Layer 2: RAG + LLM规则理解（对应rag_enhancement + skeleton_llm_extractor）

    每一层都会发送进度更新给前端
    """

    def __init__(
        self,
        db: Session,
        progress_callback: Optional[Callable] = None,
        custom_keywords: Optional[List[str]] = None
    ):
        self.db = db
        self.progress_callback = progress_callback

        # 初始化解析器（支持自定义关键词）
        self.pdf_parser = PDFParser()
        self.rfc_parser = RFCParser(
            use_llm_validation=False,
            custom_keywords=custom_keywords  # 传递自定义关键词
        )  # Regex-only, LLM在后续Layer

        # ========== 新架构：规则发现与理解分离 ==========
        # 阶段 A：Regex 规则发现（确定性枚举）
        from app.services.extraction.rule_discovery import RuleDiscovery
        from app.services.extraction.context_builder import ContextBuilder
        # ========== Enhanced IR Extraction: 使用 ControlledLLMExtractor ==========
        from app.services.extraction.controlled_llm_extractor import ControlledLLMExtractor

        self.rule_discovery = RuleDiscovery()
        self.context_builder = None  # 延迟初始化，需要文档文本
        # 使用 ControlledLLMExtractor（支持 algorithm_ref, clarification 等分类）
        self.skeleton_llm_extractor = ControlledLLMExtractor(use_internal_retrieval=False)

        app_logger.info("[OK] Rule discovery and controlled LLM extraction initialized")
        # ========== End of new architecture ==========

        # LLM配置
        from app.core.config import settings
        self.llm_api_key = settings.llm_api_key
        self.llm_api_base = settings.llm_api_base
        self.llm_model = settings.llm_model


    async def _send_progress(
        self,
        msg_type: str,  # 'start' | 'progress' | 'complete' | 'error'
        layer: str,     # 'regex' | 'validation' | 'llm' | 'reference_resolution'
        message: str,   # 用户可读的进度消息
        progress_percent: float = 0,  # 0-100
        stats: Dict = None
    ):
        """
        发送详细的进度更新到前端

        同时发送 phase（粗粒度） 和 layer（细粒度）：

        Layer → Phase 映射（两层架构）：
        - regex → initialization (Layer 1: 规则发现)
        - llm → llm_extraction (Layer 2: LLM理解)
        - reference_resolution → llm_extraction (引用解析)
        - validation → saving (最终清理)
        """
        if self.progress_callback:
            try:
                # 将 layer 映射到 phase（前端兼容）
                layer_to_phase_map = {
                    'regex': 'initialization',
                    'llm': 'llm_extraction',
                    'reference_resolution': 'llm_extraction',
                    'validation': 'saving'  # 最终清理
                }

                phase = layer_to_phase_map.get(layer, 'initialization')

                progress_data = {
                    'type': msg_type,
                    'phase': phase,      # 前端用这个
                    'layer': layer,      # 开发者/调试用这个
                    'message': message,
                    'progress_percent': progress_percent,
                    'timestamp': datetime.now().timestamp()
                }

                if stats:
                    progress_data['stats'] = stats

                # 尝试作为async函数调用
                if asyncio.iscoroutinefunction(self.progress_callback):
                    await self.progress_callback(progress_data)
                else:
                    # 同步回调
                    self.progress_callback(progress_data)
            except Exception as e:
                app_logger.error(f"Failed to send progress update: {e}")

        # 同时记录到日志
        app_logger.info(f"[{layer.upper()}] {msg_type}: {message} ({progress_percent:.1f}%)")
        if stats:
            app_logger.debug(f"[{layer.upper()}] Stats: {stats}")

    async def extract_with_full_pipeline(
        self,
        standard_id: int
    ) -> Dict[str, Any]:
        """
        完整的四层提取流程

        Returns:
            包含所有层的详细结果和可视化数据
        """
        # 获取标准
        standard = self.db.query(Standard).filter(Standard.id == standard_id).first()
        if not standard:
            raise ValueError(f"Standard {standard_id} not found")

        # 读取文档
        file_path = Path(standard.file_path)
        if file_path.suffix.lower() == '.pdf':
            # Use table-aware PDF extraction via PDFParser
            text_content, page_count = self.pdf_parser.extract_text(file_path)
            app_logger.info(f"Successfully read PDF document: {file_path} ({page_count} pages, {len(text_content)} chars)")
            # 获取 PDF 结构化 sections，避免 _parse_document_structure 误识别
            pdf_chunks = self.pdf_parser.parse_pdf(file_path)
            if pdf_chunks:
                pre_parsed_sections = [
                    {'section_id': c['section'], 'title': c.get('title', ''), 'text': c.get('text', '')}
                    for c in pdf_chunks
                ]
                app_logger.info(f"PDF pre-parsed sections: {len(pre_parsed_sections)} chunks for rule discovery")
            else:
                pre_parsed_sections = None
        else:
            # 文本文件直接读取
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                text_content = f.read()
            app_logger.info(f"Successfully read text document: {file_path} ({len(text_content)} chars)")
            pre_parsed_sections = None

        context = {
            'source': standard.source,
            'title': standard.title,
            'version': standard.version,
            'file_path': standard.file_path,
            'standard_id': standard_id
        }

        result = {
            'standard_id': standard_id,
            'standard_title': standard.title,
            'layers': {},
            'final_rules': [],
            'statistics': {},
            'visualization_data': {}
        }

        start_time = datetime.now()

        # ============ Layer 1: Regex基础提取 ============
        await self._send_progress(
            'start',
            'regex',
            ' 开始 Regex 规则提取...',
            0,
            {'phase': 'regex_extraction'}
        )

        layer1_result = await self._layer1_regex_extraction(text_content, context, pre_parsed_sections=pre_parsed_sections)
        result['layers']['layer1_regex'] = layer1_result


        await self._send_progress(
            'complete',
            'regex',
            f'[OK] Regex 提取完成 - 发现 {len(layer1_result["rules"])} 条候选规则',
            15,  # Regex完成占总进度的15%
            {
                'rule_count': len(layer1_result['rules']),
            }
        )

        # ========== Layer 1 返回规则骨架 ==========
        # 新架构：Layer 1 输出规则骨架供 Layer 2 使用
        skeletons = layer1_result.get('skeletons', [])

        # 为regex规则添加extraction_method标记
        regex_rules = layer1_result.get('rules', [])
        for rule in regex_rules:
            if 'extraction_method' not in rule:
                rule['extraction_method'] = 'regex'

        app_logger.info(f"[Layer 1] Prepared {len(skeletons)} rule skeletons for Layer 2")

        # NOTE: 冷启动逻辑已移除 - 规则由rule_extraction_routes.py统一保存到数据库
        # 避免中间阶段提交导致的数据重复问题

        # ============ Layer 2: LLM 规则理解 ============
        await self._send_progress(
            'start',
            'llm',
            'Layer 2 (LLM): 规则理解与 IR 填充 - 基于 Layer 1 规则骨架...',
            0,
            {'phase': 'llm_understanding', 'skeleton_count': len(skeletons)}
        )

        layer2_llm_result = await self._layer2_llm_extraction(
            skeletons,  # ← 传入 Layer 1 的规则骨架
            text_content,  # ← 传入完整文档文本（用于构建上下文）
            context
        )

        # ========== Layer 2业务逻辑 = RAG增强 + LLM深度提取 ==========
        # Layer 2的输出 = LLM提取的所有规则（Layer 1不再提取规则）
        layer2_llm_count = len(layer2_llm_result.get('rules', []))
        layer2_total = layer2_llm_count  # Layer 1不再提取规则，只有LLM规则

        # ========== 为规则添加extraction_method标记（用于Layer 2展示）==========
        # 标记LLM规则
        for rule in layer2_llm_result.get('rules', []):
            if 'extraction_method' not in rule:
                rule['extraction_method'] = 'llm'

        layer2_for_display = {
            'count': layer2_total,  # ← Layer 2的总输出 = LLM规则
            'by_method': {
                'llm': layer2_llm_count
            },
            'quality': f"LLM提取: {layer2_llm_count} | 全文扫描: {len(layer2_llm_result.get('full_scan_rules', []))}",
        }
        result['layers']['layer2_llm'] = layer2_for_display

        await self._send_progress(
            'complete',
            'llm',
            f'[OK] LLM 提取完成 - 发现 {len(layer2_llm_result["rules"])} 条额外规则',
            50,  # LLM完成占总进度的50%
            {
                'rule_count': len(layer2_llm_result['rules']),
                'full_scan_rules': len(layer2_llm_result.get('full_scan_rules', [])),
                'rag_based_rules': len(layer2_llm_result.get('rag_based_rules', [])),
                'chunks_processed': layer2_llm_result.get('chunks_processed', 0)
            }
        )

        # NOTE: 规则由rule_extraction_routes.py统一保存
        # 避免中间阶段提交导致的数据重复问题

        # ============ Layer 2的输出就是最终规则（LLM理解后的规则骨架）============
        # 新架构中不再需要质量验证和合并：Layer 2 LLM接收Layer 1的规则骨架并理解填充IR
        # Layer 2的输出就是完整的规则列表，直接进入KG增强
        # ⭐ label-don't-drop: Layer 2 会丢弃判不出 IR 的 skeleton（no-IR / override 聚合 /
        # scope filter），使这些含关键词句子永不落库、破坏 Q1 守恒。这里以完整 Layer-1
        # skeleton 集兜底：存活 IR 原样保留，被丢弃的 skeleton 以 regex_unclassified 标签
        # 行补回（recall-first，分类交由后续阶段），保证 |落库| = |完整召回|。
        from app.services.extraction.recall_merge import merge_label_dont_drop
        all_rules = merge_label_dont_drop(skeletons, layer2_llm_result['rules'], logger=app_logger)

        # ========== 保存 ReferenceFact（重构后新增）==========
        reference_facts = layer2_llm_result.get('reference_facts', [])
        app_logger.info(
            f"[Stage C] Extracted {len(reference_facts)} reference facts for Rule Reasoning Service"
        )

        app_logger.info(
            f"[Layer 2 Complete] {len(all_rules)} rules with IR from skeleton understanding"
        )

        # ============ Layer 2的输出就是最终规则 ============
        # KG Enhancement (Layer 3) 已移除，新IR schema已显式建模相关字段
        final_rules = all_rules

        # 最终清理控制字符
        await self._send_progress(
            'start',
            'validation',
            f' 最终清理控制字符 ({len(final_rules)} 条规则)...',
            90,
            {'total_rules': len(final_rules)}
        )

        final_rules = self._cleanup_control_characters(final_rules)

        await self._send_progress(
            'complete',
            'validation',
            f'[OK] 最终清理完成 - {len(final_rules)} 条规则',
            100,
            {'cleaned_count': len(final_rules)}
        )

        result['final_rules'] = final_rules
        result['reference_facts'] = reference_facts  # ← 新增：返回 ReferenceFact 用于 Rule Reasoning Service
        result['resolved_irs'] = layer2_llm_result.get('resolved_irs', [])  # ← 新增：返回 resolved IRs
        result['statistics'] = self._calculate_statistics(result)
        result['visualization_data'] = self._prepare_visualization_data(result)
        result['duration_seconds'] = (datetime.now() - start_time).total_seconds()

        # ========== 对抗学习已移至 rule_extraction_routes.py ==========
        # 原因：对抗学习需要Rule ORM对象（从数据库查询），而这里只有dict
        # 正确流程：提取 → 保存到数据库 → 对抗学习
        # 详见：rule_extraction_routes.py 中的 "对抗学习：保存后自动质量评估和zlint覆盖验证"
        app_logger.info(
            f"[OK] Rule extraction complete: {len(final_rules)} rules ready for saving. "
            f"Adversarial learning will execute after saving to database."
        )

        return result

    async def _layer1_regex_extraction(
        self,
        text: str,
        context: Dict[str, Any],
        pre_parsed_sections: Optional[List[Dict[str, Any]]] = None
    ) -> Dict[str, Any]:
        """
        Layer 1: Regex 规则发现（新架构）

        使用 RuleDiscovery 进行确定性规则枚举
        - 支持所有文档类型（RFC/CABF/ETSI）
        - 基于 RFC2119 关键词（MUST/SHALL/SHOULD 等）
        - 保证规则召回率上限
        """
        app_logger.info(f"[Layer 1] Starting rule discovery for {context.get('source')} document")

        # 使用新的 RuleDiscovery 进行规则枚举
        document_id = f"{context.get('source')}_{context.get('standard_id', 'unknown')}"

        skeletons = self.rule_discovery.discover_rules(text, document_id, pre_parsed_sections=pre_parsed_sections)

        discovery_stats = self.rule_discovery.get_statistics(skeletons)

        app_logger.info(
            f"[Layer 1] Rule discovery completed: "
            f"{len(skeletons)} skeletons from {discovery_stats.get('unique_sentences', 0)} unique sentences"
        )

        # 转换 skeletons 为旧格式（保持向后兼容）
        import hashlib
        rules = []
        for skeleton in skeletons:
            # 计算sentence hash用于去重
            sentence_hash = hashlib.md5(skeleton.sentence.encode('utf-8')).hexdigest()

            rule_dict = {
                'rule_id': skeleton.rule_id,
                'text': skeleton.sentence,
                'section': skeleton.section,
                'section_title': skeleton.section_title,
                'keyword': skeleton.keyword,
                'sentence_index': skeleton.sentence_index,  # ⭐ CRITICAL: 添加sentence_index用于去重
                'sentence_hash': sentence_hash,              # ⭐ CRITICAL: 添加sentence_hash用于去重
                'extraction_method': 'regex',
                'source': context.get('source'),
                'standard_id': context.get('standard_id'),
            }
            rules.append(rule_dict)

        return {
            'rules': rules,
            'count': len(rules),  # 添加count字段（向后兼容）
            'skeletons': skeletons,  # 新增：返回原始骨架
            'statistics': {
                'total_skeletons': len(skeletons),
                'discovery_stats': discovery_stats,
                'unique_sentences': discovery_stats.get('unique_sentences', 0),
                'by_keyword': discovery_stats.get('by_keyword', {}),
                'by_section': discovery_stats.get('by_section', {}),
            },
        }


    async def _layer2_llm_extraction(
        self,
        skeletons: List,  # 规则骨架
        document_text: str,  # 完整文档文本
        context: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Layer 2: LLM 规则理解与 IR 填充（新架构）

        基于 Layer 1 的规则骨架，使用 LLM 进行语义理解和结构化
        - 动态上下文构建
        - 按复杂度分批
        - 批量 LLM 理解
        """
        app_logger.info(f"[Layer 2 LLM] Starting LLM understanding for {len(skeletons)} rule skeletons")

        if not skeletons:
            return {'rules': [], 'statistics': {}}

        # 初始化 ContextBuilder（延迟初始化）
        if not self.context_builder:
            from app.services.extraction.context_builder import ContextBuilder
            document_id = f"{context.get('source')}_{context.get('standard_id', 'unknown')}"

            # 构造标准名称用于查询 section topics 知识库
            # 例如: source="RFC", title="RFC 5280 ..." → standard="RFC5280"
            standard_name = None
            source = context.get('source', '')
            title = context.get('title', '')

            if source == 'RFC' and title:
                # 从标题中提取 RFC 号
                import re
                rfc_match = re.search(r'RFC\s*(\d+)', title, re.IGNORECASE)
                if rfc_match:
                    rfc_number = rfc_match.group(1)
                    standard_name = f"RFC{rfc_number}"  # 例如 "RFC5280"
            # 未来可以添加其他标准的支持（CABF, ETSI等）

            app_logger.info(
                f"[ContextBuilder] Initializing with standard_name={standard_name} "
                f"(source={source}, title_prefix={title[:50]}...)"
            )

            self.context_builder = ContextBuilder(document_text, document_id, standard=standard_name)

        # 构建规则上下文
        contexts = [self.context_builder.build_context(sk) for sk in skeletons]

        # 按复杂度分批
        batches = self.context_builder.batch_by_complexity(contexts)

        app_logger.info(f"[Layer 2 LLM] Created {len(batches)} batches by complexity")

        # 批量提取 — 一次调用替代循环
        all_rules = []
        all_irs = []  # 保存所有 IR 用于引用解析

        total_rules = sum(len(b) for b in batches)

        async def progress_callback(completed_rules: int, total_rules_count: int):
            await self._send_progress(
                'update', 'llm',
                f'已完成 {completed_rules}/{total_rules_count} 条规则',
                30 + int(completed_rules / max(total_rules_count, 1) * 25),
                {'completed': completed_rules, 'total': total_rules_count}
            )

        try:
            extraction_results = await self.skeleton_llm_extractor.extract_batch_async(
                batches,
                progress_callback=progress_callback,
            )

            # 保存 IR（稍后进行引用解析）
            failed_count = 0
            for result in extraction_results:
                if result.ir is not None:
                    all_irs.append(result.ir)
                else:
                    failed_count += 1

            if failed_count > 0:
                app_logger.warning(
                    f"[Layer 2 LLM] {failed_count}/{len(extraction_results)} skeletons "
                    f"failed to extract IR (LLM returned null / undecided / parse error)"
                )

        except Exception as e:
            app_logger.error(f"[Layer 2 LLM] Batch extraction failed: {e}")

        app_logger.info(f"[Layer 2 LLM] Completed LLM extraction: {len(all_irs)} IRs")

        # ========== Aggregate Overrides: Merge clarification IRs into parent algorithm_ref ==========
        if all_irs:
            from app.services.extraction.structural_analyzer import StructuralAnalyzer
            aggregator = StructuralAnalyzer()
            all_irs = aggregator.aggregate_overrides(all_irs)
            app_logger.info(f"[Layer 2 LLM] After override aggregation: {len(all_irs)} IRs")

        # ========== Section-scope filter: remove cross-section noise ==========
        # Only for extension sections (extensions.X), remove IRs whose subject is
        # in a completely unrelated non-extension namespace (e.g., signature.* in a
        # basicConstraints section). Conservative: allows extensions.*, subjectaltname.*,
        # subject.*, and any path containing the canonical extension name.
        #
        # ⚠️ Single-section ONLY. This denoiser derives ONE canonical subject from the
        # section and filters against it. In whole-document / multi-section extraction
        # the skeletons span many sections (RFC ~112, CABF ~396), so a single section's
        # subject would wrongly delete every other section's IRs — observed dropping
        # 44–48% of valid IRs (485→273, 733→378). Skip the filter unless all skeletons
        # come from a single section.
        distinct_sections = {sk.section for sk in skeletons if sk.section}
        if all_irs and skeletons and len(distinct_sections) <= 1:
            section_titles = {sk.section_title for sk in skeletons if sk.section_title}
            if section_titles:
                from app.services.extraction.field_resolver import get_field_resolver
                field_resolver = get_field_resolver()
                canonical_path = None
                for title in section_titles:
                    result = field_resolver.resolve_section_subject(
                        section_title=title, section_id=skeletons[0].section
                    )
                    if result:
                        canonical_path = result.get('path')
                        break

                if canonical_path and canonical_path.startswith('extensions.'):
                    # Extract the extension name: "extensions.basicconstraints" → "basicconstraints"
                    ext_name = canonical_path.split('.')[1] if '.' in canonical_path else ''
                    # Namespaces always allowed for extension sections
                    allowed_prefixes = ('extensions.', 'extensions', 'subjectaltname', 'subject')
                    pre_filter = len(all_irs)
                    filtered = []
                    for ir in all_irs:
                        subj_path = ir.subject.path if hasattr(ir.subject, 'path') else str(ir.subject)
                        subj_lower = subj_path.lower().strip()
                        # Keep if subject is in allowed namespace or contains the extension name
                        keep = (
                            any(subj_lower.startswith(p) for p in allowed_prefixes)
                            or ext_name in subj_lower
                        )
                        if keep:
                            filtered.append(ir)
                        else:
                            app_logger.debug(
                                f"[Scope filter] Removed cross-section IR: "
                                f"subject={subj_lower} not related to {canonical_path}"
                            )
                    if len(filtered) < pre_filter:
                        app_logger.info(
                            f"[Layer 2 LLM] Scope filter: {pre_filter} → {len(filtered)} IRs "
                            f"(canonical={canonical_path})"
                        )
                        all_irs = filtered

        # ========== Stage C: 引用解析（重构后）==========
        await self._send_progress(
            'start',
            'reference_resolution',
            '开始解析引用并提取 ReferenceFact',
            55,
            {'total_irs': len(all_irs)}
        )

        from app.services.extraction.reference_resolution_orchestrator import ReferenceResolutionOrchestrator

        # 初始化引用解析编排器（传入数据库会话用于查找 structural_rule_id）
        ref_orchestrator = ReferenceResolutionOrchestrator(
            db=self.db,  # 传入数据库会话
            kg_client=None,  # 暂不使用 KG
            standards_index=None,  # 可以后续添加标准索引
            standard_id=context.get('standard_id')  # 从context获取standard_id用于内部引用验证
        )

        # 解析所有引用并提取 ReferenceFact（重构后的新接口）
        resolved_irs, reference_facts = ref_orchestrator.resolve_and_extract_facts(all_irs)

        app_logger.info(
            f"[Stage C] Output: {len(resolved_irs)} IRs, "
            f"{len(reference_facts)} reference facts"
        )

        await self._send_progress(
            'complete',
            'reference_resolution',
            f'引用解析完成: {len(reference_facts)} 个引用事实',
            60,
            {
                'total_irs': len(resolved_irs),
                'reference_facts': len(reference_facts)
            }
        )
        # ========== End Stage C ==========

        # 转换 IR 为旧格式（保持向后兼容）
        import hashlib
        for ir in resolved_irs:
            # 安全获取枚举值（兼容字符串和枚举对象）
            predicate_value = ir.predicate.value if hasattr(ir.predicate, 'value') else str(ir.predicate)
            obligation_value = ir.obligation.value if hasattr(ir.obligation, 'value') else str(ir.obligation)

            # ⭐ CRITICAL: 计算sentence_hash用于去重（基于规则文本）
            sentence_hash = hashlib.md5(ir.rule_text.encode('utf-8')).hexdigest()

            # ⭐ CRITICAL: 从provenance中提取sentence_index
            sentence_index = ir.provenance[0].line_start if ir.provenance and ir.provenance[0].line_start is not None else None

            # 序列化复杂类型为 JSON 字符串（避免 psycopg2 can't adapt type 'dict'）
            expected_value = ir.constraint.value if ir.constraint else None
            if isinstance(expected_value, (dict, list)):
                expected_value = json.dumps(expected_value, ensure_ascii=False)

            condition_value = ir.conditions if hasattr(ir, 'conditions') else None
            if isinstance(condition_value, (dict, list)):
                condition_value = json.dumps(condition_value, ensure_ascii=False)

            context_value = ir.precondition if hasattr(ir, 'precondition') else None
            if isinstance(context_value, (dict, list)):
                context_value = json.dumps(context_value, ensure_ascii=False)

            rule_dict = {
                'text': ir.rule_text,
                'section': ir.provenance[0].section if ir.provenance else '',
                'title': ir.provenance[0].title if ir.provenance else '',
                'affected_field': str(ir.subject) if ir.subject else None,
                'operation': predicate_value,
                'expected_value': expected_value,
                'requirement_level': obligation_value,
                'condition': condition_value,
                'context': context_value,
                'extraction_method': 'llm',
                # ⭐ CRITICAL: Deduplication fields
                'sentence_hash': sentence_hash,      # 用于检测重复规则
                'sentence_index': sentence_index,    # 用于追踪规则在文档中的位置
                # 新增：引用信息
                'references': [
                    {
                        'raw': ref.raw,
                        'doc_id': ref.doc_id,
                        'section': ref.section,
                        'resolved': ref.resolved
                    }
                    for ref in ir.references
                ] if ir.references else []
            }
            all_rules.append(rule_dict)

        app_logger.info(f"[Layer 2 LLM] Completed: extracted {len(all_rules)} rules from {len(skeletons)} skeletons")

        return {
            'rules': all_rules,
            'count': len(all_rules),  # 添加count字段（向后兼容）
            'reference_facts': reference_facts,  # ← 新增：返回 ReferenceFact
            'resolved_irs': resolved_irs,  # ← 新增：返回 resolved IRs（用于重新提取 ReferenceFacts）
            'statistics': {
                'total_skeletons': len(skeletons),
                'total_rules': len(all_rules),
                'batches': len(batches),
                'total_references': sum(len(r.get('references', [])) for r in all_rules),
                'resolved_references': sum(
                    1 for r in all_rules
                    for ref in r.get('references', [])
                    if ref.get('resolved')
                ),
                'reference_facts_count': len(reference_facts),  # ← 新增统计
            }
        }

    def _split_into_sections(self, text: str) -> List[str]:
        """将文档分割为章节"""
        # 简单按段落分割
        sections = text.split('\n\n')
        return [s.strip() for s in sections if len(s.strip()) > 50]

    def _split_text_into_chunks(self, text: str, chunk_size: int = 12000) -> List[str]:
        """智能分块"""
        paragraphs = text.split('\n\n')

        # PDF文本通常没有双换行符，需要强制按字符分块
        if len(paragraphs) <= 1:
            chunks = []
            for i in range(0, len(text), chunk_size):
                chunk = text[i:i + chunk_size]
                # 尽量在换行符处切割
                if i + chunk_size < len(text):
                    last_newline = chunk.rfind('\n')
                    if last_newline > chunk_size * 0.5:
                        chunk = text[i:i + last_newline]
                chunks.append(chunk)
            return chunks

        # 正常的段落合并逻辑
        chunks = []
        current_chunk = []
        current_size = 0

        for para in paragraphs:
            para_size = len(para)
            if current_size + para_size > chunk_size and current_chunk:
                chunks.append('\n\n'.join(current_chunk))
                current_chunk = [para]
                current_size = para_size
            else:
                current_chunk.append(para)
                current_size += para_size

        if current_chunk:
            chunks.append('\n\n'.join(current_chunk))

        return chunks

    def _split_text_into_smart_chunks(self, text: str, chunk_size: int = 10000) -> List[str]:
        """
        智能分块 - 优化版本

        相比普通分块，增加了：
        1. 更大的chunk_size (15000 vs 12000)
        2. 保留章节边界
        """
        # 检测是否为PDF文本（无双换行符）
        if text.count('\n\n') < 5:
            # PDF文本：使用强制分块
            return self._split_text_into_chunks(text, chunk_size)

        # 尝试按章节分割（常见的章节标记）
        import re

        # RFC风格: "4.  Section Title" or "4.1.  Subsection Title"
        section_pattern = r'\n(\d+\.(?:\d+\.)*\s+[A-Z][^\n]{0,100}\n)'
        sections = re.split(section_pattern, text)

        chunks = []
        current_chunk = []
        current_size = 0

        for i, section in enumerate(sections):
            section_size = len(section)

            if current_size + section_size > chunk_size and current_chunk:
                chunks.append(''.join(current_chunk))
                current_chunk = [section]
                current_size = section_size
            else:
                current_chunk.append(section)
                current_size += section_size

        if current_chunk:
            chunks.append(''.join(current_chunk))

        return chunks if chunks else self._split_text_into_chunks(text, chunk_size)

    def _chunk_likely_has_rules(self, chunk: str) -> bool:
        """
        判断chunk是否可能包含规则（严格过滤，保证质量）

        设计原则（根据用户反馈）：
        "我希望RAG只保存高质量规则"

        因此chunk过滤应该严格，只处理明确包含规则的chunks。
        宁可漏掉少数规则，也不要提取大量低质量内容。
        """
        if not chunk:
            return False
        chunk_lower = chunk.lower()
        chunk_first_300 = chunk_lower[:300]

        # 1. 规范性关键词 - 必须包含
        normative_keywords = ['must', 'shall', 'should', 'required', 'mandatory']
        has_normative = any(kw in chunk_lower for kw in normative_keywords)

        if not has_normative:
            return False

        # 2. 证书相关术语 - 至少2个
        cert_keywords = [
            'certificate', 'extension', 'field', 'value', 'validity',
            'key usage', 'subject', 'issuer', 'policy', 'constraint',
            'algorithm', 'signature', 'public key', 'private key',
            'ca', 'distinguished name', 'oid', 'asn.1', 'serial number'
        ]

        keyword_count = sum(1 for kw in cert_keywords if kw in chunk_lower)

        # Fix: 从2个降低到1个，避免过度过滤有效规则
        if keyword_count < 1:
            return False

        # 3. 排除明显的非规则性章节
        exclude_patterns = [
            'table of contents', 'status of this memo',
            'copyright notice', 'abstract',
            'acknowledgment', 'references', 'authors\' addresses'
        ]

        is_excluded = any(pattern in chunk_first_300 for pattern in exclude_patterns)

        return not is_excluded

    def _extract_normative_content_for_rag(self, chunk: str, max_length: int = 1000) -> str:
        """
        提取chunk中包含规范性语句的内容，用于RAG检索

        设计原理：
        - 规范性语句（含must/shall/should等）更能代表规则内容
        - 用这些句子做RAG检索，能找到更相关的few-shot示例
        - 避免用chunk开头的背景介绍、术语定义导致检索偏差

        Args:
            chunk: 原始chunk文本
            max_length: 返回内容的最大长度

        Returns:
            提取的规范性内容，如果没找到则fallback到chunk开头
        """
        if not chunk:
            return ""

        # 规范性关键词（RFC/CABF标准中表示强制/推荐的词汇）
        normative_keywords = [
            'must', 'must not', 'shall', 'shall not',
            'should', 'should not', 'required', 'mandatory',
            'prohibited', 'recommended', 'may not'
        ]

        # 按句号分割，保留句子边界
        # 使用多种分隔符：句号+空格、换行、分号
        import re
        sentences = re.split(r'(?<=[.!?])\s+|\n{2,}|;\s*(?=[A-Z])', chunk)

        normative_sentences = []
        total_length = 0

        for sent in sentences:
            sent = sent.strip()
            if not sent or len(sent) < 20:  # 跳过太短的片段
                continue

            sent_lower = sent.lower()

            # 检查是否包含规范性关键词
            has_normative = any(kw in sent_lower for kw in normative_keywords)

            if has_normative:
                normative_sentences.append(sent)
                total_length += len(sent) + 2  # +2 for ". "

                if total_length >= max_length:
                    break

        # 如果找到了规范性句子，用它们作为RAG查询
        if normative_sentences:
            result = '. '.join(normative_sentences)
            return result[:max_length]

        # Fallback 策略：如果没找到规范性句子
        # 可能是chunk确实没有规则（但这种chunk不应该到达这里）
        # 使用开头+中间采样
        if len(chunk) <= max_length:
            return chunk

        # 开头600 + 中间400的采样
        head = chunk[:600]
        mid_start = len(chunk) // 2 - 200
        mid = chunk[mid_start:mid_start + 400] if mid_start > 600 else ""

        return (head + " ... " + mid).strip()[:max_length]

    def _build_optimized_prompt_sections(self) -> Dict[str, str]:
        """
        构建优化后的prompt片段（基于对抗学习的反馈）

        Returns:
            {
                'extraction_hints': str,  # 优化的提取提示
                'ignore_patterns': str,    # 优化的忽略模式
                'field_guidance': str      # 字段映射指导
            }
        """
        sections = {
            'extraction_hints': '',
            'ignore_patterns': '',
            'field_guidance': ''
        }

        # 1. 添加优化的提取提示（extraction_hints）
        hints = self.prompt_optimizations.get('extraction_hints', [])
        if hints:
            sections['extraction_hints'] = "\n[LEARNED EXTRACTION GUIDELINES]:\n"
            sections['extraction_hints'] += "Based on previous rounds, pay special attention to:\n"
            for i, hint in enumerate(hints, 1):
                sections['extraction_hints'] += f"{i}. {hint}\n"
            sections['extraction_hints'] += "\n"

        # 2. 添加优化的忽略模式（ignore_patterns）
        patterns = self.prompt_optimizations.get('ignore_patterns', [])
        if patterns:
            sections['ignore_patterns'] = "\n[LEARNED PATTERNS TO AVOID]:\n"
            sections['ignore_patterns'] += "Based on previous extraction errors, DO NOT extract:\n"
            for i, pattern in enumerate(patterns, 1):
                sections['ignore_patterns'] += f"{i}. {pattern}\n"
            sections['ignore_patterns'] += "\n"

        # 3. 添加字段映射指导（field_mapping_rules）
        field_rules = self.prompt_optimizations.get('field_mapping_rules', {})
        if field_rules:
            sections['field_guidance'] = "\n[FIELD MAPPING GUIDANCE]:\n"
            sections['field_guidance'] += "Use these guidelines for accurate field mapping:\n"
            for field, guidance in field_rules.items():
                sections['field_guidance'] += f"- {field}: {guidance}\n"
            sections['field_guidance'] += "\n"

        return sections

    async def _llm_extract_from_multiple_chunks(
        self,
        chunks: List[str],
        chunk_metadata: List[Dict],
        context: Dict,
        few_shot_examples: List[Dict],
        batch_start_index: int
    ) -> List[Dict]:
        """批量提取：一次LLM调用处理多个chunks

        Args:
            chunks: 文本块列表
            chunk_metadata: chunk元数据列表（section, title）
            context: 上下文信息
            few_shot_examples: Few-shot示例
            batch_start_index: batch起始索引（用于日志）

        Returns:
            提取的规则列表
        """
        source = context.get('source', 'document')
        title = context.get('title', '')

        # ========== 构建 Few-shot 示例部分 ==========
        few_shot_section = ""
        if few_shot_examples and len(few_shot_examples) > 0:
            few_shot_section = "\n##  Reference Examples (High-Quality Rules from Knowledge Base)\n\n"
            few_shot_section += f"The following are {len(few_shot_examples)} high-quality rules as patterns:\n\n"

            for i, example in enumerate(few_shot_examples[:10], 1):
                few_shot_section += f"""Example {i} (similarity: {example.get('similarity', 0):.3f}):
TEXT: {example.get('text', '')[:120]}...
FIELD: {example.get('affected_field', 'N/A')}
OP: {example.get('operation', 'N/A')}
VALUE: {example.get('expected_value', 'N/A')}

"""
            few_shot_section += "[WARNING] Use these as **patterns** - extract similar rules from the text below.\n\n---\n\n"

        # ========== 构建优化后的prompt片段（基于对抗学习反馈）==========
        optimized_sections = self._build_optimized_prompt_sections()

        # ========== 构建批量chunks prompt ==========
        # 动态调整每个chunk的最大长度（根据batch大小）
        if len(chunks) <= 5:
            max_chunk_chars = 8000  # 小batch：每个chunk可以很长
        elif len(chunks) <= 20:
            max_chunk_chars = 6000  # 中等batch
        elif len(chunks) <= 50:
            max_chunk_chars = 4000  # 大batch
        else:
            max_chunk_chars = 3000  # 超大batch：每个chunk需要较短

        chunks_text = ""
        for i, (chunk, meta) in enumerate(zip(chunks, chunk_metadata), 1):
            section = meta.get('section', 'unknown')
            chunk_title = meta.get('title', 'unknown')
            chunks_text += f"\n\n### CHUNK {i} ###\n"
            chunks_text += f"SECTION: {section}\n"
            chunks_text += f"TITLE: {chunk_title}\n"
            chunks_text += f"TEXT:\n{chunk[:max_chunk_chars]}\n"

        app_logger.debug(
            f"[Batch Prompt] {len(chunks)} chunks, max_chunk_chars={max_chunk_chars}, "
            f"estimated_input_chars={len(chunks_text)}"
        )

        # ========== 动态计算max_tokens（充分利用上下文窗口）==========
        MODEL_CONTEXT_WINDOW = settings.llm_context_window

        # 粗略估算输入token数（1 token ≈ 4 characters）
        def estimate_tokens(text: str) -> int:
            return len(text) // 4

        # 估算prompt的token数
        prompt_base_tokens = 5000  # System prompt + few-shot examples + 固定格式
        chunks_input_tokens = sum(estimate_tokens(chunk[:max_chunk_chars]) for chunk in chunks)
        total_input_tokens = prompt_base_tokens + chunks_input_tokens

        # 计算可用于输出的tokens（预留10%安全边界）
        available_output_tokens = int((MODEL_CONTEXT_WINDOW - total_input_tokens) * 0.9)

        # 每个chunk预留的输出tokens（动态调整）
        avg_chunk_size = sum(len(c) for c in chunks) / len(chunks) if chunks else 5000

        if avg_chunk_size < 2000:
            # 小chunk：每个chunk可能提取2-3条规则，每条规则约150 tokens
            tokens_per_chunk = 500
        elif avg_chunk_size < 5000:
            # 中等chunk：每个chunk可能提取3-5条规则
            tokens_per_chunk = 800
        else:
            # 大chunk：每个chunk可能提取5-10条规则
            tokens_per_chunk = 1500

        # 理想的输出tokens = chunk数 × 每chunk预留
        ideal_output_tokens = len(chunks) * tokens_per_chunk

        # 取两者较小值，确保不超过上下文窗口
        dynamic_max_tokens = min(ideal_output_tokens, available_output_tokens)

        # 设置合理的下限（至少2000）和上限（不超过80k，留足够空间给输入）
        dynamic_max_tokens = max(2000, min(80000, dynamic_max_tokens))

        app_logger.info(
            f"[Token Allocation] {len(chunks)} chunks, avg_size={avg_chunk_size:.0f} chars | "
            f"Input: {total_input_tokens} tokens, Available Output: {available_output_tokens} tokens, "
            f"Ideal: {ideal_output_tokens} tokens → Final max_tokens={dynamic_max_tokens}"
        )

        # 详细的prompt
        prompt = f"""Extract TECHNICAL CERTIFICATE RULES from {source}: "{title}"

You are processing {len(chunks)} text chunks. For each chunk, extract all technical rules.

{few_shot_section}{optimized_sections['extraction_hints']}{optimized_sections['field_guidance']}{optimized_sections['ignore_patterns']}[WARNING] CRITICAL - MUST IGNORE (DO NOT extract):
1. **RFC 2119 keyword declarations**
2. **Document metadata and structure**
3. **Terminology definitions WITHOUT technical requirements**
4. **Page headers/footers**
5. **Informative/background content**

[OK] ONLY EXTRACT technical rules about:
- Certificate fields: validity, subject, issuer, extensions, keyUsage, basicConstraints, etc.
- Specific algorithm requirements: RSA, ECDSA, SHA-256, key sizes
- Certificate validation procedures
- Encoding/format requirements
- PKI policy requirements with specific constraints

**Rule of thumb**:
- If it starts with "This document..." → IGNORE IT
- If it starts with "The certificate MUST..." → EXTRACT IT
- If it doesn't specify WHAT to do with WHICH certificate field/component → IGNORE IT

**IMPORTANT**: For each rule, specify which CHUNK it came from by including "CHUNK_NUM: X" field.

Output format for each TECHNICAL rule:
---
CHUNK_NUM: <chunk number 1-{len(chunks)}>
TEXT: <exact requirement sentence>
SECTION: <from chunk metadata>
FIELD: <certificate field>
OP: <operation from list>
VALUE: <expected value if any>
LEVEL: <MUST|SHOULD|MAY|MUST_NOT|SHOULD_NOT>
CONDITION: <condition or "none">
---

Text Chunks:
{chunks_text}

TECHNICAL Rules (process all {len(chunks)} chunks):
"""

        try:
            async with httpx.AsyncClient(timeout=600.0) as client:
                response = await client.post(
                    f"{self.llm_api_base}/chat/completions",
                    headers={
                        "Authorization": f"Bearer {self.llm_api_key}",
                        "Content-Type": "application/json"
                    },
                    json={
                        "model": self.llm_model,
                        "messages": [{"role": "user", "content": prompt}],
                        "temperature": 0.1,
                        "max_tokens": dynamic_max_tokens
                    }
                )

                response.raise_for_status()
                result = response.json()
                content = result['choices'][0]['message']['content']

                # 解析规则
                parsed_rules = self._parse_llm_batch_response(
                    content,
                    chunks,
                    chunk_metadata,
                    batch_start_index
                )

                # 检查token截断
                if 'usage' in result and result['usage'].get('total_tokens', 0) > 0:
                    finish_reason = result['choices'][0].get('finish_reason', 'unknown')
                    if finish_reason == 'length':
                        app_logger.warning(
                            f"Batch {batch_start_index//len(chunks)+1}: LLM output truncated. "
                            f"Extracted {len(parsed_rules)} rules from {len(chunks)} chunks, may have missed more."
                        )

                return parsed_rules

        except httpx.TimeoutException as e:
            app_logger.error(f"LLM batch extraction timeout after 600s: {e}")
            return []
        except httpx.HTTPStatusError as e:
            app_logger.error(
                f"LLM API error for batch: Status {e.response.status_code}, Response: {e.response.text[:200]}"
            )
            return []
        except Exception as e:
            app_logger.error(
                f"LLM batch extraction failed: {type(e).__name__}: {e}",
                exc_info=True
            )
            return []

    def _parse_llm_batch_response(
        self,
        response: str,
        chunks: List[str],
        chunk_metadata: List[Dict],
        batch_start_index: int
    ) -> List[Dict]:
        """解析批量LLM返回的规则

        每条规则应该包含CHUNK_NUM字段，用于确定来源chunk并分配section/title
        """
        rules = []
        blocks = response.split('---')

        for block in blocks:
            if len(block.strip()) < 20:
                continue

            rule = self._parse_batch_rule_block(block, chunks, chunk_metadata)
            if rule:
                rules.append(rule)

        return rules

    def _parse_batch_rule_block(
        self,
        block: str,
        chunks: List[str],
        chunk_metadata: List[Dict]
    ) -> Optional[Dict]:
        """解析单个规则块（批量版本）

        相比单个chunk版本，增加了CHUNK_NUM字段解析，用于分配section/title
        """
        lines = block.split('\n')
        rule_data = {
            'text': None,
            'section': '',
            'title': '',
            'affected_field': None,
            'operation': None,
            'expected_value': None,
            'requirement_level': None,
            'condition': None,
            'chunk_num': None  # 新增：chunk编号
        }

        for line in lines:
            line = line.strip()
            if line.startswith('CHUNK_NUM:'):
                try:
                    chunk_num_str = line.split(':', 1)[1].strip()
                    rule_data['chunk_num'] = int(chunk_num_str)
                except ValueError:
                    pass
            elif line.startswith('TEXT:'):
                rule_data['text'] = line.split(':', 1)[1].strip()
            elif line.startswith('SECTION:'):
                section = line.split(':', 1)[1].strip()
                rule_data['section'] = section if section.lower() != 'unknown' else ''
            elif line.startswith('TITLE:'):
                title = line.split(':', 1)[1].strip()
                rule_data['title'] = title if title.lower() != 'unknown' else ''
            elif line.startswith('FIELD:'):
                rule_data['affected_field'] = line.split(':', 1)[1].strip()
            elif line.startswith('OP:'):
                rule_data['operation'] = line.split(':', 1)[1].strip()
            elif line.startswith('VALUE:'):
                rule_data['expected_value'] = line.split(':', 1)[1].strip()
            elif line.startswith('LEVEL:'):
                rule_data['requirement_level'] = line.split(':', 1)[1].strip()
            elif line.startswith('CONDITION:'):
                condition = line.split(':', 1)[1].strip()
                rule_data['condition'] = condition if condition.lower() not in ['none', 'n/a', ''] else None

        if not rule_data['text'] or len(rule_data['text']) < 10:
            return None

        # ========== Bug Fix: 清理文本格式异常 ==========
        rule_data['text'] = self._clean_rule_text(rule_data['text'])

        if not rule_data['text'] or len(rule_data['text']) < 10:
            app_logger.debug(f"Rejected rule due to text cleaning: {rule_data.get('text', '')[:50]}")
            return None

        # ========== 使用chunk_num分配section/title ==========
        # 如果LLM没有提供section/title，或者提供了chunk_num，使用元数据
        if rule_data['chunk_num'] is not None:
            chunk_idx = rule_data['chunk_num'] - 1  # chunk_num是1-based
            if 0 <= chunk_idx < len(chunk_metadata):
                meta = chunk_metadata[chunk_idx]
                # 只在LLM未提供section/title时使用元数据
                if not rule_data['section']:
                    rule_data['section'] = meta.get('section', '')
                if not rule_data['title']:
                    rule_data['title'] = meta.get('title', '')

                # 保存context（chunk预览）
                if chunk_idx < len(chunks):
                    rule_data['context'] = chunks[chunk_idx][:200]
                    rule_data['chunk_number'] = chunk_idx + 1
        else:
            # 如果没有chunk_num，尝试从第一个chunk获取
            if chunk_metadata:
                if not rule_data['section']:
                    rule_data['section'] = chunk_metadata[0].get('section', '')
                if not rule_data['title']:
                    rule_data['title'] = chunk_metadata[0].get('title', '')

        return rule_data

    async def _llm_extract_from_chunk(
        self,
        chunk: str,
        context: Dict,
        chunk_num: int,
        few_shot_examples: List[Dict] = None,  # ← 参数：Few-shot 示例
        chunk_specific_count: int = 0  # ← 新增：chunk专属规则数量
    ) -> List[Dict]:
        """从单个chunk中使用LLM提取规则 - 包含元信息过滤 + Few-shot学习 + 实时RAG"""

        source = context.get('source', 'document')
        title = context.get('title', '')

        # ========== 构建 Few-shot 示例部分 ==========
        few_shot_section = ""
        if few_shot_examples and len(few_shot_examples) > 0:
            few_shot_section = "\n##  Reference Examples (High-Quality Rules from Knowledge Base)\n\n"

            # 区分全局示例和chunk专属示例
            if chunk_specific_count > 0:
                few_shot_section += f"The following includes {len(few_shot_examples)} examples: "
                few_shot_section += f"{len(few_shot_examples) - chunk_specific_count} global + {chunk_specific_count} specific to this section.\n"
                few_shot_section += "Use them as **patterns** to identify similar rules:\n\n"
            else:
                few_shot_section += "The following are high-quality rules extracted from similar documents. Use them as **patterns** to identify similar rules:\n\n"

            # 使用所有示例（已在上层限制为10个）
            for i, example in enumerate(few_shot_examples, 1):
                few_shot_section += f"""Example {i} (similarity: {example.get('similarity', 0):.3f}):
TEXT: {example.get('text', '')[:120]}...
FIELD: {example.get('affected_field', 'N/A')}
OP: {example.get('operation', 'N/A')}
VALUE: {example.get('expected_value', 'N/A')}

"""
            few_shot_section += "[WARNING] Use these as **patterns** - extract similar rules from the text below.\n\n---\n\n"

        # ========== 构建优化后的prompt片段（基于对抗学习反馈）==========
        optimized_sections = self._build_optimized_prompt_sections()

        # 详细的prompt，包含元信息过滤逻辑 + 对抗学习优化
        prompt = f"""Extract TECHNICAL CERTIFICATE RULES from {source}: "{title}"
{few_shot_section}
{optimized_sections['extraction_hints']}{optimized_sections['field_guidance']}{optimized_sections['ignore_patterns']}[WARNING] CRITICAL - MUST IGNORE (DO NOT extract):
1. **RFC 2119 keyword declarations**
   Example: "The key words MUST, SHALL, SHOULD... are to be interpreted as described in [RFC2119]"

2. **Document metadata and structure**
   [ERROR] Examples (DO NOT extract these exact patterns):
   - "This document specifies..."
   - "This document describes..."
   - "This specification defines..."
   - "To promote interoperability, this document..."
   - "The remainder of this document is organized as follows..."
   - "Implementers only need to use..."
   - "This RFC updates/obsoletes..."
   - Sentences about what the document does, not what implementations must do

3. **Terminology definitions WITHOUT technical requirements**
   [ERROR] Example: "The term 'certificate' refers to..."
   [OK] BUT extract if it contains actual requirements: "The certificate MUST contain..."

4. **Page headers/footers**
   Example: "Standards Track [Page 5]"

5. **Informative/background content**
   - Historical background
   - Implementation suggestions without MUST/SHALL/SHOULD
   - General descriptions without specific constraints

[OK] ONLY EXTRACT technical rules about:
- Certificate fields: validity, subject, issuer, extensions, keyUsage, basicConstraints, etc.
- Specific algorithm requirements: RSA, ECDSA, SHA-256, key sizes
- Certificate validation procedures: path validation, revocation checking
- Encoding/format requirements: DER, PEM, ASN.1 structures
- PKI policy requirements with specific constraints

**Rule of thumb**:
- If it starts with "This document..." → It's meta-information, IGNORE IT
- If it starts with "The certificate MUST..." → It's a technical rule, EXTRACT IT
- If it doesn't specify WHAT to do with WHICH certificate field/component → IGNORE IT
- Ask yourself: "Does this tell me HOW to build/validate a certificate?" If NO → IGNORE IT

Output format for each TECHNICAL rule:
---
TEXT: <exact requirement sentence>
SECTION: <section number if visible, e.g., "7.1.2", "4.2.1.9", or "unknown">
TITLE: <section title if visible, e.g., "Subject Alternative Name", or "unknown">
FIELD: <certificate field, e.g., validity, keyUsage, basicConstraints, subjectAltName>
OP: <ONE of the following - REQUIRED>:

  ** Existence Operations **
  - must_be_present: Field MUST exist in certificate
  - must_not_be_present: Field MUST NOT exist
  - must_be_critical: Extension MUST be marked critical
  - must_not_be_critical: Extension MUST NOT be marked critical

  ** Value Equality Operations **
  - equals: Field value MUST equal specific value
  - not_equals: Field value MUST NOT equal specific value
  - contains: Field value MUST contain substring
  - matches_regex: Value MUST match pattern
  - one_of: Value MUST be one of enumerated options

  ** Numeric Comparison Operations (IMPORTANT: Choose carefully based on boundary semantics) **
  - minimum_value: Numeric value must be AT LEAST X (>= X, boundary INCLUDED)
    Example: "minimum key size is 2048 bits" → minimum_value: 2048

  - maximum_value: Numeric value must be AT MOST X (<= X, boundary INCLUDED)
    Example: "maximum validity period is 825 days" → maximum_value: 825

  - must_not_exceed: Value MUST NOT exceed X (< X or <= X depending on context)
    Example: "SHALL NOT exceed 398 days" → must_not_exceed: 398
    Example: "exceeding 398 days" → must_not_exceed: 398

  - must_be_less_than: Value MUST be strictly less than X (< X, boundary EXCLUDED)
    Example: "MUST be less than 100" → must_be_less_than: 100

  - must_be_greater_than: Value MUST be strictly greater than X (> X, boundary EXCLUDED)
    Example: "MUST be greater than 0" → must_be_greater_than: 0

  - must_be_at_least: Value MUST be at least X (>= X, boundary INCLUDED, synonym of minimum_value)
    Example: "MUST be at least 2048 bits" → must_be_at_least: 2048

  [WARNING] You MUST select ONE of the above operations. Pay special attention to boundary semantics:

  ** Operation Selection Guide **
  - "MUST be present/included" → must_be_present
  - "MUST NOT be present/included" → must_not_be_present
  - "MUST be marked critical" → must_be_critical
  - "SHALL be/equal" + specific value → equals
  - "SHALL NOT be/equal" + specific value → not_equals
  - "MUST contain" → contains

  ** Numeric Operations - BE PRECISE **
  - "minimum X" / "at least X" → minimum_value or must_be_at_least
  - "maximum X" / "at most X" → maximum_value
  - "SHALL NOT exceed X" / "exceeding X" / "not exceed X" → must_not_exceed
  - "less than X" (strict) → must_be_less_than
  - "greater than X" (strict) → must_be_greater_than

  DO NOT leave blank or use 'unknown'.
VALUE: <expected value if any>
LEVEL: <MUST|SHOULD|MAY|MUST_NOT|SHOULD_NOT>
CONDITION: <if/when condition clause, e.g., "if the certificate is a CA certificate", or "none" if unconditional>
---

**CRITICAL**: Do NOT extract:
- Version numbers (e.g., "Version 2.1.9")
- Dates (e.g., "10-November-2025")
- Copyright notices
- License information
- Document titles without technical requirements

Text:
{chunk[:8000]}

TECHNICAL Rules (ignore all meta-information):
"""

        try:
            # ========== 动态计算max_tokens（单chunk版本）==========
            MODEL_CONTEXT_WINDOW = settings.llm_context_window

            # 估算输入tokens
            def estimate_tokens(text: str) -> int:
                return len(text) // 4

            # 估算当前chunk的输入token数
            chunk_text = chunk[:8000]
            prompt_tokens = estimate_tokens(prompt) + estimate_tokens(chunk_text)

            # 计算可用输出tokens（预留10%安全边界）
            available_output_tokens = int((MODEL_CONTEXT_WINDOW - prompt_tokens) * 0.9)

            # 根据chunk大小动态调整期望输出
            # 大chunk可能包含更多规则，需要更多输出tokens
            chunk_size = len(chunk)
            if chunk_size < 2000:
                ideal_tokens = 3000
            elif chunk_size < 5000:
                ideal_tokens = 6000
            else:
                ideal_tokens = 12000

            # 取两者较小值
            dynamic_max_tokens = min(ideal_tokens, available_output_tokens, 40000)
            dynamic_max_tokens = max(2000, dynamic_max_tokens)

            app_logger.debug(
                f"[Single Chunk {chunk_num}] chunk_size={chunk_size} chars, "
                f"input_tokens≈{prompt_tokens}, max_tokens={dynamic_max_tokens}"
            )

            async with httpx.AsyncClient(timeout=600.0) as client:  # 增加超时：120→300秒（适应DeepSeek推理模型）
                response = await client.post(
                    f"{self.llm_api_base}/chat/completions",
                    headers={
                        "Authorization": f"Bearer {self.llm_api_key}",
                        "Content-Type": "application/json"
                    },
                    json={
                        "model": self.llm_model,
                        "messages": [{"role": "user", "content": prompt}],
                        "temperature": 0.1,
                        "max_tokens": dynamic_max_tokens  # 动态计算，充分利用128k上下文窗口
                    }
                )

                response.raise_for_status()
                result = response.json()
                content = result['choices'][0]['message']['content']

                parsed_rules = self._parse_llm_response(content, chunk, chunk_num)

                # 诊断信息：检查是否有token截断
                if 'usage' in result and result['usage'].get('total_tokens', 0) > 0:
                    finish_reason = result['choices'][0].get('finish_reason', 'unknown')
                    if finish_reason == 'length':
                        app_logger.warning(
                            f"Chunk {chunk_num}: LLM output truncated due to max_tokens limit. "
                            f"Extracted {len(parsed_rules)} rules, but may have missed more."
                        )

                return parsed_rules

        except httpx.TimeoutException as e:
            app_logger.error(f"LLM extraction timeout for chunk {chunk_num} after 600s: {e}")
            return []
        except httpx.HTTPStatusError as e:
            app_logger.error(
                f"LLM API error for chunk {chunk_num}: "
                f"Status {e.response.status_code}, Response: {e.response.text[:200]}"
            )
            return []
        except Exception as e:
            app_logger.error(
                f"LLM extraction failed for chunk {chunk_num}: {type(e).__name__}: {e}",
                exc_info=True
            )
            return []

    async def _llm_extract_with_evidence(
        self,
        section: str,
        evidence: List[Dict],
        context: Dict
    ) -> List[Dict]:
        """基于RAG证据的LLM提取 - 优化版本"""

        evidence_text = "\n".join([f"- {e['text'][:150]}" for e in evidence[:3]])  # 缩短证据文本

        # 更简洁的prompt
        prompt = f"""Extract requirements using similar rules as reference.

Similar:
{evidence_text}

Text:
{section[:800]}

Format:
---
TEXT: <sentence>
FIELD: <field>
OP: <operation>
---

Rules:"""

        try:
            # ========== 动态计算max_tokens（evidence版本）==========
            MODEL_CONTEXT_WINDOW = settings.llm_context_window

            # 估算输入tokens
            def estimate_tokens(text: str) -> int:
                return len(text) // 4

            prompt_tokens = estimate_tokens(prompt)

            # evidence-based提取的prompt较简洁，输入较小
            # 可以分配更多tokens给输出
            available_output_tokens = int((MODEL_CONTEXT_WINDOW - prompt_tokens) * 0.9)

            # 根据section大小动态调整
            section_size = len(section)
            if section_size < 1000:
                ideal_tokens = 5000
            elif section_size < 3000:
                ideal_tokens = 10000
            else:
                ideal_tokens = 20000

            dynamic_max_tokens = min(ideal_tokens, available_output_tokens, 50000)
            dynamic_max_tokens = max(3000, dynamic_max_tokens)

            app_logger.debug(
                f"[Evidence Extraction] section_size={section_size}, "
                f"input_tokens≈{prompt_tokens}, max_tokens={dynamic_max_tokens}"
            )

            async with httpx.AsyncClient(timeout=120.0) as client:  # 增加超时以适应更大的输出
                response = await client.post(
                    f"{self.llm_api_base}/chat/completions",
                    headers={
                        "Authorization": f"Bearer {self.llm_api_key}",
                        "Content-Type": "application/json"
                    },
                    json={
                        "model": self.llm_model,
                        "messages": [{"role": "user", "content": prompt}],
                        "temperature": 0.1,
                        "max_tokens": dynamic_max_tokens  # 动态计算，充分利用128k上下文窗口
                    }
                )

                response.raise_for_status()
                result = response.json()
                content = result['choices'][0]['message']['content']

                rules = self._parse_llm_response(content, section, 0)

                # 标记为RAG增强
                for rule in rules:
                    rule['rag_evidence'] = evidence[:3]
                    rule['extraction_method'] = 'llm_with_rag_evidence'

                return rules

        except Exception as e:
            app_logger.error(f"LLM extraction with evidence failed: {e}")
            return []

    def _parse_llm_response(self, response: str, chunk: str, chunk_num: int) -> List[Dict]:
        """解析LLM返回的规则"""
        rules = []
        blocks = response.split('---')

        for block in blocks:
            if len(block.strip()) < 20:
                continue

            rule = self._parse_rule_block(block, chunk, chunk_num)
            if rule:
                rules.append(rule)

        return rules

    def _parse_rule_block(self, block: str, chunk: str, chunk_num: int) -> Optional[Dict]:
        """解析单个规则块"""
        lines = block.split('\n')
        rule_data = {
            'text': None,
            'section': '',
            'title': '',
            'affected_field': None,
            'operation': None,
            'expected_value': None,
            'requirement_level': None,
            'condition': None
        }

        for line in lines:
            line = line.strip()
            if line.startswith('TEXT:'):
                rule_data['text'] = line.split(':', 1)[1].strip()
            elif line.startswith('SECTION:'):
                section = line.split(':', 1)[1].strip()
                rule_data['section'] = section if section.lower() != 'unknown' else ''
            elif line.startswith('TITLE:'):
                title = line.split(':', 1)[1].strip()
                rule_data['title'] = title if title.lower() != 'unknown' else ''
            elif line.startswith('FIELD:'):
                rule_data['affected_field'] = line.split(':', 1)[1].strip()
            elif line.startswith('OP:'):
                rule_data['operation'] = line.split(':', 1)[1].strip()
            elif line.startswith('VALUE:'):
                rule_data['expected_value'] = line.split(':', 1)[1].strip()
            elif line.startswith('LEVEL:'):
                rule_data['requirement_level'] = line.split(':', 1)[1].strip()
            elif line.startswith('CONDITION:'):
                condition = line.split(':', 1)[1].strip()
                rule_data['condition'] = condition if condition.lower() not in ['none', 'n/a', ''] else None

        if not rule_data['text'] or len(rule_data['text']) < 10:
            return None

        # ========== Bug Fix #3: 清理文本格式异常（缺少空格）==========
        rule_data['text'] = self._clean_rule_text(rule_data['text'])

        # 如果清理后文本过短或异常，拒绝此规则
        if not rule_data['text'] or len(rule_data['text']) < 10:
            app_logger.debug(f"Rejected rule due to text cleaning: {rule_data.get('text', '')[:50]}")
            return None

        rule_data['context'] = chunk[:200]
        rule_data['chunk_number'] = chunk_num

        return rule_data

    def _clean_rule_text(self, text: str) -> str:
        """
        清理规则文本中的格式异常

        修复：
        1. 缺失的空格（如"CAMUSTNOTrely" → "CA MUST NOT rely"）
        2. 多余的空白字符
        3. 控制字符
        """
        if not text:
            return text

        import re

        # 1. 修复常见的大写单词连写问题（规范性关键词）
        # 模式：大写字母后跟大写单词（MUST/SHALL/SHOULD/MAY/NOT/CA/IF/WHEN等）
        normative_keywords = [
            'MUST', 'MUSTNOT', 'SHALL', 'SHALLNOT', 'SHOULD', 'SHOULDNOT',
            'MAY', 'MAYNOT', 'REQUIRED', 'PROHIBITED', 'RECOMMENDED',
            'OPTIONAL', 'NOT', 'IF', 'WHEN', 'WHERE', 'UNLESS'
        ]

        # 为每个关键词添加空格分隔（注意顺序：先处理长词）
        for keyword in sorted(normative_keywords, key=len, reverse=True):
            # 匹配连写的关键词，但不破坏已有的正确格式
            # 例如：CAMUSTrely → CA MUST rely，但保留 "MUST" 本身
            text = re.sub(
                rf'\b([A-Z][a-z]*){keyword}([A-Z][a-z]+)',
                rf'\1 {keyword} \2',
                text
            )

        # 2. 修复小写单词开头连写到大写单词的情况（如"relyon" → "rely on"）
        # 但要小心不要破坏正常的驼峰命名（如keyUsage）
        # 策略：只在小写字母后立即跟大写字母且后面还有小写字母时添加空格
        text = re.sub(r'([a-z])([A-Z][a-z])', r'\1 \2', text)

        # 3. 清理多余的空白字符（保留单个空格）
        text = re.sub(r'\s+', ' ', text).strip()

        # 4. 清理控制字符
        text = re.sub(r'[\x00-\x08\x0B\x0C\x0E-\x1F]', '', text)

        return text

    def _texts_are_similar(self, text1: str, text2: str, threshold: float = 0.8) -> bool:
        """判断两个文本是否相似"""
        if not text1 or not text2:
            return False
        words1 = set(text1.lower().split())
        words2 = set(text2.lower().split())

        if not words1 or not words2:
            return False

        intersection = len(words1 & words2)
        union = len(words1 | words2)

        return (intersection / union) >= threshold if union > 0 else False

    def _cleanup_control_characters(self, rules: List[Dict]) -> List[Dict]:
        """
        清理控制字符和多余空白字符

        清理：
        1. 控制字符（换页符等）
        2. 多余的空白字符
        3. 过滤清理后文本过短的规则
        """
        import re

        cleaned_rules = []
        control_chars_cleaned = 0

        for rule in rules:
            text = rule.get('text', '')
            original_text = text

            # 清理控制字符
            # \x0C: 换页符 (Form Feed)
            # \x00-\x08, \x0B, \x0E-\x1F: 其他控制字符
            text = re.sub(r'[\x00-\x08\x0B\x0C\x0E-\x1F]', '', text)

            # 清理多余的空白字符
            text = re.sub(r'\s+', ' ', text).strip()

            # 如果清理后文本发生变化，计数
            if text != original_text:
                control_chars_cleaned += 1

            rule['text'] = text

            # label-don't-drop：全部保留，含清理后过短的残片（如 "title,"、"OPTIONAL"）
            # 这类无-IR 残片按噪声入库（is_noise 由落库口标记），不在此处丢弃。2026-06-03
            if text:
                cleaned_rules.append(rule)
                if len(text) < 10:
                    app_logger.info(f"[cleanup] Keeping short rule (len={len(text)}): {original_text[:100]}...")

        if control_chars_cleaned > 0:
            app_logger.info(f"Cleaned control characters from {control_chars_cleaned} rules")

        return cleaned_rules

    def _calculate_statistics(self, result: Dict) -> Dict:
        """计算统计信息（两层流程）"""
        stats = {
            'total_rules': len(result['final_rules'])
        }

        return stats

    def _prepare_visualization_data(self, result: Dict) -> Dict:
        """准备前端可视化数据（两层流程）"""
        layers_data = []

        # Layer 1: Regex规则发现
        if 'layer1_regex' in result['layers']:
            layers_data.append({
                'name': 'Layer 1: Regex 规则发现',
                'count': result['layers']['layer1_regex']['count'],
                'quality': result['layers']['layer1_regex'].get('quality', 'N/A'),
                'color': '#3b82f6',
                'method': 'RFC2119关键词枚举'
            })

        # Layer 2: LLM规则理解
        layer2 = None
        if 'layer2_llm' in result['layers']:
            layer2 = result['layers']['layer2_llm']

        if layer2:
            # 新架构：Layer 2输出规则数 = Layer 1输入规则数（理解而非提取）
            quality_desc = layer2.get('quality', 'N/A')

            layers_data.append({
                'name': 'Layer 2: LLM 规则理解',
                'count': layer2['count'],
                'quality': quality_desc,
                'color': '#10b981',
                'method': 'IR语义理解'
            })

        # 最终结果（数据库保存数量）
        layers_data.append({
            'name': '最终保存',
            'count': len(result['final_rules']),
            'quality': f"总规则数: {len(result['final_rules'])}",
            'color': '#22c55e',
            'method': '已保存到数据库'
        })

        return {
            'layers': layers_data
        }

