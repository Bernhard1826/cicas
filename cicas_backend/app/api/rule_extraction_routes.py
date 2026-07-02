"""
规则提取API路由
提供 Regex + LLM + KG 混合提取功能
"""
from fastapi import APIRouter, Depends, HTTPException, BackgroundTasks
from sqlalchemy.orm import Session
from typing import Optional
from pydantic import BaseModel, Field
from datetime import datetime
import hashlib
import json

from app.core.database import get_db
from app.core.logging_config import app_logger
from app.services.full_pipeline_extractor import FullPipelineExtractor
from app.models.models import Standard, Rule
import uuid
import asyncio

# ========== 并发控制：防止同一标准的多个提取任务同时运行 ==========
_extraction_lock = asyncio.Lock()

router = APIRouter(prefix="/api/v1/rule-extraction", tags=["Rule Extraction"])


# ==================== Helper Functions ====================

def _text_similarity(text1: str, text2: str) -> float:
    """简单的文本相似度计算（Jaccard similarity）"""
    words1 = set(text1.lower().split())
    words2 = set(text2.lower().split())

    if not words1 or not words2:
        return 0.0

    intersection = len(words1 & words2)
    union = len(words1 | words2)

    return intersection / union if union > 0 else 0.0


def _jsonable_text(value):
    """Serialize complex extractor objects before writing text columns."""
    if value is None or isinstance(value, str):
        return value
    if hasattr(value, "model_dump"):
        value = value.model_dump()
    elif hasattr(value, "dict"):
        value = value.dict()
    elif hasattr(value, "__dict__") and not isinstance(value, (int, float, bool)):
        value = value.__dict__
    if isinstance(value, (list, dict, tuple)):
        return json.dumps(value, ensure_ascii=False, default=str)
    return str(value)


# ==================== Request/Response Models ====================

class ExtractionRequest(BaseModel):
    """规则提取请求"""
    standard_id: int = Field(..., description="标准ID")
    enable_llm: bool = Field(default=True, description="是否启用LLM辅助提取（推荐开启，已优化速度）")
    enable_kg: bool = Field(default=True, description="是否启用知识图谱增强（推荐开启）")
    force: bool = Field(default=False, description="是否强制重新提取（忽略缓存）")
    custom_keywords: Optional[list[str]] = Field(default=None, description="自定义规范性关键词（会添加到默认关键词之上）")


class ExtractionResponse(BaseModel):
    """规则提取响应"""
    task_id: str
    status: str
    message: str
    timestamp: str


class RerunFailedIRRequest(BaseModel):
    """失败规则 IR 重跑请求。

    每次提取都会有 skeleton 无法产出 IR（LLM 空响应 / JSON 截断 /
    scope-filter 误删）。这些行召回已落库但缺 IR，无法分类、破坏 Q1 守恒。
    本接口定向重跑这些失败行：id-preserving，只 UPDATE ir_data 及 IR 派生列，
    不删不重插，幂等可多次迭代直到残差稳定。
    """
    standard_id: int = Field(..., description="标准ID（如 1=RFC5280, 19=CABF-BR）")
    dry_run: bool = Field(default=True, description="为 True 只统计失败行数量、不调用 LLM、不写库")
    limit: Optional[int] = Field(default=None, description="本次最多重跑多少条失败行（None=全部）")


class RerunFailedIRResponse(BaseModel):
    """失败规则 IR 重跑响应"""
    task_id: str
    status: str
    message: str
    standard_id: int
    failed_total: int          # 当前无 IR 的失败行总数
    selected: int              # 本次选中重跑的行数
    dry_run: bool
    timestamp: str



# ==================== Endpoints ====================

@router.post("/extract-full-pipeline")
async def extract_rules_full_pipeline(
    request: ExtractionRequest,
    db: Session = Depends(get_db)
):
    """
    完整的2层提取流程: Regex(召回) + RAG+LLM(IR提取)

    Layer 1: Regex基础提取 - 枚举规则骨架，保证召回率
    Layer 2: RAG + LLM规则理解 - 语义理解 + IR填充

    Args:
        request: 包含标准ID和配置选项
        db: 数据库会话

    Returns:
        task_id和初始状态
    """
    try:
        # 检查标准是否存在
        standard = db.query(Standard).filter(Standard.id == request.standard_id).first()
        if not standard:
            raise HTTPException(status_code=404, detail=f"Standard {request.standard_id} not found")

        # 生成任务ID
        task_id = f"std_{request.standard_id}_{uuid.uuid4().hex[:8]}"

        app_logger.info(
            f"Starting FULL PIPELINE extraction for standard {request.standard_id}: {standard.title} "
            f"(task_id: {task_id})"
        )

        # 创建完整流程提取器
        extractor = FullPipelineExtractor(
            db=db,
            custom_keywords=request.custom_keywords
        )

        # 执行完整流程提取
        result = await extractor.extract_with_full_pipeline(request.standard_id)

        # ========== 保存规则到数据库 ==========
        extracted_rules = result.get('final_rules', [])
        saved_count = 0

        # ========== FIX: 先删除该标准的旧规则（智能删除引用关系）==========
        try:
            # 先获取要删除的规则ID
            from app.models.models import AdversarialFeedback
            from sqlalchemy import text
            rule_ids = [r.id for r in db.query(Rule.id).filter(Rule.standard_id == request.standard_id).all()]

            if rule_ids:
                # 第一步：只删除 source_rule_id 指向当前标准的引用
                # 不删除 target_rule_id 指向当前标准的引用（由其他文档指向）
                # 这些引用会在后续的"更新未解析引用"阶段被更新
                # FIX: Use ANY() syntax for PostgreSQL instead of IN with tuple
                deleted_kg = db.execute(
                    text("""
                        DELETE FROM kg_relations
                        WHERE source_rule_id = ANY(:rule_ids)
                    """),
                    {'rule_ids': rule_ids}
                ).rowcount
                app_logger.info(f"Deleted {deleted_kg} kg_relations records (source only)")

                # 第二步：将 target_rule_id 指向被删除规则的引用标记为未解析
                # 这些引用会在后续被重新解析
                updated_to_unresolved = db.execute(
                    text("""
                        UPDATE kg_relations
                        SET target_rule_id = NULL,
                            is_uncertain = true,
                            confidence = 0.0,
                            reason = jsonb_set(
                                COALESCE(reason, '{}'::jsonb),
                                '{temporarily_unresolved}',
                                'true'::jsonb
                            )
                        WHERE target_rule_id = ANY(:rule_ids)
                    """),
                    {'rule_ids': rule_ids}
                ).rowcount
                app_logger.info(
                    f"Marked {updated_to_unresolved} references as temporarily unresolved "
                    f"(will be resolved after extraction)"
                )

                # 第三步：删除adversarial_feedback中的相关记录
                deleted_feedback = db.query(AdversarialFeedback).filter(
                    AdversarialFeedback.rule_id.in_(rule_ids)
                ).delete(synchronize_session=False)
                app_logger.info(f"Deleted {deleted_feedback} adversarial_feedback records")

                # 第四步：删除规则
                deleted_count = db.query(Rule).filter(Rule.standard_id == request.standard_id).delete(synchronize_session=False)
                db.flush()  # Flush删除操作，确保在当前事务中生效，避免hash冲突
                app_logger.info(f"Deleted {deleted_count} old rules (flushed, will commit after new rules saved)")
            else:
                app_logger.info("No old rules to delete")

        except Exception as e:
            app_logger.error(f"Failed to delete old rules: {e}", exc_info=True)
            db.rollback()
            raise

        if extracted_rules:
            app_logger.info(f"Saving {len(extracted_rules)} rules to database...")

            app_logger.info(f"[START] Saving {len(extracted_rules)} rules to database...")

            # 内存去重：跟踪已保存的 hash（同一次提取中避免重复）
            saved_hashes = set()
            # 跟踪新保存的规则及其索引，用于后续IR保存
            saved_rules_list = []  # List of (idx, rule_object)

            # 保存新规则
            for idx, rule_data in enumerate(extracted_rules):
                try:
                    if not isinstance(rule_data, dict) or 'text' not in rule_data or not rule_data['text']:
                        app_logger.error(f"Rule {idx+1} invalid: keys={list(rule_data.keys()) if isinstance(rule_data, dict) else type(rule_data)}")
                        continue

                    rule_text = rule_data.get('text', '')
                    section = rule_data.get('section', '')
                    title = rule_data.get('title', '')

                    # ========== 章节号验证（噪声标记，不跳过） ==========
                    # 即使章节号无效也入库，只是标记为噪声
                    section_valid, section_reason = _is_valid_section(section, standard.source)
                    if not section_valid:
                        app_logger.warning(f"Rule {idx+1}: invalid section - {section_reason}, saving with noise flag")
                        rule_data['is_noise'] = True
                        rule_data['noise_reason'] = f"invalid_section: {section_reason}"

                    # ========== 标题验证（噪声标记，不跳过） ==========
                    title_valid, title_reason = _is_valid_title(title)
                    if not title_valid:
                        app_logger.debug(f"Rule {idx+1}: invalid title - {title_reason}, saving with noise flag")
                        rule_data['is_noise'] = True
                        rule_data['noise_reason'] = f"{rule_data.get('noise_reason', '')}; invalid_title: {title_reason}"

                    # ========== 无-IR/未分类残片：入库并标噪声（label-don't-drop） ==========
                    # recall_merge 对 Layer-2 未出 IR 的 skeleton 标 unclassified=True；
                    # 这类残片（含被 cleanup 保留的过短片段）入库但标 is_noise，不丢弃。
                    if rule_data.get('unclassified'):
                        rule_data['is_noise'] = True
                        rule_data['noise_reason'] = f"{rule_data.get('noise_reason', '') or ''}; no_ir_unclassified".strip('; ')

                    # ========== 表格碎片：丢失上下文的退化行（"4 | MUST NOT"）入库标噪声 ==========
                    # 通用结构判据（_is_fragment_text）：主体退化为裸编号/空 + 无约束子句 →
                    # 非可恢复的单制品规则，标 is_noise，不进 lintability/codegen（label-don't-drop）。
                    _frag, _frag_reason = _is_fragment_text(rule_text, rule_data.get('subject') or '')
                    if _frag:
                        rule_data['is_noise'] = True
                        rule_data['noise_reason'] = f"{rule_data.get('noise_reason', '') or ''}; {_frag_reason}".strip('; ')

                    # ========== 内存去重 key：text + section + rule_type + sentence_index ==========
                    # 含 section：跨章节同措辞是不同扩展的独立规则，须各自落库
                    # 含 rule_type：同一句拆出 MUST 和 MAY 是不同 assertion，须各自落库
                    # 含 sentence_index：同章节同句的不同 occurrence 也各自落库（label-don't-drop）
                    rt_for_hash = rule_data.get('rule_type') or rule_data.get('requirement_level') or ''
                    sidx_for_hash = rule_data.get('sentence_index')
                    rule_hash = hashlib.sha256(
                        f"{request.standard_id}:{rule_text}:{section}:{rt_for_hash}:{sidx_for_hash}".encode('utf-8')
                    ).hexdigest()

                    # 内存去重：检查当前提取中是否已保存此 hash
                    if rule_hash in saved_hashes:
                        app_logger.debug(f"Skipping duplicate rule {idx+1} (hash: {rule_hash[:16]}...)")
                        continue
                    saved_hashes.add(rule_hash)

                    # 序列化复杂 extractor 对象，避免 Pydantic/自定义对象直接写 text 列。
                    condition_value = _jsonable_text(rule_data.get('condition'))
                    conditions_value = _jsonable_text(rule_data.get('conditions'))
                    expected_value_data = _jsonable_text(rule_data.get('expected_value'))
                    context_value = _jsonable_text(rule_data.get('context'))

                    # sentence_hash 仅作溯源/统计字段保留；不再据此跨 section 去重
                    # （跨章节同措辞是不同规则；去重已由含 section+rule_type+sentence_index 的 rule_hash 处理）
                    sentence_hash = rule_data.get('sentence_hash')

                    rule = Rule(
                        standard_id=request.standard_id,
                        section=section,
                        subsection=rule_data.get('subsection'),
                        title=title,
                        text=rule_text,
                        rule_type=rule_data.get('rule_type') or rule_data.get('requirement_level'),
                        # IR 派生标量(obligation/predicate/subject/constraint_value 等)
                        # 现为生成列,由后续写入的 ir_data 自动派生,不在此构造时赋值
                        # (2026-06-10 schema 迁移; 删了 modality/condition/subject_role/
                        #  affected_field/operation/expected_value 这些已废/错名列)。
                        conditions=conditions_value,
                        context=context_value,
                        hash=rule_hash,
                        # ⭐ CRITICAL: Deduplication fields
                        sentence_index=rule_data.get('sentence_index'),  # Track sentence position
                        sentence_hash=sentence_hash,                      # Track sentence uniqueness
                        is_noise=rule_data.get('is_noise', False),       # Noise flag (invalid section/title)
                        noise_reason=rule_data.get('noise_reason'),       # Noise reason details
                    )
                    db.add(rule)
                    db.commit()
                    saved_count += 1
                    saved_rules_list.append((idx, rule))  # Track saved rule with its original index
                except Exception as e:
                    app_logger.exception(f"Failed to save rule {idx+1}: {e}")
                    app_logger.error(f"Exception type: {type(e).__name__}")
                    app_logger.error(f"Exception args: {e.args}")
                    if isinstance(rule_data, dict):
                        app_logger.error(f"Rule text: {rule_data.get('text', 'N/A')[:100]}")
                        app_logger.error(f"Rule section: {rule_data.get('section', 'N/A')}")
                        app_logger.error(f"Rule affected_field: {rule_data.get('affected_field', 'N/A')}")
                        app_logger.error(f"Rule operation: {rule_data.get('operation', 'N/A')}")
                        app_logger.error(f"Rule hash: {rule_hash if 'rule_hash' in locals() else 'NOT GENERATED'}")
                    else:
                        app_logger.error(f"Rule data type: {type(rule_data)}")
                    db.rollback()
                    continue

            app_logger.info(f"[OK] Successfully saved {saved_count}/{len(extracted_rules)} rules to database")

            # ========== Post-Save: 保存IR数据到ir_data字段 ==========
            resolved_irs = result.get('resolved_irs', [])
            if resolved_irs:
                app_logger.info(f"[Post-Save IR] Saving IR data to {len(resolved_irs)} rules...")
                app_logger.info(f"[Post-Save IR] Saved rules count: {len(saved_rules_list)}")
                app_logger.info(f"[Post-Save IR] Resolved IRs count: {len(resolved_irs)}")

                # 使用正确的索引映射来保存IR
                ir_saved_count = 0
                ir_skipped_count = 0
                for idx, rule in saved_rules_list:
                    # 检查该规则的索引是否在resolved_irs范围内
                    if idx < len(resolved_irs):
                        try:
                            ir = resolved_irs[idx]
                            # 保存IR对象的JSON表示
                            rule.ir_data = ir.to_json()
                            ir_saved_count += 1

                            if ir_saved_count <= 3:  # 只记录前3条
                                app_logger.debug(f"Saved IR data for rule {rule.id} (extracted_rules[{idx}])")
                        except Exception as e:
                            app_logger.error(f"Failed to save IR for rule {rule.id} (idx={idx}): {e}")
                    else:
                        # ⭐ regex_unclassified 行（无IR骨架）：保存降级 ir_data 表示，
                        # 保证每条规则都有 ir_data 不为 NULL，满足"无IR也得入库"铁律。
                        rule_data = extracted_rules[idx]
                        fallback_ir = {
                            '_fallback': True,   # 标记：非 LLM 提取，是骨架降级表示
                            'rule_text': rule_data.get('text', ''),
                            'section': rule_data.get('section', ''),
                            'title': rule_data.get('title', ''),
                            'extraction_method': rule_data.get('extraction_method', 'regex_unclassified'),
                            'rule_type': rule_data.get('rule_type') or rule_data.get('requirement_level') or 'UNKNOWN',
                            'modality': rule_data.get('modality') or rule_data.get('rule_type') or 'UNKNOWN',
                            'sentence_hash': rule_data.get('sentence_hash'),
                            'sentence_index': rule_data.get('sentence_index'),
                        }
                        rule.ir_data = json.dumps(fallback_ir, ensure_ascii=False)
                        ir_skipped_count += 1

                db.commit()
                app_logger.info(f"[Post-Save IR] ✓ Saved IR data for {ir_saved_count}/{len(saved_rules_list)} rules (skipped: {ir_skipped_count})")
            else:
                # ⭐ 无 resolved_irs：所有规则都是 regex_unclassified，全部写降级 ir_data
                app_logger.warning(f"[Post-Save IR] No resolved_irs available - writing fallback ir_data for all {len(saved_rules_list)} rules")
                for idx, rule in saved_rules_list:
                    rule_data = extracted_rules[idx]
                    fallback_ir = {
                        '_fallback': True,
                        'rule_text': rule_data.get('text', ''),
                        'section': rule_data.get('section', ''),
                        'title': rule_data.get('title', ''),
                        'extraction_method': rule_data.get('extraction_method', 'regex_unclassified'),
                        'rule_type': rule_data.get('rule_type') or rule_data.get('requirement_level') or 'UNKNOWN',
                        'modality': rule_data.get('modality') or rule_data.get('rule_type') or 'UNKNOWN',
                        'sentence_hash': rule_data.get('sentence_hash'),
                        'sentence_index': rule_data.get('sentence_index'),
                    }
                    rule.ir_data = json.dumps(fallback_ir, ensure_ascii=False)
                db.commit()
                app_logger.info(f"[Post-Save IR] ✓ Wrote fallback ir_data for all {len(saved_rules_list)} rules")


            # ========== Step 3.5: 自动裁决和派生规则生成 (已禁用) ==========
            # 注释理由: 规则拆分逻辑已完善，不再需要compose和裁决
            adjudication_stats = {
                'basic_rules_adjudicated': 0,
                'executable': 0,
                'partially_executable': 0,
                'non_executable': 0,
                'conflicts_resolved': 0,
                'references_expanded': 0,
                'total_derived': 0,
                'failed': False,
                'error': None
            }

            # if saved_rules_list:
            #     try:
            #         from app.services.adjudication.rule_adjudicator import RuleAdjudicator
            #         from app.api.knowledge_graph_routes import get_knowledge_graph
            #
            #         # 获取知识图谱实例（从数据库构建或使用缓存）
            #         kg = get_knowledge_graph()
            #
            #         adjudicator = RuleAdjudicator(db, kg=kg)
            #         saved_rule_ids = [rule.id for _, rule in saved_rules_list]
            #
            #         # ========== Step 3.5.1: 基础规则裁决 ==========
            #         app_logger.info(f"[Step 3.5.1 Adjudication] Starting rule adjudication for {len(saved_rules_list)} rules...")
            #
            #         for idx, rule in saved_rules_list:
            #             try:
            #                 # 对每条规则进行裁决
            #                 adjudication_result = adjudicator.adjudicate_rule(rule, update_db=True)
            #                 adjudication_stats['basic_rules_adjudicated'] += 1
            #
            #                 # 统计可执行性
            #                 if adjudication_result.executability == 'executable':
            #                     adjudication_stats['executable'] += 1
            #                 elif adjudication_result.executability == 'partially_executable':
            #                     adjudication_stats['partially_executable'] += 1
            #                 else:
            #                     adjudication_stats['non_executable'] += 1
            #
            #             except Exception as e:
            #                 app_logger.error(f"Failed to adjudicate rule {rule.id}: {e}")
            #                 continue
            #
            #         db.commit()  # 提交裁决结果
            #
            #         app_logger.info(
            #             f"[OK] Adjudication complete: {adjudication_stats['basic_rules_adjudicated']} rules adjudicated, "
            #             f"executable={adjudication_stats['executable']}, "
            #             f"partially={adjudication_stats['partially_executable']}, "
            #             f"non-executable={adjudication_stats['non_executable']}"
            #         )
            #
            #         # ========== Step 3.5.2: 自动生成派生规则 ==========
            #         app_logger.info(f"[Step 3.5.2 Auto-Derive] Starting automatic derived rule generation...")
            #
            #         # 自动检测并生成派生规则
            #         derive_result = adjudicator.auto_derive_rules(
            #             rule_ids=saved_rule_ids,
            #             max_group_size=5
            #         )
            #
            #         # 更新统计信息
            #         adjudication_stats['conflicts_resolved'] = derive_result['conflicts_resolved']
            #         adjudication_stats['references_expanded'] = derive_result['references_expanded']
            #         adjudication_stats['total_derived'] = derive_result['total_derived']
            #
            #         app_logger.info(
            #             f"[OK] Auto-derive complete: "
            #             f"{adjudication_stats['conflicts_resolved']} conflicts resolved, "
            #             f"{adjudication_stats['references_expanded']} references expanded, "
            #             f"总计 {adjudication_stats['total_derived']} 条派生规则"
            #         )
            #
            #     except Exception as e:
            #         # 裁决和派生失败不影响规则提取，只记录错误
            #         app_logger.error(f"[WARNING] Adjudication/Auto-derive failed (rules are still saved): {e}", exc_info=True)
            #         adjudication_stats['failed'] = True
            #         adjudication_stats['error'] = str(e)
            # else:
            #     app_logger.info(f"[Step 3.5] No rules to adjudicate or derive, skipping")


            # ========== 重构后：调用 Rule Reasoning Service ==========
            try:
                from app.services.reasoning import RuleReasoningService
                from sqlalchemy import text
                from app.services.extraction.enhanced_reference_resolver import EnhancedReferenceResolver
                from app.services.extraction.ir_schema import IntermediateRepresentation

                # 获取刚保存的规则（包含 db_id）
                all_rules = db.query(Rule).filter(Rule.standard_id == request.standard_id).all()

                # ⚠️ 重要修复：在保存规则后重新提取 ReferenceFacts
                # 因为之前 IR 还没有 rule_id，所以提取了 0 个 reference_facts
                app_logger.info("[Rule Reasoning Service] Re-extracting ReferenceFacts with rule_ids...")

                # 从 result 中获取 IRs（如果有）
                resolved_irs = result.get('resolved_irs', [])

                reference_facts = []
                if resolved_irs:
                    # 更新 IR 的 rule_id（使用 section 精确匹配，比 hash 更可靠）
                    # 为每个 section 创建一个规则列表（因为一个 section 可能有多条规则）
                    section_to_rules = {}
                    for r in all_rules:
                        if r.section not in section_to_rules:
                            section_to_rules[r.section] = []
                        section_to_rules[r.section].append(r)

                    matched_count = 0
                    for ir in resolved_irs:
                        # 提取 section
                        section = ir.provenance[0].section if ir.provenance and len(ir.provenance) > 0 else ''

                        if section and section in section_to_rules:
                            # 找到该 section 的规则列表
                            candidates = section_to_rules[section]

                            # 如果只有一条规则，直接匹配
                            if len(candidates) == 1:
                                ir.rule_id = str(candidates[0].id)
                                matched_count += 1
                            else:
                                # 多条规则，尝试用文本相似度匹配
                                best_match = None
                                best_score = 0

                                for candidate in candidates:
                                    # 简单的相似度：看文本的开头是否匹配
                                    if candidate.text.startswith(ir.rule_text[:50]):
                                        best_match = candidate
                                        break

                                    # 或者计算更精确的相似度
                                    score = _text_similarity(ir.rule_text, candidate.text)
                                    if score > best_score:
                                        best_score = score
                                        best_match = candidate

                                if best_match and best_score > 0.8:
                                    ir.rule_id = str(best_match.id)
                                    matched_count += 1
                                else:
                                    app_logger.debug(
                                        f"[Rule Reasoning] IR section={section} has {len(candidates)} rules, "
                                        f"best_score={best_score:.2f}, text={ir.rule_text[:50]}..."
                                    )
                        else:
                            app_logger.debug(
                                f"[Rule Reasoning] IR section={section} not found in database, text={ir.rule_text[:50]}..."
                            )

                    app_logger.info(
                        f"[Rule Reasoning Service] Matched {matched_count}/{len(resolved_irs)} IRs with rule_ids (by section)"
                    )

                    # 重新提取 ReferenceFacts（现在 IR 有 rule_id了）
                    resolver = EnhancedReferenceResolver(db=db)
                    reference_facts = resolver.extract_reference_facts(resolved_irs)

                    app_logger.info(
                        f"[Rule Reasoning Service] Re-extracted {len(reference_facts)} reference facts"
                    )

                if len(all_rules) > 0 and len(reference_facts) > 0:
                    app_logger.info(
                        f"[Rule Reasoning Service] Starting for {len(all_rules)} rules "
                        f"with {len(reference_facts)} reference facts..."
                    )

                    # 创建 Reasoning Service 实例
                    reasoning_service = RuleReasoningService(db)

                    # 执行所有推理层
                    reasoning_result = reasoning_service.run_all_reasoning(
                        rules=all_rules,
                        reference_facts=reference_facts
                    )

                    app_logger.info(
                        f"[Rule Reasoning Service] Complete: "
                        f"{len(reasoning_result['certain_relations'])} certain relations, "
                        f"{len(reasoning_result['uncertain_relations'])} uncertain relations, "
                        f"{len(reasoning_result['failures'])} failures"
                    )

                    # ========== 保存推理结果到 kg_relations 表 ==========
                    saved_relations = 0
                    for relation in reasoning_result['certain_relations']:
                        try:
                            # 序列化 reason
                            import json
                            reason_json = json.dumps(relation.reason, ensure_ascii=False)

                            # 插入关系
                            insert_query = text("""
                                INSERT INTO kg_relations (
                                    source_rule_id,
                                    target_rule_id,
                                    relation_type,
                                    algorithm_version,
                                    confidence,
                                    reason,
                                    created_at
                                ) VALUES (
                                    :source_rule_id,
                                    :target_rule_id,
                                    :relation_type,
                                    :algorithm_version,
                                    :confidence,
                                    :reason,
                                    NOW()
                                )
                            """)

                            db.execute(insert_query, {
                                'source_rule_id': relation.source_rule_id,
                                'target_rule_id': relation.target_rule_id,
                                'relation_type': relation.relation_type.value,
                                'algorithm_version': relation.algorithm_version,
                                'confidence': relation.confidence,
                                'reason': reason_json
                            })

                            saved_relations += 1

                        except Exception as e:
                            app_logger.error(f"Failed to save relation: {e}")
                            continue

                    # 保存不确定关系
                    for uncertain in reasoning_result['uncertain_relations']:
                        try:
                            import json
                            missing_json = json.dumps(uncertain.missing_dimensions, ensure_ascii=False)

                            insert_query = text("""
                                INSERT INTO kg_relations (
                                    source_rule_id,
                                    target_rule_id,
                                    relation_type,
                                    algorithm_version,
                                    confidence,
                                    is_uncertain,
                                    missing_dimensions,
                                    created_at
                                ) VALUES (
                                    :source_rule_id,
                                    :target_rule_id,
                                    :relation_type,
                                    :algorithm_version,
                                    :confidence,
                                    TRUE,
                                    :missing_dimensions,
                                    NOW()
                                )
                            """)

                            db.execute(insert_query, {
                                'source_rule_id': uncertain.source_rule_id,
                                'target_rule_id': uncertain.target_rule_id,
                                'relation_type': uncertain.relation_type.value,
                                'algorithm_version': uncertain.algorithm_version,
                                'confidence': uncertain.confidence,
                                'missing_dimensions': missing_json
                            })

                            saved_relations += 1

                        except Exception as e:
                            app_logger.error(f"Failed to save uncertain relation: {e}")
                            continue

                    # 保存失败记录
                    for failure in reasoning_result['failures']:
                        try:
                            insert_query = text("""
                                INSERT INTO kg_relations (
                                    source_rule_id,
                                    target_rule_id,
                                    relation_type,
                                    algorithm_version,
                                    is_failure,
                                    error_type,
                                    error_message,
                                    stage,
                                    created_at
                                ) VALUES (
                                    :source_rule_id,
                                    :target_rule_id,
                                    'REASONING_FAILED',
                                    :algorithm_version,
                                    TRUE,
                                    :error_type,
                                    :error_message,
                                    :stage,
                                    NOW()
                                )
                            """)

                            db.execute(insert_query, {
                                'source_rule_id': failure.source_rule_id,
                                'target_rule_id': failure.target_rule_id,
                                'algorithm_version': failure.algorithm_version,
                                'error_type': failure.error_type,
                                'error_message': failure.message,
                                'stage': failure.stage
                            })

                            saved_relations += 1

                        except Exception as e:
                            app_logger.error(f"Failed to save failure record: {e}")
                            continue

                    # 提交所有关系到数据库
                    db.commit()

                    app_logger.info(f"[OK] Saved {saved_relations} relations to kg_relations table")

                    # 添加到result中返回
                    result['rule_reasoning'] = {
                        'executed': True,
                        'certain_relations': len(reasoning_result['certain_relations']),
                        'uncertain_relations': len(reasoning_result['uncertain_relations']),
                        'failures': len(reasoning_result['failures']),
                        'relations_saved': saved_relations,
                        'statistics': reasoning_result['statistics']
                    }

                else:
                    app_logger.info("No rules or reference facts found, skipping reasoning")
                    result['rule_reasoning'] = {
                        'executed': False,
                        'reason': 'No rules or reference facts'
                    }

            except Exception as e:
                app_logger.error(f"Rule Reasoning Service failed (non-critical): {e}", exc_info=True)
                result['rule_reasoning'] = {'executed': False, 'error': str(e)}
                db.rollback()  # 回滚失败的关系插入

            # ========== zlint覆盖检测已移至独立接口 POST /rule-extraction/zlint-coverage-analysis ==========

            # ========== 跨文档处理：引用解析（仅检测当前标准的引用）==========
            try:
                from app.services.knowledge_graph.rule_conflict_and_reference_engine import RuleConflictAndReferenceEngine
                from app.services.knowledge_graph.knowledge_graph import CertificateKnowledgeGraph

                # 只获取当前标准的规则（增量检测）
                current_standard_rules = db.query(Rule).filter(
                    Rule.standard_id == request.standard_id
                ).all()

                if len(current_standard_rules) > 0:
                    app_logger.info(
                        f"[CROSS-DOC] Starting incremental reference detection for {len(current_standard_rules)} rules "
                        f"from {standard.title}..."
                    )

                    # 创建KG实例以便将引用和冲突写入kg_relations表
                    kg = CertificateKnowledgeGraph()
                    cross_doc_engine = RuleConflictAndReferenceEngine(db, kg=kg)

                    # 只执行引用解析（不执行冲突检测和有效规则合并，那些需要全量数据）
                    cross_doc_report = cross_doc_engine.run(
                        rule_candidates=current_standard_rules,  # 只检测当前标准
                        resolve_conflicts=False,  # 不执行冲突检测（需要全量）
                        merge_effective=False     # 不生成有效规则（需要全量）
                    )

                    app_logger.info(
                        f"[OK] Incremental reference detection complete: "
                        f"{cross_doc_report['references']['resolved']}/{cross_doc_report['references']['total_found']} references resolved"
                    )

                    # 添加到result中返回
                    result['cross_document_processing'] = {
                        'executed': True,
                        'mode': 'incremental',  # 增量模式
                        'references_resolved': cross_doc_report['references']['resolved'],
                        'summary': f"{cross_doc_report['references']['resolved']} refs detected for {standard.title}"
                    }

                    # 保存详细报告到result（用于诊断）
                    result['cross_document_detail'] = cross_doc_report

                    # 将引用和冲突写入kg_relations表
                    try:
                        from sqlalchemy import text
                        saved_refs = 0
                        saved_conflicts = 0

                        # 写入引用关系（包括已解析和未解析的）
                        # 修复：使用正确的字段名 'details' 而不是 'resolutions'
                        for ref in cross_doc_report['references']['details']:
                            # 情况1: 引用已解析（找到了目标规则）
                            if ref.get('resolved'):
                                for target_rule in ref.get('target_rules', []):
                                    try:
                                        db.execute(
                                            text("""
                                                INSERT INTO kg_relations (
                                                    source_rule_id,
                                                    target_rule_id,
                                                    relation_type,
                                                    raw_reference_text,
                                                    target_section,
                                                    algorithm_version,
                                                    confidence
                                                ) VALUES (
                                                    :source_rule_id,
                                                    :target_rule_id,
                                                    'CITES',
                                                    :raw_reference_text,
                                                    :target_section,
                                                    'cross_doc_v1.0',
                                                    1.0
                                                )
                                            """),
                                            {
                                                'source_rule_id': ref['source_rule_id'],
                                                'target_rule_id': target_rule['id'],
                                                'raw_reference_text': ref['reference_text'],
                                                'target_section': ref['target_section']
                                            }
                                        )
                                        saved_refs += 1
                                    except Exception as e:
                                        app_logger.warning(f"Failed to save resolved reference to kg_relations: {e}")

                            # 情况2: 引用未解析（目标文档或规则不存在）
                            # 也要保存，方便用户知道有哪些文档需要提取
                            else:
                                try:
                                    # 构造 reason 字段，说明为什么未解析
                                    import json
                                    reason_data = {
                                        'unresolved': True,
                                        'target_standard': ref.get('target_standard', 'Unknown'),
                                        'target_section': ref.get('target_section'),
                                        'message': f"Target document '{ref.get('target_standard', 'Unknown')}' not found or has no rules in section {ref.get('target_section', 'N/A')}"
                                    }

                                    db.execute(
                                        text("""
                                            INSERT INTO kg_relations (
                                                source_rule_id,
                                                target_rule_id,
                                                relation_type,
                                                raw_reference_text,
                                                target_section,
                                                algorithm_version,
                                                confidence,
                                                is_uncertain,
                                                reason
                                            ) VALUES (
                                                :source_rule_id,
                                                NULL,
                                                'CITES',
                                                :raw_reference_text,
                                                :target_section,
                                                'cross_doc_v1.0',
                                                0.0,
                                                true,
                                                :reason
                                            )
                                        """),
                                        {
                                            'source_rule_id': ref['source_rule_id'],
                                            'raw_reference_text': ref['reference_text'],
                                            'target_section': ref['target_section'],
                                            'reason': json.dumps(reason_data, ensure_ascii=False)
                                        }
                                    )
                                    saved_refs += 1
                                    app_logger.debug(
                                        f"Saved unresolved reference: {ref['source_standard']} -> {ref.get('target_standard', 'Unknown')}"
                                    )
                                except Exception as e:
                                    app_logger.warning(f"Failed to save unresolved reference to kg_relations: {e}")

                        # 写入冲突关系
                        if 'conflicts' in cross_doc_report and cross_doc_report['conflicts']:
                            # 检查conflicts字段的结构
                            conflicts_data = cross_doc_report['conflicts']

                            # 兼容多种可能的结构：
                            # 1. conflicts是list，直接遍历
                            # 2. conflicts是dict，包含details键（RuleConflictAndReferenceEngine返回的格式）
                            # 3. conflicts是dict，包含resolutions键（旧格式兼容）
                            resolutions_list = []
                            if isinstance(conflicts_data, list):
                                resolutions_list = conflicts_data
                            elif isinstance(conflicts_data, dict):
                                # 优先使用details键（新格式）
                                if 'details' in conflicts_data:
                                    resolutions_list = conflicts_data['details']
                                elif 'resolutions' in conflicts_data:
                                    resolutions_list = conflicts_data['resolutions']
                                # 如果是dict但没有details/resolutions，且total_detected为0，这是正常情况
                                elif conflicts_data.get('total_detected', 0) == 0:
                                    resolutions_list = []  # 没有冲突，正常情况
                                else:
                                    app_logger.warning(
                                        f"[Cross-Doc] Unexpected conflicts structure: {type(conflicts_data)}, keys={list(conflicts_data.keys())}. "
                                        f"Skipping conflict resolution processing."
                                    )
                            else:
                                app_logger.warning(
                                    f"[Cross-Doc] Unexpected conflicts structure: {type(conflicts_data)}. "
                                    f"Skipping conflict resolution processing."
                                )

                            # 处理冲突解决方案
                            for conflict_resolution in resolutions_list:
                                conflict = conflict_resolution.get('conflict', {})
                                rule_a = conflict.get('rule_a')
                                rule_b = conflict.get('rule_b')

                                if rule_a and rule_b:
                                    rule_a_id = rule_a.id if hasattr(rule_a, 'id') else rule_a.get('id')
                                    rule_b_id = rule_b.id if hasattr(rule_b, 'id') else rule_b.get('id')

                                    if rule_a_id and rule_b_id:
                                        try:
                                            db.execute(
                                                text("""
                                                    INSERT INTO kg_relations (
                                                        source_rule_id,
                                                        target_rule_id,
                                                        relation_type,
                                                        reason,
                                                        is_uncertain,
                                                        algorithm_version
                                                    ) VALUES (
                                                        :source_rule_id,
                                                        :target_rule_id,
                                                        'CONFLICTS_WITH',
                                                        :reason,
                                                        true,
                                                        'cross_doc_v1.0'
                                                    )
                                                """),
                                                {
                                                    'source_rule_id': rule_a_id,
                                                    'target_rule_id': rule_b_id,
                                                    'reason': conflict.get('reason', '')
                                                }
                                            )
                                            saved_conflicts += 1
                                        except Exception as e:
                                            app_logger.warning(f"Failed to save conflict to kg_relations: {e}")

                        db.commit()
                        app_logger.info(
                            f"[OK] Saved {saved_refs} references and {saved_conflicts} conflicts to kg_relations table"
                        )

                    except Exception as e:
                        app_logger.error(f"Failed to save cross-document results to kg_relations: {e}", exc_info=True)

                else:
                    app_logger.info("No active rules found, skipping cross-document processing")
                    result['cross_document_processing'] = {'executed': False, 'reason': 'No active rules'}

            except Exception as e:
                app_logger.error(f"Cross-document processing failed (non-critical): {e}", exc_info=True)
                result['cross_document_processing'] = {'executed': False, 'error': str(e)}

            # ========== 更新未解析引用：将指向当前文档的未解析引用更新为已解析 ==========
            try:
                app_logger.info(f"[UPDATE UNRESOLVED] Checking for unresolved references pointing to {standard.source}...")

                # 查询所有指向当前标准的未解析引用
                # 条件：target_rule_id = NULL 且 reason 包含当前标准的标识
                from sqlalchemy import text
                import json

                # 获取当前标准的可能标识（如 "RFC 5280", "RFC5280" 等）
                standard_identifiers = []
                if standard.source == 'RFC':
                    standard_identifiers.append(f"RFC {standard.version}")
                    standard_identifiers.append(f"RFC{standard.version}")
                elif standard.source.startswith('CABF'):
                    standard_identifiers.append("CA/Browser Forum Baseline Requirements")
                    standard_identifiers.append("CABF")
                    standard_identifiers.append("Baseline Requirements")

                # 查询未解析引用
                unresolved_refs = db.execute(text("""
                    SELECT id, source_rule_id, target_section, reason, raw_reference_text
                    FROM kg_relations
                    WHERE target_rule_id IS NULL
                        AND relation_type = 'CITES'
                        AND is_uncertain = true
                """)).fetchall()

                updated_count = 0
                still_unresolved = 0

                for ref in unresolved_refs:
                    try:
                        # 解析 reason 字段
                        # PostgreSQL JSONB 字段可能直接返回 dict，也可能返回 str
                        if isinstance(ref.reason, dict):
                            reason_data = ref.reason
                        elif isinstance(ref.reason, str):
                            reason_data = json.loads(ref.reason)
                        else:
                            reason_data = {}

                        target_standard = reason_data.get('target_standard', '')

                        # 检查是否指向当前标准
                        if any(identifier in target_standard for identifier in standard_identifiers):
                            # 尝试找到目标规则
                            target_section = ref.target_section

                            if target_section:
                                # 在当前标准的规则中查找匹配的章节
                                target_rules = db.query(Rule).filter(
                                    Rule.standard_id == request.standard_id,
                                    Rule.section == target_section
                                ).all()

                                if target_rules:
                                    # 找到目标规则，更新引用关系
                                    # 如果有多个规则，选择第一个（通常同一章节的规则语义相近）
                                    target_rule = target_rules[0]

                                    # 更新引用关系
                                    db.execute(text("""
                                        UPDATE kg_relations
                                        SET target_rule_id = :target_rule_id,
                                            confidence = 1.0,
                                            is_uncertain = false,
                                            reason = :new_reason,
                                            updated_at = NOW()
                                        WHERE id = :relation_id
                                    """), {
                                        'target_rule_id': target_rule.id,
                                        'new_reason': json.dumps({
                                            'resolved': True,
                                            'originally_unresolved': True,
                                            'resolved_by_extraction': standard.title,
                                            'resolved_at': datetime.now().isoformat()
                                        }, ensure_ascii=False),
                                        'relation_id': ref.id
                                    })

                                    updated_count += 1
                                    app_logger.info(
                                        f"  Updated unresolved reference {ref.id}: "
                                        f"section {target_section} -> rule {target_rule.id}"
                                    )
                                else:
                                    # 当前标准已提取，但没有对应章节的规则
                                    still_unresolved += 1
                            else:
                                # 没有指定章节，无法精确匹配
                                still_unresolved += 1

                    except Exception as e:
                        app_logger.warning(f"Failed to update unresolved reference {ref.id}: {e}")
                        continue

                if updated_count > 0:
                    db.commit()
                    app_logger.info(
                        f"[OK] Updated {updated_count} previously unresolved references "
                        f"pointing to {standard.title} ({still_unresolved} still unresolved)"
                    )
                else:
                    app_logger.info(
                        f"[OK] No unresolved references found pointing to {standard.title}"
                    )

            except Exception as e:
                app_logger.error(f"Failed to update unresolved references: {e}", exc_info=True)

            # ========== 保存完整诊断信息到metadata_json（包含对抗学习结果和跨文档处理）==========
            try:
                standard_obj = db.query(Standard).filter(Standard.id == request.standard_id).first()
                if standard_obj:
                    import json

                    # 清理 layers 数据，移除不可序列化的对象（如 RuleSkeleton）
                    layers_data = result.get('layers', {})
                    cleaned_layers = {}
                    for layer_name, layer_result in layers_data.items():
                        if isinstance(layer_result, dict):
                            # 复制字典，排除 skeletons 字段
                            cleaned_layer = {k: v for k, v in layer_result.items() if k != 'skeletons'}
                            cleaned_layers[layer_name] = cleaned_layer
                        else:
                            cleaned_layers[layer_name] = layer_result

                    diagnostics_data = {
                        'last_extraction': {
                            'timestamp': datetime.now().isoformat(),
                            'rules_count': saved_count,
                            'layers': cleaned_layers,  # 使用清理后的 layers 数据
                            'visualization_data': result.get('visualization_data', {}),  # ← 可视化数据
                            'statistics': result.get('statistics', {}),
                            'adversarial_learning': result.get('adversarial_learning', {}),  # ← 对抗学习结果
                            'rule_reasoning': result.get('rule_reasoning', {}),  # ← 重构后：推理服务结果
                            'cross_document_processing': result.get('cross_document_processing', {}),  # ← 跨文档处理结果
                            'zlint_coverage': result.get('zlint_coverage', {}),  # ← 新增：zlint覆盖结果
                            'adjudication': adjudication_stats,  # ← 自动裁决结果
                            'status': 'completed'
                        }
                    }

                    standard_obj.metadata_json = json.dumps(diagnostics_data, ensure_ascii=False)
                    db.commit()
                    app_logger.info(
                        f"[OK] Saved complete extraction diagnostics including rule reasoning results "
                        f"for standard {request.standard_id}"
                    )
            except Exception as e:
                app_logger.error(f"Failed to save diagnostics metadata: {e}", exc_info=True)
                db.rollback()

        else:
            app_logger.warning(f"[WARNING] No rules in result['final_rules'], skipping save")

        return {
            'status': 'success',
            'task_id': task_id,
            'message': 'Full pipeline extraction completed',
            'timestamp': datetime.now().isoformat(),
            'result': result
        }

    except Exception as e:
        app_logger.error(f"Failed to extract rules with full pipeline: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/comparison/{standard_id}")
async def get_extraction_comparison(
    standard_id: int,
    db: Session = Depends(get_db)
):
    """
    获取标准的规则提取对比结果

    Args:
        standard_id: 标准ID
        db: 数据库会话

    Returns:
        对比结果，包含两个模型的提取详情和一致性分析
    """
    try:
        # 检查标准是否存在
        standard = db.query(Standard).filter(Standard.id == standard_id).first()
        if not standard:
            raise HTTPException(status_code=404, detail=f"Standard {standard_id} not found")

        # 获取该标准的所有规则
        rules = db.query(Rule).filter(
            Rule.standard_id == standard_id
        ).all()

        return {
            'status': 'success',
            'standard_id': standard_id,
            'standard_title': standard.title,
            'total_rules': len(rules),
            'rules': [
                {
                    'id': rule.id,
                    'section': rule.section,
                    'title': rule.title,
                    'text': rule.text,
                    'rule_type': rule.rule_type,
                    'context': rule.context,
                    'created_at': rule.created_at.isoformat() if rule.created_at else None
                }
                for rule in rules
            ],
            'timestamp': datetime.now().isoformat()
        }

    except Exception as e:
        app_logger.error(f"Failed to get comparison: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/standards")
async def list_standards_for_extraction(
    source: Optional[str] = None,
    skip: int = 0,
    limit: int = 50,
    db: Session = Depends(get_db)
):
    """
    列出可用于规则提取的标准

    Args:
        source: 可选的来源筛选
        skip: 跳过数量
        limit: 返回数量限制
        db: 数据库会话

    Returns:
        标准列表
    """
    try:
        query = db.query(Standard).filter(Standard.is_latest == True)

        if source:
            query = query.filter(Standard.source == source)

        total = query.count()
        # 按source排序（RFC优先），然后按title排序
        from sqlalchemy import case
        standards = query.order_by(
            case(
                (Standard.source == 'RFC', 0),
                (Standard.source == 'CABF', 1),
                (Standard.source == 'ETSI', 2),
                else_=3
            ),
            Standard.title.asc()
        ).offset(skip).limit(limit).all()

        return {
            'status': 'success',
            'total': total,
            'standards': [
                {
                    'id': std.id,
                    'source': std.source,
                    'title': std.title,
                    'version': std.version,
                    'publish_date': std.publish_date.isoformat() if std.publish_date else None,
                    'url': std.url,
                    'is_latest': std.is_latest,
                    # 统计该标准的规则数量
                    'rules_count': db.query(Rule).filter(
                        Rule.standard_id == std.id
                    ).count()
                }
                for std in standards
            ],
            'timestamp': datetime.now().isoformat()
        }

    except Exception as e:
        app_logger.error(f"Failed to list standards: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=str(e))


def _parse_section_number(section: str) -> tuple:
    """
    解析章节号为可排序的元组

    Examples:
        "4.2.1" -> (4, 2, 1)
        "11.2" -> (11, 2)
        None -> (999999,)  # 放在最后
        "" -> (999999,)
    """
    if not section:
        return (999999,)  # 空值放在最后

    try:
        parts = section.split('.')
        return tuple(int(p) for p in parts)
    except (ValueError, AttributeError):
        # 如果无法解析为数字，返回一个大数字让它排在后面
        return (999999,)


def _is_valid_section(section: str, standard_source: str) -> tuple[bool, str]:
    """
    验证章节号是否有效

    Args:
        section: 章节号字符串
        standard_source: 标准来源（RFC, CABF-Server等）

    Returns:
        (is_valid, reason): 是否有效和原因描述
    """
    if not section or not isinstance(section, str):
        return True, ""  # 空值允许（会在后续处理中标记为unknown）

    section = section.strip()

    # 1. 检查日期格式（YYYY-MM-DD）
    if '-' in section:
        parts = section.split('-')
        if len(parts) == 3:
            try:
                datetime.strptime(section, '%Y-%m-%d')
                return False, f"section is date format: {section}"
            except ValueError:
                pass  # 不是日期，继续检查

    # 2. 检查OID格式（以1.3.6.1开头）
    if section.startswith('1.3.6.1'):
        return False, f"section is OID format: {section}"

    # 3. 对于CABF-Server，检查异常的纯数字章节
    if standard_source == 'CABF-Server':
        # CABF BRs的有效主章节范围：通常是1-10
        # 单数字章节"1"或"2"很可能是列表项编号，不是真正的章节
        # 大于20的数字（如47, 9132）肯定是错误提取
        # 跳过字母章节（由第5步统一处理）
        if section.split('.')[0].isdigit():
            if section.isdigit():
                section_num = int(section)
                # 允许3-10，过滤1-2和>=20
                if section_num <= 2:
                    return False, f"section is suspicious list item number: {section}"
                if section_num >= 20:
                    return False, f"section is abnormal number: {section}"

            # 检查主章节号（第一个数字）
            main_section = section.split('.')[0]
            if main_section.isdigit():
                main_num = int(main_section)
                # CABF BRs主章节范围通常是1-10，大于20的肯定错误
                if main_num >= 20:
                    return False, f"main section number too large: {main_section} in {section}"

    # 4. 对于RFC，检查异常的纯数字章节
    elif standard_source.startswith('RFC'):
        if section.split('.')[0].isdigit():
            if section.isdigit():
                section_num = int(section)
                # 单数字章节1-2可能是附录，但>=50肯定错误
                if section_num >= 50:
                    return False, f"section number too large for RFC: {section}"

            main_section = section.split('.')[0]
            if main_section.isdigit():
                main_num = int(main_section)
                if main_num >= 50:
                    return False, f"main section number too large for RFC: {main_section} in {section}"

    # 5. 允许字母前缀章节（附录如 A.1, B.2.3）
    #    每个组件要么是纯数字，要么是单个字母（附录标识符）
    components = section.split('.')
    for i, comp in enumerate(components):
        if comp.isdigit():
            continue  # 纯数字 OK
        if len(comp) == 1 and comp.isalpha():
            continue  # 单字母 OK（如 A, B, C）
        if i == 1 and comp == '509':
            continue  # X.509 特殊技术术语，允许
        # 其他情况（如多字母 "ABC" 或混合格式）→ 标红
        return False, f"Invalid section component: {comp}"

    return True, ""


def _is_valid_title(title: str) -> tuple[bool, str]:
    """
    验证标题是否有效

    Args:
        title: 标题字符串

    Returns:
        (is_valid, reason): 是否有效和原因描述
    """
    if not title or not isinstance(title, str):
        return True, ""  # 空值允许

    title = title.strip()

    # 1. 纯数字标题（如"1", "6", "9132"）
    if title.isdigit():
        # 单个数字很可能是列表项编号或章节号误提取
        return False, f"title is pure number: {title}"

    # 2. 日期相关词汇（如"days"）
    if title.lower() in ['days', 'day', 'months', 'month', 'years', 'year']:
        return False, f"title is date-related word: {title}"

    # 3. 标题过短（<3个字符）且不是常见缩写
    if len(title) < 3:
        common_abbrev = ['CA', 'DN', 'RA', 'PKI', 'OID', 'ASN', 'DER', 'PEM']
        if title.upper() not in common_abbrev:
            return False, f"title too short: {title}"

    return True, ""


def _is_fragment_text(rule_text: str, subject_path: str = "") -> tuple[bool, str]:
    """High-precision GENERAL check for a non-rule TABLE FRAGMENT.

    Fires only when a markdown-table row lost the context that names WHICH field/bit
    it constrains, leaving a degenerate subject (a bare row/bit number, or empty)
    AND no constraint clause beyond the bare RFC2119 keyword — e.g. "4 | MUST NOT",
    "9 | MUST", "| MUST NOT |". Such a row is not a recoverable single-artifact rule
    and must never reach lintability/codegen; it is noise (label-don't-drop).

    Structural and source-agnostic — NOT per-rule text/id matching. Complete terse
    table rules are preserved: "`version` | MUST be v3(2)" (named subject),
    "`givenName` | MUST NOT | - | -" (named subject), "520 | MUST use UTF8String"
    (has a constraint clause) all return (False, "")."""
    import re as _re
    t = _re.sub(r'[`*]', '', (rule_text or '')).strip()
    if not t:
        return True, "empty rule text"

    # Truncated prose/table-cell fragments that contain an RFC2119 modal but lost
    # the left-hand subject or right-hand value. Example seen in CABF SAN table:
    #   com" and MUST NOT be encoded as "example.
    # This is not a standalone constraint; the full rule is about the zero-length
    # root label in "example.com." and must be reassembled upstream.
    if ('|' not in rule_text
            and _re.match(r'^[a-z0-9.-]+"\s+and\s+(must|shall|should)\s+not\s+be\s+encoded\s+as\s+"[^"]+\.?$',
                          t, _re.I)):
        return True, "text fragment: truncated quoted clause"

    if '|' not in rule_text:
        return False, ""                       # not a table row; other validators handle prose

    # Table HEADER / table-intro row: column-label cells (Field/Presence/Critical/
    # Description) or a "match the following <table>" intro carry no requirement of
    # their own — the constraints live in the data rows. Captured as a "rule" only by
    # mis-segmentation; classify as noise (not a rule).
    if _re.search(r'\|\s*\*?\*?\s*(field|presence|critical(?:ity)?|description)\s*\*?\*?\s*\|.*\|'
                  r'\s*\*?\*?\s*(presence|critical(?:ity)?|description|value)\s*\*?\*?\s*\|',
                  rule_text, _re.I):
        return True, "table header row: column labels, no self-contained requirement"

    # Profile-table INDEX row: a named extension/field whose only content after the
    # obligation is a criticality flag (Y/N/-/footnote) plus a "See [Section ...]" /
    # "See below" cross-reference — the row points elsewhere for the actual
    # requirement and carries no self-contained constraint. CABF BR §7.1.2.x repeats
    # these per cert-type profile (5-8 copies each), often truncated ("See [Section 7.").
    # Whether such a row became lintable depended only on whether Layer-2 happened to
    # emit an IR (a coin-flip), so classify them deterministically as noise. Self-
    # contained terse rules are spared: no See-reference ("`givenName` | MUST NOT | - | -")
    # or a real constraint clause ("`serialNumber` | MUST be ... greater than zero").
    _cells = [_re.sub(r'[`*]', '', x).strip() for x in rule_text.split('|')]
    if _re.fullmatch(r'[A-Za-z][A-Za-z0-9 ]*', _cells[0].strip()) \
            and _re.search(r'see\s+\[?section|see\s+below', t, _re.I):
        _leftover = []
        for _cc in _cells[1:]:
            _cl = _cc.strip()
            if _re.fullmatch(r'(must not|must|shall not|shall|should not|should|'
                             r'recommended|not recommended|may|required|optional)', _cl, _re.I):
                continue
            if _re.fullmatch(r'[YNyn\-]*|\[\^[^\]]*\]|', _cl):
                continue
            if _re.match(r'see\s', _cl, _re.I):
                continue
            _leftover.append(_cl)
        _CONSTRAINT_IDX = (r'\b(present|absent|set|equal|contain|include|encod|critical|'
                           r'identical|unique|greater|less|valid|byte|match|specified|'
                           r'representation|true|false|omit|use|assert|mark|appear|exceed|'
                           r'conform|derive|reserved|value|field|extension|name|policy|'
                           r'address|string|date|number)\b')
        if not any(_re.search(_CONSTRAINT_IDX, _x.lower()) for _x in _leftover):
            return True, "profile-table index row: presence/criticality marker + See-Section pointer, no self-contained constraint"

    first_cell = _re.sub(r'[`*]', '', t.split('|')[0]).strip()
    # degenerate subject := the table's first cell is a bare number or empty
    if not (first_cell == '' or _re.fullmatch(r'\d+', first_cell)):
        return False, ""
    # keep if a real constraint clause survives after the obligation keyword
    _CONSTRAINT = (r'\b(present|absent|set|equal|contain|include|encod|critical|identical|'
                   r'unique|greater|less|valid|byte|match|specified|representation|true|false|'
                   r'omit|use|assert|mark|appear|exceed|conform|derive|reserved|value|field|'
                   r'extension|name|policy|address|string|date|number)\b')
    after = _re.sub(r'^[\d\s|`*\-]*', '', t.lower())
    after = _re.sub(r'\b(must not|must|shall not|shall|should not|should|required|'
                    r'not recommended|recommended|may)\b', ' ', after, count=1).strip(' |-')
    if not _re.search(_CONSTRAINT, after):
        return True, f"table fragment: degenerate subject {first_cell!r}, no constraint clause"
    return False, ""


@router.get("/rules/{standard_id}")
async def get_rules_by_standard(
    standard_id: int,
    db: Session = Depends(get_db)
):
    """
    获取某个标准的所有规则（包含原文）

    Args:
        standard_id: 标准ID
        db: 数据库会话

    Returns:
        规则列表，每条规则包含原文和标准信息
    """
    try:
        # 获取标准
        standard = db.query(Standard).filter(Standard.id == standard_id).first()
        if not standard:
            raise HTTPException(status_code=404, detail=f"Standard {standard_id} not found")

        # 获取该标准的所有规则
        rules = db.query(Rule).filter(
            Rule.standard_id == standard_id
        ).all()

        # 使用自定义排序函数进行数值排序
        rules = sorted(rules, key=lambda r: _parse_section_number(r.section))

        # 构建返回结果，包含派生规则信息
        rules_list = []
        for rule in rules:
            # 解析 derived_from（如果是派生规则）
            derived_from_list = None
            if rule.derived_from:
                try:
                    import json
                    derived_from_list = json.loads(rule.derived_from)
                except:
                    derived_from_list = None

            rules_list.append({
                'id': rule.id,
                'section': rule.section,
                'subsection': rule.subsection,
                'title': rule.title,
                'text': rule.text,  # 完整原文
                'rule_type': rule.rule_type,
                'affected_field': rule.subject,
                'operation': rule.predicate,
                'expected_value': rule.constraint_value,
                'severity': rule.severity,
                'context': rule.context,  # 上下文
                'created_at': rule.created_at.isoformat() if rule.created_at else None,
                # 新增：派生规则相关信息
                'origin': rule.origin,  # 'source' 或 'derived'
                'derivation_type': rule.derivation_type,  # 'compose', 'merge', 'summarize' 等
                'derived_from': derived_from_list,  # 源规则ID列表
                'derivation_justification': rule.derivation_justification  # 派生理由
            })

        return {
            'status': 'success',
            'standard': {
                'id': standard.id,
                'source': standard.source,
                'title': standard.title,
                'version': standard.version,
                'url': standard.url,
                'publish_date': standard.publish_date.isoformat() if standard.publish_date else None,
                'document_last_updated': standard.document_last_updated.isoformat() if standard.document_last_updated else None,
                'is_latest': standard.is_latest
            },
            'total_rules': len(rules),
            'rules': rules_list,
            'timestamp': datetime.now().isoformat()
        }

    except Exception as e:
        app_logger.error(f"Failed to get rules: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=str(e))



@router.get("/rule/{rule_id}")
async def get_rule_detail(
    rule_id: int,
    db: Session = Depends(get_db)
):
    """
    获取单个规则的详细信息

    包含：
    - 规则完整信息
    - 关联的标准信息
    - 交叉验证结果

    Args:
        rule_id: 规则ID
        db: 数据库会话

    Returns:
        规则详细信息
    """
    try:
        # 查询规则
        rule = db.query(Rule).filter(Rule.id == rule_id).first()
        if not rule:
            raise HTTPException(status_code=404, detail=f"Rule {rule_id} not found")

        # 获取关联的标准
        standard = rule.standard

        # 解析 derived_from（如果是派生规则）
        derived_from_list = None
        if rule.derived_from:
            try:
                import json
                derived_from_list = json.loads(rule.derived_from)
            except:
                derived_from_list = None

        return {
            'status': 'success',
            'rule': {
                'id': rule.id,
                'standard_id': rule.standard_id,
                'section': rule.section,
                'subsection': rule.subsection,
                'title': rule.title,
                'text': rule.text,  # 完整原文
                'rule_type': rule.rule_type,
                'affected_field': rule.subject,
                'operation': rule.predicate,
                'expected_value': rule.constraint_value,
                'severity': rule.severity,
                'context': rule.context,
                'hash': rule.hash,
                'created_at': rule.created_at.isoformat() if rule.created_at else None,
                'updated_at': rule.updated_at.isoformat() if rule.updated_at else None,
                # 派生规则相关信息
                'origin': rule.origin,  # 'source' 或 'derived'
                'derivation_type': rule.derivation_type,  # 'compose', 'conflict_resolution' 等
                'derived_from': derived_from_list,  # 源规则ID列表
                'derivation_justification': rule.derivation_justification  # 派生理由
            },
            'standard': {
                'id': standard.id,
                'source': standard.source,
                'title': standard.title,
                'version': standard.version,
                'url': standard.url,
                'publish_date': standard.publish_date.isoformat() if standard.publish_date else None,
                'document_last_updated': standard.document_last_updated.isoformat() if standard.document_last_updated else None,
                'is_latest': standard.is_latest
            },
            'timestamp': datetime.now().isoformat()
        }

    except HTTPException:
        raise
    except Exception as e:
        app_logger.error(f"Failed to get rule detail: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=str(e))


@router.put("/rule/{rule_id}")
async def update_rule(
    rule_id: int,
    affected_field: Optional[str] = None,
    operation: Optional[str] = None,
    expected_value: Optional[str] = None,
    severity: Optional[str] = None,
    db: Session = Depends(get_db)
):
    """
    更新规则的提取字段（人工审核修正）

    Args:
        rule_id: 规则ID
        affected_field: 影响的证书字段
        operation: 操作类型
        expected_value: 期望值
        severity: 严重程度
        db: 数据库会话

    Returns:
        更新后的规则信息
    """
    try:
        # 查询规则
        rule = db.query(Rule).filter(Rule.id == rule_id).first()
        if not rule:
            raise HTTPException(status_code=404, detail=f"Rule {rule_id} not found")

        # 更新字段
        # affected_field/operation/expected_value 现为生成列(从 ir_data 派生,
        # 2026-06-10 迁移)——不能直接写;如需改这些值,应改 ir_data。此处仅留
        # 仍可直接编辑的 severity。
        if severity is not None:
            rule.severity = severity

        # 更新时间戳
        rule.updated_at = datetime.now()

        # 提交更改
        db.commit()
        db.refresh(rule)

        app_logger.info(f"Rule {rule_id} updated successfully")

        return {
            'status': 'success',
            'message': 'Rule updated successfully',
            'rule': {
                'id': rule.id,
                'affected_field': rule.subject,
                'operation': rule.predicate,
                'expected_value': rule.constraint_value,
                'severity': rule.severity,
                'updated_at': rule.updated_at.isoformat() if rule.updated_at else None
            },
            'timestamp': datetime.now().isoformat()
        }

    except HTTPException:
        raise
    except Exception as e:
        app_logger.error(f"Failed to update rule {rule_id}: {e}", exc_info=True)
        db.rollback()
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/health")
async def health_check():
    """规则提取服务健康检查"""
    return {
        'status': 'healthy',
        'service': 'Rule Extraction Service',
        'version': '1.0.0',
        'features': [
            'dual-model extraction',
            'cross-validation',
            'detailed comparison',
            'thinking process tracking',
            'batch extraction',
            'manual review and correction'
        ],
        'timestamp': datetime.now().isoformat()
    }


@router.post("/zlint-coverage-analysis")
async def zlint_coverage_analysis(
    standard_id: Optional[int] = None,
    force: bool = False,
    db: Session = Depends(get_db)
):
    """
    独立的 zlint 覆盖分析接口（字段级 LLM 判别）

    增量检查：只处理 lintable 且 lint_coverage IS NULL 的规则（未判过的），
    保留已有结果。传 force=true 可强制全量重判。

    算法：把规则 IR 的 subject/obligation/predicate/constraint 与候选 zlint lint 的
    同名 IR 字段逐字段比对（check_rule_coverage_intelligent），给 full/partial/none
    判决并写 lint_covered / lint_name / lint_coverage。已取代旧的 DSL 树匹配。
    """
    try:
        from app.services.certificate.zlint_interface import ZLintInterface

        # 构建查询
        query = db.query(Rule).join(Standard, Rule.standard_id == Standard.id)

        if standard_id:
            query = query.filter(Rule.standard_id == standard_id)

        # 只判 lintable 规则（覆盖判别的分母）
        query = query.filter(Rule.lintable.is_(True))
        if not force:
            # 增量模式：只查尚未判过覆盖的（lint_coverage IS NULL）
            query = query.filter(Rule.lint_coverage.is_(None))

        rules_to_check = query.all()
        total_rules = (
            db.query(Rule).count()
            if not standard_id
            else db.query(Rule).filter(Rule.standard_id == standard_id).count()
        )

        if not rules_to_check:
            already_checked = total_rules
            return {
                'status': 'success',
                'message': f'All {already_checked} rules already checked, no new rules to analyze',
                'total_rules': total_rules,
                'checked_this_run': 0,
                'skipped': already_checked,
                'covered': 0,
                'not_covered': 0,
            }

        app_logger.info(
            f"[zlint DSL Coverage] Starting: {len(rules_to_check)} rules "
            f"(total: {total_rules}, force={force})"
        )

        # 初始化覆盖判别器（字段级 LLM judge，已取代 DSL 树匹配）
        SRC = {1: "RFC", 19: "CABF-BR"}
        zlint_interface = ZLintInterface()
        await zlint_interface.initialize_coverage_detection()

        covered_count = 0
        not_covered_count = 0
        error_count = 0

        for i, rule in enumerate(rules_to_check):
            try:
                # 字段级覆盖判别（无 embedding，按 source 缩候选；full=覆盖）
                rule_dict = {
                    'id':       rule.id,
                    'text':     rule.text,
                    'source':   SRC.get(rule.standard_id, ''),
                    'section':  rule.section or '',
                    'ir_data':  rule.ir_data,
                }
                coverage = await zlint_interface.check_rule_coverage_intelligent(rule_dict)
                verdict = coverage.get('verdict', 'none')
                rule.lint_coverage = json.dumps({
                    'verdict': verdict,
                    'reason':  coverage.get('reasoning', ''),
                    'fields':  coverage.get('fields', {}),
                    'lint':    coverage.get('lint_name'),
                }, ensure_ascii=False)
                if coverage.get('has_coverage', False):   # verdict == 'full'
                    rule.lint_covered = True
                    rule.lint_name = coverage.get('lint_name')
                    covered_count += 1
                else:
                    rule.lint_covered = False
                    rule.lint_name = None
                    not_covered_count += 1

            except Exception as e:
                app_logger.debug(f"Failed to check rule {rule.id}: {e}")
                error_count += 1
                continue

            # 每 100 条提交一次
            if (i + 1) % 100 == 0:
                db.commit()
                app_logger.info(
                    f"[zlint DSL Coverage] Progress: {i + 1}/{len(rules_to_check)} "
                    f"(covered: {covered_count})"
                )

        # 最终提交
        db.commit()

        app_logger.info(
            f"[zlint DSL Coverage] Done: {covered_count} covered, "
            f"{not_covered_count} not covered, {error_count} errors"
        )

        return {
            'status': 'success',
            'total_rules': total_rules,
            'checked_this_run': len(rules_to_check),
            'skipped': total_rules - len(rules_to_check),
            'covered': covered_count,
            'not_covered': not_covered_count,
            'errors': error_count,
            'match_method': 'dsl_tree_match_boolean',
        }

    except Exception as e:
        app_logger.error(f"[zlint Coverage Analysis] Failed: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=str(e))


# ==================== Failed-IR Re-run (id-preserving) ====================
# 每次提取都有 skeleton 无法产出 IR（LLM 空响应 / JSON 截断 / scope-filter 误删）。
# 这些行召回已落库但缺 IR、无法分类、破坏 Q1 守恒。本接口定向重跑这些失败行：
#   选失败行 → 重建 skeleton → 跑 Layer-2（含已修的 array-recovery + scope-filter）
#   → 按 sentence_hash 把新 IR 映射回原行 → 只 UPDATE ir_data 及 IR 派生列。
# 不删不重插：id 稳定，其它行的 codegen/zlint 不受影响。幂等，可多次迭代。

_rerun_in_progress: set = set()


def _row_has_ir(ir_data) -> bool:
    """有实质 IR：抽取成功产出了 IR 对象（ir_data 带非空 'ir' 信封）。

    rerun 的目的是补救"召回已落库但*缺 IR*、无法分类"的失败行。一条被判为
    lintable=False 的规则其实抽取成功了（有完整 IR、只是判为不可lint），不应
    被当作失败行重跑。只有完全没产出 IR（无 'ir' 信封，仅 _fallback shell）才需重跑。
    （旧实现用 parsed.lintable==True 作判据，会把所有非可lint行也选进来重跑，
     既浪费额度又可能扰动已正确判为不可lint的行。）
    """
    if not ir_data:
        return False
    try:
        d = json.loads(ir_data) if isinstance(ir_data, str) else ir_data
    except Exception:
        return False
    if not isinstance(d, dict):
        return False
    ir = d.get('ir')
    return isinstance(ir, dict) and bool(ir)


def _select_failed_rules(db: Session, standard_id: int, limit: Optional[int] = None):
    """无实质 IR 的规范断言行（排除 NOISE_CANDIDATE），重新提取 IR。

    NOISE_CANDIDATE 是骨架层已判定为非规范断言的噪声行，不参与 IR 提取，
    不计入失败统计，也不在此重跑。
    """
    rows = db.query(Rule).filter(Rule.standard_id == standard_id).all()
    failed = [
        r for r in rows
        if not _row_has_ir(r.ir_data)
        and (r.obligation or r.rule_type or '').upper() != 'NOISE_CANDIDATE'
    ]
    failed.sort(key=lambda r: r.id)
    return failed[:limit] if limit else failed


def _apply_ir_to_row(rule: Rule, ir) -> bool:
    """把一个 IR 对象 id-preserving 写回 rule。只写 ir_data——派生标量
    (obligation/predicate/subject/constraint_value 等)现为生成列,从 ir_data
    自动派生,无需也不能显式赋值(2026-06-10 schema 迁移)。"""
    try:
        rule.ir_data = ir.to_json()
        return True
    except Exception as e:
        app_logger.error(f"[Rerun-IR] failed to update rule {rule.id}: {e}")
        return False


def _build_skeleton_from_row(rule: Rule):
    """从失败行重建 assertion 级 skeleton（只喂失败的给 LLM）。"""
    from app.services.extraction.rule_discovery import RuleSkeleton
    kw = (rule.obligation or rule.rule_type or 'MUST')
    sent = rule.text or ''
    pos = sent.upper().find(kw.upper())
    return RuleSkeleton(
        rule_id=f"rerun-{rule.id}",
        section=rule.section or '',
        sentence=sent,
        keyword=kw,
        keyword_position=pos if pos >= 0 else 0,
        sentence_index=rule.sentence_index if rule.sentence_index is not None else 0,
        source_sentence=sent,
        section_title=rule.title or None,
    )


async def _execute_rerun_failed_irs(task_id: str, standard_id: int, limit: Optional[int]):
    """后台执行失败行 IR 重跑（id-preserving，分块提交，抗中断/可续跑）。"""
    global _rerun_in_progress
    async with _extraction_lock:
        if standard_id in _rerun_in_progress:
            app_logger.warning(f"[Rerun-IR] standard {standard_id} already rerunning; skip")
            return
        _rerun_in_progress.add(standard_id)
    try:
        from app.core.database import SessionLocal
        import hashlib as _hl
        from pathlib import Path
        CHUNK = 40   # 每块跑完即回填+commit：中断只丢当前块，已恢复的都落库
        db = SessionLocal()
        try:
            standard = db.query(Standard).filter(Standard.id == standard_id).first()
            if not standard:
                app_logger.error(f"[Rerun-IR] standard {standard_id} not found")
                return
            failed = _select_failed_rules(db, standard_id, limit)
            app_logger.info(f"[Rerun-IR] standard {standard_id}: {len(failed)} failed rows to re-run (chunk={CHUNK})")
            if not failed:
                return
            with open(Path(standard.file_path), 'r', encoding='utf-8', errors='ignore') as f:
                document_text = f.read()
            context = {'source': standard.source, 'title': standard.title,
                       'version': standard.version, 'file_path': standard.file_path,
                       'standard_id': standard_id}

            total_recovered = 0
            for ci in range(0, len(failed), CHUNK):
                chunk = failed[ci:ci + CHUNK]
                skeletons = [_build_skeleton_from_row(r) for r in chunk]
                extractor = FullPipelineExtractor(db=db)   # fresh per chunk (context_builder 延迟初始化)
                layer2 = await extractor._layer2_llm_extraction(skeletons, document_text, context)
                ir_by_hash = {}
                for ir in layer2.get('resolved_irs', []):
                    try:
                        ir_by_hash.setdefault(_hl.md5(ir.rule_text.encode('utf-8')).hexdigest(), ir)
                    except Exception:
                        continue
                chunk_recovered = 0
                for r in chunk:
                    ir = ir_by_hash.get(_hl.md5((r.text or '').encode('utf-8')).hexdigest())
                    if ir and _apply_ir_to_row(r, ir):
                        chunk_recovered += 1
                db.commit()   # ⭐ 分块提交：已恢复的立即落库，抗中断
                total_recovered += chunk_recovered
                app_logger.info(
                    f"[Rerun-IR] standard {standard_id} chunk {ci//CHUNK + 1}/"
                    f"{(len(failed)+CHUNK-1)//CHUNK}: recovered {chunk_recovered}/{len(chunk)} "
                    f"(cumulative {total_recovered}/{ci+len(chunk)})"
                )

            app_logger.info(
                f"[Rerun-IR] standard {standard_id} DONE: re-ran {len(failed)}, "
                f"IR recovered {total_recovered}, still-failed {len(failed) - total_recovered}"
            )
        finally:
            db.close()
    finally:
        async with _extraction_lock:
            _rerun_in_progress.discard(standard_id)


@router.post("/rerun-failed-irs", response_model=RerunFailedIRResponse)
async def rerun_failed_irs(
    request: RerunFailedIRRequest,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db),
):
    """重跑某标准下提取失败（无 IR）的规则行。

    dry_run=True（默认）：只统计失败行数量，不调用 LLM、不写库。
    dry_run=False：后台跑 Layer-2 并 id-preserving 回填 IR；幂等可多次调用。
    """
    standard = db.query(Standard).filter(Standard.id == request.standard_id).first()
    if not standard:
        raise HTTPException(status_code=404, detail=f"Standard {request.standard_id} not found")

    failed = _select_failed_rules(db, request.standard_id, request.limit)
    failed_total = len(failed)
    selected = min(failed_total, request.limit) if request.limit else failed_total
    task_id = str(uuid.uuid4())

    if request.dry_run:
        return RerunFailedIRResponse(
            task_id=task_id, status="dry_run", standard_id=request.standard_id,
            message=f"[DRY-RUN] {failed_total} failed rows lack IR; would re-run {selected}. Set dry_run=false to execute.",
            failed_total=failed_total, selected=selected, dry_run=True,
            timestamp=datetime.now().isoformat(),
        )

    background_tasks.add_task(_execute_rerun_failed_irs, task_id, request.standard_id, request.limit)
    return RerunFailedIRResponse(
        task_id=task_id, status="started", standard_id=request.standard_id,
        message=f"Re-running {selected} failed rows in background (id-preserving IR backfill).",
        failed_total=failed_total, selected=selected, dry_run=False,
        timestamp=datetime.now().isoformat(),
    )
