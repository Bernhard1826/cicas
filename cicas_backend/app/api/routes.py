"""
FastAPI routes for standards and rules management
"""
from fastapi import APIRouter, Depends, HTTPException, BackgroundTasks
from sqlalchemy.orm import Session
from sqlalchemy import text, and_, or_, not_, cast, Boolean, String, func
from sqlalchemy.dialects.postgresql import JSONB
from typing import List, Optional
from datetime import datetime
from app.core.database import get_db
from app.models.models import Standard, Rule, UpdateLog, StandardRelationship
from app.api.schemas import (
    StandardResponse,
    RuleResponse,
    UpdateLogResponse,
    UpdateRequest,
    UpdateStatusResponse,
    StandardSearchRequest,
    StandardRelationshipResponse,
    StandardWithRelationships,
    StandardMetadata,
    StandardInfo
)
from app.services.update_orchestrator import UpdateOrchestrator
from app.core.logging_config import app_logger

router = APIRouter()


@router.post("/update_rules", response_model=UpdateStatusResponse)
async def update_rules(
    request: UpdateRequest,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db)
):
    """
    Trigger manual update of standards and rules

    Args:
        request: Update request with options
        background_tasks: FastAPI background tasks
        db: Database session

    Returns:
        Update status
    """
    try:
        app_logger.info(f"Manual update triggered: sources={request.sources}")

        # Create update orchestrator
        orchestrator = UpdateOrchestrator(db)

        # Run update in background
        background_tasks.add_task(
            orchestrator.run_full_update,
            sources=request.sources,
            force=request.force
        )

        return UpdateStatusResponse(
            status="started",
            message="Update process started in background",
            timestamp=datetime.utcnow()
        )

    except Exception as e:
        app_logger.error(f"Error starting update: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/standards", response_model=List[StandardResponse])
async def get_standards(
    source: Optional[str] = None,
    is_latest: Optional[bool] = None,
    skip: int = 0,
    limit: int = 100,
    db: Session = Depends(get_db)
):
    """
    Get list of standards

    Args:
        source: Filter by source (RFC, CABF, etc.)
        is_latest: Filter by latest version (None=all versions, True=latest only, False=historical only)
        skip: Number of records to skip
        limit: Maximum number of records to return
        db: Database session

    Returns:
        List of standards
    """
    try:
        query = db.query(Standard)

        if source:
            query = query.filter(Standard.source == source)

        if is_latest is not None:
            query = query.filter(Standard.is_latest == is_latest)

        query = query.order_by(Standard.created_at.desc())
        standards = query.offset(skip).limit(limit).all()

        return standards

    except Exception as e:
        app_logger.error(f"Error retrieving standards: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/standards/{standard_id}", response_model=StandardResponse)
async def get_standard(
    standard_id: int,
    db: Session = Depends(get_db)
):
    """
    Get a specific standard by ID

    Args:
        standard_id: Standard ID
        db: Database session

    Returns:
        Standard details
    """
    try:
        standard = db.query(Standard).filter(Standard.id == standard_id).first()

        if not standard:
            raise HTTPException(status_code=404, detail="Standard not found")

        return standard

    except HTTPException:
        raise
    except Exception as e:
        app_logger.error(f"Error retrieving standard: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/rules", response_model=List[RuleResponse])
async def get_rules(
    standard_id: Optional[int] = None,
    section: Optional[str] = None,
    rule_type: Optional[str] = None,
    skip: int = 0,
    limit: int = 500,
    db: Session = Depends(get_db)
):
    """
    Get list of rules with optional filters

    Args:
        standard_id: Filter by standard ID
        section: Filter by section number
        rule_type: Filter by rule type (MUST, SHOULD, etc.)
        skip: Number of records to skip
        limit: Maximum number of records to return
        db: Database session

    Returns:
        List of rules
    """
    try:
        query = db.query(Rule)

        if standard_id:
            query = query.filter(Rule.standard_id == standard_id)

        if section:
            query = query.filter(Rule.section == section)

        if rule_type:
            query = query.filter(Rule.rule_type == rule_type)

        query = query.order_by(Rule.created_at.desc())
        rules = query.offset(skip).limit(limit).all()

        return rules

    except Exception as e:
        app_logger.error(f"Error retrieving rules: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/rules/search")
async def search_rules(
    # 支持两种参数名（兼容性）
    q: Optional[str] = None,
    keyword: Optional[str] = None,
    # 筛选条件
    source: Optional[str] = None,
    ruleType: Optional[str] = None,
    rule_type: Optional[str] = None,
    affectedField: Optional[str] = None,
    affected_field: Optional[str] = None,
    section: Optional[str] = None,
    standard_id: Optional[int] = None,
    origin: Optional[str] = None,  # 新增：筛选原始/派生规则
    # 分页（支持两种方式）
    page: int = 1,
    per_page: int = 20,
    skip: Optional[int] = None,
    limit: Optional[int] = None,
    # 其他
    similarity_threshold: Optional[float] = None,
    only_lintable: bool = False,
    db: Session = Depends(get_db)
):
    """
    统一规则搜索接口 (unified search for all scenarios)

    参数兼容性：
    - 关键词: q 或 keyword
    - 规则类型: ruleType 或 rule_type
    - 受影响字段: affectedField 或 affected_field
    - 分页方式1: page/per_page (推荐)
    - 分页方式2: skip/limit (兼容旧接口)

    Args:
        q/keyword: Keyword search (searches in text, title, context, affected_field)
        source: Filter by source (RFC, CABF, ETSI, Browser_CA)
        ruleType/rule_type: Filter by rule type (MUST, SHOULD, MAY, etc.)
        affectedField/affected_field: Filter by affected field
        section: Filter by section number
        standard_id: Filter by standard ID
        origin: Filter by origin (source=original rules, derived=derived rules)
        page/per_page: Pagination (page number & items per page)
        skip/limit: Alternative pagination (offset & limit)
        similarity_threshold: (Optional) For future semantic search
        only_lintable: If True, only return rules that can generate zlint code
        db: Database session

    Returns:
        {
            "rules": [...],
            "total": total_count,
            "page": current_page,
            "pages": total_pages
        }
    """
    try:
        from sqlalchemy import or_

        # 参数兼容处理
        search_keyword = q or keyword
        search_rule_type = ruleType or rule_type
        search_affected_field = affectedField or affected_field

        # 分页参数兼容处理
        if skip is not None and limit is not None:
            # 使用 skip/limit 方式
            offset = skip
            page_size = limit
            current_page = (skip // limit) + 1 if limit > 0 else 1
        else:
            # 使用 page/per_page 方式
            current_page = page
            page_size = per_page
            offset = (page - 1) * per_page

        # Build query with JOIN to get standard info
        query = db.query(Rule).join(Standard, Rule.standard_id == Standard.id)

        # Apply keyword search with synonym expansion
        if search_keyword:
            # 导入同义词扩展功能
            from app.services.extraction.synonym_mapper import expand_query_with_synonyms
            import re

            # 扩展查询（如果是已知别名，会自动添加规范术语）
            # 例如："dNSName" 会扩展成 "dNSName||DNS name||domain name||hostname"
            # 这样可以匹配规则文本中使用"domain name"描述dNSName的情况
            expanded_q = expand_query_with_synonyms(search_keyword)

            # 记录同义词扩展情况
            if expanded_q != search_keyword:
                app_logger.info(f"Query expanded: '{search_keyword}' → '{expanded_q}'")
            else:
                app_logger.info(f"Searching for: '{search_keyword}' (no expansion)")

            # 使用 || 分割同义词短语（保持短语完整性）
            search_terms = expanded_q.split('||')
            app_logger.info(f"Search terms: {search_terms}")

            # ===== 智能搜索逻辑（基于LLM生成的topic_tags）=====
            #
            # 核心原则：
            # 1. 优先匹配：topic_tags包含搜索词（LLM已理解语义，区分不同概念）
            # 2. 兜底匹配：text/affected_field等包含搜索词（覆盖旧数据或LLM遗漏）
            # 3. 无需硬编码排除规则：LLM通过topic_tags自动区分歧义概念
            #
            # 示例：搜索"dNSName"时
            # - 优先匹配：topic_tags包含"dNSName"的规则（SubjectAltName中的dNSName字段）
            # - 不会匹配：topic_tags包含"domainComponent"的规则（Subject DN中的domainComponent）
            # - 不会匹配：topic_tags包含"validation_method"的规则（验证流程中的Authorization Domain Name）

            # 构建搜索过滤器
            all_filters = []

            for term in search_terms:
                # 为每个同义词构建OR条件
                term_filters = []

                # === 优先级1: 文本字段匹配（兜底，覆盖旧数据）===
                # 对于没有ir_data或旧版本提取的规则，仍然搜索文本字段
                term_filters.extend([
                    Rule.text.op('~*')(re.escape(term)),
                    Rule.subject.op('~*')(re.escape(term)),
                    Rule.title.op('~*')(re.escape(term)),
                    Rule.context.op('~*')(re.escape(term))
                ])

                # === 优先级2: IR subject字段匹配（结构化字段路径）===
                # 例如：extensions.subjectAltName.dNSName
                # 兼容新格式(subject是dict with path)和旧格式(subject是string)
                try:
                    ir_json = cast(Rule.ir_data, JSONB)
                    subject_text = func.coalesce(
                        ir_json['ir']['subject']['path'].astext,
                        ir_json['ir']['subject'].astext
                    )
                    ir_subject_filter = and_(
                        Rule.ir_data.isnot(None),
                        cast(subject_text, String).op('~*')(re.escape(term))
                    )
                    term_filters.append(ir_subject_filter)
                except Exception as e:
                    app_logger.debug(f"IR subject search not available: {e}")

                # 所有同义词之间是OR关系（任一匹配即可）
                all_filters.append(or_(*term_filters))

            # === 最终过滤逻辑 ===
            # 多个同义词之间是OR关系（例如："dNSName" OR "DNS name" OR "domain name"）
            query = query.filter(or_(*all_filters))

        # Apply filters
        if source:
            query = query.filter(Standard.source == source)

        if search_rule_type:
            query = query.filter(Rule.rule_type == search_rule_type)

        if search_affected_field:
            query = query.filter(Rule.subject.ilike(f"%{search_affected_field}%"))

        if section:
            query = query.filter(Rule.section == section)

        if standard_id:
            query = query.filter(Rule.standard_id == standard_id)

        if origin:
            if origin.lower() in ['source', 'derived']:
                query = query.filter(Rule.origin == origin.lower())

        # Filter for lintable rules (only if only_lintable=True)
        if only_lintable:
            # 方案1：使用rule_category字段（快速，但依赖智能分流）
            # 方案2：使用IR中的can_generate字段（慢，但实时）
            # 优先使用方案1，如果没有分类则降级到方案2
            # 【重要】同时排除已被zlint覆盖的规则（lint_covered=true）
            query = query.filter(
                and_(
                    Rule.ir_data.isnot(None),
                    # 排除已被zlint覆盖的规则
                    or_(Rule.lint_covered == False, Rule.lint_covered.is_(None)),
                    or_(
                        # 方案1：已经分类为lintable
                        Rule.rule_category == 'lintable',
                        # 方案2：IR中lintable=true（兜底）
                        # 注意：正确的JSON路径是 ir_data['ir']['lintable']
                        and_(
                            Rule.rule_category.is_(None),  # 未分类
                            # 正确的JSON路径是 ir_data['ir']['lintable']
                            cast(
                                cast(Rule.ir_data, JSONB)['ir']['lintable'].astext,
                                Boolean
                            ) == True
                        )
                    )
                )
            )

        # Get total count
        total = query.count()

        # 调试日志
        app_logger.info(f"Search query found {total} total rules")
        app_logger.info(f"Pagination: page={current_page}, page_size={page_size}, offset={offset}")

        # 保护逻辑：如果offset超出范围，自动重置到第1页
        if offset >= total and total > 0:
            app_logger.warning(f"Offset {offset} exceeds total {total}, resetting to page 1")
            offset = 0
            current_page = 1

        # 打印SQL查询（调试用）
        try:
            from sqlalchemy.dialects import postgresql
            compiled_query = query.statement.compile(
                dialect=postgresql.dialect(),
                compile_kwargs={"literal_binds": True}
            )
            app_logger.debug(f"SQL Query: {compiled_query}")
        except Exception as e:
            app_logger.debug(f"Could not compile query: {e}")

        # Get paginated results
        rules = query.order_by(Rule.created_at.desc()).offset(offset).limit(page_size).all()

        # 调试日志
        app_logger.info(f"Retrieved {len(rules)} rules after pagination")
        if len(rules) == 0 and total > 0:
            app_logger.warning(f"ISSUE: Found {total} rules but pagination returned 0 rules!")
            app_logger.warning(f"Query details - keyword: {search_keyword}, offset: {offset}, limit: {page_size}")

        # Build response with standard info
        results = []
        for rule in rules:
            rule_dict = {
                "id": rule.id,
                "standard_id": rule.standard_id,
                "section": rule.section,
                "subsection": rule.subsection,
                "title": rule.title,
                "text": rule.text,
                "rule_type": rule.rule_type,
                "affected_field": rule.subject,
                "operation": rule.predicate,
                "expected_value": rule.constraint_value,
                "severity": rule.severity,
                "context": rule.context,
                "hash": rule.hash,
                "modality": rule.obligation,
                "requirement_level": rule.obligation,
                "conditions": rule.conditions,
                "sentence_index": rule.sentence_index,
                "sentence_hash": rule.sentence_hash,
                "ir_data": rule.ir_data,
                "created_at": rule.created_at,
                "updated_at": rule.updated_at,
                # Add standard info for display
                "standard_title": rule.standard.title if rule.standard else None,
                "source": rule.standard.source if rule.standard else None,
            }
            results.append(rule_dict)

        # Calculate total pages
        total_pages = (total + page_size - 1) // page_size if page_size > 0 else 0

        # 最终保护：确保返回的page不超过总页数
        if current_page > total_pages and total_pages > 0:
            current_page = 1

        return {
            "rules": results,
            "total": total,
            "page": current_page,
            "pages": total_pages
        }

    except Exception as e:
        app_logger.error(f"Error searching rules: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/rules/{rule_id}", response_model=RuleResponse)
async def get_rule(
    rule_id: int,
    db: Session = Depends(get_db)
):
    """
    Get a specific rule by ID

    Args:
        rule_id: Rule ID
        db: Database session

    Returns:
        Rule details
    """
    try:
        rule = db.query(Rule).filter(Rule.id == rule_id).first()

        if not rule:
            raise HTTPException(status_code=404, detail="Rule not found")

        return rule

    except HTTPException:
        raise
    except Exception as e:
        app_logger.error(f"Error retrieving rule: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/update_logs", response_model=List[UpdateLogResponse])
async def get_update_logs(
    skip: int = 0,
    limit: int = 50,
    db: Session = Depends(get_db)
):
    """
    Get update logs

    Args:
        skip: Number of records to skip
        limit: Maximum number of records to return
        db: Database session

    Returns:
        List of update logs
    """
    try:
        logs = db.query(UpdateLog).order_by(
            UpdateLog.started_at.desc()
        ).offset(skip).limit(limit).all()

        return logs

    except Exception as e:
        app_logger.error(f"Error retrieving update logs: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/stats")
async def get_stats(db: Session = Depends(get_db)):
    """
    Get system statistics

    Args:
        db: Database session

    Returns:
        Statistics dictionary
    """
    try:
        total_standards = db.query(Standard).count()
        total_rules = db.query(Rule).count()
        active_rules = db.query(Rule).filter().count()

        recent_update = db.query(UpdateLog).order_by(
            UpdateLog.started_at.desc()
        ).first()

        return {
            "total_standards": total_standards,
            "total_rules": total_rules,
            "active_rules": active_rules,
            "last_update": recent_update.started_at if recent_update else None
        }

    except Exception as e:
        app_logger.error(f"Error retrieving stats: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/standards/search", response_model=List[StandardResponse])
async def search_standards(
    request: StandardSearchRequest,
    db: Session = Depends(get_db)
):
    """
    Search standards by query string and filters

    Args:
        request: Search request with query, source, is_latest, is_active filters
        db: Database session

    Returns:
        List of matching standards
    """
    try:
        query = db.query(Standard)

        # 文本搜索：标题或版本
        if request.query:
            search_pattern = f"%{request.query}%"
            query = query.filter(
                (Standard.title.ilike(search_pattern)) |
                (Standard.version.ilike(search_pattern))
            )

        # 来源过滤
        if request.source:
            query = query.filter(Standard.source == request.source)

        # 最新版本过滤
        if request.is_latest is not None:
            query = query.filter(Standard.is_latest == request.is_latest)

        # 活跃状态过滤（未被废弃）
        if request.is_active is not None:
            if request.is_active:
                # 活跃标准：is_latest=True 或者没有被其他标准废弃
                # 检查是否有incoming obsoletes关系
                obsoleted_ids = db.query(StandardRelationship.target_standard_id).filter(
                    StandardRelationship.relationship_type == 'obsoletes',
                    StandardRelationship.is_active == True
                ).all()
                obsoleted_id_list = [id[0] for id in obsoleted_ids]

                query = query.filter(
                    (Standard.is_latest == True) |
                    (~Standard.id.in_(obsoleted_id_list))
                )
            else:
                # 非活跃标准：已被废弃的
                obsoleted_ids = db.query(StandardRelationship.target_standard_id).filter(
                    StandardRelationship.relationship_type == 'obsoletes',
                    StandardRelationship.is_active == True
                ).all()
                obsoleted_id_list = [id[0] for id in obsoleted_ids]

                query = query.filter(Standard.id.in_(obsoleted_id_list))

        # 排序并分页
        query = query.order_by(Standard.document_last_updated.desc().nullslast(), Standard.created_at.desc())
        standards = query.offset(request.skip).limit(request.limit).all()

        app_logger.info(f"Search standards: query='{request.query}', found {len(standards)} results")

        return standards

    except Exception as e:
        app_logger.error(f"Error searching standards: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/standards/{standard_id}/relationships", response_model=StandardWithRelationships)
async def get_standard_relationships(
    standard_id: int,
    db: Session = Depends(get_db)
):
    """
    Get a standard with all its relationships

    Args:
        standard_id: Standard ID
        db: Database session

    Returns:
        Standard with incoming and outgoing relationships
    """
    try:
        # 获取标准
        standard = db.query(Standard).filter(Standard.id == standard_id).first()
        if not standard:
            raise HTTPException(status_code=404, detail="Standard not found")

        # 获取outgoing关系（此标准指向其他标准）
        outgoing = db.query(StandardRelationship).filter(
            StandardRelationship.source_standard_id == standard_id,
            StandardRelationship.is_active == True
        ).all()

        # 获取incoming关系（其他标准指向此标准）
        incoming = db.query(StandardRelationship).filter(
            StandardRelationship.target_standard_id == standard_id,
            StandardRelationship.is_active == True
        ).all()

        # 填充关系中的标准信息
        outgoing_with_info = []
        for rel in outgoing:
            target = db.query(Standard).filter(Standard.id == rel.target_standard_id).first()
            rel_dict = {
                "id": rel.id,
                "source_standard_id": rel.source_standard_id,
                "target_standard_id": rel.target_standard_id,
                "relationship_type": rel.relationship_type,
                "description": rel.description,
                "section": rel.section,
                "confidence": rel.confidence,
                "extraction_method": rel.extraction_method,
                "is_active": rel.is_active,
                "created_at": rel.created_at,
                "target_standard": StandardInfo(
                    id=target.id,
                    source=target.source,
                    title=target.title,
                    version=target.version,
                    url=target.url
                ) if target else None
            }
            outgoing_with_info.append(rel_dict)

        incoming_with_info = []
        for rel in incoming:
            source = db.query(Standard).filter(Standard.id == rel.source_standard_id).first()
            rel_dict = {
                "id": rel.id,
                "source_standard_id": rel.source_standard_id,
                "target_standard_id": rel.target_standard_id,
                "relationship_type": rel.relationship_type,
                "description": rel.description,
                "section": rel.section,
                "confidence": rel.confidence,
                "extraction_method": rel.extraction_method,
                "is_active": rel.is_active,
                "created_at": rel.created_at,
                "source_standard": StandardInfo(
                    id=source.id,
                    source=source.source,
                    title=source.title,
                    version=source.version,
                    url=source.url
                ) if source else None
            }
            incoming_with_info.append(rel_dict)

        # 判断是否活跃（未被废弃）
        obsoleted_by = [rel for rel in incoming if rel.relationship_type == 'obsoletes']
        is_active = len(obsoleted_by) == 0 or standard.is_latest

        # 判断是否有更新版本
        has_updates = any(rel.relationship_type == 'updates' for rel in outgoing)

        # 获取废弃者和更新者的ID列表
        obsoleted_by_ids = [rel.source_standard_id for rel in obsoleted_by]
        updates_ids = [rel.target_standard_id for rel in outgoing if rel.relationship_type == 'updates']

        return StandardWithRelationships(
            standard=standard,
            outgoing_relationships=outgoing_with_info,
            incoming_relationships=incoming_with_info,
            is_active=is_active,
            has_updates=has_updates,
            obsoleted_by=obsoleted_by_ids,
            updates=updates_ids
        )

    except HTTPException:
        raise
    except Exception as e:
        app_logger.error(f"Error retrieving standard relationships: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/standards/{standard_id}/metadata", response_model=StandardMetadata)
async def get_standard_metadata(
    standard_id: int,
    db: Session = Depends(get_db)
):
    """
    Get extended metadata for a standard including crawl configuration and relationships

    Args:
        standard_id: Standard ID
        db: Database session

    Returns:
        Extended standard metadata with crawl config and relationship summary
    """
    try:
        standard = db.query(Standard).filter(Standard.id == standard_id).first()
        if not standard:
            raise HTTPException(status_code=404, detail="Standard not found")

        # 解析metadata_json
        import json
        metadata = None
        crawl_config = None

        if standard.metadata_json:
            try:
                metadata = json.loads(standard.metadata_json)
                # 提取爬取配置信息
                crawl_config = {
                    "source_url": standard.url,
                    "file_path": standard.file_path,
                    "file_hash": standard.file_hash,
                    "last_checked": standard.last_checked.isoformat() if standard.last_checked else None,
                    "crawl_metadata": metadata.get("crawl_info", {})
                }
            except json.JSONDecodeError:
                app_logger.warning(f"Failed to parse metadata_json for standard {standard_id}")

        # 获取关系统计
        outgoing = db.query(StandardRelationship).filter(
            StandardRelationship.source_standard_id == standard_id,
            StandardRelationship.is_active == True
        ).all()

        incoming = db.query(StandardRelationship).filter(
            StandardRelationship.target_standard_id == standard_id,
            StandardRelationship.is_active == True
        ).all()

        # 统计关系类型
        relationship_summary = {
            "outgoing": {},
            "incoming": {},
            "total_outgoing": len(outgoing),
            "total_incoming": len(incoming)
        }

        for rel in outgoing:
            rel_type = rel.relationship_type
            relationship_summary["outgoing"][rel_type] = relationship_summary["outgoing"].get(rel_type, 0) + 1

        for rel in incoming:
            rel_type = rel.relationship_type
            relationship_summary["incoming"][rel_type] = relationship_summary["incoming"].get(rel_type, 0) + 1

        # 判断是否活跃
        is_active = "obsoletes" not in relationship_summary["incoming"] or standard.is_latest

        return StandardMetadata(
            id=standard.id,
            source=standard.source,
            title=standard.title,
            version=standard.version,
            url=standard.url,
            crawl_config=crawl_config,
            metadata=metadata,
            is_active=is_active,
            is_latest=standard.is_latest,
            relationship_summary=relationship_summary
        )

    except HTTPException:
        raise
    except Exception as e:
        app_logger.error(f"Error retrieving standard metadata: {e}")
        raise HTTPException(status_code=500, detail=str(e))

