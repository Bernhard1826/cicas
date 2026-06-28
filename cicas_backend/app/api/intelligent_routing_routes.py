"""
智能分流API路由 - 基于Lintability判断的智能分流
"""
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from sqlalchemy import and_, or_, func
from typing import List, Dict, Any, Optional
from pydantic import BaseModel
import re
import asyncio

from app.core.database import get_db
from app.models.models import Rule, Standard
from app.core.logging_config import app_logger

router = APIRouter(prefix="/api/v1", tags=["intelligent-routing"])


class RuleClassificationRequest(BaseModel):
    """规则分类请求"""
    rule_ids: Optional[List[int]] = None  # 如果为空，则分类所有规则
    force_reclassify: bool = False  # 是否强制重新分类（忽略已有的lintability判断）


class RuleClassificationResult(BaseModel):
    """单个规则的分类结果"""
    rule_id: int
    category: str  # 'precise' 或 'simple' 或 'non_lintable'
    reason: str
    lintable: bool  # 是否可生成zlint
    lintable_reason: str  # lintability判断原因
    failed_step: Optional[str] = None  # 失败的步骤（如果不可生成）
    # 规则详细信息
    rule_text: str = ""
    rule_title: str = ""
    rule_type: str = ""
    section: str = ""
    rule_context: str = ""  # 规则在原文档中的上下文
    # 所属标准信息
    standard_id: int = 0
    standard_name: str = ""
    standard_type: str = ""


class RuleClassificationResponse(BaseModel):
    """规则分类响应"""
    total_rules: int
    lintable_count: int  # 可生成zlint的规则数
    non_lintable_count: int  # 不可生成zlint的规则数
    results: List[RuleClassificationResult]


class RuleClassifier:
    """规则分类器 - 基于IR的Lintability判断"""

    def classify_rule_by_lintability(self, rule: Rule, force_reclassify: bool = False) -> Dict[str, Any]:
        """
        【核心方法】基于IR的规则分类

        使用6步判断算法来确定规则是否可生成zlint：
        - can_generate=true → 可生成zlint → 'lintable'类别
        - can_generate=false → 不可生成zlint → 'non_lintable'类别

        判断算法基于IR语义，而非关键词匹配：
        1. 断言主体检查
        1.5. 多对象比较检查（新增）
        2. 字段路径检查
        3. 外部依赖检查
        4. 操作符可执行性检查
        5. 确定性检查
        6. 条件规则递归判断

        【重要设计】：
        - IR生成时不包含lintability判断（职责分离）
        - 只在用户点击"智能分流"时才计算lintability
        - 计算结果会更新到IR的zlint_lintability字段并写回数据库

        Args:
            rule: 规则对象
            force_reclassify: 是否强制重新分类（忽略已有的lintability判断）

        Returns:
            {
                'category': 'lintable' | 'non_lintable',
                'confidence': float,
                'reason': str,
                'lintable': bool,
                'lintable_reason': str,
                'failed_step': str or None
            }
        """
        try:
            import json

            # 【性能优化】直接从数据库中读取已有的IR数据
            if not rule.ir_data:
                app_logger.error(f"规则 {rule.id} 没有IR数据，无法进行分流")
                return {
                    'category': 'non_lintable',
                    'reason': '❌ 规则没有IR数据',
                    'lintable': False,
                    'lintable_reason': '缺少IR数据',
                    'failed_step': 'NoIR',
                    'assertion_subject': 'Unknown',
                    'external_dependency': {},
                    'determinism': {}
                }

            # 解析IR数据
            ir_data = json.loads(rule.ir_data)
            ir = ir_data.get('ir', {})

            # 检查是否已经有lintability判断
            zlint_lintability = ir.get('zlint_lintability')

            # 如果没有lintability判断（None或不存在），或者强制重新分类，则现在计算
            if zlint_lintability is None or force_reclassify:
                if force_reclassify:
                    app_logger.info(f"规则 {rule.id} 强制重新计算lintability...")
                else:
                    app_logger.info(f"规则 {rule.id} 的IR中没有lintability判断，现在计算...")

                # 使用 lintability 判断（基于四条件框架）
                from app.services.certificate.lintability import judge_lintability
                zlint_lintability = judge_lintability(ir)

                # 更新IR中的zlint_lintability字段
                ir['zlint_lintability'] = zlint_lintability
                ir['can_generate_zlint'] = zlint_lintability.get('can_generate', False)

                # 兼容新旧格式：优先保存新版字段
                if 'explanation' in zlint_lintability:
                    ir['zlint_reason'] = zlint_lintability.get('explanation', '')
                else:
                    ir['zlint_reason'] = zlint_lintability.get('reason', '')

                ir['zlint_failed_step'] = zlint_lintability.get('failed_step')

                # 将更新后的IR写回数据库
                ir_data['ir'] = ir
                rule.ir_data = json.dumps(ir_data, ensure_ascii=False)

                app_logger.info(f"规则 {rule.id} 的lintability判断已更新到IR并保存到数据库")

            # 从zlint_lintability中获取判断结果（兼容新旧格式）
            lintable = zlint_lintability.get('can_generate', False)

            # 优先使用新版字段explanation，如果不存在则使用旧版reason
            lintable_reason = zlint_lintability.get('explanation') or zlint_lintability.get('reason', '')
            reason_code = zlint_lintability.get('reason_code', '')

            # 如果有reason_code，添加到原因前面
            if reason_code and reason_code != 'N/A' and lintable_reason:
                lintable_reason = f"{reason_code}: {lintable_reason}"
            elif reason_code and reason_code != 'N/A':
                lintable_reason = reason_code

            failed_step = zlint_lintability.get('failed_step')

            # 获取IR的其他有用信息
            assertion_subject = ir.get('assertion_subject', 'Certificate')
            external_dependency = ir.get('external_dependency', {})
            determinism = ir.get('determinism', {})

            # 根据lintability进行二分类
            if lintable:
                category = 'lintable'
                reason = f"✅ 可生成zlint: {lintable_reason}"
            else:
                category = 'non_lintable'

                # 构建详细的失败原因
                reason_parts = [f"❌ {lintable_reason}"]

                if failed_step:
                    reason_parts.append(f"失败于: {failed_step}")

                # 添加具体的失败原因细节
                if assertion_subject != 'Certificate':
                    reason_parts.append(f"主体: {assertion_subject}")

                if external_dependency.get('has_external_ref'):
                    dep_type = external_dependency.get('dependency_type', 'unknown')
                    reason_parts.append(f"外部依赖: {dep_type}")

                if not determinism.get('is_deterministic'):
                    vague_terms = determinism.get('vague_terms', [])
                    if vague_terms:
                        reason_parts.append(f"模糊词: {', '.join(vague_terms[:2])}")

                reason = " | ".join(reason_parts)

            app_logger.debug(
                f"规则 {rule.id} lintability判断: "
                f"{lintable}, 失败步骤: {failed_step}"
            )

            return {
                'category': category,
                'reason': reason,
                'lintable': lintable,
                'lintable_reason': lintable_reason,
                'failed_step': failed_step,
                # 附加IR信息
                'assertion_subject': assertion_subject,
                'external_dependency': external_dependency,
                'determinism': determinism
            }

        except Exception as e:
            app_logger.error(f"lintability判断失败: {e}", exc_info=True)
            # 降级：无法判断的规则标记为non_lintable
            return {
                'category': 'non_lintable',
                'reason': f"❌ 判断失败: {str(e)}",
                'lintable': False,
                'lintable_reason': f"算法执行失败: {str(e)}",
                'failed_step': 'Exception',
                'assertion_subject': 'Unknown',
                'external_dependency': {},
                'determinism': {}
            }


@router.post("/intelligent-routing/classify-rules", response_model=RuleClassificationResponse)
async def classify_rules(
    request: RuleClassificationRequest = RuleClassificationRequest(),
    db: Session = Depends(get_db)
):
    """
    智能分流规则 - 使用基于Lintability判断的分类器

    对规则进行智能分类，基于规则是否可以生成zlint代码:
    - lintable=true → precise_calculation (可生成zlint)
    - lintable=false → non_lintable (不可生成zlint)
    """
    try:
        app_logger.info("开始规则智能分流（使用Lintability判断）")

        # 导入Standard模型以获取标准信息
        from app.models.models import Standard

        # 【性能优化】直接查询数据库中已有分类的规则，避免重新计算
        # 除非用户明确要求force_reclassify，否则优先使用已有结果

        if not request.force_reclassify:
            # 【快速路径】如果有已分类的规则，直接返回
            already_classified = db.query(Rule).filter(
                Rule.rule_category.isnot(None)
            ).count()

            if already_classified > 0:
                app_logger.info(f"发现{already_classified}条已分类规则，将直接使用缓存结果，跳过重新分类")

                # 查询已分类的规则统计
                classified_stats = db.query(
                    Rule.rule_category,
                    func.count(Rule.id).label('count')
                ).filter(
                    Rule.rule_category.isnot(None)
                ).group_by(Rule.rule_category).all()

                lintable_count = 0
                non_lintable_count = 0

                for category, count in classified_stats:
                    if category == 'lintable':
                        lintable_count = count
                    elif category == 'non_lintable':
                        non_lintable_count = count

                total_rules = lintable_count + non_lintable_count

                # 获取分类结果的分页数据（仅前50条作为示例）
                results = []
                classified_batch = db.query(Rule, Standard).join(
                    Standard, Rule.standard_id == Standard.id, isouter=False
                ).filter(Rule.rule_category.isnot(None)).limit(50).all()

                for rule, standard in classified_batch:
                    try:
                        import json
                        ir_data = json.loads(rule.ir_data) if rule.ir_data else {}
                        ir = ir_data.get('ir', {})
                        zlint_lintability = ir.get('zlint_lintability', {})

                        lintable = zlint_lintability.get('can_generate', False)
                        lintable_reason = zlint_lintability.get('explanation') or zlint_lintability.get('reason', '')

                        results.append(RuleClassificationResult(
                            rule_id=rule.id,
                            category='lintable' if lintable else 'non_lintable',
                            reason=f"✅ 可生成zlint: {lintable_reason}" if lintable else f"❌ {lintable_reason}",
                            lintable=lintable,
                            lintable_reason=lintable_reason,
                            rule_text=rule.text or "",
                            rule_title=rule.title or "",
                            rule_type=rule.rule_type or "",
                            section=rule.section or "",
                            rule_context=rule.context or "",
                            standard_id=standard.id,
                            standard_name=standard.title,
                            standard_type=standard.source or ""
                        ))
                    except Exception as e:
                        app_logger.debug(f"处理规则{rule.id}时出错: {e}")
                        continue

                app_logger.info(f"返回已缓存的分类结果: 可生成{lintable_count}条, 不可生成{non_lintable_count}条")
                return RuleClassificationResponse(
                    total_rules=total_rules,
                    lintable_count=lintable_count,
                    non_lintable_count=non_lintable_count,
                    results=results
                )

        # 【强制重新分类】仅在用户明确要求时执行
        # 【性能优化】使用分批处理避免内存溢出
        # 减小批处理大小防止数据库锁定
        BATCH_SIZE = 20  # 从100减小到20，减少每次提交的数据量

        # 先统计总数
        if request.rule_ids:
            total_count = db.query(Rule).join(
                Standard, Rule.standard_id == Standard.id
            ).filter(Rule.id.in_(request.rule_ids)).count()
        else:
            total_count = db.query(Rule).join(
                Standard, Rule.standard_id == Standard.id, isouter=False
            ).filter(Rule.ir_data.isnot(None)).count()

        app_logger.info(f"将对{total_count}条规则强制重新分类，分批处理（每批{BATCH_SIZE}条）")

        if total_count == 0:
            # 提供更详细的错误信息
            total_rules = db.query(Rule).count()
            rules_with_ir = db.query(Rule).filter(Rule.ir_data.isnot(None)).count()

            error_detail = f"没有找到可分类的规则。数据库共有{total_rules}条规则，其中{rules_with_ir}条有IR数据。"
            if total_rules == 0:
                error_detail += "请先提取规则。"
            elif rules_with_ir == 0:
                error_detail += "请先为规则生成IR。"
            else:
                error_detail += "请检查规则的standard_id是否正确关联到standards表。"

            raise HTTPException(status_code=404, detail=error_detail)

        # 创建分类器实例
        classifier = RuleClassifier()

        # 对每个规则进行分类
        results = []
        lintable_count = 0  # 可生成zlint的数量
        non_lintable_count = 0  # 不可生成zlint的数量

        # 分批处理规则
        for offset in range(0, total_count, BATCH_SIZE):
            app_logger.info(f"处理批次: {offset}-{min(offset + BATCH_SIZE, total_count)}/{total_count}")

            try:
                # 获取当前批次的规则
                if request.rule_ids:
                    rules_batch = db.query(Rule, Standard).join(
                        Standard, Rule.standard_id == Standard.id
                    ).filter(Rule.id.in_(request.rule_ids)).offset(offset).limit(BATCH_SIZE).all()
                else:
                    rules_batch = db.query(Rule, Standard).join(
                        Standard, Rule.standard_id == Standard.id, isouter=False
                    ).filter(Rule.ir_data.isnot(None)).offset(offset).limit(BATCH_SIZE).all()

                # 处理当前批次
                batch_count = 0
                for rule, standard in rules_batch:
                    try:
                        # 使用基于IR的分类器
                        classification = classifier.classify_rule_by_lintability(rule, force_reclassify=request.force_reclassify)

                        # 将分类结果保存到数据库
                        if classification['category'] == 'lintable':
                            rule.rule_category = 'lintable'  # 可生成zlint
                            lintable_count += 1
                        else:  # 'non_lintable'
                            rule.rule_category = 'non_lintable'  # 不可生成zlint
                            non_lintable_count += 1

                        results.append(RuleClassificationResult(
                            rule_id=rule.id,
                            category=classification['category'],
                            reason=classification['reason'],
                            lintable=classification['lintable'],
                            lintable_reason=classification['lintable_reason'],
                            # 规则详细信息
                            rule_text=rule.text or "",
                            rule_title=rule.title or "",
                            rule_type=rule.rule_type or "",
                            section=rule.section or "",
                            rule_context=rule.context or "",  # 规则原文上下文
                            # 所属标准信息
                            standard_id=standard.id,
                            standard_name=standard.title,
                            standard_type=standard.source or ""
                        ))

                        batch_count += 1

                    except Exception as e:
                        app_logger.error(
                            f"处理规则{rule.id}时出错: {type(e).__name__}: {str(e)}",
                            exc_info=True
                        )
                        # 继续处理下一个规则
                        continue

                # 【性能优化】每批处理完立即提交，不等待整个任务完成
                db.commit()
                app_logger.info(f"批次 {offset}-{min(offset + BATCH_SIZE, total_count)} 已保存({batch_count}条规则)")

            except Exception as e:
                # 批处理出错时回滚
                db.rollback()
                app_logger.error(
                    f"批处理{offset}-{min(offset + BATCH_SIZE, total_count)}时出错: {type(e).__name__}: {str(e)}",
                    exc_info=True
                )
                # 继续处理下一批
                continue

        app_logger.info("已将所有分类结果保存到数据库")

        app_logger.info(
            f"分类完成：可生成zlint {lintable_count} 条，"
            f"不可生成zlint {non_lintable_count} 条"
        )

        return RuleClassificationResponse(
            total_rules=total_count,  # 使用实际总数
            lintable_count=lintable_count,
            non_lintable_count=non_lintable_count,
            results=results
        )

    except HTTPException:
        raise
    except Exception as e:
        import traceback
        error_detail = f"{type(e).__name__}: {str(e)}"
        app_logger.error(f"规则分类失败: {error_detail}")
        app_logger.error(f"完整堆栈:\n{traceback.format_exc()}")
        raise HTTPException(status_code=500, detail=f"规则分类失败: {error_detail}")


@router.get("/intelligent-routing/rule-stats")
async def get_rule_stats(db: Session = Depends(get_db)):
    """
    获取已分类规则的统计信息（快速查询，不重新分类）

    这个端点只读取数据库中已经分类的规则统计，不会触发重新分类。
    适合前端页面加载时快速获取规则状态。

    Returns:
        {
            "total_rules": 总规则数,
            "lintable_count": 可生成zlint规则数,
            "non_lintable_count": 不可生成zlint规则数,
            "unclassified_count": 未分类规则数
        }
    """
    try:
        from sqlalchemy import func

        # 统计已分类的规则
        classified_stats = db.query(
            Rule.rule_category,
            func.count(Rule.id).label('count')
        ).filter(
            Rule.rule_category.isnot(None)
        ).group_by(Rule.rule_category).all()

        # 统计未分类的规则
        unclassified_count = db.query(func.count(Rule.id)).filter(
            Rule.rule_category.is_(None)
        ).scalar()

        # 组织结果 - 简化为两类：lintable和non_lintable
        lintable_count = 0
        non_lintable_count = 0

        for category, count in classified_stats:
            if category == 'lintable':
                lintable_count = count
            elif category == 'non_lintable':
                non_lintable_count = count
            # 忽略旧的simple_judgment和precise_calculation（已迁移）

        # 总规则数应该包含所有规则（已分类+未分类）
        total_rules = lintable_count + non_lintable_count + (unclassified_count or 0)

        return {
            "total_rules": total_rules,
            "lintable_count": lintable_count,
            "non_lintable_count": non_lintable_count,
            "unclassified_count": unclassified_count or 0
        }

    except Exception as e:
        app_logger.error(f"获取规则统计失败: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"获取规则统计失败: {str(e)}")


@router.get("/intelligent-routing/classified-rules", response_model=RuleClassificationResponse)
async def get_classified_rules(
    page: int = 1,
    page_size: int = 50,
    keyword: Optional[str] = None,
    db: Session = Depends(get_db)
):
    """
    获取已分类的规则详细信息（不重新分类）- 支持分页和搜索

    此端点直接从数据库读取已分类的规则和其IR数据中的lintability信息，
    不会触发重新分类，适合用户查看已有的分类结果。

    优化：
    - 只查询已分类的规则（rule_category != NULL），跳过未分类的规则
    - 支持分页，默认每页50条，大幅提升响应速度
    - 支持关键词搜索（与规则浏览保持一致的搜索逻辑）

    Args:
        page: 页码（从1开始）
        page_size: 每页数量（默认50，最大1000）
        keyword: 搜索关键词（可选）

    Returns:
        RuleClassificationResponse: 包含已分类规则的详细信息
    """
    try:
        import json

        # 限制page_size
        page_size = min(page_size, 1000)
        page = max(page, 1)

        # 构建基础查询条件
        base_filters = [
            Rule.ir_data.isnot(None),
            Rule.rule_category.isnot(None),  # 只查询已分类的
            # 过滤掉已被zlint覆盖的规则
            or_(
                Rule.lint_covered.is_(None),
                Rule.lint_covered == False
            )
        ]

        # 添加关键词搜索（与规则浏览保持一致的搜索逻辑）
        if keyword:
            from sqlalchemy.dialects.postgresql import JSONB
            from sqlalchemy import cast, String
            # 导入同义词扩展功能
            from app.services.extraction.synonym_mapper import expand_query_with_synonyms
            import re

            app_logger.info(f"搜索关键词: {keyword}")

            # 扩展查询（如果是已知别名，会自动添加规范术语）
            expanded_q = expand_query_with_synonyms(keyword)

            # 使用 || 分割同义词短语（保持短语完整性）
            search_terms = expanded_q.split('||')

            # 构建搜索过滤器
            all_filters = []

            for term in search_terms:
                term_filters = []

                # === 优先级1: 文本字段匹配 ===
                term_filters.extend([
                    Rule.text.op('~*')(re.escape(term)),
                    Rule.subject.op('~*')(re.escape(term)),
                    Rule.title.op('~*')(re.escape(term)),
                    Rule.context.op('~*')(re.escape(term))
                ])

                # === 优先级2: IR subject字段匹配 ===
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
                    app_logger.debug(f"IR subject搜索不可用: {e}")

                # 每个term的所有字段是OR关系
                all_filters.append(or_(*term_filters))

            # 所有同义词之间是OR关系
            if all_filters:
                base_filters.append(or_(*all_filters))

        # 【优化】只获取已分类的规则（rule_category不为空）
        total_count = db.query(Rule).filter(and_(*base_filters)).count()

        if total_count == 0:
            return RuleClassificationResponse(
                total_rules=0,
                lintable_count=0,
                non_lintable_count=0,
                results=[]
            )

        # 计算偏移量
        offset = (page - 1) * page_size

        # 【分页查询】只查询当前页的数据 - 使用PostgreSQL JSON operators提取字段，避免Python JSON解析
        from sqlalchemy.dialects.postgresql import JSONB
        from sqlalchemy import cast, Boolean

        # 使用JSONB operators直接在SQL层提取需要的字段，大幅提升性能
        # 注意：ir_data列在数据库中是Text类型，需要先cast成JSONB才能使用JSON operators
        rules_page = db.query(
            Rule.id,
            Rule.text,
            Rule.title,
            Rule.rule_type,
            Rule.section,
            Rule.context,
            Rule.rule_category,
            Standard.id.label('standard_id'),
            Standard.title.label('standard_name'),
            Standard.source.label('standard_source'),
            # 先cast成JSONB，再使用operators提取字段
            cast(
                cast(Rule.ir_data, JSONB)['ir']['zlint_lintability']['can_generate'].astext,
                Boolean
            ).label('lintable'),
            # 兼容新旧格式：读取explanation和reason
            cast(Rule.ir_data, JSONB)['ir']['zlint_lintability']['explanation'].astext.label('lintable_explanation'),
            cast(Rule.ir_data, JSONB)['ir']['zlint_lintability']['reason'].astext.label('lintable_reason_old'),
            cast(Rule.ir_data, JSONB)['ir']['zlint_lintability']['reason_code'].astext.label('reason_code'),
            cast(Rule.ir_data, JSONB)['ir']['zlint_lintability']['failed_step'].astext.label('failed_step')
        ).join(
            Standard, Rule.standard_id == Standard.id, isouter=False
        ).filter(
            and_(*base_filters)  # 使用构建好的过滤条件（包含搜索）
        ).offset(offset).limit(page_size).all()

        results = []
        lintable_count = 0
        non_lintable_count = 0

        # 处理当前页的规则（数据已由PostgreSQL提取，无需Python JSON解析）
        for row in rules_page:
            try:
                # 数据已经由PostgreSQL提取，直接使用
                lintable = row.lintable if row.lintable is not None else False

                # 兼容新旧格式：优先使用新版explanation，如果没有则使用旧版reason
                lintable_reason = row.lintable_explanation or row.lintable_reason_old or ''
                reason_code = row.reason_code or ''

                # 如果有reason_code，添加到原因前面
                if reason_code and reason_code != 'N/A' and lintable_reason:
                    lintable_reason = f"{reason_code}: {lintable_reason}"
                elif reason_code and reason_code != 'N/A':
                    lintable_reason = reason_code

                failed_step = row.failed_step

                # 分类
                if lintable:
                    category = 'lintable'
                    reason = f"✅ 可生成zlint: {lintable_reason}"
                    lintable_count += 1
                else:
                    category = 'non_lintable'
                    reason = f"❌ {lintable_reason}"
                    non_lintable_count += 1

                results.append(RuleClassificationResult(
                    rule_id=row.id,
                    category=category,
                    reason=reason,
                    lintable=lintable,
                    lintable_reason=lintable_reason,
                    failed_step=failed_step,
                    rule_text=row.text or "",
                    rule_title=row.title or "",
                    rule_type=row.rule_type or "",
                    section=row.section or "",
                    rule_context=row.context or "",
                    standard_id=row.standard_id,
                    standard_name=row.standard_name,
                    standard_type=row.standard_source or ""
                ))

            except Exception as e:
                app_logger.error(f"处理规则{row.id}时出错: {e}")
                continue

        # 统计所有分类（用于返回总数）
        all_stats = db.query(
            Rule.rule_category,
            func.count(Rule.id).label('count')
        ).filter(
            Rule.rule_category.isnot(None)
        ).group_by(Rule.rule_category).all()

        total_lintable = 0
        total_non_lintable = 0
        for category, count in all_stats:
            if category == 'lintable' or category == 'precise_calculation':
                total_lintable += count
            elif category == 'non_lintable':
                total_non_lintable += count

        app_logger.info(
            f"返回第{page}页分类规则: {len(results)}条 (本页: 可生成{lintable_count}, 不可生成{non_lintable_count}), "
            f"总计: 可生成{total_lintable}, 不可生成{total_non_lintable}"
        )

        return RuleClassificationResponse(
            total_rules=total_count,  # 总规则数
            lintable_count=total_lintable,  # 全部可生成的数量
            non_lintable_count=total_non_lintable,  # 全部不可生成的数量
            results=results  # 当前页的结果
        )

    except Exception as e:
        import traceback
        error_traceback = traceback.format_exc()
        app_logger.error(f"获取已分类规则失败: {str(e)}")
        app_logger.error(f"完整堆栈:\n{error_traceback}")
        raise HTTPException(status_code=500, detail=f"获取已分类规则失败: {str(e)}")

