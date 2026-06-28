"""
zlint Coverage Analysis API (V2)
提供基于三层验证的 zlint 覆盖率检查接口

三层验证：
1. Source 匹配：规则来源 → zlint Source 常量
2. Citation 章节号匹配：规则章节 → Citation 中的章节号
3. Embedding 相似度：规则文本 → Description（相似度 >= 阈值）
"""
from fastapi import APIRouter, Depends, HTTPException, BackgroundTasks
from sqlalchemy.orm import Session
from typing import List, Dict, Optional
from pydantic import BaseModel

from app.core.database import get_db
from app.core.logging_config import app_logger
from app.models.models import Rule, Standard
from app.services.certificate.zlint_interface import ZLintInterface
from app.core.config import settings

router = APIRouter()

# 全局 ZLintInterface 实例
_zlint_interface: Optional[ZLintInterface] = None


async def get_zlint_interface() -> ZLintInterface:
    """
    获取全局 ZLintInterface 实例

    在首次调用时初始化，后续调用直接返回缓存的实例
    """
    global _zlint_interface

    if _zlint_interface is None:
        app_logger.info("[ZLintAnalysis] Initializing ZLintInterface...")
        _zlint_interface = ZLintInterface(zlint_path=settings.zlint_path)
        await _zlint_interface.initialize_coverage_detection()
        app_logger.info("[ZLintAnalysis] ZLintInterface initialized!")

    return _zlint_interface


class RuleCoverageRequest(BaseModel):
    """单个规则覆盖率检查请求"""
    rule_id: int


class BatchCoverageRequest(BaseModel):
    """批量规则覆盖率检查请求"""
    rule_ids: Optional[List[int]] = None  # None = all rules
    standard_id: Optional[int] = None  # Filter by standard
    limit: int = 100


@router.post("/api/v1/zlint-analysis/coverage")
async def check_rule_coverage(
    request: RuleCoverageRequest,
    db: Session = Depends(get_db)
):
    """
    检查单个规则的zlint覆盖率（V2：三层验证）

    Returns:
        {
            'rule_id': int,
            'rule_text': str,
            'has_coverage': bool,
            'lint_name': str or None,
            'match_method': str,  # 'three_layer_match', 'no_source_section', 'no_match'
            'matched_lints': List[Dict],  # 匹配的 lints 详情
            'reasoning': str,
            'similarity': float or None,  # 最高相似度
            'confidence': float  # 置信度 (0-1)
        }
    """
    try:
        # Get rule
        rule = db.query(Rule).filter(Rule.id == request.rule_id).first()
        if not rule:
            raise HTTPException(status_code=404, detail=f"Rule {request.rule_id} not found")

        # Get ZLintInterface
        zlint_interface = await get_zlint_interface()

        # Convert rule to dict
        rule_dict = {
            'id': rule.id,
            'text': rule.text,
            'section': rule.section,
            'source': rule.standard.source if rule.standard else 'Unknown'
        }

        # Check coverage (V2: three-layer validation)
        result = await zlint_interface.check_rule_coverage_intelligent(rule_dict)

        # Add rule info
        result['rule_id'] = rule.id
        result['rule_text'] = rule.text[:200]

        return result

    except Exception as e:
        app_logger.error(f"Error checking coverage for rule {request.rule_id}: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/api/v1/zlint-analysis/batch-coverage")
async def check_batch_coverage(
    request: BatchCoverageRequest,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db)
):
    """
    批量检查规则的zlint覆盖率（V2：三层验证）

    Returns:
        {
            'total_rules': int,
            'covered_rules': int,
            'coverage_rate': float,
            'results': List[dict]
        }
    """
    try:
        # Build query
        query = db.query(Rule)

        if request.rule_ids:
            query = query.filter(Rule.id.in_(request.rule_ids))
        elif request.standard_id:
            query = query.filter(Rule.standard_id == request.standard_id)

        # Apply limit
        rules = query.limit(request.limit).all()

        if not rules:
            raise HTTPException(status_code=404, detail="No rules found")

        # Get ZLintInterface
        zlint_interface = await get_zlint_interface()

        # Check coverage for all rules
        results = []
        covered_count = 0

        for rule in rules:
            rule_dict = {
                'id': rule.id,
                'text': rule.text,
                'section': rule.section,
                'source': rule.standard.source if rule.standard else 'Unknown'
            }

            try:
                coverage_result = await zlint_interface.check_rule_coverage_intelligent(
                    rule_dict
                )

                # Add rule info
                coverage_result['rule_id'] = rule.id
                coverage_result['rule_text'] = rule.text[:200]

                results.append(coverage_result)

                if coverage_result['has_coverage']:
                    covered_count += 1

            except Exception as e:
                app_logger.error(f"Error checking rule {rule.id}: {e}")
                results.append({
                    'rule_id': rule.id,
                    'rule_text': rule.text[:200],
                    'has_coverage': False,
                    'error': str(e)
                })

        # Calculate statistics
        total_rules = len(results)
        coverage_rate = covered_count / total_rules if total_rules > 0 else 0

        return {
            'total_rules': total_rules,
            'covered_rules': covered_count,
            'coverage_rate': coverage_rate,
            'results': results
        }

    except Exception as e:
        app_logger.error(f"Error in batch coverage check: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/api/v1/zlint-analysis/statistics")
async def get_analysis_statistics(
    db: Session = Depends(get_db)
):
    """
    获取zlint覆盖率分析的统计信息（V2：三层验证）
    """
    try:
        # Get total rules count
        total_rules = db.query(Rule).count()

        # Get ZLintInterface
        zlint_interface = await get_zlint_interface()

        # Get all parsed lints count
        total_lints = len(zlint_interface.all_zlint_metadata)

        # Get package counts
        package_counts = {}
        for lint in zlint_interface.all_zlint_metadata:
            package = lint.package
            package_counts[package] = package_counts.get(package, 0) + 1

        # Get source counts
        source_counts = {}
        for lint in zlint_interface.all_zlint_metadata:
            source = lint.source or "None"
            source_counts[source] = source_counts.get(source, 0) + 1

        return {
            'total_rules': total_rules,
            'total_lints': total_lints,
            'lint_packages': list(package_counts.keys()),
            'package_counts': package_counts,
            'source_counts': source_counts,
            'analysis_capabilities': {
                'coverage_check': True,
                'three_layer_validation': True,
                'match_method': 'Source + Citation + LLM synonym judgment'
            }
        }

    except Exception as e:
        app_logger.error(f"Error getting statistics: {e}")
        raise HTTPException(status_code=500, detail=str(e))
