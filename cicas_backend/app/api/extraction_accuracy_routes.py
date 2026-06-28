"""
规则提取准确性统计API
提供规则提取质量、准确性和交叉验证结果的统计数据
"""
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from sqlalchemy import func, and_, or_, case
from typing import Dict, Any, List
from datetime import datetime

from app.core.database import get_db
from app.core.logging_config import app_logger
from app.models.models import Standard, Rule


router = APIRouter(prefix="/api/v1/extraction-accuracy", tags=["Extraction Accuracy"])


@router.get("/overview")
async def get_extraction_accuracy_overview(db: Session = Depends(get_db)):
    """
    获取规则提取准确性概览

    包含：
    - 总规则数
    - 各字段提取情况
    - 交叉验证通过率
    - 需要人工审核的规则数
    """
    try:
        # 总规则数
        total_rules = db.query(Rule).filter().count()

        # 字段提取完整性统计
        # affected_field 提取率
        field_extracted = db.query(Rule).filter(
            Rule.subject.isnot(None),
            Rule.subject != '',
            Rule.subject != 'unknown'
        ).count()
        field_extraction_rate = (field_extracted / total_rules * 100) if total_rules > 0 else 0

        # operation 提取率
        operation_extracted = db.query(Rule).filter(
            Rule.predicate.isnot(None),
            Rule.predicate != ''
        ).count()
        operation_extraction_rate = (operation_extracted / total_rules * 100) if total_rules > 0 else 0

        # expected_value 提取率
        value_extracted = db.query(Rule).filter(
            Rule.constraint_value.isnot(None),
            Rule.constraint_value != ''
        ).count()
        value_extraction_rate = (value_extracted / total_rules * 100) if total_rules > 0 else 0

        # 规则类型分布
        rule_type_dist = db.query(
            Rule.rule_type,
            func.count(Rule.id).label('count')
        ).filter(
            Rule.rule_type.isnot(None)
        ).group_by(Rule.rule_type).all()

        rule_types = {rule_type: count for rule_type, count in rule_type_dist}

        return {
            'status': 'success',
            'overview': {
                'total_rules': total_rules,
                'extraction_rates': {
                    'affected_field': round(field_extraction_rate, 2),
                    'operation': round(operation_extraction_rate, 2),
                    'expected_value': round(value_extraction_rate, 2),
                    'overall': round((field_extraction_rate + operation_extraction_rate + value_extraction_rate) / 3, 2)
                },
                'rule_types': rule_types
            },
            'timestamp': datetime.now().isoformat()
        }

    except Exception as e:
        app_logger.error(f"Failed to get extraction accuracy overview: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/by-standard")
async def get_accuracy_by_standard(
    source: str = None,
    db: Session = Depends(get_db)
):
    """
    按标准分组统计提取准确性

    Args:
        source: 可选的来源筛选（RFC, CABF, ETSI）
    """
    try:
        # 构建查询
        query = db.query(
            Standard.id,
            Standard.source,
            Standard.title,
            func.count(Rule.id).label('total_rules'),
            func.sum(case(
                (and_(
                    Rule.subject.isnot(None),
                    Rule.subject != '',
                    Rule.subject != 'unknown'
                ), 1),
                else_=0
            )).label('field_extracted'),
            func.sum(case(
                (Rule.cross_validation_status == 'passed', 1),
                else_=0
            )).label('cv_passed'),
            func.avg(Rule.cross_validation_score).label('avg_cv_score')
        ).join(
            Rule, Standard.id == Rule.standard_id
        ).filter(
        ).group_by(
            Standard.id, Standard.source, Standard.title
        )

        if source:
            query = query.filter(Standard.source == source)

        results = query.order_by(Standard.source, Standard.title).all()

        standards_accuracy = []
        for std_id, std_source, std_title, total, field_ext, cv_pass, avg_score in results:
            field_rate = (field_ext / total * 100) if total > 0 else 0
            cv_rate = (cv_pass / total * 100) if total > 0 else 0

            standards_accuracy.append({
                'standard_id': std_id,
                'source': std_source,
                'title': std_title,
                'total_rules': total,
                'field_extraction_rate': round(field_rate, 2),
                'cv_pass_rate': round(cv_rate, 2),
                'avg_cv_score': round(float(avg_score), 3) if avg_score else None
            })

        return {
            'status': 'success',
            'standards': standards_accuracy,
            'total_standards': len(standards_accuracy),
            'timestamp': datetime.now().isoformat()
        }

    except Exception as e:
        app_logger.error(f"Failed to get accuracy by standard: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/field-analysis")
async def get_field_extraction_analysis(db: Session = Depends(get_db)):
    """
    分析各个字段的提取情况

    返回最常见的 affected_field 及其准确性
    """
    try:
        # 统计各字段出现频率
        field_stats = db.query(
            Rule.subject,
            func.count(Rule.id).label('count'),
            func.avg(Rule.cross_validation_score).label('avg_score'),
            func.sum(case(
                (Rule.cross_validation_status == 'passed', 1),
                else_=0
            )).label('cv_passed')
        ).filter(
            Rule.subject.isnot(None),
            Rule.subject != '',
            Rule.subject != 'unknown'
        ).group_by(
            Rule.subject
        ).order_by(
            func.count(Rule.id).desc()
        ).limit(30).all()

        field_analysis = []
        for field, count, avg_score, cv_pass in field_stats:
            cv_rate = (cv_pass / count * 100) if count > 0 else 0
            field_analysis.append({
                'field': field,
                'count': count,
                'avg_cv_score': round(float(avg_score), 3) if avg_score else None,
                'cv_pass_rate': round(cv_rate, 2)
            })

        return {
            'status': 'success',
            'top_fields': field_analysis,
            'timestamp': datetime.now().isoformat()
        }

    except Exception as e:
        app_logger.error(f"Failed to get field extraction analysis: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/problematic-rules")
async def get_problematic_rules(
    limit: int = 50,
    db: Session = Depends(get_db)
):
    """
    获取需要人工审核的问题规则

    包含：
    - 交叉验证失败的规则
    - 字段提取不完整的规则
    - 标记为需要审核的规则

    Args:
        limit: 返回数量限制
    """
    try:
        # 查询问题规则
        problematic = db.query(Rule).join(Standard).filter(
            or_(
                Rule.cross_validation_status == 'failed',
                and_(
                    or_(
                        Rule.subject.is_(None),
                        Rule.subject == '',
                        Rule.subject == 'unknown'
                    ),
                    Rule.rule_type.in_(['MUST', 'REQUIRED', 'SHALL'])
                )
            )
        ).order_by(
            Rule.cross_validation_score.asc().nullsfirst()
        ).limit(limit).all()

        rules_list = []
        for rule in problematic:
            # 判断问题类型
            issues = []
            if rule.cross_validation_status == 'failed':
                issues.append('cv_failed')
            if not rule.subject or rule.subject in ['', 'unknown']:
                issues.append('missing_field')
            if not rule.predicate:
                issues.append('missing_operation')

            rules_list.append({
                'id': rule.id,
                'standard': {
                    'id': rule.standard.id,
                    'source': rule.standard.source,
                    'title': rule.standard.title
                },
                'section': rule.section,
                'text': rule.text[:150] + '...' if len(rule.text) > 150 else rule.text,
                'rule_type': rule.rule_type,
                'affected_field': rule.subject,
                'operation': rule.predicate,
                'cv_status': rule.cross_validation_status,
                'cv_score': rule.cross_validation_score,
                'issues': issues
            })

        return {
            'status': 'success',
            'total_problematic': len(rules_list),
            'rules': rules_list,
            'timestamp': datetime.now().isoformat()
        }

    except Exception as e:
        app_logger.error(f"Failed to get problematic rules: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/quality-trend")
async def get_quality_trend(db: Session = Depends(get_db)):
    """
    获取提取质量趋势（按创建时间分组）

    显示最近的提取质量变化
    """
    try:
        # 按日期统计
        from sqlalchemy import cast, Date

        trend = db.query(
            cast(Rule.created_at, Date).label('date'),
            func.count(Rule.id).label('total'),
            func.avg(Rule.cross_validation_score).label('avg_score'),
            func.sum(case(
                (Rule.cross_validation_status == 'passed', 1),
                else_=0
            )).label('cv_passed')
        ).filter(
            Rule.created_at.isnot(None)
        ).group_by(
            cast(Rule.created_at, Date)
        ).order_by(
            cast(Rule.created_at, Date).desc()
        ).limit(30).all()

        trend_data = []
        for date, total, avg_score, cv_pass in trend:
            cv_rate = (cv_pass / total * 100) if total > 0 else 0
            trend_data.append({
                'date': date.isoformat() if date else None,
                'total_rules': total,
                'avg_cv_score': round(float(avg_score), 3) if avg_score else None,
                'cv_pass_rate': round(cv_rate, 2)
            })

        return {
            'status': 'success',
            'trend': list(reversed(trend_data)),  # 按时间正序
            'timestamp': datetime.now().isoformat()
        }

    except Exception as e:
        app_logger.error(f"Failed to get quality trend: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=str(e))
