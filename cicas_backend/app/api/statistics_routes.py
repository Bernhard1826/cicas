"""
Statistics API Routes
提供各种统计信息接口，包括规则、证书、验证等统计数据
"""
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from sqlalchemy import func, and_
from typing import Dict, Any
from datetime import datetime, timedelta

from app.core.database import get_db
from app.core.logging_config import app_logger
from app.models.models import Standard, Rule, UpdateLog


router = APIRouter(prefix="/api/v1/statistics", tags=["statistics"])


# ==================== Endpoints ====================

@router.get("/rules")
async def get_rule_statistics(db: Session = Depends(get_db)):
    """
    获取规则统计信息

    Returns:
        规则统计数据，包括总数、各来源规则数等
    """
    try:
        # 总规则数
        total_rules = db.query(Rule).filter().count()

        # 按来源统计规则数
        rules_by_source = db.query(
            Standard.source,
            func.count(Rule.id).label('count')
        ).join(
            Rule, Standard.id == Rule.standard_id
        ).filter(
        ).group_by(
            Standard.source
        ).all()

        # 转换为字典
        source_counts = {source: count for source, count in rules_by_source}

        # RFC规则数
        rfc_rules = source_counts.get('RFC', 0)

        # CA/B Forum规则数（包含所有CABF-*变体）
        cabforum_rules = sum(
            count for source, count in source_counts.items()
            if source and (
                source.startswith('CABF') or
                source == 'CAB Forum' or
                source == 'CA/B Forum'
            )
        )

        # ETSI规则数
        etsi_rules = sum(
            count for source, count in source_counts.items()
            if source and source.startswith('ETSI')
        )

        # Browser CA规则数
        browser_rules = sum(
            count for source, count in source_counts.items()
            if source and (
                source.startswith('Browser_CA') or
                source == 'Mozilla' or
                source == 'Google' or
                source == 'Apple' or
                source == 'Microsoft'
            )
        )

        # 最近更新时间
        latest_update = db.query(UpdateLog).order_by(
            UpdateLog.started_at.desc()
        ).first()

        # 按规则类型统计
        rules_by_type = db.query(
            Rule.rule_type,
            func.count(Rule.id).label('count')
        ).filter(
            Rule.rule_type.isnot(None)
        ).group_by(
            Rule.rule_type
        ).all()

        type_counts = {rule_type: count for rule_type, count in rules_by_type}

        # 按严重程度统计
        rules_by_severity = db.query(
            Rule.severity,
            func.count(Rule.id).label('count')
        ).filter(
            Rule.severity.isnot(None)
        ).group_by(
            Rule.severity
        ).all()

        severity_counts = {severity: count for severity, count in rules_by_severity}

        # 标准总数
        total_standards = db.query(Standard).count()
        latest_standards = db.query(Standard).filter(Standard.is_latest == True).count()

        return {
            'total_rules': total_rules,
            'rfc_rules': rfc_rules,
            'cabforum_rules': cabforum_rules,
            'etsi_rules': etsi_rules,
            'browser_rules': browser_rules,
            'rules_by_source': source_counts,
            'rules_by_type': type_counts,
            'rules_by_severity': severity_counts,
            'total_standards': total_standards,
            'latest_standards': latest_standards,
            'last_update': latest_update.started_at.isoformat() if latest_update else None,
            'last_update_status': latest_update.status if latest_update else None,
            'timestamp': datetime.now().isoformat()
        }

    except Exception as e:
        error_msg = f"Failed to get rule statistics: {str(e)}"
        app_logger.error(error_msg, exc_info=True)
        raise HTTPException(status_code=500, detail=error_msg)


@router.get("/certificates")
async def get_certificate_statistics(db: Session = Depends(get_db)):
    """
    获取证书统计信息

    Returns:
        证书统计数据
    """
    try:
        # TODO: 实现证书统计逻辑
        # 这里需要根据实际的证书表结构来查询

        return {
            'total_certificates': 0,
            'valid_certificates': 0,
            'expired_certificates': 0,
            'revoked_certificates': 0,
            'timestamp': datetime.now().isoformat()
        }

    except Exception as e:
        app_logger.error(f"Failed to get certificate statistics: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/validation")
async def get_validation_statistics(db: Session = Depends(get_db)):
    """
    获取验证统计信息

    Returns:
        验证统计数据
    """
    try:
        # TODO: 实现验证统计逻辑
        # 这里需要根据实际的验证记录表结构来查询

        return {
            'total_validations': 0,
            'passed_validations': 0,
            'failed_validations': 0,
            'success_rate': 0.0,
            'timestamp': datetime.now().isoformat()
        }

    except Exception as e:
        app_logger.error(f"Failed to get validation statistics: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/extraction")
async def get_rule_extraction_statistics(db: Session = Depends(get_db)):
    """
    获取规则提取统计信息

    Returns:
        规则提取统计数据，包括zlint覆盖率、文档引用、跨文档冲突等
    """
    try:
        import json

        app_logger.info("[STATS API] Starting extraction statistics calculation")

        # 统计最近的更新日志
        recent_updates = db.query(UpdateLog).filter(
            UpdateLog.started_at >= datetime.now() - timedelta(days=30)
        ).all()

        total_extracted = sum(log.rules_added or 0 for log in recent_updates)
        total_updated = sum(log.rules_updated or 0 for log in recent_updates)
        total_errors = sum(log.errors_count or 0 for log in recent_updates)

        # ========== 新增：从metadata_json获取详细统计 ==========
        # 获取所有最新标准的metadata
        standards = db.query(Standard).filter(Standard.is_latest == True).all()
        app_logger.info(f"[STATS API] Found {len(standards)} latest standards")

        # zlint覆盖率统计
        total_rules_all_standards = 0
        total_covered_rules = 0

        # 文档引用统计
        total_references = 0
        total_conflicts = 0

        # 各标准的详细统计
        standards_stats = []

        for standard in standards:
            if not standard.metadata_json:
                continue

            try:
                metadata = json.loads(standard.metadata_json)
                last_extraction = metadata.get('last_extraction', {})

                # zlint覆盖率
                zlint_data = last_extraction.get('zlint_coverage', {})
                if zlint_data.get('executed'):
                    total_rules_count = zlint_data.get('total_rules', 0)
                    covered_count = zlint_data.get('covered_count', 0)
                    total_rules_all_standards += total_rules_count
                    total_covered_rules += covered_count

                # 文档引用
                ref_data = last_extraction.get('cross_document_processing', {})
                if ref_data.get('executed'):
                    total_references += ref_data.get('references_resolved', 0)
                    total_conflicts += ref_data.get('conflicts_resolved', 0)

                # 记录各标准统计
                standards_stats.append({
                    'standard_id': standard.id,
                    'source': standard.source,
                    'title': standard.title,
                    'rules_count': zlint_data.get('total_rules', 0),
                    'zlint_covered': zlint_data.get('covered_count', 0),
                    'zlint_coverage_rate': zlint_data.get('coverage_rate', 0),
                    'references': ref_data.get('references_resolved', 0),
                    'conflicts': ref_data.get('conflicts_resolved', 0)
                })
            except (json.JSONDecodeError, KeyError) as e:
                app_logger.debug(f"Failed to parse metadata for standard {standard.id}: {e}")
                continue

        # 计算总体zlint覆盖率
        overall_coverage_rate = (total_covered_rules / total_rules_all_standards * 100) if total_rules_all_standards > 0 else 0

        return {
            # 原有统计
            'total_extracted_last_30_days': total_extracted,
            'total_updated_last_30_days': total_updated,
            'total_errors_last_30_days': total_errors,
            'extraction_runs': len(recent_updates),

            # 新增：zlint覆盖率统计
            'zlint_coverage': {
                'total_rules': total_rules_all_standards,
                'covered_rules': total_covered_rules,
                'coverage_rate': round(overall_coverage_rate, 2),
                'uncovered_rules': total_rules_all_standards - total_covered_rules
            },

            # 新增：文档引用和冲突统计
            'cross_document': {
                'total_references': total_references,
                'total_conflicts': total_conflicts
            },

            # 新增：各标准详细统计
            'standards_details': standards_stats,

            'timestamp': datetime.now().isoformat()
        }

    except Exception as e:
        app_logger.error(f"Failed to get extraction statistics: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/system")
async def get_system_statistics(db: Session = Depends(get_db)):
    """
    获取系统统计信息

    Returns:
        系统整体统计数据
    """
    try:
        # 标准统计
        total_standards = db.query(Standard).count()
        latest_standards = db.query(Standard).filter(Standard.is_latest == True).count()

        # 规则统计
        total_rules = db.query(Rule).filter().count()

        # 更新统计
        total_updates = db.query(UpdateLog).count()
        successful_updates = db.query(UpdateLog).filter(
            UpdateLog.status == 'completed'
        ).count()
        failed_updates = db.query(UpdateLog).filter(
            UpdateLog.status == 'failed'
        ).count()

        # 最近更新
        latest_update = db.query(UpdateLog).order_by(
            UpdateLog.started_at.desc()
        ).first()

        # 系统运行时间（从最早的更新日志开始）
        first_update = db.query(UpdateLog).order_by(
            UpdateLog.started_at.asc()
        ).first()

        system_uptime = None
        if first_update:
            uptime_delta = datetime.now() - first_update.started_at
            system_uptime = uptime_delta.total_seconds()

        return {
            'total_standards': total_standards,
            'latest_standards': latest_standards,
            'total_rules': total_rules,
            'total_updates': total_updates,
            'successful_updates': successful_updates,
            'failed_updates': failed_updates,
            'update_success_rate': (successful_updates / total_updates * 100) if total_updates > 0 else 0,
            'last_update': latest_update.started_at.isoformat() if latest_update else None,
            'last_update_status': latest_update.status if latest_update else None,
            'system_uptime_seconds': system_uptime,
            'timestamp': datetime.now().isoformat()
        }

    except Exception as e:
        app_logger.error(f"Failed to get system statistics: {e}")
        raise HTTPException(status_code=500, detail=str(e))
