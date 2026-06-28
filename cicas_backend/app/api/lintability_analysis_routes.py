"""
Lintability Analysis API Routes
提供规则可执行性分析的真实统计接口 - 用于前端Dashboard展示

可执行性(Lintability)定义:
一条规则是可执行的当且仅当满足以下四个条件：
1. 主体可访问 - 在X.509证书结构中可定位目标字段
2. 约束可验证 - 约束条件可转化为确定性布尔判断
3. 义务可检测 - 规则义务可映射到代码检测逻辑
4. 上下文完备 - 无需外部信息即可完成验证
"""
from fastapi import APIRouter, HTTPException
from typing import Dict, Any
from datetime import datetime
import json
import os

from app.core.logging_config import app_logger

router = APIRouter(prefix="/api/v1/lintability", tags=["lintability-analysis"])

# 数据文件路径
BASE_DIR = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
DATA_FILES = {
    'section_72_results': os.path.join(BASE_DIR, 'test_section_7_2_results.json'),
    'section_72_generated': os.path.join(BASE_DIR, 'section_72_generated_zlint.json'),
    'section_72_extracted': os.path.join(BASE_DIR, 'section_72_llm_extracted.json'),
    'other_sections': os.path.join(BASE_DIR, 'sections_4216_42110_extracted.json'),
}


def load_json_file(filepath: str) -> Any:
    """安全加载JSON文件"""
    try:
        if os.path.exists(filepath):
            with open(filepath, 'r', encoding='utf-8') as f:
                return json.load(f)
    except Exception as e:
        app_logger.warning(f"Failed to load {filepath}: {e}")
    return None


@router.get("/section72/lintability")
async def get_section72_lintability_stats():
    """
    获取RFC 5280 §7.2的可执行性分析统计（真实数据）
    数据来源：section_72_llm_extracted.json (extraction_stats)

    Returns:
        可执行性分析统计数据，包括：
        - 总规则数（聚合后）
        - 可执行/不可执行分布
        - lint_category分布
    """
    try:
        # 从提取结果文件获取统计数据
        extracted = load_json_file(DATA_FILES['section_72_extracted'])
        if not extracted:
            raise HTTPException(status_code=404, detail="提取结果数据不存在")

        stats = extracted.get('extraction_stats', {})

        # lint_category分布来自extraction_stats
        category_distribution = stats.get('lint_category_distribution', {})

        # 计算总数和可执行数
        total = stats.get('after_aggregation', 0)
        lintable = stats.get('lintable_rules', 0)

        return {
            'source': 'RFC 5280 §7.2',
            'total_rules': total,  # 12
            'lintable_count': lintable,  # 4
            'non_lintable_count': total - lintable,  # 8
            'lintable_rate': round(lintable / total * 100, 1) if total > 0 else 0,  # 33.3
            'category_distribution': category_distribution,
            'pools': {
                'rules': stats.get('rules_pool', 0),
                'behavior': stats.get('behavior_pool', 0),
                'guidance': stats.get('guidance_pool', 0),
                'definitions': stats.get('definitions_pool', 0),
            },
            'extraction_method': extracted.get('extraction_method'),
            'generated_at': extracted.get('generated_at'),
            'timestamp': datetime.now().isoformat()
        }

    except HTTPException:
        raise
    except Exception as e:
        app_logger.error(f"Failed to get section 7.2 lintability stats: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/section72/generated")
async def get_section72_generated_stats():
    """
    获取RFC 5280 §7.2生成的zlint代码统计（真实数据）

    Returns:
        zlint代码生成统计
    """
    try:
        data = load_json_file(DATA_FILES['section_72_generated'])
        if not data:
            raise HTTPException(status_code=404, detail="生成数据不存在")

        generated_codes = data.get('generated_codes', [])

        # 统计生成强度分布
        strength_counts = {'strong': 0, 'weak': 0}
        for code in generated_codes:
            lintability = code.get('lintability', {})
            strength = lintability.get('strength', 'weak')
            if strength in strength_counts:
                strength_counts[strength] += 1

        return {
            'source': data.get('source', 'RFC 5280 §7.2'),
            'generated_at': data.get('generated_at'),
            'total_rules': data.get('total_rules', 0),
            'generated_count': data.get('generated_count', 0),
            'pattern_distribution': data.get('pattern_distribution', {}),
            'strength_distribution': strength_counts,
            'lint_names': [c.get('lint_name') for c in generated_codes],
            'timestamp': datetime.now().isoformat()
        }

    except HTTPException:
        raise
    except Exception as e:
        app_logger.error(f"Failed to get section 7.2 generated stats: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/section72/details")
async def get_section72_details():
    """
    获取RFC 5280 §7.2的详细规则列表（真实数据）

    Returns:
        每条规则的详细信息
    """
    try:
        results = load_json_file(DATA_FILES['section_72_results'])
        if not results:
            raise HTTPException(status_code=404, detail="测试结果数据不存在")

        rules = []
        for item in results:
            rules.append({
                'sentence_num': item.get('sentence_num'),
                'sentence': item.get('sentence', '')[:100] + '...' if len(item.get('sentence', '')) > 100 else item.get('sentence', ''),
                'category': item.get('ir_category'),
                'can_generate': item.get('final_can_generate', False),
                'expected_lintable': item.get('expected_lintable', False),
                'match': item.get('match', False),
                'strength': item.get('lintability', {}).get('strength'),
                'reason': item.get('lintability', {}).get('reason_code'),
            })

        return {
            'source': 'RFC 5280 §7.2',
            'rules': rules,
            'total': len(rules),
            'timestamp': datetime.now().isoformat()
        }

    except HTTPException:
        raise
    except Exception as e:
        app_logger.error(f"Failed to get section 7.2 details: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/overview")
async def get_lintability_overview():
    """
    获取可执行性分析概览统计（真实数据）
    数据来源：section_72_llm_extracted.json, sections_4216_42110_extracted.json

    用于Dashboard展示的汇总数据
    """
    try:
        # 加载§7.2数据
        extracted_72 = load_json_file(DATA_FILES['section_72_extracted']) or {}
        generated_72 = load_json_file(DATA_FILES['section_72_generated']) or {}
        other_sections = load_json_file(DATA_FILES['other_sections']) or {}

        # §7.2统计（来自extraction_stats）
        stats_72 = extracted_72.get('extraction_stats', {})
        total_72 = stats_72.get('after_aggregation', 0)
        lintable_72 = stats_72.get('lintable_rules', 0)

        # 分类统计（lint_category_distribution）
        categories = stats_72.get('lint_category_distribution', {})

        # 生成的lint数量
        generated_count = generated_72.get('generated_count', 0)

        # 其他章节统计
        sections_data = other_sections.get('sections', {})
        section_4216 = sections_data.get('4.2.1.6', {}).get('stats', {})
        section_42110 = sections_data.get('4.2.1.10', {}).get('stats', {})

        return {
            'sections_analyzed': ['RFC 5280 §7.2', 'RFC 5280 §4.2.1.6', 'RFC 5280 §4.2.1.10'],
            'section_72': {
                'total_rules': total_72,  # 12
                'lintable': lintable_72,  # 4
                'non_lintable': total_72 - lintable_72,  # 8
                'lintable_rate': round(lintable_72 / total_72 * 100, 1) if total_72 > 0 else 0,  # 33.3%
                'generated_lints': generated_count,  # 4
            },
            'section_4216': {
                'total_rules': section_4216.get('aggregated_irs', 0),  # 32
                'lintable': section_4216.get('lintable', 0),  # 22
                'lintable_rate': round(section_4216.get('lintable', 0) / section_4216.get('aggregated_irs', 1) * 100, 1) if section_4216.get('aggregated_irs', 0) > 0 else 0,
            },
            'section_42110': {
                'total_rules': section_42110.get('aggregated_irs', 0),  # 30
                'lintable': section_42110.get('lintable', 0),  # 19
                'lintable_rate': round(section_42110.get('lintable', 0) / section_42110.get('aggregated_irs', 1) * 100, 1) if section_42110.get('aggregated_irs', 0) > 0 else 0,
            },
            'category_distribution': categories,
            'total_extracted': total_72 + section_4216.get('aggregated_irs', 0) + section_42110.get('aggregated_irs', 0),  # 74
            'total_lintable': lintable_72 + section_4216.get('lintable', 0) + section_42110.get('lintable', 0),  # 45
            'total_generated': generated_count,
            'timestamp': datetime.now().isoformat()
        }

    except Exception as e:
        app_logger.error(f"Failed to get lintability overview: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=str(e))
