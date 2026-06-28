"""
ZLint Code Generation API Routes
提供完整的 规则→IR→Go代码→测试 生成接口
"""
from fastapi import APIRouter, Depends, HTTPException, BackgroundTasks
from sqlalchemy.orm import Session
from sqlalchemy import and_, or_, cast, String, func
from sqlalchemy.dialects.postgresql import JSONB
from typing import List, Dict, Optional, Any
from pydantic import BaseModel
import json

from app.core.database import get_db
from app.core.logging_config import app_logger
from app.models.models import Rule, Standard
from app.services.certificate.zlint_generator import ZlintCodeGenerator
from app.services.certificate.ir_field_guard import apply_ir_field_guard
from app.services.certificate.zlint_interface import ZLintInterface
from app.core.config import settings

router = APIRouter()


# IR 的 predicate → L-subclass 模板键的确定性映射。
# 数据库中规则未填充 lint_subclass，但每条都带 predicate，可无歧义地推导出
# 生成器所需的模板类别（L1-L6）。仅作为缺失字段的派生输入，不改动生成算法本身。
_PREDICATE_TO_SUBCLASS = {
    "must_be_present": "L1",      # 存在性
    "must_not_be_present": "L1",  # 缺省性
    "must_equal": "L2",           # 取值相等
    "must_be_critical": "L2",     # criticality 布尔相等
    "must_not_be_critical": "L2",
    "allowed_values": "L3",       # 枚举集合
    "encode_as": "L4",            # 编码/格式
    "matches_pattern": "L4",
    "conform_to": "L4",
    "must_conform_to": "L4",
    "must_include": "L5",         # 包含
    "must_not_include": "L5",
    "in_range": "L6",             # 数值范围
}


def _ensure_lint_subclass(ir: Dict) -> None:
    """缺失 lint_subclass 时，从 predicate 确定性派生并就地补入 ir（仅内存，不写库）。"""
    if ir.get("lint_subclass"):
        return
    predicate = (ir.get("predicate") or "").strip().lower()
    derived = _PREDICATE_TO_SUBCLASS.get(predicate)
    if derived:
        ir["lint_subclass"] = derived


class GenerateCodeRequest(BaseModel):
    """代码生成请求"""
    rule_id: int
    save_files: bool = True  # 是否保存到文件系统


class BatchGenerateRequest(BaseModel):
    """批量代码生成请求"""
    rule_ids: Optional[List[int]] = None
    standard_id: Optional[int] = None
    save_files: bool = True
    limit: int = 100


class ParseRuleToIRRequest(BaseModel):
    """解析规则到IR的请求"""
    rule_text: str
    source: str = "RFC"
    section: str = ""
    affected_field: str = ""
    operation: str = ""
    expected_value: str = ""




@router.post("/parse-to-ir")
async def parse_rule_to_ir(
    request: ParseRuleToIRRequest,
    db: Session = Depends(get_db)
):
    """
    将规则解析为中间表示（IR v2.0） - 主要用于测试和调试

    ⚠️ 注意：此API已弃用。
    在实际使用中，IR v2.0已在规则提取时生成并存储在数据库中。
    请直接使用 /api/v1/codegen/generate-from-rule 接口，
    该接口会使用数据库中已存储的IR v2.0数据。

    如需重新生成IR，请使用规则提取流程。

    Returns:
        {
            'success': bool,
            'error': str
        }
    """
    return {
        'success': False,
        'error': '此API已弃用。IR v2.0应通过规则提取流程生成。请使用 /api/v1/codegen/generate-from-rule 接口，该接口使用数据库中已有的IR数据。'
    }


@router.post("/generate-from-rule")
async def generate_code_from_rule(
    request: GenerateCodeRequest,
    db: Session = Depends(get_db)
):
    """
    从规则生成完整的zlint代码（使用IR）

    要求：Rule.ir_data 必须包含IR格式的数据

    Returns:
        {
            'success': bool,
            'go_code': str,
            'test_code': str,
            'metadata': dict,
            'lintability': dict,
            'file_path': str (if saved),
            'test_file_path': str (if saved),
            'error': str (if failed)
        }
    """
    try:
        # 获取规则
        rule = db.query(Rule).filter(Rule.id == request.rule_id).first()
        if not rule:
            raise HTTPException(status_code=404, detail=f"Rule {request.rule_id} not found")

        # 检查IR数据
        if not rule.ir_data:
            raise HTTPException(
                status_code=400,
                detail="规则缺少IR数据。请先运行规则提取流程生成IR数据。"
            )

        # 解析IR
        try:
            ir_data = json.loads(rule.ir_data)
            # 新格式：IR数据在ir_data['ir']中
            ir = ir_data.get('ir', {})
            if not ir:
                raise HTTPException(
                    status_code=400,
                    detail="IR数据格式错误：缺少'ir'字段。请重新提取规则。"
                )
        except json.JSONDecodeError:
            raise HTTPException(status_code=400, detail="IR数据格式错误")

        # 初始化 LLM 生成器（确定性 codegen 已逻辑删除，全走 LLM）
        generator = ZlintCodeGenerator(
            api_key=settings.LLM_API_KEY,
            api_base=settings.LLM_API_BASE,
            model=settings.LLM_MODEL,
        )
        zlint_interface = ZLintInterface()

        # 生成代码（LLM 路径）
        result = generator.generate(ir)

        # IR 字段来源检查：确保 LLM 没有引用 IR 之外的字段
        result, guard = apply_ir_field_guard(result, ir)
        if not result.success:
            return {
                'success': False,
                'error': result.error,
                'ir_field_guard': guard,
                'rule_id': request.rule_id,
            }

        if not result.success:
            raise HTTPException(status_code=400, detail=result.error)

        # 添加原始IR数据给前端（用于显示）
        result_dict = {
            'success': True,
            'go_code': result.go_code,
            'test_code': result.test_code,
            'metadata': result.metadata,
            'ir_json': json.dumps(ir, ensure_ascii=False),
            'ir_field_guard': {
                'ok': guard.ok,
                'violations': guard.violations,
                'referenced_fields': sorted(guard.referenced_fields),
                'ir_subject_fields': sorted(guard.ir_subject_fields),
            },
        }

        # 保存文件到zlint项目
        if request.save_files:
            try:
                # 保存lint Go代码
                save_result = zlint_interface.save_generated_code(
                    lint_name=result.metadata.get('lint_name') or result_dict['metadata'].get('lint_name', ''),
                    package_name=result_dict['metadata'].get('package', 'rfc'),
                    go_code=result.go_code
                )

                if save_result['success']:
                    result_dict['file_path'] = save_result['file_path']
                    result_dict['files_saved'] = True

                    # 保存测试代码
                    test_file_path = save_result['file_path'].replace('.go', '_test.go')
                    try:
                        with open(test_file_path, 'w') as f:
                            f.write(result.test_code or '')
                        result_dict['test_file_path'] = test_file_path
                        app_logger.info(f"Saved test code to: {test_file_path}")
                    except Exception as e:
                        app_logger.warning(f"Failed to save test code: {e}")
                else:
                    result_dict['files_saved'] = False
                    result_dict['save_error'] = save_result['error']
            except Exception as e:
                app_logger.error(f"Error saving files: {e}")
                result_dict['files_saved'] = False
                result_dict['save_error'] = str(e)
        else:
            result_dict['files_saved'] = False

        return result_dict

    except HTTPException:
        raise
    except Exception as e:
        app_logger.error(f"Error generating code from rule: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/batch-generate")
async def batch_generate_codes(
    request: BatchGenerateRequest,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db)
):
    """
    批量生成zlint代码（使用IR）

    过滤条件：
    1. 有IR数据
    2. zlint_lintability.can_generate = true (规则可生成zlint)
    3. lint_covered = false 或 null (规则未被zlint覆盖)

    Returns:
        {
            'success': bool,
            'total_rules': int,
            'generated_count': int,
            'failed_count': int,
            'skipped_count': int,  # 跳过的规则（已覆盖或无法生成）
            'results': List[dict]
        }
    """
    try:
        # 构建查询
        query = db.query(Rule)

        if request.rule_ids:
            query = query.filter(Rule.id.in_(request.rule_ids))
        elif request.standard_id:
            query = query.filter(Rule.standard_id == request.standard_id)

        # 只查询有IR数据的规则
        query = query.filter(Rule.ir_data.isnot(None))

        # 应用限制
        rules = query.limit(request.limit).all()

        if not rules:
            raise HTTPException(status_code=404, detail="No rules with IR data found")

        # 初始化 LLM 生成器（确定性 codegen 已逻辑删除，全走 LLM）
        generator = ZlintCodeGenerator(
            api_key=settings.LLM_API_KEY,
            api_base=settings.LLM_API_BASE,
            model=settings.LLM_MODEL,
        )
        zlint_interface = ZLintInterface()

        # 批量生成
        results = []
        generated_count = 0
        failed_count = 0
        skipped_count = 0  # 新增：跳过的规则计数

        for rule in rules:
            try:
                # 解析IR
                ir_data = json.loads(rule.ir_data)
                # 新格式：IR数据在ir_data['ir']中
                ir = ir_data.get('ir', {})
                parsed = ir_data.get('parsed', {})

                # 判断是否可生成（仅使用新格式）
                can_generate = False
                zlint_lintability = {}

                if 'zlint_lintability' in ir:
                    zlint_lintability = ir['zlint_lintability']
                    can_generate = zlint_lintability.get('can_generate', False)
                elif 'lintable' in parsed:
                    can_generate = parsed.get('lintable', False)
                    zlint_lintability = {'reason': parsed.get('lintable_reason', '')}

                # 应用过滤条件：可生成且未被覆盖
                not_covered = (rule.lint_covered is None or rule.lint_covered == False)

                if not can_generate:
                    results.append({
                        'rule_id': rule.id,
                        'rule_text': rule.text[:100],
                        'success': False,
                        'skipped': True,
                        'reason': '规则无法生成zlint代码',
                        'error': zlint_lintability.get('reason', '未知原因')
                    })
                    skipped_count += 1
                    continue

                if not not_covered:
                    results.append({
                        'rule_id': rule.id,
                        'rule_text': rule.text[:100],
                        'success': False,
                        'skipped': True,
                        'reason': '规则已被zlint覆盖',
                        'covered_by': rule.lint_name
                    })
                    skipped_count += 1
                    continue

                # 生成代码（LLM 路径）
                gen_result = generator.generate(ir)

                # IR 字段来源检查
                gen_result, guard = apply_ir_field_guard(gen_result, ir)

                if not gen_result.success:
                    results.append({
                        'rule_id': rule.id,
                        'rule_text': rule.text[:100],
                        'success': False,
                        'error': gen_result.error,
                        'ir_field_guard': {
                            'ok': guard.ok,
                            'violations': guard.violations,
                        }
                    })
                    failed_count += 1
                    continue

                result_item = {
                    'rule_id': rule.id,
                    'rule_text': rule.text[:100],
                    'success': True,
                    'lint_name': gen_result.lint_name,
                    'package': gen_result.metadata.get('package', 'rfc'),
                    'lint_subclass': gen_result.lint_subclass,
                    'ir_field_guard': {
                        'ok': guard.ok,
                        'violations': guard.violations,
                    }
                }

                # 保存文件到zlint项目
                if request.save_files:
                    try:
                        save_result = zlint_interface.save_generated_code(
                            lint_name=gen_result.lint_name,
                            package_name=gen_result.metadata.get('package', 'rfc'),
                            go_code=gen_result.go_code
                        )

                        if save_result['success']:
                            result_item['files_saved'] = True
                            result_item['file_path'] = save_result['file_path']

                            # 保存测试代码
                            test_file_path = save_result['file_path'].replace('.go', '_test.go')
                            try:
                                with open(test_file_path, 'w') as f:
                                    f.write(gen_result.test_code or '')
                                result_item['test_file_path'] = test_file_path
                            except Exception as e:
                                app_logger.warning(f"Failed to save test code for rule {rule.id}: {e}")
                        else:
                            result_item['files_saved'] = False
                            result_item['save_error'] = save_result['error']
                    except Exception as e:
                        app_logger.error(f"Error saving files for rule {rule.id}: {e}")
                        result_item['files_saved'] = False
                        result_item['save_error'] = str(e)
                else:
                    result_item['files_saved'] = False

                results.append(result_item)
                generated_count += 1

            except json.JSONDecodeError as e:
                app_logger.error(f"Error parsing IR for rule {rule.id}: {e}")
                results.append({
                    'rule_id': rule.id,
                    'rule_text': rule.text[:100],
                    'success': False,
                    'error': 'IR数据格式错误'
                })
                failed_count += 1
            except Exception as e:
                app_logger.error(f"Error generating code for rule {rule.id}: {e}")
                results.append({
                    'rule_id': rule.id,
                    'rule_text': rule.text[:100],
                    'success': False,
                    'error': str(e)
                })
                failed_count += 1

        return {
            'success': True,
            'total_rules': len(rules),
            'generated_count': generated_count,
            'failed_count': failed_count,
            'skipped_count': skipped_count,  # 新增：跳过的规则数量
            'results': results
        }

    except Exception as e:
        app_logger.error(f"Error in batch generate: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/ir-to-code")
async def generate_code_from_ir(
    ir: Dict,
    save_files: bool = True
):
    """
    从IR v2.0生成Go代码（LLM 路径，含 IR 字段来源检查）

    允许用户提供自定义IR，然后生成代码

    Args:
        ir: IR v2.0字典
        save_files: 是否保存文件（当前未实现）

    Returns:
        {
            'success': bool,
            'go_code': str,
            'test_code': str,
            'metadata': dict,
            'lintability': dict,
            'ir_field_guard': dict
        }
    """
    try:
        # 初始化 LLM 生成器（确定性 codegen 已逻辑删除，全走 LLM）
        generator = ZlintCodeGenerator(
            api_key=settings.LLM_API_KEY,
            api_base=settings.LLM_API_BASE,
            model=settings.LLM_MODEL,
        )

        # 生成代码（LLM 路径）
        result = generator.generate(ir)

        # IR 字段来源检查
        result, guard = apply_ir_field_guard(result, ir)

        if not result.success:
            raise HTTPException(status_code=400, detail=result.error)

        response = {
            'success': True,
            'go_code': result.go_code,
            'test_code': result.test_code,
            'metadata': result.metadata,
            'lint_subclass': result.lint_subclass,
            'ir_field_guard': {
                'ok': guard.ok,
                'violations': guard.violations,
                'referenced_fields': sorted(guard.referenced_fields),
                'ir_subject_fields': sorted(guard.ir_subject_fields),
            },
        }

        # TODO: 保存文件功能待实现
        if save_files:
            response['files_saved'] = False
            response['note'] = 'File saving not implemented yet'

        return response

    except HTTPException:
        raise
    except Exception as e:
        app_logger.error(f"Error generating code from IR: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/logic-types")
async def get_logic_types():
    """
    获取所有支持的逻辑类型及其支持级别

    Returns:
        {
            'logic_types': dict
        }
    """
    return {
        'logic_types': {
            'presence': {'support_level': 'native', 'description': '存在性检查'},
            'equality': {'support_level': 'native', 'description': '相等性检查'},
            'range': {'support_level': 'native', 'description': '范围检查'},
            'regex': {'support_level': 'native', 'description': '正则表达式检查'},
            'contains': {'support_level': 'native', 'description': '包含检查'},
            'time_based': {'support_level': 'native', 'description': '时间相关检查'},
            'encoding': {'support_level': 'native', 'description': '编码格式检查'},
            'length': {'support_level': 'native', 'description': '长度检查'},
            'chain': {'support_level': 'unsupported', 'description': '证书链检查（需访问父证书）'},
            'uniqueness': {'support_level': 'unsupported', 'description': '唯一性检查（需跨证书）'},
            'multi_field_consistency': {'support_level': 'partial', 'description': '多字段一致性（复杂度高）'}
        }
    }


@router.get("/lintable-rules")
async def get_lintable_rules(
    limit: int = 100,
    offset: int = 0,
    db: Session = Depends(get_db)
):
    """
    获取可以生成zlint代码的规则

    依赖智能分流的结果。如果规则还没有经过智能分流,应该先运行分流流程。

    过滤条件:
    1. 有IR数据且IR中标记为can_generate=true
    2. 未被zlint覆盖 (lint_covered = false OR lint_covered IS NULL)

    Returns:
        {
            'total': int,
            'limit': int,
            'offset': int,
            'rules': List[dict]
        }
    """
    try:
        app_logger.info(f"[lintable-rules] Query with limit={limit}, offset={offset}")

        # 使用JSONB查询过滤can_generate=true的规则
        # 注意: ir_data是TEXT类型,需要转换为JSONB
        from sqlalchemy import cast, Boolean, and_, or_
        from sqlalchemy.dialects.postgresql import JSONB

        # 注意：ir_data的结构是 { "ir": { "zlint_lintability": { "can_generate": true } } }
        # 需要使用正确的JSON路径：ir_data['ir']['zlint_lintability']['can_generate']
        query = db.query(Rule).filter(
            and_(
                Rule.ir_data.isnot(None),
                or_(Rule.lint_covered == False, Rule.lint_covered.is_(None)),
                cast(
                    cast(Rule.ir_data, JSONB)['ir']['zlint_lintability']['can_generate'].astext,
                    Boolean
                ) == True
            )
        )

        # 获取规则
        rules = query.offset(offset).limit(limit).all()

        app_logger.info(f"[lintable-rules] Found {len(rules)} rules")

        # 获取Standards（批量）
        standard_ids = list(set(r.standard_id for r in rules if r.standard_id))
        standards_dict = {}
        if standard_ids:
            standards = db.query(Standard).filter(Standard.id.in_(standard_ids)).all()
            standards_dict = {s.id: s for s in standards}

        # 构建返回数据
        result_rules = []

        for rule in rules:
            standard = standards_dict.get(rule.standard_id)
            result_rules.append({
                'id': rule.id,
                'text': rule.text[:200] if rule.text else '',
                'section': rule.section or '',
                'source': standard.source if standard else 'Unknown',
                'affected_field': rule.subject or '',
                'operation': rule.predicate or '',
                'can_generate': True,
                'lint_covered': rule.lint_covered or False,
                'lint_name': rule.lint_name or '',
            })

        # 检查是否有未经智能分流的规则
        # 判断标准: 有ir_data但是ir中没有zlint_lintability字段
        has_unsorted_rules = False
        unsorted_count = 0

        try:
            # 查询所有有IR但可能未分流的规则样本
            sample_rules = db.query(Rule).filter(Rule.ir_data.isnot(None)).limit(100).all()

            for rule in sample_rules:
                try:
                    ir_data = json.loads(rule.ir_data)
                    # 新格式：检查ir_data['ir']中的lintability
                    ir = ir_data.get('ir', {})
                    if ir and 'zlint_lintability' not in ir:
                        has_unsorted_rules = True
                        unsorted_count += 1
                except:
                    pass

        except Exception as e:
            app_logger.warning(f"Failed to check for unsorted rules: {e}")

        app_logger.info(f"[lintable-rules] Returning {len(result_rules)} rules (unsorted sample: {unsorted_count}/100)")

        return {
            'total': len(result_rules),
            'limit': limit,
            'offset': offset,
            'rules': result_rules,
            'has_unsorted_rules': has_unsorted_rules  # 告诉前端是否需要提醒用户做分流
        }

    except Exception as e:
        app_logger.error(f"Error in lintable-rules: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/statistics")
async def get_codegen_statistics(db: Session = Depends(get_db)):
    """
    获取zlint覆盖统计信息（从metadata读取真实覆盖数据）

    Returns:
        {
            'total_rules': int,
            'covered_rules': int,  # 已被zlint覆盖的规则数
            'uncovered_rules': int,
            'coverage_rate': float,
            'rules_with_ir': int,
            'rules_with_ir_v2': int,
            'supported_logic_types': list
        }
    """
    try:
        import json

        # 从metadata获取真实的zlint覆盖统计
        standards = db.query(Standard).filter(Standard.is_latest == True).all()

        total_rules = 0
        covered_rules = 0

        for standard in standards:
            if not standard.metadata_json:
                continue

            try:
                metadata = json.loads(standard.metadata_json)
                last_extraction = metadata.get('last_extraction', {})
                zlint_coverage = last_extraction.get('zlint_coverage', {})

                if zlint_coverage.get('executed'):
                    total_rules += zlint_coverage.get('total_rules', 0)
                    covered_rules += zlint_coverage.get('covered_count', 0)
            except (json.JSONDecodeError, KeyError) as e:
                app_logger.debug(f"Failed to parse metadata for standard {standard.id}: {e}")
                continue

        # 如果metadata中没有数据，回退到数据库规则总数
        if total_rules == 0:
            total_rules = db.query(Rule).count()

        coverage_rate = (covered_rules / total_rules * 100) if total_rules > 0 else 0
        uncovered_rules = total_rules - covered_rules

        # 统计有IR数据的规则
        rules_with_ir = db.query(Rule).filter(Rule.ir_data.isnot(None)).count()

        # 统计可生成且未被覆盖的规则（使用JSONB查询）
        from sqlalchemy import cast, Boolean, and_, or_
        from sqlalchemy.dialects.postgresql import JSONB

        # 注意：使用正确的JSON路径 ir_data['ir']['lintable']
        lintable_uncovered_rules = db.query(Rule).filter(
            and_(
                Rule.ir_data.isnot(None),
                or_(Rule.lint_covered == False, Rule.lint_covered.is_(None)),
                cast(
                    cast(Rule.ir_data, JSONB)['ir']['lintable'].astext,
                    Boolean
                ) == True
            )
        ).count()

        return {
            'total_rules': total_rules,
            'covered_rules': covered_rules,
            'uncovered_rules': uncovered_rules,
            'coverage_rate': round(coverage_rate, 2),
            'rules_with_ir': rules_with_ir,
            'lintable_rules': lintable_uncovered_rules,  # 可生成且未覆盖的规则数
            'supported_logic_types': [
                'presence', 'equality', 'range', 'regex',
                'contains', 'time_based', 'encoding', 'length'
            ],
            'generator_info': {
                'version': '3.0',
                'features': [
                    '语义分离（assertion_subject + applicability_scope）',
                    '结构化target_path映射',
                    '6步严格lintability判断',
                    'native支持的逻辑类型自动生成',
                    '批量生成支持'
                ]
            }
        }

    except Exception as e:
        app_logger.error(f"Error getting statistics: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/compile-zlint")
async def compile_zlint():
    """
    编译zlint项目

    Returns:
        {
            'success': bool,
            'stdout': str,
            'stderr': str,
            'returncode': int,
            'error': str (if failed)
        }
    """
    try:
        zlint_interface = ZLintInterface()
        compile_result = zlint_interface._compile_zlint()

        return {
            'success': compile_result['success'],
            'stdout': compile_result.get('stdout', ''),
            'stderr': compile_result.get('stderr', ''),
            'returncode': compile_result.get('returncode', -1),
            'error': None if compile_result['success'] else compile_result.get('stderr', 'Compilation failed')
        }

    except Exception as e:
        app_logger.error(f"Error compiling zlint: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=str(e))


class TransactionalBatchGenerateRequest(BaseModel):
    """事务性批量生成请求"""
    rule_ids: List[int]
    save_files: bool = True


class ApproveAndSaveRequest(BaseModel):
    """人工审核通过后保存代码的请求"""
    rule_id: int
    lint_name: str
    package: str
    go_code: str
    test_code: str


@router.post("/transactional-batch-generate")
async def transactional_batch_generate(
    request: TransactionalBatchGenerateRequest,
    db: Session = Depends(get_db)
):
    """
    事务性批量生成zlint代码

    特点：
    1. 一条失败，全部失败（all-or-nothing）
    2. 返回每条规则的完整生成代码（Go + Test）供前端预览
    3. 只有全部成功才保存文件

    用于前端"翻书"界面，让用户逐一检查生成的代码

    Returns:
        {
            'success': bool,
            'total': int,
            'results': List[{
                'rule_id': int,
                'rule_info': {
                    'id': int,
                    'text': str,
                    'title': str,
                    'section': str,
                    'affected_field': str,
                    'target_field': str,
                    'logic_type': str
                },
                'go_code': str,
                'test_code': str,
                'metadata': {
                    'lint_name': str,
                    'package': str,
                    'logic_type': str
                },
                'file_path': str (if saved),
                'test_file_path': str (if saved)
            }],
            'error': str (if failed)
        }
    """
    import os
    import tempfile

    try:
        app_logger.info(f"[transactional-batch-generate] Processing {len(request.rule_ids)} rules")

        # 获取所有规则
        rules = db.query(Rule).filter(Rule.id.in_(request.rule_ids)).all()

        if len(rules) != len(request.rule_ids):
            found_ids = {r.id for r in rules}
            missing_ids = set(request.rule_ids) - found_ids
            raise HTTPException(
                status_code=404,
                detail=f"Rules not found: {missing_ids}"
            )

        # 按照用户提供的顺序排序
        rules_dict = {r.id: r for r in rules}
        ordered_rules = [rules_dict[rid] for rid in request.rule_ids]

        # 全量 LLM 路径 + IR 字段守卫检查
        generator = ZlintCodeGenerator(
            api_key=settings.llm_api_key,
            api_base=settings.llm_api_base,
            model=settings.llm_model,
        )
        zlint_interface = ZLintInterface()

        # 第一阶段：生成所有代码（不保存）
        results = []
        temp_files = []  # 用于回滚

        for rule in ordered_rules:
            try:
                app_logger.info(f"Generating code for rule {rule.id}")

                # 检查IR数据
                if not rule.ir_data:
                    raise HTTPException(
                        status_code=400,
                        detail=f"Rule {rule.id} missing IR data"
                    )

                # 解析IR
                try:
                    ir_data = json.loads(rule.ir_data)
                    # 新格式：IR数据在ir_data['ir']中
                    ir = ir_data.get('ir', {})
                    if not ir:
                        raise ValueError("Missing 'ir' field in IR data")
                except json.JSONDecodeError:
                    raise HTTPException(
                        status_code=400,
                        detail=f"Rule {rule.id} has invalid IR data"
                    )

                # 检查是否可生成
                # 真实字段为 ir['lintable']；兼容旧版 ir['zlint_lintability']['can_generate']
                can_generate = False
                reason = ''
                if 'zlint_lintability' in ir:
                    can_generate = ir['zlint_lintability'].get('can_generate', False)
                    reason = ir['zlint_lintability'].get('reason', '')
                else:
                    can_generate = bool(ir.get('lintable', False))
                    reason = ir.get('non_lintable_reason') or 'Rule is not lintable'

                if not can_generate:
                    raise HTTPException(
                        status_code=400,
                        detail=f"Rule {rule.id} cannot generate zlint code: {reason}"
                    )

                # 缺失 lint_subclass 时从 predicate 确定性派生（生成器选模板所需）
                _ensure_lint_subclass(ir)

                # 生成代码（LLM 路径）
                gen_result = generator.generate(ir)

                # 应用 IR 字段守卫检查
                guarded_result, guard = apply_ir_field_guard(gen_result, ir)

                # 构建兼容旧接口的 dict 格式
                if guarded_result.success:
                    go_code = guarded_result.go_code or ""
                    test_code = guarded_result.test_code or ""
                    metadata = dict(guarded_result.metadata or {})
                    metadata['lint_name'] = guarded_result.lint_name or ""
                    metadata['package'] = guarded_result.lint_name or ""
                    metadata['generation_method'] = 'zlint_generator'
                    generation_method = 'zlint_generator'
                else:
                    go_code = ""
                    test_code = ""
                    metadata = {}
                    generation_method = 'zlint_generator'

                if not go_code:
                    raise HTTPException(
                        status_code=400,
                        detail=f"Rule {rule.id} code generation failed: {guarded_result.error or 'no code produced'}"
                    )

                # 获取标准信息
                standard = None
                if rule.standard_id:
                    standard = db.query(Standard).filter(Standard.id == rule.standard_id).first()

                # 判断是否需要人工审核
                # 全量 LLM 路径全部需要人工审核（IR 字段守卫会降级严重违规）
                requires_review = True

                # 构建结果
                result_item = {
                    'rule_id': rule.id,
                    'rule_info': {
                        'id': rule.id,
                        'text': rule.text or '',
                        'title': rule.title or '',
                        'section': rule.section or '',
                        'source': standard.source if standard else 'Unknown',
                        'affected_field': rule.subject or '',
                        # 优先使用target_field，如果不存在则回退到subject字段
                        'target_field': ir.get('target_field') or (ir.get('subject', {}).get('path', '') if isinstance(ir.get('subject'), dict) else ir.get('subject', '')),
                        'logic_type': ir.get('logic', {}).get('type', 'unknown'),
                        # 添加验证需要的示例值
                        'invalid_value': ir.get('operation', {}).get('invalid_example', ''),
                        'valid_value': ir.get('operation', {}).get('valid_example', ''),
                        # 添加description用于证书类型推断
                        'description': ir.get('description', '') or ir.get('rule_text', '') or rule.text or rule.title or ''
                    },
                    'go_code': go_code,
                    'test_code': test_code,
                    'metadata': metadata,
                    'requires_review': requires_review,  # 是否需要人工审核
                    'generation_method': generation_method  # 生成方式
                }

                results.append(result_item)

            except HTTPException:
                raise
            except Exception as e:
                app_logger.error(f"Error generating code for rule {rule.id}: {e}", exc_info=True)
                raise HTTPException(
                    status_code=500,
                    detail=f"Rule {rule.id} generation error: {str(e)}"
                )

        # 第二阶段：如果全部成功且需要保存，保存所有文件
        # 只自动保存不需要人工审核的代码（specialized_generator生成的）
        if request.save_files:
            try:
                # 分离需要审核和不需要审核的结果
                auto_save_results = [r for r in results if not r.get('requires_review', False)]
                review_results = [r for r in results if r.get('requires_review', False)]

                if auto_save_results:
                    app_logger.info(f"Auto-saving {len(auto_save_results)} specialized-generated rules...")

                    for result_item in auto_save_results:
                        # 保存Go代码
                        save_result = zlint_interface.save_generated_code(
                            lint_name=result_item['metadata']['lint_name'],
                            package_name=result_item['metadata']['package'],
                            go_code=result_item['go_code']
                        )

                        if not save_result['success']:
                            raise Exception(f"Failed to save Go code: {save_result['error']}")

                        result_item['file_path'] = save_result['file_path']
                        result_item['saved'] = True
                        temp_files.append(save_result['file_path'])

                        # 保存测试代码
                        test_file_path = save_result['file_path'].replace('.go', '_test.go')
                        with open(test_file_path, 'w', encoding='utf-8') as f:
                            f.write(result_item['test_code'])

                        result_item['test_file_path'] = test_file_path
                        temp_files.append(test_file_path)

                        app_logger.info(f"Auto-saved: {save_result['file_path']}")

                    app_logger.info(f"Successfully auto-saved {len(auto_save_results)} rule files")

                # 标记需要审核的结果为未保存
                for result_item in review_results:
                    result_item['saved'] = False
                    result_item['file_path'] = None
                    result_item['test_file_path'] = None

                if review_results:
                    app_logger.info(f"{len(review_results)} rules require human review before saving")

            except Exception as e:
                app_logger.error(f"Error saving files: {e}", exc_info=True)

                # 回滚：删除已保存的文件
                app_logger.warning("Rolling back: deleting saved files...")
                for file_path in temp_files:
                    try:
                        if os.path.exists(file_path):
                            os.remove(file_path)
                            app_logger.info(f"Deleted: {file_path}")
                    except Exception as del_err:
                        app_logger.error(f"Failed to delete {file_path}: {del_err}")

                raise HTTPException(
                    status_code=500,
                    detail=f"File save failed, rolled back: {str(e)}"
                )

        return {
            'success': True,
            'total': len(results),
            'results': results,
            'error': None
        }

    except HTTPException:
        raise
    except Exception as e:
        app_logger.error(f"Error in transactional batch generate: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/approve-and-save")
async def approve_and_save_code(
    request: ApproveAndSaveRequest,
    db: Session = Depends(get_db)
):
    """
    人工审核通过后保存LLM生成的代码

    当代码使用LLM生成时（requires_review=true），用户审核通过后调用此接口保存代码。

    Returns:
        {
            'success': bool,
            'file_path': str,
            'test_file_path': str,
            'error': str (if failed)
        }
    """
    try:
        app_logger.info(f"[approve-and-save] Saving approved code for rule {request.rule_id}, lint: {request.lint_name}")

        zlint_interface = ZLintInterface()

        # 保存Go代码
        save_result = zlint_interface.save_generated_code(
            lint_name=request.lint_name,
            package_name=request.package,
            go_code=request.go_code
        )

        if not save_result['success']:
            raise HTTPException(
                status_code=500,
                detail=f"Failed to save Go code: {save_result['error']}"
            )

        file_path = save_result['file_path']

        # 保存测试代码
        test_file_path = file_path.replace('.go', '_test.go')
        with open(test_file_path, 'w', encoding='utf-8') as f:
            f.write(request.test_code)

        app_logger.info(f"[approve-and-save] Successfully saved: {file_path}")

        return {
            'success': True,
            'file_path': file_path,
            'test_file_path': test_file_path,
            'error': None
        }

    except HTTPException:
        raise
    except Exception as e:
        app_logger.error(f"Error in approve-and-save: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/get-all-irs")
async def get_all_rules_irs(
    filters: Optional[Dict] = None,
    db: Session = Depends(get_db)
):
    """
    获取所有带IR数据的规则（用于IR展示页面）

    支持筛选条件:
    - keyword: 搜索关键词（支持同义词扩展）
    - standard_id: 标准ID
    - rule_type: 规则类型 (MUST, SHOULD, etc.)
    - severity: 严重程度
    - rule_category: 规则分类
    - ir_rule_type: IR类型 (presence, equality, range, etc.)
    - applies_to: 适用范围 (CA, Subscriber, Root, All)

    Returns:
        {
            'success': bool,
            'rules_with_ir': List[dict],  # 带IR的规则列表
            'summary': {
                'total_rules': int,
                'filtered_count': int,
                'ir_rule_types': Dict[str, int]  # IR类型分布
            },
            'filtered': int  # 筛选结果数量
        }
    """
    try:
        from sqlalchemy import or_, and_

        app_logger.info(f"[get-all-irs] Query with filters: {filters}")

        if filters is None:
            filters = {}

        # 构建查询：只查询有IR数据的规则
        query = db.query(Rule).filter(Rule.ir_data.isnot(None))

        # 添加关键词搜索（使用与规则浏览相同的搜索逻辑）
        if 'keyword' in filters and filters['keyword']:
            keyword = filters['keyword']

            # 导入同义词扩展功能
            from app.services.extraction.synonym_mapper import expand_query_with_synonyms
            import re

            # 扩展查询（如果是已知别名，会自动添加规范术语）
            expanded_q = expand_query_with_synonyms(keyword)

            # 记录同义词扩展情况
            if expanded_q != keyword:
                app_logger.info(f"Query expanded: '{keyword}' → '{expanded_q}'")
            else:
                app_logger.info(f"Searching for: '{keyword}' (no expansion)")

            # 使用 || 分割同义词短语（保持短语完整性）
            search_terms = expanded_q.split('||')
            app_logger.info(f"Search terms: {search_terms}")

            # 构建搜索过滤器
            all_filters = []

            for term in search_terms:
                # 为每个同义词构建OR条件
                term_filters = []

                # === 优先级1: 文本字段匹配 ===
                term_filters.extend([
                    Rule.text.op('~*')(re.escape(term)),
                    Rule.subject.op('~*')(re.escape(term)),
                    Rule.title.op('~*')(re.escape(term)),
                    Rule.context.op('~*')(re.escape(term))
                ])

                # === 优先级2: IR subject字段匹配（结构化字段路径）===
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
            # 多个同义词之间是OR关系
            keyword_filter = or_(*all_filters)
            query = query.filter(keyword_filter)

        # 应用筛选条件
        if 'standard_id' in filters and filters['standard_id']:
            query = query.filter(Rule.standard_id == filters['standard_id'])

        if 'rule_type' in filters and filters['rule_type']:
            query = query.filter(Rule.rule_type == filters['rule_type'])

        if 'severity' in filters and filters['severity']:
            query = query.filter(Rule.severity == filters['severity'])

        if 'rule_category' in filters and filters['rule_category']:
            from sqlalchemy import cast
            from sqlalchemy.dialects.postgresql import JSONB
            query = query.filter(
                cast(Rule.ir_data, JSONB)['parsed']['rule_type'].astext == filters['rule_category']
            )

        # 执行查询
        rules = query.all()

        app_logger.info(f"[get-all-irs] Found {len(rules)} rules with IR data")

        # 解析IR数据并构建返回结构
        rules_with_ir = []
        ir_type_distribution = {}

        for rule in rules:
            try:
                ir_data = json.loads(rule.ir_data) if rule.ir_data else {}

                # 直接提取新格式的 parsed、ir、clauses 部分
                # 如果数据不是新格式，将被忽略（用户会重新提取规则）
                parsed = ir_data.get('parsed', {})
                ir_section = ir_data.get('ir', {})
                clauses = ir_data.get('clauses', [])

                # 获取IR规则类型
                ir_rule_type = parsed.get('rule_type', 'unknown')

                # 统计IR类型分布
                ir_type_distribution[ir_rule_type] = ir_type_distribution.get(ir_rule_type, 0) + 1

                # 应用ir_rule_type筛选
                if 'ir_rule_type' in filters and filters['ir_rule_type']:
                    if ir_rule_type != filters['ir_rule_type']:
                        continue

                # 应用applies_to筛选
                if 'applies_to' in filters and filters['applies_to']:
                    applies_to = ir_section.get('applies_to', '')
                    if applies_to != filters['applies_to']:
                        continue

                # 构建返回数据
                rule_data = {
                    'rule_id': rule.id,
                    'standard_id': rule.standard_id,
                    'section': rule.section or '',
                    'title': rule.title or '',
                    'text': rule.text,
                    'rule_type': rule.rule_type,
                    'severity': rule.severity,
                    'rule_category': ir_rule_type,
                    'parsed': parsed,
                    'ir': ir_section,
                    'clauses': clauses
                }

                rules_with_ir.append(rule_data)

            except Exception as e:
                app_logger.warning(f"Failed to parse IR data for rule {rule.id}: {e}")
                continue

        # 构建摘要信息
        summary = {
            'total_rules': db.query(Rule).filter(Rule.ir_data.isnot(None)).count(),
            'filtered_count': len(rules_with_ir),
            'ir_rule_types': ir_type_distribution
        }

        app_logger.info(
            f"[get-all-irs] Returning {len(rules_with_ir)} rules "
            f"(IR types: {list(ir_type_distribution.keys())})"
        )

        return {
            'success': True,
            'rules_with_ir': rules_with_ir,
            'summary': summary,
            'filtered': len(rules_with_ir)
        }

    except Exception as e:
        app_logger.error(f"Error in get-all-irs: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=str(e))


# ============================================================
# 同义测量端点 (Synonymy Measurement)
# ============================================================
# 后端实现 canonical 同义测量：调用 judge_vote 5票多数
# 路径: cicas_backend/app/services/certificate/codegen/synonym_judge.py


class MeasureSynonymyRequest(BaseModel):
    """同义测量请求"""
    rule_id: int
    code_summary: str           # sigma_mech 渲染的代码摘要
    rule_text: str             # 原始规则文本


class MeasureSynonymyBatchRequest(BaseModel):
    """批量同义测量请求"""
    items: List[Dict[str, Any]]  # [{"rule_id": int, "code_summary": str, "rule_text": str}, ...]
    vote_n: int = 5            # 投票数，默认5票


@router.post("/measure-synonymy")
async def measure_synonymy(
    request: MeasureSynonymyRequest,
    db: Session = Depends(get_db)
):
    """
    测量单条规则的同义性（code_summary vs rule_text）。

    使用 judge_vote 5票多数裁定。返回各票结果和最终裁定。

    Returns:
        {
            'rule_id': int,
            'votes': List[dict],  # 每票结果
            'final_verdict': str,  # 'EXPRESSES' | 'NOT_EXPRESSES' | 'PARTIAL'
            'confidence': float,    # 多数置信度
        }
    """
    from app.services.certificate.codegen.binary_judge import judge_expresses

    votes = []
    for i in range(5):
        result = judge_expresses(
            request.rule_text,
            request.code_summary,
        )
        votes.append(result)
        if i < 4:
            import time
            time.sleep(0.1)

    # 多数裁定
    expresses_count = sum(1 for v in votes if v.get('verdict') == 'EXPRESSES')
    not_count = sum(1 for v in votes if v.get('verdict') == 'DOES_NOT_EXPRESS')
    partial_count = sum(1 for v in votes if v.get('verdict') == 'PARTIAL')

    if expresses_count >= 3:
        final = 'EXPRESSES'
    elif not_count >= 3:
        final = 'NOT_EXPRESSES'
    elif expresses_count + partial_count > not_count:
        final = 'PARTIAL'
    else:
        final = 'NOT_EXPRESSES'

    return {
        'rule_id': request.rule_id,
        'votes': votes,
        'final_verdict': final,
        'confidence': expresses_count / 5.0,
    }


@router.post("/measure-synonymy-batch")
async def measure_synonymy_batch(
    request: MeasureSynonymyBatchRequest,
):
    """
    批量测量同义性。

    对每条规则调用 judge_vote N票（默认5票）多数裁定。

    Returns:
        {
            'total': int,
            'results': List[dict],  # 每条的结果
            'summary': {
                'expresses': int,
                'not_expresses': int,
                'partial': int,
            }
        }
    """
    from app.services.certificate.codegen.binary_judge import judge_expresses

    n = request.vote_n
    results = []

    for item in request.items:
        rule_id = item.get('rule_id')
        code_summary = item.get('code_summary', '')
        rule_text = item.get('rule_text', '')

        votes = []
        for i in range(n):
            try:
                result = judge_expresses(rule_text, code_summary)
                votes.append(result)
            except Exception as e:
                votes.append({'verdict': 'ERROR', 'error': str(e)})
            if i < n - 1:
                import time
                time.sleep(0.1)

        expresses_count = sum(1 for v in votes if v.get('verdict') == 'EXPRESSES')
        not_count = sum(1 for v in votes if v.get('verdict') == 'DOES_NOT_EXPRESS')

        if expresses_count >= (n + 1) // 2:
            final = 'EXPRESSES'
        elif not_count >= (n + 1) // 2:
            final = 'NOT_EXPRESSES'
        else:
            final = 'PARTIAL'

        results.append({
            'rule_id': rule_id,
            'votes': votes,
            'final_verdict': final,
            'confidence': expresses_count / n,
        })

    expresses_total = sum(1 for r in results if r['final_verdict'] == 'EXPRESSES')
    not_total = sum(1 for r in results if r['final_verdict'] == 'NOT_EXPRESSES')
    partial_total = sum(1 for r in results if r['final_verdict'] == 'PARTIAL')

    return {
        'total': len(results),
        'results': results,
        'summary': {
            'expresses': expresses_total,
            'not_expresses': not_total,
            'partial': partial_total,
        }
    }
