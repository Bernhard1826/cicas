"""
受控 IR 提取 API 路由

提供基于新架构的规则提取功能：
- LLM 仅作为受控的结构化提取器
- 所有规范知识通过常驻知识层提供
- 不允许 LLM 做判断、推理或裁决
"""
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from typing import Optional, List
from pydantic import BaseModel, Field
from datetime import datetime

from app.core.database import get_db
from app.core.logging_config import app_logger

# 新架构导入
from app.services.extraction.controlled_llm_extractor import (
    ControlledLLMExtractor,
    extract_ir,
)
from app.services.extraction.ir_schema import (
    SpecFamily,
)
from app.services.extraction.output_validator import validate_llm_output
from app.services.extraction.sentence_preprocessor import (
    SentencePreprocessor,
    needs_split,
)
from app.services.spec_context.context_manager import (
    SpecificationContextManager,
    detect_spec_family,
    get_applicable_scope,
)
from app.services.knowledge_layer.knowledge_initializer import (
    get_knowledge_graph,
    get_knowledge_initializer,
)

router = APIRouter(
    prefix="/api/v1/structured-ir",
    tags=["Structured IR Extraction"]
)


# ==================== Request/Response Models ====================

class IRExtractionRequest(BaseModel):
    """IR 提取请求"""
    text: str = Field(..., description="规范文本（单个句子或段落）")
    context: Optional[str] = Field(None, description="额外的规范上下文（可选）")
    spec_id: Optional[str] = Field(None, description="规范 ID，如 'RFC5280'（可选，系统会自动检测）")
    section_id: Optional[str] = Field(None, description="章节 ID（可选）")
    auto_split: bool = Field(True, description="是否自动拆分多规则句子")


class IRExtractionResponse(BaseModel):
    """IR 提取响应"""
    success: bool
    results: List[dict]
    spec_family: str
    extraction_count: int
    needs_split: bool
    message: str
    timestamp: str


class BatchIRExtractionRequest(BaseModel):
    """批量 IR 提取请求"""
    texts: List[str] = Field(..., description="规范文本列表")
    spec_id: Optional[str] = Field(None, description="规范 ID")
    auto_split: bool = Field(True, description="是否自动拆分多规则句子")


class BatchIRExtractionResponse(BaseModel):
    """批量 IR 提取响应"""
    success: bool
    total_input: int
    total_extracted: int
    results: List[dict]
    timestamp: str


class SpecDetectionRequest(BaseModel):
    """规范检测请求"""
    text: str = Field(..., description="待检测的文本")


class SpecDetectionResponse(BaseModel):
    """规范检测响应"""
    spec_family: str
    scope: str
    spec_id: Optional[str]
    confidence: str


class SentenceAnalysisRequest(BaseModel):
    """句子分析请求"""
    text: str = Field(..., description="待分析的句子")


class SentenceAnalysisResponse(BaseModel):
    """句子分析响应"""
    needs_split: bool
    split_reason: Optional[str]
    atomic_sentences: List[str]
    original_text: str


# ==================== API Endpoints ====================

@router.post("/extract", response_model=IRExtractionResponse)
async def extract_structured_ir(
    request: IRExtractionRequest,
    db: Session = Depends(get_db)
):
    """
    提取结构化 IR（中间表示）

    这是主要的提取入口。系统内部自动：
    1. 检测规范体系（RFC/CABF/ETSI）
    2. 检索最小上下文
    3. 使用受控 LLM 提取
    4. 验证输出

    HARD CONSTRAINTS:
    - LLM 不做规范判断
    - LLM 不解决冲突
    - LLM 不推断隐含要求
    """
    try:
        # 1. 检测规范体系
        spec_family = detect_spec_family(request.text)

        # 2. 构建 provenance
        provenance = {
            "source_id": request.spec_id or "unknown",
            "section": request.section_id,
        }

        # 3. 调用受控提取器（注入知识图谱）
        kg = get_knowledge_graph()
        results = extract_ir(
            text=request.text,
            context=request.context,
            provenance=provenance,
            knowledge_graph=kg,
        )

        # 4. 转换结果为字典
        result_dicts = []
        for result in results:
            ir = result.ir
            result_dicts.append({
                "subject": str(ir.subject) if ir.subject else None,
                "obligation": ir.obligation if isinstance(ir.obligation, str) else ir.obligation.value,
                "predicate": ir.predicate if isinstance(ir.predicate, str) else ir.predicate.value,
                "constraint": ir.constraint.model_dump() if ir.constraint else {},
                "references": [ref.model_dump() for ref in ir.references],
                "spec_family": ir.spec_family if isinstance(ir.spec_family, str) else ir.spec_family.value,
                "extraction_confidence": ir.extraction_confidence if isinstance(ir.extraction_confidence, str) else ir.extraction_confidence.value,
                "needs_split": ir.needs_split,
                "rule_text": ir.rule_text,
            })

        # 5. 检查是否需要拆分
        check_needs_split = needs_split(request.text)

        return IRExtractionResponse(
            success=True,
            results=result_dicts,
            spec_family=spec_family.value,
            extraction_count=len(result_dicts),
            needs_split=check_needs_split,
            message=f"成功提取 {len(result_dicts)} 条规则",
            timestamp=datetime.now().isoformat(),
        )

    except Exception as e:
        app_logger.error(f"IR 提取失败: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/extract/batch", response_model=BatchIRExtractionResponse)
async def extract_batch_ir(
    request: BatchIRExtractionRequest,
    db: Session = Depends(get_db)
):
    """
    批量提取 IR

    对多个文本批量执行 IR 提取。
    """
    try:
        all_results = []
        kg = get_knowledge_graph()

        for text in request.texts:
            provenance = {"source_id": request.spec_id or "unknown"}

            results = extract_ir(
                text=text,
                provenance=provenance,
                knowledge_graph=kg,
            )

            for result in results:
                ir = result.ir
                all_results.append({
                    "original_text": text,
                    "subject": str(ir.subject) if ir.subject else None,
                    "obligation": ir.obligation if isinstance(ir.obligation, str) else ir.obligation.value,
                    "predicate": ir.predicate if isinstance(ir.predicate, str) else ir.predicate.value,
                    "spec_family": ir.spec_family if isinstance(ir.spec_family, str) else ir.spec_family.value,
                    "extraction_confidence": ir.extraction_confidence if isinstance(ir.extraction_confidence, str) else ir.extraction_confidence.value,
                })

        return BatchIRExtractionResponse(
            success=True,
            total_input=len(request.texts),
            total_extracted=len(all_results),
            results=all_results,
            timestamp=datetime.now().isoformat(),
        )

    except Exception as e:
        app_logger.error(f"批量 IR 提取失败: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/detect-spec", response_model=SpecDetectionResponse)
async def detect_specification(request: SpecDetectionRequest):
    """
    检测规范体系

    自动识别文本所属的规范体系（RFC/CABF/ETSI 等）和适用范围。
    """
    try:
        manager = SpecificationContextManager()

        spec_family = manager.detect_spec_family(request.text)
        scope = manager.get_applicable_scope(request.text)
        spec_id = manager.extract_spec_id(request.text)

        return SpecDetectionResponse(
            spec_family=spec_family.value,
            scope=scope.value,
            spec_id=spec_id,
            confidence="high" if spec_id else "medium",
        )

    except Exception as e:
        app_logger.error(f"规范检测失败: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/analyze-sentence", response_model=SentenceAnalysisResponse)
async def analyze_sentence(request: SentenceAnalysisRequest):
    """
    分析句子结构

    检测句子是否包含多个独立规则，如果需要则进行拆分。
    """
    try:
        preprocessor = SentencePreprocessor()
        result = preprocessor.preprocess(request.text)

        atomic_texts = [s.text for s in result.sentences]

        return SentenceAnalysisResponse(
            needs_split=result.needs_split,
            split_reason=result.split_reason.value if result.split_reason else None,
            atomic_sentences=atomic_texts,
            original_text=request.text,
        )

    except Exception as e:
        app_logger.error(f"句子分析失败: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/health")
async def health_check():
    """健康检查"""
    return {
        "status": "healthy",
        "service": "structured-ir-extraction",
        "version": "1.0.0",
        "constraints": [
            "LLM does NOT make normative judgments",
            "LLM does NOT resolve conflicts",
            "LLM does NOT infer implicit requirements",
        ],
        "timestamp": datetime.now().isoformat(),
    }


@router.get("/knowledge-status")
async def knowledge_status():
    """
    查看知识层状态

    返回已加载的文档、索引统计、KG 节点数等信息。
    """
    initializer = get_knowledge_initializer()
    if not initializer:
        return {
            "initialized": False,
            "message": "Knowledge layer not initialized",
        }

    return initializer.get_status()
