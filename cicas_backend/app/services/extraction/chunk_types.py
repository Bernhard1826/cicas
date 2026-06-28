"""
结构化 Chunk 类型定义
定义文档分块的类型系统，用于指导提取器选择
"""
import re
from enum import Enum
from typing import Optional, List, Dict, Any
from pydantic import BaseModel, Field


class ChunkType(str, Enum):
    """Chunk 类型枚举"""
    SECTION_CHUNK = "section"           # 章节标题和概述
    DEFINITION_CHUNK = "definition"     # 定义（含 ABNF 或格式定义）
    REQUIREMENT_CHUNK = "requirement"   # 需求（含 MUST/MUST NOT/SHALL）
    LIST_CHUNK = "list"                 # 列表（bullet list、编号列表）
    TABLE_CHUNK = "table"               # 表格
    NON_NORMATIVE_CHUNK = "non_normative"  # 非规范内容（example/illustration/test）
    UNKNOWN_CHUNK = "unknown"           # 未分类


class ExtractorType(str, Enum):
    """提取器类型"""
    REGEX = "regex"         # 正则提取器
    TEMPLATE = "template"   # 模板提取器
    LLM = "llm"            # LLM 提取器
    NONE = "none"          # 不提取


# Chunk类型到提取器的映射规则
CHUNK_EXTRACTOR_MAPPING = {
    ChunkType.SECTION_CHUNK: ExtractorType.NONE,         # 章节不提取
    ChunkType.DEFINITION_CHUNK: ExtractorType.TEMPLATE,  # 定义用模板
    ChunkType.REQUIREMENT_CHUNK: ExtractorType.REGEX,    # 需求优先正则
    ChunkType.LIST_CHUNK: ExtractorType.REGEX,           # 列表用正则（修复：原为TEMPLATE，但REGEX效果更好）
    ChunkType.TABLE_CHUNK: ExtractorType.TEMPLATE,       # 表格用模板
    ChunkType.NON_NORMATIVE_CHUNK: ExtractorType.NONE,   # 非规范不提取（关键！）
    ChunkType.UNKNOWN_CHUNK: ExtractorType.LLM,          # 未知用LLM
}


class StructuredChunk(BaseModel):
    """结构化的文档块"""
    chunk_id: str = Field(..., description="Chunk 唯一标识")
    chunk_type: ChunkType = Field(..., description="Chunk 类型")
    text: str = Field(..., description="Chunk 文本内容")

    # 元数据
    line_start: int = Field(..., description="起始行号")
    line_end: int = Field(..., description="结束行号")
    section: Optional[str] = Field(None, description="所属章节")
    title: Optional[str] = Field(None, description="章节标题")
    subsection: Optional[str] = Field(None, description="所属子章节")

    # 上下文
    context_before: Optional[str] = Field(None, description="前文上下文")
    context_after: Optional[str] = Field(None, description="后文上下文")

    # 提取控制
    extractor_type: ExtractorType = Field(..., description="推荐的提取器类型")
    should_extract: bool = Field(True, description="是否应该提取规则")

    # 标记信息
    is_normative: bool = Field(True, description="是否为规范性内容")
    contains_requirement: bool = Field(False, description="是否包含需求关键词")
    contains_definition: bool = Field(False, description="是否包含定义")

    # Do-Not-Extract 标记
    non_normative_markers: List[str] = Field(default_factory=list,
                                            description="检测到的非规范标记")

    # 额外属性
    metadata: Dict[str, Any] = Field(default_factory=dict, description="额外元数据")

    class Config:
        use_enum_values = True


# Do-Not-Extract 区域检测规则
DO_NOT_EXTRACT_MARKERS = {
    # 示例标记
    "example": [
        r"\bExample[s]?:",
        r"\bFor example\b",
        r"\be\.g\.,",
        r"\bExample \d+",
        r"\bSample\b",
    ],
    # 说明标记
    "illustration": [
        r"\bIllustration:",
        r"\bFor illustration\b",
        r"\billustrative purposes?\b",
        r"\bFor illustration only\b",
    ],
    # 非规范标记
    "non_normative": [
        r"\bNon-[Nn]ormative\b",
        r"\bInformative\b",
        r"\bNote:",
        r"\bNOTE:",
        r"\bEditor's note\b",
    ],
    # 测试向量
    "test_vectors": [
        r"\bTest [Vv]ector[s]?:",
        r"\bTest [Cc]ase[s]?:",
        r"\bTest [Dd]ata:",
    ],
    # 附录和参考
    "appendix": [
        r"\bAppendix [A-Z]\b",
        r"\bAcknowledgements?\b",
        r"\bReferences?\b",
    ],
}


# 需求关键词（MUST/SHOULD等，大小写均匹配，覆盖ETSI等用小写的文档）
REQUIREMENT_KEYWORDS = [
    r"\bMUST\b",
    r"\bMUST NOT\b",
    r"\bSHALL\b",
    r"\bSHALL NOT\b",
    r"\bSHOULD\b",
    r"\bSHOULD NOT\b",
    r"\bREQUIRED\b",
    r"\bRECOMMENDED\b",
    r"\bMAY\b",
    r"\bOPTIONAL\b",
    r"\bmust\b",
    r"\bmust not\b",
    r"\bshall\b",
    r"\bshall not\b",
    r"\bshould\b",
    r"\bshould not\b",
    r"\brequired\b",
    r"\brecommended\b",
]


def _normalize_requirement_keyword_pattern(pattern: str) -> str:
    """Normalize requirement keyword regexes to a canonical uppercase phrase."""
    normalized = pattern
    normalized = normalized.replace(r"\b", "")
    normalized = normalized.replace(r"\s+", " ")
    normalized = normalized.strip()
    return normalized.upper()


REQUIREMENT_KEYWORD_PHRASES = sorted(
    {
        _normalize_requirement_keyword_pattern(pattern)
        for pattern in REQUIREMENT_KEYWORDS
    },
    key=len,
    reverse=True,
)


REQUIREMENT_KEYWORD_REGEX = re.compile(
    r"\b(?:" + "|".join(re.escape(keyword) for keyword in REQUIREMENT_KEYWORD_PHRASES) + r")\b",
    re.IGNORECASE,
)


def contains_requirement_keyword(text: str) -> bool:
    """Return whether text contains any supported normative keyword phrase."""
    return bool(REQUIREMENT_KEYWORD_REGEX.search(text or ""))


# 定义标记
DEFINITION_KEYWORDS = [
    r"\bis defined as\b",
    r"\bmeans\b",
    r"\brefers to\b",
    r"::=",  # ABNF定义
    r"\bABNF\b",
    r"\bsyntax:\b",
    r"\bformat:\b",
]
