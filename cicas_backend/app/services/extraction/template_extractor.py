"""
模板提取器
处理半结构化内容：表格、字段列表、OID列表、定义
"""
import re
from typing import List, Optional, Dict, Any
from .base_extractor import BaseExtractor
from .chunk_types import StructuredChunk, ChunkType
from .ir_schema import (
    ExtractionResult,
    IntermediateRepresentation,
    IRStage,
    IRConstraint,
    IRProvenance,
    ObligationType,
    PredicateType,
    ConstraintType,
)
from datetime import datetime


class TemplateExtractor(BaseExtractor):
    """模板提取器 - 处理半结构化内容"""

    def __init__(self):
        super().__init__(name="template", confidence_base=0.85)

        self._compile_patterns()

    def _compile_patterns(self):
        """编译模式"""
        # 表格行模式
        self.table_row_pattern = re.compile(
            r'\|([^|]+)\|([^|]+)\|([^|]*)\|?',
        )

        # 列表项模式
        self.list_item_pattern = re.compile(
            r'^[\s]*[\*\-\+\d]+[\.\)]\s+(.+)$',
            re.MULTILINE
        )

        # ABNF 定义模式
        self.abnf_pattern = re.compile(
            r'([a-zA-Z0-9\-]+)\s*::=\s*(.+)',
        )

        # 字段定义模式（如：fieldName: description）
        self.field_def_pattern = re.compile(
            r'^([a-zA-Z][a-zA-Z0-9_\.]*)\s*:\s*(.+)$',
            re.MULTILINE
        )

        # OID 模式
        self.oid_pattern = re.compile(
            r'\b(\d+(?:\.\d+){3,})\b'
        )

    def can_extract(self, chunk: StructuredChunk) -> bool:
        """判断是否可以处理"""
        return (
            chunk.chunk_type in [
                ChunkType.TABLE_CHUNK,
                ChunkType.LIST_CHUNK,
                ChunkType.DEFINITION_CHUNK,
            ]
            and chunk.should_extract
        )

    def extract(self, chunk: StructuredChunk) -> List[ExtractionResult]:
        """提取规则"""
        if chunk.chunk_type == ChunkType.TABLE_CHUNK:
            return self._extract_from_table(chunk)
        elif chunk.chunk_type == ChunkType.LIST_CHUNK:
            return self._extract_from_list(chunk)
        elif chunk.chunk_type == ChunkType.DEFINITION_CHUNK:
            return self._extract_from_definition(chunk)
        return []

    def _extract_from_table(self, chunk: StructuredChunk) -> List[ExtractionResult]:
        """从表格提取"""
        results = []
        lines = chunk.text.split('\n')

        # 解析表头
        header = None
        for line in lines:
            if self.table_row_pattern.match(line):
                header = self._parse_table_row(line)
                break

        if not header:
            return []

        # 解析数据行
        for line in lines:
            if not line.strip() or line.startswith('+') or line.startswith('|---'):
                continue

            row = self._parse_table_row(line)
            if not row or row == header:
                continue

            # 尝试从行构建 IR
            ir = self._build_ir_from_table_row(header, row, chunk)
            if ir:
                result = ExtractionResult(ir=ir)
                if self.validate_extraction(result, chunk):
                    results.append(result)

        return results

    def _parse_table_row(self, line: str) -> Optional[List[str]]:
        """解析表格行"""
        match = self.table_row_pattern.match(line)
        if not match:
            return None

        # 提取所有列
        cells = []
        for part in line.split('|'):
            cell = part.strip()
            if cell:
                cells.append(cell)
        return cells if cells else None

    def _build_ir_from_table_row(
        self, header: List[str], row: List[str], chunk: StructuredChunk
    ) -> Optional[IntermediateRepresentation]:
        """从表格行构建 IR"""
        if len(row) < 2:
            return None

        # 假设第一列是字段名，第二列是要求/值
        subject = row[0].strip()
        requirement_text = row[1].strip() if len(row) > 1 else ""

        # 判断义务类型
        obligation = self._infer_obligation(requirement_text)
        if not obligation:
            obligation = ObligationType.MUST  # 默认

        # 判断谓词
        predicate = self._infer_predicate(requirement_text)

        # 构建约束
        constraint = IRConstraint(
            raw_text=requirement_text,
            type=ConstraintType.STRING,
            value=requirement_text if requirement_text else None,
        )

        # 只使用可靠的section（详细章节号），否则设置为None
        section = chunk.section if (chunk.section and '.' in chunk.section) else None

        # 构建 provenance
        provenance = IRProvenance(
            source_id=chunk.metadata.get('document_id', 'unknown'),
            section=section,
            title=chunk.title,
            line_start=chunk.line_start,
            line_end=chunk.line_end,
            chunk_id=chunk.chunk_id,
            extractor_type='template:table',
            extraction_timestamp=datetime.now(),
        )

        ir = IntermediateRepresentation(
            stage=IRStage.RAW,
            subject=subject,
            obligation=obligation,
            predicate=predicate,
            constraint=constraint,
            rule_text=f"{subject}: {requirement_text}",
            provenance=[provenance],
        )

        return ir

    def _extract_from_list(self, chunk: StructuredChunk) -> List[ExtractionResult]:
        """从列表提取"""
        results = []

        for match in self.list_item_pattern.finditer(chunk.text):
            item_text = match.group(1).strip()

            # 尝试解析列表项
            ir = self._build_ir_from_list_item(item_text, chunk)
            if ir:
                result = ExtractionResult(ir=ir)
                if self.validate_extraction(result, chunk):
                    results.append(result)

        return results

    def _build_ir_from_list_item(
        self, item_text: str, chunk: StructuredChunk
    ) -> Optional[IntermediateRepresentation]:
        """从列表项构建 IR"""
        # 尝试检测字段定义格式：fieldName: description
        match = self.field_def_pattern.match(item_text)
        if match:
            subject = match.group(1)
            description = match.group(2)

            obligation = self._infer_obligation(description)
            if not obligation:
                obligation = ObligationType.MUST

            predicate = self._infer_predicate(description)

            constraint = IRConstraint(
                raw_text=description,
                type=ConstraintType.STRING,
                value=description,
            )

            # 只使用可靠的section（详细章节号），否则设置为None
            section = chunk.section if (chunk.section and '.' in chunk.section) else None

            provenance = IRProvenance(
                source_id=chunk.metadata.get('document_id', 'unknown'),
                section=section,
                title=chunk.title,
                line_start=chunk.line_start,
                line_end=chunk.line_end,
                chunk_id=chunk.chunk_id,
                extractor_type='template:list',
                extraction_timestamp=datetime.now(),
            )

            ir = IntermediateRepresentation(
                stage=IRStage.RAW,
                subject=subject,
                obligation=obligation,
                predicate=predicate,
                constraint=constraint,
                rule_text=item_text,
                provenance=[provenance],
            )

            return ir

        return None

    def _extract_from_definition(self, chunk: StructuredChunk) -> List[ExtractionResult]:
        """从定义提取"""
        results = []

        # 检测 ABNF 定义
        for match in self.abnf_pattern.finditer(chunk.text):
            field_name = match.group(1)
            definition = match.group(2)

            ir = self._build_ir_from_abnf(field_name, definition, chunk)
            if ir:
                result = ExtractionResult(ir=ir)
                if self.validate_extraction(result, chunk):
                    results.append(result)

        return results

    def _build_ir_from_abnf(
        self, field_name: str, definition: str, chunk: StructuredChunk
    ) -> Optional[IntermediateRepresentation]:
        """从 ABNF 构建 IR"""
        constraint = IRConstraint(
            raw_text=f"{field_name} ::= {definition}",
            type=ConstraintType.ABNF,
            value=definition,
        )

        # 只使用可靠的section（详细章节号），否则设置为None
        section = chunk.section if (chunk.section and '.' in chunk.section) else None

        provenance = IRProvenance(
            source_id=chunk.metadata.get('document_id', 'unknown'),
            section=section,
            title=chunk.title,
            line_start=chunk.line_start,
            line_end=chunk.line_end,
            chunk_id=chunk.chunk_id,
            extractor_type='template:abnf',
            extraction_timestamp=datetime.now(),
        )

        ir = IntermediateRepresentation(
            stage=IRStage.RAW,
            subject=field_name,
            obligation=ObligationType.MUST,
            predicate=PredicateType.CONFORM_TO,
            constraint=constraint,
            rule_text=f"{field_name} ::= {definition}",
            provenance=[provenance],
        )

        return ir

    def _infer_obligation(self, text: str) -> Optional[ObligationType]:
        """推断义务类型"""
        text_upper = text.upper()
        if 'MUST NOT' in text_upper:
            return ObligationType.MUST_NOT
        elif 'MUST' in text_upper:
            return ObligationType.MUST
        elif 'SHALL NOT' in text_upper:
            return ObligationType.SHALL_NOT
        elif 'SHALL' in text_upper:
            return ObligationType.SHALL
        elif 'SHOULD NOT' in text_upper:
            return ObligationType.SHOULD_NOT
        elif 'SHOULD' in text_upper:
            return ObligationType.SHOULD
        elif 'MAY' in text_upper:
            return ObligationType.MAY
        elif 'REQUIRED' in text_upper:
            return ObligationType.REQUIRED
        elif 'OPTIONAL' in text_upper:
            return ObligationType.OPTIONAL
        return None

    def _infer_predicate(self, text: str) -> PredicateType:
        """推断谓词"""
        text_lower = text.lower()

        if 'not present' in text_lower or 'absent' in text_lower or 'omit' in text_lower:
            return PredicateType.MUST_NOT_BE_PRESENT
        elif 'present' in text_lower or 'include' in text_lower or 'contain' in text_lower:
            return PredicateType.MUST_BE_PRESENT
        elif 'conform' in text_lower or 'comply' in text_lower:
            return PredicateType.CONFORM_TO
        elif 'equal' in text_lower or 'match' in text_lower:
            return PredicateType.EQUAL
        else:
            return PredicateType.MUST_BE_PRESENT  # 默认
