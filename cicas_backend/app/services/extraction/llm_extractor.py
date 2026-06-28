"""
LLM 提取器
仅处理复杂句、跨段落句、包含条件的规则
必须生成 raw IR，不做归一化
"""
import json
from typing import List, Optional, Dict, Any
from .base_extractor import BaseExtractor
from .chunk_types import StructuredChunk, ChunkType
from .ir_schema import (
    ExtractionResult,
    IntermediateRepresentation,
    IRStage,
    IRConstraint,
    IRProvenance,
    IRReference,
    ObligationType,
    PredicateType,
    ConstraintType,
)
from datetime import datetime
import re


class LLMExtractor(BaseExtractor):
    """LLM 提取器 - 处理复杂规则"""

    def __init__(self, llm_client=None):
        super().__init__(name="llm", confidence_base=0.90)
        self.llm_client = llm_client

    def can_extract(self, chunk: StructuredChunk) -> bool:
        """判断是否可以处理"""
        # 仅处理 LLM 指定的 chunk 或 UNKNOWN chunk
        return (
            chunk.should_extract
            and (
                chunk.extractor_type.value == "llm"
                or chunk.chunk_type == ChunkType.UNKNOWN_CHUNK
            )
        )

    def extract(self, chunk: StructuredChunk) -> List[ExtractionResult]:
        """提取规则"""
        if not self.llm_client:
            return []

        # 构建 prompt
        prompt = self._build_extraction_prompt(chunk)

        # 调用 LLM
        try:
            response = self._call_llm(prompt)
            rules = self._parse_llm_response(response)

            results = []
            for rule_data in rules:
                ir = self._build_ir_from_llm_output(rule_data, chunk)
                if ir:
                    result = ExtractionResult(ir=ir)
                    if self.validate_extraction(result, chunk):
                        results.append(result)

            return results

        except Exception as e:
            print(f"LLM extraction error: {e}")
            return []

    def _build_extraction_prompt(self, chunk: StructuredChunk) -> str:
        """构建提取 prompt"""
        prompt = f"""You are a PKI standards rule extractor. Extract rules from the following text.

**IMPORTANT INSTRUCTIONS:**
1. Extract ONLY rules that contain normative requirements (MUST, SHALL, SHOULD, etc.)
2. Do NOT extract examples, test vectors, or non-normative content
3. Generate RAW IR - do NOT normalize field paths or synonyms
4. Each rule must have: subject (certificate field), obligation, predicate, and constraint
5. Extract all references (e.g., "RFC 5280 Section 4.2")
6. If the rule has conditions (if/unless/except), include them in the conditions field

**Text to analyze:**
{chunk.text}

**Context (if relevant):**
Before: {chunk.context_before or 'N/A'}
After: {chunk.context_after or 'N/A'}

**Output format (JSON array):**
[
  {{
    "subject": "extensions.keyUsage",
    "obligation": "MUST",
    "predicate": "must_be_present",
    "constraint": {{
      "raw_text": "The keyUsage extension MUST be present",
      "type": "presence",
      "value": null
    }},
    "references": [
      {{
        "raw": "RFC 5280 Section 4.2.1.3",
        "doc_id": "RFC5280",
        "section": "4.2.1.3",
        "resolved": true,
        "confidence": 1.0
      }}
    ],
    "conditions": [],
    "rule_text": "The keyUsage extension MUST be present in all CA certificates.",
    "confidence": 0.95
  }}
]

**Return only valid JSON.**
"""
        return prompt

    def _call_llm(self, prompt: str) -> str:
        """调用 LLM API"""
        if not self.llm_client:
            return "[]"

        # 这里需要集成实际的 LLM 客户端
        # 示例：使用 OpenAI API 或本地模型
        # response = self.llm_client.chat.completions.create(
        #     model="gpt-4",
        #     messages=[{"role": "user", "content": prompt}],
        #     temperature=0.1,
        # )
        # return response.choices[0].message.content

        # 临时返回空列表
        return "[]"

    def _parse_llm_response(self, response: str) -> List[Dict[str, Any]]:
        """解析 LLM 响应"""
        try:
            # 提取 JSON
            json_match = re.search(r'\[.*\]', response, re.DOTALL)
            if json_match:
                json_str = json_match.group(0)
                rules = json.loads(json_str)
                return rules if isinstance(rules, list) else []
        except json.JSONDecodeError as e:
            print(f"JSON parse error: {e}")
            return []

        return []

    def _build_ir_from_llm_output(
        self, rule_data: Dict[str, Any], chunk: StructuredChunk
    ) -> Optional[IntermediateRepresentation]:
        """从 LLM 输出构建 IR"""
        try:
            # 提取字段
            subject = rule_data.get('subject')
            obligation_str = rule_data.get('obligation')
            predicate_str = rule_data.get('predicate')
            constraint_data = rule_data.get('constraint', {})

            if not all([subject, obligation_str, predicate_str]):
                return None

            # 解析枚举
            try:
                obligation = ObligationType(obligation_str)
            except ValueError:
                return None

            try:
                predicate = PredicateType(predicate_str)
            except ValueError:
                return None

            # 构建约束
            constraint = IRConstraint(
                raw_text=constraint_data.get('raw_text', ''),
                type=ConstraintType(constraint_data.get('type', 'presence')),
                value=constraint_data.get('value'),
                unit=constraint_data.get('unit'),
            )

            # 解析引用
            references = []
            for ref_data in rule_data.get('references', []):
                ref = IRReference(
                    raw=ref_data.get('raw', ''),
                    doc_id=ref_data.get('doc_id'),
                    section=ref_data.get('section'),
                    resolved=ref_data.get('resolved', False),
                )
                references.append(ref)

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
                extractor_type='llm',
                extraction_timestamp=datetime.now(),
            )

            # 构建 IR
            ir = IntermediateRepresentation(
                stage=IRStage.RAW,
                subject=subject,
                obligation=obligation,
                predicate=predicate,
                constraint=constraint,
                references=references,
                rule_text=rule_data.get('rule_text', ''),
                conditions=rule_data.get('conditions'),
                context=chunk.context_before or chunk.context_after,
                provenance=[provenance],
                confidence=rule_data.get('confidence', self.confidence_base),
            )

            return ir

        except Exception as e:
            print(f"Error building IR from LLM output: {e}")
            return None
