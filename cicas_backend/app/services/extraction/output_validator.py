"""
LLM 输出验证器 (Output Validator)

这是防止 "LLM 看起来很乖但偷偷乱填" 的最后防线。

职责：
1. Schema 校验 - JSON 是否合法，枚举值是否合法
2. 值域校验 - operation ∈ {MUST, MUST_NOT, SHOULD, MAY}
3. 引用合法性 - references 是否存在于 KG
4. 失败处理 - 标记 invalid，不进入后续模块

设计原则：
- 所有验证都是规则驱动的，无 LLM 参与
- 失败时提供明确的错误信息
- 支持 "undetermined" 作为合法值
"""
import json
import re
from typing import Dict, Any, List, Optional, Tuple
from dataclasses import dataclass, field
from enum import Enum

from app.core.logging_config import app_logger


class ValidationErrorType(str, Enum):
    """验证错误类型"""
    INVALID_JSON = "invalid_json"
    MISSING_REQUIRED_FIELD = "missing_required_field"
    INVALID_ENUM_VALUE = "invalid_enum_value"
    INVALID_FIELD_TYPE = "invalid_field_type"
    INVALID_REFERENCE = "invalid_reference"
    SCHEMA_VIOLATION = "schema_violation"
    VALUE_OUT_OF_RANGE = "value_out_of_range"


@dataclass
class ValidationError:
    """单个验证错误"""
    error_type: ValidationErrorType
    field: str
    message: str
    value: Optional[Any] = None


@dataclass
class ValidationResult:
    """验证结果"""
    is_valid: bool
    errors: List[ValidationError] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)
    normalized_output: Optional[Dict[str, Any]] = None

    def add_error(self, error_type: ValidationErrorType, field: str, message: str, value: Any = None):
        """添加错误"""
        self.errors.append(ValidationError(error_type, field, message, value))
        self.is_valid = False

    def add_warning(self, message: str):
        """添加警告（不影响验证结果）"""
        self.warnings.append(message)


class OutputValidator:
    """
    LLM 输出验证器

    验证流程：
    1. JSON 解析检查
    2. 必填字段检查
    3. 枚举值合法性检查
    4. 字段类型检查
    5. 引用合法性检查（可选，需要 KG）
    """

    # 允许的 operation/obligation 值
    VALID_OBLIGATIONS = {
        "MUST", "MUST NOT", "MUST_NOT",
        "SHALL", "SHALL NOT", "SHALL_NOT",
        "SHOULD", "SHOULD NOT", "SHOULD_NOT",
        "MAY", "OPTIONAL", "REQUIRED", "RECOMMENDED"
    }

    # 允许的 spec_family 值
    VALID_SPEC_FAMILIES = {"RFC", "CABF", "ETSI", "Other"}

    # 允许的 assertion_subject 值
    VALID_ASSERTION_SUBJECTS = {"Certificate", "CRL", "CrossArtifact", "Implementation", "RelyingParty"}

    # 允许的 enforcement_phase 值
    VALID_ENFORCEMENT_PHASES = {"Encoding", "Comparison", "Validation", "Processing"}

    # 允许的 rule_category 值（Enhanced IR Extraction）
    VALID_RULE_CATEGORIES = {
        "encoding_constraint", "definition", "algorithm_ref", "clarification",
        "comparison", "capability", "display"
    }

    # 允许的 verifiability 值（Enhanced IR Extraction）
    VALID_VERIFIABILITIES = {"observable", "context_dependent", "runtime_only", "none"}

    # 必填字段（obligation 由 Layer 1 Regex 提取，LLM 不输出，由 _build_ir 优先用 skeleton.keyword 回填）
    REQUIRED_FIELDS = ["subject", "predicate"]

    # 允许的特殊值
    UNDETERMINED = "undetermined"

    def __init__(self, knowledge_graph=None):
        """
        初始化验证器

        Args:
            knowledge_graph: 知识图谱实例（用于引用合法性检查，可选）
        """
        self.kg = knowledge_graph

    def validate(self, llm_output: Any) -> ValidationResult:
        """
        验证 LLM 输出

        Args:
            llm_output: LLM 原始输出（字符串或已解析的字典）

        Returns:
            ValidationResult 包含验证结果和规范化后的输出
        """
        result = ValidationResult(is_valid=True)

        # Step 1: JSON 解析
        parsed_output = self._parse_json(llm_output, result)
        if not result.is_valid:
            return result

        # Step 2: 处理特殊输出
        if self._is_special_output(parsed_output, result):
            return result

        # Step 3: 必填字段检查
        self._validate_required_fields(parsed_output, result)
        if not result.is_valid:
            return result

        # Step 4: 枚举值检查
        self._validate_enum_values(parsed_output, result)

        # Step 5: 字段类型检查
        self._validate_field_types(parsed_output, result)

        # Step 6: 引用合法性检查（如果有 KG）
        if self.kg:
            self._validate_references(parsed_output, result)

        # Step 7: 规范化输出
        if result.is_valid:
            result.normalized_output = self._normalize_output(parsed_output)

        return result

    def _parse_json(self, llm_output: Any, result: ValidationResult) -> Optional[Dict[str, Any]]:
        """解析 JSON"""
        if isinstance(llm_output, dict):
            return llm_output

        if isinstance(llm_output, str):
            # 尝试提取 JSON
            try:
                # 处理可能的 markdown 代码块
                json_str = llm_output.strip()
                if json_str.startswith("```"):
                    # 提取代码块内容
                    match = re.search(r'```(?:json)?\s*([\s\S]*?)\s*```', json_str)
                    if match:
                        json_str = match.group(1)
                    else:
                        json_str = json_str.replace("```json", "").replace("```", "").strip()

                parsed = json.loads(json_str)
                return parsed

            except json.JSONDecodeError as e:
                result.add_error(
                    ValidationErrorType.INVALID_JSON,
                    "root",
                    f"JSON 解析失败: {str(e)}",
                    llm_output[:200] if len(llm_output) > 200 else llm_output
                )
                return None

        result.add_error(
            ValidationErrorType.INVALID_JSON,
            "root",
            f"无效的输出类型: {type(llm_output).__name__}",
            None
        )
        return None

    def _is_special_output(self, parsed: Dict[str, Any], result: ValidationResult) -> bool:
        """检查是否是特殊输出（undetermined）"""
        # 检查整体 undetermined
        if parsed.get("status") == "undetermined" or (
            len(parsed) == 1 and "undetermined" in str(parsed).lower()
        ):
            result.normalized_output = {"status": "undetermined", "reason": "无法提取结构化规则"}
            result.add_warning("输出为 undetermined，句子可能是描述性或解释性的")
            return True

        return False

    def _validate_required_fields(self, parsed: Dict[str, Any], result: ValidationResult):
        """验证必填字段"""
        for field in self.REQUIRED_FIELDS:
            value = parsed.get(field)
            if value is None:
                result.add_error(
                    ValidationErrorType.MISSING_REQUIRED_FIELD,
                    field,
                    f"缺少必填字段: {field}"
                )
            elif value == "":
                result.add_error(
                    ValidationErrorType.MISSING_REQUIRED_FIELD,
                    field,
                    f"必填字段 {field} 不能为空"
                )

    def _validate_enum_values(self, parsed: Dict[str, Any], result: ValidationResult):
        """验证枚举值"""
        # 验证 obligation
        obligation = parsed.get("obligation", "")
        if (
            obligation
            and obligation.upper() not in self.VALID_OBLIGATIONS
            and obligation.lower() != self.UNDETERMINED
        ):
            result.add_error(
                ValidationErrorType.INVALID_ENUM_VALUE,
                "obligation",
                f"无效的 obligation 值: {obligation}",
                obligation
            )

        # 验证 spec_family
        spec_family = parsed.get("spec_family", "")
        if spec_family and spec_family not in self.VALID_SPEC_FAMILIES:
            result.add_warning(f"未知的 spec_family: {spec_family}，将使用 'Other'")

        # 验证 assertion_subject
        assertion_subject = parsed.get("assertion_subject", "")
        if assertion_subject and assertion_subject not in self.VALID_ASSERTION_SUBJECTS:
            result.add_warning(f"未知的 assertion_subject: {assertion_subject}，将使用 'Certificate'")

        # 验证 enforcement_phase
        enforcement_phase = parsed.get("enforcement_phase", "")
        if enforcement_phase and enforcement_phase not in self.VALID_ENFORCEMENT_PHASES:
            result.add_warning(f"未知的 enforcement_phase: {enforcement_phase}，将忽略")

        # 验证 rule_category（Enhanced IR Extraction）
        rule_category = parsed.get("rule_category", "")
        if rule_category and rule_category not in self.VALID_RULE_CATEGORIES:
            result.add_warning(f"未知的 rule_category: {rule_category}，将忽略")

        # 验证 verifiability（Enhanced IR Extraction）
        verifiability = parsed.get("verifiability", "")
        if verifiability and verifiability not in self.VALID_VERIFIABILITIES:
            result.add_warning(f"未知的 verifiability: {verifiability}，将使用 'observable'")

    def _validate_field_types(self, parsed: Dict[str, Any], result: ValidationResult):
        """验证字段类型"""
        # subject 必须是字符串
        subject = parsed.get("subject")
        if subject is not None and not isinstance(subject, str):
            result.add_error(
                ValidationErrorType.INVALID_FIELD_TYPE,
                "subject",
                f"subject 必须是字符串，得到: {type(subject).__name__}",
                subject
            )

        # references 必须是列表
        references = parsed.get("references")
        if references is not None and not isinstance(references, list):
            result.add_error(
                ValidationErrorType.INVALID_FIELD_TYPE,
                "references",
                f"references 必须是列表，得到: {type(references).__name__}",
                references
            )

        # constraint 必须是字典或字符串
        constraint = parsed.get("constraint")
        if constraint is not None and not isinstance(constraint, (dict, str)):
            result.add_error(
                ValidationErrorType.INVALID_FIELD_TYPE,
                "constraint",
                f"constraint 必须是字典或字符串，得到: {type(constraint).__name__}",
                constraint
            )

        # precondition 必须是字典或 null
        precondition = parsed.get("precondition")
        if precondition is not None and not isinstance(precondition, dict):
            result.add_warning(f"precondition 应该是字典，得到: {type(precondition).__name__}")

        # requires_operation 必须是字典或 null
        requires_operation = parsed.get("requires_operation")
        if requires_operation is not None and not isinstance(requires_operation, dict):
            result.add_warning(f"requires_operation 应该是字典，得到: {type(requires_operation).__name__}")

        # algorithm_ref 必须是字典或 null（Enhanced IR Extraction）
        algorithm_ref = parsed.get("algorithm_ref")
        if algorithm_ref is not None and not isinstance(algorithm_ref, dict):
            result.add_warning(f"algorithm_ref 应该是字典，得到: {type(algorithm_ref).__name__}")

        # overrides 必须是列表（Enhanced IR Extraction）
        overrides = parsed.get("overrides")
        if overrides is not None and not isinstance(overrides, list):
            result.add_warning(f"overrides 应该是列表，得到: {type(overrides).__name__}")

    def _validate_references(self, parsed: Dict[str, Any], result: ValidationResult):
        """验证引用合法性（需要知识图谱）"""
        if not self.kg:
            return

        references = parsed.get("references", [])
        if not isinstance(references, list):
            return

        for i, ref in enumerate(references):
            if not isinstance(ref, dict):
                continue

            # 检查 doc_id 是否存在于 KG
            doc_id = ref.get("doc_id")
            if doc_id:
                # 构建可能的节点 ID
                possible_ids = [
                    f"spec:{doc_id}",
                    doc_id
                ]

                found = False
                for node_id in possible_ids:
                    if self.kg.get_node(node_id):
                        found = True
                        break

                if not found:
                    # 这只是警告，不是错误（引用可能是新规范）
                    result.add_warning(
                        f"引用的文档 '{doc_id}' 在知识图谱中未找到（引用 #{i+1}）"
                    )

            # 检查 section 格式
            section = ref.get("section")
            if section and not self._is_valid_section_format(section):
                result.add_warning(
                    f"引用的章节格式可能无效: '{section}'（引用 #{i+1}）"
                )

    def _is_valid_section_format(self, section: str) -> bool:
        """检查章节格式是否有效"""
        # 常见格式：4.2.1, 4.2.1.1, Section 4.2, Appendix A
        patterns = [
            r'^\d+(\.\d+)*$',  # 4.2.1
            r'^Section\s+\d+(\.\d+)*$',  # Section 4.2
            r'^Appendix\s+[A-Z](\.\d+)*$',  # Appendix A.1
            r'^§\s*\d+(\.\d+)*$',  # § 4.2
        ]
        return any(re.match(pattern, section, re.IGNORECASE) for pattern in patterns)

    def _normalize_output(self, parsed: Dict[str, Any]) -> Dict[str, Any]:
        """规范化输出"""
        normalized = {}

        # 复制基本字段
        for key in ["subject", "predicate", "rule_text", "conditions"]:
            if key in parsed:
                normalized[key] = parsed[key]

        # 规范化 predicate（保留自定义谓词，避免把 assertion 级算法步骤谓词抹掉）
        predicate = parsed.get("predicate")
        if predicate is not None:
            normalized["predicate"] = str(predicate)

        # 规范化 obligation
        obligation = parsed.get("obligation", "")
        if obligation:
            normalized["obligation"] = obligation.upper().replace(" ", "_")

        # 规范化 spec_family
        spec_family = parsed.get("spec_family", "Other")
        if spec_family in self.VALID_SPEC_FAMILIES:
            normalized["spec_family"] = spec_family
        else:
            normalized["spec_family"] = "Other"

        # 规范化 constraint
        constraint = parsed.get("constraint")
        if isinstance(constraint, str):
            normalized["constraint"] = {"raw_text": constraint}
        elif isinstance(constraint, dict):
            normalized["constraint"] = constraint
        else:
            normalized["constraint"] = {"raw_text": ""}

        # 规范化 references（仅保留显式引用）
        references = parsed.get("references", [])
        normalized["references"] = self._normalize_references(references)

        # ========== 新字段（支持四个条件）==========

        # assertion_subject: Certificate | CRL | CrossArtifact | Implementation | RelyingParty
        assertion_subject = parsed.get("assertion_subject", "Certificate")
        valid_assertion_subjects = {"Certificate", "CRL", "CrossArtifact", "Implementation", "RelyingParty"}
        if assertion_subject in valid_assertion_subjects:
            normalized["assertion_subject"] = assertion_subject
        else:
            normalized["assertion_subject"] = "Certificate"  # 默认值

        # enforcement_phase: Encoding | Comparison | Validation | Processing
        enforcement_phase = parsed.get("enforcement_phase")
        valid_phases = {"Encoding", "Comparison", "Validation", "Processing"}
        if enforcement_phase and enforcement_phase in valid_phases:
            normalized["enforcement_phase"] = enforcement_phase
        else:
            normalized["enforcement_phase"] = None

        # precondition: 前置条件（可以是 dict 或 null）
        precondition = parsed.get("precondition")
        if isinstance(precondition, dict) and precondition:
            normalized["precondition"] = precondition
        else:
            normalized["precondition"] = None

        # requires_operation: 依赖的操作及其来源（可以是 dict 或 null）
        requires_operation = parsed.get("requires_operation")
        if isinstance(requires_operation, dict) and requires_operation:
            normalized["requires_operation"] = requires_operation
        else:
            normalized["requires_operation"] = None

        # ========== Enhanced IR Extraction 字段 ==========

        # rule_category: definition | algorithm_ref | clarification | comparison | capability | display
        rule_category = parsed.get("rule_category")
        if rule_category and rule_category in self.VALID_RULE_CATEGORIES:
            normalized["rule_category"] = rule_category
        else:
            normalized["rule_category"] = None

        # verifiability: observable | context_dependent | runtime_only | none
        verifiability = parsed.get("verifiability")
        if verifiability and verifiability in self.VALID_VERIFIABILITIES:
            normalized["verifiability"] = verifiability
        else:
            normalized["verifiability"] = "observable"  # 默认值

        # algorithm_ref: 外部算法引用（可以是 dict 或 null）
        algorithm_ref = parsed.get("algorithm_ref")
        if isinstance(algorithm_ref, dict) and algorithm_ref.get("base_spec"):
            # 确保 inheritance 有默认值，避免 None 导致验证失败
            if not algorithm_ref.get("inheritance"):
                algorithm_ref["inheritance"] = "full"
            normalized["algorithm_ref"] = algorithm_ref
        else:
            normalized["algorithm_ref"] = None

        # overrides: 算法步骤覆盖列表
        overrides = parsed.get("overrides")
        if isinstance(overrides, list):
            normalized["overrides"] = [
                ov for ov in overrides
                if isinstance(ov, dict) and ov.get("param")
            ]
        else:
            normalized["overrides"] = []

        return normalized

    def _normalize_references(self, references: Any) -> List[Dict[str, Any]]:
        """规范化引用列表（仅保留显式引用）"""
        if not isinstance(references, list):
            return []

        normalized = []
        for ref in references:
            if not isinstance(ref, dict):
                continue

            # 必须有 raw 或 doc_id
            raw = ref.get("raw", "")
            doc_id = ref.get("doc_id", "")

            if not raw and not doc_id:
                continue

            normalized_ref = {
                "raw": raw,
                "doc_id": doc_id,
                "section": ref.get("section"),
                "resolved": ref.get("resolved", False),
                "resolution_method": "explicit"  # 由 LLM 提取的都是显式引用
            }
            normalized.append(normalized_ref)

        return normalized


def validate_llm_output(llm_output: Any, kg=None) -> ValidationResult:
    """
    便捷函数：验证 LLM 输出

    Args:
        llm_output: LLM 原始输出
        kg: 知识图谱实例（可选）

    Returns:
        ValidationResult
    """
    validator = OutputValidator(knowledge_graph=kg)
    return validator.validate(llm_output)
