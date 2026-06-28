"""
改进的 IR 数据结构
支持 raw IR → normalized IR → final IR 三阶段

架构原则（HARD CONSTRAINTS）：
1. LLM 不做规范判断
2. LLM 不解决冲突
3. LLM 不推断隐含要求
4. 所有决策必须基于规则且可审计
5. 规范知识不嵌入模型参数
6. 更新规范不需要重新训练 LLM
"""
from typing import Optional, List, Dict, Any, Union, Literal
from enum import Enum
from pydantic import BaseModel, Field, model_validator
from datetime import datetime


class SpecFamily(str, Enum):
    """规范体系标识"""
    RFC = "RFC"      # IETF RFC 系列
    CABF = "CABF"    # CA/Browser Forum
    ETSI = "ETSI"    # ETSI 标准
    OTHER = "Other"  # 其他规范


class RuleCategory(str, Enum):
    """
    Rule classification - determines processing strategy and lintability.

    This classification is the first step in determining whether a rule
    can generate a zlint check.
    """
    ENCODING_CONSTRAINT = "encoding_constraint"  # Certificate field encoding/format constraints (lintable!)
                                        # e.g., "MUST be encoded as UTF8String", "MUST NOT exceed 64 characters"
                                        # e.g., "extension MUST be present", "field MUST be marked critical"
                                        # → verifiability = "observable", assertion_subject = "Certificate"
    DEFINITION = "definition"           # Type/field definitions (e.g., "IA5String is limited to ASCII")
                                        # → verifiability = "none", lintable = false
    ALGORITHM_REF = "algorithm_ref"     # Reference to external algorithm (e.g., "perform operation specified in RFC 3490 §4")
                                        # → Extract algorithm_ref, verifiability = "none"
    CLARIFICATION = "clarification"     # Value semantics or conditional constraints
                                        # e.g., "cA boolean indicates whether the subject is a CA"
                                        # → verifiability = "observable" if about certificate content
    COMPARISON = "comparison"           # Comparison/matching rules (e.g., "MUST perform case-insensitive match")
                                        # → verifiability = "observable" if about certificate content
                                        # → verifiability = "runtime_only" if about comparison behavior
    CAPABILITY = "capability"           # Implementation capacity requirements (e.g., "MUST allow for increased space")
                                        # → verifiability = "none", lintable = false
                                        # CRITICAL: "Implementations MUST allow for X" = CAPABILITY
    DISPLAY = "display"                 # UI/presentation recommendations (e.g., "should convert to Unicode before display")
                                        # → verifiability = "none", lintable = false


class Verifiability(str, Enum):
    """
    Whether the rule can be verified by examining a certificate.

    Only OBSERVABLE rules can generate zlint checks.
    """
    OBSERVABLE = "observable"           # Can be verified in certificate → lintable
    CONTEXT_DEPENDENT = "context_dependent"  # Certificate fields are observable, but rule applicability needs extra trust/program context
    RUNTIME_ONLY = "runtime_only"       # Only verifiable at runtime → not lintable
    NONE = "none"                       # Cannot be verified → not lintable


class LintCategory(str, Enum):
    """
    Lint category for further classification of rules within rules_pool.

    This helps distinguish between different types of rules without removing
    them from rules_pool, maintaining traceability while improving conceptual purity.
    """
    STATIC_VERIFIABLE = "static_verifiable"       # Can be checked by examining certificate content
    RUNTIME_SEMANTIC = "runtime_semantic"         # Describes runtime behavior (comparison, validation)
    IMPLEMENTATION_GUIDANCE = "implementation_guidance"  # Implementation requirements (capability, display)
    DEFINITION = "definition"                     # Defines semantics, not constraints


# ExtractionConfidence 已删除 - 使用 IRStage 表示处理阶段即可


class ObligationType(str, Enum):
    """义务类型"""
    MUST = "MUST"
    MUST_NOT = "MUST NOT"
    SHALL = "SHALL"
    SHALL_NOT = "SHALL NOT"
    SHOULD = "SHOULD"
    SHOULD_NOT = "SHOULD NOT"
    MAY = "MAY"
    OPTIONAL = "OPTIONAL"
    REQUIRED = "REQUIRED"
    RECOMMENDED = "RECOMMENDED"


class PredicateType(str, Enum):
    """谓词类型"""
    MUST_INCLUDE = "must_include"
    MUST_NOT_INCLUDE = "must_not_include"
    MUST_BE_PRESENT = "must_be_present"
    MUST_NOT_BE_PRESENT = "must_not_be_present"
    CONFORM_TO = "conform_to"
    EQUAL = "equal"
    NOT_EQUAL = "not_equal"
    LESS_THAN = "less_than"
    LESS_THAN_OR_EQUAL = "less_than_or_equal"
    GREATER_THAN = "greater_than"
    GREATER_THAN_OR_EQUAL = "greater_than_or_equal"
    IN_RANGE = "in_range"
    MATCHES_PATTERN = "matches_pattern"
    ALLOWED_VALUES = "allowed_values"
    FORBIDDEN_VALUES = "forbidden_values"
    # 更具体的 algorithm 相关谓词（解决 MUST/SHOULD 混乱问题）
    ENCODE_AS = "encode_as"             # 编码/存储时的格式转换 (e.g., ToASCII for storage)
    DISPLAY_AS = "display_as"           # 显示时的格式转换 (e.g., ToUnicode for display)
    COMPARE_AS = "compare_as"           # 比较时的算法 (e.g., case-insensitive match)


class ConstraintType(str, Enum):
    """约束类型"""
    PRESENCE = "presence"
    ABSENCE = "absence"
    NUMERIC = "numeric"
    STRING = "string"
    SYNTAX = "syntax"
    FORMAT = "format"
    ENUM = "enum"
    TIME_BASED = "time_based"
    OID_LIST = "oid_list"
    ABNF = "abnf"
    REGEX = "regex"
    LENGTH = "length"
    BOOLEAN = "boolean"


class IRReference(BaseModel):
    """引用信息"""
    raw: str = Field(..., description="原始引用文本，如 'RFC 5280 Section 4.2'")
    doc_id: Optional[str] = Field(None, description="文档ID，如 'RFC5280'")
    section: Optional[str] = Field(None, description="章节号，如 '4.2'")
    resolved: bool = Field(False, description="是否已解析")
    unresolved: bool = Field(False, description="是否无法解析")

    # 解析详情
    resolution_method: Optional[str] = Field(None, description="解析方法: explicit/implicit/contextual")
    target_rule_id: Optional[str] = Field(None, description="引用的目标规则ID")

    class Config:
        use_enum_values = True


class ReferenceRelationType(str, Enum):
    """
    Semantic relationship type between specifications.

    Determines how the referencing spec relates to the referenced spec.
    """
    PROFILES = "profiles"     # Customizes/restricts the referenced spec (e.g., RFC5280 profiles RFC3490)
    REQUIRES = "requires"     # Depends on the referenced spec (hard dependency)
    USES = "uses"             # References for a specific operation (soft dependency)
    OVERRIDES = "overrides"   # Replaces/modifies behavior from referenced spec
    EXTENDS = "extends"       # Adds functionality to referenced spec
    DEFINES = "defines"       # The referenced spec defines the concept being used


class StepModification(BaseModel):
    """
    Step-level modification to a referenced algorithm.

    This captures the semantic relationship between the referencing spec and
    the referenced algorithm at the step level, enabling:
    1. Conflict detection between specs that modify the same step
    2. Inheritance tracking (what was the original vs what is overridden)
    3. Graph-based algorithm provenance

    Example from RFC 5280 §7.2 modifying RFC 3490 §4:
    - step=1, param="domain_type", original="query_or_stored", override="stored_only"
    - step=3, param="UseSTD3ASCIIRules", original="optional", override="required"
    - step=5, modification_type="skip" (entire step skipped)
    """
    step: int = Field(..., description="Step number in the referenced algorithm")
    param: str = Field(..., description="Parameter being modified (or 'entire_step' for skip)")
    original_value: Optional[str] = Field(
        None,
        description="Original value in referenced algorithm (if known from cross-ref resolution)"
    )
    override_value: str = Field(..., description="New value specified by this spec")
    modification_type: str = Field(
        "override",
        description="Type of modification: 'override' (change value) | 'skip' (omit step) | 'add' (new requirement)"
    )
    source_text: str = Field(..., description="Original text fragment for this modification")

    class Config:
        use_enum_values = True


class AlgorithmReference(BaseModel):
    """
    Reference to an external algorithm (not expanded inline).

    This captures references like "perform the operation specified in RFC 3490 Section 4"
    without trying to expand or inline the algorithm steps.

    The relation_type field captures the semantic relationship:
    - profiles: This spec customizes/restricts RFC3490's algorithm (most common for RFC→RFC refs)
    - requires: This spec requires RFC3490's algorithm to function
    - uses: This spec uses RFC3490's algorithm for a specific operation
    - overrides: This spec modifies the default behavior of RFC3490
    - extends: This spec adds to RFC3490's functionality
    - defines: RFC3490 defines the algorithm being referenced

    The step_modifications field provides step-level granularity for inheritance tracking.
    """
    base_spec: str = Field(..., description="Referenced specification, e.g., 'RFC 3490'")
    section: Optional[str] = Field(None, description="Section reference, e.g., 'Section 4' or '4'")
    operation: Optional[str] = Field(None, description="Operation name if identifiable, e.g., 'ToASCII', 'IDN_to_ACE'")
    inheritance: str = Field("full", description="'full' if no overrides, 'partial' if local clarifications exist")
    relation_type: Union[ReferenceRelationType, str] = Field(
        ReferenceRelationType.PROFILES,
        description="Semantic relationship: profiles|requires|uses|overrides|extends|defines"
    )
    # Step-level modifications (升级为规则级引用)
    step_modifications: List['StepModification'] = Field(
        default_factory=list,
        description="Step-level modifications to the referenced algorithm (enables conflict detection and inheritance tracking)"
    )

    class Config:
        use_enum_values = True


class Override(BaseModel):
    """
    Override/clarification to a referenced algorithm step.

    Captures local modifications to external algorithm steps, e.g.,
    "in step 3, set UseSTD3ASCIIRules to true".
    """
    step: Optional[int] = Field(None, description="Step number in referenced algorithm (if applicable)")
    param: str = Field(..., description="Parameter being overridden, e.g., 'UseSTD3ASCIIRules'")
    value: Any = Field(..., description="Override value, e.g., True, 'false', 0")
    action: str = Field("override", description="Action type: 'override' | 'skip' | 'inherit'")
    source_text: str = Field(..., description="Original text fragment for this override")

    class Config:
        use_enum_values = True


class SubjectRef(BaseModel):
    """
    主体引用（Subject Reference）

    将 subject 从纯字符串升级为类型化引用，支持：
    1. Canonical subject path（规范路径，用于跨章节聚合）
    2. 与 KG 中 CertificateField 节点的链接
    3. 可审计的解析路径
    4. 向后兼容纯字符串输入

    示例：
    - path: "extensions.subjectAltName.dNSName"  (canonical)
    - aliases: ["dNSName", "DNS name", "IDN in GeneralName"]
    - field_id: "field:extensions.subjectAltName.dNSName" (KG 节点 ID)
    - raw: "internationalized domain names" (原始文本)
    """
    # 规范化路径（必填） - 这是 CANONICAL 路径，用于跨章节聚合
    path: str = Field(..., description="证书字段的规范路径 (canonical path)，如 'extensions.subjectAltName.dNSName'")

    # 别名列表（可选） - 同一 subject 的其他表达方式
    aliases: List[str] = Field(
        default_factory=list,
        description="同一 subject 的别名列表，如 ['dNSName', 'DNS name', 'IDN']"
    )

    # KG 链接（可选）
    field_id: Optional[str] = Field(
        None,
        description="KG 中 CertificateField 节点的 ID，如 'field:extensions.subjectAltName.dNSName'"
    )

    # 原始文本（用于审计）
    raw: Optional[str] = Field(
        None,
        description="LLM 提取的原始文本，用于审计和调试"
    )

    # 解析状态
    resolved: bool = Field(
        False,
        description="是否已与 KG 中的 CertificateField 节点解析链接"
    )

    # 解析方法
    resolution_method: Optional[str] = Field(
        None,
        description="解析方法: exact_match/normalized/alias/canonical_from_kb/unresolved"
    )

    class Config:
        use_enum_values = True

    @classmethod
    def from_string(cls, path: str) -> "SubjectRef":
        """
        从字符串创建 SubjectRef（向后兼容）

        Args:
            path: 字段路径字符串

        Returns:
            SubjectRef 实例
        """
        return cls(path=path, raw=path, resolved=False, aliases=[])

    @classmethod
    def from_canonical(
        cls,
        canonical_path: str,
        raw: str,
        aliases: Optional[List[str]] = None
    ) -> "SubjectRef":
        """
        从规范路径和别名创建 SubjectRef

        Args:
            canonical_path: 规范的字段路径（用于跨章节聚合）
            raw: 原始文本
            aliases: 别名列表

        Returns:
            SubjectRef 实例
        """
        return cls(
            path=canonical_path,
            raw=raw,
            aliases=aliases or [],
            resolved=False,
            resolution_method="canonical_from_kb"
        )

    def to_path_string(self) -> str:
        """返回路径字符串（向后兼容）"""
        return self.path

    def matches(self, other_path: str) -> bool:
        """
        检查是否匹配给定路径（包括别名匹配）

        Args:
            other_path: 要匹配的路径

        Returns:
            是否匹配
        """
        other_lower = other_path.lower()
        if self.path.lower() == other_lower:
            return True
        for alias in self.aliases:
            if alias.lower() == other_lower:
                return True
        return False

    def __str__(self) -> str:
        """字符串表示"""
        return self.path


class IRConstraint(BaseModel):
    """约束信息"""
    # 原始文本（必须保留）
    raw_text: str = Field(..., description="原始约束文本片段")

    # 结构化约束（允许枚举或字符串，以支持动态扩展）
    type: Optional[Union[ConstraintType, str]] = Field(None, description="约束类型（枚举或自由文本）")
    value: Optional[Any] = Field(None, description="约束值")
    unit: Optional[str] = Field(None, description="单位（如 'bits', 'days', 'bytes'）")

    # 展开的定义（从引用展开）
    expanded: Optional[Dict[str, Any]] = Field(None, description="展开的定义内容（ABNF/Regex/摘要）")

    # 附加约束
    min_value: Optional[Union[int, float]] = Field(None, description="最小值")
    max_value: Optional[Union[int, float]] = Field(None, description="最大值")
    pattern: Optional[str] = Field(None, description="正则模式")
    allowed_values: Optional[List[str]] = Field(None, description="允许的值列表")
    asn1_types: Optional[List[str]] = Field(None, description="ASN.1 permitted encoding types (e.g. UTF8String, PrintableString)")

    class Config:
        use_enum_values = True
        extra = "allow"  # allow asn1_types and future constraint fields from LLM


class IRProvenance(BaseModel):
    """来源信息"""
    source_id: str = Field(..., description="来源文档ID")
    section: Optional[str] = Field(None, description="章节号")
    title: Optional[str] = Field(None, description="章节标题")
    line_start: Optional[int] = Field(None, description="起始行号")
    line_end: Optional[int] = Field(None, description="结束行号")
    chunk_id: Optional[str] = Field(None, description="Chunk ID")
    extractor_type: Optional[str] = Field(None, description="提取器类型")
    extraction_timestamp: Optional[datetime] = Field(None, description="提取时间")


class IRStage(str, Enum):
    """IR 处理阶段"""
    RAW = "raw"                 # 原始 IR，直接从提取器输出
    NORMALIZED = "normalized"   # 归一化 IR，经过字段路径和同义词归一化
    FINAL = "final"            # 最终 IR，经过引用展开、冲突检测等全流程


class AssertionSubject(str, Enum):
    """断言主体 - 规则约束的对象"""
    CERTIFICATE = "Certificate"        # 证书本身（可 lint — 仅凭单张证书字节可裁决）
    CRL = "CRL"                        # CRL 文档本身（可 lint — 单工件静态）
    CROSS_ARTIFACT = "CrossArtifact"   # 需跨证书/跨CRL/证书↔CRL 比对（不可 lint）
    IMPLEMENTATION = "Implementation"  # 实现/软件行为（不可 lint）
    CA = "CA"                         # CA 组织行为（不可 lint）
    RELYING_PARTY = "RelyingParty"    # 依赖方/验证方（不可 lint）


class EnforcementPhase(str, Enum):
    """执行阶段 - 约束在何时生效"""
    ENCODING = "Encoding"          # 证书编码时（可 lint）
    COMPARISON = "Comparison"      # 名称比较时（运行时，不可 lint）
    VALIDATION = "Validation"      # 证书验证时（运行时，不可 lint）
    PROCESSING = "Processing"      # 证书处理时（运行时，不可 lint）


# CheckScope removed (2026-06-28): merged into AssertionSubject as CrossArtifact.
# The lintability gate now checks assertion_subject in {Certificate, CA} for
# single-certificate observability (C2), which subsumes the former check_scope
# single_certificate gate. Cross-certificate rules are classified with
# assertion_subject = CrossArtifact and are correctly rejected by C2.

# Recognised certificate/CRL structural field ROOTS (first path segment of subject).
# Used by C2 subject_path gate: regardless of assertion_subject, the subject path
# must point to a real certificate/CRL field — rules whose subject is an operational
# noun (domain_validation_record, phone_contact, etc.) are about CA process, not
# certificate content, so NOT lintable.
_CERT_FIELD_ROOTS = frozenset({
    "certificate", "tbscertificate", "cert",
    "version", "serialnumber", "serial_number", "signature",
    "signaturealgorithm", "signaturevalue",
    "issuer", "validity", "notbefore", "notafter",
    "subject", "subjectpublickeyinfo", "publickey",
    "issueruniqueid", "subjectuniqueid", "extensions", "extension",
    "tbscertlist", "crl", "thisupdate", "nextupdate", "crlnumber",
    "revokedcertificates", "revokedcertificate", "crlextensions", "crlentry",
})

def _is_valid_subject_path(subject_path, assertion_subject) -> bool:
    """Return True iff the subject path points to a real certificate/CRL field.

    This gate catches rules whose assertion_subject is Certificate but whose
    subject is an operational noun (e.g. domain_validation_record, phone_contact) —
    those describe CA process, not certificate content, so NOT lintable.
    """
    if not subject_path:
        return False
    subj = getattr(subject_path, "path", str(subject_path or ""))
    if not subj:
        return False
    return subj.split(".")[0].lower() in _CERT_FIELD_ROOTS


# infer_logic_type_from_predicate 已删除 - 由 zlint generator 自己推断


# ── 前置条件（守卫）的封闭类型化模型 ────────────────────────────────────────
# 取代旧的松散 dict（{type, value, negate, description, trigger}）与分开、几乎
# 没用的 conditions 字段。叶子 kind 各映射到 rule_ir_to_dsl 的一个守卫原子；
# all_of / any_of 递归组合（"only basic fields" = 三条 field_present 的合取）；
# unstructured = 无法结构化成确定性守卫 —— 配合 DNE 判定即触发"该规则真该
# lintable 吗"的复核（见 feedback_dne_signals_lintability_review）。
CONDITION_KINDS = {
    # leaf — each maps to exactly one guard atom in _condition_to_guard
    "certificate_type",   # value: ca|root|subscriber|server|end_entity → IsCA/IsRootCA/...
    "extension_present",  # ext → ExtPresent
    "field_present",      # field (+negate) → FieldNonEmpty/FieldEmpty
    "field_equals",       # field, values → FieldEq/FieldInSet  (generalizes field_boolean)
    "version_is",         # values:[1|2|3] → FieldInSet(Version, …)
    "address_family",     # field, family:ipv4|ipv6 → SubtreeIPv4Conditional arm
    "key_usage",          # bit → KeyUsageHas
    "eku_present",        # eku → ExtKeyUsageHas
    "field_boolean",      # legacy: cA → IsCA / FieldEq(field, True)
    "unstructured",       # no guard; lint-ability review signal
    # composite — recurse
    "all_of",             # conditions → And(guards)
    "any_of",             # conditions → Or(guards)
}

_LEGACY_TYPE_TO_KIND = {
    "extension": "extension_present", "extension_present": "extension_present",
    "key_usage_bit": "key_usage", "key_usage": "key_usage",
    "extended_key_usage": "eku_present", "eku": "eku_present", "eku_present": "eku_present",
    "field_absent": "field_present", "field_empty": "field_present",
    "field_nonempty": "field_present", "field_present": "field_present",
    "certificate_type": "certificate_type", "field_boolean": "field_boolean",
    "version": "version_is", "field_value": "field_equals",
}


class Condition(BaseModel):
    """规则的前置条件（antecedent / 守卫），reducer 消费成 When(guard, main)。

    封闭枚举 kind（见 CONDITION_KINDS）。向后兼容：旧 dict（type/value/...）经
    before-validator 自动归一化为 kind；无 type 的纯散文 → unstructured。
    """
    kind: str = Field("unstructured", description="封闭集 CONDITION_KINDS 之一")
    field: Optional[str] = Field(None, description="字段名（field_present/field_equals/address_family）")
    value: Optional[str] = Field(None, description="单值（certificate_type: ca|root|subscriber|server|end_entity）")
    values: Optional[List[str]] = Field(None, description="值集（field_equals / version_is:[1|2|3]）")
    ext: Optional[str] = Field(None, description="扩展名/OID（extension_present）")
    bit: Optional[str] = Field(None, description="keyUsage 位名（key_usage）")
    eku: Optional[str] = Field(None, description="EKU 名/OID（eku_present）")
    family: Optional[str] = Field(None, description="ipv4|ipv6（address_family）")
    negate: bool = Field(False, description="取反守卫（'unless' / 'if NOT'）")
    conditions: Optional[List["Condition"]] = Field(None, description="子条件（all_of / any_of）")
    description: Optional[str] = None  # audit prose (non-structural)
    trigger: Optional[str] = None

    @model_validator(mode="before")
    @classmethod
    def _normalize_legacy(cls, data):
        """接受旧 dict：type→kind，散文（无 type/kind）→ unstructured。GENERAL。"""
        if not isinstance(data, dict):
            return data
        d = dict(data)
        d["negate"] = bool(d.get("negate"))   # legacy stores negate:null → False
        if not d.get("kind"):
            t = (d.get("type") or "").strip().lower()
            # legacy type → kind, OR a new-style type that is already a valid kind
            # (version_is / field_equals / address_family / all_of / any_of).
            kind = _LEGACY_TYPE_TO_KIND.get(t) or (t if t in CONDITION_KINDS else None)
            if kind:
                d["kind"] = kind
                if t in ("field_absent", "field_empty"):
                    d["negate"] = not bool(d.get("negate"))
                v = d.get("value")
                if v:
                    if kind == "field_present" and not d.get("field"):
                        d["field"] = v
                    elif kind == "extension_present" and not d.get("ext"):
                        d["ext"] = v
                    elif kind == "key_usage" and not d.get("bit"):
                        d["bit"] = v
                    elif kind == "eku_present" and not d.get("eku"):
                        d["eku"] = v
                    elif kind in ("version_is", "field_equals") and not d.get("values"):
                        d["values"] = [v]       # legacy single value → values list
                if kind == "version_is" and not d.get("field"):
                    d["field"] = "Version"
            else:
                d["kind"] = "unstructured"
        if d.get("kind") not in CONDITION_KINDS:
            d["kind"] = "unstructured"
        return d


Condition.model_rebuild()


class IntermediateRepresentation(BaseModel):
    """
    中间表示（IR）- 规则的结构化表示

    设计原则：
    1. IR 只表达"规则是什么"，不表达"如何处理规则"
    2. 临时处理标记不属于 IR（如 needs_split, is_composed）
    3. 下游工具的专用字段不属于 IR（如 check_oids, extension_oid_const）
    4. 可推断的字段不属于 IR（如 logic_type - 由 zlint generator 推断）
    """

    # === 元信息 ===
    rule_id: Optional[str] = Field(None, description="规则唯一ID")
    stage: IRStage = Field(IRStage.RAW, description="IR 处理阶段: raw/normalized/final")
    spec_family: Union[SpecFamily, str] = Field(
        SpecFamily.OTHER,
        description="规范体系：RFC/CABF/ETSI/Other"
    )

    # === 断言主体与执行阶段（新增 - 满足四个条件的关键）===
    assertion_subject: Union[AssertionSubject, str] = Field(
        AssertionSubject.CERTIFICATE,
        description="断言主体：Certificate（可lint）vs Implementation/CA（不可lint）"
    )
    enforcement_phase: Optional[Union[EnforcementPhase, str]] = Field(
        None,
        description="执行阶段：Encoding（可lint）vs Comparison/Validation（运行时，不可lint）"
    )

    # === 核心四元组 ===
    subject: Union[SubjectRef, str] = Field(..., description="主体（证书字段路径）")
    obligation: Union[ObligationType, str] = Field(..., description="义务类型（MUST/SHALL/SHOULD等）")
    predicate: Union[PredicateType, str] = Field(..., description="谓词（must_be_present/equal/conform_to等）")
    constraint: IRConstraint = Field(..., description="约束")

    # === 前置条件与依赖（新增 - 显式建模上下文依赖）===
    precondition: Optional[Condition] = Field(
        None,
        description=(
            "前置条件（规则的 antecedent / 守卫）= 类型化 Condition（封闭 kind，见 "
            "CONDITION_KINDS）。rule_ir_to_dsl._condition_to_guard 消费成 When(guard, main)。"
            "向后兼容：旧松散 dict（{type,value,negate,description,trigger}）由 Condition "
            "的 before-validator 自动归一化；无 type 的纯散文 → kind=unstructured。"
            "已吸收旧的 conditions 字段（合并为单一条件树）。"
        )
    )
    requires_operation: Optional[Dict[str, Any]] = Field(
        None,
        description="依赖的操作及其定义来源，如 {'operation': 'StringPrep', 'defined_in': 'RFC4518'}"
    )

    # === 引用与来源 ===
    references: List[IRReference] = Field(default_factory=list, description="引用列表")
    provenance: List[IRProvenance] = Field(default_factory=list, description="来源列表（支持多来源合并）")
    kg_links: Dict[str, List[str]] = Field(
        default_factory=dict,
        description="KG 节点链接，如 {'field': ['node:123'], 'concept': ['node:456']}"
    )

    # === 冲突信息（仅 final stage）===
    conflicts: List[Dict[str, Any]] = Field(
        default_factory=list,
        description="冲突列表（冲突规则ID、类型、原因）- 由规则引擎生成，非 LLM"
    )

    # === 文本 ===
    rule_text: Optional[str] = Field(None, description="原始规则文本")
    canonical_text: Optional[str] = Field(None, description="规范化的自然语言表述（仅 final stage）")

    # === 条件 ===
    conditions: Optional[List[Dict[str, Any]]] = Field(
        None,
        description="条件列表（if/unless/except）- 注意：不同于 precondition"
    )

    # === Lintable 判定（新增 - 显式标记是否可生成 zlint）===
    lintable: bool = Field(
        True,
        description="是否可生成 zlint（根据 assertion_subject 和 enforcement_phase 自动推断）"
    )
    non_lintable_reason: Optional[str] = Field(
        None,
        description="不可 lint 的原因（如 'Runtime comparison behavior not observable in certificate'）"
    )

    # === Rule Classification (Enhanced IR Extraction) ===
    rule_category: Optional[Union[RuleCategory, str]] = Field(
        None,
        description="Rule classification: encoding_constraint/definition/algorithm_ref/clarification/comparison/capability/display"
    )
    verifiability: Union[Verifiability, str] = Field(
        Verifiability.OBSERVABLE,
        description="Whether rule can be verified in certificate: observable/runtime_only/none"
    )

    # === Algorithm Reference & Overrides ===
    algorithm_ref: Optional[AlgorithmReference] = Field(
        None,
        description="Reference to external algorithm (e.g., RFC 3490 Section 4)"
    )
    overrides: List[Override] = Field(
        default_factory=list,
        description="List of overrides/clarifications to referenced algorithm steps"
    )

    # === Scope Inheritance Tracking ===
    keyword_source: str = Field(
        "direct",
        description="How the RFC2119 keyword was obtained: direct|inherited|normative_pattern"
    )
    parent_rule_id: Optional[str] = Field(
        None,
        description="Parent rule ID if keyword was inherited from a parent sentence"
    )
    scope_block_id: Optional[str] = Field(
        None,
        description="Scope block ID for grouped rules with shared parent (e.g., '7.2-scope-000')"
    )
    section_scope: Optional[str] = Field(
        None,
        description="Section-level scope shared by all IRs in a section (e.g., 'RFC5280-7.2')"
    )

    # === IR Eligibility Gate (问题4修复) ===
    ir_eligible: bool = Field(
        True,
        description="Whether this IR should be included in final output. False for capability/resource hints."
    )
    ir_ineligible_reason: Optional[str] = Field(
        None,
        description="Reason for IR ineligibility (e.g., 'capability rule - implementation design consideration')"
    )

    # === IR Pool Classification (问题3修复 - definition分离) ===
    ir_pool: str = Field(
        "rules",
        description="Which pool this IR belongs to: 'rules' (main pool for conflict/inheritance analysis) | 'definitions' (background knowledge, not for rule analysis) | 'background' (informational only)"
    )

    # === Lint Category (进一步分类 rules_pool 中的规则类型) ===
    lint_category: Optional[Union[LintCategory, str]] = Field(
        None,
        description=(
            "Further classification within rules_pool: "
            "static_verifiable (certificate-observable) | "
            "runtime_semantic (comparison/validation behavior) | "
            "implementation_guidance (capability/display requirements) | "
            "definition (semantic definitions)"
        )
    )

    @model_validator(mode='before')
    @classmethod
    def normalize_subject(cls, data: Any) -> Any:
        """将 subject 字符串自动转换为 SubjectRef（向后兼容）"""
        if isinstance(data, dict) and 'subject' in data:
            subject = data['subject']
            if isinstance(subject, str):
                data['subject'] = SubjectRef.from_string(subject)
            elif isinstance(subject, dict) and 'path' not in subject:
                data['subject'] = SubjectRef.from_string(str(subject))
        return data

    @model_validator(mode='after')
    def auto_determine_lintable(self) -> 'IntermediateRepresentation':
        """
        Determine lintability based on classification and verifiability.

        A rule is lintable if ALL of the following four conditions are met:
        1. Obligation is normative (RFC 2119 levels except MAY/OPTIONAL;
           SHOULD/RECOMMENDED count, mapping to warning-level lints)
        2. Assertion subject is Certificate (constrains certificate content;
           CRL is OUT OF SCOPE — a CRL is a separate artifact, not a certificate lint;
           CA is OUT OF SCOPE — a CA is an organization, its behavior is not in certificate bytes;
           cross-artifact rules — assertion_subject = CrossArtifact — are excluded).
        3. Rule category allows linting (whitelist: encoding/structural; not
           DEFINITION/ALGORITHM_REF/CAPABILITY/DISPLAY/COMPARISON/CLARIFICATION
           or historical non-lintable aliases)
        4. Enforcement phase is Encoding (or unset), not a runtime phase

        verifiability/observable is intentionally NOT a gate (redundant; subsumed
        by assertion_subject). This implements the zlint single-artifact static
        boundary: assertion_subject == Certificate implies single-certificate.
        """
        # 如果用户已经显式设置了 lintable，则不覆盖
        if hasattr(self, '_lintable_explicitly_set'):
            return self

        reasons = []

        # Rule 1: Must be normative (RFC 2119 except MAY/OPTIONAL).
        # SHOULD / SHOULD NOT / RECOMMENDED may still be lintable when the
        # remaining conditions make them deterministically checkable; they map
        # to warning-level lints rather than error-level lints.
        normative_obligations = {
            "MUST", "MUST NOT", "MUST_NOT",
            "SHALL", "SHALL NOT", "SHALL_NOT",
            "SHOULD", "SHOULD NOT", "SHOULD_NOT",
            "RECOMMENDED", "NOT RECOMMENDED", "NOT_RECOMMENDED",
        }
        obligation_str = self.obligation.value if isinstance(self.obligation, ObligationType) else str(self.obligation)
        is_normative = obligation_str.upper().replace(" ", "_") in normative_obligations or \
                       obligation_str.upper() in normative_obligations

        if not is_normative:
            reasons.append(f"Non-normative obligation: {obligation_str}")

        # Rule 2 (renumbered from old Rule 3): Must constrain certificate content
        # (single-certificate observable). CA is OUT OF SCOPE: a CA is an organization
        # — its behavior is not in certificate bytes. Even when a rule says "CA MUST
        # include extension X", the assertion_subject should be Certificate (the
        # constraint manifests in the certificate), not CA. CRL is OUT OF SCOPE: a CRL
        # is a separate artifact. Cross-artifact rules (assertion_subject = CrossArtifact)
        # are rejected here.
        #
        # Subsumes the former check_scope single_certificate gate:
        # assertion_subject == Certificate is equivalent to single-certificate
        # observability. Rules with assertion_subject = CrossArtifact (cross-certificate
        # uniqueness, SKI=AKI matching, etc.) are rejected here.
        # Subject path gate further rejects rules whose subject points to an operational
        # noun (domain_validation_record, phone_contact) — those are CA process, not
        # certificate content.
        assertion_str = self.assertion_subject.value if isinstance(self.assertion_subject, AssertionSubject) else str(self.assertion_subject)
        constrains_certificate = assertion_str == "Certificate"

        if not constrains_certificate:
            if assertion_str == "CrossArtifact":
                reasons.append(f"Assertion subject is '{assertion_str}' (cross-artifact), not 'Certificate'/'CA'")
            else:
                reasons.append(f"Assertion subject is '{assertion_str}', not 'Certificate'/'CA'")

        # Subject path gate: regardless of assertion_subject, the subject must point
        # to a real certificate/CRL field. Rules whose subject is an operational noun
        # (domain_validation_record, phone_contact, etc.) describe CA process, not
        # certificate content — NOT lintable.
        subject_path = getattr(self, "subject", "")
        if constrains_certificate and not _is_valid_subject_path(subject_path, assertion_str):
            reasons.append(f"Subject path '{subject_path}' does not map to a certificate/CRL field")
            constrains_certificate = False

        # Rule 4: Category-based filtering (RELAXED: explicit whitelist + blacklist)
        # Whitelist: categories that are definitely lintable
        lintable_categories = {
            RuleCategory.ENCODING_CONSTRAINT, "encoding_constraint",
            "structural_constraint",
        }

        # Blacklist: categories that are definitely NOT lintable
        non_lintable_categories = {
            RuleCategory.DEFINITION, RuleCategory.ALGORITHM_REF,
            RuleCategory.CAPABILITY, RuleCategory.DISPLAY,
            "definition", "algorithm_ref", "capability", "display",
            # Historical aliases
            "procedural", "operational", "precondition",
            "external_validation", "implementation_process", "delegation",
            # Clarification is generally not lintable
            RuleCategory.CLARIFICATION, "clarification",
        }

        category_allows_lint = True
        if self.rule_category:
            category_value = self.rule_category.value if isinstance(self.rule_category, RuleCategory) else str(self.rule_category)

            # If in whitelist, definitely allow
            if self.rule_category in lintable_categories or category_value in lintable_categories:
                category_allows_lint = True
            # If in blacklist, definitely deny
            elif self.rule_category in non_lintable_categories or category_value in non_lintable_categories:
                category_allows_lint = False
                reasons.append(f"Rule category '{category_value}' is not lintable")
            # For COMPARISON: NEVER lintable (runtime behavior, not certificate constraint)
            elif category_value == "comparison" or self.rule_category == RuleCategory.COMPARISON:
                category_allows_lint = False
                reasons.append(f"Rule category 'comparison' is runtime behavior, not lintable")
            # Default: deny (only whitelist is lintable)
            else:
                category_allows_lint = False
                reasons.append(f"Rule category '{category_value}' not in lintable whitelist")

        # Rule 5: Enforcement phase check (RELAXED: allow missing phase)
        # If enforcement_phase is not set, don't penalize
        phase_blocks_lint = False
        if self.enforcement_phase:
            phase_str = self.enforcement_phase.value if isinstance(self.enforcement_phase, EnforcementPhase) else str(self.enforcement_phase)
            # Only block if explicitly set to non-Encoding phase
            if phase_str not in ["Encoding", "encoding"]:
                phase_blocks_lint = True
                reasons.append(f"Enforcement phase is '{phase_str}' (runtime), not observable in certificate")

        # Negative gate: high-precision NON-observable patterns (CA process /
        # user behavior / randomness / cross-cert-runtime / real-world semantic
        # content) the LLM-labeled axes miss. Validated to demote ZERO codegen-
        # proven-synonymous rules. Stops "can't be coded" rules reaching codegen.
        from app.services.extraction.lintability_guard import (
            definitely_not_single_artifact_lintable as _dnl)
        not_observable = _dnl(getattr(self, "rule_text", "") or "")
        if not_observable:
            reasons.append("rule text describes a non-single-certificate-observable "
                           "requirement (CA process / runtime / cross-cert / "
                           "real-world semantic content)")

        # Determine final lintability.
        # NOTE: observable/verifiability is intentionally NOT a conjunct (see Rule 2).
        # The four classic gates (normative, subject, category, phase) PLUS
        # the non-observable negative gate.
        self.lintable = (
            is_normative and
            constrains_certificate and
            category_allows_lint and
            not phase_blocks_lint and
            not not_observable
        )

        if not self.lintable and reasons:
            self.non_lintable_reason = "; ".join(reasons)

        # === IR Eligibility Gate (问题4修复) ===
        # 某些规则虽然是 MUST，但不该进入 IR 层（实现能力提醒/资源需求等）
        ineligible_categories = {
            RuleCategory.CAPABILITY, "capability"  # "MUST allow for increased space" 等
        }

        if self.rule_category:
            category_value = self.rule_category.value if isinstance(self.rule_category, RuleCategory) else str(self.rule_category)
            if self.rule_category in ineligible_categories or category_value in ineligible_categories:
                self.ir_eligible = False
                self.ir_ineligible_reason = f"Category '{category_value}' is an implementation design consideration, not a verifiable rule"

        # === IR Pool Classification (问题3修复 - definition分离) ===
        # definition 类 IR 不应参与冲突分析、规则继承等
        definition_categories = {
            RuleCategory.DEFINITION, "definition"
        }

        if self.rule_category:
            category_value = self.rule_category.value if isinstance(self.rule_category, RuleCategory) else str(self.rule_category)
            if self.rule_category in definition_categories or category_value in definition_categories:
                self.ir_pool = "definitions"

        return self

    class Config:
        use_enum_values = True

    def _get_subject_path(self) -> str:
        """
        获取 subject 的路径字符串（兼容 SubjectRef 和 str）

        Returns:
            subject 路径字符串
        """
        if isinstance(self.subject, SubjectRef):
            return self.subject.path
        elif isinstance(self.subject, str):
            return self.subject
        else:
            return str(self.subject) if self.subject else ""

    def _get_subject_ref_dict(self) -> Optional[Dict[str, Any]]:
        """
        获取 SubjectRef 的字典表示（用于前端显示详细信息）

        Returns:
            SubjectRef 字典或 None（如果是纯字符串）
        """
        if isinstance(self.subject, SubjectRef):
            return {
                "path": self.subject.path,
                "aliases": self.subject.aliases,  # Fix #5: Include aliases
                "field_id": self.subject.field_id,
                "raw": self.subject.raw,
                "resolved": self.subject.resolved,
                "resolution_method": self.subject.resolution_method,
            }
        return None

    def _build_lint_name(self, subject_path: str) -> str:
        """
        Build a unique lint_name using multiple context sources.

        Priority order:
        1. precondition.trigger (e.g., "equality check", "name constraints")
        2. rule_category (e.g., "comparison", "algorithm_ref", "display")
        3. Description keywords (e.g., "ToASCII", "ToUnicode", "case-insensitive")
        4. Constraint value (e.g., "stored string", "ASCII characters")

        Format: {subject}_{predicate}[_{context}]
        Examples:
          - implementation_must_perform_equality_comparison
          - implementation_must_perform_name_constraint_evaluation
          - implementation_must_perform_toascii_dn
          - extensions.subjectAltName.dNSName_must_be_considered_step1
        """
        import re

        if not subject_path or not self.predicate:
            return "unnamed"

        predicate_str = self.predicate.value if hasattr(self.predicate, 'value') else str(self.predicate)
        base = f"{subject_path}_{predicate_str}"

        context_parts = []

        # Source 1: precondition (highest priority)
        if self.precondition and isinstance(self.precondition, dict):
            trigger = self.precondition.get('trigger', '') or ''
            if trigger:
                context_parts.append(self._normalize_context(trigger))

        # Source 2: Description keywords (higher priority than generic rule_category)
        if not context_parts:
            description = getattr(self, 'rule_text', '') or getattr(self, 'description', '') or ''
            desc_lower = description.lower()

            # Extract distinguishing keywords - ordered by specificity
            # Network/IP related
            if 'ipv6' in desc_lower or 'ip version 6' in desc_lower:
                context_parts.append('ipv6')
            elif 'ipv4' in desc_lower or 'ip version 4' in desc_lower:
                context_parts.append('ipv4')
            elif 'ipaddress' in desc_lower or 'ip address' in desc_lower:
                if 'cidr' in desc_lower or 'address range' in desc_lower:
                    context_parts.append('ipaddress_cidr')
                elif 'syntax' in desc_lower:
                    context_parts.append('ipaddress_syntax')
                elif 'reject' in desc_lower:
                    context_parts.append('ipaddress_reject')
                elif 'able to process' in desc_lower:
                    context_parts.append('ipaddress_app_process')
                else:
                    context_parts.append('ipaddress')
            # Mail related
            elif 'rfc822' in desc_lower or 'mail address' in desc_lower or 'mailbox' in desc_lower:
                if 'emailaddress' in desc_lower or 'email' in desc_lower:
                    context_parts.append('rfc822name_emailattr')
                elif 'constraint' in desc_lower and 'particular' not in desc_lower:
                    context_parts.append('rfc822name_constraint')
                elif 'particular mailbox' in desc_lower or 'all addresses' in desc_lower:
                    context_parts.append('rfc822name_forms')
                else:
                    context_parts.append('rfc822name')
            # URI related
            elif 'uniformresourceidentifier' in desc_lower or ('uri' in desc_lower and 'relative' not in desc_lower):
                if 'reject' in desc_lower:
                    context_parts.append('uri_reject')
                elif 'authority' in desc_lower:
                    context_parts.append('uri_authority')
                elif 'scheme' in desc_lower:
                    context_parts.append('uri_scheme')
                elif 'constraint' in desc_lower:
                    context_parts.append('uri_constraint')
                else:
                    context_parts.append('uri')
            elif 'relative uri' in desc_lower:
                context_parts.append('uri_not_relative')
            # DNS related
            elif 'dnsname' in desc_lower and 'empty' in desc_lower:
                context_parts.append('dnsname_not_empty')
            elif 'preferred name syntax' in desc_lower:
                context_parts.append('dnsname_syntax')
            elif 'wildcard' in desc_lower:
                context_parts.append('wildcard')
            # Directory/DN related
            elif 'directoryname' in desc_lower:
                if 'subject field' in desc_lower:
                    context_parts.append('directoryname_subject')
                elif 'compare' in desc_lower or 'comparison' in desc_lower:
                    context_parts.append('directoryname_comparison')
                elif 'should not rely' in desc_lower or 'ca' in desc_lower[:50].lower():
                    context_parts.append('directoryname_ca_encoding')
                else:
                    context_parts.append('directoryname')
            # CA certificate specific
            elif 'ca certificate' in desc_lower:
                context_parts.append('ca_only')
            # Name constraints specific
            elif 'permittedsubtrees' in desc_lower and 'excludedsubtrees' in desc_lower:
                context_parts.append('subtrees_required')
            elif 'permittedsubtrees' in desc_lower:
                context_parts.append('permitted')
            elif 'excludedsubtrees' in desc_lower:
                context_parts.append('excluded')
            # Constraint format
            elif 'minimum' in desc_lower and 'zero' in desc_lower:
                context_parts.append('minimum_zero')
            elif 'maximum' in desc_lower and 'absent' in desc_lower:
                context_parts.append('maximum_absent')
            # General encoding
            elif 'network byte order' in desc_lower:
                context_parts.append('network_byte_order')
            elif 'octet string' in desc_lower or 'octets' in desc_lower:
                if 'four' in desc_lower or '4' in desc_lower:
                    context_parts.append('four_octets')
                elif 'sixteen' in desc_lower or '16' in desc_lower:
                    context_parts.append('sixteen_octets')
                elif 'eight' in desc_lower or '8' in desc_lower:
                    context_parts.append('eight_octets')
                elif 'thirty' in desc_lower or '32' in desc_lower:
                    context_parts.append('thirtytwo_octets')
                else:
                    context_parts.append('octets')
            # Criticality
            elif 'marked as critical' in desc_lower or 'critical' in desc_lower:
                if 'non-critical' in desc_lower:
                    context_parts.append('non_critical')
                elif 'minimum or maximum' in desc_lower:
                    context_parts.append('critical_minmax')
                elif 'process the constraint' in desc_lower or 'reject the certificate' in desc_lower:
                    context_parts.append('critical_process')
                else:
                    context_parts.append('critical')
            # Empty/presence checks
            elif 'empty sequence' in desc_lower or 'empty' in desc_lower:
                context_parts.append('not_empty')
            elif 'at least one' in desc_lower:
                context_parts.append('at_least_one')
            # Existing patterns
            elif 'equality' in desc_lower or 'for equality' in desc_lower:
                context_parts.append('equality_comparison')
            elif 'name constraint' in desc_lower or 'evaluating name' in desc_lower:
                context_parts.append('name_constraint_evaluation')
            elif 'in step' in desc_lower:
                step_match = re.search(r'in step\s*(\d+)', desc_lower)
                if step_match:
                    context_parts.append(f'step{step_match.group(1)}')
            elif 'toascii' in desc_lower:
                if 'distinguished name' in desc_lower or ' dn' in desc_lower or 'domaincomponent' in desc_lower:
                    context_parts.append('toascii_dn')
                else:
                    context_parts.append('toascii')
            elif 'tounicode' in desc_lower:
                context_parts.append('tounicode')
            elif 'display' in desc_lower:
                context_parts.append('display')
            elif 'storage' in desc_lower or 'before storage' in desc_lower:
                context_parts.append('storage')
            # Verified by CA
            elif 'verified by the ca' in desc_lower:
                context_parts.append('ca_verified')
            # Application requirements
            elif 'able to process' in desc_lower or 'must be able' in desc_lower:
                context_parts.append('app_process_capability')
            elif 'should be able' in desc_lower:
                context_parts.append('app_should_process')

        # Source 3: rule_category (fallback for non-generic categories)
        if not context_parts and self.rule_category:
            category = self.rule_category.value if hasattr(self.rule_category, 'value') else str(self.rule_category)
            # Skip overly generic categories that don't help distinguish rules
            if category not in ('definition', 'algorithm_ref', 'comparison', 'clarification', 'certificate_field', 'encoding_constraint'):
                context_parts.append(category)

        # Source 4: Constraint value
        if not context_parts and self.constraint:
            constraint_value = getattr(self.constraint, 'value', None)
            if constraint_value and isinstance(constraint_value, str):
                context_parts.append(self._normalize_context(constraint_value[:20]))

        # Source 5: Description hash (last resort for uniqueness)
        if not context_parts:
            description = getattr(self, 'rule_text', '') or getattr(self, 'description', '') or ''
            if description:
                import hashlib
                desc_hash = hashlib.md5(description.encode()).hexdigest()[:6]
                context_parts.append(f'h{desc_hash}')

        # Build final name
        if context_parts:
            context = '_'.join(context_parts)
            return f"{base}_{context}"

        return base

    def _normalize_context(self, text: str) -> str:
        """Normalize context string for use in lint_name."""
        import re
        # Remove quotes, clean whitespace, limit length
        text = re.sub(r'["\']', '', text)
        text = re.sub(r'[^a-zA-Z0-9_\s]', '', text)
        text = text.strip().lower().replace(' ', '_')
        if len(text) > 25:
            text = text[:25]
        return text

    def _format_algorithm_ref(self) -> Optional[Dict[str, Any]]:
        """
        Format algorithm_ref for frontend, including step_modifications.

        This upgrades from "text-level reference" to "rule-level reference"
        by including structured step modifications.
        """
        if not self.algorithm_ref:
            return None

        result = {
            "base_spec": self.algorithm_ref.base_spec,
            "section": self.algorithm_ref.section,
            "operation": self.algorithm_ref.operation,
            "inheritance": self.algorithm_ref.inheritance,
            "relation_type": self.algorithm_ref.relation_type if isinstance(
                self.algorithm_ref.relation_type, str
            ) else self.algorithm_ref.relation_type.value,
        }

        # Include step_modifications if present (rule-level reference)
        if self.algorithm_ref.step_modifications:
            result["step_modifications"] = [
                {
                    "step": mod.step,
                    "param": mod.param,
                    "original_value": mod.original_value,
                    "override_value": mod.override_value,
                    "modification_type": mod.modification_type,
                    "source_text": mod.source_text,
                }
                for mod in self.algorithm_ref.step_modifications
            ]

        return result

    def to_frontend_format(self) -> Dict[str, Any]:
        """
        将 IR 对象转换为前端期望的格式

        前端期望格式：
        {
            "parsed": {...},  # 解析后的结构化信息
            "ir": {...},      # IR核心信息
            "clauses": [...]  # 语义切片（如果有）
        }
        """
        # 获取 subject 路径字符串（兼容 SubjectRef 和 str）
        subject_path = self._get_subject_path()

        # 提取字段和操作符
        fields = [subject_path] if subject_path else []
        operators = [self.predicate] if self.predicate else []

        # 构建 parsed 部分（简化）
        parsed = {
            "fields": fields,
            "operators": operators,
            "rule_type": self.constraint.type if self.constraint and self.constraint.type else "unknown",
            "lintable": self.lintable,
            "lintable_reason": self.non_lintable_reason or "Lintable",
            "conditions": self.conditions or []
        }

        # 构建 ir 部分
        # lint_name 需要包含 precondition context 来区分相似规则
        lint_name = self._build_lint_name(subject_path)
        ir_section = {
            "lint_name": lint_name,
            "description": self.canonical_text or self.rule_text or "",
            "applies_to": getattr(self, "applies_to", None) or "All",
            "citation": self.provenance[0].section if self.provenance and len(self.provenance) > 0 else "",
            "effective_date": None,
            "subject": subject_path,
            "subject_ref": self._get_subject_ref_dict(),

            # 规范体系信息
            "spec_family": self.spec_family if isinstance(self.spec_family, str) else self.spec_family.value,

            # 核心四元组
            "obligation": self.obligation,
            "predicate": self.predicate,
            "constraint": self.constraint.model_dump() if self.constraint else {},

            # 新增：断言主体与执行阶段
            "assertion_subject": self.assertion_subject if isinstance(self.assertion_subject, str) else self.assertion_subject.value,
            "enforcement_phase": self.enforcement_phase if isinstance(self.enforcement_phase, str) else (self.enforcement_phase.value if self.enforcement_phase else None),


            # 前置条件与依赖
            "precondition": (self.precondition.model_dump(exclude_none=True)
                             if self.precondition else None),
            "requires_operation": self.requires_operation,

            # Lintable 判定
            "lintable": self.lintable,
            "non_lintable_reason": self.non_lintable_reason,

            # 引用与来源
            "references": [r.model_dump() for r in self.references],
            "kg_links": self.kg_links,

            # 冲突信息
            "conflicts": self.conflicts,

            # Enhanced IR fields: Rule Classification
            "rule_category": self.rule_category if isinstance(self.rule_category, str) else (self.rule_category.value if self.rule_category else None),
            "lint_category": self.lint_category if isinstance(self.lint_category, str) else (self.lint_category.value if self.lint_category else None),
            "verifiability": self.verifiability if isinstance(self.verifiability, str) else self.verifiability.value,

            # Enhanced IR fields: Algorithm Reference & Overrides
            "algorithm_ref": self._format_algorithm_ref() if self.algorithm_ref else None,
            "overrides": [o.model_dump() for o in self.overrides] if self.overrides else [],

            # Enhanced IR fields: Scope Inheritance
            "keyword_source": self.keyword_source,
            "parent_rule_id": self.parent_rule_id,
            "scope_block_id": self.scope_block_id,
            "section_scope": self.section_scope,

            # IR Eligibility Gate
            "ir_eligible": self.ir_eligible,
            "ir_ineligible_reason": self.ir_ineligible_reason,

            # IR Pool Classification
            "ir_pool": self.ir_pool,
        }

        # 构建 clauses 部分（如果有条件，则作为 clause）
        clauses = []
        if self.conditions:
            for cond in self.conditions:
                clauses.append({
                    "clause": str(cond)
                })

        return {
            "parsed": parsed,
            "ir": ir_section,
            "clauses": clauses
        }

    def recompute_lintable(self) -> "IntermediateRepresentation":
        """Recompute lintability after in-place canonicalization/mutation."""
        if hasattr(self, '_lintable_explicitly_set'):
            delattr(self, '_lintable_explicitly_set')
        return self.auto_determine_lintable()

    def to_json(self) -> str:
        """
        将IR对象转换为JSON字符串（前端格式）

        兼容旧代码中调用 ir.to_json() 的地方
        返回前端期望的格式，而不是原始Pydantic序列化
        """
        import json
        return json.dumps(self.to_frontend_format(), ensure_ascii=False, indent=None)

    def to_normalized(self) -> "IntermediateRepresentation":
        """标记为 normalized 阶段"""
        self.stage = IRStage.NORMALIZED
        return self

    def to_final(self) -> "IntermediateRepresentation":
        """标记为 final 阶段"""
        self.stage = IRStage.FINAL
        return self


class ExtractionResult(BaseModel):
    """提取结果包装"""
    ir: Optional[IntermediateRepresentation] = Field(None, description="IR 对象（提取失败时为 None）")


class ReferenceEnrichmentQueueItem(BaseModel):
    """引用丰富队列项"""
    rule_id: str = Field(..., description="规则ID")
    reference: IRReference = Field(..., description="未解析的引用")
    priority: int = Field(0, description="优先级")
    retry_count: int = Field(0, description="重试次数")
    created_at: datetime = Field(default_factory=datetime.now, description="创建时间")


# compute_extraction_confidence 已删除 - 不再使用 extraction_confidence 字段
