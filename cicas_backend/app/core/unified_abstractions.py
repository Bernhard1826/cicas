"""
统一抽象层 - Web PKI 规则工程系统的核心数据抽象

本模块定义了所有规则、文档、引用和冲突的统一抽象，
禁止任何基于文档类型的硬编码特判逻辑。

设计原则：
1. 通用性：不对任何文档类型（CABF/RFC/ETSI/Browser Policy）做硬编码
2. 确定性：所有判定必须基于逻辑，而非概率
3. 完备性：覆盖所有可形式化的规则关系
4. 分层清晰：引用检测是基础，冲突检测基于IR和引用结果
"""

from typing import Optional, List, Dict, Any, Set, Union
from enum import Enum
from pydantic import BaseModel, Field
from datetime import datetime


# ============================================================
# 第一层：文档抽象（Document Abstraction）
# ============================================================

class DocumentType(str, Enum):
    """
    文档类型枚举

    WARNING: 此枚举仅用于元数据标记，禁止用于业务逻辑判断。
    所有业务逻辑必须基于 DocumentTypeRegistry 的能力声明。
    """
    RFC = "RFC"
    CABF_BR = "CABF-BR"  # CA/Browser Forum Baseline Requirements
    CABF_EV = "CABF-EV"  # CA/Browser Forum EV Guidelines
    CABF_CS = "CABF-CS"  # CA/Browser Forum Code Signing
    ETSI_EN = "ETSI-EN"  # ETSI European Norms
    ETSI_TS = "ETSI-TS"  # ETSI Technical Specifications
    MOZILLA = "Mozilla"  # Mozilla Root Store Policy
    APPLE = "Apple"      # Apple Root Certificate Program
    MICROSOFT = "Microsoft"  # Microsoft Trusted Root Program
    CHROME = "Chrome"    # Chrome Root Store Policy
    CUSTOM = "Custom"    # Custom/Internal standards


class DocumentMetadata(BaseModel):
    """文档元数据（不可变属性）"""
    document_id: str = Field(..., description="文档唯一标识符，如 'RFC5280', 'CABF-BR-2.0.5'")
    document_type: DocumentType = Field(..., description="文档类型")
    title: str = Field(..., description="文档标题")
    version: Optional[str] = Field(None, description="版本号")
    publish_date: Optional[datetime] = Field(None, description="发布日期")
    effective_date: Optional[datetime] = Field(None, description="生效日期")
    supersedes: Optional[List[str]] = Field(default_factory=list, description="替代的文档ID列表")
    url: Optional[str] = Field(None, description="官方URL")

    class Config:
        use_enum_values = True


class DocumentTypeRegistry:
    """
    文档类型注册表

    提供文档类型的能力声明，替代硬编码的 if-else 判断。
    所有文档类型的特性必须通过注册表查询，而非硬编码。
    """

    def __init__(self):
        # 优先级定义（数值越大优先级越高）
        self._priority_map: Dict[DocumentType, int] = {
            DocumentType.CUSTOM: 100,      # 最高优先级
            DocumentType.MOZILLA: 90,
            DocumentType.APPLE: 90,
            DocumentType.MICROSOFT: 90,
            DocumentType.CHROME: 90,
            DocumentType.CABF_BR: 80,
            DocumentType.CABF_EV: 80,
            DocumentType.CABF_CS: 80,
            DocumentType.ETSI_EN: 70,
            DocumentType.ETSI_TS: 70,
            DocumentType.RFC: 60,          # 基础标准，最低优先级
        }

        # 细化关系（refinement）：哪些文档类型细化了哪些基础标准
        self._refinement_map: Dict[DocumentType, Set[DocumentType]] = {
            DocumentType.CABF_BR: {DocumentType.RFC},
            DocumentType.CABF_EV: {DocumentType.RFC, DocumentType.CABF_BR},
            DocumentType.CABF_CS: {DocumentType.RFC},
            DocumentType.MOZILLA: {DocumentType.RFC, DocumentType.CABF_BR},
            DocumentType.APPLE: {DocumentType.RFC, DocumentType.CABF_BR},
            DocumentType.MICROSOFT: {DocumentType.RFC, DocumentType.CABF_BR},
            DocumentType.CHROME: {DocumentType.RFC, DocumentType.CABF_BR},
            DocumentType.ETSI_EN: {DocumentType.RFC},
            DocumentType.ETSI_TS: {DocumentType.RFC},
        }

    def get_priority(self, doc_type: DocumentType) -> int:
        """获取文档类型的优先级"""
        return self._priority_map.get(doc_type, 50)

    def is_refinement(self, derived: DocumentType, base: DocumentType) -> bool:
        """
        判断 derived 是否是 base 的细化

        例如：CABF-BR 是 RFC 的细化
        """
        return base in self._refinement_map.get(derived, set())

    def get_refinement_chain(self, doc_type: DocumentType) -> List[DocumentType]:
        """
        获取文档类型的细化链

        返回：从当前类型到基础标准的细化链
        例如：CABF-EV -> [CABF-EV, CABF-BR, RFC]
        """
        chain = [doc_type]
        current = doc_type

        while current in self._refinement_map:
            bases = self._refinement_map[current]
            if not bases:
                break
            # 选择优先级最低的作为基础（通常是RFC）
            next_base = min(bases, key=lambda x: self.get_priority(x))
            chain.append(next_base)
            current = next_base

        return chain


# ============================================================
# 第二层：规则抽象（Rule Abstraction）
# ============================================================

class Modality(str, Enum):
    """
    模态类型（RFC 2119 + 扩展）

    定义规则的强制程度
    """
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
    NOT_RECOMMENDED = "NOT RECOMMENDED"


class ConstraintOperator(str, Enum):
    """约束操作符（统一各种谓词）"""
    # 存在性
    MUST_BE_PRESENT = "must_be_present"
    MUST_NOT_BE_PRESENT = "must_not_be_present"

    # 包含
    MUST_INCLUDE = "must_include"
    MUST_NOT_INCLUDE = "must_not_include"

    # 相等
    EQUAL = "equal"
    NOT_EQUAL = "not_equal"

    # 比较
    LESS_THAN = "less_than"
    LESS_THAN_OR_EQUAL = "less_than_or_equal"
    GREATER_THAN = "greater_than"
    GREATER_THAN_OR_EQUAL = "greater_than_or_equal"
    IN_RANGE = "in_range"

    # 模式匹配
    MATCHES_PATTERN = "matches_pattern"
    CONFORMS_TO = "conforms_to"

    # 枚举
    ALLOWED_VALUES = "allowed_values"
    FORBIDDEN_VALUES = "forbidden_values"


class ConditionSet(BaseModel):
    """
    条件集合

    表示规则的适用条件（if/when/unless/except）
    """
    conditions: List[Dict[str, Any]] = Field(default_factory=list, description="条件列表")
    logic: str = Field("AND", description="条件逻辑：AND/OR")

    def is_empty(self) -> bool:
        """判断条件集是否为空（即无条件规则）"""
        return len(self.conditions) == 0

    def intersects_with(self, other: "ConditionSet") -> bool:
        """
        判断两个条件集是否有交集

        TODO: 实现基于 SMT 求解器的条件交集判定
        当前简化实现：空条件集与任何条件集都有交集
        """
        if self.is_empty() or other.is_empty():
            return True

        # 简化实现：条件集有任何相同元素即认为有交集
        self_set = {str(c) for c in self.conditions}
        other_set = {str(c) for c in other.conditions}
        return len(self_set & other_set) > 0


class UnifiedRule(BaseModel):
    """
    统一规则抽象

    所有规则（无论来源）都必须规范化为此结构。
    禁止基于 document_id 或 section_id 的特判逻辑。
    """
    # 唯一标识
    rule_id: str = Field(..., description="规则唯一ID")

    # 来源元数据
    document_id: str = Field(..., description="来源文档ID")
    section_id: Optional[str] = Field(None, description="章节ID")

    # 核心三元组
    subject: str = Field(..., description="主体（证书字段路径）")
    predicate: ConstraintOperator = Field(..., description="谓词（操作符）")
    object: Any = Field(..., description="客体（约束值）")

    # 条件集
    condition_set: ConditionSet = Field(default_factory=ConditionSet, description="条件集合")

    # 模态
    modality: Modality = Field(..., description="模态（MUST/SHOULD/MAY）")

    # 原始文本（追溯性）
    rule_text: str = Field(..., description="原始规则文本")

    # 引用信息（由引用检测器填充）
    references: List["RuleReference"] = Field(default_factory=list, description="引用列表")

    # 验证状态
    verified: bool = Field(False, description="是否经过验证")

    # 元数据
    metadata: Dict[str, Any] = Field(default_factory=dict, description="额外元数据")

    class Config:
        use_enum_values = True

    def get_constraint_space(self) -> Dict[str, Any]:
        """
        获取约束空间

        返回：{subject, predicate, object, conditions}
        用于冲突检测的可满足性判定
        """
        return {
            "subject": self.subject,
            "predicate": self.predicate,
            "object": self.object,
            "conditions": self.condition_set.conditions
        }


# ============================================================
# 第三层：引用抽象（Reference Abstraction）
# ============================================================

class ReferenceType(str, Enum):
    """
    引用类型

    定义引用的语义关系，而非语法形式
    """
    REFERENCE_ONLY = "reference_only"  # 纯引用声明，不重申内容
    REFERENCE_WITH_RESTATEMENT = "reference_with_restatement"  # 引用并重申
    REFERENCE_WITH_RESTRICTION = "reference_with_restriction"  # 引用并收紧
    REFERENCE_WITH_OVERRIDE = "reference_with_override"  # 引用并覆盖
    AMBIGUOUS_REFERENCE = "ambiguous_reference"  # 模糊引用（无法明确类型）


class ReferenceRelationship(str, Enum):
    """引用关系"""
    CITES = "cites"  # 引用
    REFINES = "refines"  # 细化
    OVERRIDES = "overrides"  # 覆盖
    CONFLICTS_WITH = "conflicts_with"  # 冲突


class RuleReference(BaseModel):
    """
    规则引用

    表示 Rule A 引用 Rule B 的关系
    """
    source_rule_id: str = Field(..., description="源规则ID")
    target_document_id: str = Field(..., description="目标文档ID")
    target_section_id: Optional[str] = Field(None, description="目标章节ID")
    target_rule_id: Optional[str] = Field(None, description="目标规则ID（如果已解析）")

    # 引用类型
    reference_type: ReferenceType = Field(..., description="引用类型")
    relationship: ReferenceRelationship = Field(ReferenceRelationship.CITES, description="引用关系")

    # 引用文本
    raw_reference_text: str = Field(..., description="原始引用文本，如 'RFC 5280 Section 4.2'")

    # 解析状态
    resolved: bool = Field(False, description="是否已解析到具体规则")
    resolution_method: Optional[str] = Field(None, description="解析方法：explicit/implicit/contextual")
    confidence: float = Field(1.0, description="解析置信度 (0-1)")

    # 元数据
    metadata: Dict[str, Any] = Field(default_factory=dict, description="额外元数据")

    class Config:
        use_enum_values = True


# ============================================================
# 第四层：冲突抽象（Conflict Abstraction）
# ============================================================

class ConflictType(str, Enum):
    """
    冲突类型

    基于逻辑可满足性定义，而非经验判断
    """
    # 1. 硬冲突（逻辑矛盾）
    HARD_CONFLICT = "hard_conflict"  # MUST vs MUST NOT，无解

    # 2. 覆盖型冲突（单向收紧）
    REFINEMENT_CONFLICT = "refinement_conflict"  # 同约束维度，一方更严格

    # 3. 条件交叠冲突
    CONDITIONAL_CONFLICT = "conditional_conflict"  # 条件部分重叠，交集区域冲突

    # 4. 隐式引用冲突
    TRANSITIVE_CONFLICT = "transitive_conflict"  # A 引用 B，B 被 C 修改，A 与 C 冲突

    # 5. 值域冲突
    VALUE_RANGE_CONFLICT = "value_range_conflict"  # 值范围无交集

    # 6. 假冲突（可共存）
    DISJOINT = "disjoint"  # 条件互斥或作用对象不同，实际不冲突


class ConflictSeverity(str, Enum):
    """冲突严重程度"""
    CRITICAL = "critical"  # 逻辑矛盾，必须解决
    HIGH = "high"          # 实际影响大
    MEDIUM = "medium"      # 需要注意
    LOW = "low"            # 理论冲突，实际影响小
    INFO = "info"          # 信息性警告


class RuleConflict(BaseModel):
    """
    规则冲突

    表示两条规则之间的冲突关系

    WARNING: 冲突检测器只负责发现和解释冲突，不做裁决或修改。
    """
    # 冲突双方
    rule_a_id: str = Field(..., description="规则 A 的 ID")
    rule_b_id: str = Field(..., description="规则 B 的 ID")

    # 冲突类型
    conflict_type: ConflictType = Field(..., description="冲突类型")
    severity: ConflictSeverity = Field(..., description="严重程度")

    # 不可满足性原因
    unsatisfiability_reason: str = Field(..., description="逻辑不可满足的原因")

    # 冲突详情
    conflicting_dimension: str = Field(..., description="冲突维度（如 'value', 'presence', 'modality'）")
    conflict_details: Dict[str, Any] = Field(default_factory=dict, description="冲突详细信息")

    # 上下文
    condition_intersection: Optional[Dict[str, Any]] = Field(None, description="条件交集（如果是条件冲突）")

    # 可满足性分析
    satisfiable: bool = Field(False, description="是否存在满足两条规则的实例")
    counterexample: Optional[Dict[str, Any]] = Field(None, description="反例（如果不可满足）")

    # 元数据
    detected_at: datetime = Field(default_factory=datetime.now, description="检测时间")
    metadata: Dict[str, Any] = Field(default_factory=dict, description="额外元数据")

    class Config:
        use_enum_values = True


# ============================================================
# 第五层：约束空间抽象（Constraint Space Abstraction）
# ============================================================

class ConstraintSpace(BaseModel):
    """
    约束空间

    表示一组规则共同定义的约束空间，用于可满足性判定
    """
    subject: str = Field(..., description="主体（证书字段）")
    constraints: List[Dict[str, Any]] = Field(default_factory=list, description="约束列表")
    conditions: List[Dict[str, Any]] = Field(default_factory=list, description="条件列表")

    def is_satisfiable(self) -> bool:
        """
        判断约束空间是否可满足

        TODO: 实现基于 SMT 求解器的可满足性判定
        当前简化实现
        """
        # 简化实现：检查是否有明显矛盾
        presence_constraints = [c for c in self.constraints if c.get("predicate") in ["must_be_present", "must_not_be_present"]]

        if len(presence_constraints) >= 2:
            # 检查是否同时要求存在和不存在
            has_must_present = any(c.get("predicate") == "must_be_present" for c in presence_constraints)
            has_must_not_present = any(c.get("predicate") == "must_not_be_present" for c in presence_constraints)
            if has_must_present and has_must_not_present:
                return False

        return True

    def add_constraint(self, constraint: Dict[str, Any]) -> None:
        """添加约束"""
        self.constraints.append(constraint)

    def merge_with(self, other: "ConstraintSpace") -> "ConstraintSpace":
        """
        合并两个约束空间

        返回：合并后的约束空间
        """
        if self.subject != other.subject:
            raise ValueError(f"Cannot merge constraint spaces with different subjects: {self.subject} vs {other.subject}")

        merged = ConstraintSpace(
            subject=self.subject,
            constraints=self.constraints + other.constraints,
            conditions=self.conditions + other.conditions
        )
        return merged


# ============================================================
# 第六层：例外规则抽象（Exception Rule Abstraction）
# ============================================================

class ExceptionPattern(str, Enum):
    """
    例外句式模式（基于RFC/CABF真实文本）

    这些模式直接对应规范文本中的例外语言，不是人工总结的白名单。

    真实示例：
    - UNLESS: "The subject field MUST be present unless the subjectAltName extension is present"
    - ONLY_IF: "MUST use the rfc822Name only if such identities are present"
    - DOES_NOT_APPLY_TO: "This requirement does not apply to self-signed certificates"
    - EXCEPT: "CAs SHALL verify domain control except for domains validated under Enterprise RA"
    - IN_CASE_OF: "In the case of a Key Compromise, the CA MUST revoke within 24 hours"
    """
    UNLESS = "unless"                      # 除非（否定前提）
    ONLY_IF = "only_if"                    # 仅当（正向前提）
    EXCEPT = "except"                      # 除外（排除特定情况）
    EXCEPT_WHEN = "except_when"            # 除非当（时间/条件）
    EXCEPT_WHERE = "except_where"          # 除非在（位置/范围）
    OTHER_THAN = "other_than"              # 除了（排除）
    DOES_NOT_APPLY_TO = "does_not_apply_to"  # 不适用于
    IN_CASE_OF = "in_case_of"              # 在...情况下（条件触发）
    MAY_BE_IGNORED_IF = "may_be_ignored_if"  # 可忽略如果


class ExceptionEffect(str, Enum):
    """
    例外效果类型

    定义例外对主规则的影响方式
    """
    NEGATE = "negate"              # 否定主规则（主规则不适用）
    RELAX = "relax"                # 放松主规则（MUST → SHOULD/MAY）
    RESTRICT = "restrict"          # 限制主规则（收窄适用范围）
    MODIFY_VALUE = "modify_value"  # 修改约束值（如时间延长）
    ADD_CONDITION = "add_condition"  # 增加条件（进一步限定）


class ExceptionScope(str, Enum):
    """
    例外作用域类型

    定义例外影响的证书范围
    """
    FIELD = "field"                    # 字段级（如 subject）
    EXTENSION = "extension"            # 扩展级（如 keyUsage）
    CERTIFICATE_TYPE = "certificate_type"  # 证书类型（如 self-signed, CA）
    PROFILE = "profile"                # 证书配置（如 TLS Server, Code Signing）
    TIME_PERIOD = "time_period"        # 时间周期（如生效日期前）
    VALIDATION_METHOD = "validation_method"  # 验证方法（如 Enterprise RA）
    GLOBAL = "global"                  # 全局（整条规则）


class SourceSpan(BaseModel):
    """
    源文本定位信息

    精确定位例外句式在原文中的位置
    """
    start_char: int = Field(..., description="起始字符位置")
    end_char: int = Field(..., description="结束字符位置")
    matched_text: str = Field(..., description="匹配的原始文本")
    context_before: str = Field("", description="前文上下文（50字符）")
    context_after: str = Field("", description="后文上下文（50字符）")


class ExceptionRuleIR(BaseModel):
    """
    例外规则中间表示

    表达规范文本中的"显式例外句式"，而非人工白名单。

    设计原则：
    1. 直接对齐RFC/CABF中的例外语言模式
    2. 不是配置，而是规则提取的一部分
    3. 必须可追溯到原文
    4. 语义必须可组合（与主规则结合）

    真实示例映射：

    示例1: RFC 5280 §4.1.2.6
    原文: "The subject field MUST be present unless the subjectAltName extension
           is present and marked critical."

    ExceptionRuleIR:
        exception_id: "rfc5280-4.1.2.6-ex1"
        target_rule_id: "rfc5280-4.1.2.6-001"  # subject MUST be present
        pattern: UNLESS
        effect: NEGATE
        scope: FIELD
        condition_set: {
            "conditions": [
                {"field": "extensions.subjectAltName", "predicate": "must_be_present"},
                {"field": "extensions.subjectAltName.critical", "predicate": "equal", "value": true}
            ],
            "logic": "AND"
        }

    示例2: RFC 5280 §4.2.1.6
    原文: "MUST use the rfc822Name only if such identities are present."

    ExceptionRuleIR:
        exception_id: "rfc5280-4.2.1.6-ex1"
        target_rule_id: "rfc5280-4.2.1.6-005"
        pattern: ONLY_IF
        effect: ADD_CONDITION
        scope: EXTENSION
        condition_set: {
            "conditions": [
                {"field": "email_identity", "predicate": "must_be_present"}
            ]
        }

    示例3: 多处通用
    原文: "This requirement does not apply to self-signed certificates."

    ExceptionRuleIR:
        exception_id: "{rule_id}-ex-selfsigned"
        target_rule_id: "{rule_id}"
        pattern: DOES_NOT_APPLY_TO
        effect: NEGATE
        scope: CERTIFICATE_TYPE
        condition_set: {
            "conditions": [
                {"field": "certificate_type", "predicate": "equal", "value": "self-signed"}
            ]
        }
    """
    # ========== 唯一标识 ==========
    exception_id: str = Field(..., description="例外规则唯一ID")
    target_rule_id: str = Field(..., description="被例外的主规则ID")

    # ========== 例外模式 ==========
    pattern: ExceptionPattern = Field(..., description="例外句式模式")
    effect: ExceptionEffect = Field(..., description="例外效果类型")
    scope: ExceptionScope = Field(..., description="例外作用域")

    # ========== 例外条件 ==========
    condition_set: ConditionSet = Field(
        default_factory=ConditionSet,
        description="例外触发条件（什么情况下例外生效）"
    )

    # ========== 来源追溯 ==========
    document_id: str = Field(..., description="来源文档ID")
    section_id: Optional[str] = Field(None, description="章节ID")
    source_span: SourceSpan = Field(..., description="源文本定位")

    # ========== 语义信息 ==========
    justification: str = Field("", description="例外理由（人类可读）")

    # ========== 元数据 ==========
    auto_detected: bool = Field(True, description="是否自动检测（vs 人工添加）")
    confidence: float = Field(1.0, description="检测置信度 (0-1)")
    needs_review: bool = Field(False, description="是否需要人工审核")

    metadata: Dict[str, Any] = Field(default_factory=dict, description="额外元数据")

    class Config:
        use_enum_values = True

    def get_effective_rule_formula(self) -> str:
        """
        获取有效规则公式

        返回：EffectiveRule = NormalRule ∧ ¬ ExceptionCondition（如果 effect=NEGATE）
        """
        if self.effect == ExceptionEffect.NEGATE:
            return f"EffectiveRule({self.target_rule_id}) = NormalRule AND NOT ({self.condition_set.conditions})"
        elif self.effect == ExceptionEffect.ADD_CONDITION:
            return f"EffectiveRule({self.target_rule_id}) = NormalRule IF ({self.condition_set.conditions})"
        else:
            return f"EffectiveRule({self.target_rule_id}) = Modified by {self.effect}"


# ============================================================
# 全局注册表实例
# ============================================================

# 全局文档类型注册表（单例）
DOCUMENT_TYPE_REGISTRY = DocumentTypeRegistry()


# ============================================================
# 辅助函数
# ============================================================

def are_subjects_compatible(subject_a: str, subject_b: str) -> bool:
    """
    判断两个 subject 是否兼容（可对齐）

    例如：
    - "extensions.basicConstraints" 和 "extensions.basicConstraints.cA" 兼容
    - "extensions.keyUsage" 和 "extensions.basicConstraints" 不兼容
    """
    # 简化实现：检查是否有包含关系
    return subject_a.startswith(subject_b) or subject_b.startswith(subject_a) or subject_a == subject_b


def normalize_subject(subject: str) -> str:
    """
    归一化 subject 路径

    例如：
    - "basicConstraints" -> "extensions.basicConstraints"
    - "keyUsage" -> "extensions.keyUsage"
    """
    # 简化实现：确保扩展字段有 "extensions." 前缀
    known_extensions = [
        "basicConstraints", "keyUsage", "extKeyUsage", "subjectAltName",
        "authorityKeyIdentifier", "subjectKeyIdentifier", "cRLDistributionPoints",
        "certificatePolicies", "policyConstraints", "nameConstraints"
    ]

    for ext in known_extensions:
        if subject == ext:
            return f"extensions.{ext}"
        elif subject.startswith(f"{ext}."):
            return f"extensions.{subject}"

    return subject
