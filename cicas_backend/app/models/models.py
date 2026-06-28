"""
Database models for PKI standards management
"""
from sqlalchemy import Column, Integer, String, Text, Date, DateTime, Float, Boolean, ForeignKey, Index, Computed
from pgvector.sqlalchemy import Vector
from sqlalchemy.orm import relationship
from sqlalchemy.sql import func
from datetime import datetime
from app.core.database import Base
from typing import Optional


class Standard(Base):
    """Model for storing PKI standard documents"""
    __tablename__ = "standards"

    id = Column(Integer, primary_key=True, index=True)
    source = Column(String(100), nullable=False, index=True)  # RFC, CABF, Mozilla, etc.
    title = Column(Text, nullable=False)
    version = Column(String(50), nullable=True)
    publish_date = Column(Date, nullable=True)  # 发布日期
    effective_date = Column(Date, nullable=True)  # 生效时间（政策实际生效的时间）
    document_last_updated = Column(Date, nullable=True)  # 标准文档最后更新时间
    url = Column(Text, nullable=False)
    file_path = Column(Text, nullable=True)  # Local storage path
    file_hash = Column(String(64), nullable=True, index=True)  # SHA-256 hash for change detection
    last_checked = Column(DateTime, default=func.now(), onupdate=func.now())
    is_latest = Column(Boolean, default=True)
    metadata_json = Column(Text, nullable=True)  # JSON string for additional metadata
    created_at = Column(DateTime, default=func.now())
    updated_at = Column(DateTime, default=func.now(), onupdate=func.now())

    # Relationships
    rules = relationship("Rule", back_populates="standard", cascade="all, delete-orphan")
    update_logs = relationship("UpdateLog", back_populates="standard")
    # Document relationships
    outgoing_relationships = relationship(
        "StandardRelationship",
        foreign_keys="StandardRelationship.source_standard_id",
        backref="source_standard"
    )
    incoming_relationships = relationship(
        "StandardRelationship",
        foreign_keys="StandardRelationship.target_standard_id",
        backref="target_standard"
    )

    def __repr__(self):
        return f"<Standard(id={self.id}, source={self.source}, title={self.title}, version={self.version})>"


class Rule(Base):
    """Model for storing individual rules extracted from standards"""
    __tablename__ = "rules"

    id = Column(Integer, primary_key=True, index=True)
    standard_id = Column(Integer, ForeignKey("standards.id"), nullable=False, index=True)
    section = Column(String(50), nullable=True, index=True)  # Section number (e.g., "4.2.1", "4.1.2.6")
    subsection = Column(String(100), nullable=True)
    title = Column(Text, nullable=True)
    text = Column(Text, nullable=False)
    rule_type = Column(String(50), nullable=True)  # MUST, SHOULD, MAY, etc.

    # ========== IR 派生标量(生成列, 2026-06-10 schema 迁移) ==========
    # 全部 GENERATED ALWAYS AS ((ir_data::jsonb)->'ir'->>'<字段>') STORED。
    # 列名严格对齐 IR 字段名；单一真源(ir_data)、零失同步、可 SQL 查/索引；
    # 只读——改值改 ir_data 即可，这些列自动重算。
    # 取代了旧的错名列 modality/requirement_level→obligation、operation→
    # predicate、affected_field→subject、expected_value→constraint_value。
    obligation          = Column(String,  Computed("((ir_data::jsonb)->'ir'->>'obligation')", persisted=True))
    predicate           = Column(String,  Computed("((ir_data::jsonb)->'ir'->>'predicate')", persisted=True))
    subject             = Column(Text,    Computed("((ir_data::jsonb)->'ir'->'subject'->>'path')", persisted=True))
    constraint_value    = Column(Text,    Computed("((ir_data::jsonb)->'ir'->'constraint'->>'value')", persisted=True))
    assertion_subject   = Column(String,  Computed("((ir_data::jsonb)->'ir'->>'assertion_subject')", persisted=True))
    enforcement_phase   = Column(String,  Computed("((ir_data::jsonb)->'ir'->>'enforcement_phase')", persisted=True))
    spec_family         = Column(String,  Computed("((ir_data::jsonb)->'ir'->>'spec_family')", persisted=True))
    verifiability       = Column(String,  Computed("((ir_data::jsonb)->'ir'->>'verifiability')", persisted=True))
    stage               = Column(String,  Computed("((ir_data::jsonb)->'ir'->>'stage')", persisted=True))
    non_lintable_reason = Column(Text,    Computed("((ir_data::jsonb)->'ir'->>'non_lintable_reason')", persisted=True))
    lintable            = Column(Boolean, Computed("(((ir_data::jsonb)->'ir'->>'lintable')::boolean)", persisted=True))
    ir_eligible         = Column(Boolean, Computed("(((ir_data::jsonb)->'ir'->>'ir_eligible')::boolean)", persisted=True))

    # ========== 其余规则元数据（非 IR 派生） ==========
    conditions = Column(Text, nullable=True)  # 条件列表(JSON)，逻辑冲突检测器在用
    # ⚠ rule_category 待迁移：DB 历史语义被挪用为 lintable/non_lintable 标志，
    #   IR 语义实为规则类型(definition/encoding_constraint…)；下一批处理。
    rule_category = Column(String(50), default=None, index=True)
    severity = Column(String(50), nullable=True)  # 严重程度

    context = Column(Text, nullable=True)  # Surrounding context
    hash = Column(String(64), nullable=False, index=True, unique=True)  # Unique content hash

    # ========== 规则拆分追踪 ==========
    sentence_index = Column(Integer, nullable=True, index=True)  # 原始句子索引（同句拆分的规则共享相同值）
    sentence_hash = Column(String(64), nullable=True, index=True)  # 原始句子哈希值（用于快速查找同源规则）

    # ========== 向量嵌入 (Vector Embeddings for Semantic Search) ==========
    # TEMP (no-pgvector env): 可达的 15432/cicas 无 pgvector 扩展、rules 表无 embedding 列。
    # 召回/提取管线不使用 embedding（相似度走 Jaccard 文本匹配），embedding 仅服务于独立的
    # 语义检索（提取全程不调）。注释掉以免 ORM SELECT 不存在的列。
    # ⚠️ 在带 pgvector 的环境（如 docker）需恢复此行。
    # embedding = Column(Vector(1024), nullable=True, index=True)  # Vector embedding for semantic search (1024-dim BAAI/bge-m3)

    # ========== 完整IR数据 (Complete Intermediate Representation) ==========
    ir_data = Column(Text, nullable=True)  # JSON: 完整的IR对象，包含新版v2.0判断算法的所有字段
    # ir_data包含：assertion_subject, external_dependency, determinism, zlint_lintability等
    # 使用JSON存储以保持灵活性，便于IR结构演进

    # ========== zlint覆盖字段 ==========
    lint_covered = Column(Boolean, default=False, nullable=True)  # 是否被zlint覆盖 (verdict=='full')
    lint_name = Column(String(255), nullable=True)  # 覆盖该规则的 zlint lint 名称
    lint_coverage = Column(Text, nullable=True)  # 覆盖判别 JSON {verdict, reason, fields, lint, n_candidates}
    similarity_score = Column(Float, nullable=True)  # 相似度分数（无 embedding 判别后不再写）

    # ========== 裁决模块字段 (Rule Adjudication Fields) ==========
    # 规则来源
    origin = Column(String(20), default="source", index=True)  # source | derived

    # 派生规则信息（仅当origin='derived'时有值）
    derived_from = Column(Text, nullable=True)  # JSON数组：源规则ID列表，如 [123, 456]
    derivation_type = Column(String(20), nullable=True)  # compose | merge | summarize | refine | expand
    derivation_justification = Column(Text, nullable=True)  # 派生理由

    # 旧的空列(executability/execution_target/observability/self_contained/
    # determinism/formalized/subjective_terms)已于 2026-06-10 删除。它们
    # 0/2109 全空、无 ORM 访问。其中 `executability` 是对“可 lint 性
    # (lintability)”的错译——该概念现由 IR 的 `lintable` 字段及同名生成列
    # 正确承载;其余判据由 verifiability 等 IR 字段承载。

    # 裁决时间戳
    adjudicated_at = Column(DateTime, nullable=True)
    adjudication_version = Column(String(20), nullable=True)  # 裁决算法版本

    # ========== 噪声标记（用于全量召回后标记质量问题，不过滤） ==========
    is_noise = Column(Boolean, default=False, index=True)      # 是否被标记为噪音
    noise_reason = Column(String(500), nullable=True)             # 噪音原因（如 invalid_section, invalid_title）

    created_at = Column(DateTime, default=func.now())
    updated_at = Column(DateTime, default=func.now(), onupdate=func.now())

    # Relationships
    standard = relationship("Standard", back_populates="rules")
    validations = relationship("RuleValidation", back_populates="rule")
    exception_rules = relationship("ExceptionRule", back_populates="target_rule", cascade="all, delete-orphan")  # ⭐ 新增

    # Indexes
    __table_args__ = (
        Index('idx_rule_standard_section', 'standard_id', 'section'),
    )

    def __repr__(self):
        return f"<Rule(id={self.id}, section={self.section})>"


class ExceptionRule(Base):
    """
    Model for storing exception rules extracted from standards

    Exception rules express regulatory exception patterns (e.g., "unless", "except", "only if")
    found in PKI specifications, NOT manually maintained whitelists.

    Design principle:
    EffectiveRule = NormalRule ∧ ¬ ExceptionRule

    Examples:
    - RFC 5280: "subject MUST be present unless subjectAltName is critical"
    - CABF BR: "CAs SHALL verify domain control except for Enterprise RA"
    """
    __tablename__ = "exception_rules"

    id = Column(Integer, primary_key=True, index=True)

    # ========== Identity ==========
    exception_id = Column(String(200), nullable=False, unique=True, index=True)
    target_rule_id = Column(Integer, ForeignKey("rules.id"), nullable=False, index=True)

    # ========== Exception Pattern ==========
    pattern = Column(String(50), nullable=False, index=True)  # ExceptionPattern enum value
    effect = Column(String(50), nullable=False)  # ExceptionEffect enum value
    scope = Column(String(50), nullable=False)  # ExceptionScope enum value

    # ========== Exception Conditions (JSON) ==========
    condition_set = Column(Text, nullable=True)  # JSON: ConditionSet structure

    # ========== Source Provenance ==========
    document_id = Column(String(100), nullable=False, index=True)
    section_id = Column(String(100), nullable=True, index=True)
    source_span = Column(Text, nullable=True)  # JSON: SourceSpan structure

    # ========== Semantic Information ==========
    justification = Column(Text, nullable=True)  # Human-readable explanation

    # ========== Metadata ==========
    auto_detected = Column(Boolean, default=True, index=True)
    confidence = Column(Float, default=1.0)
    needs_review = Column(Boolean, default=False, index=True)
    metadata_json = Column(Text, nullable=True)  # JSON: additional metadata

    created_at = Column(DateTime, default=func.now())
    updated_at = Column(DateTime, default=func.now(), onupdate=func.now())

    # Relationships
    target_rule = relationship("Rule", back_populates="exception_rules")

    # Indexes
    __table_args__ = (
        Index('idx_exception_target_rule', 'target_rule_id'),
        Index('idx_exception_pattern', 'pattern'),
        Index('idx_exception_auto_detected', 'auto_detected', 'needs_review'),
        Index('idx_exception_document_section', 'document_id', 'section_id'),
    )

    def __repr__(self):
        return f"<ExceptionRule(id={self.id}, exception_id={self.exception_id}, pattern={self.pattern}, target={self.target_rule_id})>"


class RuleValidation(Base):
    """Model for storing rule validation results"""
    __tablename__ = "rule_validations"

    id = Column(Integer, primary_key=True, index=True)
    rule_id = Column(Integer, ForeignKey("rules.id"), nullable=False, index=True)
    validator_model = Column(String(100), nullable=False)  # Model used for validation
    validation_type = Column(String(50), nullable=False)  # cross_check, consistency, etc.
    explanation = Column(Text, nullable=True)
    consistency_score = Column(Float, nullable=True)
    is_consistent = Column(Boolean, nullable=True)
    issues_found = Column(Text, nullable=True)  # JSON string of issues
    validated_at = Column(DateTime, default=func.now())

    # Relationships
    rule = relationship("Rule", back_populates="validations")

    def __repr__(self):
        return f"<RuleValidation(id={self.id}, rule_id={self.rule_id}, is_consistent={self.is_consistent})>"


class UpdateLog(Base):
    """Model for tracking update operations"""
    __tablename__ = "update_logs"

    id = Column(Integer, primary_key=True, index=True)
    standard_id = Column(Integer, ForeignKey("standards.id"), nullable=True, index=True)
    operation = Column(String(50), nullable=False)  # crawl, parse, embed, validate, merge
    status = Column(String(50), nullable=False)  # started, completed, failed
    message = Column(Text, nullable=True)
    rules_added = Column(Integer, default=0)
    rules_updated = Column(Integer, default=0)
    rules_deprecated = Column(Integer, default=0)
    errors_count = Column(Integer, default=0)
    execution_time = Column(Float, nullable=True)  # Seconds
    metadata_json = Column(Text, nullable=True)  # Additional metadata
    started_at = Column(DateTime, default=func.now())
    completed_at = Column(DateTime, nullable=True)

    # Relationships
    standard = relationship("Standard", back_populates="update_logs")

    def __repr__(self):
        return f"<UpdateLog(id={self.id}, operation={self.operation}, status={self.status})>"


class CrawlQueue(Base):
    """Model for managing crawl queue"""
    __tablename__ = "crawl_queue"

    id = Column(Integer, primary_key=True, index=True)
    source = Column(String(100), nullable=False, index=True)
    url = Column(Text, nullable=False)
    priority = Column(Integer, default=5)  # 1-10, higher is more urgent
    status = Column(String(50), default="pending")  # pending, processing, completed, failed
    retry_count = Column(Integer, default=0)
    last_error = Column(Text, nullable=True)
    scheduled_at = Column(DateTime, nullable=True)
    started_at = Column(DateTime, nullable=True)
    completed_at = Column(DateTime, nullable=True)
    created_at = Column(DateTime, default=func.now())

    __table_args__ = (
        Index('idx_crawl_queue_status_priority', 'status', 'priority'),
    )

    def __repr__(self):
        return f"<CrawlQueue(id={self.id}, source={self.source}, status={self.status})>"


class ZlintLintDsl(Base):
    """
    zlint DSL 元数据表

    对应 zlint_lint_dsl 表，存储每个 zlint lint 的 DSL 树表示。
    用于 DSL 树匹配（替代旧的 source+citation+LLM 三层匹配）。

    字段对应数据库表 zlint_lint_dsl。
    """
    __tablename__ = "zlint_lint_dsl"

    id              = Column(Integer, primary_key=True, index=True)
    lint_name       = Column(String(255), nullable=False, index=True)
    source          = Column(String(100), nullable=True)
    section         = Column(String(100), nullable=True)
    package         = Column(String(100), nullable=True)
    predicate       = Column(Text, nullable=True)
    subject         = Column(Text, nullable=True)          # zlint subject path
    obligation      = Column(String(50), nullable=True)     # MUST / SHOULD / MAY / NOT
    constraint_type = Column(String(50), nullable=True)
    constraint_value = Column(Text, nullable=True)
    raw_source      = Column(Text, nullable=True)
    dsl_atom        = Column(Text, nullable=True)          # JSON DSL 原子表达式
    dsl_form        = Column(String(255), nullable=True)
    irred_class     = Column(String(50), nullable=True)
    created_at      = Column(DateTime, default=func.now())

    def __repr__(self):
        return f"<ZlintLintDsl(lint_name={self.lint_name}, obligation={self.obligation})>"


class RuleAuditLog(Base):
    """Model for tracking human audit feedback on extracted rules"""
    __tablename__ = "rule_audit_logs"

    id = Column(Integer, primary_key=True, index=True)
    rule_id = Column(Integer, ForeignKey("rules.id"), nullable=False, index=True)

    # 审核操作
    action = Column(String(50), nullable=False)  # approve, reject, edit, revert
    previous_status = Column(String(50), nullable=True)  # 之前的状态
    new_status = Column(String(50), nullable=True)  # 新的状态

    # 审核反馈
    human_approved = Column(Boolean, nullable=True)  # True(通过), False(拒绝), None(修改)
    rejection_reason = Column(Text, nullable=True)  # 拒绝原因

    # 修改内容（如果是edit操作）
    field_changed = Column(String(100), nullable=True)  # 修改的字段名
    old_value = Column(Text, nullable=True)  # 旧值
    new_value = Column(Text, nullable=True)  # 新值

    # 审核元数据
    auditor_note = Column(Text, nullable=True)  # 审核员备注
    confidence_before = Column(Float, nullable=True)  # 审核前置信度
    confidence_after = Column(Float, nullable=True)  # 审核后置信度
    quality_score_before = Column(Float, nullable=True)  # 审核前质量分
    quality_score_after = Column(Float, nullable=True)  # 审核后质量分

    # 时间戳
    created_at = Column(DateTime, default=func.now())

    # Relationships
    rule = relationship("Rule", backref="audit_logs")

    __table_args__ = (
        Index('idx_audit_log_rule', 'rule_id'),
        Index('idx_audit_log_action', 'action', 'created_at'),
    )

    def __repr__(self):
        return f"<RuleAuditLog(id={self.id}, rule_id={self.rule_id}, action={self.action})>"


class CertificateValidation(Base):
    """Model for storing certificate validation results from two-stage processing"""
    __tablename__ = "certificate_validations"

    id = Column(Integer, primary_key=True, index=True)
    certificate_id = Column(String(200), nullable=False, index=True)  # 证书唯一标识（如序列号）

    # 验证结果
    validation_time = Column(DateTime, default=func.now(), nullable=False)
    is_compliant = Column(Boolean, nullable=False)  # 总体是否合规
    simple_compliant = Column(Boolean, nullable=True)  # 简单分支是否合规
    precise_compliant = Column(Boolean, nullable=True)  # 精确分支是否合规

    # 分支使用情况
    branch_used = Column(String(100), nullable=True)  # simple, precise, both, escalated

    # 违规信息
    violation_count = Column(Integer, default=0)
    validation_result = Column(Text, nullable=True)  # JSON格式的完整验证结果

    # 性能指标
    duration = Column(Float, nullable=True)  # 验证耗时（秒）

    # 状态标记
    has_ambiguity = Column(Boolean, default=False)  # 是否存在歧义
    needs_reprocessing = Column(Boolean, default=False)  # 是否需要重新处理

    created_at = Column(DateTime, default=func.now())
    updated_at = Column(DateTime, default=func.now(), onupdate=func.now())

    __table_args__ = (
        Index('idx_cert_validation_cert_id', 'certificate_id'),
        Index('idx_cert_validation_time', 'validation_time'),
        Index('idx_cert_validation_compliant', 'is_compliant'),
    )

    def __repr__(self):
        return f"<CertificateValidation(id={self.id}, cert_id={self.certificate_id}, compliant={self.is_compliant}, branch={self.branch_used})>"


class Certificate(Base):
    """Model for storing crawled certificates"""
    __tablename__ = "certificates"

    id = Column(Integer, primary_key=True, index=True)

    # 唯一标识 - SHA256 fingerprint（最可靠的去重方式）
    sha256_fingerprint = Column(String(64), unique=True, nullable=True, index=True)

    # 证书基本信息
    serial_number = Column(String(200), nullable=False, index=True)
    subject = Column(Text, nullable=True)
    issuer = Column(Text, nullable=True, index=True)
    not_before = Column(DateTime, nullable=True)
    not_after = Column(DateTime, nullable=True)

    # 证书内容
    pem_data = Column(Text, nullable=False)  # PEM格式证书
    der_hash = Column(String(64), nullable=True, index=True)  # DER格式的SHA256哈希（兼容旧代码）

    # 证书字段
    version = Column(String(10), nullable=True)
    signature_algorithm = Column(String(100), nullable=True)
    public_key_algorithm = Column(String(100), nullable=True)
    key_size = Column(Integer, nullable=True)

    # Subject Alternative Names
    san_dns = Column(Text, nullable=True)  # JSON array of DNS names
    san_ip = Column(Text, nullable=True)  # JSON array of IP addresses

    # Extensions
    extensions_json = Column(Text, nullable=True)  # JSON of all extensions

    # 来源信息
    source = Column(String(100), nullable=False, index=True)  # crt.sh, ct_logs, manual_upload
    source_url = Column(Text, nullable=True)
    crawl_task_id = Column(Integer, ForeignKey("certificate_crawl_tasks.id"), nullable=True, index=True)

    # 验证状态
    validation_status = Column(String(50), default="pending", index=True)  # pending, validated, failed
    is_compliant = Column(Boolean, nullable=True)
    last_validated_at = Column(DateTime, nullable=True)

    # zlint合规性检查结果（新增）
    is_zlint_compliant = Column(Boolean, nullable=True, index=True)
    zlint_violations = Column(Text, nullable=True)  # JSON array
    zlint_violation_count = Column(Integer, nullable=True)
    zlint_last_checked = Column(DateTime, nullable=True)

    # IDN验证结果（新增）
    has_idn = Column(Boolean, default=False, index=True)
    idn_domains = Column(Text, nullable=True)  # JSON array

    # CA异常检测结果（新增）
    has_anomalies = Column(Boolean, default=False, index=True)
    anomalies_count = Column(Integer, default=0)
    anomalies = Column(Text, nullable=True)  # JSON array
    anomaly_severity = Column(String(50), nullable=True, index=True)

    # 元数据
    domain = Column(String(500), nullable=True, index=True)  # 主域名
    certificate_type = Column(String(50), nullable=True)  # DV, OV, EV
    is_self_signed = Column(Boolean, default=False)
    is_expired = Column(Boolean, default=False)
    is_revoked = Column(Boolean, default=False)

    # 地理位置信息（从Subject/Issuer DN中提取）
    subject_country = Column(String(2), nullable=True, index=True)  # Subject C= (ISO 3166-1 alpha-2)
    subject_state = Column(String(255), nullable=True)  # Subject ST=
    subject_locality = Column(String(255), nullable=True)  # Subject L=
    issuer_country = Column(String(2), nullable=True, index=True)  # Issuer C=

    # 撤销检查结果（扩展）
    revocation_check_status = Column(String(50), nullable=True)
    revocation_method = Column(String(50), nullable=True)
    revocation_time = Column(DateTime, nullable=True)
    revocation_reason = Column(String(200), nullable=True)

    created_at = Column(DateTime, default=func.now())
    updated_at = Column(DateTime, default=func.now(), onupdate=func.now())

    # Relationships
    crawl_task = relationship("CertificateCrawlTask", back_populates="certificates")
    ct_scan_records = relationship("CTScanRecord", back_populates="certificate", cascade="all, delete-orphan")

    __table_args__ = (
        Index('idx_cert_serial', 'serial_number'),
        Index('idx_cert_domain', 'domain'),
        Index('idx_cert_source', 'source', 'created_at'),
        Index('idx_cert_validation_status', 'validation_status'),
        Index('idx_cert_sha256', 'sha256_fingerprint'),
        Index('idx_cert_zlint', 'is_zlint_compliant'),
        Index('idx_cert_issuer', 'issuer'),
    )

    def __repr__(self):
        return f"<Certificate(id={self.id}, serial={self.serial_number[:16]}..., domain={self.domain})>"


class CertificateCrawlTask(Base):
    """Model for managing certificate crawl tasks"""
    __tablename__ = "certificate_crawl_tasks"

    id = Column(Integer, primary_key=True, index=True)

    # 任务配置
    source = Column(String(100), nullable=False, index=True)  # crt.sh, ct_logs, censys
    domain = Column(String(500), nullable=True, index=True)  # 目标域名（可选）
    limit = Column(Integer, default=100)  # 爬取数量限制

    # 任务状态
    status = Column(String(50), default="pending", index=True)  # pending, running, completed, failed, cancelled
    progress = Column(Integer, default=0)  # 进度 0-100

    # 统计信息
    total_found = Column(Integer, default=0)  # 发现的证书总数
    total_crawled = Column(Integer, default=0)  # 成功爬取的证书数
    total_failed = Column(Integer, default=0)  # 失败的数量
    total_duplicates = Column(Integer, default=0)  # 重复的数量

    # 错误信息
    error_message = Column(Text, nullable=True)
    retry_count = Column(Integer, default=0)
    max_retries = Column(Integer, default=3)

    # 时间信息
    started_at = Column(DateTime, nullable=True)
    completed_at = Column(DateTime, nullable=True)
    duration = Column(Float, nullable=True)  # 执行时长（秒）

    # 创建者信息
    created_by = Column(String(100), default="system")

    # 任务参数
    params_json = Column(Text, nullable=True)  # JSON格式的额外参数

    created_at = Column(DateTime, default=func.now())
    updated_at = Column(DateTime, default=func.now(), onupdate=func.now())

    # Relationships
    certificates = relationship("Certificate", back_populates="crawl_task")

    __table_args__ = (
        Index('idx_crawl_task_status', 'status', 'created_at'),
        Index('idx_crawl_task_source', 'source', 'status'),
    )

    def __repr__(self):
        return f"<CertificateCrawlTask(id={self.id}, source={self.source}, status={self.status}, progress={self.progress}%)>"

class StandardRelationship(Base):
    """Model for storing relationships between standards documents"""
    __tablename__ = "standard_relationships"

    id = Column(Integer, primary_key=True, index=True)
    source_standard_id = Column(Integer, ForeignKey("standards.id"), nullable=False, index=True)
    target_standard_id = Column(Integer, ForeignKey("standards.id"), nullable=False, index=True)

    # 关系类型
    relationship_type = Column(String(50), nullable=False, index=True)
    # - references: 引用关系（如BR引用了RFC 5280）
    # - updates: 更新关系（如RFC 6818更新了RFC 5280）
    # - obsoletes: 废弃关系（如RFC 5280废弃了RFC 3280）
    # - depends_on: 依赖关系（如EV Guidelines依赖BR）
    # - supplements: 补充关系（如NetSec补充BR）
    # - version_of: 版本关系（如BR v2.0.0和BR v2.0.1）

    # 关系详情
    description = Column(Text, nullable=True)  # 关系描述
    section = Column(String(100), nullable=True)  # 引用的具体章节（如果适用）
    confidence = Column(Float, default=1.0)  # 关系置信度（0-1）
    extraction_method = Column(String(50), default="manual")  # manual, automatic_text, automatic_metadata

    # 元数据
    metadata_json = Column(Text, nullable=True)  # 额外的关系元数据（JSON格式）
    is_active = Column(Boolean, default=True)  # 关系是否有效

    created_at = Column(DateTime, default=func.now())
    updated_at = Column(DateTime, default=func.now(), onupdate=func.now())

    # 索引
    __table_args__ = (
        Index('idx_std_rel_source', 'source_standard_id'),
        Index('idx_std_rel_target', 'target_standard_id'),
        Index('idx_std_rel_type', 'relationship_type'),
        Index('idx_std_rel_active', 'is_active'),
    )

    def __repr__(self):
        return f"<StandardRelationship(id={self.id}, source={self.source_standard_id}, target={self.target_standard_id}, type={self.relationship_type})>"


class CTScanTask(Base):
    """Model for storing CT log scan tasks"""
    __tablename__ = "ct_scan_tasks"

    id = Column(Integer, primary_key=True, index=True)
    task_id = Column(String(100), nullable=False, unique=True, index=True)

    # 扫描配置
    ct_log_name = Column(String(100), nullable=False)
    max_certificates = Column(Integer, nullable=True, default=None)  # None表示不限制
    date_from = Column(Date, nullable=True)  # 证书有效期开始日期筛选
    date_to = Column(Date, nullable=True)    # 证书有效期结束日期筛选

    # 扫描状态
    status = Column(String(50), default="running", index=True)  # running, completed, failed

    # 扫描统计
    total_scanned = Column(Integer, default=0)
    idn_found = Column(Integer, default=0)
    issues_found = Column(Integer, default=0)
    anomalies_found = Column(Integer, default=0)  # 异常证书数量
    revoked_found = Column(Integer, default=0)  # 已撤销证书数量

    # 时间信息
    started_at = Column(DateTime, default=func.now())
    completed_at = Column(DateTime, nullable=True)
    duration = Column(Float, nullable=True)  # 耗时（秒）

    # 错误信息
    error_message = Column(Text, nullable=True)

    # 批量验证进度跟踪
    validation_status = Column(String(50), default="not_started", index=True)  # not_started, running, completed, failed
    validation_progress = Column(Integer, default=0)  # 已验证的证书数
    validation_total = Column(Integer, default=0)  # 需要验证的证书总数
    validation_started_at = Column(DateTime, nullable=True)  # 验证开始时间
    validation_completed_at = Column(DateTime, nullable=True)  # 验证完成时间
    validation_error = Column(Text, nullable=True)  # 验证错误信息

    created_at = Column(DateTime, default=func.now())
    updated_at = Column(DateTime, default=func.now(), onupdate=func.now())

    # Relationship
    idn_results = relationship("CTCertificateIDNResult", back_populates="scan_task", cascade="all, delete-orphan")
    scan_records = relationship("CTScanRecord", back_populates="scan_task", cascade="all, delete-orphan")

    __table_args__ = (
        Index('idx_ct_scan_status', 'status'),
        Index('idx_ct_scan_time', 'started_at'),
    )

    def __repr__(self):
        return f"<CTScanTask(id={self.id}, task_id={self.task_id}, status={self.status}, scanned={self.total_scanned})>"


class CTScanRecord(Base):
    """
    CT扫描记录表 - 记录证书在CT日志中的出现
    一个证书可以在多个CT日志中出现，形成多对多关系
    """
    __tablename__ = "ct_scan_records"

    id = Column(Integer, primary_key=True, index=True)

    # 关联关系
    certificate_id = Column(Integer, ForeignKey("certificates.id"), nullable=False, index=True)
    task_id = Column(Integer, ForeignKey("ct_scan_tasks.id"), nullable=False, index=True)

    # CT日志信息
    ct_log_name = Column(String(100), nullable=True, index=True)
    cert_index = Column(Integer, nullable=True)  # 证书在CT日志中的索引

    # 扫描时间
    scanned_at = Column(DateTime, default=func.now(), index=True)

    # Relationships
    certificate = relationship("Certificate", back_populates="ct_scan_records")
    scan_task = relationship("CTScanTask", back_populates="scan_records")

    __table_args__ = (
        Index('idx_scan_record_cert', 'certificate_id'),
        Index('idx_scan_record_task', 'task_id'),
        Index('idx_scan_record_log', 'ct_log_name'),
        Index('idx_scan_record_time', 'scanned_at'),
        # 防止同一证书在同一任务中重复记录
        Index('idx_scan_record_unique', 'certificate_id', 'task_id', unique=True),
    )

    def __repr__(self):
        return f"<CTScanRecord(id={self.id}, cert_id={self.certificate_id}, task_id={self.task_id}, log={self.ct_log_name})>"


class CTCertificateIDNResult(Base):
    """Model for storing CT certificate IDN validation results (DEPRECATED - use Certificate + CTScanRecord)"""
    __tablename__ = "ct_certificate_idn_results"

    id = Column(Integer, primary_key=True, index=True)
    task_id = Column(Integer, ForeignKey("ct_scan_tasks.id"), nullable=False, index=True)

    # 证书信息
    cert_index = Column(Integer, nullable=True)
    serial_number = Column(String(200), nullable=True, index=True)
    subject = Column(Text, nullable=True)
    issuer = Column(Text, nullable=True)
    not_before = Column(DateTime, nullable=True)
    not_after = Column(DateTime, nullable=True)
    ct_log_name = Column(String(100), nullable=True)

    # 证书内容
    pem_data = Column(Text, nullable=False)

    # IDN验证结果
    is_valid = Column(Boolean, nullable=False, index=True)
    has_idn = Column(Boolean, default=False, index=True)
    idn_domains = Column(Text, nullable=True)  # JSON array of IDN domains

    # 验证详情
    validation_result = Column(Text, nullable=True)  # JSON格式的完整验证结果
    issues_count = Column(Integer, default=0)
    warnings_count = Column(Integer, default=0)

    # 问题详情
    issues = Column(Text, nullable=True)  # JSON array of issues
    warnings = Column(Text, nullable=True)  # JSON array of warnings
    checks_performed = Column(Text, nullable=True)  # JSON array of check names

    # CA异常检测结果
    has_anomalies = Column(Boolean, default=False, index=True)  # 是否有异常
    anomalies_count = Column(Integer, default=0)  # 异常数量
    anomalies = Column(Text, nullable=True)  # JSON array of anomalies
    anomaly_severity = Column(String(50), nullable=True, index=True)  # critical, high, medium, low

    # 撤销检查结果
    is_revoked = Column(Boolean, default=False, index=True)  # 是否已撤销
    revocation_check_status = Column(String(50), nullable=True)  # success, failed, unavailable
    revocation_method = Column(String(50), nullable=True)  # OCSP, CRL, NONE
    revocation_time = Column(DateTime, nullable=True)  # 撤销时间
    revocation_reason = Column(String(200), nullable=True)  # 撤销原因

    # zlint合规性检查结果（默认NULL表示未验证）
    is_zlint_compliant = Column(Boolean, nullable=True, index=True)  # zlint合规性（NULL=未验证）
    zlint_violations = Column(Text, nullable=True)  # JSON array of zlint violations
    zlint_violation_count = Column(Integer, nullable=True)  # zlint违规数量（NULL=未验证）

    created_at = Column(DateTime, default=func.now())

    # Relationship
    scan_task = relationship("CTScanTask", back_populates="idn_results")

    __table_args__ = (
        Index('idx_ct_idn_task', 'task_id'),
        Index('idx_ct_idn_valid', 'is_valid'),
        Index('idx_ct_idn_has_idn', 'has_idn'),
        Index('idx_ct_idn_serial', 'serial_number'),
        Index('idx_ct_idn_has_anomalies', 'has_anomalies'),
        Index('idx_ct_idn_is_revoked', 'is_revoked'),
        Index('idx_ct_idn_anomaly_severity', 'anomaly_severity'),
        Index('idx_ct_idn_zlint_compliant', 'is_zlint_compliant'),
    )

    def __repr__(self):
        return f"<CTCertificateIDNResult(id={self.id}, serial={self.serial_number}, valid={self.is_valid}, has_idn={self.has_idn})>"



class AdversarialOptimizationConfig(Base):
    """
    对抗学习优化配置模型
    存储动态调整的阈值、prompt优化和反馈统计
    """
    __tablename__ = "adversarial_optimization_config"

    id = Column(Integer, primary_key=True, index=True)

    # 配置类型和版本
    config_type = Column(String(50), nullable=False, index=True)  # 'threshold', 'prompt', 'filter'
    version = Column(Integer, default=1)  # 配置版本号
    is_active = Column(Boolean, default=True, index=True)  # 是否激活

    # 动态阈值配置
    zlint_coverage_threshold = Column(Float, default=0.95)
    quality_auto_approve_threshold = Column(Float, default=0.90)
    rag_quality_threshold = Column(Float, default=0.9)
    rag_min_similarity = Column(Float, default=0.3)

    # Prompt优化配置 (JSON格式)
    ignore_patterns = Column(Text, nullable=True)  # JSON数组: 需要忽略的模式
    extraction_hints = Column(Text, nullable=True)  # JSON数组: 提取提示
    field_mapping_rules = Column(Text, nullable=True)  # JSON对象: 字段映射规则

    # Challenger权重配置 (JSON格式) - 更新二：动态权重调整
    challenger_weights = Column(Text, nullable=True)  # JSON对象: RuleChallenger各维度权重

    # 反馈统计 (JSON格式)
    feedback_stats = Column(Text, nullable=True)  # JSON对象: 失败模式统计
    performance_metrics = Column(Text, nullable=True)  # JSON对象: 性能指标

    # 优化效果追踪
    total_extractions = Column(Integer, default=0)  # 总提取次数
    avg_quality_score = Column(Float, nullable=True)  # 平均质量分
    auto_approve_rate = Column(Float, nullable=True)  # 自动通过率
    false_positive_rate = Column(Float, nullable=True)  # 误报率
    false_negative_rate = Column(Float, nullable=True)  # 漏报率

    # 学习元数据
    learning_source = Column(String(100), nullable=True)  # 学习来源: 'manual', 'auto', 'feedback'
    optimization_note = Column(Text, nullable=True)  # 优化说明

    created_at = Column(DateTime, default=func.now())
    updated_at = Column(DateTime, default=func.now(), onupdate=func.now())

    __table_args__ = (
        Index('idx_adv_config_type', 'config_type'),
        Index('idx_adv_config_active', 'is_active'),
    )

    def __repr__(self):
        return f"<AdversarialOptimizationConfig(id={self.id}, type={self.config_type}, version={self.version}, active={self.is_active})>"


class AdversarialFeedback(Base):
    """
    对抗学习反馈记录
    存储每次提取的反馈数据，用于优化参数
    """
    __tablename__ = "adversarial_feedback"

    id = Column(Integer, primary_key=True, index=True)

    # 关联信息
    extraction_batch_id = Column(String(100), nullable=True, index=True)  # 提取批次ID
    rule_id = Column(Integer, ForeignKey("rules.id"), nullable=True, index=True)

    # 反馈类型
    feedback_type = Column(String(50), nullable=False, index=True)  # 'extraction_error', 'quality_issue', 'human_correction'
    severity = Column(String(20), nullable=True)  # 'high', 'medium', 'low'

    # 问题详情
    issue_category = Column(String(100), nullable=True, index=True)  # 'field_mapping', 'false_positive', 'false_negative'
    issue_description = Column(Text, nullable=True)

    # 原始数据和修正数据
    original_data = Column(Text, nullable=True)  # JSON: 原始提取结果
    corrected_data = Column(Text, nullable=True)  # JSON: 修正后的数据

    # 影响的配置
    affected_config_type = Column(String(50), nullable=True)  # 影响的配置类型
    suggested_threshold = Column(Float, nullable=True)  # 建议的阈值
    suggested_prompt_change = Column(Text, nullable=True)  # 建议的prompt修改

    # 处理状态
    is_processed = Column(Boolean, default=False, index=True)  # 是否已处理
    applied_to_config_id = Column(Integer, ForeignKey("adversarial_optimization_config.id"), nullable=True)

    created_at = Column(DateTime, default=func.now())

    # Relationships
    rule = relationship("Rule")
    applied_config = relationship("AdversarialOptimizationConfig")

    __table_args__ = (
        Index('idx_adv_feedback_type', 'feedback_type'),
        Index('idx_adv_feedback_processed', 'is_processed'),
        Index('idx_adv_feedback_batch', 'extraction_batch_id'),
    )

    def __repr__(self):
        return f"<AdversarialFeedback(id={self.id}, type={self.feedback_type}, category={self.issue_category}, processed={self.is_processed})>"


class KnowledgeBaseEntry(Base):
    """
    知识库条目表
    存储经过验证的字段映射模式和操作映射模式
    """
    __tablename__ = "knowledge_base_entries"

    id = Column(Integer, primary_key=True, index=True)

    # 知识类型
    entry_type = Column(String(50), nullable=False, index=True)  # field_mapping, operation_mapping

    # 模式定义
    pattern = Column(Text, nullable=False)  # 规范化的文本模式
    pattern_hash = Column(String(64), nullable=True, unique=True, index=True)  # 模式哈希

    # 映射信息
    operation = Column(String(100), nullable=True)  # 操作类型
    affected_field_hint = Column(String(200), nullable=True)  # 字段提示

    # 统计信息
    support_count = Column(Integer, default=0)  # 支持该模式的规则数量
    avg_score = Column(Float, nullable=True)  # 平均质量分

    # 状态
    status = Column(String(20), default="proposed", index=True)  # proposed, active, rejected
    confidence = Column(Float, default=0.0)  # 置信度

    # 示例
    examples = Column(Text, nullable=True)  # JSON数组：前5个示例规则

    # 统计显著性
    p_value = Column(Float, nullable=True)  # p值（统计检验）
    effect_size = Column(Float, nullable=True)  # 效应量

    # 元数据
    created_by = Column(String(50), default="system")  # system, manual, meta_learner
    approval_note = Column(Text, nullable=True)  # 审批说明

    # 版本控制
    version = Column(Integer, default=1)
    parent_entry_id = Column(Integer, ForeignKey("knowledge_base_entries.id"), nullable=True)

    created_at = Column(DateTime, default=func.now())
    updated_at = Column(DateTime, default=func.now(), onupdate=func.now())

    # Relationships
    children = relationship("KnowledgeBaseEntry", backref="parent", remote_side=[id])

    __table_args__ = (
        Index('idx_kb_entry_type', 'entry_type', 'status'),
        Index('idx_kb_support', 'support_count', 'avg_score'),
    )

    def __repr__(self):
        return f"<KnowledgeBaseEntry(id={self.id}, type={self.entry_type}, status={self.status}, support={self.support_count})>"


class KBCandidateProposal(Base):
    """
    KB候选提案表
    存储从Challenger生成但尚未写入KB的候选条目
    """
    __tablename__ = "kb_candidate_proposals"

    id = Column(Integer, primary_key=True, index=True)

    # 候选信息
    pattern = Column(Text, nullable=False)
    mapping = Column(Text, nullable=False)  # JSON: {affected_field_hint, operation}

    # 统计信息
    support_count = Column(Integer, default=0)
    avg_score = Column(Float, nullable=True)

    # 示例规则
    examples = Column(Text, nullable=True)  # JSON数组：前5个示例

    # Meta-Learner决策
    decision = Column(String(20), nullable=True, index=True)  # auto_apply, manual_review, rejected
    decision_reason = Column(Text, nullable=True)

    # 统计检验结果
    p_value = Column(Float, nullable=True)
    effect_size = Column(Float, nullable=True)
    statistical_test_passed = Column(Boolean, default=False)

    # 风险评估
    risk_level = Column(String(20), nullable=True)  # low, medium, high

    # 处理状态
    is_processed = Column(Boolean, default=False, index=True)
    applied_to_kb_id = Column(Integer, ForeignKey("knowledge_base_entries.id"), nullable=True)

    # 来源
    generated_by = Column(String(50), default="challenger")
    generation_round = Column(Integer, nullable=True)  # 生成该候选的演化轮次

    created_at = Column(DateTime, default=func.now())
    processed_at = Column(DateTime, nullable=True)

    # Relationships
    kb_entry = relationship("KnowledgeBaseEntry", backref="candidate_proposals")

    __table_args__ = (
        Index('idx_kb_candidate_decision', 'decision', 'is_processed'),
        Index('idx_kb_candidate_round', 'generation_round'),
    )

    def __repr__(self):
        return f"<KBCandidateProposal(id={self.id}, decision={self.decision}, support={self.support_count}, processed={self.is_processed})>"


class PromptVersion(Base):
    """
    Prompt版本表
    支持多版本prompt并行测试
    """
    __tablename__ = "prompt_versions"

    id = Column(Integer, primary_key=True, index=True)

    # 版本信息
    prompt_name = Column(String(100), nullable=False, index=True)  # extractor_v1, challenger_v2等
    version = Column(Integer, default=1)
    variant_id = Column(String(50), nullable=True, index=True)  # variant_1, variant_2, variant_3

    # Prompt内容
    system_prompt = Column(Text, nullable=False)
    user_prompt_template = Column(Text, nullable=True)  # 带变量的模板

    # 配置参数
    temperature = Column(Float, default=0.7)
    max_tokens = Column(Integer, default=2000)
    model_name = Column(String(50), nullable=True)

    # 状态
    status = Column(String(20), default="testing", index=True)  # testing, active, deprecated
    is_baseline = Column(Boolean, default=False)  # 是否为基准版本

    # 性能指标
    avg_quality_score = Column(Float, nullable=True)
    avg_consistency_score = Column(Float, nullable=True)  # 与其他变体的一致性
    total_usage_count = Column(Integer, default=0)

    # AB测试结果
    ab_test_result = Column(Text, nullable=True)  # JSON格式的AB测试统计

    # 元数据
    description = Column(Text, nullable=True)
    created_by = Column(String(50), default="system")

    created_at = Column(DateTime, default=func.now())
    updated_at = Column(DateTime, default=func.now(), onupdate=func.now())

    __table_args__ = (
        Index('idx_prompt_name_version', 'prompt_name', 'version'),
        Index('idx_prompt_status', 'status', 'prompt_name'),
    )

    def __repr__(self):
        return f"<PromptVersion(id={self.id}, name={self.prompt_name}, version={self.version}, variant={self.variant_id}, status={self.status})>"


class ExtractionConsistency(Base):
    """
    提取一致性记录表
    存储多版本prompt提取的一致性评分
    """
    __tablename__ = "extraction_consistency"

    id = Column(Integer, primary_key=True, index=True)

    # 关联的规则和prompt版本
    source_text = Column(Text, nullable=False)  # 原始输入文本
    source_text_hash = Column(String(64), nullable=True, index=True)

    # 提取结果（多个变体）
    variant_1_result = Column(Text, nullable=True)  # JSON格式
    variant_2_result = Column(Text, nullable=True)
    variant_3_result = Column(Text, nullable=True)

    # Prompt版本ID
    variant_1_prompt_id = Column(Integer, ForeignKey("prompt_versions.id"), nullable=True)
    variant_2_prompt_id = Column(Integer, ForeignKey("prompt_versions.id"), nullable=True)
    variant_3_prompt_id = Column(Integer, ForeignKey("prompt_versions.id"), nullable=True)

    # 一致性评分
    consistency_score = Column(Float, nullable=True, index=True)  # 总体一致性
    pairwise_similarity_1_2 = Column(Float, nullable=True)
    pairwise_similarity_1_3 = Column(Float, nullable=True)
    pairwise_similarity_2_3 = Column(Float, nullable=True)

    # 语义表征
    repr_1 = Column(Vector(768), nullable=True)  # embedding of variant 1
    repr_2 = Column(Vector(768), nullable=True)
    repr_3 = Column(Vector(768), nullable=True)

    # 分析
    has_high_disagreement = Column(Boolean, default=False, index=True)  # 是否存在高度不一致
    disagreement_analysis = Column(Text, nullable=True)  # 不一致分析

    # 元数据
    extraction_batch_id = Column(String(100), nullable=True, index=True)

    created_at = Column(DateTime, default=func.now())

    # Relationships
    variant_1_prompt = relationship("PromptVersion", foreign_keys=[variant_1_prompt_id])
    variant_2_prompt = relationship("PromptVersion", foreign_keys=[variant_2_prompt_id])
    variant_3_prompt = relationship("PromptVersion", foreign_keys=[variant_3_prompt_id])

    __table_args__ = (
        Index('idx_extraction_consistency_score', 'consistency_score'),
        Index('idx_extraction_disagreement', 'has_high_disagreement'),
    )

    def __repr__(self):
        return f"<ExtractionConsistency(id={self.id}, consistency={self.consistency_score:.3f}, disagreement={self.has_high_disagreement})>"


class EvolutionRound(Base):
    """
    演化轮次表
    存储每一轮的完整输出和统计信息
    """
    __tablename__ = "evolution_rounds"

    id = Column(Integer, primary_key=True, index=True)

    # 轮次信息
    round_id = Column(String(100), nullable=False, unique=True, index=True)
    round_number = Column(Integer, nullable=False, index=True)

    # 输入参数
    standard_id = Column(Integer, ForeignKey("standards.id"), nullable=True, index=True)
    auto_apply = Column(Boolean, default=False)  # 是否自动应用优化

    # 提取结果统计
    total_rules_extracted = Column(Integer, default=0)
    total_rules_challenged = Column(Integer, default=0)
    avg_quality_score = Column(Float, nullable=True)
    avg_consistency_score = Column(Float, nullable=True)

    # KB候选生成统计
    kb_candidates_generated = Column(Integer, default=0)
    kb_auto_applied = Column(Integer, default=0)
    kb_manual_review = Column(Integer, default=0)

    # 优化器更新统计
    weights_updated = Column(Boolean, default=False)
    prompts_updated = Column(Boolean, default=False)

    # 完整输出（JSON格式）
    extracted_rules = Column(Text, nullable=True)  # JSON数组
    challenged_scores = Column(Text, nullable=True)  # JSON数组
    kb_candidates = Column(Text, nullable=True)  # JSON数组
    kb_decisions = Column(Text, nullable=True)  # JSON数组
    updated_weights = Column(Text, nullable=True)  # JSON对象
    updated_prompts = Column(Text, nullable=True)  # JSON对象
    optimizer_logs = Column(Text, nullable=True)  # JSON对象

    # 性能指标
    extractor_reward = Column(Float, nullable=True)  # Extractor的奖励
    challenger_performance = Column(Float, nullable=True)  # Challenger的性能
    mutual_information = Column(Float, nullable=True)  # MI值

    # 元数据
    status = Column(String(20), default="completed", index=True)  # running, completed, failed
    error_message = Column(Text, nullable=True)
    execution_duration = Column(Float, nullable=True)  # 执行时长（秒）

    started_at = Column(DateTime, default=func.now())
    completed_at = Column(DateTime, nullable=True)

    # Relationships
    standard = relationship("Standard", backref="evolution_rounds")

    __table_args__ = (
        Index('idx_evolution_round_number', 'round_number'),
        Index('idx_evolution_status', 'status', 'started_at'),
    )

    def __repr__(self):
        return f"<EvolutionRound(id={self.id}, round={self.round_number}, rules={self.total_rules_extracted}, kb_candidates={self.kb_candidates_generated})>"


class RuleChunk(Base):
    """
    规则Chunk表（Layer1输出）
    存储文档预处理器切分的chunk，用于Layer2提取规则
    """
    __tablename__ = "rule_chunks"

    id = Column(Integer, primary_key=True, index=True)

    # Chunk标识
    chunk_id = Column(String(100), nullable=False, unique=True, index=True)  # 唯一ID
    doc_id = Column(String(100), nullable=False, index=True)  # 文档ID
    section = Column(String(100), nullable=True, index=True)  # 章节号

    # Chunk位置
    start_line = Column(Integer, nullable=False)  # 起始行号（1-indexed）
    end_line = Column(Integer, nullable=False)    # 结束行号（1-indexed）

    # Chunk内容
    text = Column(Text, nullable=False)  # 完整chunk文本
    text_hash = Column(String(64), nullable=False, index=True)  # 文本hash（用于去重）

    # 锚点信息
    anchor = Column(String(50), nullable=False, index=True)  # 锚点关键词（MUST/SHALL等）

    # 处理状态
    status = Column(String(50), default="pending", index=True)  # pending, processed, filtered
    processed_by = Column(String(50), nullable=True)  # layer2, manual等

    # 提取结果
    rules_extracted_count = Column(Integer, default=0)  # 从该chunk提取的规则数量
    extracted_rule_ids = Column(Text, nullable=True)  # JSON数组：提取的规则ID列表

    # 质量标记
    is_noise = Column(Boolean, default=False, index=True)  # 是否被标记为噪音
    noise_reason = Column(String(200), nullable=True)  # 噪音原因

    # 元数据
    standard_id = Column(Integer, ForeignKey("standards.id"), nullable=True, index=True)
    created_by = Column(String(50), default="regex_layer")  # 创建来源

    created_at = Column(DateTime, default=func.now())
    updated_at = Column(DateTime, default=func.now(), onupdate=func.now())

    # Relationships
    standard = relationship("Standard")

    __table_args__ = (
        Index('idx_chunk_doc_section', 'doc_id', 'section'),
        Index('idx_chunk_status', 'status', 'created_at'),
        Index('idx_chunk_anchor', 'anchor', 'status'),
    )

    def __repr__(self):
        return f"<RuleChunk(id={self.id}, chunk_id={self.chunk_id}, anchor={self.anchor}, status={self.status})>"


class ValidationResultHistory(Base):
    """
    证书验证结果历史记录表
    用于保存CT扫描后的验证统计结果，不保留证书PEM数据
    """
    __tablename__ = "validation_result_history"

    id = Column(Integer, primary_key=True, index=True)

    # 关联的扫描任务
    task_id = Column(String(100), nullable=False, index=True)
    ct_scan_task_id = Column(Integer, ForeignKey("ct_scan_tasks.id"), nullable=True, index=True)

    # 扫描配置
    ct_log_name = Column(String(100), nullable=True)
    date_from = Column(Date, nullable=True)  # 证书有效期起始日期
    date_to = Column(Date, nullable=True)    # 证书有效期结束日期

    # 证书数量统计
    total_certificates = Column(Integer, default=0)  # 扫描的总证书数
    validated_certificates = Column(Integer, default=0)  # 验证的证书数
    compliant_certificates = Column(Integer, default=0)  # 合规证书数
    non_compliant_certificates = Column(Integer, default=0)  # 非合规证书数

    # 合规率
    compliance_rate = Column(Float, nullable=True)  # 合规率（百分比）

    # 统计数据（JSON格式）
    organization_stats = Column(Text, nullable=True)  # 组织错误率统计（TABLE II数据）
    common_errors_stats = Column(Text, nullable=True)  # 常见错误统计（TABLE III数据）
    cdf_stats = Column(Text, nullable=True)  # CDF统计数据（Fig. 3 & Fig. 4数据）

    # 用户保存标记
    is_saved = Column(Boolean, default=False, index=True)  # 用户是否选择保存此结果
    description = Column(Text, nullable=True)  # 用户添加的描述

    # 时间信息
    created_at = Column(DateTime, default=func.now(), index=True)
    updated_at = Column(DateTime, default=func.now(), onupdate=func.now())

    # Relationship
    ct_scan_task = relationship("CTScanTask")

    __table_args__ = (
        Index('idx_validation_history_task', 'task_id'),
        Index('idx_validation_history_saved', 'is_saved', 'created_at'),
        Index('idx_validation_history_time', 'created_at'),
    )

    def __repr__(self):
        return f"<ValidationResultHistory(id={self.id}, task_id={self.task_id}, total={self.total_certificates}, saved={self.is_saved})>"

