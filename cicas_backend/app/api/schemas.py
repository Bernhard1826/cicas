"""
Pydantic schemas for API request/response models
"""
from pydantic import BaseModel, Field
from typing import Optional, List, Dict
from datetime import datetime, date


class StandardResponse(BaseModel):
    """Response model for Standard"""
    id: int
    source: str
    title: str
    version: Optional[str] = None
    publish_date: Optional[date] = None
    effective_date: Optional[date] = None
    document_last_updated: Optional[date] = None
    url: str
    file_path: Optional[str] = None
    file_hash: Optional[str] = None
    last_checked: Optional[datetime] = None
    is_latest: bool
    created_at: datetime
    updated_at: datetime

    class Config:
        from_attributes = True


class RuleResponse(BaseModel):
    """Response model for Rule"""
    id: int
    standard_id: int
    section: Optional[str] = None
    subsection: Optional[str] = None
    title: Optional[str] = None
    text: str
    rule_type: Optional[str] = None
    affected_field: Optional[str] = None
    operation: Optional[str] = None
    expected_value: Optional[str] = None
    severity: Optional[str] = None
    context: Optional[str] = None
    hash: str
    # Semantic IR fields
    modality: Optional[str] = None
    requirement_level: Optional[str] = None
    condition: Optional[str] = None
    conditions: Optional[str] = None
    subject_role: Optional[str] = None
    target_type: Optional[str] = None
    # Tracking fields
    sentence_index: Optional[int] = None
    sentence_hash: Optional[str] = None
    # IR data
    ir_data: Optional[str] = None
    # zlint coverage fields
    lint_covered: Optional[bool] = None
    lint_name: Optional[str] = None
    similarity_score: Optional[float] = None
    created_at: datetime
    updated_at: datetime

    class Config:
        from_attributes = True


class UpdateLogResponse(BaseModel):
    """Response model for UpdateLog"""
    id: int
    standard_id: Optional[int] = None
    operation: str
    status: str
    message: Optional[str] = None
    rules_added: int
    rules_updated: int
    rules_deprecated: int
    errors_count: int
    execution_time: Optional[float] = None
    started_at: datetime
    completed_at: Optional[datetime] = None

    class Config:
        from_attributes = True


class UpdateRequest(BaseModel):
    """Request model for triggering updates"""
    sources: Optional[List[str]] = Field(
        default=None,
        description="List of sources to update (e.g., ['RFC', 'CABF']). If None, update all."
    )
    force: bool = Field(
        default=False,
        description="Force update even if no changes detected"
    )


class UpdateStatusResponse(BaseModel):
    """Response model for update status"""
    status: str
    message: str
    timestamp: datetime


from app.config.search_config import SemanticSearchConfig

class SearchRequest(BaseModel):
    """Request model for rule search"""
    query: str = Field(..., min_length=1, description="Search query text (cannot be empty)")
    limit: int = Field(
        default=SemanticSearchConfig.Limits.DEFAULT,
        ge=SemanticSearchConfig.Limits.MIN,
        le=SemanticSearchConfig.Limits.MAX,
        description="Number of results to return"
    )
    threshold: float = Field(
        default=SemanticSearchConfig.Similarity.DEFAULT,
        ge=SemanticSearchConfig.Similarity.MIN,
        le=SemanticSearchConfig.Similarity.MAX,
        description="Similarity threshold (0-1)"
    )
    # 过滤条件（可选）
    source: Optional[str] = Field(default=None, description="标准来源 (RFC, CABF, ETSI)")
    rule_type: Optional[str] = Field(default=None, description="规则类型 (MUST, SHALL, SHOULD, MAY)")
    affected_field: Optional[str] = Field(default=None, description="影响的证书字段")
    # 查询扩展（可选）
    expand_query: bool = Field(
        default=SemanticSearchConfig.QueryExpansion.ENABLED_BY_DEFAULT,
        description="是否启用PKI术语同义词扩展"
    )


class StandardInfo(BaseModel):
    """Nested standard information for search results"""
    id: int
    source: str
    title: str
    version: Optional[str] = None
    url: str

    class Config:
        from_attributes = True


class SearchResult(BaseModel):
    """Single search result with similarity score"""
    id: int
    standard_id: int
    section: Optional[str] = None
    title: Optional[str] = None
    text: str
    rule_type: Optional[str] = None
    context: Optional[str] = None
    affected_field: Optional[str] = None
    severity: Optional[str] = None
    document_verified: Optional[bool] = None
    similarity: float = Field(description="Cosine similarity score (0-1)")
    standard: Optional[StandardInfo] = None  # ← 添加standard信息

    class Config:
        from_attributes = True


class SearchResponse(BaseModel):
    """Response model for semantic search"""
    query: str
    results: List[SearchResult]
    total_results: int
    threshold_used: float


class CompareVersionsRequest(BaseModel):
    """Request model for version comparison"""
    standard_id_1: int
    standard_id_2: int


class StatsResponse(BaseModel):
    """Response model for system statistics"""
    total_standards: int
    total_rules: int
    active_rules: int
    rules_need_review: int
    last_update: Optional[datetime] = None


# ========== Dual Branch Certificate Validation Schemas ==========

class CertificateValidationRequest(BaseModel):
    """Request model for certificate validation"""
    cert_pem: str = Field(description="PEM-encoded certificate")
    rules: List[Dict] = Field(description="Rules to validate against")
    certificate_id: Optional[str] = Field(default=None, description="Optional certificate identifier")
    max_retry_attempts: Optional[int] = Field(default=3, ge=1, le=10, description="Max retry attempts for simple branch")


class ViolationDetail(BaseModel):
    """Single violation detail"""
    rule: str
    issue: str
    severity: str
    source: Optional[str] = None
    suggestion: Optional[str] = None  # 修改建议


class BranchResult(BaseModel):
    """Result from a single branch"""
    branch: str
    success: bool
    is_compliant: bool
    violations: List[ViolationDetail]
    error: Optional[str] = None


class CertificateValidationResponse(BaseModel):
    """Response model for certificate validation"""
    success: bool
    certificate_id: Optional[str] = None
    is_compliant: bool
    simple_compliant: Optional[bool] = None
    precise_compliant: Optional[bool] = None
    violations: List[ViolationDetail]
    violation_count: int
    duration: float
    timestamp: str
    has_ambiguity: Optional[bool] = None
    needs_reprocessing: Optional[bool] = None
    routing: Dict
    simple_branch: Optional[Dict] = None
    precise_branch: Optional[Dict] = None


class BranchRoutingRequest(BaseModel):
    """Request model for branch routing preview"""
    rules: List[Dict] = Field(description="Rules to route")


class BranchRoutingResponse(BaseModel):
    """Response model for branch routing"""
    total: int
    precise_count: int
    simple_count: int
    precise_rules: List[Dict]
    simple_rules: List[Dict]
    precise_percentage: float
    simple_percentage: float


class ZLintCoverageRequest(BaseModel):
    """Request model for checking ZLint coverage"""
    rules: List[Dict] = Field(description="Rules to check coverage for")


class ZLintCoverageDetail(BaseModel):
    """Coverage detail for a single rule"""
    rule_text: str
    has_coverage: bool
    needs_generation: bool
    lint_name: Optional[str] = None
    expected_file: Optional[str] = None
    match_method: str = 'none'
    source_code: Optional[str] = None
    reasoning: Optional[str] = None
    confidence: Optional[float] = None


class ZLintCoverageResponse(BaseModel):
    """Response model for ZLint coverage check"""
    total_rules: int
    covered_count: int
    needs_generation_count: int
    coverage_percentage: float
    details: List[ZLintCoverageDetail]
    zlint_available: bool


# ========== Precise Branch Processing Schemas ==========

class GenerateCodeRequest(BaseModel):
    """Request model for generating ZLint code"""
    rules: List[Dict] = Field(description="Rules to generate code for")
    preview_only: bool = Field(default=True, description="If true, only generate code without saving")
    use_llm: bool = Field(default=True, description="If true, use LLM for intelligent code generation (higher accuracy)")



class GeneratedCodeDetail(BaseModel):
    """Generated code for a single rule"""
    rule_id: Optional[int] = None
    rule_text: str
    lint_name: str
    package_name: str
    file_path: str
    go_code: str
    test_code: Optional[str] = None
    has_coverage: bool
    needs_generation: bool
    generation_method: Optional[str] = None  # 'llm' or 'template'
    llm_used: Optional[bool] = None
    validation_passed: Optional[bool] = None
    can_compile: Optional[bool] = None  # Go编译是否通过
    compile_errors: Optional[List[Dict]] = None  # 编译错误列表


class GenerateCodeResponse(BaseModel):
    """Response model for code generation"""
    success: bool
    total_rules: int
    generated_count: int
    skipped_count: int
    generated_codes: List[GeneratedCodeDetail]
    error: Optional[str] = None


class SaveCodeRequest(BaseModel):
    """Request model for saving modified code"""
    lint_name: str
    package_name: str
    go_code: str
    file_path: Optional[str] = None


class SaveCodeResponse(BaseModel):
    """Response model for code save operation"""
    success: bool
    file_path: str
    compile_attempted: bool
    compile_success: Optional[bool] = None
    compile_output: Optional[str] = None
    error: Optional[str] = None


class CompileZLintRequest(BaseModel):
    """Request model for compiling ZLint"""
    test_mode: bool = Field(default=False, description="If true, run tests after compilation")


class CompileZLintResponse(BaseModel):
    """Response model for ZLint compilation"""
    success: bool
    compile_output: str
    test_output: Optional[str] = None
    compilation_time: float
    error: Optional[str] = None


class PreciseBranchProcessRequest(BaseModel):
    """Request model for complete precise branch processing"""
    cert_pem: str = Field(description="PEM-encoded certificate")
    rules: List[Dict] = Field(description="Rules to process")
    certificate_id: Optional[str] = None
    auto_compile: bool = Field(default=False, description="Automatically compile after code generation")


class ProcessingStep(BaseModel):
    """Single processing step in precise branch"""
    step_number: int
    step_name: str
    status: str  # pending, in_progress, completed, failed
    details: Optional[str] = None
    timestamp: Optional[datetime] = None


class PreciseBranchProcessResponse(BaseModel):
    """Response model for precise branch processing"""
    success: bool
    certificate_id: Optional[str] = None
    processing_steps: List[ProcessingStep]
    coverage_check: Optional[Dict] = None
    generated_codes: List[GeneratedCodeDetail]
    compilation_result: Optional[CompileZLintResponse] = None
    validation_result: Optional[Dict] = None
    total_duration: float
    error: Optional[str] = None


class BatchGenerateUncoveredRequest(BaseModel):
    """Request model for batch generating uncovered rules"""
    rule_ids: Optional[List[int]] = Field(default=None, description="Specific rule IDs to check (if None, use all precise rules)")
    auto_compile: bool = Field(default=True, description="Automatically compile after generation")


class BatchGenerateUncoveredResponse(BaseModel):
    """Response model for batch generation"""
    success: bool
    total_rules_checked: int
    uncovered_rules_count: int
    generated_codes_count: int
    skipped_count: int
    generated_codes: List[GeneratedCodeDetail]
    compilation_result: Optional[CompileZLintResponse] = None
    total_duration: float
    error: Optional[str] = None


# ========== ZLint Code Testing Schemas ==========

class TestCodeRequest(BaseModel):
    """Request model for testing a single ZLint code"""
    rule: Dict = Field(description="Rule to test")
    go_code: str = Field(description="Generated Go code")
    lint_name: str = Field(description="Lint name")
    package_name: str = Field(default="rfc", description="Package name")
    cert_count: int = Field(default=2, ge=1, le=10, description="Number of test certificates per type")


class TestStepResult(BaseModel):
    """Single test step result"""
    step: str
    success: bool
    details: Optional[Dict] = None
    error: Optional[str] = None


class TestAccuracy(BaseModel):
    """Test accuracy metrics"""
    valid_correct: int
    valid_total: int
    valid_accuracy: float
    invalid_correct: int
    invalid_total: int
    invalid_accuracy: float
    correct: int
    total: int
    total_accuracy: float


class TestCodeResponse(BaseModel):
    """Response model for code testing"""
    success: bool
    lint_name: str
    rule_text: str
    package_name: str
    timestamp: str
    steps: List[TestStepResult]
    accuracy: Optional[TestAccuracy] = None
    overall_success: bool
    duration: float
    error: Optional[str] = None


class BatchTestCodesRequest(BaseModel):
    """Request model for batch testing"""
    codes: List[Dict] = Field(description="List of codes to test, each with rule, go_code, lint_name, package_name")
    generate_report: bool = Field(default=True, description="Generate test report after batch test")


class BatchTestCodesResponse(BaseModel):
    """Response model for batch testing"""
    success: bool
    total: int
    passed: int
    failed: int
    pass_rate: float
    compile_success_count: int
    compile_success_rate: float
    avg_accuracy: float
    total_duration: float
    results: List[TestCodeResponse]
    report: Optional[str] = None  # Markdown report


class TestReportResponse(BaseModel):
    """Response model for test report"""
    success: bool
    report: str  # Markdown format
    test_count: int
    generated_at: str


# ========== Standard Search and Relationship Schemas ==========

class StandardSearchRequest(BaseModel):
    """Request model for searching standards"""
    query: Optional[str] = Field(default=None, description="Search query for title/version")
    source: Optional[str] = Field(default=None, description="Filter by source (RFC, CABF, ETSI, Browser_CA)")
    is_latest: Optional[bool] = Field(default=None, description="Filter by latest version flag")
    is_active: Optional[bool] = Field(default=None, description="Filter by active status (not obsoleted)")
    skip: int = Field(default=0, ge=0)
    limit: int = Field(default=100, ge=1, le=1000)


class StandardRelationshipResponse(BaseModel):
    """Response model for standard relationships"""
    id: int
    source_standard_id: int
    target_standard_id: int
    relationship_type: str
    description: Optional[str] = None
    section: Optional[str] = None
    confidence: float
    extraction_method: str
    is_active: bool
    created_at: datetime

    # Include related standard info
    source_standard: Optional[StandardInfo] = None
    target_standard: Optional[StandardInfo] = None

    class Config:
        from_attributes = True


class StandardWithRelationships(BaseModel):
    """Standard with its relationships"""
    standard: StandardResponse
    outgoing_relationships: List[StandardRelationshipResponse] = []
    incoming_relationships: List[StandardRelationshipResponse] = []
    is_active: bool  # 是否活跃（未被废弃）
    has_updates: bool  # 是否有更新版本
    obsoleted_by: List[int] = []  # 被哪些标准废弃
    updates: List[int] = []  # 更新了哪些标准


class StandardMetadata(BaseModel):
    """Extended standard metadata"""
    id: int
    source: str
    title: str
    version: Optional[str] = None
    url: str
    crawl_config: Optional[Dict] = None  # 爬取配置信息
    metadata: Optional[Dict] = None  # 解析后的metadata_json
    is_active: bool
    is_latest: bool
    relationship_summary: Optional[Dict] = None  # 关系摘要

    class Config:
        from_attributes = True
