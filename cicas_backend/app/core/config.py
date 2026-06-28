"""
Core configuration module using Pydantic settings
"""
from pydantic_settings import BaseSettings
from pydantic import Field
from typing import Optional
import os
from pathlib import Path

# 获取 iccas_backend 目录的绝对路径
BACKEND_DIR = Path(__file__).parent.parent.parent.resolve()


class Settings(BaseSettings):
    """Application settings loaded from environment variables"""

    # Database Configuration
    database_url: str = Field(default="postgresql://postgres:123456@localhost:5432/pki_standards")
    db_host: str = Field(default="localhost")
    db_port: int = Field(default=5432)
    db_name: str = Field(default="pki_standards")
    db_user: str = Field(default="postgres")
    db_password: str = Field(default="123456")

    # Redis Configuration
    redis_host: str = Field(default="localhost")
    redis_port: int = Field(default=6379)
    redis_db: int = Field(default=0)
    redis_password: Optional[str] = Field(default=None)
    redis_cache_ttl_hours: int = Field(default=24)
    use_redis_cache: bool = Field(default=True)

    # LLM Configuration (SiliconFlow - Qwen3-8B)
    # 策略：使用 Qwen/Qwen3-8B 作为主模型
    # - SiliconFlow
    # - Qwen3-8B: 128K context, 32K max output
    llm_api_key: str = Field(default="sk-94293042a13e21774be92ac6d1153b807f3ea2b15083e70a814fbb49a05b22aa")
    llm_api_base: str = Field(default="https://ai.ailink1.com/v1")
    llm_model: str = Field(default="gpt-5.4")
    llm_provider: str = Field(
        default="openai_compatible",
        description="LLM provider override: anthropic or openai_compatible. Empty means infer from api_base."
    )
    llm_context_window: int = Field(
        default=131072,
        description="LLM模型的输入上下文窗口大小（tokens）。Qwen3-8B=128K"
    )
    llm_max_output_tokens: int = Field(
        default=32768,
        description="LLM模型的最大输出 token 数。Qwen3-8B=32K"
    )
    llm_max_concurrency: int = Field(
        default=2,
        description="LLM API 最大并发请求数（免费模型速率限制更严，降低并发）"
    )

    # DISABLED: Challenger Module removed (part of adversarial learning)
    # challenger_llm_api_key: str = Field(default="")
    # challenger_llm_api_base: str = Field(default="https://api.siliconflow.cn/v1")
    # challenger_llm_model: str = Field(default="Qwen/Qwen2.5-7B-Instruct")

    # Crawler Configuration
    user_agent: str = Field(default="Mozilla/5.0 (PKI Standards Crawler Bot)")
    request_timeout: int = Field(default=30)
    max_retries: int = Field(default=3)
    rate_limit_delay: float = Field(default=1.0)

    # Censys API Configuration
    censys_api_id: Optional[str] = Field(default=None, validation_alias="CENSYS_API_ID")
    censys_api_secret: Optional[str] = Field(default=None, validation_alias="CENSYS_API_SECRET")

    # Storage Paths (relative paths from working directory)
    # NOTE: Backend must be started from iccas_backend directory
    data_raw_path: str = Field(default="data/raw")
    data_processed_path: str = Field(default="data/processed")
    logs_path: str = Field(default="data/logs")
    zlint_path: str = Field(default="zlint")

    # zlint Validation Paths
    ZLINT_REPO_PATH: str = Field(default=str(BACKEND_DIR / "zlint"))
    VALIDATION_OUTPUT_DIR: str = Field(default=str(BACKEND_DIR / "validation_output"))

    # Standard Sources
    rfc_base_url: str = Field(default="https://datatracker.ietf.org/doc/html")
    rfc_text_base_url: str = Field(default="https://www.rfc-editor.org/rfc")

    # CABF URLs
    cabf_base_url: str = Field(default="https://cabforum.org")
    cabf_br_url: str = Field(default="https://cabforum.org/working-groups/server/baseline-requirements/documents/")
    cabf_ev_url: str = Field(default="https://cabforum.org/working-groups/server/extended-validation/documents/")
    cabf_smime_url: str = Field(default="https://cabforum.org/working-groups/smime/documents/")
    cabf_netsec_url: str = Field(default="https://cabforum.org/working-groups/netsec/documents/")
    cabf_cs_url: str = Field(default="https://cabforum.org/working-groups/code-signing/documents/")

    # ETSI URLs
    etsi_base_url: str = Field(default="https://www.etsi.org")
    etsi_en_base_url: str = Field(default="https://www.etsi.org/deliver/etsi_en")
    etsi_ts_base_url: str = Field(default="https://www.etsi.org/deliver/etsi_ts")

    # Browser CA Policy URLs
    mozilla_ca_url: str = Field(default="https://www.mozilla.org/en-US/about/governance/policies/security-group/certs/policy/")
    chrome_ca_url: str = Field(default="https://www.chromium.org/Home/chromium-security/root-ca-policy/")
    apple_ca_url: str = Field(default="https://www.apple.com/certificateauthority/ca_program.html")
    microsoft_ca_url: str = Field(default="https://aka.ms/RootCert")

    # Other Standards
    itu_x509_url: str = Field(default="https://www.itu.int/rec/T-REC-X.509")

    # Scheduler Configuration
    enable_scheduler: bool = Field(default=True)
    update_schedule_cron: str = Field(default="0 0 * * 0")
    timezone: str = Field(default="UTC")

    # Standards Update Scheduler Configuration
    enable_standards_update: bool = Field(default=True, description="Enable automatic standards update")
    standards_update_time: str = Field(default="11:00", description="Time to update standards daily (HH:MM format)")

    # Zlint Update Scheduler Configuration
    enable_zlint_update: bool = Field(default=True, description="Enable automatic zlint repository update")
    zlint_update_time: str = Field(default="10:00", description="Time to update zlint daily (HH:MM format)")
    zlint_repo_url: str = Field(default="https://github.com/zmap/zlint.git", description="Zlint repository URL")

    # Embedding API Configuration
    embedding_api_key: str = Field(default="", validation_alias="EMBEDDING_API_KEY")
    embedding_api_base: str = Field(default="https://api.siliconflow.cn/v1")
    embedding_model: str = Field(default="BAAI/bge-m3")
    embedding_dimension: int = Field(default=1024)

    # Evidence System Thresholds
    evidence_confidence_threshold_accept: float = Field(default=0.7, description="自动接受阈值")
    evidence_confidence_threshold_reject: float = Field(default=0.5, description="自动拒绝阈值")

    # Validation Settings
    min_consistency_rate: float = Field(default=0.90)
    enable_cross_validation: bool = Field(default=True)
    use_llm_rule_validation: bool = Field(default=True)  # 使用LLM进行规则语义验证

    # Certificate Validation Statistics Configuration
    stats_top_errors_count: int = Field(
        default=10,
        description="统计分析中显示的错误（errors）数量"
    )
    stats_top_warnings_count: int = Field(
        default=10,
        description="统计分析中显示的警告（warnings）数量"
    )

    # DISABLED: Two-Stage Validation Configuration (removed)
    # enable_two_stage_validation: bool = Field(
    #     default=False,
    #     description="启用两阶段验证（先simple branch LLM筛查，再precise branch zlint验证）。False则直接使用zlint"
    # )

    # Regex Rule Quality Gate Configuration (Layer 3去重时的质量门控)
    regex_quality_enable_llm_verify: bool = Field(
        default=True,
        description="启用LLM验证regex规则（对中等置信度规则进行深度验证）"
    )
    regex_quality_heuristic_min: float = Field(
        default=0.5,
        description="启发式过滤最低阈值（<此值直接过滤，无需LLM验证）"
    )
    regex_quality_llm_verify_min: float = Field(
        default=0.5,
        description="LLM验证最低阈值（>=此值才进入LLM验证）"
    )
    regex_quality_llm_verify_max: float = Field(
        default=0.7,
        description="LLM验证最高阈值（>此值直接通过，无需LLM验证）"
    )
    regex_quality_llm_batch_size: int = Field(
        default=10,
        description="LLM验证批次大小（控制并发和成本）"
    )

    # Adversarial Learning Thresholds (对抗学习阈值配置)

    # zlint覆盖阈值（统一阈值：标记覆盖、自动通过、进入RAG）
    zlint_coverage_threshold: float = Field(
        default=0.95,
        description="zlint覆盖阈值：match_confidence>=此值表示已覆盖，自动通过审核，直接进入RAG"
    )

    # LLM语义判断阈值（LLM内部使用，判断候选lint是否匹配）
    zlint_llm_confidence_threshold: float = Field(
        default=0.75,
        description="LLM语义判断阈值（LLM返回的confidence>=此值才认为匹配成功）"
    )

    # DISABLED: Quality score threshold removed (part of adversarial learning)
    # quality_auto_approve_threshold: float = Field(default=90, description="...")


    # ========== 完整性检查配置 (Completeness Check) ==========
    completeness_check_enabled: bool = Field(default=True, description="是否启用完整性检查")
    completeness_coverage_threshold: float = Field(default=0.80, description="完整性覆盖率阈值")
    completeness_doc_sample_length: int = Field(default=5000, description="文档采样长度")
    completeness_llm_temperature: float = Field(default=0.1, description="LLM温度参数")

    # ========== 冗余性检查配置 (Redundancy Check) ==========
    redundancy_check_enabled: bool = Field(default=True, description="是否启用冗余性检查")
    redundancy_rate_threshold: float = Field(default=0.15, description="冗余率阈值")
    redundancy_similarity_threshold: float = Field(default=0.85, description="相似度阈值")
    redundancy_max_rules_check: int = Field(default=100, description="最多检查规则数")
    redundancy_llm_temperature: float = Field(default=0.1, description="LLM温度参数")

    # API Configuration
    api_host: str = Field(default="0.0.0.0")
    api_port: int = Field(default=8000)
    api_reload: bool = Field(default=True)
    log_level: str = Field(default="INFO")

    class Config:
        env_file = ".env"
        case_sensitive = False
        extra = "ignore"  # 忽略.env中的额外字段（如已删除的配置项）

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        # Ensure directories exist
        Path(self.data_raw_path).mkdir(parents=True, exist_ok=True)
        Path(self.data_processed_path).mkdir(parents=True, exist_ok=True)
        Path(self.logs_path).mkdir(parents=True, exist_ok=True)


# Global settings instance
settings = Settings()
