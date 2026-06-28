"""
规则系统配置管理器

统一管理所有阈值、关键词、字段映射等配置，
替代硬编码，支持热加载和版本管理。

设计原则：
1. 所有业务配置必须可外部化
2. 支持配置继承和覆盖（默认 < 文件 < 环境变量）
3. 配置变更可审计和回滚
4. 类型安全和验证
"""

from typing import Dict, List, Optional, Any, Set
from pydantic import BaseModel, Field, validator
from pathlib import Path
import yaml
import json
from datetime import datetime
from enum import Enum
import os


# ============================================================
# 配置数据模型
# ============================================================

class ReferencePatternConfig(BaseModel):
    """引用模式配置"""
    name: str = Field(..., description="模式名称")
    regex: str = Field(..., description="正则表达式")
    doc_type: str = Field(..., description="文档类型")
    priority: int = Field(..., description="优先级")
    capture_groups: Dict[str, int] = Field(default_factory=dict, description="捕获组映射")
    requires_context: bool = Field(False, description="是否需要上下文验证")


class ConflictDetectionConfig(BaseModel):
    """冲突检测配置"""

    # 性能参数
    enable_parallel: bool = Field(True, description="是否启用并行检测")
    max_workers: int = Field(4, description="最大并行工作线程数")
    batch_size: int = Field(100, description="批处理大小")

    # 可满足性判定参数
    enable_smt_solver: bool = Field(False, description="是否启用SMT求解器（Z3）")
    smt_timeout_ms: int = Field(5000, description="SMT求解器超时时间（毫秒）")

    # 冲突类型启用/禁用
    detect_hard_conflicts: bool = Field(True, description="检测硬冲突")
    detect_refinement_conflicts: bool = Field(True, description="检测细化型冲突")
    detect_conditional_conflicts: bool = Field(True, description="检测条件交叠冲突")
    detect_transitive_conflicts: bool = Field(False, description="检测传递冲突（性能开销大）")


class FieldMappingConfig(BaseModel):
    """字段映射配置"""

    # 字段依赖关系
    field_dependencies: Dict[str, List[str]] = Field(
        default_factory=dict,
        description="字段依赖关系，如 {'extensions.extKeyUsage': ['extensions.keyUsage']}"
    )

    # 字段别名（用于归一化）
    field_aliases: Dict[str, str] = Field(
        default_factory=dict,
        description="字段别名映射，如 {'basicConstraints': 'extensions.basicConstraints'}"
    )

    # 已知扩展字段
    known_extensions: List[str] = Field(
        default_factory=lambda: [
            "basicConstraints", "keyUsage", "extKeyUsage", "subjectAltName",
            "authorityKeyIdentifier", "subjectKeyIdentifier", "cRLDistributionPoints",
            "certificatePolicies", "policyConstraints", "nameConstraints",
            "issuerAltName", "subjectDirectoryAttributes", "authorityInfoAccess",
            "privateKeyUsagePeriod", "certificateIssuer", "cRLNumber",
            "issuingDistributionPoint", "deltaCRLIndicator", "freshestCRL"
        ],
        description="已知的证书扩展字段"
    )


class QualityThresholdsConfig(BaseModel):
    """质量阈值配置"""

    # 提取置信度阈值
    min_extraction_confidence: float = Field(0.7, description="最小提取置信度", ge=0.0, le=1.0)

    # 文档验证阈值
    document_match_threshold: float = Field(0.75, description="文档匹配阈值", ge=0.0, le=1.0)

    # 字段映射置信度
    field_confidence_threshold: float = Field(0.70, description="字段置信度阈值", ge=0.0, le=1.0)

    # 语义相似度阈值
    semantic_similarity_threshold: float = Field(0.85, description="语义相似度阈值", ge=0.0, le=1.0)

    # DISABLED: Quality score threshold removed (part of adversarial learning)
    # min_quality_score: float = Field(50.0, description="最小质量评分", ge=0.0, le=100.0)


class DocumentTypeConfig(BaseModel):
    """文档类型配置"""

    # 文档类型优先级
    priority_map: Dict[str, int] = Field(
        default_factory=lambda: {
            "CUSTOM": 100,
            "Mozilla": 90,
            "Apple": 90,
            "Microsoft": 90,
            "Chrome": 90,
            "CABF-BR": 80,
            "CABF-EV": 80,
            "CABF-CS": 80,
            "ETSI-EN": 70,
            "ETSI-TS": 70,
            "RFC": 60,
        },
        description="文档类型优先级映射"
    )

    # 文档细化关系
    refinement_map: Dict[str, List[str]] = Field(
        default_factory=lambda: {
            "CABF-BR": ["RFC"],
            "CABF-EV": ["RFC", "CABF-BR"],
            "CABF-CS": ["RFC"],
            "Mozilla": ["RFC", "CABF-BR"],
            "Apple": ["RFC", "CABF-BR"],
            "Microsoft": ["RFC", "CABF-BR"],
            "Chrome": ["RFC", "CABF-BR"],
            "ETSI-EN": ["RFC"],
            "ETSI-TS": ["RFC"],
        },
        description="文档细化关系（derived -> [base]）"
    )


class RuleSystemConfig(BaseModel):
    """规则系统总配置"""

    # 版本信息
    version: str = Field("1.0.0", description="配置版本")
    last_updated: datetime = Field(default_factory=datetime.now, description="最后更新时间")

    # 子配置
    reference_patterns: List[ReferencePatternConfig] = Field(
        default_factory=list,
        description="引用模式配置列表"
    )

    conflict_detection: ConflictDetectionConfig = Field(
        default_factory=ConflictDetectionConfig,
        description="冲突检测配置"
    )

    field_mapping: FieldMappingConfig = Field(
        default_factory=FieldMappingConfig,
        description="字段映射配置"
    )

    quality_thresholds: QualityThresholdsConfig = Field(
        default_factory=QualityThresholdsConfig,
        description="质量阈值配置"
    )

    document_types: DocumentTypeConfig = Field(
        default_factory=DocumentTypeConfig,
        description="文档类型配置"
    )

    # 扩展配置（允许任意键值对）
    extensions: Dict[str, Any] = Field(
        default_factory=dict,
        description="扩展配置，用于插件等"
    )


# ============================================================
# 配置管理器
# ============================================================

class ConfigManager:
    """
    配置管理器

    职责：
    1. 加载和验证配置
    2. 提供类型安全的配置访问
    3. 支持配置热加载
    4. 支持配置版本管理和回滚
    """

    def __init__(self, config_path: Optional[Path] = None):
        """
        初始化配置管理器

        Args:
            config_path: 配置文件路径（YAML或JSON）
                        如果为None，使用默认配置
        """
        self.config_path = config_path
        self.config: RuleSystemConfig = self._load_config()
        self._config_history: List[RuleSystemConfig] = [self.config]

    def _load_config(self) -> RuleSystemConfig:
        """
        加载配置

        优先级：环境变量 > 配置文件 > 默认配置
        """
        # Step 1: 加载默认配置
        config_dict = self._get_default_config()

        # Step 2: 如果有配置文件，覆盖默认配置
        if self.config_path and self.config_path.exists():
            file_config = self._load_from_file(self.config_path)
            config_dict = self._merge_configs(config_dict, file_config)

        # Step 3: 环境变量覆盖（如果有）
        env_config = self._load_from_env()
        if env_config:
            config_dict = self._merge_configs(config_dict, env_config)

        # Step 4: 验证和构造配置对象
        return RuleSystemConfig(**config_dict)

    def _get_default_config(self) -> Dict:
        """获取默认配置"""
        return {
            "version": "1.0.0",
            "reference_patterns": self._get_default_reference_patterns(),
            "conflict_detection": {
                "enable_parallel": True,
                "max_workers": 4,
                "batch_size": 100,
                "enable_smt_solver": False,
                "smt_timeout_ms": 5000,
                "detect_hard_conflicts": True,
                "detect_refinement_conflicts": True,
                "detect_conditional_conflicts": True,
                "detect_transitive_conflicts": False
            },
            "field_mapping": {
                "field_dependencies": {
                    "extensions.subjectAltName": ["subject"],
                    "extensions.issuerAltName": ["issuer"],
                    "extensions.extendedKeyUsage": ["extensions.keyUsage"],
                    "extensions.authorityKeyIdentifier": ["extensions.subjectKeyIdentifier"],
                    "extensions.authorityInfoAccess": ["extensions.basicConstraints"],
                    "validity.notAfter": ["validity.notBefore"],
                },
                "field_aliases": {
                    "basicConstraints": "extensions.basicConstraints",
                    "keyUsage": "extensions.keyUsage",
                    "extKeyUsage": "extensions.extKeyUsage",
                    "subjectAltName": "extensions.subjectAltName",
                    "SAN": "extensions.subjectAltName",
                }
            },
            "quality_thresholds": {
                "min_extraction_confidence": 0.7,
                "document_match_threshold": 0.75,
                "field_confidence_threshold": 0.70,
                "semantic_similarity_threshold": 0.85
            }
        }

    def _get_default_reference_patterns(self) -> List[Dict]:
        """获取默认引用模式"""
        return [
            {
                "name": "RFC_WITH_SECTION",
                "regex": r'\bRFC\s+(\d+)\s*,?\s+[Ss]ection\s+(\d+(?:\.\d+)*)',
                "doc_type": "RFC",
                "capture_groups": {"doc_number": 1, "section": 2},
                "priority": 100
            },
            {
                "name": "RFC_ONLY",
                "regex": r'\bRFC\s+(\d+)\b',
                "doc_type": "RFC",
                "capture_groups": {"doc_number": 1},
                "priority": 80
            },
            {
                "name": "CABF_BR_WITH_SECTION",
                "regex": r'\b(?:CABF\s+)?(?:Baseline\s+Requirements?|BR)\s+[Ss]ection\s+(\d+(?:\.\d+)*)',
                "doc_type": "CABF-BR",
                "capture_groups": {"section": 1},
                "priority": 90
            },
            {
                "name": "ETSI_WITH_SECTION",
                "regex": r'\bETSI\s+(?:EN|TS)\s+(\d+(?:-\d+)*)\s+[Ss]ection\s+(\d+(?:\.\d+)*)',
                "doc_type": "ETSI-EN",
                "capture_groups": {"doc_number": 1, "section": 2},
                "priority": 90
            },
            {
                "name": "SECTION_ONLY",
                "regex": r'[Ss]ection\s+([\d.]+)',
                "doc_type": "",  # 需要从上下文推断
                "capture_groups": {"section": 1},
                "priority": 50,
                "requires_context": True
            }
        ]

    def _load_from_file(self, path: Path) -> Dict:
        """从文件加载配置"""
        with open(path, 'r', encoding='utf-8') as f:
            if path.suffix in ['.yaml', '.yml']:
                return yaml.safe_load(f) or {}
            elif path.suffix == '.json':
                return json.load(f)
            else:
                raise ValueError(f"Unsupported config file format: {path.suffix}")

    def _load_from_env(self) -> Optional[Dict]:
        """从环境变量加载配置"""
        # 支持通过环境变量覆盖关键配置
        env_config = {}

        # 示例：RULE_SYSTEM_MIN_CONFIDENCE=0.8
        if "RULE_SYSTEM_MIN_CONFIDENCE" in os.environ:
            env_config.setdefault("quality_thresholds", {})
            env_config["quality_thresholds"]["min_extraction_confidence"] = \
                float(os.environ["RULE_SYSTEM_MIN_CONFIDENCE"])

        # 示例：RULE_SYSTEM_ENABLE_SMT=true
        if "RULE_SYSTEM_ENABLE_SMT" in os.environ:
            env_config.setdefault("conflict_detection", {})
            env_config["conflict_detection"]["enable_smt_solver"] = \
                os.environ["RULE_SYSTEM_ENABLE_SMT"].lower() == "true"

        return env_config if env_config else None

    def _merge_configs(self, base: Dict, override: Dict) -> Dict:
        """
        深度合并配置

        override 中的值会覆盖 base 中的值
        """
        result = base.copy()

        for key, value in override.items():
            if key in result and isinstance(result[key], dict) and isinstance(value, dict):
                result[key] = self._merge_configs(result[key], value)
            else:
                result[key] = value

        return result

    # ========== 配置访问接口 ==========

    def get_reference_patterns(self) -> List[ReferencePatternConfig]:
        """获取引用模式配置"""
        return self.config.reference_patterns

    def get_conflict_detection_config(self) -> ConflictDetectionConfig:
        """获取冲突检测配置"""
        return self.config.conflict_detection

    def get_field_mapping_config(self) -> FieldMappingConfig:
        """获取字段映射配置"""
        return self.config.field_mapping

    def get_quality_thresholds(self) -> QualityThresholdsConfig:
        """获取质量阈值配置"""
        return self.config.quality_thresholds

    def get_document_type_config(self) -> DocumentTypeConfig:
        """获取文档类型配置"""
        return self.config.document_types

    def get_extension(self, key: str, default: Any = None) -> Any:
        """获取扩展配置"""
        return self.config.extensions.get(key, default)

    # ========== 配置管理 ==========

    def reload(self):
        """重新加载配置"""
        old_config = self.config
        try:
            new_config = self._load_config()
            self.config = new_config
            self._config_history.append(new_config)
            return True
        except Exception as e:
            self.config = old_config
            raise RuntimeError(f"Failed to reload config: {e}")

    def save(self, path: Optional[Path] = None):
        """保存当前配置到文件"""
        target_path = path or self.config_path

        if not target_path:
            raise ValueError("No config path specified")

        config_dict = self.config.dict()

        with open(target_path, 'w', encoding='utf-8') as f:
            if target_path.suffix in ['.yaml', '.yml']:
                yaml.dump(config_dict, f, default_flow_style=False, allow_unicode=True)
            elif target_path.suffix == '.json':
                json.dump(config_dict, f, indent=2, ensure_ascii=False)
            else:
                raise ValueError(f"Unsupported config file format: {target_path.suffix}")

    def rollback(self) -> bool:
        """回滚到上一个配置版本"""
        if len(self._config_history) < 2:
            return False

        self._config_history.pop()  # 移除当前配置
        self.config = self._config_history[-1]
        return True

    def get_version(self) -> str:
        """获取配置版本"""
        return self.config.version

    def get_history_count(self) -> int:
        """获取配置历史数量"""
        return len(self._config_history)


# ============================================================
# 全局配置管理器实例（单例）
# ============================================================

_global_config_manager: Optional[ConfigManager] = None


def get_config_manager(config_path: Optional[Path] = None) -> ConfigManager:
    """
    获取全局配置管理器实例

    Args:
        config_path: 配置文件路径（仅在首次调用时有效）

    Returns:
        ConfigManager实例
    """
    global _global_config_manager

    if _global_config_manager is None:
        _global_config_manager = ConfigManager(config_path)

    return _global_config_manager


def reset_config_manager():
    """重置全局配置管理器（主要用于测试）"""
    global _global_config_manager
    _global_config_manager = None


# ============================================================
# 便捷函数
# ============================================================

def get_reference_patterns() -> List[ReferencePatternConfig]:
    """获取引用模式配置（便捷函数）"""
    return get_config_manager().get_reference_patterns()


def get_conflict_detection_config() -> ConflictDetectionConfig:
    """获取冲突检测配置（便捷函数）"""
    return get_config_manager().get_conflict_detection_config()


def get_field_mapping_config() -> FieldMappingConfig:
    """获取字段映射配置（便捷函数）"""
    return get_config_manager().get_field_mapping_config()


def get_quality_thresholds() -> QualityThresholdsConfig:
    """获取质量阈值配置（便捷函数）"""
    return get_config_manager().get_quality_thresholds()


def get_document_type_config() -> DocumentTypeConfig:
    """获取文档类型配置（便捷函数）"""
    return get_config_manager().get_document_type_config()
