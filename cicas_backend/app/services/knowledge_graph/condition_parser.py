"""
⚠️ DEPRECATED - 此文件已废弃 (2025-12-23)

原因：白名单条件解析机制与 ExceptionRule 设计理念冲突

ExceptionRule 的设计理念：
- 不要人工维护白名单（无法追溯到规范文本）
- 所有规则和例外都应该从 RFC/CABF 文本中自动提取

替代方案：
- 规则 IR 的 conditions 字段已经由 LLM 提取时填充
- 冲突检测器直接从 Rule.conditions (JSON) 字段加载 ConditionSet
- 无需白名单映射，直接使用结构化条件

迁移说明：
- logical_conflict_detector.py 已迁移到从 IR 加载条件
- 此文件保留仅供参考，将在未来版本中删除

============================================================

原文档：白名单条件解析器

基于《冲突和引用处理算法详解.md》第1层过滤器设计
将自然语言条件转换为结构化的 ConditionSet
"""
from typing import Dict, List, Tuple, Optional, Set
import re
from app.core.unified_abstractions import ConditionSet
from app.core.logging_config import app_logger


class WhitelistDimension:
    """白名单维度定义"""

    def __init__(self, name: str, values: List[Tuple[str, List[str]]]):
        """
        Args:
            name: 维度名称（如 "cert_profile"）
            values: [(标准值, [匹配模式列表])]
        """
        self.name = name
        self.value_patterns = values  # [(标准值, [匹配模式])]

    def match(self, text: str) -> Optional[str]:
        """
        在文本中匹配该维度的值

        Returns:
            匹配到的标准值，如果没有匹配返回 None
        """
        text_lower = text.lower()

        for standard_value, patterns in self.value_patterns:
            for pattern in patterns:
                if pattern.lower() in text_lower:
                    return standard_value

        return None


# 定义10个核心维度的白名单
WHITELIST_DIMENSIONS = {
    # 维度1：证书类型
    "cert_profile": WhitelistDimension(
        "cert_profile",
        [
            ("TLS_SERVER", ["tls server", "server certificate", "subscriber certificate", "end entity"]),
            ("TLS_CLIENT", ["tls client", "client certificate"]),
            ("CA", ["ca certificate", "certification authority", "intermediate ca"]),
            ("ROOT_CA", ["root ca", "root certificate", "trust anchor"]),
            ("OCSP", ["ocsp responder", "ocsp signing"]),
            ("CODE_SIGNING", ["code signing", "codesigning"]),
            ("EMAIL", ["email certificate", "s/mime"]),
        ]
    ),

    # 维度2：扩展密钥用途 (EKU)
    "eku": WhitelistDimension(
        "eku",
        [
            ("serverAuth", ["serverauth", "server authentication", "id-kp-serverauth"]),
            ("clientAuth", ["clientauth", "client authentication", "id-kp-clientauth"]),
            ("emailProtection", ["emailprotection", "email protection", "id-kp-emailprotection"]),
            ("codeSigning", ["codesigning", "code signing", "id-kp-codesigning"]),
            ("timeStamping", ["timestamping", "time stamping", "id-kp-timestamping"]),
            ("OCSPSigning", ["ocspsigning", "ocsp signing", "id-kp-ocspsigning"]),
        ]
    ),

    # 维度3：密钥用途 (KeyUsage)
    "key_usage": WhitelistDimension(
        "key_usage",
        [
            ("digitalSignature", ["digitalsignature", "digital signature"]),
            ("keyEncipherment", ["keyencipherment", "key encipherment"]),
            ("dataEncipherment", ["dataencipherment", "data encipherment"]),
            ("keyAgreement", ["keyagreement", "key agreement"]),
            ("keyCertSign", ["keycertsign", "key cert sign", "certificate signing"]),
            ("cRLSign", ["crlsign", "crl sign", "crl signing"]),
            ("encipherOnly", ["encipheronly", "encipher only"]),
            ("decipherOnly", ["decipheronly", "decipher only"]),
        ]
    ),

    # 维度4：密钥算法
    "key_algorithm": WhitelistDimension(
        "key_algorithm",
        [
            ("RSA", ["rsa", "rsaencryption"]),
            ("ECDSA", ["ecdsa", "ec", "elliptic curve"]),
            ("EdDSA", ["eddsa", "ed25519", "ed448"]),
            ("DSA", ["dsa", "digital signature algorithm"]),
        ]
    ),

    # 维度5：签名算法
    "signature_algorithm": WhitelistDimension(
        "signature_algorithm",
        [
            ("SHA256withRSA", ["sha256withrsa", "sha-256 with rsa"]),
            ("SHA384withRSA", ["sha384withrsa", "sha-384 with rsa"]),
            ("SHA512withRSA", ["sha512withrsa", "sha-512 with rsa"]),
            ("ECDSAwithSHA256", ["ecdsawithsha256", "ecdsa with sha-256"]),
            ("ECDSAwithSHA384", ["ecdsawithsha384", "ecdsa with sha-384"]),
        ]
    ),

    # 维度6：BasicConstraints.cA
    "ca_flag": WhitelistDimension(
        "ca_flag",
        [
            ("TRUE", ["ca:true", "ca=true", "ca field true", "ca must be true"]),
            ("FALSE", ["ca:false", "ca=false", "ca field false", "ca must be false"]),
        ]
    ),

    # 维度7：Critical 标记
    "critical_flag": WhitelistDimension(
        "critical_flag",
        [
            ("CRITICAL", ["critical", "must be critical", "marked as critical"]),
            ("NON_CRITICAL", ["non-critical", "not critical", "must not be critical"]),
        ]
    ),

    # 维度8：有效期约束
    "validity_period": WhitelistDimension(
        "validity_period",
        [
            ("398_DAYS", ["398 days", "398 day", "398-day"]),
            ("825_DAYS", ["825 days", "825 day", "825-day"]),
            ("1095_DAYS", ["1095 days", "1095 day", "three years"]),
            ("39_MONTHS", ["39 months", "39 month"]),
        ]
    ),

    # 维度9：证书策略 OID
    "certificate_policy": WhitelistDimension(
        "certificate_policy",
        [
            ("DV", ["domain validated", "dv certificate", "2.23.140.1.2.1"]),
            ("OV", ["organization validated", "ov certificate", "2.23.140.1.2.2"]),
            ("EV", ["extended validation", "ev certificate", "2.23.140.1.1"]),
        ]
    ),

    # 维度10：名称约束
    "name_constraints": WhitelistDimension(
        "name_constraints",
        [
            ("PERMITTED", ["permitted subtrees", "permitted names"]),
            ("EXCLUDED", ["excluded subtrees", "excluded names"]),
        ]
    ),
}


class ConditionParser:
    """条件解析器

    将规则的自然语言条件转换为结构化的 ConditionSet
    """

    def __init__(self):
        self.dimensions = WHITELIST_DIMENSIONS

    def parse_condition(self, rule_text: str, condition_text: Optional[str] = None) -> Tuple[ConditionSet, List[str]]:
        """
        解析条件

        Args:
            rule_text: 规则文本（用于兜底搜索）
            condition_text: 显式的条件文本（如果有）

        Returns:
            (ConditionSet, unmapped_phrases)
            - ConditionSet: 解析出的条件集合
            - unmapped_phrases: 无法映射的短语列表
        """
        # 优先使用显式条件文本，否则使用规则文本
        text_to_parse = condition_text if condition_text else rule_text

        if not text_to_parse:
            # 空文本 → 空条件集（全局适用）
            return ConditionSet(conditions=[], logic="AND"), []

        # 解析条件
        conditions = []
        matched_phrases = set()

        for dim_name, dimension in self.dimensions.items():
            matched_value = dimension.match(text_to_parse)
            if matched_value:
                conditions.append({
                    "dimension": dim_name,
                    "value": matched_value,
                    "source": "whitelist"
                })
                # 记录已匹配的部分（用于后续unmapped检测）
                for std_val, patterns in dimension.value_patterns:
                    if std_val == matched_value:
                        for pattern in patterns:
                            if pattern.lower() in text_to_parse.lower():
                                matched_phrases.add(pattern)

        # 检测 unmapped 短语（简化版）
        unmapped = self._detect_unmapped(text_to_parse, matched_phrases)

        # 构造 ConditionSet
        condition_set = ConditionSet(
            conditions=conditions,
            logic="AND"  # 默认用 AND 逻辑
        )

        if unmapped:
            app_logger.warning(f"Unmapped condition phrases: {unmapped}")

        return condition_set, unmapped

    def _detect_unmapped(self, text: str, matched_phrases: Set[str]) -> List[str]:
        """
        检测无法映射的短语

        简化实现：提取关键词，排除已匹配的部分
        """
        unmapped = []

        # 提取潜在的条件关键词
        keywords = [
            "for", "when", "if", "where", "applies to", "applicable",
            "except", "unless", "with", "containing", "having"
        ]

        text_lower = text.lower()
        for keyword in keywords:
            if keyword in text_lower:
                # 提取关键词附近的上下文
                idx = text_lower.find(keyword)
                snippet = text[idx:idx+50].strip()

                # 检查是否已被白名单匹配
                is_matched = any(phrase.lower() in snippet.lower() for phrase in matched_phrases)

                if not is_matched:
                    unmapped.append(snippet)

        return unmapped[:5]  # 最多返回5个unmapped短语


# 全局单例
_condition_parser = None

def get_condition_parser() -> ConditionParser:
    """获取条件解析器单例"""
    global _condition_parser
    if _condition_parser is None:
        _condition_parser = ConditionParser()
    return _condition_parser
