"""
规则字段提取器
从规则文本中提取结构化信息：affected_field, operation, expected_value, condition
"""
import re
from typing import Dict, Optional, List, Any
from app.core.logging_config import app_logger


class RuleFieldExtractor:
    """提取规则的结构化字段"""

    # 证书字段映射
    CERTIFICATE_FIELDS = {
        # Extensions
        'subjectaltname|subject alternative name|san|dnsname|dns name': 'extensions.subjectAltName',
        'keyusage|key usage': 'extensions.keyUsage',
        'extendedkeyusage|extended key usage|eku': 'extensions.extendedKeyUsage',
        'basicconstraints|basic constraints': 'extensions.basicConstraints',
        'certificatepolicies|certificate policies': 'extensions.certificatePolicies',
        'crldistributionpoints|crl distribution points|crl distribution point': 'extensions.cRLDistributionPoints',
        'authorityinformationaccess|authority information access|aia': 'extensions.authorityInfoAccess',
        'subjectkeyidentifier|subject key identifier|ski': 'extensions.subjectKeyIdentifier',
        'authoritykeyidentifier|authority key identifier|aki': 'extensions.authorityKeyIdentifier',
        'nameconstraints|name constraints': 'extensions.nameConstraints',
        'policyconstraints|policy constraints': 'extensions.policyConstraints',
        'subjectinformationaccess|subject information access|sia': 'extensions.subjectInfoAccess',
        'inhibitanypolicy|inhibit any policy': 'extensions.inhibitAnyPolicy',
        'policymappings|policy mappings': 'extensions.policyMappings',
        'freshestcrl|freshest crl': 'extensions.freshestCRL',
        'ocspnocheck|ocsp no check': 'extensions.ocspNoCheck',

        # Core fields
        'validity period|validity|notbefore|notafter': 'validity',
        'subject|subject dn|subject name': 'subject',
        'issuer|issuer dn|issuer name': 'issuer',
        'serial number|serialnumber': 'serialNumber',
        'signature algorithm|signaturealgorithm': 'signatureAlgorithm',
        'public keys?|publickey|rsa keys?|rsa public keys?|ec keys?': 'subjectPublicKeyInfo',
        'rsa modulus': 'subjectPublicKeyInfo.rsaKey',
        'elliptic curve|ecdsa': 'subjectPublicKeyInfo.ecKey',
        'version': 'version',
    }

    # 操作类型模式（按优先级排序 - 更具体的模式在前）
    OPERATION_PATTERNS = {
        # Critical flag (must be before general "must be")
        r'\b(must|shall)\s+be\s+(marked\s+as\s+)?critical\b': 'must_be_critical',
        r'\b(must|shall)\s+not\s+be\s+(marked\s+as\s+)?critical\b': 'must_not_be_critical',

        # Value checks - MUST come before presence checks to avoid "must have" matching first
        r'\b(must|shall)\s+be\s+at\s+least\b': 'minimum_value',
        r'\b(must|shall)\s+be\s+greater\s+than\b': 'minimum_value',
        r'\bor\s+(?:stronger|greater|larger|longer)\b': 'minimum_value',  # "SHA-256 or stronger"
        r'\b(must|shall)\s+be\s+at\s+most\b': 'maximum_value',
        r'\b(must|shall)\s+be\s+less\s+than\b': 'maximum_value',
        r'\b(must|shall)\s+not\s+exceed(?:ing)?\b': 'maximum_value',  # "not exceed" or "not exceeding"
        r'\bnot\s+exceed(?:ing)?\b': 'maximum_value',  # standalone "not exceeding"
        r'\b(must|shall)\s+not\s+be\s+(?:valid\s+for\s+)?(?:longer|greater|more)\s+than\b': 'maximum_value',
        r'\b(must|shall)\s+be\s+equal\s+to\b': 'must_equal',
        r'\b(must|shall)\s+be\s+set\s+to\b': 'must_equal',

        # Presence checks (after value checks to avoid false matches)
        r'\b(must|shall)\s+not\s+(contain|include|be\s+present)\b': 'must_not_be_present',
        r'\bprohibited\b': 'must_not_be_present',
        r'\b(must|shall)\s+(contain|include|present)\b': 'must_be_present',
        r'\b(must|shall)\s+be\s+present\b': 'must_be_present',
        r'\brequired\b': 'must_be_present',

        # Empty/non-empty
        r'\b(must|shall)\s+not\s+be\s+empty\b': 'must_not_be_empty',
        r'\b(must|shall)\s+be\s+non-empty\b': 'must_not_be_empty',

        # Compound operations - specific patterns for common compound rules
        r'\b(must|shall)\s+not\s+be\s+(a\s+)?relative\b': 'must_not_be',
        r'\b(must|shall)\s+follow\b': 'must_follow',
        r'\b(must|shall)\s+not\s+be\b': 'must_not_be',

        # General "must be" (lowest priority)
        r'\b(must|shall)\s+be\b': 'must_equal',
    }

    # 值提取模式
    VALUE_PATTERNS = {
        'number': r'\b(\d+(?:\.\d+)?)\s*(bits?|bytes?|days?|years?|months?)?\b',
        'boolean': r'\b(true|false|yes|no)\b',
        'algorithm': r'\b(SHA-?256|SHA-?384|SHA-?512|RSA|ECDSA|Ed25519)\b',
    }

    def extract_fields(self, rule_text: str, context: str = "", modality: str = None) -> Dict[str, Any]:
        """
        从规则文本中提取结构化字段

        Args:
            rule_text: 规则文本
            context: 上下文（前后句子）
            modality: 规则类型（behavioral_rule, field_constraint等）- 用于改进字段识别

        Returns:
            包含 affected_field, operation, expected_value, condition 的字典
        """
        result = {
            'affected_field': None,
            'operation': None,
            'expected_value': None,
            'condition': None,
            'extraction_method': 'regex',
        }

        # 1. 提取受影响的字段（✅ 新增：传入modality）
        affected_field, _ = self._extract_affected_field(rule_text, context, modality)
        result['affected_field'] = affected_field

        # 2. 提取操作类型
        operation, _ = self._extract_operation(rule_text)
        result['operation'] = operation

        # 3. 提取期望值
        expected_value, _ = self._extract_expected_value(rule_text, operation)
        result['expected_value'] = expected_value

        # 4. 提取条件
        condition = self._extract_condition(rule_text, context)
        result['condition'] = condition

        return result

    def _extract_affected_field(self, text: str, context: str = "", modality: str = None) -> tuple[Optional[str], float]:
        """
        提取受影响的证书字段（改进版：结合modality提高准确率）

        Args:
            text: 规则文本
            context: 上下文
            modality: 规则类型（behavioral_rule, field_constraint等）

        Returns:
            (field_name, confidence)
        """
        text_lower = text.lower()
        combined_text = (context + " " + text).lower() if context else text_lower

        # ✅ 新增：behavioral_rule优先判断为CA行为
        if modality == 'behavioral_rule':
            # 检查是否是CA的行为规则
            ca_pattern = r'\b(CA|CAs|Certificate\s+Authorit(?:y|ies))\s+(MUST|SHALL|SHOULD|MAY|REQUIRED|PROHIBITED)\b'
            if re.search(ca_pattern, text, re.IGNORECASE):
                app_logger.debug(f"Identified as CA behavioral rule: {text[:80]}...")
                return 'CA', 0.9

        best_match = None
        best_confidence = 0.0

        # 正常匹配（使用权重系统）
        for pattern, field_name in self.CERTIFICATE_FIELDS.items():
            # 支持多个关键词（用 | 分隔）
            keywords = pattern.split('|')

            for keyword in keywords:
                # ✅ 改进：使用更严格的匹配，避免误匹配
                # 例如：避免'CA'被匹配为'basicConstraints'的'cA'

                # 特殊处理：如果keyword是'basicconstraints'或'basic constraints'
                # 确保不会误匹配'CA MUST'中的'CA'
                if keyword in ['basicconstraints', 'basic constraints']:
                    # 只有在明确提到'basicConstraints'或'cA'字段时才匹配
                    if re.search(r'\bbasicConstraints\b', text, re.IGNORECASE):
                        confidence = 0.9
                    elif re.search(r'\bcA\s*(?:MUST|SHALL|MAY|SHOULD)\s*(?:be|equal)', text):
                        # 'cA MUST be TRUE/FALSE'这种明确的字段约束
                        confidence = 0.85
                    else:
                        continue  # 不匹配
                else:
                    # 使用词边界匹配
                    if re.search(r'\b' + re.escape(keyword) + r'\b', combined_text):
                        # 优先匹配规则文本本身，而非上下文
                        confidence = 0.9 if keyword in text_lower else 0.6
                    else:
                        continue

                if confidence > best_confidence:
                    best_match = field_name
                    best_confidence = confidence

        # 增强推断：如果没找到，尝试推断
        if not best_match:
            best_match, inferred_confidence = self._infer_field_from_context(text_lower, combined_text)
            if best_match:
                best_confidence = inferred_confidence

        # ✅ 新增：如果还是没找到，且是process_rule或behavioral_rule，默认为CA
        if not best_match and modality in ['behavioral_rule', 'process_rule']:
            app_logger.debug(f"Defaulting to 'CA' for {modality}: {text[:80]}...")
            return 'CA', 0.5

        return best_match, best_confidence

    def _infer_field_from_context(self, text: str, context: str) -> tuple[Optional[str], float]:
        """从上下文推断字段（当直接匹配失败时）"""

        # 推断规则：基于关键词组合（按优先级排序）
        inference_rules = [
            # DNS/域名相关 -> subjectAltName
            (r'\bdNSName\s+field\b', 'extensions.subjectAltName', 0.9),
            (r'\bdNSName\b', 'extensions.subjectAltName', 0.85),
            (r'\b(?:internationalized\s+)?domain\s+names?\b', 'extensions.subjectAltName', 0.75),
            (r'\bIA5String\b', 'extensions.subjectAltName', 0.6),

            # CRL/策略相关 -> 特定扩展
            (r'\bfreshest\s+crl\b', 'extensions.freshestCRL', 0.9),
            (r'\binhibit\s+any\s*-?policy\b', 'extensions.inhibitAnyPolicy', 0.9),
            (r'\bpolicy\s+mappings?\b', 'extensions.policyMappings', 0.85),
            (r'\bsubject\s+information\s+access\b', 'extensions.subjectInfoAccess', 0.9),
            (r'\bocsp\s+no\s+check\b', 'extensions.ocspNoCheck', 0.9),

            # RSA/密钥相关 -> publicKey（多种表达方式）
            (r'\brsa\s+(?:public\s+)?keys?\b', 'subjectPublicKeyInfo', 0.8),
            (r'\bpublic\s+keys?\b.{0,30}\b(?:rsa|bits?|size)', 'subjectPublicKeyInfo', 0.75),
            (r'\bkeys?\b.{0,20}\b(?:bits?|size|length)', 'subjectPublicKeyInfo', 0.7),
            (r'\bkey\s+size\b', 'subjectPublicKeyInfo', 0.8),
            (r'\bmodulus\b', 'subjectPublicKeyInfo.rsaKey', 0.75),

            # 有效期相关 -> validity
            (r'\bvalidity\s+period\b', 'validity', 0.9),
            (r'\bvalid\s+for\b.{0,20}\bdays?\b', 'validity', 0.8),
            (r'\b(?:not\s+)?(?:exceed|longer\s+than).{0,20}\bdays?\b', 'validity', 0.75),
            (r'\bexpir(?:e|ation|y)\b', 'validity', 0.7),
            (r'\bnotbefore|notafter\b', 'validity', 0.85),

            # 扩展相关
            (r'\bextension\b.{0,30}\bcritical\b', 'extensions.', 0.6),
            (r'\bextension\b.{0,30}\bpresent\b', 'extensions.', 0.6),

            # Subject 相关
            (r'\bsubject\s+(?:dn|name|field)\b', 'subject', 0.8),

            # 算法相关
            (r'\bsignature\s+algorithm\b', 'signatureAlgorithm', 0.85),
            (r'\bhash\s+algorithm\b', 'signatureAlgorithm', 0.75),
            (r'\bsha-?\d+\b', 'signatureAlgorithm', 0.7),

            # 版本
            (r'\bversion\b', 'version', 0.7),
        ]

        for pattern, field, confidence in inference_rules:
            if re.search(pattern, text, re.IGNORECASE):
                app_logger.debug(f"Inferred field '{field}' from pattern '{pattern}'")
                return field, confidence

        return None, 0.0

    def _extract_operation(self, text: str) -> tuple[Optional[str], float]:
        """
        提取操作类型（支持复合操作识别）

        如果一个句子包含多个操作（如 "MUST NOT be X, and it MUST follow Y"），
        将返回组合操作如 "must_not_be AND must_follow"
        """
        text_lower = text.lower()

        # 收集所有匹配的操作
        matched_operations = []

        for pattern, operation in self.OPERATION_PATTERNS.items():
            if re.search(pattern, text_lower, re.IGNORECASE):
                # 计算置信度 - 更具体的模式优先级更高
                confidence = 0.9 if 'not' in pattern else 0.8
                matched_operations.append((operation, confidence, pattern))

        if not matched_operations:
            return None, 0.0

        # 去重 - 如果匹配到了多个相同的操作，只保留一个
        unique_operations = []
        seen_ops = set()
        for op, conf, pat in matched_operations:
            if op not in seen_ops:
                unique_operations.append((op, conf))
                seen_ops.add(op)

        # 如果只有一个操作，直接返回
        if len(unique_operations) == 1:
            return unique_operations[0][0], unique_operations[0][1]

        # 如果有多个不同的操作，检查是否是复合规则
        # 典型模式: "MUST NOT be X, and it MUST follow Y"
        if len(unique_operations) >= 2:
            # 检查是否包含连接词 "and" - 支持多种模式：
            # 1. ", and it MUST"
            # 2. ", and MUST"
            # 3. ", and the X MUST"
            if re.search(r',\s*and\s+(it\s+)?(the\s+\w+\s+)?(must|shall)', text_lower):
                # 这是一个复合规则，组合所有操作
                combined_op = ' AND '.join([op for op, _ in unique_operations])
                avg_confidence = sum(conf for _, conf in unique_operations) / len(unique_operations)

                app_logger.debug(f"Detected compound operation: {combined_op}")
                return combined_op, avg_confidence

        # 否则返回第一个（最高优先级）操作
        return unique_operations[0][0], unique_operations[0][1]

    def _extract_expected_value(self, text: str, operation: Optional[str]) -> tuple[Optional[str], float]:
        """提取期望值"""
        if not operation:
            return None, 0.0

        # 对于存在性检查，值是固定的
        if operation in ['must_be_present', 'must_not_be_present']:
            return 'present' if operation == 'must_be_present' else 'absent', 1.0

        if operation in ['must_be_critical', 'must_not_be_critical']:
            return 'true' if operation == 'must_be_critical' else 'false', 1.0

        # 提取数值
        number_match = re.search(self.VALUE_PATTERNS['number'], text, re.IGNORECASE)
        if number_match:
            value = number_match.group(1)
            unit = number_match.group(2) if number_match.lastindex >= 2 else ''
            return f"{value} {unit}".strip(), 0.8

        # 提取布尔值
        bool_match = re.search(self.VALUE_PATTERNS['boolean'], text, re.IGNORECASE)
        if bool_match:
            return bool_match.group(1).lower(), 0.9

        # 提取算法名称
        algo_match = re.search(self.VALUE_PATTERNS['algorithm'], text, re.IGNORECASE)
        if algo_match:
            return algo_match.group(1), 0.9

        return None, 0.0

    def _extract_condition(self, text: str, context: str = "") -> Optional[str]:
        """提取条件（如果有）"""
        combined_text = (context + " " + text) if context else text

        # 查找条件关键词
        condition_patterns = [
            r'if\s+(.+?),',
            r'when\s+(.+?),',
            r'for\s+(certificates?.+?),',
            r'in\s+case\s+(.+?),',
        ]

        for pattern in condition_patterns:
            match = re.search(pattern, combined_text, re.IGNORECASE)
            if match:
                condition = match.group(1).strip()
                # 清理条件文本
                condition = re.sub(r'\s+', ' ', condition)
                return condition

        return None

    def validate_extraction(self, extraction: Dict[str, Any]) -> Dict[str, Any]:
        """
        验证提取结果的质量

        Returns:
            包含 is_valid, issues, suggestions 的字典
        """
        issues = []
        suggestions = []

        # 检查必需字段
        if not extraction.get('affected_field'):
            issues.append("Missing affected_field - cannot determine which certificate field to validate")
            suggestions.append("Check if the rule text contains recognizable certificate field names")

        if not extraction.get('operation'):
            issues.append("Missing operation - cannot determine what validation to perform")
            suggestions.append("Check if the rule text contains normative keywords (MUST, SHALL, etc.)")

        # 检查操作和值的一致性
        operation = extraction.get('operation')
        expected_value = extraction.get('expected_value')

        if operation in ['minimum_value', 'maximum_value', 'must_equal'] and not expected_value:
            issues.append(f"Operation '{operation}' requires expected_value but none was extracted")
            suggestions.append("Check if the rule text contains numeric values or specific requirements")

        is_valid = len(issues) == 0

        return {
            'is_valid': is_valid,
            'issues': issues,
            'suggestions': suggestions
        }

    def format_for_database(self, extraction: Dict[str, Any], rule_text: str, section: str, source: str) -> Dict[str, Any]:
        """
        格式化提取结果用于保存到数据库

        Returns:
            完整的规则字典
        """
        return {
            'text': rule_text,
            'section': section,
            'source': source,
            'affected_field': extraction['affected_field'],
            'operation': extraction['operation'],
            'expected_value': extraction['expected_value'],
            'condition': extraction['condition'],
            'extraction_method': extraction['extraction_method']
        }
