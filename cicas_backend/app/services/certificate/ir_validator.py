"""
IR Validator - 中间表示验证器
验证IR的合法性、一致性和完整性
"""
from typing import Dict, List, Tuple, Optional
import re
from app.core.logging_config import app_logger


class IRValidator:
    """
    IR验证器 - 确保生成的IR符合规范
    """

    # 合法的x509.Certificate字段
    VALID_CERT_FIELDS = {
        # 核心字段
        'c.Version',
        'c.SerialNumber',
        'c.SignatureAlgorithm',
        'c.Issuer',
        'c.Subject',
        'c.NotBefore',
        'c.NotAfter',
        'c.PublicKey',
        'c.PublicKeyAlgorithm',
        'c.Signature',

        # 扩展字段
        'c.SubjectAltName',
        'c.KeyUsage',
        'c.ExtKeyUsage',
        'c.BasicConstraintsValid',
        'c.IsCA',
        'c.MaxPathLen',
        'c.SubjectKeyId',
        'c.AuthorityKeyId',
        'c.DNSNames',
        'c.EmailAddresses',
        'c.IPAddresses',
        'c.URIs',

        # 其他常用字段
        'c.Extensions',
        'c.ExtraExtensions',
        'c.UnhandledCriticalExtensions',
        'c.ExtKeyUsage',
        'c.PolicyIdentifiers',
        'c.PermittedDNSDomains',
        'c.ExcludedDNSDomains',
        'c.CRLDistributionPoints',
        'c.IssuingCertificateURL',
        'c.OCSPServer',
    }

    # 合法的逻辑类型
    VALID_LOGIC_TYPES = {
        'presence',
        'regex',
        'equality',
        'range',
        'contains',
        'uniqueness',
        'conditional',
        'custom',
        # 扩展的逻辑类型
        'multi_field_consistency',
        'dependency',
        'time_based',
        'oid_list',
        'chain',
        'encoding',
        'length',
        'format',
        'enumeration',
        'bitstring',
    }

    # 合法的错误级别
    VALID_ERROR_LEVELS = {'Error', 'Warn', 'Notice'}

    # 合法的applies_to值
    VALID_APPLIES_TO = {'Subscriber', 'CA', 'All'}

    # 合法的source值
    VALID_SOURCES = {
        'RFC5280',
        'CABFBaselineRequirements',
        'CABFEVGuidelines',
        'MozillaRootStorePolicy',
        'AppleRootStorePolicy',
    }

    def __init__(self):
        self.validation_errors = []
        self.validation_warnings = []

    def validate(self, ir: Dict) -> Tuple[bool, List[str], List[str]]:
        """
        验证IR的完整性和正确性

        Args:
            ir: IR字典

        Returns:
            (is_valid, errors, warnings)
        """
        self.validation_errors = []
        self.validation_warnings = []

        # 1. 验证必需字段
        self._validate_required_fields(ir)

        # 2. 验证字段值的合法性
        self._validate_field_values(ir)

        # 3. 验证target_field的合法性
        self._validate_target_field(ir)

        # 4. 验证logic的一致性
        self._validate_logic_consistency(ir)

        # 5. 验证applies_to的合理性
        self._validate_applies_to(ir)

        # 6. 验证lint_name的唯一性和规范性
        self._validate_lint_name(ir)

        is_valid = len(self.validation_errors) == 0

        return is_valid, self.validation_errors, self.validation_warnings

    def _validate_required_fields(self, ir: Dict):
        """验证必需字段是否存在"""
        required_fields = [
            'lint_name',
            'description',
            'citation',
            'source',
            'effective_date',
            'target_field',
            'logic',
            'error_level'
        ]

        for field in required_fields:
            if field not in ir or not ir[field]:
                self.validation_errors.append(f"Missing required field: {field}")

        # 验证logic子字段
        if 'logic' in ir:
            logic = ir['logic']
            if 'type' not in logic or not logic['type']:
                self.validation_errors.append("Missing logic.type")

    def _validate_field_values(self, ir: Dict):
        """验证字段值的合法性"""
        # 验证source
        if 'source' in ir:
            if ir['source'] not in self.VALID_SOURCES:
                self.validation_errors.append(
                    f"Invalid source: {ir['source']}. Must be one of {self.VALID_SOURCES}"
                )

        # 验证error_level
        if 'error_level' in ir:
            if ir['error_level'] not in self.VALID_ERROR_LEVELS:
                self.validation_errors.append(
                    f"Invalid error_level: {ir['error_level']}. Must be one of {self.VALID_ERROR_LEVELS}"
                )

        # 验证applies_to
        if 'applies_to' in ir:
            if ir['applies_to'] not in self.VALID_APPLIES_TO:
                self.validation_errors.append(
                    f"Invalid applies_to: {ir['applies_to']}. Must be one of {self.VALID_APPLIES_TO}"
                )

        # 验证logic.type
        if 'logic' in ir and 'type' in ir['logic']:
            logic_type = ir['logic']['type']
            if logic_type not in self.VALID_LOGIC_TYPES:
                self.validation_errors.append(
                    f"Invalid logic type: {logic_type}. Must be one of {self.VALID_LOGIC_TYPES}"
                )

    def _validate_target_field(self, ir: Dict):
        """验证target_field是否合法"""
        if 'target_field' not in ir:
            return

        target_field = ir['target_field']

        # 检查是否是合法的证书字段
        is_valid = False

        # 1. 直接匹配
        if target_field in self.VALID_CERT_FIELDS:
            is_valid = True

        # 2. 检查是否是c.开头的字段
        elif target_field.startswith('c.'):
            # 允许c.开头的字段（可能是自定义或不在列表中的合法字段）
            self.validation_warnings.append(
                f"target_field '{target_field}' not in standard field list, please verify"
            )
            is_valid = True

        # 3. 检查是否是util.GetExtFromCert调用
        elif 'util.GetExtFromCert' in target_field or 'util.IsExtInCert' in target_field:
            is_valid = True

        if not is_valid:
            self.validation_errors.append(
                f"Invalid target_field: {target_field}. Must start with 'c.' or use util functions"
            )

    def _validate_logic_consistency(self, ir: Dict):
        """验证logic配置与规则文本的一致性"""
        if 'logic' not in ir:
            return

        logic = ir['logic']
        logic_type = logic.get('type')
        description = ir.get('description', '').lower()

        # 检查逻辑类型与描述的一致性
        consistency_checks = {
            'presence': ['must', 'shall', 'present', 'include', 'contain'],
            'regex': ['format', 'pattern', 'match', 'valid'],
            'equality': ['equal', 'must be', 'shall be', 'is'],
            'range': ['minimum', 'maximum', 'at least', 'no more than', 'between'],
            'contains': ['contain', 'include'],
            'conditional': ['if', 'when', 'then'],
        }

        if logic_type in consistency_checks:
            keywords = consistency_checks[logic_type]
            has_keyword = any(keyword in description for keyword in keywords)

            if not has_keyword:
                self.validation_warnings.append(
                    f"Logic type '{logic_type}' may not match rule description. "
                    f"Expected keywords: {keywords}"
                )

        # 检查必需的logic子字段
        if logic_type == 'presence':
            if 'operator' not in logic or logic['operator'] not in ['exists', 'not_exists', 'critical', 'not_critical']:
                self.validation_errors.append(
                    f"presence type requires operator to be 'exists', 'not_exists', 'critical', or 'not_critical'"
                )

        elif logic_type == 'regex':
            if 'value' not in logic or not logic['value']:
                self.validation_errors.append("regex type requires a 'value' field with regex pattern")

        elif logic_type == 'range':
            if 'operator' not in logic or logic['operator'] not in ['>=', '<=', '>', '<', '==', '!=']:
                self.validation_errors.append("range type requires a valid comparison operator")
            if 'value' not in logic:
                self.validation_errors.append("range type requires a 'value' field")

    def _validate_applies_to(self, ir: Dict):
        """验证applies_to的合理性"""
        if 'applies_to' not in ir or 'target_field' not in ir:
            return

        applies_to = ir['applies_to']
        target_field = ir['target_field']

        # CA证书特有字段
        ca_specific_fields = ['c.IsCA', 'c.MaxPathLen', 'c.BasicConstraintsValid']

        for ca_field in ca_specific_fields:
            if ca_field in target_field and applies_to == 'Subscriber':
                self.validation_warnings.append(
                    f"Field '{ca_field}' is CA-specific but applies_to is 'Subscriber'. "
                    f"Consider using 'CA' or 'All'"
                )

    def _validate_lint_name(self, ir: Dict):
        """验证lint_name的规范性"""
        if 'lint_name' not in ir:
            return

        lint_name = ir['lint_name']

        # 1. 检查命名规范（小写、下划线分隔）
        if not re.match(r'^[a-z0-9_]+$', lint_name):
            self.validation_errors.append(
                f"lint_name '{lint_name}' must contain only lowercase letters, numbers, and underscores"
            )

        # 2. 检查长度
        if len(lint_name) > 100:
            self.validation_warnings.append(
                f"lint_name '{lint_name}' is too long ({len(lint_name)} chars). Consider shortening."
            )

        # 3. 检查是否包含source前缀
        source = ir.get('source', '')
        if source == 'RFC5280' and not lint_name.startswith('rfc'):
            self.validation_warnings.append(
                f"lint_name should start with 'rfc' for RFC5280 source"
            )
        elif source == 'CABFBaselineRequirements' and not lint_name.startswith('cabf'):
            self.validation_warnings.append(
                f"lint_name should start with 'cabf' for CABF source"
            )

    def validate_with_rag_reference(self, ir: Dict, similar_lints: List[Dict]) -> Dict:
        """
        使用RAG检索到的相似lint作为参考进行验证

        Args:
            ir: 待验证的IR
            similar_lints: RAG检索到的相似lint列表

        Returns:
            {
                'is_valid': bool,
                'errors': List[str],
                'warnings': List[str],
                'suggestions': List[str]
            }
        """
        is_valid, errors, warnings = self.validate(ir)

        suggestions = []

        # 基于相似lint提供建议
        if similar_lints:
            # 1. 字段访问方式建议
            target_field = ir.get('target_field', '')
            similar_fields = [lint.get('target_field', '') for lint in similar_lints if lint.get('target_field')]

            if similar_fields and target_field not in similar_fields:
                suggestions.append(
                    f"Consider using field access pattern similar to: {similar_fields[0]}"
                )

            # 2. CheckApplies模式建议
            check_applies_patterns = [lint.get('check_applies', '') for lint in similar_lints if lint.get('check_applies')]
            if check_applies_patterns:
                suggestions.append(
                    f"Similar lints use CheckApplies pattern: {check_applies_patterns[0][:50]}..."
                )

            # 3. Execute模式建议
            execute_patterns = [lint.get('execute', '') for lint in similar_lints if lint.get('execute')]
            if execute_patterns:
                suggestions.append(
                    f"Consider Execute pattern from similar lint: {execute_patterns[0][:50]}..."
                )

        return {
            'is_valid': is_valid,
            'errors': errors,
            'warnings': warnings,
            'suggestions': suggestions
        }


class IREnhancer:
    """
    IR增强器 - 基于RAG检索结果增强IR
    """

    def __init__(self):
        pass

    def enhance_with_rag(self, ir: Dict, similar_lints: List[Dict]) -> Dict:
        """
        使用RAG检索到的相似lint增强IR

        Args:
            ir: 原始IR
            similar_lints: 相似的lint列表（来自RAG）

        Returns:
            增强后的IR
        """
        if not similar_lints:
            return ir

        enhanced_ir = ir.copy()

        # 1. 如果target_field为空或不确定，尝试从相似lint推断
        if not ir.get('target_field') or ir.get('target_field') == 'c':
            top_lint = similar_lints[0]
            if 'target_field' in top_lint:
                enhanced_ir['target_field'] = top_lint['target_field']
                enhanced_ir['_rag_suggested_field'] = True

        # 2. 如果logic.custom_code为空，可以参考相似lint的实现
        if ir.get('logic', {}).get('type') == 'custom':
            if not ir['logic'].get('custom_code'):
                # 从最相似的lint提取execute代码作为参考
                top_lint = similar_lints[0]
                if 'execute' in top_lint:
                    enhanced_ir['logic']['custom_code'] = (
                        f"// Reference from similar lint: {top_lint.get('lint_name', 'unknown')}\n"
                        f"// Adapt the following logic:\n"
                        f"{top_lint['execute'][:200]}...\n"
                        f"// TODO: Customize for current rule"
                    )
                    enhanced_ir['_rag_code_reference'] = top_lint.get('lint_name')

        # 3. 添加RAG元数据
        enhanced_ir['_rag_references'] = [
            {
                'lint_name': lint.get('lint_name'),
                'similarity': lint.get('similarity', 0),
                'package': lint.get('package')
            }
            for lint in similar_lints[:3]  # 只保留top 3
        ]

        return enhanced_ir
