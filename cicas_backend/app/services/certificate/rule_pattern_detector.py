"""
规则模式检测器

识别zlint规则属于哪个模式，并为每个模式提供专门的代码生成器。

支持的规则模式（基于用户示例）：
1. DN_ATTRIBUTE_TYPE_CHECK - Subject DN属性编码检查（UTF8String/PrintableString）
2. DNS_LABEL_LENGTH_CHECK - DNS标签长度检查（最多63字符）
3. ACE_FORMAT_CHECK - ACE/Punycode格式检查（仅ASCII）
4. DN_FIELD_ASCII_CHECK - DN字段ToASCII检查（domainComponent）
5. EXTENSION_PRESENCE - 扩展存在性检查
"""
from enum import Enum
from typing import Dict, Any, Optional, Tuple
from app.core.logging_config import app_logger


class ZlintRulePattern(str, Enum):
    """识别的zlint规则模式"""

    # 遍历和检查类规则
    DN_ATTRIBUTE_TYPE_CHECK = "dn_attribute_type_check"
    DNS_LABEL_LENGTH_CHECK = "dns_label_length_check"
    ACE_FORMAT_CHECK = "ace_format_check"
    DN_FIELD_ASCII_CHECK = "dn_field_ascii_check"
    DNSNAME_ASCII_CHECK = "dnsname_ascii_check"  # dNSName ASCII-only check
    LDH_LABEL_CHECK = "ldh_label_check"  # UseSTD3ASCIIRules - LDH字符+连字符位置检查

    # 简单字段检查
    EXTENSION_PRESENCE = "extension_presence"
    FIELD_EQUALITY = "field_equality"
    FIELD_RANGE = "field_range"

    # 未知
    UNKNOWN = "unknown"


class RulePatternDetector:
    """从规则文本和IR检测规则模式

    关键insight: 不同的规则有不同的模式
    - DN属性编码检查需要遍历Subject.Names并检查类型
    - DNS标签长度需要遍历并分割字符串
    - ACE格式需要前缀检查和ASCII验证
    - 等等

    通用参数化生成无法处理这些复杂规则，需要专门的生成器。
    """

    def detect(self, ir: Dict[str, Any]) -> ZlintRulePattern:
        """从IR检测规则模式

        Args:
            ir: 规则的中间表示

        Returns:
            检测到的规则模式
        """

        # 方法1: 检查IR中是否已有明确的pattern指示
        if 'rule_pattern' in ir:
            try:
                pattern = ZlintRulePattern(ir['rule_pattern'])
                app_logger.debug(f"Rule pattern explicitly specified: {pattern}")
                return pattern
            except ValueError:
                pass

        # 方法2: 从规则描述推断
        description = ir.get('description', '').lower()
        subject = ir.get('subject', '')
        if isinstance(subject, dict):
            subject = subject.get('path', '')
        subject = subject.lower()
        # citation: old format has 'citation', new format has provenance list
        citation = ir.get('citation', '')
        if not citation:
            provenance = ir.get('provenance', [])
            if isinstance(provenance, list) and provenance:
                citation = provenance[0].get('section', '') if isinstance(provenance[0], dict) else ''
        rule_text = ir.get('rule_text', '').lower()

        # 合并所有文本用于检测
        all_text = f"{description} {subject} {rule_text}".lower()

        # 检测顺序很重要：更具体的模式应该先检测

        # 0. LDH标签检查 - UseSTD3ASCIIRules（最高优先级，因为非常明确的特征）
        if self._is_ldh_label_check(description, subject, all_text):
            app_logger.debug("Detected pattern: LDH_LABEL_CHECK")
            return ZlintRulePattern.LDH_LABEL_CHECK

        # 1. DN字段ASCII检查 - 检查domainComponent能否ToASCII
        # 这个检测要在其他检测之前，因为它有非常明确的特征
        if self._is_dn_field_ascii_check(description, subject, all_text):
            app_logger.debug("Detected pattern: DN_FIELD_ASCII_CHECK")
            return ZlintRulePattern.DN_FIELD_ASCII_CHECK

        # 2. DN编码检查 - 检查Subject DN属性是否是UTF8String或PrintableString
        if self._is_dn_attribute_type_check(description, subject, all_text):
            app_logger.debug("Detected pattern: DN_ATTRIBUTE_TYPE_CHECK")
            return ZlintRulePattern.DN_ATTRIBUTE_TYPE_CHECK

        # 3. DNS标签长度检查 - 必须在ACE检查之前，因为它有更具体的特征（63 + label）
        # 这样包含"(ACE/Punycode)"备注的长度规则不会被误判为ACE格式检查
        if self._is_dns_label_length_check(description, subject, all_text):
            app_logger.debug("Detected pattern: DNS_LABEL_LENGTH_CHECK")
            return ZlintRulePattern.DNS_LABEL_LENGTH_CHECK

        # 4. dNSName ASCII检查 - 在ACE格式检查之前，检测一般性的ASCII-only约束
        # 用于encode_as规则的可观测结果验证
        if self._is_dnsname_ascii_check(description, subject, all_text):
            app_logger.debug("Detected pattern: DNSNAME_ASCII_CHECK")
            return ZlintRulePattern.DNSNAME_ASCII_CHECK

        # 5. ACE/Punycode格式检查 - 检查ACE编码的域名有效性
        if self._is_ace_format_check(description, subject, all_text):
            app_logger.debug("Detected pattern: ACE_FORMAT_CHECK")
            return ZlintRulePattern.ACE_FORMAT_CHECK

        # 6. Extension presence - 检查扩展是否存在
        if self._is_extension_presence(description, ir.get('obligation', '')):
            app_logger.debug("Detected pattern: EXTENSION_PRESENCE")
            return ZlintRulePattern.EXTENSION_PRESENCE

        app_logger.debug(f"Could not detect rule pattern for rule: {ir.get('lint_name', 'unknown')}")
        return ZlintRulePattern.UNKNOWN

    @staticmethod
    def _is_dn_attribute_type_check(description: str, subject: str, all_text: str) -> bool:
        """检查是否是DN属性类型检查

        示例规则：Standard naming attributes (CN, O, OU) must be UTF8String or PrintableString
        """
        # 核心特征：UTF8String/PrintableString + Subject/DN/attribute
        has_encoding_type = any(term in all_text for term in [
            'utf8string', 'printablestring', 'utf8', 'printable',
            'directorystring', 'asn.1 string type'
        ])

        has_dn_context = any(term in all_text for term in [
            'subject', 'issuer', 'dn', 'distinguished name',
            'cn', 'o ', 'ou', 'commonname', 'organization',
            'naming attribute', 'attribute type'
        ])

        if has_encoding_type and has_dn_context:
            return True

        # 备用检测：明确提到编码要求
        if 'encoded as' in all_text and any(term in all_text for term in ['subject', 'dn', 'attribute']):
            return True

        return False

    @staticmethod
    def _is_dns_label_length_check(description: str, subject: str, all_text: str) -> bool:
        """检查是否是DNS标签长度检查

        示例规则：
        - Each IDN label must be at most 63 characters (ACE/Punycode)
        - Implementations MUST allow for increased space requirements for IDNs
        """
        # 核心特征：DNS/label/domain/IDN + 长度/空间限制
        has_dns_context = any(term in all_text for term in [
            'dns', 'dnsname', 'domain', 'label', 'idn', 'hostname'
        ])

        has_length_constraint = any(term in all_text for term in [
            '63', 'length', 'octet', 'byte',
            'exceed', 'maximum', 'at most', 'no more than',
            'space requirement'  # More specific than just 'space'
        ])

        if has_dns_context and has_length_constraint:
            # Exclude ASCII character constraints (should be DNSNAME_ASCII_CHECK)
            if 'ia5string' in all_text or 'ascii characters' in all_text:
                # If no explicit length number, this is about character set, not length
                if '63' not in all_text and 'octet' not in all_text:
                    return False

            # 排除：如果主要是关于ACE格式检查而非长度
            # "allowunassigned"是ACE格式检查的明确标志
            if 'allowunassigned' in all_text.replace('_', '').replace('-', '').replace(' ', ''):
                return False
            # 如果同时强调"non-ascii"或"ascii"检查，可能是ACE格式检查
            if 'non-ascii' in all_text and 'ascii' in all_text:
                return False
            return True

        return False

    @staticmethod
    def _is_ace_format_check(description: str, subject: str, all_text: str) -> bool:
        """检查是否是ACE/Punycode格式检查

        示例规则：ACE-encoded IDN labels must be valid Punycode (no non-ASCII characters)
        """
        # "allowunassigned"是ACE格式检查的明确标志，最高优先级
        if 'allowunassigned' in all_text.replace('_', '').replace('-', '').replace(' ', ''):
            return True

        # 核心特征：ACE/Punycode + ASCII/格式验证
        has_ace_indicator = any(term in all_text for term in [
            'punycode', 'ace', 'xn--', 'idn',
            'internationalized', 'a-label'
        ])

        has_format_check = any(term in all_text for term in [
            'ascii', 'non-ascii', 'character',
            'valid', 'format', 'encoded', 'encoding'
        ])

        if has_ace_indicator and has_format_check:
            # 确认是格式检查而非长度检查
            # 如果没有长度关键词，或者有"non-ascii"关键词，则是格式检查
            has_no_length_focus = '63' not in all_text
            has_ascii_focus = 'non-ascii' in all_text or ('ascii' in all_text and 'character' in all_text)
            if has_no_length_focus or has_ascii_focus:
                return True

        return False

    @staticmethod
    def _is_dn_field_ascii_check(description: str, subject: str, all_text: str) -> bool:
        """检查是否是DN字段ASCII检查

        示例规则：DN domainComponent labels must be ToASCII encoded
        """
        # 核心特征：domainComponent/DC + ToASCII
        has_dc_field = any(term in all_text for term in [
            'domaincomponent', 'domain component', ' dc ', 'dc=',
            '0.9.2342.19200300.100.1.25'  # domainComponent OID
        ])

        has_ascii_check = any(term in all_text for term in [
            'toascii', 'to ascii', 'idna', 'ascii',
            'ascii-compatible', 'ace encoding'
        ])

        if has_dc_field and has_ascii_check:
            return True

        # 备用检测：DN + ToASCII
        if ('toascii' in all_text or 'idna' in all_text) and 'dn' in all_text:
            return True

        return False

    @staticmethod
    def _is_dnsname_ascii_check(description: str, subject: str, all_text: str) -> bool:
        """检查是否是dNSName ASCII-only检查

        示例规则：
        - "implementations MUST convert internationalized domain names to ACE format"
        - "dNSName MUST contain only ASCII characters"

        这种模式用于验证encode_as规则的可观测结果：
        dNSName值必须只包含ASCII字符（因为IA5String编码要求）
        """
        # 核心特征：必须涉及dNSName或subjectAltName的DNS部分
        has_dnsname = any(term in all_text for term in [
            'dnsname', 'dns name', 'subjectaltname.dnsname', 'san.dnsname',
            'dnsname field', 'dns names'
        ])

        # 必须涉及ASCII/ACE/编码转换
        has_ascii_context = any(term in all_text for term in [
            'ace', 'ascii', 'toascii', 'ia5string', 'ascii compatible',
            'convert', 'encoding', 'internationalized domain',
            'ascii characters', 'limited to'  # For IA5String definitions
        ])

        # IA5String + ASCII should match even without explicit dnsname keyword
        # if the subject is about dNSName
        if 'ia5string' in all_text and 'ascii' in all_text:
            if has_dnsname or 'dnsname' in subject.lower() or 'subjectaltname' in subject.lower():
                return True

        if has_dnsname and has_ascii_context:
            # 排除ACE_FORMAT_CHECK（专注于xn--前缀验证的规则）
            # 如果规则主要是关于punycode验证，则不是一般的ASCII检查
            if 'xn--' in all_text and 'punycode' in all_text:
                return False
            # 排除DN_FIELD_ASCII_CHECK（关于domainComponent的）
            if 'domaincomponent' in all_text or 'domain component' in all_text:
                return False
            return True

        return False

    @staticmethod
    def _is_extension_presence(description: str, obligation: str) -> bool:
        """检查是否是扩展必须存在检查"""
        # 关键词：MUST存在，MUST包含扩展
        obligation_upper = obligation.upper()
        return (
            'MUST' in obligation_upper and
            'extension' in description.lower() and
            ('present' in description.lower() or 'include' in description.lower() or
             'contain' in description.lower() or 'required' in description.lower())
        )

    @staticmethod
    def _is_ldh_label_check(description: str, subject: str, all_text: str) -> bool:
        """检查是否是LDH标签检查（UseSTD3ASCIIRules）

        示例规则：
        - "in step 3, set the flag called 'UseSTD3ASCIIRules'"
        - "DNS labels must contain only letters, digits, and hyphens (LDH)"
        - "Labels must not begin or end with a hyphen"

        UseSTD3ASCIIRules 的效果是时间不变、确定性的：
        - 只允许 LDH 字符（letters, digits, hyphens）
        - 不允许标签以连字符开头或结尾
        可通过 modus tollens 逆推验证
        """
        # 最明确的特征：UseSTD3ASCIIRules
        normalized = all_text.replace(' ', '').replace('_', '').replace('-', '').lower()
        if 'usestd3asciirules' in normalized:
            # Value-aware check: if UseSTD3ASCIIRules is explicitly set to false,
            # LDH rules are NOT enforced — don't classify as LDH_LABEL_CHECK
            import re
            if re.search(r'usestd3asciirules.*?(?:to\s*)?(?:false|no)\b', normalized):
                pass  # Don't return True; fall through to other LDH indicators
            else:
                return True

        # 核心特征：LDH + DNS/label
        has_ldh_indicator = any(term in all_text for term in [
            'ldh', 'letter', 'digit', 'hyphen',
            'letters, digits', 'letters and digits',
            'alphanumeric', 'std3', 'rfc 952', 'rfc952', 'rfc 1123', 'rfc1123'
        ])

        has_label_context = any(term in all_text for term in [
            'label', 'dns', 'domain name', 'hostname'
        ])

        if has_ldh_indicator and has_label_context:
            return True

        # 检查连字符位置约束
        has_hyphen_constraint = any(term in all_text for term in [
            'begin with a hyphen', 'end with a hyphen',
            'start with a hyphen', 'start with hyphen',
            'begin or end', 'start or end',
            'leading hyphen', 'trailing hyphen'
        ])

        if has_hyphen_constraint and has_label_context:
            return True

        return False
