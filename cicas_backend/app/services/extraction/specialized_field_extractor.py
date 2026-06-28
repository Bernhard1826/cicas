"""
专门字段提取器

从规则文本中提取用于特定规则模式的字段值
这些字段由zlint代码生成器使用，以生成完整的、优化的代码
"""
import re
from typing import Optional, List, Dict, Any
from app.core.logging_config import app_logger
from app.services.extraction.ir_schema import IntermediateRepresentation


class SpecializedFieldExtractor:
    """从规则文本和IR提取专门字段的工具类

    关键insight: 不同的规则模式需要不同的参数值
    - DN属性编码检查需要OID列表
    - DNS标签检查需要最大长度
    - ACE格式检查需要前缀
    - DN字段ASCII检查需要OID
    - 扩展存在检查需要扩展OID常量

    这个提取器尝试从规则文本中推断这些值。
    """

    # OID映射表：常见的属性OID
    ATTRIBUTE_OID_MAP = {
        'cn': '2.5.4.3',
        'commonname': '2.5.4.3',
        'o': '2.5.4.10',
        'organizationname': '2.5.4.10',
        'ou': '2.5.4.11',
        'organizationalunitname': '2.5.4.11',
        'c': '2.5.4.6',
        'countryname': '2.5.4.6',
        'st': '2.5.4.8',
        'stateorprovincename': '2.5.4.8',
        'l': '2.5.4.7',
        'localityname': '2.5.4.7',
    }

    # 扩展OID映射表：zlint常量名到OID
    EXTENSION_CONST_MAP = {
        'subjectaltname': ('SubjectAlternateNameOID', '2.5.29.17'),
        'issueraltname': ('IssuerAlternateNameOID', '2.5.29.18'),
        'basicconstraints': ('BasicConstOID', '2.5.29.19'),
        'keyusage': ('KeyUsageOID', '2.5.29.15'),
        'extendedkeyusage': ('EkuSynOid', '2.5.29.37'),
        'certificatepolicies': ('CertPolicyOID', '2.5.29.32'),
        'subjectkeyidentifier': ('SubjectKeyIdentityOID', '2.5.29.14'),
        'authoritykeyidentifier': ('AuthkeyOID', '2.5.29.35'),
        'nameconstraints': ('NameConstOID', '2.5.29.30'),
        'crldistributionpoints': ('CrlDistOID', '2.5.29.31'),
        'authorityinfoaccess': ('AiaOID', '1.3.6.1.5.5.7.1.1'),
    }

    @classmethod
    def extract_specialized_fields(cls, ir: IntermediateRepresentation) -> IntermediateRepresentation:
        """尝试从IR中提取并填充专门字段

        Args:
            ir: 原始IR对象

        Returns:
            填充了专门字段的IR对象
        """

        rule_text = ir.rule_text or ir.canonical_text or ""
        subject = str(ir.subject) if ir.subject else ""
        constraint_text = ir.constraint.raw_text if ir.constraint else ""

        try:
            # 1. 提取check_oids（DN属性类型检查）
            if not ir.check_oids:
                ir.check_oids = cls._extract_check_oids(subject, rule_text, constraint_text)

            # 2. 提取max_label_length（DNS标签长度检查）
            if ir.max_label_length is None:
                ir.max_label_length = cls._extract_max_label_length(rule_text, constraint_text)

            # 3. 提取ace_prefix（ACE格式检查）
            if not ir.ace_prefix:
                ir.ace_prefix = cls._extract_ace_prefix(rule_text)

            # 4. 提取oid（DN字段ASCII检查）
            if not ir.oid:
                ir.oid = cls._extract_oid(subject, rule_text)

            # 5. 提取extension_oid_const（扩展存在检查）
            if not ir.extension_oid_const:
                ir.extension_oid_const = cls._extract_extension_oid_const(subject, rule_text)

            app_logger.debug(f"Extracted specialized fields for rule: check_oids={ir.check_oids}, "
                           f"max_label_length={ir.max_label_length}, ace_prefix={ir.ace_prefix}, "
                           f"oid={ir.oid}, extension_oid_const={ir.extension_oid_const}")

        except Exception as e:
            app_logger.warning(f"Error extracting specialized fields: {e}")

        return ir

    @staticmethod
    def _extract_check_oids(subject: str, rule_text: str, constraint_text: str) -> Optional[List[str]]:
        """提取DN属性检查的OID列表

        寻找规则中提到的属性名称（CN, O, OU等）
        """

        # 常见的DN属性名称在规则中的表现形式
        dn_attrs_pattern = r'\b(CN|O|OU|C|ST|L|commonName|organizationName|organizationalUnitName|countryName)\b'

        text_to_search = f"{subject} {rule_text} {constraint_text}".lower()
        matches = re.findall(dn_attrs_pattern, f"{subject} {rule_text} {constraint_text}", re.IGNORECASE)

        if matches:
            oids = []
            for match in set(matches):  # 去重
                oid = SpecializedFieldExtractor.ATTRIBUTE_OID_MAP.get(match.lower())
                if oid:
                    oids.append(oid)

            if oids:
                return oids

        # 默认的Subject DN字段
        if 'subject' in subject.lower() and ('utf8' in rule_text.lower() or 'printable' in rule_text.lower()):
            return ['2.5.4.3', '2.5.4.10', '2.5.4.11']  # CN, O, OU

        return None

    @staticmethod
    def _extract_max_label_length(rule_text: str, constraint_text: str) -> Optional[int]:
        """提取DNS标签最大长度限制

        寻找规则中的数字限制（通常是63）
        """

        text = f"{rule_text} {constraint_text}"

        # 寻找"63"、"63 characters"、"63 octets"等模式
        patterns = [
            r'\b(63)\s*(?:octets?|bytes?|characters?)?',  # 标准的63
            r'max(?:imum)?\s+(?:length|size)\s+(?:of\s+)?(\d+)',  # "maximum length of 63"
            r'(?:no\s+more\s+than|at\s+most)\s+(\d+)',  # "at most 63"
            r'exceeds?\s+(\d+)',  # "exceeds 63"
        ]

        for pattern in patterns:
            match = re.search(pattern, text, re.IGNORECASE)
            if match:
                try:
                    length = int(match.group(1))
                    return length
                except (ValueError, IndexError):
                    continue

        # 默认值（RFC 5280中DNS标签的限制）
        if 'dns' in text.lower() and 'label' in text.lower():
            return 63

        return None

    @staticmethod
    def _extract_ace_prefix(rule_text: str) -> Optional[str]:
        """提取ACE编码前缀

        寻找规则中对ACE格式的描述
        """

        text = rule_text.lower()

        # 寻找"xn--"、"ACE"、"Punycode"等
        if 'xn--' in text:
            return 'xn--'

        if 'punycode' in text or ('ace' in text and 'encoded' in text):
            return 'xn--'  # 默认的Punycode前缀

        return None

    @staticmethod
    def _extract_oid(subject: str, rule_text: str) -> Optional[str]:
        """提取OID标识符

        寻找规则中的OID值（特别是domainComponent的OID）
        """

        text = f"{subject} {rule_text}".lower()

        # 寻找domainComponent相关的OID
        if 'domaincomponent' in text or 'domain component' in text:
            # domainComponent的标准OID
            return '0.9.2342.19200300.100.1.25'

        # 寻找显式的OID值
        oid_pattern = r'\b(\d+(?:\.\d+)+)\b'
        matches = re.findall(oid_pattern, f"{subject} {rule_text}")

        if matches:
            # 返回最后一个（通常是最相关的）
            return matches[-1]

        return None

    @staticmethod
    def _extract_extension_oid_const(subject: str, rule_text: str) -> Optional[str]:
        """提取扩展OID常量名

        寻找规则中提到的扩展类型
        """

        text = f"{subject} {rule_text}".lower()

        # 尝试匹配所有已知的扩展
        for ext_name, (const_name, oid) in SpecializedFieldExtractor.EXTENSION_CONST_MAP.items():
            if ext_name in text or ext_name.replace('', ' ') in text:
                return const_name

        # 如果subject中包含扩展相关信息
        subject_lower = subject.lower()
        for ext_name, (const_name, oid) in SpecializedFieldExtractor.EXTENSION_CONST_MAP.items():
            if ext_name in subject_lower:
                return const_name

        return None
