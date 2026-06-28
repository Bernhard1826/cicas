"""
Section Topics Knowledge Base

为已知标准的特定章节提供主题映射，用于增强规则提取时的字段识别。

设计原则：
1. 只记录明确的、高置信度的映射
2. 优先记录容易产生歧义的章节（如使用代词较多的章节）
3. 支持多层级映射（父章节 → 子章节）
"""
from typing import Dict, List, Optional, Any


class SectionTopicsKB:
    """Section Topics 知识库"""

    # RFC5280 章节主题映射
    RFC5280_SECTIONS = {
        # 4. Certificate and Certificate Extensions Profile
        '4.1': {
            'title': 'Basic Certificate Fields',
            'primary_topics': ['certificate'],
        },
        '4.1.1': {
            'title': 'Certificate Fields',
            'primary_topics': ['certificate'],
        },
        '4.1.1.1': {
            'title': 'tbsCertificate',
            'primary_topics': ['tbsCertificate'],
        },
        '4.1.1.2': {
            'title': 'signatureAlgorithm',
            'primary_topics': ['signatureAlgorithm'],
            'default_affected_field': 'signatureAlgorithm',
        },
        '4.1.1.3': {
            'title': 'signatureValue',
            'primary_topics': ['signatureValue'],
            'default_affected_field': 'signatureValue',
        },
        '4.1.2': {
            'title': 'TBSCertificate',
            'primary_topics': ['tbsCertificate'],
        },
        '4.1.2.1': {
            'title': 'Version',
            'primary_topics': ['version'],
            'default_affected_field': 'version',
        },
        '4.1.2.2': {
            'title': 'Serial Number',
            'primary_topics': ['serialNumber'],
            'default_affected_field': 'serialNumber',
        },
        '4.1.2.3': {
            'title': 'Signature',
            'primary_topics': ['signature'],
            'default_affected_field': 'signature',
        },
        '4.1.2.4': {
            'title': 'Issuer',
            'primary_topics': ['issuer'],
            'default_affected_field': 'issuer',
        },
        '4.1.2.5': {
            'title': 'Validity',
            'primary_topics': ['validity', 'notBefore', 'notAfter'],
            'default_affected_field': 'validity',
            'sub_topics': {
                'notBefore': 'validity.notBefore',
                'notAfter': 'validity.notAfter',
            }
        },
        '4.1.2.5.1': {
            'title': 'UTCTime',
            'primary_topics': ['validity', 'utcTime'],
            'default_affected_field': 'validity',
        },
        '4.1.2.5.2': {
            'title': 'GeneralizedTime',
            'primary_topics': ['validity', 'generalizedTime'],
            'default_affected_field': 'validity',
        },
        '4.1.2.6': {
            'title': 'Subject',
            'primary_topics': ['subject'],
            'default_affected_field': 'subject',
        },
        '4.1.2.7': {
            'title': 'Subject Public Key Info',
            'primary_topics': ['subjectPublicKeyInfo'],
            'default_affected_field': 'subjectPublicKeyInfo',
        },
        '4.1.2.8': {
            'title': 'Unique Identifiers',
            'primary_topics': ['issuerUniqueID', 'subjectUniqueID'],
        },
        '4.1.2.9': {
            'title': 'Extensions',
            'primary_topics': ['extensions'],
        },

        # 4.2. Certificate Extensions
        '4.2': {
            'title': 'Certificate Extensions',
            'primary_topics': ['extensions'],
        },
        '4.2.1': {
            'title': 'Standard Extensions',
            'primary_topics': ['extensions'],
        },

        # 4.2.1.1 Authority Key Identifier
        '4.2.1.1': {
            'title': 'Authority Key Identifier',
            'primary_topics': ['authorityKeyIdentifier'],
            'default_affected_field': 'extensions.authorityKeyIdentifier',
        },

        # 4.2.1.2 Subject Key Identifier
        '4.2.1.2': {
            'title': 'Subject Key Identifier',
            'primary_topics': ['subjectKeyIdentifier'],
            'default_affected_field': 'extensions.subjectKeyIdentifier',
        },

        # 4.2.1.3 Key Usage
        '4.2.1.3': {
            'title': 'Key Usage',
            'primary_topics': ['keyUsage'],
            'default_affected_field': 'extensions.keyUsage',
        },

        # 4.2.1.4 Certificate Policies
        '4.2.1.4': {
            'title': 'Certificate Policies',
            'primary_topics': ['certificatePolicies'],
            'default_affected_field': 'extensions.certificatePolicies',
        },

        # 4.2.1.5 Policy Mappings
        '4.2.1.5': {
            'title': 'Policy Mappings',
            'primary_topics': ['policyMappings'],
            'default_affected_field': 'extensions.policyMappings',
        },

        # 4.2.1.6 Subject Alternative Name (重要！)
        '4.2.1.6': {
            'title': 'Subject Alternative Name',
            'primary_topics': ['subjectAltName', 'dNSName', 'iPAddress', 'rfc822Name', 'uniformResourceIdentifier'],
            'default_affected_field': 'extensions.subjectAltName.dNSName',  # dNSName是最常见的类型
            'sub_topics': {
                'dNSName': 'extensions.subjectAltName.dNSName',
                'iPAddress': 'extensions.subjectAltName.iPAddress',
                'rfc822Name': 'extensions.subjectAltName.rfc822Name',
                'uniformResourceIdentifier': 'extensions.subjectAltName.uniformResourceIdentifier',
                'directoryName': 'extensions.subjectAltName.directoryName',
                'registeredID': 'extensions.subjectAltName.registeredID',
                'otherName': 'extensions.subjectAltName.otherName',
            },
            'notes': 'This section discusses multiple GeneralName types, but dNSName is the most common. Rules using pronouns like "the name" likely refer to dNSName unless context suggests otherwise.'
        },

        # 4.2.1.7 Issuer Alternative Name
        '4.2.1.7': {
            'title': 'Issuer Alternative Name',
            'primary_topics': ['issuerAltName'],
            'default_affected_field': 'extensions.issuerAltName',
        },

        # 4.2.1.8 Subject Directory Attributes
        '4.2.1.8': {
            'title': 'Subject Directory Attributes',
            'primary_topics': ['subjectDirectoryAttributes'],
            'default_affected_field': 'extensions.subjectDirectoryAttributes',
        },

        # 4.2.1.9 Basic Constraints
        '4.2.1.9': {
            'title': 'Basic Constraints',
            'primary_topics': ['basicConstraints'],
            'default_affected_field': 'extensions.basicConstraints',
        },

        # 4.2.1.10 Name Constraints
        '4.2.1.10': {
            'title': 'Name Constraints',
            'primary_topics': ['nameConstraints'],
            'default_affected_field': 'extensions.nameConstraints',
        },

        # 4.2.1.11 Policy Constraints
        '4.2.1.11': {
            'title': 'Policy Constraints',
            'primary_topics': ['policyConstraints'],
            'default_affected_field': 'extensions.policyConstraints',
        },

        # 4.2.1.12 Extended Key Usage
        '4.2.1.12': {
            'title': 'Extended Key Usage',
            'primary_topics': ['extendedKeyUsage'],
            'default_affected_field': 'extensions.extendedKeyUsage',
        },

        # 4.2.1.13 CRL Distribution Points
        '4.2.1.13': {
            'title': 'CRL Distribution Points',
            'primary_topics': ['cRLDistributionPoints'],
            'default_affected_field': 'extensions.cRLDistributionPoints',
        },

        # 4.2.1.14 Inhibit anyPolicy
        '4.2.1.14': {
            'title': 'Inhibit anyPolicy',
            'primary_topics': ['inhibitAnyPolicy'],
            'default_affected_field': 'extensions.inhibitAnyPolicy',
        },

        # 4.2.1.15 Freshest CRL
        '4.2.1.15': {
            'title': 'Freshest CRL',
            'primary_topics': ['freshestCRL'],
            'default_affected_field': 'extensions.freshestCRL',
        },

        # 4.2.2 Private Internet Extensions
        '4.2.2': {
            'title': 'Private Internet Extensions',
            'primary_topics': ['extensions'],
        },

        # 4.2.2.1 Authority Information Access
        '4.2.2.1': {
            'title': 'Authority Information Access',
            'primary_topics': ['authorityInfoAccess'],
            'default_affected_field': 'extensions.authorityInfoAccess',
        },

        # 4.2.2.2 Subject Information Access
        '4.2.2.2': {
            'title': 'Subject Information Access',
            'primary_topics': ['subjectInfoAccess'],
            'default_affected_field': 'extensions.subjectInfoAccess',
        },

        # 5. CRL and CRL Extensions Profile
        '5': {
            'title': 'CRL and CRL Extensions Profile',
            'primary_topics': ['crl'],
        },

        # 6. Certification Path Validation
        '6': {
            'title': 'Certification Path Validation',
            'primary_topics': ['validation', 'certification_path'],
        },

        # 7. Processing Rules
        '7': {
            'title': 'Processing Rules',
            'primary_topics': ['processing', 'encoding'],
        },

        # 7.1 Internationalized Names in Distinguished Names
        '7.1': {
            'title': 'Internationalized Names in Distinguished Names',
            'primary_topics': ['directoryString', 'internationalization', 'encoding'],
            'default_affected_field': 'subject',
            # canonical_subject now resolved by FieldResolver from x509_field_schema
        },

        # 7.2 Internationalized Domain Names in GeneralName (重要！)
        '7.2': {
            'title': 'Internationalized Domain Names in GeneralName',
            'primary_topics': ['dNSName', 'IDN', 'ACE', 'internationalization', 'GeneralName'],
            'default_affected_field': 'extensions.subjectAltName.dNSName',
            # canonical_subject now resolved by FieldResolver from x509_field_schema
            'notes': 'This section specifically discusses how IDNs must be encoded when stored in the dNSName field of GeneralName. All rules here apply to dNSName, not to the broader subjectAltName extension.',
        },
    }

    # Mozilla Root Store Policy §5 章节主题映射
    MOZILLA_MRSP_SECTIONS = {
        '5': {
            'title': 'Technical Requirements',
            'primary_topics': ['certificate', 'algorithm', 'key'],
        },
        '5.1': {
            'title': 'Cryptographic Algorithms',
            'primary_topics': ['signatureAlgorithm', 'subjectPublicKeyInfo', 'algorithm'],
            'notes': 'Rules about allowed cryptographic algorithms and key types. Subject is typically signatureAlgorithm or subjectPublicKeyInfo.algorithm.',
        },
        '5.1.1': {
            'title': 'RSA',
            'primary_topics': ['subjectPublicKeyInfo', 'signatureAlgorithm'],
            'default_affected_field': 'subjectPublicKeyInfo.algorithm',
            'notes': 'RSA key and signature algorithm constraints. AlgorithmIdentifier rules apply to signatureAlgorithm field.',
        },
        '5.1.2': {
            'title': 'DSA',
            'primary_topics': ['subjectPublicKeyInfo', 'signatureAlgorithm'],
            'default_affected_field': 'subjectPublicKeyInfo.algorithm',
        },
        '5.1.3': {
            'title': 'ECDSA',
            'primary_topics': ['subjectPublicKeyInfo', 'signatureAlgorithm'],
            'default_affected_field': 'subjectPublicKeyInfo.algorithm',
        },
        '5.2': {
            'title': 'Certificate Fields',
            'primary_topics': ['certificate', 'serialNumber', 'extensions'],
            'notes': 'General certificate field requirements.',
        },
        '5.3': {
            'title': 'Revocation',
            'primary_topics': ['extensions.cRLDistributionPoints', 'extensions.authorityInfoAccess'],
            'default_affected_field': 'extensions.cRLDistributionPoints',
            'notes': 'Revocation information requirements. Subject is typically extensions.cRLDistributionPoints or extensions.authorityInfoAccess.',
        },
        '5.3.1': {
            'title': 'Revocation Checking',
            'primary_topics': ['extensions.cRLDistributionPoints', 'extensions.authorityInfoAccess'],
            'default_affected_field': 'extensions.cRLDistributionPoints',
        },
        '5.4': {
            'title': 'Certificate Transparency',
            'primary_topics': ['extensions.sct', 'extensions.certificateTransparency'],
            'default_affected_field': 'extensions.sct',
        },
    }

    @classmethod
    def get_section_info(cls, standard: str, section: str) -> Optional[Dict[str, Any]]:
        """
        获取指定标准和章节的信息

        Args:
            standard: 标准名称（如 "RFC5280"）
            section: 章节号（如 "4.2.1.6"）

        Returns:
            章节信息字典，如果找不到则返回 None
        """
        if standard.upper() == 'RFC5280' or standard.upper() == 'RFC 5280':
            return cls.RFC5280_SECTIONS.get(section)

        std_upper = standard.upper()
        if 'MOZILLA' in std_upper or 'MRSP' in std_upper:
            # Try exact match first, then parent section
            info = cls.MOZILLA_MRSP_SECTIONS.get(section)
            if info:
                return info
            # Try parent section (e.g. 5.1.2 → 5.1 → 5)
            parts = section.split('.')
            for i in range(len(parts) - 1, 0, -1):
                parent = '.'.join(parts[:i])
                info = cls.MOZILLA_MRSP_SECTIONS.get(parent)
                if info:
                    return info
            return None

        # 可以在这里添加其他标准的支持
        return None

    @classmethod
    def get_default_affected_field(cls, standard: str, section: str) -> Optional[str]:
        """
        获取指定章节的默认 affected_field

        当规则使用代词且无法明确识别字段时，使用此默认值

        Args:
            standard: 标准名称
            section: 章节号

        Returns:
            默认的 affected_field，如果未定义则返回 None
        """
        section_info = cls.get_section_info(standard, section)
        if section_info:
            return section_info.get('default_affected_field')
        return None

    @classmethod
    def get_primary_topics(cls, standard: str, section: str) -> List[str]:
        """
        获取指定章节的主要主题列表

        Args:
            standard: 标准名称
            section: 章节号

        Returns:
            主题列表，如果找不到则返回空列表
        """
        section_info = cls.get_section_info(standard, section)
        if section_info:
            return section_info.get('primary_topics', [])
        return []

    @classmethod
    def resolve_sub_topic(cls, standard: str, section: str, keyword: str) -> Optional[str]:
        """
        在章节内解析子主题

        例如在 RFC5280 Section 4.2.1.6 中:
        - keyword="dNSName" → "extensions.subjectAltName.dNSName"
        - keyword="iPAddress" → "extensions.subjectAltName.iPAddress"

        Args:
            standard: 标准名称
            section: 章节号
            keyword: 关键词

        Returns:
            解析后的完整字段路径，如果找不到则返回 None
        """
        section_info = cls.get_section_info(standard, section)
        if section_info and 'sub_topics' in section_info:
            sub_topics = section_info['sub_topics']
            # 不区分大小写匹配
            for key, value in sub_topics.items():
                if key.lower() == keyword.lower():
                    return value
        return None

    @classmethod
    def get_canonical_subject(cls, standard: str, section: str) -> Optional[Dict[str, Any]]:
        """
        获取指定章节的规范主体（canonical subject）

        Canonical subject 用于：
        1. 跨章节聚合（相同 subject 的规则聚合到一起）
        2. GraphRAG 节点规范化（避免 subject 漂移）
        3. 冲突检测（相同 subject 的规则冲突检测）

        Args:
            standard: 标准名称（如 "RFC5280"）
            section: 章节号（如 "7.2"）

        Returns:
            Canonical subject 字典，包含:
            - path: 规范路径（如 "extensions.subjectAltName.dNSName"）
            - aliases: 别名列表（如 ["dNSName", "DNS name", "IDN"]）

            如果未定义则返回 None
        """
        section_info = cls.get_section_info(standard, section)
        if section_info:
            return section_info.get('canonical_subject')
        return None

    @classmethod
    def normalize_subject_to_canonical(
        cls,
        standard: str,
        section: str,
        raw_subject: str
    ) -> Optional[Dict[str, Any]]:
        """
        将原始 subject 归一化为 canonical subject

        如果 raw_subject 匹配章节的 canonical_subject 或其别名之一，
        则返回 canonical 信息。

        Args:
            standard: 标准名称
            section: 章节号
            raw_subject: 原始 subject 文本

        Returns:
            归一化后的 subject 信息，包含:
            - canonical_path: 规范路径
            - matched_alias: 匹配的别名（如果通过别名匹配）
            - raw: 原始文本

            如果无法归一化则返回 None
        """
        canonical = cls.get_canonical_subject(standard, section)
        if not canonical:
            return None

        canonical_path = canonical.get('path', '')
        aliases = canonical.get('aliases', [])
        raw_lower = raw_subject.lower().strip()

        # 检查是否直接匹配 canonical path
        if raw_lower == canonical_path.lower():
            return {
                'canonical_path': canonical_path,
                'matched_alias': None,
                'raw': raw_subject,
            }

        # 检查是否匹配别名
        for alias in aliases:
            if raw_lower == alias.lower() or alias.lower() in raw_lower:
                return {
                    'canonical_path': canonical_path,
                    'matched_alias': alias,
                    'raw': raw_subject,
                }

        # 检查 canonical path 的最后一部分是否匹配
        path_parts = canonical_path.split('.')
        if path_parts and raw_lower == path_parts[-1].lower():
            return {
                'canonical_path': canonical_path,
                'matched_alias': path_parts[-1],
                'raw': raw_subject,
            }

        return None


# 导出单例实例
section_topics_kb = SectionTopicsKB()
