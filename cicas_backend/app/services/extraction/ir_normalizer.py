"""
IR 归一化器
将 raw IR 转换为 normalized IR，然后转换为 final IR
"""
from typing import Dict, List, Optional, Any, Union
from .ir_schema import (
    IntermediateRepresentation,
    IRStage,
    IRConstraint,
    ConstraintType,
    ObligationType,
    PredicateType,
    SubjectRef,
)
import re


class IRNormalizer:
    """IR 归一化器"""

    def __init__(self, kg_client=None):
        """
        初始化归一化器

        Args:
            kg_client: 知识图谱客户端（用于字段映射）
        """
        self.kg_client = kg_client

        # 字段路径映射表
        self.field_mapping = {
            # Extensions
            'extensions.keyUsage': 'c.KeyUsage',
            'extensions.extendedKeyUsage': 'c.ExtKeyUsage',
            'extensions.basicConstraints': 'c.BasicConstraintsValid',
            'extensions.subjectAltName': 'c.SubjectAltName',
            'extensions.issuerAltName': 'c.IssuerAltName',
            'extensions.subjectKeyIdentifier': 'c.SubjectKeyIdentifier',
            'extensions.authorityKeyIdentifier': 'c.AuthorityKeyIdentifier',
            'extensions.certificatePolicies': 'c.CertificatePolicies',
            'extensions.cRLDistributionPoints': 'c.CRLDistributionPoints',

            # Subject/Issuer fields
            'subject.commonName': 'c.Subject.CommonName',
            'subject.countryName': 'c.Subject.Country',
            'subject.organizationName': 'c.Subject.Organization',
            'subject.organizationalUnitName': 'c.Subject.OrganizationalUnit',
            'issuer.commonName': 'c.Issuer.CommonName',

            # Validity
            'validity.notBefore': 'c.NotBefore',
            'validity.notAfter': 'c.NotAfter',

            # Public Key
            'subjectPublicKeyInfo': 'c.PublicKey',
            'publicKeyAlgorithm': 'c.PublicKeyAlgorithm',

            # Signature
            'signatureAlgorithm': 'c.SignatureAlgorithm',
        }

        # PKI 同义词表
        self.synonyms = {
            'distinguished name': 'DN',
            'subject alternative name': 'SAN',
            'authority key identifier': 'AKI',
            'subject key identifier': 'SKI',
            'certificate revocation list': 'CRL',
            'online certificate status protocol': 'OCSP',
            'certification authority': 'CA',
        }

    def normalize(
        self, ir: IntermediateRepresentation
    ) -> IntermediateRepresentation:
        """
        归一化 IR

        将 raw IR 转换为 normalized IR

        Args:
            ir: raw IR

        Returns:
            normalized IR
        """
        if ir.stage != IRStage.RAW:
            # 已归一化，直接返回
            return ir

        # Step 1: 归一化主体路径
        normalized_subject = self._normalize_subject_path(ir.subject)

        # Step 2: 归一化同义词
        normalized_constraint = self._normalize_constraint(ir.constraint)

        # Step 3: 结构化约束
        structured_constraint = self._structure_constraint(normalized_constraint)

        # 创建归一化的 IR
        normalized_ir = IntermediateRepresentation(
            rule_id=ir.rule_id,
            stage=IRStage.NORMALIZED,
            version=ir.version,
            subject=normalized_subject,
            obligation=ir.obligation,
            predicate=ir.predicate,
            constraint=structured_constraint,
            references=ir.references,
            provenance=ir.provenance,
            kg_links=ir.kg_links,
            conflicts=ir.conflicts,
            rule_text=ir.rule_text,
            conditions=ir.conditions,
            context=ir.context,
        )

        return normalized_ir

    def _normalize_subject_path(self, subject: Union[str, SubjectRef, None]) -> Union[str, SubjectRef]:
        """归一化主体路径"""
        if subject is None:
            return ""

        # 如果是 SubjectRef，提取路径进行归一化
        if isinstance(subject, SubjectRef):
            subject_str = subject.path
        else:
            subject_str = str(subject)

        # 查找映射表
        subject_lower = subject_str.lower()

        for raw_path, canonical_path in self.field_mapping.items():
            if subject_lower == raw_path.lower():
                # 如果原始是 SubjectRef，返回更新后的 SubjectRef
                if isinstance(subject, SubjectRef):
                    return SubjectRef(path=canonical_path, raw=subject.raw, field_id=subject.field_id)
                return canonical_path

        # 尝试部分匹配
        for raw_path, canonical_path in self.field_mapping.items():
            if raw_path.lower() in subject_lower or subject_lower in raw_path.lower():
                if isinstance(subject, SubjectRef):
                    return SubjectRef(path=canonical_path, raw=subject.raw, field_id=subject.field_id)
                return canonical_path

        # 如果没有找到映射，返回原始值
        return subject

    def _normalize_constraint(self, constraint: IRConstraint) -> IRConstraint:
        """归一化约束中的同义词"""
        raw_text = constraint.raw_text.lower()

        # 替换同义词
        normalized_text = raw_text
        for synonym, canonical in self.synonyms.items():
            normalized_text = normalized_text.replace(synonym, canonical)

        # 创建新的约束对象
        normalized_constraint = IRConstraint(
            raw_text=constraint.raw_text,  # 保留原始文本
            type=constraint.type,
            value=constraint.value,
            expanded=constraint.expanded,
            unit=constraint.unit,
            min_value=constraint.min_value,
            max_value=constraint.max_value,
            pattern=constraint.pattern,
            allowed_values=constraint.allowed_values,
        )

        return normalized_constraint

    def _structure_constraint(self, constraint: IRConstraint) -> IRConstraint:
        """结构化约束"""
        # 如果约束已经结构化，直接返回
        if constraint.type and constraint.type != ConstraintType.STRING:
            return constraint

        # 尝试从 raw_text 提取结构化信息
        raw_text = constraint.raw_text

        # 检测数值约束
        numeric_match = re.search(
            r'(\d+)\s*(bit[s]?|byte[s]?|day[s]?|year[s]?|month[s]?)',
            raw_text,
            re.IGNORECASE
        )
        if numeric_match:
            value = int(numeric_match.group(1))
            unit = numeric_match.group(2).lower()

            return IRConstraint(
                raw_text=constraint.raw_text,
                type=ConstraintType.NUMERIC,
                value=value,
                unit=unit,
            )

        # 检测布尔约束
        if 'TRUE' in raw_text.upper() or 'FALSE' in raw_text.upper():
            return IRConstraint(
                raw_text=constraint.raw_text,
                type=ConstraintType.BOOLEAN,
                value='TRUE' in raw_text.upper(),
            )

        # 检测 ABNF
        if '::=' in raw_text:
            return IRConstraint(
                raw_text=constraint.raw_text,
                type=ConstraintType.ABNF,
                value=raw_text,
            )

        # 默认返回原始约束
        return constraint

    def normalize_batch(
        self, irs: List[IntermediateRepresentation]
    ) -> List[IntermediateRepresentation]:
        """批量归一化"""
        return [self.normalize(ir) for ir in irs]
