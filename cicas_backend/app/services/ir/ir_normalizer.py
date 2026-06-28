"""
模块 D: IR 归一化模块
实现超级提示词规范中的 normalize_ir(IR, KG)
"""
from typing import Dict, Optional, List
from sqlalchemy.orm import Session
from app.core.logging_config import app_logger
from app.utils.pki_synonyms import PKI_SYNONYMS


class IRNormalizer:
    """
    IR 归一化器

    功能：
    1. subject 路径归一化为 canonical path
    2. 同义词归一化
    3. constraint 结构化处理
    4. 引用定义注入 constraint.expanded
    """

    def __init__(self, db: Session, kg, definition_expander):
        self.db = db
        self.kg = kg
        self.definition_expander = definition_expander

    def normalize_ir(self, ir: Dict) -> Dict:
        """
        完整的 IR 归一化流程

        Args:
            ir: 原始 IR 字典

        Returns:
            归一化后的 IR
        """
        app_logger.info(f"Normalizing IR: {ir.get('lint_name')}")

        # Step 1: 归一化 target_field (subject)
        ir = self._normalize_subject_path(ir)

        # Step 2: 同义词归一化
        ir = self._normalize_synonyms(ir)

        # Step 3: 约束结构化
        ir = self._normalize_constraint(ir)

        # Step 4: 引用定义展开
        ir = self.definition_expander.expand_constraint_definition(ir)

        app_logger.info("IR normalization complete")
        return ir

    def _normalize_subject_path(self, ir: Dict) -> Dict:
        """
        Step 1: 归一化 subject 路径

        转换规则：
        - extensions.keyUsage → c.KeyUsage
        - subject.commonName → c.Subject.CommonName
        - validity.notBefore → c.NotBefore

        Args:
            ir: IR 字典

        Returns:
            归一化后的 IR
        """
        # 从subject字段读取原始字段名（而不是target_field）
        # 因为IR生成时只生成subject，target_field由归一化器创建
        source_field = ir.get('target_field') or ir.get('subject', '')

        if not source_field:
            app_logger.warning("No subject or target_field found in IR, skipping normalization")
            return ir

        # 如果已经是 c. 开头，检查是否需要进一步归一化
        if source_field.startswith('c.'):
            # 已经归一化，检查是否在同义词表中
            canonical = self._get_canonical_field(source_field)
            if canonical != source_field:
                app_logger.debug(f"Normalizing field: {source_field} → {canonical}")
                ir['target_field'] = canonical
        else:
            # 未归一化，进行转换
            canonical = self._convert_to_canonical_path(source_field)
            ir['target_field'] = canonical
            app_logger.debug(f"Converted field: {source_field} → {canonical}")

        return ir

    def _convert_to_canonical_path(self, field: str) -> str:
        """
        将原始字段路径转换为 canonical 路径

        Args:
            field: 原始字段名

        Returns:
            canonical 路径
        """
        # 字段映射表（扩展现有的映射）
        field_mapping = {
            # Extensions
            'extensions.keyUsage': 'c.KeyUsage',
            'extensions.extendedKeyUsage': 'c.ExtKeyUsage',
            'extensions.basicConstraints': 'c.BasicConstraintsValid',
            'extensions.subjectAltName': 'c.SubjectAltName',
            'extensions.issuerAltName': 'c.IssuerAltName',
            'extensions.authorityKeyIdentifier': 'c.AuthorityKeyId',
            'extensions.subjectKeyIdentifier': 'c.SubjectKeyId',
            'extensions.cRLDistributionPoints': 'c.CRLDistributionPoints',

            # Subject
            'subject': 'c.Subject',
            'subject.commonName': 'c.Subject.CommonName',
            'subject.organization': 'c.Subject.Organization',
            'subject.country': 'c.Subject.Country',

            # Validity
            'validity': 'c.NotBefore, c.NotAfter',
            'validity.notBefore': 'c.NotBefore',
            'validity.notAfter': 'c.NotAfter',

            # Other
            'serialNumber': 'c.SerialNumber',
            'signatureAlgorithm': 'c.SignatureAlgorithm',
            'issuer': 'c.Issuer',
            'publicKey': 'c.PublicKey',
            'version': 'c.Version',
        }

        # 优先使用映射表
        if field in field_mapping:
            return field_mapping[field]

        # 处理 extensions.* 模式
        if field.startswith('extensions.'):
            ext_name = field.split('.')[-1]
            # 转换为驼峰命名
            camel_case = ''.join(word.capitalize() for word in ext_name.split('_'))
            return f'c.{camel_case}'

        # 默认添加 c. 前缀
        return f'c.{field}'

    def _normalize_synonyms(self, ir: Dict) -> Dict:
        """
        Step 2: 同义词归一化

        使用 PKI_SYNONYMS 表进行归一化

        Args:
            ir: IR 字典

        Returns:
            归一化后的 IR
        """
        target_field = ir.get('target_field', '')

        # 从同义词表中查找 canonical 形式
        canonical = self._get_canonical_field(target_field)

        if canonical != target_field:
            app_logger.debug(f"Synonym normalized: {target_field} → {canonical}")
            ir['target_field'] = canonical

        # 归一化 description/rule_text 中的同义词
        desc_key = 'description' if 'description' in ir else 'rule_text'
        description = ir.get(desc_key, '')
        for synonym_group in PKI_SYNONYMS.values():
            canonical_term = synonym_group[0]  # 第一个是 canonical
            for synonym in synonym_group[1:]:
                if synonym.lower() in description.lower():
                    description = description.replace(synonym, canonical_term)

        ir[desc_key] = description

        return ir

    def _get_canonical_field(self, field: str) -> str:
        """
        从同义词表中获取 canonical 字段名

        Args:
            field: 字段名

        Returns:
            canonical 字段名
        """
        for canonical, synonyms in PKI_SYNONYMS.items():
            if field in synonyms or field == canonical:
                return canonical

        return field

    def _normalize_constraint(self, ir: Dict) -> Dict:
        """
        Step 3: 约束结构化处理

        处理包括：
        - 数值范围归一化
        - ABNF 引用标记
        - presence 映射

        Args:
            ir: IR 字典

        Returns:
            归一化后的 IR
        """
        constraint = ir.get('constraint', {})
        logic = ir.get('logic', {})

        # 合并 constraint 和 logic（兼容旧格式）
        if not constraint and logic:
            constraint = {
                'type': logic.get('type'),
                'value': logic.get('value'),
                'operator': logic.get('operator'),
            }

        # 归一化数值范围
        if constraint.get('type') == 'range':
            constraint = self._normalize_numeric_range(constraint)

        # 处理 presence
        elif constraint.get('type') == 'presence':
            constraint = self._normalize_presence(constraint)

        # 标记 ABNF 引用
        if 'abnf' in constraint.get('value', '').lower():
            constraint['has_abnf_reference'] = True

        ir['constraint'] = constraint

        return ir

    def _normalize_numeric_range(self, constraint: Dict) -> Dict:
        """
        归一化数值范围

        Args:
            constraint: 约束字典

        Returns:
            归一化后的约束
        """
        import re

        value = constraint.get('value', '')

        # 提取数值
        match = re.search(r'(\d+(?:\.\d+)?)', str(value))
        if match:
            numeric_value = float(match.group(1))
            constraint['numeric_value'] = numeric_value

        # 提取单位
        if 'bit' in value.lower():
            constraint['unit'] = 'bits'
        elif 'byte' in value.lower() or 'octet' in value.lower():
            constraint['unit'] = 'bytes'
        elif 'day' in value.lower():
            constraint['unit'] = 'days'
        elif 'month' in value.lower():
            constraint['unit'] = 'months'

        return constraint

    def _normalize_presence(self, constraint: Dict) -> Dict:
        """
        归一化 presence 约束

        Args:
            constraint: 约束字典

        Returns:
            归一化后的约束
        """
        operator = constraint.get('operator', '')

        # 标准化操作符
        if operator in ['exists', 'must_be_present', 'present']:
            constraint['operator'] = 'exists'
        elif operator in ['not_exists', 'must_not_be_present', 'absent']:
            constraint['operator'] = 'not_exists'
        elif operator in ['critical', 'must_be_critical']:
            constraint['operator'] = 'critical'
        elif operator in ['not_critical', 'must_not_be_critical']:
            constraint['operator'] = 'not_critical'

        return constraint

    def batch_normalize(self, irs: List[Dict]) -> List[Dict]:
        """
        批量归一化 IR

        Args:
            irs: IR 列表

        Returns:
            归一化后的 IR 列表
        """
        app_logger.info(f"Batch normalizing {len(irs)} IRs...")

        normalized_irs = []
        for ir in irs:
            try:
                normalized_ir = self.normalize_ir(ir)
                normalized_irs.append(normalized_ir)
            except Exception as e:
                app_logger.error(f"Failed to normalize IR {ir.get('lint_name')}: {e}")
                # 保留原始 IR
                normalized_irs.append(ir)

        app_logger.info(f"Successfully normalized {len(normalized_irs)} IRs")
        return normalized_irs
