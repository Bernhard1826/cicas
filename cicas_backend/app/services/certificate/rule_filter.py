"""
Rule Filter - 规则预过滤器
根据证书类型和字段智能过滤相关规则，避免不必要的检查
"""
from typing import List, Dict, Set
from app.core.logging_config import app_logger


class RuleFilter:
    """
    规则过滤器 - 根据证书特征筛选相关规则

    优化策略：
    1. 根据证书类型过滤（CA、终端实体、代码签名等）
    2. 根据证书扩展字段过滤
    3. 根据规则的 affected_field 过滤
    """

    # 证书类型与规则字段的映射
    CERT_TYPE_FIELDS = {
        'CA': {
            'basicConstraints', 'keyUsage', 'subjectKeyIdentifier',
            'authorityKeyIdentifier', 'certificatePolicies', 'cRLDistributionPoints'
        },
        'END_ENTITY': {
            'subjectAltName', 'keyUsage', 'extendedKeyUsage',
            'authorityKeyIdentifier', 'subjectKeyIdentifier'
        },
        'CODE_SIGNING': {
            'extendedKeyUsage', 'keyUsage', 'subjectAltName',
            'certificatePolicies'
        },
        'SERVER': {
            'subjectAltName', 'keyUsage', 'extendedKeyUsage',
            'authorityInfoAccess', 'cRLDistributionPoints'
        }
    }

    def __init__(self):
        self.filter_stats = {
            'total_rules': 0,
            'filtered_rules': 0,
            'filter_ratio': 0.0
        }

    def filter_rules(self, rules: List[Dict], cert_data: Dict) -> List[Dict]:
        """
        根据证书数据过滤相关规则

        Args:
            rules: 所有规则列表
            cert_data: 证书解析后的数据

        Returns:
            过滤后的规则列表
        """
        self.filter_stats['total_rules'] = len(rules)

        # 1. 检测证书类型
        cert_type = self._detect_cert_type(cert_data)
        app_logger.info(f"Detected certificate type: {cert_type}")

        # 2. 提取证书中实际存在的扩展字段
        cert_extensions = self._extract_extensions(cert_data)
        app_logger.debug(f"Certificate extensions: {cert_extensions}")

        # 3. 过滤规则
        filtered_rules = []
        for rule in rules:
            if self._is_rule_relevant(rule, cert_type, cert_extensions):
                filtered_rules.append(rule)

        self.filter_stats['filtered_rules'] = len(filtered_rules)
        self.filter_stats['filter_ratio'] = (
            1 - len(filtered_rules) / len(rules) if len(rules) > 0 else 0
        )

        app_logger.info(
            f"Rule filtering: {len(rules)} -> {len(filtered_rules)} "
            f"(filtered out {self.filter_stats['filter_ratio']*100:.1f}%)"
        )

        return filtered_rules

    def _detect_cert_type(self, cert_data: Dict) -> str:
        """检测证书类型"""
        # 检查 basicConstraints 扩展
        extensions = cert_data.get('extensions', {})
        basic_constraints = extensions.get('basicConstraints', {})

        if basic_constraints.get('cA', False):
            return 'CA'

        # 检查 extendedKeyUsage
        ext_key_usage = extensions.get('extendedKeyUsage', {})
        usages = ext_key_usage.get('usages', [])

        if 'codeSigning' in usages:
            return 'CODE_SIGNING'

        if 'serverAuth' in usages or 'clientAuth' in usages:
            return 'SERVER'

        return 'END_ENTITY'

    def _extract_extensions(self, cert_data: Dict) -> Set[str]:
        """提取证书中存在的扩展字段"""
        extensions = cert_data.get('extensions', {})

        # 标准化扩展名称
        extension_names = set()
        for ext_name in extensions.keys():
            # 转换为常见的扩展名称格式
            normalized = self._normalize_extension_name(ext_name)
            extension_names.add(normalized)

        # 添加基本字段（所有证书都有）
        extension_names.update({
            'subject', 'issuer', 'serialNumber',
            'notBefore', 'notAfter', 'signature'
        })

        return extension_names

    def _normalize_extension_name(self, ext_name: str) -> str:
        """标准化扩展名称"""
        # 转换常见的变体
        mappings = {
            'subject_alt_name': 'subjectAltName',
            'SubjectAltName': 'subjectAltName',
            'key_usage': 'keyUsage',
            'KeyUsage': 'keyUsage',
            'extended_key_usage': 'extendedKeyUsage',
            'ExtendedKeyUsage': 'extendedKeyUsage',
            'basic_constraints': 'basicConstraints',
            'BasicConstraints': 'basicConstraints',
            'subject_key_identifier': 'subjectKeyIdentifier',
            'SubjectKeyIdentifier': 'subjectKeyIdentifier',
            'authority_key_identifier': 'authorityKeyIdentifier',
            'AuthorityKeyIdentifier': 'authorityKeyIdentifier',
        }

        return mappings.get(ext_name, ext_name)

    def _is_rule_relevant(
        self,
        rule: Dict,
        cert_type: str,
        cert_extensions: Set[str]
    ) -> bool:
        """
        判断规则是否与证书相关

        规则相关性判断：
        1. 如果规则没有指定 affected_field，则总是相关
        2. 如果规则的 affected_field 在证书中存在，则相关
        3. 如果规则属于该证书类型的必需字段，则相关
        """
        affected_field = rule.get('affected_field', 'general')

        # 通用规则总是检查
        if affected_field in ('general', 'all', 'certificate', None, ''):
            return True

        # 标准化字段名
        affected_field = self._normalize_extension_name(affected_field)

        # 检查字段是否在证书中
        if affected_field in cert_extensions:
            return True

        # 检查是否是该证书类型的必需字段
        type_fields = self.CERT_TYPE_FIELDS.get(cert_type, set())
        if affected_field in type_fields:
            return True

        # 检查规则文本中是否包含证书中的字段（模糊匹配）
        rule_text = rule.get('text', '').lower()
        for ext in cert_extensions:
            if ext.lower() in rule_text:
                return True

        return False

    def get_stats(self) -> Dict:
        """获取过滤统计信息"""
        return self.filter_stats.copy()
