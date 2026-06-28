"""
Target Path 映射器

将IR v2.0的结构化 target_path 映射到 Go 访问表达式
禁止直接拼接字符串，必须通过映射表
"""
from typing import Dict, Optional, Tuple


class TargetPathMapper:
    """
    Target Path 到 Go 字段的映射器
    """

    # 扩展OID到Go字段的映射表
    EXTENSION_OID_MAP = {
        # 标准扩展 (names must match zlint/v3/util/oid.go exactly)
        "2.5.29.15": {"go_field": "KeyUsage", "util_const": "KeyUsageOID"},
        "2.5.29.19": {"go_field": "BasicConstraintsValid", "util_const": "BasicConstOID"},
        "2.5.29.17": {"go_field": "SubjectAltName", "util_const": "SubjectAlternateNameOID"},
        "2.5.29.37": {"go_field": "ExtKeyUsage", "util_const": "EkuSynOid"},
        "2.5.29.31": {"go_field": "CRLDistributionPoints", "util_const": "CrlDistOID"},
        "2.5.29.35": {"go_field": "AuthorityKeyId", "util_const": "AuthkeyOID"},
        "2.5.29.14": {"go_field": "SubjectKeyId", "util_const": "SubjectKeyIdentityOID"},
        "2.5.29.32": {"go_field": "PolicyIdentifiers", "util_const": "CertPolicyOID"},
        "1.3.6.1.5.5.7.1.1": {"go_field": "AuthorityInfoAccess", "util_const": "AiaOID"},
        "2.5.29.18": {"go_field": "IssuerAltName", "util_const": "IssuerAlternateNameOID"},
        "2.5.29.30": {"go_field": "NameConstraints", "util_const": "NameConstOID"},

        # CABF扩展
        "2.23.140.1.2.1": {"go_field": "CABForumOrgIdExt", "util_const": "CabfExtensionOrganizationIdentifier"},
        "1.3.6.1.4.1.11129.2.4.2": {"go_field": "SCTList", "util_const": "CtPoisonOID"},
    }

    # 扩展名称到OID的反向映射
    EXTENSION_NAME_MAP = {
        "KeyUsage": "2.5.29.15",
        "BasicConstraints": "2.5.29.19",
        "BasicConstraintsValid": "2.5.29.19",
        "SubjectAltName": "2.5.29.17",
        "ExtendedKeyUsage": "2.5.29.37",
        "ExtKeyUsage": "2.5.29.37",
        "CRLDistributionPoints": "2.5.29.31",
        "AuthorityKeyId": "2.5.29.35",
        "SubjectKeyId": "2.5.29.14",
        "CertificatePolicies": "2.5.29.32",
        "PolicyIdentifiers": "2.5.29.32",
        "AuthorityInfoAccess": "1.3.6.1.5.5.7.1.1",
        "IssuerAltName": "2.5.29.18",
    }

    # 证书子字段映射（非扩展字段）
    CERTIFICATE_SUBFIELD_MAP = {
        # 基本字段
        "Version": "c.Version",
        "SerialNumber": "c.SerialNumber",
        "Issuer": "c.Issuer",
        "Subject": "c.Subject",
        "NotBefore": "c.NotBefore",
        "NotAfter": "c.NotAfter",
        "PublicKey": "c.PublicKey",
        "PublicKeyAlgorithm": "c.PublicKeyAlgorithm",
        "SignatureAlgorithm": "c.SignatureAlgorithm",
        "IsCA": "c.IsCA",

        # Subject子字段
        "Subject.CommonName": "c.Subject.CommonName",
        "Subject.Country": "c.Subject.Country",
        "Subject.Organization": "c.Subject.Organization",
        "Subject.OrganizationalUnit": "c.Subject.OrganizationalUnit",
        "Subject.Locality": "c.Subject.Locality",
        "Subject.Province": "c.Subject.Province",
        "Subject.SerialNumber": "c.Subject.SerialNumber",

        # Issuer子字段
        "Issuer.CommonName": "c.Issuer.CommonName",
        "Issuer.Country": "c.Issuer.Country",
        "Issuer.Organization": "c.Issuer.Organization",
    }

    # 访问模式到Go代码的映射
    ACCESS_PATTERN_MAP = {
        "field": {
            "read": lambda field: f"{field}",
            "check_nil": lambda field: f"{field} == nil",
            "check_not_nil": lambda field: f"{field} != nil",
        },
        "bitmask": {
            "check_bit": lambda field, bit: f"{field} & {bit} != 0",
            "check_any": lambda field: f"{field} != 0",
        },
        "element": {
            "iterate": lambda field: f"for _, item := range {field}",
            "count": lambda field: f"len({field})",
        }
    }

    def map_target_path_to_go(
        self,
        target_path: Dict[str, any],
        operation: str = "read"
    ) -> Tuple[str, str]:
        """
        将 target_path 映射到 Go 访问表达式

        Args:
            target_path: IR v2.0 的 target_path 字典
            operation: 操作类型（read, check_nil, check_bit等）

        Returns:
            (go_expression, error_msg)
            go_expression: Go访问表达式，如 "c.KeyUsage"
            error_msg: 错误信息（如果映射失败）
        """
        root = target_path.get('root', 'Certificate')

        if root != 'Certificate':
            return None, f"Unsupported root: {root}"

        # 情况1: 扩展字段
        if target_path.get('extension'):
            return self._map_extension(target_path, operation)

        # 情况2: 证书子字段
        elif target_path.get('subfield'):
            return self._map_subfield(target_path, operation)

        # 情况3: 整个证书
        else:
            return "c", None

    def _map_extension(
        self,
        target_path: Dict[str, any],
        operation: str
    ) -> Tuple[Optional[str], Optional[str]]:
        """映射扩展字段"""
        extension = target_path['extension']
        oid = extension.get('oid', '')
        name = extension.get('name', '')

        # 通过OID查找
        if oid and oid in self.EXTENSION_OID_MAP:
            ext_info = self.EXTENSION_OID_MAP[oid]
            go_field = ext_info['go_field']

        # 通过名称查找
        elif name and name in self.EXTENSION_NAME_MAP:
            oid = self.EXTENSION_NAME_MAP[name]
            ext_info = self.EXTENSION_OID_MAP[oid]
            go_field = ext_info['go_field']

        else:
            return None, f"Unknown extension: OID={oid}, Name={name}"

        # 获取访问模式
        access_pattern = target_path.get('access_pattern', {})
        pattern_type = access_pattern.get('type', 'field')
        pattern_operation = access_pattern.get('operation', operation)

        # 生成Go表达式
        if pattern_type == 'field':
            if pattern_operation == 'read':
                return f"c.{go_field}", None
            elif pattern_operation == 'check_nil':
                return f"c.{go_field} == nil", None
            elif pattern_operation == 'check_not_nil':
                return f"c.{go_field} != nil", None

        elif pattern_type == 'bitmask':
            # KeyUsage等bitmask字段
            if pattern_operation == 'check_any':
                return f"c.{go_field} != 0", None
            elif pattern_operation.startswith('check_bit:'):
                bit = pattern_operation.split(':')[1]
                return f"c.{go_field} & {bit} != 0", None

        return f"c.{go_field}", None

    def _map_subfield(
        self,
        target_path: Dict[str, any],
        operation: str
    ) -> Tuple[Optional[str], Optional[str]]:
        """映射证书子字段"""
        subfield = target_path['subfield']

        if subfield in self.CERTIFICATE_SUBFIELD_MAP:
            go_field = self.CERTIFICATE_SUBFIELD_MAP[subfield]

            # 应用操作
            if operation == 'read':
                return go_field, None
            elif operation == 'check_nil':
                return f"{go_field} == nil", None
            elif operation == 'check_not_nil':
                return f"{go_field} != nil", None
            else:
                return go_field, None

        else:
            return None, f"Unknown subfield: {subfield}"

    def get_util_const_for_extension(self, oid: str) -> Optional[str]:
        """
        获取扩展的 util 常量名

        Args:
            oid: 扩展的OID

        Returns:
            util常量名，如 "KeyUsageOID"，如果不存在返回None
        """
        if oid in self.EXTENSION_OID_MAP:
            return self.EXTENSION_OID_MAP[oid]['util_const']
        return None

    def map_legacy_target_field(self, target_field: str) -> Tuple[Optional[str], Optional[str]]:
        """
        映射 v1.x 的 target_field 或原始字段名到 Go 表达式

        Args:
            target_field: v1.x 格式的字段（如 "c.KeyUsage"）或原始字段名（如 "extensions.keyUsage"）

        Returns:
            (go_expression, error_msg)
        """
        # 已经是Go格式，直接返回
        if target_field.startswith('c.') or target_field == 'c':
            return target_field, None

        # 原始字段名映射表（兼容未归一化的字段）
        raw_field_mapping = {
            # Extensions - 标准化不同的写法
            'extensions.keyUsage': 'c.KeyUsage',
            'extensions.KeyUsage': 'c.KeyUsage',
            'extensions.extendedKeyUsage': 'c.ExtKeyUsage',
            'extensions.ExtendedKeyUsage': 'c.ExtKeyUsage',
            'extensions.basicConstraints': 'c.BasicConstraintsValid',
            'extensions.BasicConstraints': 'c.BasicConstraintsValid',
            'extensions.subjectAltName': 'c.SubjectAltName',  # 扩展本身
            'extensions.SubjectAltName': 'c.SubjectAltName',
            'extensions.subjectAltName.dNSName': 'c.DNSNames',  # DNS names列表
            'extensions.subjectAltName.dnsName': 'c.DNSNames',
            'extensions.subjectAltName.DNSName': 'c.DNSNames',
            'extensions.issuerAltName': 'c.IssuerAltName',
            'extensions.IssuerAltName': 'c.IssuerAltName',
            'extensions.authorityKeyIdentifier': 'c.AuthorityKeyId',
            'extensions.AuthorityKeyIdentifier': 'c.AuthorityKeyId',
            'extensions.subjectKeyIdentifier': 'c.SubjectKeyId',
            'extensions.SubjectKeyIdentifier': 'c.SubjectKeyId',
            'extensions.cRLDistributionPoints': 'c.CRLDistributionPoints',
            'extensions.CRLDistributionPoints': 'c.CRLDistributionPoints',
            'extensions.certificatePolicies': 'c.PolicyIdentifiers',
            'extensions.CertificatePolicies': 'c.PolicyIdentifiers',
            'extensions.authorityInfoAccess': 'c.AuthorityInfoAccess',
            'extensions.AuthorityInfoAccess': 'c.AuthorityInfoAccess',

            # Subject fields
            'subject': 'c.Subject',
            'Subject': 'c.Subject',
            'subject.commonName': 'c.Subject.CommonName',
            'Subject.CommonName': 'c.Subject.CommonName',
            'subject.organization': 'c.Subject.Organization',
            'Subject.Organization': 'c.Subject.Organization',
            'subject.country': 'c.Subject.Country',
            'Subject.Country': 'c.Subject.Country',

            # Validity fields
            'validity': 'c.NotBefore',  # 通用validity返回NotBefore
            'Validity': 'c.NotBefore',
            'validity.notBefore': 'c.NotBefore',
            'NotBefore': 'c.NotBefore',
            'validity.notAfter': 'c.NotAfter',
            'NotAfter': 'c.NotAfter',

            # Other fields
            'serialNumber': 'c.SerialNumber',
            'SerialNumber': 'c.SerialNumber',
            'signatureAlgorithm': 'c.SignatureAlgorithm',
            'SignatureAlgorithm': 'c.SignatureAlgorithm',
            'issuer': 'c.Issuer',
            'Issuer': 'c.Issuer',
            'publicKey': 'c.PublicKey',
            'PublicKey': 'c.PublicKey',
            'version': 'c.Version',
            'Version': 'c.Version',

            # CRL-specific fields
            'thisUpdate': 'c.ThisUpdate',
            'ThisUpdate': 'c.ThisUpdate',
            'nextUpdate': 'c.NextUpdate',
            'NextUpdate': 'c.NextUpdate',
        }

        # 尝试精确匹配
        if target_field in raw_field_mapping:
            return raw_field_mapping[target_field], None

        # 尝试部分匹配（处理嵌套字段）
        for raw_path, go_expr in raw_field_mapping.items():
            if target_field.lower() == raw_path.lower():
                return go_expr, None

        return None, f"Unknown field: {target_field}"


# ==================== 使用示例 ====================

def example_usage():
    """使用示例"""
    mapper = TargetPathMapper()

    # 示例1: KeyUsage扩展
    target_path_1 = {
        "root": "Certificate",
        "extension": {
            "oid": "2.5.29.15",
            "name": "KeyUsage"
        },
        "subfield": None,
        "access_pattern": {
            "type": "field",
            "operation": "read"
        }
    }

    go_expr, error = mapper.map_target_path_to_go(target_path_1)
    print(f"KeyUsage: {go_expr}")  # 输出: c.KeyUsage

    # 示例2: Subject.CommonName
    target_path_2 = {
        "root": "Certificate",
        "extension": None,
        "subfield": "Subject.CommonName",
        "access_pattern": {
            "type": "field",
            "operation": "read"
        }
    }

    go_expr, error = mapper.map_target_path_to_go(target_path_2)
    print(f"CommonName: {go_expr}")  # 输出: c.Subject.CommonName

    # 示例3: KeyUsage bitmask检查
    target_path_3 = {
        "root": "Certificate",
        "extension": {
            "oid": "2.5.29.15",
            "name": "KeyUsage"
        },
        "subfield": None,
        "access_pattern": {
            "type": "bitmask",
            "operation": "check_bit:x509.KeyUsageDigitalSignature"
        }
    }

    go_expr, error = mapper.map_target_path_to_go(target_path_3)
    print(f"KeyUsage bit check: {go_expr}")
    # 输出: c.KeyUsage & x509.KeyUsageDigitalSignature != 0


if __name__ == "__main__":
    example_usage()
