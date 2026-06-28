"""
IR 到 zlint 映射表

将新 IR schema 的核心字段映射到 zlint 代码生成所需的常量和 OID。
按照 "Option 1" 设计：生成器从核心 IR 字段推断 OID/常量，不依赖 IR 中的派生字段。

映射类型：
1. subject 字段路径 -> 扩展 OID / DN 属性 OID
2. 扩展名 -> zlint util 常量名
3. requires_operation -> Go 辅助函数（如果有实现）
4. assertion_subject + enforcement_phase -> lintability 快速判断
"""

from typing import Dict, Optional, Any, Tuple, List
from dataclasses import dataclass


# ============================================================================
# 1. Subject 字段路径到 OID 的映射
# ============================================================================

SUBJECT_TO_EXTENSION_OID: Dict[str, str] = {
    # SubjectAltName (SAN) 扩展
    "extensions.subjectAltName": "2.5.29.17",
    "extensions.subjectAltName.dNSName": "2.5.29.17",
    "extensions.subjectAltName.iPAddress": "2.5.29.17",
    "extensions.subjectAltName.rfc822Name": "2.5.29.17",
    "extensions.subjectAltName.uniformResourceIdentifier": "2.5.29.17",
    "extensions.san": "2.5.29.17",
    "dNSName": "2.5.29.17",
    "DNSNames": "2.5.29.17",

    # Key Usage
    "extensions.keyUsage": "2.5.29.15",
    "KeyUsage": "2.5.29.15",

    # Extended Key Usage
    "extensions.extendedKeyUsage": "2.5.29.37",
    "extensions.extKeyUsage": "2.5.29.37",
    "ExtKeyUsage": "2.5.29.37",

    # Basic Constraints
    "extensions.basicConstraints": "2.5.29.19",
    "BasicConstraints": "2.5.29.19",

    # Authority/Subject Key Identifiers
    "extensions.authorityKeyIdentifier": "2.5.29.35",
    "extensions.subjectKeyIdentifier": "2.5.29.14",
    "AuthorityKeyId": "2.5.29.35",
    "SubjectKeyId": "2.5.29.14",

    # CRL Distribution Points
    "extensions.cRLDistributionPoints": "2.5.29.31",
    "CRLDistributionPoints": "2.5.29.31",

    # Certificate Policies
    "extensions.certificatePolicies": "2.5.29.32",
    "PolicyIdentifiers": "2.5.29.32",

    # Authority Info Access
    "extensions.authorityInfoAccess": "1.3.6.1.5.5.7.1.1",
    "AuthorityInfoAccess": "1.3.6.1.5.5.7.1.1",

    # Name Constraints
    "extensions.nameConstraints": "2.5.29.30",
    "NameConstraints": "2.5.29.30",

    # Issuer Alt Name
    "extensions.issuerAltName": "2.5.29.18",
    "IssuerAltName": "2.5.29.18",
}


# ============================================================================
# 2. DN 属性 OID 映射
# ============================================================================

DN_ATTRIBUTE_OIDS: Dict[str, str] = {
    # 常用 Subject DN 属性
    "commonName": "2.5.4.3",
    "CN": "2.5.4.3",
    "organization": "2.5.4.10",
    "O": "2.5.4.10",
    "organizationalUnit": "2.5.4.11",
    "OU": "2.5.4.11",
    "country": "2.5.4.6",
    "C": "2.5.4.6",
    "stateOrProvinceName": "2.5.4.8",
    "ST": "2.5.4.8",
    "localityName": "2.5.4.7",
    "L": "2.5.4.7",
    "serialNumber": "2.5.4.5",
    "givenName": "2.5.4.42",
    "GN": "2.5.4.42",
    "surname": "2.5.4.4",
    "SN": "2.5.4.4",
    "title": "2.5.4.12",
    "domainComponent": "0.9.2342.19200300.100.1.25",
    "DC": "0.9.2342.19200300.100.1.25",
    "emailAddress": "1.2.840.113549.1.9.1",
    "E": "1.2.840.113549.1.9.1",
    "streetAddress": "2.5.4.9",
    "postalCode": "2.5.4.17",

    # DirectoryString (泛指 DN 属性，用于编码规则)
    "DirectoryString": None,  # 特殊标记：适用于所有 DN 属性
    "subject.Names": None,
}

# 标准 DN 属性 OID 列表 (用于 UTF8String/PrintableString 编码检查)
STANDARD_DN_ATTRIBUTE_OIDS: List[str] = [
    "2.5.4.3",   # CN
    "2.5.4.10",  # O
    "2.5.4.11",  # OU
    "2.5.4.6",   # C
    "2.5.4.8",   # ST
    "2.5.4.7",   # L
    "2.5.4.5",   # serialNumber
]


# ============================================================================
# 3. OID 到 zlint util 常量的映射
# ============================================================================

OID_TO_ZLINT_CONST: Dict[str, Dict[str, str]] = {
    # 扩展 OID (names must match zlint/v3/util/oid.go exactly)
    "2.5.29.15": {"const": "util.KeyUsageOID", "go_field": "KeyUsage"},
    "2.5.29.19": {"const": "util.BasicConstOID", "go_field": "BasicConstraintsValid"},
    "2.5.29.17": {"const": "util.SubjectAlternateNameOID", "go_field": "DNSNames"},  # DNSNames for SAN
    "2.5.29.37": {"const": "util.EkuSynOid", "go_field": "ExtKeyUsage"},
    "2.5.29.31": {"const": "util.CrlDistOID", "go_field": "CRLDistributionPoints"},
    "2.5.29.35": {"const": "util.AuthkeyOID", "go_field": "AuthorityKeyId"},
    "2.5.29.14": {"const": "util.SubjectKeyIdentityOID", "go_field": "SubjectKeyId"},
    "2.5.29.32": {"const": "util.CertPolicyOID", "go_field": "PolicyIdentifiers"},
    "1.3.6.1.5.5.7.1.1": {"const": "util.AiaOID", "go_field": "AuthorityInfoAccess"},
    "2.5.29.18": {"const": "util.IssuerAlternateNameOID", "go_field": "IssuerAltName"},
    "2.5.29.30": {"const": "util.NameConstOID", "go_field": "NameConstraints"},

    # DN 属性 OID
    "2.5.4.3": {"const": "util.CommonNameOID", "go_field": "CommonName"},
    "2.5.4.10": {"const": "util.OrganizationNameOID", "go_field": "Organization"},
    "2.5.4.11": {"const": "util.OrganizationalUnitNameOID", "go_field": "OrganizationalUnit"},
    "2.5.4.6": {"const": "util.CountryNameOID", "go_field": "Country"},
    "2.5.4.8": {"const": "util.StateOrProvinceNameOID", "go_field": "Province"},
    "2.5.4.7": {"const": "util.LocalityNameOID", "go_field": "Locality"},

    # CABF 特殊 OID
    "2.23.140.1.2.1": {"const": "util.CabfExtensionOrganizationIdentifier", "go_field": "CABForumOrgIdExt"},
    "1.3.6.1.4.1.11129.2.4.2": {"const": "util.CtPoisonOID", "go_field": "SCTList"},
}


# ============================================================================
# 4. requires_operation 到 Go 辅助函数的映射
# ============================================================================

@dataclass
class OperationMapping:
    """操作到 Go 代码的映射"""
    go_helper: Optional[str]  # Go 辅助函数名
    go_import: Optional[str]  # 需要的 Go import
    description: str
    is_runtime_only: bool  # True = 只能在运行时检查，不可 lint


REQUIRES_OPERATION_MAP: Dict[str, OperationMapping] = {
    # RFC 4518 字符串准备
    "StringPrep": OperationMapping(
        go_helper=None,  # 无现成实现
        go_import=None,
        description="RFC 4518 六步字符串准备算法",
        is_runtime_only=True,  # 比较时检查，不可 lint
    ),

    # RFC 3490 ToASCII
    "ToASCII": OperationMapping(
        go_helper="golang.org/x/net/idna.ToASCII",
        go_import="golang.org/x/net/idna",
        description="将国际化域名转换为 ACE 格式",
        is_runtime_only=False,  # 可以在证书时检查 ACE 格式
    ),

    # RFC 3490 ToUnicode
    "ToUnicode": OperationMapping(
        go_helper="golang.org/x/net/idna.ToUnicode",
        go_import="golang.org/x/net/idna",
        description="将 ACE 格式转换回 Unicode",
        is_runtime_only=True,  # 比较时使用
    ),

    # Punycode 编码验证
    "Punycode": OperationMapping(
        go_helper="util.IsValidPunycode",  # 假设 zlint/util 有此函数
        go_import=None,
        description="验证 Punycode 编码格式",
        is_runtime_only=False,
    ),

    # DNS 标签长度检查
    "DNSLabelLengthCheck": OperationMapping(
        go_helper="util.CheckDNSLabelLength",
        go_import=None,
        description="检查 DNS 标签不超过 63 字符",
        is_runtime_only=False,
    ),

    # UTF-8/PrintableString 编码检查
    "EncodingCheck": OperationMapping(
        go_helper="util.IsValidDirectoryStringEncoding",
        go_import=None,
        description="检查 DirectoryString 编码类型",
        is_runtime_only=False,
    ),
}


# ============================================================================
# 5. Lintability 快速判断映射
# ============================================================================

# 不可 lint 的 assertion_subject 值
NON_LINTABLE_ASSERTION_SUBJECTS = {
    "Implementation",  # 实现行为，不是证书属性
    "CA",              # CA 行为
    "RelyingParty",    # RP 行为
}

# 不可 lint 的 enforcement_phase 值
NON_LINTABLE_ENFORCEMENT_PHASES = {
    "Comparison",   # 运行时比较
    "Validation",   # 证书链验证
    "Processing",   # 运行时处理
}

# 可 lint 的组合
LINTABLE_COMBINATIONS = {
    # (assertion_subject, enforcement_phase): lintable
    ("Certificate", "Encoding"): True,
    ("Certificate", None): True,  # 默认 encoding
    ("Implementation", "Encoding"): False,  # 即使是 encoding，实现行为也不可 lint
}


def is_lintable_from_ir(ir_data: Dict[str, Any]) -> Tuple[bool, Optional[str]]:
    """
    从 IR 数据快速判断是否可 lint

    Args:
        ir_data: IR 字典，包含 assertion_subject, enforcement_phase 等字段

    Returns:
        (is_lintable, reason)
    """
    assertion_subject = ir_data.get("assertion_subject", "Certificate")
    enforcement_phase = ir_data.get("enforcement_phase")

    # 检查 assertion_subject
    if assertion_subject in NON_LINTABLE_ASSERTION_SUBJECTS:
        return False, f"Assertion subject is {assertion_subject}, not Certificate"

    # 检查 enforcement_phase
    if enforcement_phase in NON_LINTABLE_ENFORCEMENT_PHASES:
        return False, f"Enforcement phase is {enforcement_phase}, requires runtime behavior"

    # 检查 requires_operation
    requires_op = ir_data.get("requires_operation")
    if requires_op:
        op_name = requires_op.get("operation", "")
        if op_name in REQUIRES_OPERATION_MAP:
            mapping = REQUIRES_OPERATION_MAP[op_name]
            if mapping.is_runtime_only:
                return False, f"Requires runtime operation: {op_name}"

    return True, None


# ============================================================================
# 6. 便捷函数
# ============================================================================

def get_extension_oid(subject: str) -> Optional[str]:
    """
    从 subject 字段获取扩展 OID

    Args:
        subject: IR 的 subject 字段，如 "extensions.subjectAltName.dNSName"

    Returns:
        OID 字符串，如 "2.5.29.17"，找不到返回 None
    """
    # 尝试精确匹配
    if subject in SUBJECT_TO_EXTENSION_OID:
        return SUBJECT_TO_EXTENSION_OID[subject]

    # 尝试不区分大小写匹配
    subject_lower = subject.lower()
    for key, oid in SUBJECT_TO_EXTENSION_OID.items():
        if key.lower() == subject_lower:
            return oid

    # 尝试部分匹配（处理 extensions.xxx 前缀）
    if subject.startswith("extensions."):
        short_name = subject.split(".")[-1]
        for key, oid in SUBJECT_TO_EXTENSION_OID.items():
            if key.lower().endswith(short_name.lower()):
                return oid

    return None


def get_dn_attribute_oids(subject: str) -> List[str]:
    """
    从 subject 字段获取 DN 属性 OID 列表

    Args:
        subject: IR 的 subject 字段，如 "DirectoryString" 或 "subject.Names"

    Returns:
        OID 列表，如 ["2.5.4.3", "2.5.4.10", "2.5.4.11"]
    """
    subject_lower = subject.lower()

    # 特殊标记：返回所有标准 DN 属性 OID
    if "directorystring" in subject_lower or "subject.names" in subject_lower:
        return STANDARD_DN_ATTRIBUTE_OIDS.copy()

    # 尝试精确匹配单个属性
    if subject in DN_ATTRIBUTE_OIDS:
        oid = DN_ATTRIBUTE_OIDS[subject]
        return [oid] if oid else []

    # 尝试从 subject 路径提取属性名
    # 如 "subject.commonName" -> "commonName"
    if "." in subject:
        attr_name = subject.split(".")[-1]
        if attr_name in DN_ATTRIBUTE_OIDS:
            oid = DN_ATTRIBUTE_OIDS[attr_name]
            return [oid] if oid else []

    return []


def get_zlint_const(oid: str) -> Optional[str]:
    """
    从 OID 获取 zlint util 常量名

    Args:
        oid: OID 字符串

    Returns:
        zlint 常量名，如 "util.SubjectAltNameOID"
    """
    if oid in OID_TO_ZLINT_CONST:
        return OID_TO_ZLINT_CONST[oid].get("const")
    return None


def get_go_field(oid: str) -> Optional[str]:
    """
    从 OID 获取 Go x509.Certificate 字段名

    Args:
        oid: OID 字符串

    Returns:
        Go 字段名，如 "DNSNames"
    """
    if oid in OID_TO_ZLINT_CONST:
        return OID_TO_ZLINT_CONST[oid].get("go_field")
    return None


def get_operation_helper(operation_name: str) -> Optional[OperationMapping]:
    """
    从 requires_operation.operation 获取 Go 辅助函数信息

    Args:
        operation_name: 操作名，如 "StringPrep" 或 "ToASCII"

    Returns:
        OperationMapping 或 None
    """
    return REQUIRES_OPERATION_MAP.get(operation_name)


# ============================================================================
# 7. 调试/测试函数
# ============================================================================

def debug_ir_mapping(ir_data: Dict[str, Any]) -> Dict[str, Any]:
    """
    调试：显示 IR 字段到 zlint 映射的结果

    Args:
        ir_data: IR 字典

    Returns:
        映射结果字典
    """
    subject = ir_data.get("subject", "")
    assertion_subject = ir_data.get("assertion_subject", "Certificate")
    enforcement_phase = ir_data.get("enforcement_phase")
    requires_op = ir_data.get("requires_operation")

    result = {
        "input": {
            "subject": subject,
            "assertion_subject": assertion_subject,
            "enforcement_phase": enforcement_phase,
            "requires_operation": requires_op,
        },
        "mappings": {
            "extension_oid": get_extension_oid(subject),
            "dn_attribute_oids": get_dn_attribute_oids(subject),
        },
        "lintability": {},
    }

    # 获取 zlint 常量
    ext_oid = result["mappings"]["extension_oid"]
    if ext_oid:
        result["mappings"]["zlint_const"] = get_zlint_const(ext_oid)
        result["mappings"]["go_field"] = get_go_field(ext_oid)

    # 获取操作辅助函数
    if requires_op:
        op_name = requires_op.get("operation", "")
        op_mapping = get_operation_helper(op_name)
        if op_mapping:
            result["mappings"]["operation_helper"] = {
                "go_helper": op_mapping.go_helper,
                "is_runtime_only": op_mapping.is_runtime_only,
            }

    # 判断 lintability
    is_lintable, reason = is_lintable_from_ir(ir_data)
    result["lintability"] = {
        "is_lintable": is_lintable,
        "reason": reason,
    }

    return result


if __name__ == "__main__":
    # 测试示例
    test_ir = {
        "subject": "DirectoryString",
        "assertion_subject": "Implementation",
        "enforcement_phase": "Comparison",
        "requires_operation": {"operation": "StringPrep", "defined_in": "RFC4518"},
    }

    result = debug_ir_mapping(test_ir)
    import json
    print(json.dumps(result, indent=2))
