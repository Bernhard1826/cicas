"""
PKI 领域术语同义词映射
用于语义搜索的查询扩展，提升召回率
"""

PKI_SYNONYMS = {
    # DNS/域名相关
    "dnsname": ["dNSName", "DNS name", "hostname", "domain name", "FQDN", "fully qualified domain name"],
    "hostname": ["hostname", "host name", "dNSName", "DNS name", "domain name"],
    "domain": ["domain name", "dNSName", "DNS name", "FQDN"],
    "fqdn": ["FQDN", "fully qualified domain name", "domain name", "dNSName"],

    # IP地址相关
    "ipaddress": ["IP address", "iPAddress", "IP addr", "internet protocol address"],
    "ipv4": ["IPv4", "IPv4 address", "IP version 4"],
    "ipv6": ["IPv6", "IPv6 address", "IP version 6"],

    # 证书扩展相关
    "san": ["subjectAltName", "SAN", "subject alternative name", "subject alt name"],
    "subjectaltname": ["subjectAltName", "SAN", "subject alternative name"],
    "keyusage": ["keyUsage", "key usage", "key usage extension"],
    "basicconstraints": ["basicConstraints", "basic constraints", "CA flag"],
    "extendedkeyusage": ["extendedKeyUsage", "EKU", "extended key usage"],
    "nameconstraints": ["nameConstraints", "name constraints", "permitted subtrees"],

    # 密钥相关
    "publickey": ["public key", "subject public key", "SubjectPublicKeyInfo"],
    "privatekey": ["private key", "signing key"],
    "rsa": ["RSA", "RSA encryption", "Rivest-Shamir-Adleman"],
    "ecc": ["ECC", "elliptic curve", "ECDSA", "EC"],
    "ecdsa": ["ECDSA", "elliptic curve digital signature", "EC DSA"],

    # 有效期相关
    "validity": ["validity", "validity period", "notBefore", "notAfter", "expiration"],
    "expiration": ["expiration", "expiry", "validity period", "notAfter"],
    "notbefore": ["notBefore", "validity start", "valid from"],
    "notafter": ["notAfter", "validity end", "expiration", "valid until"],

    # CA相关
    "ca": ["CA", "certificate authority", "certification authority", "issuer"],
    "issuer": ["issuer", "CA", "certificate authority", "issuing CA"],
    "rootca": ["root CA", "trust anchor", "root certificate authority"],
    "subordinateca": ["subordinate CA", "intermediate CA", "issuing CA"],

    # 主题/名称相关
    "subject": ["subject", "subject DN", "subject distinguished name"],
    "commonname": ["common name", "CN", "commonName"],
    "organization": ["organization", "O", "organizationName"],
    "organizationalunit": ["organizational unit", "OU", "organizationalUnitName"],

    # 签名相关
    "signature": ["signature", "digital signature", "signatureAlgorithm"],
    "hash": ["hash", "digest", "message digest", "checksum"],
    "sha256": ["SHA-256", "SHA256", "SHA2-256"],
    "sha1": ["SHA-1", "SHA1"],

    # 其他
    "serial": ["serial number", "serialNumber", "certificate serial"],
    "crl": ["CRL", "certificate revocation list", "revocation list"],
    "ocsp": ["OCSP", "online certificate status protocol", "certificate status"],
}

def expand_query(query: str, max_synonyms: int = 3) -> list:
    """
    扩展查询词为同义词列表

    Args:
        query: 原始查询词
        max_synonyms: 最多返回的同义词数量（避免扩展过多）

    Returns:
        扩展后的查询词列表（包含原查询）
    """
    query_lower = query.lower().strip()

    # 移除空格和特殊字符进行匹配
    normalized_query = query_lower.replace(" ", "").replace("-", "").replace("_", "")

    # 查找匹配的同义词组
    for key, synonyms in PKI_SYNONYMS.items():
        # 检查是否匹配键或同义词
        if normalized_query == key or query_lower in [s.lower() for s in synonyms]:
            # 限制返回数量，避免查询过多
            return synonyms[:max_synonyms]

    # 如果没有匹配，返回原查询
    return [query]

def get_expanded_terms(query: str) -> str:
    """
    获取扩展后的术语，用于提示用户

    Args:
        query: 原始查询词

    Returns:
        格式化的同义词字符串
    """
    expanded = expand_query(query, max_synonyms=5)
    if len(expanded) > 1:
        return " / ".join(expanded)
    return query
