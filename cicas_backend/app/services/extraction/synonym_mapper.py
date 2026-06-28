"""
同义词映射器 - 用于搜索查询扩展

将常见的别名映射到规范的术语，增强搜索效果。
"""

# X.509 Name Type 别名映射表
NAME_TYPE_SYNONYMS = {
    "dNSName": {
        "canonical": "dNSName",
        "aliases": [
            "dNSName",
            "hostname",
            "DNS-ID",
            "DNS name",
            "domain name",
            "FQDN",
            "fully qualified domain name"
        ]
    },
    "rfc822Name": {
        "canonical": "rfc822Name",
        "aliases": [
            "rfc822Name",
            "email",
            "email address",
            "e-mail",
            "mail address",
            "RFC822"
        ]
    },
    "iPAddress": {
        "canonical": "iPAddress",
        "aliases": [
            "iPAddress",
            "IP address",
            "IP",
            "IP addr",
            "internet protocol address"
        ]
    },
    "uniformResourceIdentifier": {
        "canonical": "uniformResourceIdentifier",
        "aliases": [
            "uniformResourceIdentifier",
            "URI",
            "URL",
            "uniform resource identifier",
            "web address"
        ]
    },
    "directoryName": {
        "canonical": "directoryName",
        "aliases": [
            "directoryName",
            "DN",
            "distinguished name",
            "directory name"
        ]
    }
}


def get_canonical_term(query: str) -> str:
    """
    将查询别名映射到规范术语

    Args:
        query: 用户输入的查询词

    Returns:
        规范术语，如果找不到映射则返回 None

    Example:
        >>> get_canonical_term("hostname")
        'dNSName'
        >>> get_canonical_term("email")
        'rfc822Name'
        >>> get_canonical_term("unknown")
        None
    """
    import re
    # 标准化：小写 + 去除首尾空格 + 标准化内部空格为单个空格
    query_normalized = re.sub(r'\s+', ' ', query.lower().strip())

    for canonical_data in NAME_TYPE_SYNONYMS.values():
        canonical = canonical_data["canonical"]
        aliases = canonical_data["aliases"]

        # 检查是否匹配任何别名（标准化后比较）
        for alias in aliases:
            alias_normalized = re.sub(r'\s+', ' ', alias.lower())
            if query_normalized == alias_normalized:
                return canonical

    return None


def expand_query_with_synonyms(query: str) -> str:
    """
    使用同义词扩展查询（双向扩展）

    使用 || 作为分隔符来保持短语的完整性

    Args:
        query: 原始查询词

    Returns:
        扩展后的查询，使用 || 分隔不同的同义词短语

    Example:
        >>> expand_query_with_synonyms("hostname")
        'hostname||dNSName||DNS name||domain name'
        >>> expand_query_with_synonyms("dNSName")
        'dNSName||DNS name||domain name'
        >>> expand_query_with_synonyms("email")
        'email||rfc822Name||email address||mail address'
    """
    import re
    # 标准化：小写 + 去除首尾空格 + 标准化内部空格
    query_normalized = re.sub(r'\s+', ' ', query.lower().strip())

    # 尝试找到规范术语
    canonical = get_canonical_term(query)

    # 如果查询本身就是规范术语，找到其所有别名
    if not canonical:
        for canonical_data in NAME_TYPE_SYNONYMS.values():
            canonical_normalized = re.sub(r'\s+', ' ', canonical_data["canonical"].lower())
            if query_normalized == canonical_normalized:
                canonical = canonical_data["canonical"]
                break

    if canonical:
        # 找到对应的别名组
        canonical_data = NAME_TYPE_SYNONYMS.get(canonical)
        if canonical_data:
            # 只添加常用的短语别名（2个词以上），避免单个词造成误匹配
            aliases = canonical_data["aliases"]
            # 过滤：只保留包含空格的别名（短语）和规范术语本身
            phrase_aliases = [a for a in aliases if ' ' in a or a == canonical]

            # 如果没有短语别名，至少包含规范术语
            if not phrase_aliases:
                phrase_aliases = [canonical]

            # 组合：原查询 + 规范术语（如果不同） + 短语别名
            terms = [query]
            canonical_normalized = re.sub(r'\s+', ' ', canonical.lower())
            if canonical_normalized != query_normalized:
                terms.append(canonical)

            # 添加其他短语别名（排除已有的，标准化后比较）
            terms_normalized = [re.sub(r'\s+', ' ', t.lower()) for t in terms]
            for alias in phrase_aliases:
                alias_normalized = re.sub(r'\s+', ' ', alias.lower())
                if alias_normalized not in terms_normalized:
                    terms.append(alias)

            # 使用 || 作为分隔符
            return '||'.join(terms)

    return query


# 测试
if __name__ == "__main__":
    test_cases = [
        "hostname",
        "dNSName",
        "email",
        "IP address",
        "URI",
        "certificate",
        "validity period"
    ]

    print("同义词扩展测试:\n")
    for test in test_cases:
        expanded = expand_query_with_synonyms(test)
        canonical = get_canonical_term(test)
        print(f"  '{test}' -> '{expanded}' (canonical: {canonical})")
