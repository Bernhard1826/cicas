"""
RFC文本预处理 - 清理页脚和格式问题

在规则提取之前，清理RFC文档中的：
1. 页脚信息（作者名、页码、标准轨道标记）
2. 页眉信息（RFC编号、日期）
3. 分页符
"""
import re

def clean_rfc_text(text: str) -> str:
    """
    清理RFC文本中的页脚、页眉和格式问题

    Args:
        text: 原始RFC文本

    Returns:
        清理后的文本
    """
    lines = text.split('\n')
    cleaned_lines = []

    # 页脚模式
    footer_patterns = [
        r'^[A-Z][a-z]+,\s+et\s+al\.?\s+Standards\s+Track\s+\[Page\s+\d+\]',  # Cooper, et al.              Standards Track                    [Page 97]
        r'^[A-Z][a-z]+,\s+et\s+al\.',  # Cooper, et al.
        r'^\s*Standards\s+Track\s+\[Page\s+\d+\]',  # Standards Track                    [Page 97]
        r'^\[Page\s+\d+\]',  # [Page 97]
    ]

    # 页眉模式
    # 注意：只匹配真正的页眉，不匹配内容行如 "RFC 3490 before storage..."
    header_patterns = [
        r'^RFC\s+\d+\s+.*\d{4}$',  # RFC 5280            PKIX Certificate and CRL Profile            May 2008
        r'^RFC\s+\d+\s*$',  # RFC 5280 (只有RFC编号，没有其他内容)
    ]

    # 分页符
    form_feed = '\f'

    for line in lines:
        # 跳过分页符
        if form_feed in line:
            continue

        # 跳过空行
        if not line.strip():
            cleaned_lines.append(line)
            continue

        # 检查是否为页脚
        is_footer = False
        for pattern in footer_patterns:
            if re.match(pattern, line.strip()):
                is_footer = True
                break

        if is_footer:
            continue

        # 检查是否为页眉
        is_header = False
        for pattern in header_patterns:
            if re.match(pattern, line.strip()):
                is_header = True
                break

        if is_header:
            continue

        # 保留这一行
        cleaned_lines.append(line)

    return '\n'.join(cleaned_lines)


def clean_sentence_footer(sentence: str) -> str:
    """
    清理单个句子中的页脚信息

    这是一个后备方案，用于清理已经混入句子的页脚信息

    Args:
        sentence: 原始句子

    Returns:
        清理后的句子
    """
    # 移除常见的页脚模式
    patterns = [
        r'\s+Cooper,\s+et\s+al\.?',
        r'\s+Standards\s+Track',
        r'\s+\[Page\s+\d+\]',
        r'\s+RFC\s+\d+',
    ]

    cleaned = sentence
    for pattern in patterns:
        cleaned = re.sub(pattern, '', cleaned)

    return cleaned.strip()


if __name__ == '__main__':
    # 测试
    test_text = """Some normative text here.

Cooper, et al.              Standards Track                    [Page 97]

RFC 5280            PKIX Certificate and CRL Profile            May 2008


More normative text here."""

    print("Original:")
    print(test_text)
    print("\n" + "="*80 + "\n")
    print("Cleaned:")
    print(clean_rfc_text(test_text))
