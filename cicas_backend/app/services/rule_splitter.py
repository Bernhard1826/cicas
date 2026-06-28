"""
规则拆分优化器
用于识别和处理列表型规则、复合规则等
"""
import re
from typing import Dict, List, Any, Optional


class RuleSplitter:
    """规则拆分优化器"""

    def __init__(self):
        self.list_indicators = [
            '•', '*', '-', '–',  # Bullet points
            r'\d+\.',  # Numbered lists
            r'\([a-z]\)',  # (a), (b), (c)
            r'\([0-9]+\)',  # (1), (2), (3)
        ]

        self.timeline_keywords = [
            'effective', 'starting', 'beginning', 'from', 'until',
            'phase', 'timeline', 'deadline', 'by'
        ]

    def detect_list_rule(self, text: str) -> bool:
        """
        检测文本是否是列表型规则

        Args:
            text: 规则文本

        Returns:
            True if text appears to be a list-based rule
        """
        # 特征1: 包含多个bullet points或编号
        bullet_count = sum(text.count(indicator) for indicator in ['•', '*', '-'])

        # 特征2: 包含时间线关键词
        text_lower = text.lower()
        has_timeline = any(kw in text_lower for kw in self.timeline_keywords)

        # 特征3: 包含多个编号项
        has_numbering = len(re.findall(r'\n\s*\d+\.', text)) >= 2

        # 特征4: 包含字母编号
        has_letter_numbering = len(re.findall(r'\n\s*\([a-z]\)', text)) >= 2

        # 判断
        is_list = (
            bullet_count >= 2 or
            (has_timeline and bullet_count >= 1) or
            has_numbering or
            has_letter_numbering
        )

        return is_list

    def should_keep_as_composite(self, text: str) -> bool:
        """
        判断是否应该保持为复合规则而不拆分

        Args:
            text: 规则文本

        Returns:
            True if rule should be kept as a single composite rule
        """
        # 1. 如果是列表型规则
        if self.detect_list_rule(text):
            return True

        # 2. 如果包含"以下所有"、"所有以下条件"等
        collective_patterns = [
            r'all of the following',
            r'all\s+of\s+these',
            r'both.*and',
            r'either.*or',
            r'以下所有',
            r'所有以下',
        ]

        for pattern in collective_patterns:
            if re.search(pattern, text, re.IGNORECASE):
                return True

        # 3. 如果文本过短（可能已经是最小单元）
        if len(text.split()) < 10:
            return False

        return False

    def extract_list_items(self, text: str) -> List[Dict[str, Any]]:
        """
        从列表型规则中提取各个项目

        Args:
            text: 列表规则文本

        Returns:
            List of extracted items with their properties
        """
        items = []

        # 提取前言（列表之前的引导文字）
        preamble = self._extract_preamble(text)

        # 按不同的列表模式提取
        # 模式1: Bullet points
        bullet_items = re.split(r'\n\s*[•*\-–]\s+', text)
        if len(bullet_items) > 1:
            for i, item in enumerate(bullet_items[1:], 1):  # Skip preamble
                items.append({
                    'index': i,
                    'text': item.strip(),
                    'preamble': preamble,
                    'type': 'bullet'
                })
            return items

        # 模式2: Numbered lists
        numbered_items = re.split(r'\n\s*\d+\.\s+', text)
        if len(numbered_items) > 1:
            for i, item in enumerate(numbered_items[1:], 1):
                items.append({
                    'index': i,
                    'text': item.strip(),
                    'preamble': preamble,
                    'type': 'numbered'
                })
            return items

        # 模式3: Letter enumeration
        letter_items = re.split(r'\n\s*\([a-z]\)\s+', text)
        if len(letter_items) > 1:
            for i, item in enumerate(letter_items[1:], 1):
                items.append({
                    'index': i,
                    'text': item.strip(),
                    'preamble': preamble,
                    'type': 'letter'
                })
            return items

        return items

    def _extract_preamble(self, text: str) -> str:
        """提取列表前的引导文字"""
        # 找到第一个列表标记之前的内容
        patterns = [
            r'(.*?)\n\s*[•*\-–]\s+',
            r'(.*?)\n\s*\d+\.\s+',
            r'(.*?)\n\s*\([a-z]\)\s+',
        ]

        for pattern in patterns:
            match = re.search(pattern, text, re.DOTALL)
            if match:
                return match.group(1).strip()

        # 如果没有找到，返回前两句
        sentences = text.split('.')
        if len(sentences) >= 2:
            return '. '.join(sentences[:2]) + '.'

        return ""

    def optimize_rule_extraction(self, rule_dict: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        优化规则提取：决定是否拆分或保持为复合规则

        Args:
            rule_dict: 单条规则字典

        Returns:
            List of optimized rules (may be single item or multiple items)
        """
        text = rule_dict.get('text', '')

        # 判断是否应该保持为复合规则
        if self.should_keep_as_composite(text):
            # 保持为复合规则
            rule_dict['modality'] = 'composite_rule'
            rule_dict['operation'] = 'composite'
            rule_dict['is_list_rule'] = True
            return [rule_dict]

        # 检测是否可以拆分为子规则
        items = self.extract_list_items(text)

        if items:
            # 创建一个父规则和多个子规则
            parent_rule = rule_dict.copy()
            parent_rule['modality'] = 'composite_rule'
            parent_rule['operation'] = 'composite'
            parent_rule['is_parent_rule'] = True

            result = [parent_rule]

            # 为每个项目创建子规则
            for item in items:
                child_rule = rule_dict.copy()
                child_rule['text'] = f"{item['preamble']} {item['text']}"
                child_rule['is_split_from_parent'] = True
                child_rule['split_index'] = item['index']
                result.append(child_rule)

            return result

        # 无法拆分，返回原规则
        return [rule_dict]


def optimize_rules(rules: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    批量优化规则列表

    Args:
        rules: 规则列表

    Returns:
        Optimized rules list
    """
    splitter = RuleSplitter()
    optimized_rules = []

    for rule in rules:
        optimized = splitter.optimize_rule_extraction(rule)
        optimized_rules.extend(optimized)

    return optimized_rules


if __name__ == "__main__":
    # 测试用例
    splitter = RuleSplitter()

    # 测试1: 列表型规则
    test_rule_1 = {
        'text': '''Phased Implementation Timeline:
        • Effective September 15, 2024, the CA SHOULD implement Multi-Perspective Issuance Corroboration using at least two (2) remote Network Perspectives
        • Effective March 15, 2025, the CA MUST implement Multi-Perspective Issuance Corroboration using at least two (2) remote Network Perspectives
        ''',
        'modality': 'behavioral_rule',
        'affected_field': 'CA',
        'operation': 'behavior'
    }

    print("Test 1: List Rule")
    is_list = splitter.detect_list_rule(test_rule_1['text'])
    print(f"  Is list: {is_list}")

    should_keep = splitter.should_keep_as_composite(test_rule_1['text'])
    print(f"  Should keep as composite: {should_keep}")

    items = splitter.extract_list_items(test_rule_1['text'])
    print(f"  Extracted items: {len(items)}")
    for item in items:
        print(f"    {item['index']}: {item['text'][:60]}...")

    print()

    # 测试2: 普通规则
    test_rule_2 = {
        'text': 'The CA MUST validate the domain name before issuing the certificate.',
        'modality': 'behavioral_rule',
        'affected_field': 'CA',
        'operation': 'behavior'
    }

    print("Test 2: Normal Rule")
    is_list_2 = splitter.detect_list_rule(test_rule_2['text'])
    print(f"  Is list: {is_list_2}")

    optimized_2 = splitter.optimize_rule_extraction(test_rule_2)
    print(f"  Optimized count: {len(optimized_2)}")
