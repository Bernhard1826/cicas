"""
规则复杂度评估器
根据规则文本和初步提取结果，评估规则的复杂程度
用于决定使用哪种提取策略
"""
import re
from typing import Dict, Any, Literal
from app.core.logging_config import app_logger


ComplexityLevel = Literal['simple', 'medium', 'complex']


class RuleComplexityAssessor:
    """评估规则复杂度，决定使用哪种提取策略"""

    # 代词模式
    PRONOUN_PATTERN = re.compile(
        r'\b(it|this|that|these|those|they|them|their)\b',
        re.IGNORECASE
    )

    # 条件逻辑模式
    CONDITIONAL_PATTERN = re.compile(
        r'\b(if|when|unless|provided that|in case|where|whenever)\b',
        re.IGNORECASE
    )

    # 复杂连接词模式
    CONJUNCTION_PATTERN = re.compile(
        r'\b(and|or|but|however|while|whereas)\b',
        re.IGNORECASE
    )

    # 否定词模式
    NEGATION_PATTERN = re.compile(
        r'\b(not|no|never|neither|nor|except|excluding)\b',
        re.IGNORECASE
    )

    # 模糊描述词
    VAGUE_TERMS = re.compile(
        r'\b(appropriate|reasonable|suitable|adequate|sufficient|proper|'
        r'合理|适当|恰当|充分)\b',
        re.IGNORECASE
    )

    # 嵌套结构（括号）
    NESTED_STRUCTURE_PATTERN = re.compile(r'\([^)]+\([^)]+\)\)')

    def assess_complexity(
        self,
        rule_text: str,
        regex_result: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        评估规则复杂度

        Args:
            rule_text: 规则文本
            regex_result: 正则提取的初步结果

        Returns:
            {
                'complexity': 'simple' | 'medium' | 'complex',
                'score': int,  # 复杂度分数 (0-10+)
                'reasons': List[str],  # 复杂度原因
                'needs_rag': bool,  # 是否需要RAG辅助
                'needs_full_llm': bool  # 是否需要完整LLM处理
            }
        """
        score = 0
        reasons = []

        # 因素1: 正则提取置信度低 (权重最高)
        if confidence < 0.3:
            score += 4
            reasons.append(f"Very low extraction confidence ({confidence:.2f})")
        elif confidence < 0.5:
            score += 3
            reasons.append(f"Low extraction confidence ({confidence:.2f})")
        elif confidence < 0.7:
            score += 1
            reasons.append(f"Medium extraction confidence ({confidence:.2f})")

        # 因素2: 字段识别失败
        if not regex_result.get('affected_field'):
            score += 3
            reasons.append("Failed to identify affected field")

        # 因素3: 操作类型识别失败
        if not regex_result.get('operation'):
            score += 2
            reasons.append("Failed to identify operation type")

        # 因素4: 包含代词（需要上下文理解）
        if self.PRONOUN_PATTERN.search(rule_text):
            score += 2
            reasons.append("Contains pronouns (needs context)")

        # 因素5: 包含条件逻辑
        conditional_matches = len(self.CONDITIONAL_PATTERN.findall(rule_text))
        if conditional_matches >= 2:
            score += 3
            reasons.append(f"Multiple conditional clauses ({conditional_matches})")
        elif conditional_matches == 1:
            score += 1
            reasons.append("Contains conditional logic")

        # 因素6: 复杂连接词（AND/OR逻辑）
        conjunction_matches = len(self.CONJUNCTION_PATTERN.findall(rule_text))
        if conjunction_matches >= 3:
            score += 2
            reasons.append(f"Multiple conjunctions ({conjunction_matches})")
        elif conjunction_matches >= 2:
            score += 1
            reasons.append("Contains multiple clauses")

        # 因素7: 否定词（容易误判）
        negation_matches = len(self.NEGATION_PATTERN.findall(rule_text))
        if negation_matches >= 2:
            score += 2
            reasons.append(f"Multiple negations ({negation_matches})")
        elif negation_matches == 1:
            score += 1
            reasons.append("Contains negation")

        # 因素8: 模糊描述词
        if self.VAGUE_TERMS.search(rule_text):
            score += 1
            reasons.append("Contains vague terms")

        # 因素9: 嵌套结构
        if self.NESTED_STRUCTURE_PATTERN.search(rule_text):
            score += 2
            reasons.append("Contains nested structure")

        # 因素10: 规则长度（过长通常更复杂）
        if len(rule_text) > 200:
            score += 1
            reasons.append(f"Long rule text ({len(rule_text)} chars)")

        # 因素11: 期望值缺失但操作类型需要
        operation = regex_result.get('operation')
        expected_value = regex_result.get('expected_value')
        if operation in ['minimum_value', 'maximum_value', 'must_equal'] and not expected_value:
            score += 2
            reasons.append(f"Operation '{operation}' requires value but none extracted")

        # 决定复杂度级别（调整后的阈值）
        # 优化：提高LLM阈值到8，减少LLM调用次数以提升速度
        if score >= 8:
            complexity = 'complex'
            needs_rag = True
            needs_full_llm = True
        elif score >= 3:
            complexity = 'medium'
            needs_rag = True
            needs_full_llm = False
        else:
            complexity = 'simple'
            needs_rag = False
            needs_full_llm = False

        result = {
            'complexity': complexity,
            'score': score,
            'reasons': reasons,
            'needs_rag': needs_rag,
            'needs_full_llm': needs_full_llm,
            'confidence': confidence
        }

        # 记录日志
        if complexity != 'simple':
            app_logger.info(
                f"Complex rule detected [{complexity}, score={score}]: "
                f"{rule_text[:80]}... Reasons: {', '.join(reasons[:3])}"
            )

        return result

    def get_complexity_stats(self, assessment: Dict[str, Any]) -> str:
        """获取复杂度统计的友好文本"""
        complexity = assessment['complexity']
        score = assessment['score']
        reasons = assessment['reasons']

        return (
            f"Complexity: {complexity.upper()} (score: {score})\n"
            f"Reasons: {', '.join(reasons)}"
        )
