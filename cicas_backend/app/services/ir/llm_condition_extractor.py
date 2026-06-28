"""
LLM条件提取器
使用LLM从规则文本中提取结构化条件
"""
import json
import re
from typing import Optional
from app.services.ir.condition_set import (
    ConditionSet, FieldCondition, SetCondition, RangeCondition, LogicalCondition
)
from app.core.logging_config import app_logger


class LLMConditionExtractor:
    """使用LLM提取结构化条件"""

    # Few-shot示例
    FEW_SHOT_EXAMPLES = """
示例1：
输入："IF the certificate is a CA certificate THEN keyUsage MUST contain keyCertSign"
输出：
{
  "conditions": [
    {"type": "field", "field": "c.IsCA", "operator": "==", "value": true}
  ],
  "logic": "AND"
}

示例2：
输入："WHEN the validity period exceeds 825 days"
输出：
{
  "conditions": [
    {"type": "range", "field": "validity_days", "operator": ">", "value": 825, "unit": "days"}
  ],
  "logic": "AND"
}

示例3：
输入："IF cA=TRUE AND pathLenConstraint >= 2"
输出：
{
  "conditions": [
    {"type": "field", "field": "c.IsCA", "operator": "==", "value": true},
    {"type": "range", "field": "c.MaxPathLen", "operator": ">=", "value": 2}
  ],
  "logic": "AND"
}
"""

    EXTRACTION_PROMPT_TEMPLATE = """你是PKI证书规则专家。从规则文本中提取**前提条件**（IF/WHEN/UNLESS中的条件部分）。

{few_shot_examples}

支持的证书字段：
- c.IsCA (布尔)
- c.Subject.CommonName (字符串)
- c.Subject.Organization (字符串)
- c.KeyUsage (整数，位掩码)
- c.ExtKeyUsage (字符串数组)
- c.BasicConstraintsValid (布尔)
- c.MaxPathLen (整数)
- c.NotBefore, c.NotAfter (时间)
- c.DNSNames, c.IPAddresses (数组)
- validity_days (整数，证书有效期天数)

支持的操作符：
- 字段条件: ==, !=, >, <, >=, <=, EXISTS, NOT_EXISTS
- 集合条件: IN, NOT_IN, CONTAINS, NOT_CONTAINS
- 范围条件: >, <, >=, <=

输出JSON格式：
{{
  "conditions": [
    {{"type": "field|set|range", "field": "...", "operator": "...", "value": ...}}
  ],
  "logic": "AND|OR"
}}

**重要**：
1. 只提取**条件部分**，不要提取结果部分（THEN后面的内容）
2. 如果没有明确的条件（如"keyUsage MUST be present"），返回空数组
3. 布尔值用true/false，不要用字符串
4. 字段名必须是上面列出的标准字段

规则文本：
{rule_text}

请提取条件（JSON格式）：
"""

    def __init__(self, llm_client=None):
        """
        初始化提取器

        Args:
            llm_client: LLM客户端，如果为None则使用fallback逻辑
        """
        self.llm_client = llm_client

    def extract(self, rule_text: str) -> ConditionSet:
        """
        从规则文本提取条件

        Args:
            rule_text: 规则文本

        Returns:
            ConditionSet对象
        """
        try:
            # 预处理：检测是否包含条件关键词
            if not self._has_condition_keywords(rule_text):
                app_logger.info("规则不包含条件关键词，返回空条件集")
                return ConditionSet(conditions=[])

            # 尝试LLM提取
            if self.llm_client:
                return self._extract_with_llm(rule_text)
            else:
                # Fallback: 使用regex启发式
                app_logger.warning("LLM客户端未配置，使用fallback提取")
                return self._extract_with_regex(rule_text)

        except Exception as e:
            app_logger.error(f"条件提取失败: {e}", exc_info=True)
            return ConditionSet(conditions=[])

    def _has_condition_keywords(self, text: str) -> bool:
        """检测是否包含条件关键词"""
        text_lower = text.lower()
        keywords = ['if', 'when', 'unless', 'except', 'only if', 'in case of']
        return any(kw in text_lower for kw in keywords)

    def _extract_with_llm(self, rule_text: str) -> ConditionSet:
        """使用LLM提取条件"""
        try:
            # 构建prompt
            prompt = self.EXTRACTION_PROMPT_TEMPLATE.format(
                few_shot_examples=self.FEW_SHOT_EXAMPLES,
                rule_text=rule_text
            )

            # 调用LLM
            response = self.llm_client.chat(prompt, temperature=0.1)

            # 解析JSON
            # 提取JSON部分（可能被包裹在markdown代码块中）
            json_match = re.search(r'```(?:json)?\s*(\{.*?\})\s*```', response, re.DOTALL)
            if json_match:
                json_str = json_match.group(1)
            else:
                # 尝试直接解析
                json_str = response.strip()

            result = json.loads(json_str)

            # 构建ConditionSet
            return self._build_condition_set(result)

        except json.JSONDecodeError as e:
            app_logger.error(f"LLM返回的JSON格式错误: {e}\nResponse: {response[:200]}")
            return ConditionSet(conditions=[])
        except Exception as e:
            app_logger.error(f"LLM提取失败: {e}", exc_info=True)
            return ConditionSet(conditions=[])

    def _extract_with_regex(self, rule_text: str) -> ConditionSet:
        """
        Fallback: 使用regex启发式提取条件

        这是简化版本，只处理常见模式
        """
        conditions = []
        text_lower = rule_text.lower()

        # 模式1: IF cA=TRUE
        if_ca_match = re.search(r'if\s+.*?c[aA]\s*=\s*true', rule_text, re.IGNORECASE)
        if if_ca_match:
            conditions.append(
                FieldCondition(field="c.IsCA", operator="==", value=True)
            )

        # 模式2: IF certificate is a CA
        if re.search(r'if\s+.*?(?:certificate\s+)?is\s+a\s+ca', text_lower):
            conditions.append(
                FieldCondition(field="c.IsCA", operator="==", value=True)
            )

        # 模式3: WHEN validity exceeds X days
        validity_match = re.search(r'(?:when|if)\s+.*?validity.*?(?:exceeds?|greater\s+than)\s+(\d+)\s*days?', text_lower)
        if validity_match:
            days = int(validity_match.group(1))
            conditions.append(
                RangeCondition(field="validity_days", operator=">", value=days, unit="days")
            )

        # 模式4: UNLESS subjectAltName is present
        unless_san_match = re.search(r'unless\s+.*?subjectalternativename.*?(?:is\s+)?present', text_lower)
        if unless_san_match:
            conditions.append(
                FieldCondition(field="c.SubjectAltName", operator="EXISTS", value=None)
            )

        return ConditionSet(conditions=conditions, logic="AND")

    def _build_condition_set(self, result: dict) -> ConditionSet:
        """从LLM返回的JSON构建ConditionSet"""
        conditions = []

        for cond_dict in result.get("conditions", []):
            try:
                cond_type = cond_dict.get("type", "field")

                if cond_type == "field":
                    conditions.append(FieldCondition(**cond_dict))
                elif cond_type == "set":
                    conditions.append(SetCondition(**cond_dict))
                elif cond_type == "range":
                    conditions.append(RangeCondition(**cond_dict))
                elif cond_type in ["and", "or"]:
                    conditions.append(LogicalCondition(**cond_dict))
                else:
                    app_logger.warning(f"未知条件类型: {cond_type}")

            except Exception as e:
                app_logger.error(f"构建条件失败: {e}, dict: {cond_dict}")
                continue

        return ConditionSet(
            conditions=conditions,
            logic=result.get("logic", "AND")
        )


# 简化版LLM客户端（用于测试）
class SimpleLLMClient:
    """简化版LLM客户端，用于测试"""

    def chat(self, prompt: str, temperature: float = 0.1) -> str:
        """
        模拟LLM调用

        实际使用时，替换为真实的LLM API调用
        如：OpenAI, Claude, 本地模型等
        """
        # TODO: 替换为实际LLM调用
        # 示例：
        # import openai
        # response = openai.ChatCompletion.create(
        #     model="gpt-4",
        #     messages=[{"role": "user", "content": prompt}],
        #     temperature=temperature
        # )
        # return response.choices[0].message.content

        # 暂时返回空结果
        return '{"conditions": [], "logic": "AND"}'
