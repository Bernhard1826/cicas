"""
Rule Classifier Service
Classifies rules into lintable or non_lintable categories based on IR v2.0 algorithm
"""
import json
from typing import Dict
from app.core.logging_config import app_logger


class RuleClassifier:
    """
    Classifier to determine if a rule can generate zlint code based on IR lintability
    """

    def __init__(self):
        pass

    @staticmethod
    def _extract_ir(rule) -> Dict:
        raw = json.loads(rule.ir_data)
        if isinstance(raw, dict):
            return raw.get('ir', raw)
        return {}

    def classify_rule_by_lintability(self, rule) -> Dict:
        """
        基于IR中的zlint_lintability判断分类规则（v2.1新增）

        使用IR v2.0的6步判断算法结果来分类规则：
        - zlint_lintability.can_generate = true → lintable (可生成zlint)
        - zlint_lintability.can_generate = false → non_lintable (不可生成zlint)

        Args:
            rule: Rule对象，包含ir_data字段

        Returns:
            {
                'category': 'lintable' or 'non_lintable',
                'confidence': 0.0-1.0,
                'reason': str,
                'lintable': bool,
                'lintable_reason': str
            }
        """
        try:
            if not rule.ir_data:
                app_logger.warning(f"Rule {rule.id} has no IR data, cannot classify by lintability")
                return {
                    'category': 'non_lintable',
                    'confidence': 1.0,
                    'reason': '规则没有IR数据',
                    'lintable': False,
                    'lintable_reason': '缺少IR数据，无法判断是否可生成zlint'
                }

            try:
                ir = self._extract_ir(rule)
            except json.JSONDecodeError as e:
                app_logger.error(f"Failed to parse IR data for rule {rule.id}: {e}")
                return {
                    'category': 'non_lintable',
                    'confidence': 1.0,
                    'reason': 'IR数据解析失败',
                    'lintable': False,
                    'lintable_reason': f'IR JSON解析错误: {str(e)}'
                }

            zlint_lintability = ir.get('zlint_lintability', {})
            can_generate = zlint_lintability.get('can_generate', None)

            if can_generate is None:
                app_logger.warning(f"Rule {rule.id} IR lacks zlint_lintability.can_generate field")
                return {
                    'category': 'non_lintable',
                    'confidence': 0.5,
                    'reason': 'IR缺少zlint_lintability判断结果',
                    'lintable': False,
                    'lintable_reason': 'IR中没有zlint_lintability字段，可能是旧版本IR'
                }

            if can_generate:
                return {
                    'category': 'lintable',
                    'confidence': 1.0,
                    'reason': zlint_lintability.get('reason', 'IR判断为可生成zlint'),
                    'lintable': True,
                    'lintable_reason': zlint_lintability.get('reason', ''),
                    'failed_step': None,
                    'algorithm_version': zlint_lintability.get('algorithm_version', 'v2.0')
                }
            return {
                'category': 'non_lintable',
                'confidence': 1.0,
                'reason': zlint_lintability.get('reason', 'IR判断为不可生成zlint'),
                'lintable': False,
                'lintable_reason': zlint_lintability.get('reason', ''),
                'failed_step': zlint_lintability.get('failed_step'),
                'algorithm_version': zlint_lintability.get('algorithm_version', 'v2.0')
            }

        except Exception as e:
            app_logger.error(f"Error classifying rule {rule.id} by lintability: {e}", exc_info=True)
            return {
                'category': 'non_lintable',
                'confidence': 0.0,
                'reason': f'分类过程出错: {str(e)}',
                'lintable': False,
                'lintable_reason': str(e)
            }
