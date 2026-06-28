"""
规则后处理验证器和修正器
"""
import re
import json
import logging
from typing import Dict, List, Any, Optional

logger = logging.getLogger(__name__)


class RuleValidator:
    """规则字段验证和自动修正"""

    VALID_MODALITIES = {
        'behavioral_rule', 'field_constraint', 'process_rule',
        'validation_rule', 'composite_rule', 'encoding_rule',
        'initialization_rule'
    }

    MODAL_WORDS = {'MUST', 'SHALL', 'SHOULD', 'MAY', 'MUST_NOT', 'SHALL_NOT', 'SHOULD_NOT'}

    # 标准X.509证书字段
    CERT_FIELDS = {
        'version', 'serialNumber', 'signature', 'issuer', 'subject',
        'validity', 'subjectPublicKeyInfo', 'issuerUniqueID', 'subjectUniqueID',
        'certificate', 'tbsCertificate', 'signatureAlgorithm', 'signatureValue'
    }

    # 证书扩展字段前缀
    EXTENSION_PREFIX = 'extensions.'

    # 实体角色
    ENTITY_ROLES = {'CA', 'Subscriber', 'Relying_Party', 'RA', 'Applicant'}

    # 证书字段相关操作
    FIELD_OPERATIONS = {
        'must_be_present', 'must_not_be_present', 'must_equal',
        'minimum_value', 'maximum_value', 'must_be_critical',
        'must_not_equal', 'length_constraint'
    }

    # 行为/流程相关操作
    BEHAVIOR_OPERATIONS = {'behavior', 'process', 'validate', 'reject'}

    def __init__(self):
        pass

    def validate_and_fix(self, rule_dict: Dict[str, Any]) -> Dict[str, Any]:
        """
        验证并修正规则字典

        Args:
            rule_dict: 规则字典

        Returns:
            修正后的规则字典
        """
        # 验证并修正modality
        rule_dict = self._fix_modality(rule_dict)

        # 验证并修正affected_field
        rule_dict = self._fix_affected_field(rule_dict)

        # 验证并修正section
        rule_dict = self._fix_section(rule_dict)

        # 统一conditions格式
        rule_dict = self._normalize_conditions(rule_dict)

        # 验证字段一致性
        rule_dict = self._check_field_consistency(rule_dict)

        return rule_dict

    def _fix_modality(self, rule_dict: Dict[str, Any]) -> Dict[str, Any]:
        """修正modality字段"""
        modality = rule_dict.get('modality', '')
        text = rule_dict.get('text', '')

        # 如果modality是模态词，自动修正
        if modality in self.MODAL_WORDS:
            # 保存到requirement_level
            rule_dict['requirement_level'] = modality

            # 根据文本内容推断正确的modality
            text_lower = text.lower()

            # 启发式规则
            if any(word in text_lower for word in ['validate', 'verify', 'check', 'confirm']):
                rule_dict['modality'] = 'validation_rule'
            elif any(word in text_lower for word in ['encode', 'encoding', 'format']):
                rule_dict['modality'] = 'encoding_rule'
            elif any(field in text_lower for field in ['extension', 'field', 'attribute', 'value']):
                rule_dict['modality'] = 'field_constraint'
            elif any(word in text_lower for word in ['process', 'procedure', 'step']):
                rule_dict['modality'] = 'process_rule'
            else:
                rule_dict['modality'] = 'behavioral_rule'

            logger.warning(f"Auto-corrected modality from '{modality}' to '{rule_dict['modality']}': {text[:100]}")

        # 检查modality是否合法
        if rule_dict.get('modality') not in self.VALID_MODALITIES:
            logger.error(f"Invalid modality '{rule_dict.get('modality')}': {text[:100]}")
            # 默认设置为behavioral_rule
            rule_dict['modality'] = 'behavioral_rule'

        return rule_dict

    def _fix_affected_field(self, rule_dict: Dict[str, Any]) -> Dict[str, Any]:
        """修正affected_field字段"""
        affected_field = rule_dict.get('affected_field', '')
        operation = rule_dict.get('operation', '')
        subject_role = rule_dict.get('subject_role', '')
        text = rule_dict.get('text', '')

        # 判断是否是实体行为规范
        is_entity_behavior = (
            affected_field in self.ENTITY_ROLES and
            operation in self.BEHAVIOR_OPERATIONS
        )

        # 设置target_type
        if is_entity_behavior:
            rule_dict['target_type'] = 'entity_behavior'
        elif affected_field.startswith(self.EXTENSION_PREFIX):
            rule_dict['target_type'] = 'certificate_field'
        elif affected_field in self.CERT_FIELDS:
            rule_dict['target_type'] = 'certificate_field'
        elif operation in {'process', 'validate'}:
            rule_dict['target_type'] = 'process_requirement'
        else:
            # 尝试从文本推断
            if any(role in text for role in self.ENTITY_ROLES):
                rule_dict['target_type'] = 'entity_behavior'
            else:
                rule_dict['target_type'] = 'unknown'

        return rule_dict

    def _fix_section(self, rule_dict: Dict[str, Any]) -> Dict[str, Any]:
        """修正section字段"""
        section = rule_dict.get('section', '')

        # 如果section是"1"或"Section 1"，尝试从文本提取
        if section in ['1', 'Section 1', 'Section']:
            text = rule_dict.get('text', '')

            # 尝试从文本开头提取章节号
            patterns = [
                r'^(\d+(?:\.\d+){1,5})\s',  # "4.2.1.9 "
                r'^Section\s+(\d+(?:\.\d+)*)',  # "Section 4.2"
                r'^\[(\d+(?:\.\d+)*)\]',  # "[4.2]"
            ]

            for pattern in patterns:
                match = re.match(pattern, text.strip())
                if match:
                    extracted_section = match.group(1)
                    if extracted_section != '1':
                        rule_dict['section'] = extracted_section
                        logger.info(f"Extracted section '{extracted_section}' from text")
                        break

        # 标准化section格式（去除"Section"前缀）
        if isinstance(section, str) and section.startswith('Section '):
            rule_dict['section'] = section.replace('Section ', '')

        return rule_dict

    def _normalize_conditions(self, rule_dict: Dict[str, Any]) -> Dict[str, Any]:
        """统一conditions格式为JSON数组"""
        conditions = rule_dict.get('conditions')

        if conditions is None or conditions == '':
            rule_dict['conditions'] = []
            return rule_dict

        # 如果是字符串
        if isinstance(conditions, str):
            try:
                # 尝试解析为JSON
                parsed = json.loads(conditions)
                if isinstance(parsed, list):
                    rule_dict['conditions'] = parsed
                elif isinstance(parsed, dict):
                    # 将字典的值提取为列表
                    rule_dict['conditions'] = list(parsed.values())
                else:
                    # 单个字符串，包装成列表
                    rule_dict['conditions'] = [str(parsed)]
            except json.JSONDecodeError:
                # 不是JSON，直接包装为列表
                rule_dict['conditions'] = [conditions]

        # 如果已经是列表
        elif isinstance(conditions, list):
            rule_dict['conditions'] = conditions

        # 其他情况（如字典）
        elif isinstance(conditions, dict):
            rule_dict['conditions'] = list(conditions.values())

        else:
            rule_dict['conditions'] = []

        return rule_dict

    def _check_field_consistency(self, rule_dict: Dict[str, Any]) -> Dict[str, Any]:
        """检查字段一致性"""
        affected_field = rule_dict.get('affected_field', '')
        operation = rule_dict.get('operation', '')
        modality = rule_dict.get('modality', '')
        text = rule_dict.get('text', '')

        # 检查1: affected_field与operation匹配
        if affected_field in self.ENTITY_ROLES:
            if operation not in self.BEHAVIOR_OPERATIONS:
                logger.warning(f"Inconsistent: affected_field={affected_field} but operation={operation}: {text[:100]}")

        elif affected_field in self.CERT_FIELDS or affected_field.startswith(self.EXTENSION_PREFIX):
            if operation not in self.FIELD_OPERATIONS and operation != 'behavior':
                logger.warning(f"Inconsistent: certificate field '{affected_field}' but operation={operation}: {text[:100]}")

        # 检查2: modality与operation匹配
        modality_operation_map = {
            'behavioral_rule': self.BEHAVIOR_OPERATIONS,
            'field_constraint': self.FIELD_OPERATIONS,
            'process_rule': {'process', 'behavior'},
            'validation_rule': {'validate', 'process'},
        }

        expected_ops = modality_operation_map.get(modality, set())
        if expected_ops and operation not in expected_ops:
            logger.warning(f"Inconsistent: modality={modality} but operation={operation}: {text[:100]}")

        return rule_dict


def validate_rule(rule_dict: Dict[str, Any]) -> Dict[str, Any]:
    """
    便捷函数：验证并修正单条规则

    Args:
        rule_dict: 规则字典

    Returns:
        修正后的规则字典
    """
    validator = RuleValidator()
    return validator.validate_and_fix(rule_dict)


if __name__ == "__main__":
    # 测试
    logging.basicConfig(level=logging.INFO)

    # 测试用例1: modality错误
    test_rule_1 = {
        'text': 'The CA MUST validate the domain.',
        'modality': 'MUST',
        'affected_field': 'CA',
        'operation': 'behavior',
        'section': '1'
    }

    fixed_1 = validate_rule(test_rule_1)
    print("Test 1 - Fixed modality:")
    print(f"  Before: {test_rule_1}")
    print(f"  After: {fixed_1}")
    print()

    # 测试用例2: conditions格式
    test_rule_2 = {
        'text': 'If the certificate is self-signed...',
        'modality': 'field_constraint',
        'affected_field': 'certificate',
        'operation': 'must_equal',
        'conditions': '{"condition": "If the certificate is self-signed"}'
    }

    fixed_2 = validate_rule(test_rule_2)
    print("Test 2 - Fixed conditions:")
    print(f"  Before: {test_rule_2['conditions']}")
    print(f"  After: {fixed_2['conditions']}")
