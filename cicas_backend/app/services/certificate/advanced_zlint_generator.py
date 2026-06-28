"""
Advanced ZLint Code Generator with IR (Intermediate Representation) - Enhanced with RAG
Implements the complete pipeline: Rule → IR → Go Code → Test
Now includes:
1. RAG integration for retrieving similar lint implementations
2. IR validation for correctness
3. Extended logic types (15 types)
"""
import json
import re
from typing import Dict, List, Optional, Tuple
from pathlib import Path
from datetime import datetime

from app.core.logging_config import app_logger
from app.core.config import settings


class IntermediateRepresentation:
    """
    中间表示（IR）类
    将自然语言规则转换为结构化的中间表示
    """

    # 扩展的逻辑类型定义（15种）
    LOGIC_TYPES = {
        # 基础类型（8种）
        'presence': '字段必须存在或必须不存在',
        'regex': '按正则表达式检查格式',
        'equality': '必须等于某值',
        'range': '长度或数值范围',
        'contains': '字段必须包含某个值',
        'uniqueness': '必须唯一',
        'conditional': '条件规则(A→B)',
        'custom': '复杂规则,由LLM生成代码片段',

        # 扩展类型（7种）
        'multi_field_consistency': '多字段一致性检查（如Subject和SAN一致）',
        'dependency': '依赖关系（如果有字段A，则必须有字段B）',
        'time_based': '时间相关规则（如有效期检查、时间窗口）',
        'oid_list': 'OID列表规则（如允许的算法OID）',
        'chain': '证书链规则（涉及父证书或链验证）',
        'encoding': '编码规则（如DER编码、UTF-8编码）',
        'length': '长度限制（字符串、数组长度）',
    }

    def __init__(self):
        self.ir = {
            "lint_name": "",
            "description": "",
            "citation": "",
            "source": "",
            "effective_date": "",
            "applies_to": "Subscriber",  # Subscriber | CA | All
            "target_field": "",
            "logic": {
                "type": "",
                "operator": "",
                "value": "",
                "conditions": [],
                "custom_code": ""
            },
            "error_level": "Error",  # Error | Warn | Notice

            # 新增字段 - 用于精确判断zlint可生成性
            "assertion_subject": "Certificate",  # Certificate | CA | RP (Relying Party)
            "external_dependency": {
                "has_external_ref": False,
                "dependency_type": None,  # ocsp, crl, database, manual_verification, ct_log, whois
                "description": ""
            },
            "determinism": {
                "is_deterministic": True,
                "vague_terms": [],  # ["reasonable", "appropriate", "suitable"]
                "requires_context": False,  # 是否需要上下文理解（如代词：it, this, that）
                "confidence": 1.0  # 确定性置信度 0.0-1.0
            },
            "zlint_lintability": {
                "can_generate": None,  # True/False/None(未判定)
                "reason": "",
                "failed_step": None,  # Step 1-6中哪一步失败
                "algorithm_version": "v2.0"  # 算法版本，用于追踪
            }
        }

    def from_rule(self, rule: Dict, rag_reference: Optional[List[Dict]] = None) -> Dict:
        """
        从规则字典生成IR（增强版 - 使用RAG参考）

        Args:
            rule: 规则字典，包含 text, source, section, affected_field, operation等
            rag_reference: RAG检索到的相似lint列表（可选）

        Returns:
            IR字典
        """
        try:
            # 基本信息
            self.ir['lint_name'] = self._generate_lint_name(rule)

            # 【新增】验证 lint_name 格式
            lint_name = self.ir['lint_name']
            if not re.match(r'^[ewn]_[a-z0-9_]+$', lint_name):
                app_logger.error(
                    f"[IR Generation] Invalid lint_name format: '{lint_name}' for rule {rule.get('id')}. "
                    f"Expected pattern: ^[ewn]_[a-z0-9_]+$"
                )
                # 尝试修复：移除非法字符
                lint_name_fixed = re.sub(r'[^a-z0-9_]', '_', lint_name.lower())
                lint_name_fixed = re.sub(r'__+', '_', lint_name_fixed).strip('_')
                # 确保有前缀
                if not lint_name_fixed.startswith(('e_', 'w_', 'n_')):
                    lint_name_fixed = f"e_{lint_name_fixed}"
                # 限制长度
                if len(lint_name_fixed) > 60:
                    lint_name_fixed = lint_name_fixed[:60].rstrip('_')
                self.ir['lint_name'] = lint_name_fixed
                app_logger.warning(f"[IR Generation] Auto-fixed lint_name to: '{lint_name_fixed}'")

            self.ir['description'] = rule.get('text', '')[:500]  # 扩展到500字符以保留更多信息（包括引用）
            self.ir['citation'] = f"{rule.get('source', 'RFC')} {rule.get('section', '')}"
            self.ir['source'] = self._map_source(rule.get('source', 'RFC'))
            self.ir['effective_date'] = 'RFC5280Date'  # 默认

            # 目标字段（优先使用RAG参考和文本提取，支持section推断）
            self.ir['target_field'] = self._normalize_field_path(
                rule.get('affected_field', ''),
                rag_reference,
                rule.get('text', ''),
                rule.get('section', '')  # 新增：传递section用于推断字段
            )

            # 逻辑类型推断（使用RAG参考）
            logic_type, logic_config = self._infer_logic_type(rule, rag_reference)
            self.ir['logic']['type'] = logic_type
            self.ir['logic'].update(logic_config)

            # 错误级别（根据规则文本推断）
            self.ir['error_level'] = self._infer_error_level(rule)

            # 新增：填充assertion_subject
            self.ir['assertion_subject'] = self._detect_assertion_subject(rule)

            # 新增：检测外部依赖
            self.ir['external_dependency'] = self._detect_external_dependency(rule)

            # 新增：评估确定性
            self.ir['determinism'] = self._assess_determinism(rule)

            # 注意：zlint_lintability 不在此处计算
            # 这个字段应该在用户点击"智能分流"时才计算并填充
            # 这样可以实现职责分离：IR生成 vs 分流判断
            self.ir['zlint_lintability'] = None  # 默认为None，表示未判断

            # 如果有RAG参考，添加元数据
            if rag_reference:
                self.ir['_rag_references'] = [
                    {
                        'lint_name': ref.get('lint_name'),
                        'similarity': ref.get('similarity', 0),
                        'package': ref.get('package')
                    }
                    for ref in rag_reference[:3]  # top 3
                ]

            return self.ir

        except Exception as e:
            app_logger.error(f"Error generating IR: {e}")
            raise

    def _generate_lint_name(self, rule: Dict) -> str:
        """
        生成符合zlint规范的lint名称（改进版v2）

        zlint命名规范：
        - 格式：{severity_prefix}_{descriptive_name}
        - 示例：e_ext_san_uri_relative, w_dnsname_underscore, n_subject_common_name
        - 长度：建议不超过60个字符

        改进点：
        1. 更robust的severity检测（支持多种字段名）
        2. Section严格清理（移除所有非数字字符）
        3. 始终限制section长度为前3段
        4. 添加验证和警告日志
        """
        # 1. 提取severity前缀（改进：支持多种字段名）
        severity = (
            rule.get('requirement_level') or
            rule.get('obligation') or
            rule.get('severity') or
            'MUST'
        )
        if severity in ['MUST', 'SHALL', 'MUST NOT', 'SHALL NOT']:
            prefix = 'e'  # error
        elif severity in ['SHOULD', 'SHOULD NOT', 'RECOMMENDED']:
            prefix = 'w'  # warning
        else:
            prefix = 'n'  # notice

        # 2. 提取字段的最后一部分作为描述
        field = rule.get('affected_field') or ''
        if field:
            # 提取最后一个点后的部分，如 extensions.subjectAltName.dNSName -> dnsname
            field_parts = field.split('.')
            field_short = field_parts[-1].lower()
            # 驼峰转下划线
            field_short = re.sub(r'(?<!^)(?=[A-Z])', '_', field_short).lower()
        else:
            field_short = 'cert'

        # 3. 提取操作描述
        operation = rule.get('operation', '')
        if operation:
            # 提取操作的关键词
            op_map = {
                'must_not_be_present': 'not_present',
                'must_be_present': 'present',
                'must_not_be': 'prohibited',
                'must_equal': 'equals',
                'must_include': 'contains',
                'must_follow': 'follows',
                'maximum_value': 'max',
                'minimum_value': 'min',
                'must_be_critical': 'critical',
                'must_not_be_critical': 'not_critical',
            }
            op_desc = op_map.get(operation, operation.replace('must_', '').replace('_', ''))
        else:
            op_desc = ''

        # 4. 构建描述性名称
        # 如果有操作描述，使用 {field}_{operation}
        # 否则只使用字段名
        if op_desc:
            descriptive_name = f"{field_short}_{op_desc}"
        else:
            descriptive_name = field_short

        # 5. 清理和限制长度
        descriptive_name = re.sub(r'[^a-z0-9_]', '', descriptive_name)
        descriptive_name = re.sub(r'__+', '_', descriptive_name).strip('_')

        # 初始lint_name
        lint_name = f"{prefix}_{descriptive_name}"
        if len(lint_name) > 60:
            # 截断到60字符，保留前缀
            lint_name = lint_name[:60].rstrip('_')

        # 6. 如果名称太短或太通用，添加source/section信息
        if len(descriptive_name) < 5 or descriptive_name == 'cert':
            source = (rule.get('source') or 'rfc').lower()
            # 【改进】统一清理source
            source = source.replace('-', '_').replace(' ', '_')

            section = (rule.get('section') or '').replace('.', '_')

            # 【改进】严格清理 section：只保留数字和下划线
            section_original = section
            section = re.sub(r'[^0-9_]', '', section)

            # 【改进】如果清理后发生变化，记录警告
            if section != section_original and section_original:
                app_logger.warning(
                    f"[lint_name] Cleaned section for rule {rule.get('id')}: "
                    f"'{section_original}' -> '{section}'"
                )

            if section:
                # 【改进】始终限制 section 为前3段
                section_parts = section.split('_')
                if len(section_parts) > 3:
                    app_logger.debug(
                        f"[lint_name] Truncating section from {len(section_parts)} to 3 parts for rule {rule.get('id')}"
                    )
                section_short = '_'.join(section_parts[:3])

                lint_name = f"{prefix}_{source}_{section_short}_{descriptive_name}"

                # 再次检查长度
                if len(lint_name) > 60:
                    app_logger.warning(
                        f"[lint_name] Lint name too long ({len(lint_name)} chars), truncating for rule {rule.get('id')}"
                    )
                    lint_name = lint_name[:60].rstrip('_')

        # 【新增】最终验证
        if not re.match(r'^[ewn]_[a-z0-9_]+$', lint_name):
            app_logger.error(
                f"[lint_name] Generated lint_name '{lint_name}' does not match zlint naming convention! "
                f"Rule ID: {rule.get('id')}"
            )

        return lint_name

    def _map_source(self, source: str) -> str:
        """映射标准源"""
        source_map = {
            'RFC': 'RFC5280',
            'RFC5280': 'RFC5280',
            'CABF': 'CABFBaselineRequirements',
            'CABF-SERVER': 'CABFBaselineRequirements',  # CABF Server证书基线要求
            'CABF_BR': 'CABFBaselineRequirements',
            'BR': 'CABFBaselineRequirements',
            'CABF-EV': 'CABFEVGuidelines',  # CABF EV扩展验证指南
            'CABF_EV': 'CABFEVGuidelines',
            'EV': 'CABFEVGuidelines',
            'CABF-SMIME': 'CABFSMIMERequirements',  # CABF S/MIME要求
            'Mozilla': 'MozillaRootStorePolicy',
            'Apple': 'AppleRootStorePolicy',
        }
        return source_map.get(source.upper(), 'RFC5280')

    def _normalize_field_path(self, field: str, rag_reference: Optional[List[Dict]] = None, rule_text: str = '', section: str = '') -> str:
        """
        规范化字段路径到x509.Certificate结构
        改进版v2：支持从规则文本和section中智能提取字段

        Args:
            field: 原始字段名
            rag_reference: RAG检索的相似lint列表
            rule_text: 规则文本（用于智能提取）
            section: 规则所在的section（用于推断字段）

        Returns:
            规范化的字段路径
        """
        # 字段映射表
        field_mapping = {
            'extensions.subjectAltName': 'c.SubjectAltName',
            'extensions.keyUsage': 'c.KeyUsage',
            'extensions.extendedKeyUsage': 'c.ExtKeyUsage',
            'extensions.basicConstraints': 'c.BasicConstraintsValid',
            'validity.notBefore': 'c.NotBefore',
            'validity.notAfter': 'c.NotAfter',
            'validity': 'c.NotBefore, c.NotAfter',
            'subject': 'c.Subject',
            'issuer': 'c.Issuer',
            'serialNumber': 'c.SerialNumber',
            'version': 'c.Version',
            'signatureAlgorithm': 'c.SignatureAlgorithm',
            'subjectPublicKeyInfo': 'c.PublicKey',
        }

        # 1. 如果有明确的字段参数，先尝试映射
        if field:
            # 直接映射
            if field in field_mapping:
                return field_mapping[field]

            # 处理extensions.*
            if field.startswith('extensions.'):
                ext_name = field.split('.')[-1]
                # 驼峰命名
                camel_case = ''.join(word.capitalize() for word in ext_name.split('_'))
                return f'c.{camel_case}'

            # 如果字段已经是c.开头的格式，直接返回
            if field.startswith('c.'):
                return field

        # 2. 从规则文本中智能提取字段（优先级高）
        if rule_text:
            extracted_field = self._extract_field_from_text(rule_text, section)
            if extracted_field and extracted_field != 'c':
                app_logger.info(f"Extracted field from text: {extracted_field}")
                return extracted_field

        # 3. 基于section推断字段（新增 - 解决Step2_FieldPath问题）
        if section:
            section_field = self._infer_field_from_section(section, rule_text)
            if section_field and section_field != 'c':
                app_logger.info(f"Inferred field from section {section}: {section_field}")
                return section_field

        # 4. 尝试从RAG参考推断
        if rag_reference and len(rag_reference) > 0:
            top_ref = rag_reference[0]
            if 'target_field' in top_ref:
                app_logger.info(f"Using target_field from RAG: {top_ref['target_field']}")
                return top_ref['target_field']

        # 5. 如果有字段但不在映射表中，尝试智能构造
        if field:
            return f'c.{field}'

        # 6. 默认返回通用证书对象
        return 'c'

    def _extract_field_from_text(self, text: str, section: str = '') -> str:
        """
        从规则文本中提取目标字段
        改进版v2：添加URI相关模式识别

        使用优先级匹配：越具体的模式优先级越高

        Args:
            text: 规则文本
            section: 规则所在section（可选，用于辅助判断）

        Returns:
            提取的字段路径（如 'c.SubjectAltName'）
        """
        text_lower = text.lower()

        # 字段提取模式（按优先级排序：越具体的越靠前）
        field_patterns = [
            # Subject Alternative Name (高优先级，非常明确)
            (r'subject\s+alternative\s+name|subjectaltname|san\s+extension|san\s+entry', 'c.SubjectAltName'),
            (r'dnsname|dns\s+name|dns\s+entries', 'c.DNSNames'),
            (r'ipaddress|ip\s+address', 'c.IPAddresses'),

            # URI 相关（新增 - 解决规则74498-74502）
            # "The name MUST NOT be a relative URI" 通常指SAN中的uniformResourceIdentifier
            (r'uniform\s+resource\s+identifier|uniformresourceidentifier', 'c.URIs'),
            (r'\buri\b.*syntax|uri.*encoding|relative\s+uri|absolute\s+uri', 'c.URIs'),

            # Public Key 相关 (高优先级)
            (r'rsa\s+public\s+key|public\s+key\s+algorithm', 'c.PublicKeyAlgorithm'),
            (r'public\s+exponent', 'c.PublicKey'),
            (r'public\s+key(?!\s+algorithm)', 'c.PublicKey'),

            # Key Usage 扩展
            (r'key\s+usage\s+extension|keyusage', 'c.KeyUsage'),
            (r'extended\s+key\s+usage|extendedkeyusage|eku', 'c.ExtKeyUsage'),

            # Basic Constraints
            (r'basic\s+constraints?\s+extension|basicconstraints', 'c.BasicConstraintsValid'),
            (r'\bca\s+flag\b|\bca\s+bit\b|\bca\s*=\s*true', 'c.IsCA'),
            (r'path\s+len(?:gth)?\s+constraint', 'c.MaxPathLen'),

            # Validity 相关
            (r'validity\s+period|certificate\s+lifetime', 'c.NotBefore'),
            (r'not\s*before|notbefore', 'c.NotBefore'),
            (r'not\s*after|notafter|expir(?:ation|y)', 'c.NotAfter'),

            # CRL Distribution Points
            (r'crl\s+distribution\s+points?|crldistributionpoints', 'c.CRLDistributionPoints'),

            # Authority Information Access
            (r'authority\s+information\s+access|aia', 'c.IssuingCertificateURL'),
            (r'ocsp|online\s+certificate\s+status', 'c.OCSPServer'),

            # 其他常见扩展
            (r'certificate\s+policies|certificatepolicies', 'c.PolicyIdentifiers'),
            (r'name\s+constraints?', 'c.PermittedDNSDomains'),
            (r'subject\s+key\s+identifier|subjectkeyidentifier|ski', 'c.SubjectKeyId'),
            (r'authority\s+key\s+identifier|authoritykeyidentifier|aki', 'c.AuthorityKeyId'),

            # Signature 相关
            (r'signature\s+algorithm', 'c.SignatureAlgorithm'),
            (r'signature\s+value', 'c.Signature'),

            # Subject/Issuer (低优先级，因为很常见但不够具体)
            (r'subject\s+distinguished\s+name|subject\s+dn|subject\s+field', 'c.Subject'),
            (r'common\s+name|cn\s+field', 'c.Subject.CommonName'),
            (r'organization|o\s+field', 'c.Subject.Organization'),
            (r'country|c\s+field', 'c.Subject.Country'),
            (r'issuer\s+distinguished\s+name|issuer\s+dn|issuer\s+field', 'c.Issuer'),

            # Serial Number
            (r'serial\s+number', 'c.SerialNumber'),

            # Version
            (r'certificate\s+version|x\.?509\s+version', 'c.Version'),
        ]

        # 按优先级匹配
        for pattern, field in field_patterns:
            if re.search(pattern, text_lower):
                return field

        # 如果没有匹配到任何模式，返回通用对象
        return 'c'

    def _infer_field_from_section(self, section: str, rule_text: str = '') -> str:
        """
        基于RFC section编号推断目标字段

        用于解决那些规则文本中没有明确提到字段名，但section编号能指示字段的情况
        例如：RFC 5280 Section 4.2.1.6 总是关于 Subject Alternative Name

        Args:
            section: RFC section编号（如 "4.2.1.6"）
            rule_text: 规则文本（可选，用于辅助判断）

        Returns:
            推断的字段路径（如 'c.SubjectAltName'）
        """
        if not section:
            return 'c'

        # RFC 5280 section到字段的映射
        # 参考：https://datatracker.ietf.org/doc/html/rfc5280
        section_field_map = {
            # Section 4.1: Certificate 基本字段
            '4.1.1.1': 'c.Version',                    # version
            '4.1.1.2': 'c.SerialNumber',              # serialNumber
            '4.1.1.3': 'c.SignatureAlgorithm',        # signature
            '4.1.2.4': 'c.Issuer',                    # issuer
            '4.1.2.5': 'c.NotBefore',                 # validity (notBefore/notAfter)
            '4.1.2.6': 'c.Subject',                   # subject
            '4.1.2.7': 'c.PublicKey',                 # subjectPublicKeyInfo

            # Section 4.2: Extensions
            '4.2.1.1': 'c.AuthorityKeyId',            # authorityKeyIdentifier
            '4.2.1.2': 'c.SubjectKeyId',              # subjectKeyIdentifier
            '4.2.1.3': 'c.KeyUsage',                  # keyUsage
            '4.2.1.4': 'c.PolicyIdentifiers',         # certificatePolicies
            '4.2.1.5': 'c.PolicyIdentifiers',         # policyMappings
            '4.2.1.6': 'c.SubjectAltName',            # ← 关键：这个section总是关于SAN
            '4.2.1.7': 'c.Issuer',                    # issuerAltName
            '4.2.1.9': 'c.BasicConstraintsValid',     # basicConstraints
            '4.2.1.10': 'c.PermittedDNSDomains',      # nameConstraints
            '4.2.1.12': 'c.ExtKeyUsage',              # extendedKeyUsage
            '4.2.1.13': 'c.CRLDistributionPoints',    # cRLDistributionPoints

            # CABF sections
            '7.1.2.5.2': 'c.PermittedDNSDomains',     # nameConstraints (CABF)
            '7.1.2.7.12': 'c.SubjectAltName',         # subjectAltName (CABF)
            '7.1.2.10.8': 'c.PermittedDNSDomains',    # nameConstraints (CABF subordinate)
            '7.1.4.2': 'c.SubjectAltName',            # subjectAltName encoding (CABF)
            '7.1.4.3': 'c.Subject',                   # subject DN encoding (CABF)
        }

        # 精确匹配section
        if section in section_field_map:
            return section_field_map[section]

        # 前缀匹配（用于处理subsection）
        # 例如："4.2.1.6.1" 也应该映射到 SubjectAltName
        for sec_prefix, field in section_field_map.items():
            if section.startswith(sec_prefix + '.'):
                return field

        # 如果规则文本中明确提到了某个扩展，结合section推断
        text_lower = rule_text.lower() if rule_text else ''

        # Section 4.2.1.x 通常是扩展相关
        if section.startswith('4.2.1.'):
            # 检查文本中是否提到了特定的名称类型
            if 'uri' in text_lower or 'uniform resource' in text_lower:
                return 'c.URIs'
            elif 'dnsname' in text_lower or 'dns name' in text_lower:
                return 'c.DNSNames'
            elif 'ip' in text_lower and 'address' in text_lower:
                return 'c.IPAddresses'
            elif 'email' in text_lower or 'rfc822' in text_lower:
                return 'c.EmailAddresses'

        # 默认返回通用对象
        return 'c'

    def _infer_logic_type(self, rule: Dict, rag_reference: Optional[List[Dict]] = None) -> Tuple[str, Dict]:
        """
        推断规则的逻辑类型（增强版 - 使用RAG参考）

        Args:
            rule: 规则字典
            rag_reference: RAG检索的相似lint

        Returns:
            (logic_type, logic_config)
        """
        operation = rule.get('operation', '')
        affected_field = rule.get('affected_field', '')
        expected_value = rule.get('expected_value', '')
        text = rule.get('text', '').lower()

        # 0. 条件存在性检查（扩展版 - 支持更多模式）
        # 模式1: "if present, must..."
        if 'if present' in text and 'must' in text:
            # 确定内部条件类型
            if 'must contain' in text or 'must include' in text:
                return 'conditional_presence', {
                    'operator': 'if_present_then_contains',
                    'value': self._extract_value_from_text(text),
                    'inner_check': 'contains'
                }
            elif 'must be' in text and ('equal' in text or '=' in text):
                return 'conditional_presence', {
                    'operator': 'if_present_then_equals',
                    'value': self._extract_value_from_text(text),
                    'inner_check': 'equality'
                }
            elif 'must not' in text:
                return 'conditional_presence', {
                    'operator': 'if_present_then_not',
                    'value': self._extract_value_from_text(text),
                    'inner_check': 'absence'
                }
            else:
                # 通用的if present模式
                return 'conditional_presence', {
                    'operator': 'if_present_then_check',
                    'value': '',
                    'inner_check': 'custom'
                }

        # 模式2: "If at least one X is present..." （新增）
        # 示例："If at least one dNSName instance is present in the permittedSubtrees..."
        if re.search(r'if\s+at\s+least\s+one\s+\w+.*is\s+present', text):
            return 'conditional_presence', {
                'operator': 'if_at_least_one_present',
                'value': self._extract_value_from_text(text),
                'inner_check': 'count_check'
            }

        # 模式3: "If the value is X, then..." （新增）
        # 示例："If the value is a Fully-Qualified Domain Name..."
        if re.search(r'if\s+the\s+value\s+is\s+(a|an)\s+', text):
            # 这是基于值类型的条件判断
            return 'conditional_presence', {
                'operator': 'if_value_type_then',
                'value': self._extract_value_type(text),
                'inner_check': 'type_based'
            }

        # 模式4: "must contain either X or Y" （新增）
        # 示例："The entry MUST contain either a Fully-Qualified Domain Name or Wildcard Domain Name"
        if 'either' in text and 'or' in text:
            # 检查是否是简单的either...or...选择
            if 'must contain either' in text or 'must be either' in text:
                return 'conditional_presence', {
                    'operator': 'must_be_one_of',
                    'value': self._extract_either_or_options(text),
                    'inner_check': 'enumeration'
                }

        # 模式5: "unless..." 条件（新增）
        # 示例："MUST contain X, unless there is..."
        if 'unless' in text and 'must' in text:
            return 'conditional_presence', {
                'operator': 'unless',
                'value': '',
                'inner_check': 'exception_condition'
            }

        # 重要：处理 "X MUST NOT be present in Y" 的模式
        # 这种模式指的是Y中不能包含X，而不是Y字段不存在
        # 示例："underscore characters ("_") MUST NOT be present in dNSName entries"
        if 'must not be present in' in text:
            # 提取被禁止的字符或值
            # 模式: "X MUST NOT be present in Y"
            # 支持ASCII引号和Unicode引号 (" " ' ')
            match = re.search(r'([^\s]+\s+(?:character|string|value)s?)\s*(?:[()\[\{]["\'"\u201c\u2018]([^"\'"\u201d\u2019]+)["\'"\u201d\u2019][)\]\}])?\s+must not be present in', text, re.IGNORECASE)
            if match:
                forbidden_value = match.group(2) if match.group(2) else match.group(1)
                return 'format', {
                    'operator': 'must_not_contain',
                    'value': forbidden_value,
                    'conditions': []
                }
            # 如果没匹配到具体值，也归类为format检查
            elif any(kw in text for kw in ['character', 'string', 'value', 'digit', 'letter']):
                return 'format', {
                    'operator': 'must_not_contain',
                    'value': '',  # 需要手动填充
                    'conditions': [],
                    'custom_code': f'// TODO: Extract forbidden value from: {text[:100]}'
                }

        # 1. 存在性检查
        if operation in ['must_be_present', 'must_not_be_present']:
            return 'presence', {
                'operator': 'exists' if operation == 'must_be_present' else 'not_exists',
                'value': ''
            }

        # 2. Critical标记检查
        if operation in ['must_be_critical', 'must_not_be_critical']:
            return 'presence', {
                'operator': 'critical' if operation == 'must_be_critical' else 'not_critical',
                'value': ''
            }

        # 3. 时间相关规则（新增）
        if any(kw in text for kw in ['validity', 'expir', 'notbefore', 'notafter', 'lifetime', 'days', 'months', 'years']):
            if 'maximum' in text or 'minimum' in text or 'at least' in text or 'no more than' in text:
                return 'time_based', {
                    'operator': self._extract_time_operator(text),
                    'value': self._extract_time_value(text)
                }

        # 4. 多字段一致性（新增）
        if any(kw in text for kw in ['consistent', 'match', 'same as', 'equal to', 'correspond']):
            if 'subject' in text and 'san' in text:
                return 'multi_field_consistency', {
                    'operator': 'must_match',
                    'fields': ['c.Subject', 'c.SubjectAltName']
                }

        # 5. 依赖关系（新增）
        if 'if' in text and 'then' in text and 'must' in text:
            return 'dependency', {
                'operator': 'if_then',
                'condition_field': self._extract_condition_field(text),
                'required_field': self._extract_required_field(text)
            }

        # 6. OID列表规则（新增）
        if 'oid' in text or 'algorithm' in text or 'allowed' in text:
            return 'oid_list', {
                'operator': 'in_list' if 'allowed' in text else 'not_in_list',
                'value': self._extract_oid_list(text, rag_reference)
            }

        # 7. 编码规则（新增）
        if any(kw in text for kw in ['encoding', 'der', 'utf8', 'printable', 'ia5']):
            return 'encoding', {
                'operator': 'must_be_encoding',
                'value': self._extract_encoding_type(text)
            }

        # 8. 长度规则（新增）
        if 'length' in text or 'size' in text:
            return 'length', {
                'operator': self._extract_length_operator(text),
                'value': self._extract_length_value(text)
            }

        # 9. 正则表达式检查
        if any(keyword in text for keyword in ['format', 'pattern', 'match', 'valid']):
            regex_pattern = self._extract_regex_from_text(text)
            if regex_pattern:
                return 'regex', {
                    'operator': 'matches',
                    'value': regex_pattern
                }

        # 10. 相等性检查
        if operation == 'must_equal':
            return 'equality', {
                'operator': '==',
                'value': expected_value
            }

        # 11. 范围检查
        if operation in ['minimum_value', 'maximum_value']:
            return 'range', {
                'operator': '>=' if operation == 'minimum_value' else '<=',
                'value': expected_value
            }

        # 12. 包含检查
        if 'contain' in text or 'include' in text:
            return 'contains', {
                'operator': 'contains',
                'value': expected_value
            }

        # 13. 条件规则（if-then）
        if 'if' in text and ('then' in text or 'must' in text):
            return 'conditional', {
                'operator': 'if_then',
                'conditions': self._parse_conditional(text)
            }

        # 14. 使用RAG参考推断
        if rag_reference and len(rag_reference) > 0:
            top_ref = rag_reference[0]
            if 'logic_type' in top_ref:
                app_logger.info(f"Using logic type from RAG: {top_ref['logic_type']}")
                return top_ref['logic_type'], {
                    'operator': 'custom',
                    'custom_code': f"// Inferred from similar lint: {top_ref.get('lint_name')}\n// TODO: Customize"
                }

        # 15. 默认：复杂规则（需要自定义代码）
        return 'custom', {
            'operator': 'custom',
            'custom_code': f'// TODO: Implement custom logic for: {text[:100]}'
        }

    def _extract_time_operator(self, text: str) -> str:
        """从文本提取时间操作符"""
        if 'maximum' in text or 'no more than' in text or 'at most' in text:
            return '<='
        elif 'minimum' in text or 'at least' in text:
            return '>='
        return '=='

    def _extract_time_value(self, text: str) -> str:
        """从文本提取时间值"""
        # 提取数字+单位
        import re
        match = re.search(r'(\d+)\s*(day|month|year)', text)
        if match:
            return f"{match.group(1)} {match.group(2)}s"
        return "unknown"

    def _extract_condition_field(self, text: str) -> str:
        """提取条件字段"""
        # 简化实现
        if 'ca' in text.lower():
            return 'c.IsCA'
        return 'unknown_field'

    def _extract_required_field(self, text: str) -> str:
        """提取必需字段"""
        if 'basicconstraints' in text.lower():
            return 'c.BasicConstraintsValid'
        return 'unknown_field'

    def _extract_oid_list(self, text: str, rag_reference: Optional[List[Dict]] = None) -> str:
        """提取OID列表"""
        # 可以从RAG参考中提取常见的OID列表
        if rag_reference:
            # 从相似lint的实现中提取OID
            pass
        return "[]"  # 返回空列表，待实现

    def _extract_encoding_type(self, text: str) -> str:
        """提取编码类型"""
        if 'utf8' in text.lower():
            return 'UTF8String'
        elif 'printable' in text.lower():
            return 'PrintableString'
        elif 'ia5' in text.lower():
            return 'IA5String'
        return 'DER'

    def _extract_length_operator(self, text: str) -> str:
        """提取长度操作符"""
        if 'maximum' in text or 'no more than' in text:
            return '<='
        elif 'minimum' in text or 'at least' in text:
            return '>='
        return '=='

    def _extract_length_value(self, text: str) -> str:
        """提取长度值"""
        import re
        match = re.search(r'(\d+)', text)
        if match:
            return match.group(1)
        return "0"

    def _extract_value_from_text(self, text: str) -> str:
        """从规则文本中提取期望值（用于conditional_presence等）"""
        # 简化实现：提取引号中的内容或must contain/must be后的内容
        import re

        # 尝试提取引号中的内容
        quoted = re.search(r'"([^"]+)"', text)
        if quoted:
            return quoted.group(1)

        # 尝试提取must contain后的内容
        if 'must contain' in text.lower():
            idx = text.lower().index('must contain') + len('must contain')
            snippet = text[idx:idx+50].strip()
            # 提取第一个单词或短语
            words = snippet.split()
            if words:
                return words[0].strip('.,;')

        return ""

    def _extract_value_type(self, text: str) -> str:
        """
        从"if the value is a/an X"模式中提取值类型

        示例：
        - "if the value is a Fully-Qualified Domain Name" → "FQDN"
        - "if the value is an IP address" → "IP"

        Args:
            text: 规则文本

        Returns:
            值类型标识符
        """
        import re

        # 尝试匹配 "if the value is a/an [TYPE]"
        pattern = r'if\s+the\s+value\s+is\s+(?:a|an)\s+([^,\.]+)'
        match = re.search(pattern, text.lower())

        if match:
            value_type = match.group(1).strip()

            # 标准化常见类型
            type_mapping = {
                'fully-qualified domain name': 'FQDN',
                'fully qualified domain name': 'FQDN',
                'wildcard domain name': 'Wildcard',
                'ip address': 'IP',
                'ipaddress': 'IP',
                'email address': 'Email',
                'uri': 'URI',
                'uniform resource identifier': 'URI',
            }

            return type_mapping.get(value_type, value_type)

        return ""

    def _extract_either_or_options(self, text: str) -> str:
        """
        从"either X or Y"模式中提取选项

        示例：
        - "must contain either a Fully-Qualified Domain Name or Wildcard Domain Name"
          → "FQDN,Wildcard"

        Args:
            text: 规则文本

        Returns:
            逗号分隔的选项列表
        """
        import re

        # 尝试匹配 "either X or Y"
        pattern = r'either\s+(?:a|an)\s+([^,]+?)\s+or\s+(?:a|an)?\s*([^,\.]+)'
        match = re.search(pattern, text.lower())

        if match:
            option1 = match.group(1).strip()
            option2 = match.group(2).strip()

            # 标准化
            type_mapping = {
                'fully-qualified domain name': 'FQDN',
                'fully qualified domain name': 'FQDN',
                'wildcard domain name': 'Wildcard',
                'ip address': 'IP',
            }

            option1 = type_mapping.get(option1, option1)
            option2 = type_mapping.get(option2, option2)

            return f"{option1},{option2}"

        return ""

    def _extract_regex_from_text(self, text: str) -> str:
        """从规则文本中提取正则表达式"""
        # 这里可以使用LLM来提取，暂时返回空
        return ''

    def _parse_conditional(self, text: str) -> List[Dict]:
        """解析条件规则"""
        # 简单的条件解析，实际可以使用LLM
        return [
            {
                'condition': 'TODO: parse condition',
                'action': 'TODO: parse action'
            }
        ]

    def _infer_error_level(self, rule: Dict) -> str:
        """推断错误级别"""
        text = rule.get('text', '').lower()

        # MUST = Error
        if 'must' in text or 'shall' in text or 'required' in text:
            return 'Error'

        # SHOULD = Warn
        if 'should' in text or 'recommended' in text:
            return 'Warn'

        # MAY = Notice
        if 'may' in text or 'optional' in text:
            return 'Notice'

        return 'Error'  # 默认

    def _detect_assertion_subject(self, rule: Dict) -> str:
        """
        检测规则的断言主体

        改进版：区分CA操作行为、证书内容约束、CRL规则

        核心原则：
        - "CA must issue certificates with X" → Certificate（约束证书内容）
        - "CA must verify Y" → CA（约束CA行为）
        - "CRL must contain..." → CRL（约束CRL内容）

        Args:
            rule: 规则字典

        Returns:
            "Certificate" | "CA" | "RP" | "CRL"
        """
        text = rule.get('text', '').lower()

        # CRL关键词（优先级最高）
        # 如果规则明确提到CRL对象本身的约束，则是CRL规则
        crl_keywords = [
            'crl must', 'crls must',
            'crl shall', 'crls shall',
            'crl should', 'crls should',
            'revocation list must', 'revocation lists must',
            'revocation list shall', 'revocation lists shall',
            'this crl', 'the crl',
            'each crl', 'every crl',
            'two crls', 'multiple crls',
            'crl issuer', 'crl number',
            'this update', 'next update',  # CRL专有字段
            'in the crl', 'in crls',
            'delta crl', 'base crl',
            'crl entry', 'crl entries',  # CRL条目
            'crl extension', 'crl extensions',  # CRL扩展
        ]

        # 检查是否是CRL规则
        for keyword in crl_keywords:
            if keyword in text:
                return "CRL"

        # 证书内容约束的模式（优先级第二）
        # 这些模式说明规则约束的是证书本身，而不是CA的操作
        certificate_constraint_patterns = [
            'certificate must', 'certificates must',
            'certificate shall', 'certificates shall',
            'certificate should', 'certificates should',
            'must be present', 'must contain',
            'must have', 'must include',
            'shall be present', 'shall contain',
            'shall have', 'shall include',
            'must not be present', 'must not contain',
            'shall not be present', 'shall not contain',
            'must be true', 'must be false',
            'must be set', 'shall be set',
            'must be identical', 'shall be identical',
            # CA发证但约束证书内容的模式
            'ca must issue certificates with',
            'ca must issue certificates that',
            'ca shall issue certificates with',
            'ca shall issue certificates that',
            'certificates issued by',
            'issued certificates must',
            'issued certificates shall',
            # 字段级约束
            'extension must', 'extension shall',
            'field must', 'field shall',
            'value must', 'value shall',
            'subject must', 'issuer must',
            'validity must', 'serial number must',
            # 证书字段名直接约束（如"cA MUST be"）
            'ca must be',  # basicConstraints.cA字段
            'pathlenconstraint must',
            'keyusage must', 'extendedkeyusage must',
            'basicconstraints must',
            'subjectkeyidentifier must',
            'authoritykeyidentifier must',
            'authoritycertissuer must',
            'authoritycertserialnum must',
        ]

        # 检查是否是证书内容约束
        for pattern in certificate_constraint_patterns:
            if pattern in text:
                return "Certificate"

        # Relying Party关键词
        rp_keywords = [
            'relying party', 'application must', 'client must', 'client shall',
            'verifier must', 'verifier shall',
            'validator must', 'validator shall'
        ]

        # 检查是否是RP行为
        for keyword in rp_keywords:
            if keyword in text:
                return "RP"

        # CA操作行为关键词（必须是操作动词，不包括issue）
        ca_operation_keywords = [
            'ca performs', 'ca verifies', 'ca validates',
            'ca ensures', 'ca checks', 'ca confirms',
            'ca maintains', 'ca records', 'ca monitors',
            'ca revokes', 'ca suspends',
            'ca publishes', 'ca distributes',
            'ca archives', 'ca protects',
            'ca audits', 'ca reviews',
            'certification authority performs',
            'certification authority verifies',
        ]

        # 检查是否是CA操作行为
        for keyword in ca_operation_keywords:
            if keyword in text:
                return "CA"

        # 默认：证书断言
        # 原则：当不确定时，优先假设是证书约束，因为zlint主要检查证书
        return "Certificate"

    def _detect_external_dependency(self, rule: Dict) -> Dict:
        """
        检测规则是否依赖外部系统/验证

        改进版v2：区分证书字段引用 vs 外部系统访问

        核心原则：
        - "CRL Distribution Points extension MUST..." → 证书字段检查（无外部依赖）
        - "CA must check CRL before..." → 外部CRL访问（有外部依赖）

        Args:
            rule: 规则字典

        Returns:
            external_dependency字典
        """
        text = rule.get('text', '').lower()

        # ===== Step 1: 证书字段引用排除模式（优先级最高）=====
        # 如果规则提到这些，说明是检查证书字段，不是外部依赖
        certificate_field_patterns = [
            # CRL相关字段
            'crl distribution points extension',
            'crldistributionpoints extension',
            'crl distribution point',
            'issuing distribution point extension',
            'issuingdistributionpoint extension',
            'freshest crl extension',
            'crl number extension',

            # OCSP相关字段
            'ocsp-nocheck extension',
            'id-pkix-ocsp-nocheck',
            'authority information access',
            'authorityinformationaccess',

            # 其他撤销相关字段
            'revocation reason',
            'invalidity date',
        ]

        # 检查是否匹配证书字段模式
        for pattern in certificate_field_patterns:
            if pattern in text:
                # 这是证书字段检查，不是外部依赖
                return {
                    "has_external_ref": False,
                    "dependency_type": None,
                    "description": ""
                }

        # ===== Step 2: 外部依赖模式检测 =====
        # 只有在不匹配证书字段模式时，才检查外部依赖

        external_patterns = {
            'manual_verification': [
                'identity verification', 'organization verification', 'domain validation',
                'verify identity', 'verify organization', 'validate domain',
                'manual verification', 'human verification',
                '身份验证', '组织验证', '人工验证'
            ],
            'database': [
                'database', 'registry', 'repository', 'whois',
                'government database', 'ca database', 'subscriber database'
            ],
            'ocsp': [
                'ocsp response',  # 更严格：只检测OCSP响应/服务
                'ocsp server',
                'ocsp responder',
                'check ocsp',
                'query ocsp',
                'online certificate status protocol'
            ],
            'crl': [
                'crl entry',  # 更严格：CRL条目、CRL发布
                'crl must',
                'generate crl',
                'publish crl',
                'ca must.*crl',  # CA must ... CRL (操作)
                'check.*crl',  # check ... CRL
                'verify.*crl',
                'revoked certificates.*crl'
            ],
            'ct_log': ['ct log', 'certificate transparency log'],
            'external_system': [
                'external system', 'third-party', 'third party',
                'validation service', 'verification service'
            ],
            'business_process': [
                'audit', 'business process', 'operational requirement',
                '业务流程', '审计'
            ]
        }

        # 检查每种依赖类型
        for dep_type, keywords in external_patterns.items():
            for keyword in keywords:
                # 使用正则匹配（对于带.*的模式）
                if '.*' in keyword:
                    import re
                    if re.search(keyword, text):
                        return {
                            "has_external_ref": True,
                            "dependency_type": dep_type,
                            "description": f"Detected pattern '{keyword}' - requires {dep_type}"
                        }
                else:
                    if keyword in text:
                        return {
                            "has_external_ref": True,
                            "dependency_type": dep_type,
                            "description": f"Detected '{keyword}' - requires {dep_type}"
                        }

        # 无外部依赖
        return {
            "has_external_ref": False,
            "dependency_type": None,
            "description": ""
        }

    def _assess_determinism(self, rule: Dict) -> Dict:
        """
        评估规则的确定性

        改进版：在特定上下文中，某些词不算模糊

        Args:
            rule: 规则字典

        Returns:
            determinism字典
        """
        text = rule.get('text', '').lower()

        # 模糊词检测
        vague_terms_patterns = [
            'reasonable', 'appropriate', 'suitable', 'adequate',
            'sufficient', 'proper', 'correct', 'acceptable',
            'meaningful', 'secure', 'strong', 'weak',
            '合理', '适当', '恰当', '充分'
        ]

        # 在特定上下文中不算模糊的词
        # 例如："valid"在"validity period"上下文中不模糊
        context_specific_ok_words = {
            'valid': ['validity', 'validity period', 'valid certificate'],
        }

        vague_terms = []
        for term in vague_terms_patterns:
            if term in text:
                vague_terms.append(term)

        # 检查context_specific_ok_words
        for word, contexts in context_specific_ok_words.items():
            if word in text:
                # 检查是否在允许的上下文中
                in_valid_context = any(ctx in text for ctx in contexts)
                if not in_valid_context:
                    vague_terms.append(word)

        # 代词检测（需要上下文）
        pronoun_pattern = r'\b(it|this|that|these|those|they|them|their|its)\b'
        requires_context = bool(re.search(pronoun_pattern, text))

        # 计算确定性置信度
        confidence = 1.0

        # 每个模糊词扣0.15
        confidence -= len(vague_terms) * 0.15

        # 需要上下文扣0.2
        if requires_context:
            confidence -= 0.2

        # 检查是否有明确的数值/具体值
        has_concrete_value = bool(re.search(r'\d+', text))
        if has_concrete_value:
            confidence += 0.1

        # 限制在0-1范围
        confidence = max(0.0, min(1.0, confidence))

        # 判断是否确定性（放宽标准）
        is_deterministic = (
            len(vague_terms) <= 1 and  # 允许最多1个模糊词
            confidence >= 0.6  # 降低置信度阈值从0.7到0.6
        )

        return {
            "is_deterministic": is_deterministic,
            "vague_terms": vague_terms,
            "requires_context": requires_context,
            "confidence": round(confidence, 2)
        }

    def determine_zlint_lintability(self, ir: Dict, rule_text: str = None) -> Dict:
        """Delegate lintability to the canonical four-condition framework."""
        from app.services.certificate.lintability import judge_lintability
        result = judge_lintability(ir)
        return {
            "can_generate": result.get("can_generate", False),
            "reason": result.get("explanation", ""),
            "failed_step": result.get("failed_step"),
        }


    def to_json(self) -> str:
        """导出为JSON格式"""
        return json.dumps(self.ir, indent=2, ensure_ascii=False)


class AdvancedZLintCodeGenerator:
    """
    Advanced ZLint Code Generator
    Complete pipeline: Rule → IR → Go Code → Test
    """

    def __init__(self):
        self.zlint_path = Path(settings.zlint_path) if hasattr(settings, 'zlint_path') else None
        self.ir_generator = IntermediateRepresentation()

    def generate_from_rule(self, rule: Dict) -> Tuple[str, str, str, Dict]:
        """
        Generate complete zlint code from rule

        Args:
            rule: Rule dictionary

        Returns:
            (go_code, test_code, ir_json, metadata)
        """
        # Step 1: Generate IR
        ir = self.ir_generator.from_rule(rule)
        ir_json = self.ir_generator.to_json()

        # Step 2: Generate Go code from IR
        go_code = self._generate_go_code_from_ir(ir)

        # Step 3: Generate test code from IR
        test_code = self._generate_test_code_from_ir(ir)

        # Step 4: Generate metadata
        metadata = {
            'lint_name': ir['lint_name'],
            'package': self._get_package_name(ir['source']),
            'file_path': str(self._get_file_path(ir)),
            'test_file_path': str(self._get_test_file_path(ir)),
            'logic_type': ir['logic']['type']
        }

        return go_code, test_code, ir_json, metadata

    def _generate_go_code_from_ir(self, ir: Dict) -> str:
        """Generate Go code from IR"""
        lint_name = ir['lint_name']
        struct_name = self._to_camel_case(lint_name)
        package_name = self._get_package_name(ir['source'])

        # Generate code based on logic type
        check_applies_body = self._generate_check_applies_from_ir(ir)
        execute_body = self._generate_execute_from_ir(ir)

        # Determine additional imports based on logic type
        additional_imports = []
        logic_type = ir.get('logic', {}).get('type', '')

        if logic_type in ['format', 'contains']:
            additional_imports.append('\t"strings"')
        if logic_type == 'regex':
            additional_imports.append('\t"regexp"')
        if logic_type in ['time', 'time_based']:
            additional_imports.append('\t"time"')

        # Build import block
        import_lines = [
            '\t"github.com/zmap/zcrypto/x509"',
            '\t"github.com/zmap/zlint/v3/lint"',
            '\t"github.com/zmap/zlint/v3/util"'
        ]
        import_lines.extend(additional_imports)
        import_block = '\n'.join(import_lines)

        code = f'''package {package_name}

/*
 * zlint Copyright 2025 Regents of the University of Michigan
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy
 * of the License at http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
 * implied. See the License for the specific language governing
 * permissions and limitations under the License.
 */

import (
{import_block}
)

type {struct_name} struct{{}}

/************************************************
{ir['description']}
************************************************/

func init() {{
\tlint.RegisterCertificateLint(&lint.CertificateLint{{
\t\tLintMetadata: lint.LintMetadata{{
\t\t\tName:          "{lint_name}",
\t\t\tDescription:   "{self._escape_string(ir['description'][:100])}",
\t\t\tCitation:      "{ir['citation']}",
\t\t\tSource:        lint.{ir['source']},
\t\t\tEffectiveDate: util.{ir['effective_date']},
\t\t}},
\t\tLint: New{struct_name},
\t}})
}}

func New{struct_name}() lint.LintInterface {{
\treturn &{struct_name}{{}}
}}

func (l *{struct_name}) CheckApplies(c *x509.Certificate) bool {{
{check_applies_body}
}}

func (l *{struct_name}) Execute(c *x509.Certificate) *lint.LintResult {{
{execute_body}
}}
'''
        return code

    def _generate_check_applies_from_ir(self, ir: Dict) -> str:
        """Generate CheckApplies function body"""
        applies_to = ir.get('applies_to', 'Subscriber')

        if applies_to == 'CA':
            return '\treturn util.IsExtInCert(c, util.CertPolicyOID) && c.IsCA'
        elif applies_to == 'Subscriber':
            return '\treturn util.IsSubscriberCert(c)'
        else:
            return '\treturn true'

    def _generate_execute_from_ir(self, ir: Dict) -> str:
        """Generate Execute function body based on logic type"""
        logic = ir['logic']
        logic_type = logic['type']
        operator = logic.get('operator', '')
        value = logic.get('value', '')
        target_field = ir['target_field']
        error_level = ir['error_level']

        # Map error level to lint status
        status = 'lint.Error' if error_level == 'Error' else 'lint.Warn'

        if logic_type == 'presence':
            if operator == 'exists':
                return f'''\tif {target_field} == nil {{
\t\treturn &lint.LintResult{{Status: {status}}}
\t}}
\treturn &lint.LintResult{{Status: lint.Pass}}'''
            elif operator == 'not_exists':
                return f'''\tif {target_field} != nil {{
\t\treturn &lint.LintResult{{Status: {status}}}
\t}}
\treturn &lint.LintResult{{Status: lint.Pass}}'''
            elif operator == 'critical':
                ext_name = target_field.replace('c.', '')
                return f'''\text := util.GetExtFromCert(c, util.{ext_name}OID)
\tif ext != nil && !ext.Critical {{
\t\treturn &lint.LintResult{{Status: {status}}}
\t}}
\treturn &lint.LintResult{{Status: lint.Pass}}'''

        elif logic_type == 'equality':
            return f'''\tif {target_field} != {value} {{
\t\treturn &lint.LintResult{{Status: {status}}}
\t}}
\treturn &lint.LintResult{{Status: lint.Pass}}'''

        elif logic_type == 'range':
            return f'''\tif !({target_field} {operator} {value}) {{
\t\treturn &lint.LintResult{{Status: {status}}}
\t}}
\treturn &lint.LintResult{{Status: lint.Pass}}'''

        elif logic_type == 'regex':
            return f'''\tmatched, _ := regexp.MatchString(`{value}`, {target_field})
\tif !matched {{
\t\treturn &lint.LintResult{{Status: {status}}}
\t}}
\treturn &lint.LintResult{{Status: lint.Pass}}'''

        elif logic_type == 'format':
            # Format检查：字符串格式验证、禁止字符检查等
            if operator == 'must_not_contain':
                # 检查字段是否包含禁止的字符/字符串
                # 需要判断target_field是单个字符串还是数组
                if 'DNSNames' in target_field or 'EmailAddresses' in target_field or '[]' in target_field:
                    # 数组类型：遍历每个元素
                    return f'''\tfor _, value := range {target_field} {{
\t\tif strings.Contains(value, "{value}") {{
\t\t\treturn &lint.LintResult{{Status: {status}}}
\t\t}}
\t}}
\treturn &lint.LintResult{{Status: lint.Pass}}'''
                else:
                    # 单个字符串
                    return f'''\tif strings.Contains({target_field}, "{value}") {{
\t\treturn &lint.LintResult{{Status: {status}}}
\t}}
\treturn &lint.LintResult{{Status: lint.Pass}}'''
            elif operator == 'must_contain':
                # 检查字段必须包含某个字符/字符串
                if 'DNSNames' in target_field or 'EmailAddresses' in target_field or '[]' in target_field:
                    return f'''\tfor _, value := range {target_field} {{
\t\tif !strings.Contains(value, "{value}") {{
\t\t\treturn &lint.LintResult{{Status: {status}}}
\t\t}}
\t}}
\treturn &lint.LintResult{{Status: lint.Pass}}'''
                else:
                    return f'''\tif !strings.Contains({target_field}, "{value}") {{
\t\treturn &lint.LintResult{{Status: {status}}}
\t}}
\treturn &lint.LintResult{{Status: lint.Pass}}'''
            else:
                # 其他format operator，使用自定义代码
                return f'''\t// Format check: {operator}
\t// TODO: Implement format validation for operator '{operator}'
\treturn &lint.LintResult{{Status: lint.NA}}'''

        elif logic_type == 'contains':
            # Contains检查（类似format，但更通用）
            if operator == 'contains':
                return f'''\tif !strings.Contains({target_field}, "{value}") {{
\t\treturn &lint.LintResult{{Status: {status}}}
\t}}
\treturn &lint.LintResult{{Status: lint.Pass}}'''
            elif operator == 'not_contains':
                return f'''\tif strings.Contains({target_field}, "{value}") {{
\t\treturn &lint.LintResult{{Status: {status}}}
\t}}
\treturn &lint.LintResult{{Status: lint.Pass}}'''

        elif logic_type == 'length':
            # Length检查
            if operator == '==':
                return f'''\tif len({target_field}) != {value} {{
\t\treturn &lint.LintResult{{Status: {status}}}
\t}}
\treturn &lint.LintResult{{Status: lint.Pass}}'''
            elif operator == '>':
                return f'''\tif len({target_field}) <= {value} {{
\t\treturn &lint.LintResult{{Status: {status}}}
\t}}
\treturn &lint.LintResult{{Status: lint.Pass}}'''
            elif operator == '<':
                return f'''\tif len({target_field}) >= {value} {{
\t\treturn &lint.LintResult{{Status: {status}}}
\t}}
\treturn &lint.LintResult{{Status: lint.Pass}}'''

        else:
            # Custom or complex logic
            custom_code = logic.get('custom_code', '// TODO: Implement custom logic')
            return f'''\t// Custom logic for {logic_type}
\t{custom_code}
\t// TODO: Implement complete validation
\treturn &lint.LintResult{{Status: lint.NA}}'''

    def _generate_test_code_from_ir(self, ir: Dict) -> str:
        """Generate test code from IR"""
        lint_name = ir['lint_name']
        struct_name = self._to_camel_case(lint_name)
        package_name = self._get_package_name(ir['source'])

        test_code = f'''package {package_name}

import (
\t"testing"
\t"github.com/zmap/zlint/v3/lint"
\t"github.com/zmap/zlint/v3/test"
)

func TestNew{struct_name}(t *testing.T) {{
\tl := New{struct_name}()
\tif l == nil {{
\t\tt.Fatalf("expected non-nil lint")
\t}}
}}

func Test{struct_name}(t *testing.T) {{
\t// TODO: Add test cases
\t// Example test structure:
\t// testCases := []struct {{
\t//     name     string
\t//     filename string
\t//     want     lint.LintStatus
\t// }}{{
\t//     {{
\t//         name:     "valid certificate",
\t//         filename: "validCert.pem",
\t//         want:     lint.Pass,
\t//     }},
\t//     {{
\t//         name:     "invalid certificate",
\t//         filename: "invalidCert.pem",
\t//         want:     lint.Error,
\t//     }},
\t// }}
\t//
\t// for _, tc := range testCases {{
\t//     t.Run(tc.name, func(t *testing.T) {{
\t//         result := test.TestLint("{lint_name}", tc.filename)
\t//         if result.Status != tc.want {{
\t//             t.Errorf("expected %v, got %v", tc.want, result.Status)
\t//         }}
\t//     }})
\t// }}
}}
'''
        return test_code

    def save_generated_code(self, go_code: str, test_code: str, metadata: Dict) -> Dict:
        """Save generated code to files"""
        try:
            result = {
                'success': True,
                'errors': []
            }

            # Save Go file
            go_file = Path(metadata['file_path'])
            if go_file.parent.exists():
                go_file.write_text(go_code, encoding='utf-8')
                result['go_file'] = str(go_file)
                app_logger.info(f"Saved Go file: {go_file}")
            else:
                result['errors'].append(f"Directory does not exist: {go_file.parent}")
                result['success'] = False

            # Save test file
            test_file = Path(metadata['test_file_path'])
            if test_file.parent.exists():
                test_file.write_text(test_code, encoding='utf-8')
                result['test_file'] = str(test_file)
                app_logger.info(f"Saved test file: {test_file}")
            else:
                result['errors'].append(f"Directory does not exist: {test_file.parent}")
                result['success'] = False

            return result

        except Exception as e:
            app_logger.error(f"Error saving files: {e}")
            return {
                'success': False,
                'errors': [str(e)]
            }

    def _get_package_name(self, source: str) -> str:
        """
        Get package name from source with fuzzy matching

        支持的映射：
        - RFC* → rfc
        - CABF-Server, CABFBaselineRequirements → cabf_br
        - CABF-EV, CABFEVGuidelines → cabf_ev
        - CABF-SMIME → cabf_smime
        - Mozilla* → mozilla
        - Apple* → apple
        - 其他 → community
        """
        if not source:
            return 'community'

        source_upper = source.upper()

        # RFC标准
        if 'RFC' in source_upper:
            return 'rfc'

        # CA/B Forum - Baseline Requirements (Server Authentication)
        if any(x in source_upper for x in ['CABF-SERVER', 'CABFBASELINEREQUIREMENTS', 'BASELINE']):
            return 'cabf_br'

        # CA/B Forum - Extended Validation
        if any(x in source_upper for x in ['CABF-EV', 'CABFEVGUIDELINES', 'EV']):
            return 'cabf_ev'

        # CA/B Forum - S/MIME
        if 'SMIME' in source_upper or 'S/MIME' in source_upper:
            return 'cabf_smime'

        # Mozilla Root Store Policy
        if 'MOZILLA' in source_upper:
            return 'mozilla'

        # Apple Root Store Policy
        if 'APPLE' in source_upper:
            return 'apple'

        # 默认归类为community
        return 'community'

    def _get_file_path(self, ir: Dict) -> Path:
        """Get file path for generated code"""
        package = self._get_package_name(ir['source'])
        lint_name = ir['lint_name']

        if self.zlint_path:
            return self.zlint_path / 'v3' / 'lint' / package / f'{lint_name}.go'
        else:
            return Path(f'./generated/{package}/{lint_name}.go')

    def _get_test_file_path(self, ir: Dict) -> Path:
        """Get test file path"""
        file_path = self._get_file_path(ir)
        return file_path.parent / f'{file_path.stem}_test.go'

    def _to_camel_case(self, snake_str: str) -> str:
        """Convert snake_case to CamelCase"""
        # 先将连字符替换为下划线（Go标识符不能包含连字符）
        snake_str = snake_str.replace('-', '_')
        components = snake_str.split('_')
        return ''.join(x.title() for x in components)

    def _escape_string(self, s: str) -> str:
        """Escape string for Go code"""
        return s.replace('"', '\\"').replace('\n', ' ')

