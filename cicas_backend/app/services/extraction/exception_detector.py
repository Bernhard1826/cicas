"""
例外规则检测器（Exception Pattern Detector）

职责：
1. 从规则文本中检测RFC/CABF规范的例外句式
2. 自动生成候选ExceptionRuleIR
3. 不是白名单，而是基于句式模板的结构化提取

设计原则：
- 直接对齐真实规范文本
- 不做语义推理，只做模式匹配
- 输出候选供后续处理

真实示例来源：
- RFC 5280 §4.1.2.6: "unless the subjectAltName extension is present"
- RFC 5280 §4.2.1.6: "only if such identities are present"
- CABF BR: "except for domains validated under Enterprise RA"
"""

import re
from typing import List, Dict, Any, Optional, Tuple
from dataclasses import dataclass

from app.core.logging_config import app_logger
from app.core.unified_abstractions import (
    ExceptionRuleIR,
    ExceptionPattern,
    ExceptionEffect,
    ExceptionScope,
    SourceSpan,
    ConditionSet
)


@dataclass
class ExceptionCandidate:
    """例外候选（检测结果）"""
    pattern: ExceptionPattern
    matched_text: str
    start_pos: int
    end_pos: int
    exception_clause: str  # 例外条件文本（e.g., "the subjectAltName extension is present"）
    main_rule_text: str    # 主规则文本（例外前的部分）


class ExceptionPatternDetector:
    """
    例外句式模板检测器

    基于真实RFC/CABF文本的句式模板，自动检测例外规则。
    """

    # ========== 句式模板定义 ==========
    # 每个模板包含：正则表达式、捕获组说明
    PATTERN_TEMPLATES = {
        # 示例1: "MUST be present unless the subjectAltName extension is present and marked critical"
        ExceptionPattern.UNLESS: [
            r"(?P<main_rule>.*?)\s+unless\s+(?P<exception_clause>[^.;]+)",
            r"(?P<main_rule>.*?)\s+except\s+when\s+(?P<exception_clause>[^.;]+)",
            r"(?P<main_rule>.*?)\s+except\s+where\s+(?P<exception_clause>[^.;]+)",
        ],

        # 示例2: "MUST use the rfc822Name only if such identities are present"
        ExceptionPattern.ONLY_IF: [
            r"(?P<main_rule>.*?)\s+only\s+if\s+(?P<exception_clause>[^.;]+)",
            r"(?P<main_rule>.*?)\s+if\s+and\s+only\s+if\s+(?P<exception_clause>[^.;]+)",
        ],

        # 示例3: "This requirement does not apply to self-signed certificates"
        ExceptionPattern.DOES_NOT_APPLY_TO: [
            r"(?P<main_rule>.*?)\s+does\s+not\s+apply\s+to\s+(?P<exception_clause>[^.;]+)",
            r"(?P<main_rule>.*?)\s+shall\s+not\s+apply\s+to\s+(?P<exception_clause>[^.;]+)",
            r"(?P<main_rule>.*?)\s+must\s+not\s+apply\s+to\s+(?P<exception_clause>[^.;]+)",
        ],

        # 示例4: "CAs SHALL verify domain control except for domains validated under Enterprise RA"
        ExceptionPattern.EXCEPT: [
            r"(?P<main_rule>.*?)\s+except\s+for\s+(?P<exception_clause>[^.;]+)",
            r"(?P<main_rule>.*?)\s+except\s+in\s+(?P<exception_clause>[^.;]+)",
            r"(?P<main_rule>.*?)\s+with\s+the\s+exception\s+of\s+(?P<exception_clause>[^.;]+)",
        ],

        # 示例5: "In the case of a Key Compromise, the CA MUST revoke within 24 hours"
        ExceptionPattern.IN_CASE_OF: [
            r"in\s+the\s+case\s+of\s+(?P<exception_clause>[^,]+),\s+(?P<main_rule>[^.;]+)",
            r"in\s+cases?\s+where\s+(?P<exception_clause>[^,]+),\s+(?P<main_rule>[^.;]+)",
        ],

        # 其他变体
        ExceptionPattern.OTHER_THAN: [
            r"(?P<main_rule>.*?)\s+other\s+than\s+(?P<exception_clause>[^.;]+)",
        ],

        ExceptionPattern.MAY_BE_IGNORED_IF: [
            r"(?P<main_rule>.*?)\s+may\s+be\s+ignored\s+if\s+(?P<exception_clause>[^.;]+)",
            r"(?P<main_rule>.*?)\s+can\s+be\s+omitted\s+if\s+(?P<exception_clause>[^.;]+)",
        ],
    }

    def __init__(self):
        """初始化检测器"""
        self.logger = app_logger

        # 编译所有正则表达式（性能优化）
        self.compiled_patterns: Dict[ExceptionPattern, List[re.Pattern]] = {}
        for pattern_type, regex_list in self.PATTERN_TEMPLATES.items():
            self.compiled_patterns[pattern_type] = [
                re.compile(regex, re.IGNORECASE | re.DOTALL)
                for regex in regex_list
            ]

    def detect_exceptions(
        self,
        rule_text: str,
        context: Optional[str] = None
    ) -> List[ExceptionCandidate]:
        """
        检测规则文本中的例外句式

        Args:
            rule_text: 规则文本（可能包含例外）
            context: 可选的上下文文本

        Returns:
            例外候选列表
        """
        candidates = []

        # 对每种模式进行匹配
        for pattern_type, regex_list in self.compiled_patterns.items():
            for regex in regex_list:
                matches = regex.finditer(rule_text)
                for match in matches:
                    candidate = self._extract_candidate(
                        pattern_type,
                        match,
                        rule_text
                    )
                    if candidate:
                        candidates.append(candidate)

        if candidates:
            self.logger.debug(
                f"Detected {len(candidates)} exception candidates in rule text"
            )

        return candidates

    def _extract_candidate(
        self,
        pattern_type: ExceptionPattern,
        match: re.Match,
        full_text: str
    ) -> Optional[ExceptionCandidate]:
        """
        从正则匹配中提取例外候选

        Args:
            pattern_type: 例外模式类型
            match: 正则匹配对象
            full_text: 完整文本

        Returns:
            例外候选或None
        """
        try:
            groups = match.groupdict()
            main_rule = groups.get("main_rule", "").strip()
            exception_clause = groups.get("exception_clause", "").strip()

            if not exception_clause:
                return None

            # 对于IN_CASE_OF模式，main_rule和exception_clause位置相反
            if pattern_type == ExceptionPattern.IN_CASE_OF:
                # "in the case of X, Y" -> exception_clause=X, main_rule=Y
                pass

            candidate = ExceptionCandidate(
                pattern=pattern_type,
                matched_text=match.group(0),
                start_pos=match.start(),
                end_pos=match.end(),
                exception_clause=exception_clause,
                main_rule_text=main_rule
            )

            return candidate

        except Exception as e:
            self.logger.warning(f"Failed to extract exception candidate: {e}")
            return None

    def build_exception_ir(
        self,
        candidate: ExceptionCandidate,
        target_rule_id: str,
        document_id: str,
        section_id: Optional[str] = None,
        full_context: str = ""
    ) -> ExceptionRuleIR:
        """
        从候选构建ExceptionRuleIR

        Args:
            candidate: 例外候选
            target_rule_id: 目标规则ID
            document_id: 文档ID
            section_id: 章节ID
            full_context: 完整上下文

        Returns:
            ExceptionRuleIR实例
        """
        # 推断例外效果和作用域
        effect = self._infer_exception_effect(candidate)
        scope = self._infer_exception_scope(candidate)

        # 提取上下文
        context_start = max(0, candidate.start_pos - 50)
        context_end = min(len(full_context), candidate.end_pos + 50)
        context_before = full_context[context_start:candidate.start_pos]
        context_after = full_context[candidate.end_pos:context_end]

        # 构建SourceSpan
        source_span = SourceSpan(
            start_char=candidate.start_pos,
            end_char=candidate.end_pos,
            matched_text=candidate.matched_text,
            context_before=context_before,
            context_after=context_after
        )

        # 解析例外条件（简化版，后续可扩展）
        condition_set = self._parse_exception_condition(candidate)

        # 生成例外ID
        exception_id = f"{target_rule_id}-exception-{candidate.pattern.value}"

        return ExceptionRuleIR(
            exception_id=exception_id,
            target_rule_id=target_rule_id,
            pattern=candidate.pattern,
            effect=effect,
            scope=scope,
            condition_set=condition_set,
            document_id=document_id,
            section_id=section_id,
            source_span=source_span,
            justification=f"Exception detected: {candidate.exception_clause}",
            auto_detected=True,
            confidence=0.9,  # 基于模板匹配，置信度较高
            needs_review=False  # 第一版不需要审核
        )

    def _infer_exception_effect(
        self,
        candidate: ExceptionCandidate
    ) -> ExceptionEffect:
        """
        推断例外效果

        Args:
            candidate: 例外候选

        Returns:
            例外效果类型
        """
        pattern = candidate.pattern

        # 基于句式模式映射效果
        effect_mapping = {
            ExceptionPattern.UNLESS: ExceptionEffect.NEGATE,
            ExceptionPattern.ONLY_IF: ExceptionEffect.ADD_CONDITION,
            ExceptionPattern.DOES_NOT_APPLY_TO: ExceptionEffect.NEGATE,
            ExceptionPattern.EXCEPT: ExceptionEffect.NEGATE,
            ExceptionPattern.IN_CASE_OF: ExceptionEffect.ADD_CONDITION,
            ExceptionPattern.OTHER_THAN: ExceptionEffect.NEGATE,
            ExceptionPattern.MAY_BE_IGNORED_IF: ExceptionEffect.RELAX,
        }

        return effect_mapping.get(pattern, ExceptionEffect.NEGATE)

    def _infer_exception_scope(
        self,
        candidate: ExceptionCandidate
    ) -> ExceptionScope:
        """
        推断例外作用域

        Args:
            candidate: 例外候选

        Returns:
            例外作用域类型
        """
        exception_text = candidate.exception_clause.lower()

        # 关键词映射（按优先级排序，特异性高的在前）

        # 1. 验证方法相关（高优先级）
        if "enterprise ra" in exception_text or ("enterprise" in exception_text and "ra" in exception_text):
            return ExceptionScope.VALIDATION_METHOD

        if "validation" in exception_text and ("method" in exception_text or "procedure" in exception_text):
            return ExceptionScope.VALIDATION_METHOD

        # 2. 证书类型相关
        if "self-signed" in exception_text or "root certificate" in exception_text:
            return ExceptionScope.CERTIFICATE_TYPE

        if "ca certificate" in exception_text or "subscriber certificate" in exception_text:
            return ExceptionScope.CERTIFICATE_TYPE

        # 3. 扩展相关
        if "extension" in exception_text:
            return ExceptionScope.EXTENSION

        # 4. 字段相关
        if "field" in exception_text or "subject" in exception_text:
            return ExceptionScope.FIELD

        # 5. 时间周期相关（优先级较低，避免误判）
        if ("before" in exception_text or "after" in exception_text) and "date" in exception_text:
            return ExceptionScope.TIME_PERIOD

        # 6. 配置/Profile相关
        if "profile" in exception_text or "configuration" in exception_text:
            return ExceptionScope.PROFILE

        # 默认为全局
        return ExceptionScope.GLOBAL

    def _parse_exception_condition(
        self,
        candidate: ExceptionCandidate
    ) -> ConditionSet:
        """
        解析例外条件为结构化ConditionSet

        简化版：提取关键实体作为条件
        未来可扩展为完整的NLP解析

        Args:
            candidate: 例外候选

        Returns:
            条件集合
        """
        exception_text = candidate.exception_clause.lower()
        conditions = []

        # 简单的实体识别（基于关键词）
        # 示例1: "the subjectAltName extension is present and marked critical"
        if "subjectaltname" in exception_text or "subject alternative name" in exception_text:
            conditions.append({
                "field": "extensions.subjectAltName",
                "predicate": "must_be_present",
                "source": "exception_clause"
            })

            if "critical" in exception_text:
                conditions.append({
                    "field": "extensions.subjectAltName.critical",
                    "predicate": "equal",
                    "value": True,
                    "source": "exception_clause"
                })

        # 示例2: "self-signed certificates"
        if "self-signed" in exception_text:
            conditions.append({
                "field": "certificate_type",
                "predicate": "equal",
                "value": "self-signed",
                "source": "exception_clause"
            })

        # 示例3: "email identity present"
        if "email" in exception_text and "present" in exception_text:
            conditions.append({
                "field": "email_identity",
                "predicate": "must_be_present",
                "source": "exception_clause"
            })

        # 示例4: "Enterprise RA"
        if "enterprise" in exception_text and "ra" in exception_text:
            conditions.append({
                "field": "validation_method",
                "predicate": "equal",
                "value": "Enterprise_RA",
                "source": "exception_clause"
            })

        # 示例5: "Key Compromise"
        if "key compromise" in exception_text or "compromise" in exception_text:
            conditions.append({
                "field": "revocation_reason",
                "predicate": "equal",
                "value": "keyCompromise",
                "source": "exception_clause"
            })

        # 如果没有解析到条件，创建一个占位符
        if not conditions:
            conditions.append({
                "field": "unknown",
                "predicate": "matches_pattern",
                "value": candidate.exception_clause,
                "source": "exception_clause",
                "needs_manual_review": True
            })

        return ConditionSet(
            conditions=conditions,
            logic="AND"  # 默认AND逻辑
        )


# ========== 获取单例 ==========

_detector_instance: Optional[ExceptionPatternDetector] = None


def get_exception_detector() -> ExceptionPatternDetector:
    """
    获取例外检测器单例

    Returns:
        ExceptionPatternDetector实例
    """
    global _detector_instance
    if _detector_instance is None:
        _detector_instance = ExceptionPatternDetector()
    return _detector_instance
