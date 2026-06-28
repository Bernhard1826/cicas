"""
IR Field Source Guard

检查 LLM 生成的 Go 代码是否引用了 IR 中未声明的字段。
规则：Go 代码里的 `c.Field` 必须出现在 IR 的 `subject` 字段列表中。
不在列表中的引用 → 标记为 IR 外字段违规（降级为失败而非直接过滤）。
"""
import re
from typing import Dict, List, Set, Any, Tuple
from dataclasses import dataclass

from .zlint_generator import CodeGenResult


# zlint/zcrypto 允许的字段白名单（任何 LLM 都可引用这些基础字段，
# 不要求它们出现在每条规则的 IR subject 中）
ALLOWED_GLOBAL_FIELDS: Set[str] = {
    # 基础元数据/方法
    "SerialNumber", "SignatureAlgorithm", "Signature", "TBSCertificate",
    "Extensions", "ExtB", "IsCA", "MaxPathLen", "MaxPathLenZero",
    "KeyUsage", "PublicKeyAlgorithm", "PublicKey",
    # Subject / Issuer
    "Subject", "Issuer", "RawSubject", "RawIssuer",
    # 时间
    "NotBefore", "NotAfter", "Validity",
    # 证书类型便捷方法
    "IsSubscriberCert", "IsCACert", "IsSelfSigned",
    # 扩展便捷方法（不直接是字段但 LLM 可能写）
    "ExtCrit", "ExtPresent",
}

# zlint/zlint/v3/lint/global.go:58+ 中允许的工具函数
ALLOWED_UTIL_FUNCTIONS: Set[str] = {
    "IsExtInCert", "IsExtNotInCert",
    "IsExtPresent", "IsExtNotPresent",
    "IsSubscriberCert", "IsCACert",
    "IsAnySubCA", "IsSelfSigned",
    "KeyUsageHas", "KeyUsageNotHas",
    "ExtKeyUsageHas", "ExtKeyUsageNotHas",
    "SerialNumberHex",
    "SpkiParse",
    "DigSHA1", "DigSHA256", "DigSHA384", "DigSHA512",
    "TimeBefore", "TimeAfter",
    "GeneralNamesInclude", "GeneralNamesHasDNS",
    "GeneralNamesHasEmail", "GeneralNamesHasIP",
    "GeneralNamesHasURI", "GeneralNamesHasOtherName",
    "EKUHas", "EKUHasNoServerAuth",
}


@dataclass
class FieldGuardResult:
    """检查结果"""
    ok: bool                    # True = 所有字段都在 IR 中
    violations: List[Tuple[str, str]]  # (field, reason)
    referenced_fields: Set[str]  # 代码中所有引用的字段
    ir_subject_fields: Set[str]  # IR 中声明的主语字段
    go_code: str                # 原始代码（或降级后的错误消息）
    error: str = ""            # 错误消息


def _extract_go_field_refs(go_code: str) -> Set[str]:
    """
    从 Go 代码中提取所有 `c.Field` 形式的字段引用。
    忽略方法调用 `c.Method()` 和切片 `c.List[idx]`。
    """
    refs = set()
    # 匹配 c.Xxx 但排除 c.Xxx( 和 c.Xxx[ 和 c.Xxx.
    # 只取标识符：c. 后面跟字母/数字/下划线
    pattern = re.compile(r'\bc\.([A-Za-z_][A-Za-z0-9_]*)\b')
    for match in pattern.finditer(go_code):
        field = match.group(1)
        # 跳过已经是允许工具函数的情况
        if field not in ALLOWED_UTIL_FUNCTIONS:
            refs.add(field)
    return refs


def _normalize_field_for_ir_comparison(field: str) -> Set[str]:
    """
    字段名可能有多种变体，返回其在 IR subject 中的等价名集合。
    例如 "Subject" 的子字段可能是 "Subject.CommonName"、"Subject.Organization" 等。
    """
    return {field}


def _fields_in_ir_subject(field: str, ir_subject: Any) -> bool:
    """
    检查 field 是否出现在 IR subject 中。
    ir_subject 可能是字符串列表、字典、或嵌套结构。
    """
    if ir_subject is None:
        return False

    # 列表形式：["subject.Subject", "subject.CommonName", ...]
    if isinstance(ir_subject, list):
        for item in ir_subject:
            if isinstance(item, str):
                # 支持精确匹配和前缀匹配
                # "Extensions.BasicConstraints" 包含 "Extensions"
                if item == field:
                    return True
                # "Subject.CommonName" → 允许 "Subject"
                if item.startswith(field + "."):
                    return True
                # "Extensions.SubjectAlternateName" → 允许 "Extensions"
                if field.startswith(item + "."):
                    return True
        return False

    # 字典形式：{"subject.Subject": {...}, ...}
    if isinstance(ir_subject, dict):
        for key in ir_subject:
            if key == field:
                return True
            if key.startswith(field + "."):
                return True
            if field.startswith(key + "."):
                return True
        return False

    # 字符串形式（空格分隔或逗号分隔）
    if isinstance(ir_subject, str):
        parts = re.split(r'[,;\s]+', ir_subject)
        for part in parts:
            part = part.strip()
            if part == field or part.endswith("." + field) or field.endswith("." + part):
                return True
        return False

    return False


def check_ir_field_guard(go_code: str, ir: Dict[str, Any]) -> FieldGuardResult:
    """
    主检查函数：验证 Go 代码中的字段引用都来自 IR 的 subject 字段。

    Args:
        go_code: LLM 生成的 Go 代码
        ir: 完整的 IR dict

    Returns:
        FieldGuardResult: ok=True 表示全部合规；ok=False 时 violations 列出违规字段
    """
    if not go_code:
        return FieldGuardResult(
            ok=True,
            violations=[],
            referenced_fields=set(),
            ir_subject_fields=set(),
            go_code="",
        )

    # 1. 提取所有 c.Xxx 字段引用
    referenced = _extract_go_field_refs(go_code)

    # 2. 收集 IR subject 字段
    # IR 结构：ir["subject"] 或 ir["constraint"]["subject"] 或 ir["ir"]["subject"]
    ir_subject = None
    if "subject" in ir:
        ir_subject = ir["subject"]
    elif "constraint" in ir and isinstance(ir["constraint"], dict) and "subject" in ir["constraint"]:
        ir_subject = ir["constraint"]["subject"]

    # 解析为集合
    ir_fields: Set[str] = set()
    if ir_subject is not None:
        if isinstance(ir_subject, list):
            ir_fields = {str(x) for x in ir_subject}
        elif isinstance(ir_subject, dict):
            ir_fields = {str(k) for k in ir_subject}
        elif isinstance(ir_subject, str):
            ir_fields = {s.strip() for s in re.split(r'[,;\s]+', ir_subject) if s.strip()}

    # 3. 逐字段检查
    violations = []
    for field in sorted(referenced):
        # 允许全局基础字段（不在 subject 列表中也能用）
        if field in ALLOWED_GLOBAL_FIELDS:
            continue
        # 允许工具函数
        if field in ALLOWED_UTIL_FUNCTIONS:
            continue
        # 检查是否在 IR subject 中
        if not _fields_in_ir_subject(field, ir_subject):
            violations.append((field, f"字段 '{field}' 未出现在 IR subject 声明中"))

    ok = len(violations) == 0
    return FieldGuardResult(
        ok=ok,
        violations=violations,
        referenced_fields=referenced,
        ir_subject_fields=ir_fields,
        go_code=go_code,
    )


def apply_ir_field_guard(result, ir: Dict[str, Any]) -> Tuple[Dict, Dict]:
    """
    对 ZlintCodeGenerator.generate() 的结果应用字段守卫。

    如果发现 IR 外字段引用：
    - 记录违规到 metadata（不直接过滤，让路由决定降级策略）
    - 如果有严重违规（超过阈值），可以把 go_code 改为 error placeholder

    Args:
        result: ZlintCodeGenerator.generate() 返回的 CodeGenResult
        ir: 原始 IR dict

    Returns:
        (modified_result, guard_result): 修改后的 result 和守卫结果
    """
    if not result.success or not result.go_code:
        return result, FieldGuardResult(
            ok=True, violations=[], referenced_fields=set(),
            ir_subject_fields=set(), go_code="", error="no code to check"
        )

    guard = check_ir_field_guard(result.go_code, ir)

    # 把守卫结果注入 metadata
    metadata = dict(result.metadata or {})
    metadata["ir_field_guard"] = {
        "ok": guard.ok,
        "violations": [
            {"field": f, "reason": r} for f, r in guard.violations
        ],
        "referenced_fields": sorted(guard.referenced_fields),
        "ir_subject_fields": sorted(guard.ir_subject_fields),
    }

    # 严重违规（引用了 >3 个 IR 外字段）→ 降级为失败
    severe_violations = [
        v for v in guard.violations
        if v[0] not in ALLOWED_GLOBAL_FIELDS and v[0] not in ALLOWED_UTIL_FUNCTIONS
    ]
    if len(severe_violations) > 3:
        return CodeGenResult(
            rule_id=result.rule_id,
            lint_name=result.lint_name,
            lint_subclass=result.lint_subclass,
            success=False,
            go_code=None,
            test_code=None,
            metadata=metadata,
            llm_params=result.llm_params,
            error=(
                f"LLM 生成的代码引用了 IR 之外的字段: "
                f"{', '.join(v[0] for v in severe_violations)}"
            ),
            attempts=result.attempts,
            generation_time_ms=result.generation_time_ms,
            description_from_ir=result.description_from_ir,
        ), guard
    else:
        # 有少量违规但不够严重 → 保留代码但在 metadata 标记警告
        # 让调用方决定是否接受
        result.metadata = metadata
        return result, guard