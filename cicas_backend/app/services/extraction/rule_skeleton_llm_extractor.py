"""
阶段 B：LLM 规则理解层
基于规则骨架（rule skeleton）进行语义理解和 IR 填充

职责：
1. 接收规则骨架 + 上下文
2. 条件补全
3. 指代消解
4. 语义归一化
5. IR 字段填充
6. 判断是否可转为 zlint

禁止：
- 合并多条规则
- 判断规则"重要性"而省略
- 认为规则"重复"而去重
- 自由提取规则（规则发现已由 Stage A 完成）
"""
import json
import re
import requests
from typing import List, Dict, Any, Optional
from app.services.extraction.context_builder import RuleContext
from app.services.extraction.ir_schema import (
    ExtractionResult,
    IntermediateRepresentation,
    IRStage,
    IRConstraint,
    IRProvenance,
    IRReference,
    ObligationType,
    PredicateType,
    ConstraintType,
    # RuleCategory已删除 - 现在使用 AssertionSubject + EnforcementPhase
)
from datetime import datetime
from app.core.logging_config import app_logger
from app.core.config import settings


class RuleSkeletonLLMExtractor:
    """
    基于规则骨架的 LLM 提取器

    设计原则：
    - 输入单位是"规则"而非"文本块"
    - 一条规则对应一条 IR 输出
    - LLM 决定 IR 语义质量下限
    """

    def __init__(self, api_key: str = None, base_url: str = None, model: str = None):
        """
        初始化 LLM 提取器

        Args:
            api_key: API密钥
            base_url: API基础URL
            model: 模型名称
        """
        self.api_key = api_key or settings.llm_api_key
        self.base_url = base_url or settings.llm_api_base
        self.model = model or settings.llm_model

        # 获取模型的上下文窗口大小
        self.context_window = settings.llm_context_window

        if not self.api_key:
            app_logger.warning("LLM API key not configured. LLM extraction will be disabled.")
            self.enabled = False
            return

        self.enabled = True
        self.api_endpoint = f"{self.base_url.rstrip('/')}/chat/completions"

        # 编译引用提取的正则模式（Stage B: 只提取原始文本）
        self._compile_reference_patterns()

        app_logger.info(f"[RuleSkeletonLLMExtractor] Initialized: {self.api_endpoint} / {self.model}")

    def _compile_reference_patterns(self):
        """编译引用提取的正则模式（复用 EnhancedReferenceResolver 的模式）"""
        self.reference_patterns = {
            # RFC + Section: "RFC 5280 Section 4.2.1.3"
            'rfc_section': re.compile(
                r'\b(RFC\s+\d+)\s*,?\s*[Ss]ection\s+([\d.]+)',
                re.IGNORECASE
            ),
            # RFC only: "RFC 5280"
            'rfc_only': re.compile(
                r'\b(RFC\s+\d+)\b',
                re.IGNORECASE
            ),
            # CABF section: "CA/Browser Forum Baseline Requirements Section 7.1.2"
            'cabf_section': re.compile(
                r'\b(CA/Browser Forum|CABF|Baseline Requirements?|BRs?)\s+.*?[Ss]ection\s+([\d.]+)',
                re.IGNORECASE
            ),
            # Section only (隐式引用): "Section 4.2.1.3"
            'section_only': re.compile(
                r'\b[Ss]ection\s+([\d.]+)\b'
            ),
            # "see Section X", "as defined in Section X"
            'contextual_section': re.compile(
                r'\b(see|as\s+defined\s+in|as\s+specified\s+in|according\s+to)\s+[Ss]ection\s+([\d.]+)\b',
                re.IGNORECASE
            ),
        }

    def _extract_references_from_text(self, text: str) -> List[IRReference]:
        """
        从文本中提取引用（Stage B：只提取原始文本，不解析）

        Args:
            text: 规则文本

        Returns:
            引用列表（只填充 raw 字段，resolved=False）
        """
        references = []
        seen_raw = set()  # 去重

        # 按优先级提取（先精确的，后模糊的）

        # 1. RFC + Section（最精确）
        for match in self.reference_patterns['rfc_section'].finditer(text):
            raw = match.group(0)
            if raw not in seen_raw:
                ref = IRReference(
                    raw=raw,
                    doc_id=None,  # Stage B 不解析
                    section=None,
                    resolved=False
                )
                references.append(ref)
                seen_raw.add(raw)

        # 2. CABF Section
        for match in self.reference_patterns['cabf_section'].finditer(text):
            raw = match.group(0)
            if raw not in seen_raw:
                ref = IRReference(
                    raw=raw,
                    doc_id=None,
                    section=None,
                    resolved=False
                )
                references.append(ref)
                seen_raw.add(raw)

        # 3. Contextual section ("see Section X")
        for match in self.reference_patterns['contextual_section'].finditer(text):
            raw = match.group(0)
            if raw not in seen_raw:
                ref = IRReference(
                    raw=raw,
                    doc_id=None,
                    section=None,
                    resolved=False
                )
                references.append(ref)
                seen_raw.add(raw)

        # 4. Section only（隐式引用，需要上下文）
        for match in self.reference_patterns['section_only'].finditer(text):
            raw = match.group(0)
            # 避免重复提取（可能已经被 contextual_section 捕获）
            if raw not in seen_raw:
                ref = IRReference(
                    raw=raw,
                    doc_id=None,
                    section=None,
                    resolved=False
                )
                references.append(ref)
                seen_raw.add(raw)

        # 5. RFC only（文档级引用，没有具体章节）
        for match in self.reference_patterns['rfc_only'].finditer(text):
            raw = match.group(0)
            # 避免重复（可能已经被 rfc_section 捕获）
            if raw not in seen_raw:
                ref = IRReference(
                    raw=raw,
                    doc_id=None,
                    section=None,
                    resolved=False
                )
                references.append(ref)
                seen_raw.add(raw)

        app_logger.debug(f"[RuleSkeletonLLMExtractor] Extracted {len(references)} references from text")
        return references

    def extract_batch(
        self,
        contexts: List[RuleContext]
    ) -> List[ExtractionResult]:
        """
        批量提取规则 IR

        Args:
            contexts: 规则上下文列表

        Returns:
            提取结果列表（每条规则对应一条 IR）
        """
        if not self.enabled:
            app_logger.warning("[RuleSkeletonLLMExtractor] LLM disabled, skipping extraction")
            return []

        if not contexts:
            return []

        # 构建 prompt
        prompt = self._build_batch_prompt(contexts)

        # 调用 LLM（动态计算输出token）
        try:
            response = self._call_llm(prompt, batch_size=len(contexts))
            rules_data = self._parse_llm_response(response)

            # 日志监控：记录 LLM 返回的规则数量
            diff = len(rules_data) - len(contexts)

            # 计算差异程度
            if len(contexts) > 0:
                diff_ratio = abs(diff) / len(contexts)
            else:
                diff_ratio = 0

            # 根据差异程度选择日志级别
            # - 完全匹配：INFO
            # - 差异1-2条且比例<10%：DEBUG（LLM可能合并了重复规则，这是正常的）
            # - 差异>2条或比例>=10%：WARNING（可能有问题）
            if diff == 0:
                app_logger.info(
                    f"[RuleSkeletonLLMExtractor] LLM returned {len(rules_data)} rules for {len(contexts)} input skeletons (exact match)"
                )
                # 数量一致，不需要打印原始输出
            elif abs(diff) <= 2 and diff_ratio < 0.1:
                app_logger.debug(
                    f"[RuleSkeletonLLMExtractor] LLM returned {len(rules_data)} rules for {len(contexts)} input skeletons "
                    f"(diff: {diff:+d}, likely merged duplicates)"
                )
                # 差异较小，打印LLM原始输出以供分析
                app_logger.debug(
                    f"[LLM RAW OUTPUT] ========== START ==========\n"
                    f"{response}\n"
                    f"[LLM RAW OUTPUT] ========== END =========="
                )
            else:
                # 严重不匹配：详细输出诊断信息
                app_logger.warning(
                    f"[RuleSkeletonLLMExtractor] LLM returned {len(rules_data)} rules but expected {len(contexts)} rules "
                    f"(diff: {diff:+d}, ratio: {diff_ratio:.1%})"
                )

                # 打印完整的LLM原始输出（重要：用于诊断严重不匹配）
                app_logger.warning(
                    f"[LLM RAW OUTPUT] ========== START ==========\n"
                    f"{response}\n"
                    f"[LLM RAW OUTPUT] ========== END =========="
                )

                # 详细诊断信息：对比输入和输出
                app_logger.warning("=" * 80)
                app_logger.warning(f"[DIAGNOSIS] Input vs Output Mismatch")
                app_logger.warning(f"  Expected: {len(contexts)} rules")
                app_logger.warning(f"  Got:      {len(rules_data)} rules")
                app_logger.warning(f"  Diff:     {diff:+d} rules ({diff_ratio:.1%})")
                app_logger.warning("=" * 80)

                # 打印所有输入规则（用于对比）
                app_logger.warning(f"[INPUT] Expected {len(contexts)} input skeletons:")
                for idx, context in enumerate(contexts, 1):
                    skeleton = context.skeleton
                    sentence_preview = skeleton.sentence[:80] + "..." if len(skeleton.sentence) > 80 else skeleton.sentence
                    app_logger.warning(
                        f"  IN-{idx:02d}: [{skeleton.keyword}] {sentence_preview}"
                    )

                app_logger.warning("-" * 80)

                # 打印所有输出规则
                app_logger.warning(f"[OUTPUT] LLM returned {len(rules_data)} rules:")
                for idx, rule_data in enumerate(rules_data, 1):
                    subject = rule_data.get('subject', 'N/A')
                    obligation = rule_data.get('obligation', 'N/A')
                    predicate = rule_data.get('predicate', 'N/A')
                    constraint_raw = rule_data.get('constraint', {}).get('raw_text', 'N/A')

                    # 截断长文本
                    if isinstance(constraint_raw, str) and len(constraint_raw) > 100:
                        constraint_raw = constraint_raw[:100] + "..."

                    app_logger.warning(
                        f"  OUT-{idx:02d}: [{obligation}] subject={subject}, predicate={predicate}"
                    )
                    app_logger.warning(
                        f"          raw_text={constraint_raw}"
                    )

                app_logger.warning("=" * 80)

                # 分析可能的原因
                if len(rules_data) > len(contexts):
                    app_logger.warning(
                        f"[ANALYSIS] LLM返回了 {len(rules_data) - len(contexts)} 条额外规则。"
                        f"可能原因："
                    )
                    app_logger.warning("  1. LLM拆分了复合句（一条输入拆成多条输出）")
                    app_logger.warning("  2. LLM从上下文中提取了额外规则")
                    app_logger.warning("  3. LLM重复提取了相同规则")
                    app_logger.warning("  建议：检查上述OUT日志，找出多余的规则来自哪里")
                elif len(rules_data) < len(contexts):
                    app_logger.warning(
                        f"[ANALYSIS] LLM少返回了 {len(contexts) - len(rules_data)} 条规则。"
                        f"可能原因："
                    )
                    app_logger.warning("  1. LLM合并了多条规则")
                    app_logger.warning("  2. LLM过滤掉了认为非规则的内容")
                    app_logger.warning("  3. LLM输出被截断（检查finish_reason）")
                    app_logger.warning("  建议：对比IN和OUT日志，找出缺失的规则")

                app_logger.warning("=" * 80)

            # ========== 总是打印输入输出对比 ==========
            app_logger.info("=" * 80)
            app_logger.info(f"[BATCH SUMMARY] Input: {len(contexts)} rules → Output: {len(rules_data)} rules")

            if len(rules_data) < len(contexts):
                app_logger.warning(f"  ✗ MISSING: {len(contexts) - len(rules_data)} rules not returned (LLM error)")
            elif len(rules_data) > len(contexts):
                app_logger.warning(f"  ✗ EXTRA: {len(rules_data) - len(contexts)} extra rules (will be discarded)")
            else:
                app_logger.info(f"  ✓ CORRECT: 1:1 mapping")

            app_logger.info("=" * 80)

            # 打印输入规则列表
            app_logger.info("[INPUT RULES]")
            for i, ctx in enumerate(contexts, 1):
                skeleton = ctx.skeleton
                app_logger.info(
                    f"  IN-{i:02d} | ID: {skeleton.rule_id} | "
                    f"Keyword: {skeleton.keyword} | "
                    f"Section: {skeleton.section or 'N/A'}"
                )
                app_logger.info(f"         Text: {skeleton.sentence[:100]}...")

            app_logger.info("-" * 80)

            # 打印输出规则列表
            app_logger.info("[OUTPUT RULES]")
            for i, rule_data in enumerate(rules_data, 1):
                constraint = rule_data.get('constraint', {})

                app_logger.info(
                    f"  OUT-{i:02d} | "
                    f"Subject: {rule_data.get('subject', 'N/A')} | "
                    f"Predicate: {rule_data.get('predicate', 'N/A')}"
                )
                app_logger.info(f"          Constraint: {constraint.get('raw_text', 'N/A')[:100]}...")

            app_logger.info("=" * 80)

            # 如果输出多于输入，详细分析被丢弃的规则
            if len(rules_data) > len(contexts):
                app_logger.warning("[DISCARDED RULES ANALYSIS]")
                for j in range(len(contexts), len(rules_data)):
                    discarded_rule = rules_data[j]
                    constraint = discarded_rule.get('constraint', {})
                    app_logger.warning(
                        f"\n[DISCARDED #{j + 1 - len(contexts)}] "
                        f"\n  Subject: {discarded_rule.get('subject', 'N/A')}"
                        f"\n  Predicate: {discarded_rule.get('predicate', 'N/A')}"
                        f"\n  Constraint: {constraint.get('raw_text', 'N/A')}"
                    )
                app_logger.warning("=" * 80)
                app_logger.warning(
                    "[ANALYSIS] 可能原因："
                    "\n  1. LLM 拆分了复合句（一条输入拆成多条输出）"
                    "\n  2. LLM 从上下文中提取了额外规则"
                    "\n  建议：检查上述 DISCARDED 规则，判断是否应该调整 prompt"
                )
                app_logger.warning("=" * 80)

            # 转换为 IR
            results = []
            for i, rule_data in enumerate(rules_data):
                if i >= len(contexts):
                    # 已经在上面详细打印过，这里直接 break
                    break

                context = contexts[i]
                ir = self._build_ir_from_llm_output(rule_data, context)

                if ir:
                    result = ExtractionResult(ir=ir)
                    results.append(result)

            app_logger.info(
                f"[RuleSkeletonLLMExtractor] Extracted {len(results)} IRs "
                f"from {len(contexts)} skeletons"
            )

            return results

        except requests.exceptions.Timeout:
            # 超时降级：如果批量太大，尝试拆分成更小的批次
            if len(contexts) > 2:
                app_logger.warning(
                    f"[RuleSkeletonLLMExtractor] Batch of {len(contexts)} timed out, splitting into smaller batches"
                )
                mid = len(contexts) // 2
                results1 = self.extract_batch(contexts[:mid])
                results2 = self.extract_batch(contexts[mid:])
                return results1 + results2
            else:
                app_logger.error(f"[RuleSkeletonLLMExtractor] Batch extraction timeout for {len(contexts)} rules")
                return []

        except Exception as e:
            app_logger.error(f"[RuleSkeletonLLMExtractor] Batch extraction error: {e}")
            return []

    def _build_batch_prompt(self, contexts: List[RuleContext]) -> str:
        """
        构建批量提取 prompt

        关键指令：
        1. 输入已经是确认存在的规则
        2. 禁止合并、省略、总结
        3. 一条规则对应一条 IR 输出
        """
        num_rules = len(contexts)

        prompt = f"""# Task: Technical Standards Rule IR Extraction

## CRITICAL INSTRUCTIONS (MUST FOLLOW)

**YOU WILL RECEIVE EXACTLY {num_rules} INPUT RULES.**

**OUTPUT REQUIREMENT - STRICT 1:1 MAPPING:**
- **MUST output EXACTLY {num_rules} rules** (one output per input)
- **DO NOT skip any rules** - every input must have a corresponding output
- **DO NOT create extra rules** - only process the input rules provided

## CRITICAL QUALITY REQUIREMENTS (NON-NEGOTIABLE)

**These requirements are MANDATORY. Failure to follow will result in rejected output.**

**⚠️ MOST COMMON MISTAKE TO AVOID:**
When you see rules like "the use of the DNS representation for Internet mail addresses MUST NOT be used", DO NOT extract "DNS representation" as the constraint value. Instead, extract the concrete pattern to check (e.g., "@" character). See Section 3.0.5 for detailed explanation.

### 0. X.509 Certificate Field Structure (REFERENCE)

When extracting rules from X.509/RFC 5280 standards, you MUST map abstract concepts in rule text to concrete certificate field paths. Use this reference structure:

**X.509 Certificate Field Hierarchy:**

```
Certificate (root)
├── version
├── serialNumber
├── signature (algorithm identifier)
├── issuer (Distinguished Name)
│   ├── commonName (CN)
│   ├── organizationName (O)
│   ├── organizationalUnitName (OU)
│   ├── countryName (C)
│   ├── stateOrProvinceName (ST)
│   ├── localityName (L)
│   ├── domainComponent (DC)        ← Note: "domain" in DN context
│   └── ... (other DN attributes)
├── validity
│   ├── notBefore
│   └── notAfter
├── subject (Distinguished Name)
│   ├── commonName (CN)
│   ├── domainComponent (DC)        ← Note: "domain" in DN context
│   └── ... (same structure as issuer)
├── subjectPublicKeyInfo
│   ├── algorithm
│   └── subjectPublicKey
├── issuerUniqueID (optional)
├── subjectUniqueID (optional)
└── extensions
    ├── basicConstraints
    │   ├── cA
    │   └── pathLenConstraint
    ├── keyUsage
    ├── extendedKeyUsage
    ├── subjectKeyIdentifier
    ├── authorityKeyIdentifier
    ├── subjectAltName
    │   ├── dNSName                  ← Note: "domain name" in SAN context
    │   ├── iPAddress
    │   ├── uniformResourceIdentifier (URI)
    │   ├── rfc822Name (email)
    │   ├── directoryName
    │   └── ... (other name forms)
    ├── issuerAltName
    │   └── ... (same structure as subjectAltName)
    ├── nameConstraints
    │   ├── permittedSubtrees
    │   └── excludedSubtrees
    ├── certificatePolicies
    ├── policyMappings
    ├── cRLDistributionPoints
    ├── authorityInfoAccess
    ├── ... (other extensions)
```

**CRITICAL: Disambiguating Common Terms**

When you encounter these ambiguous terms in rule text, use **section title** and **context** to determine the correct field:

| Rule Text Term | Possible Certificate Fields | How to Distinguish |
|----------------|---------------------------|-------------------|
| "domain name" | 1. `extensions.subjectAltName.dNSName`<br>2. `subject.domainComponent`<br>3. `issuer.domainComponent` | • Section "Subject Alternative Name" → dNSName<br>• Section "Subject DN" or "Issuer DN" → domainComponent<br>• Context mentions "DNS label" → dNSName |
| "name" | 1. `extensions.subjectAltName.dNSName`<br>2. `extensions.subjectAltName.uniformResourceIdentifier`<br>3. `subject` (entire DN)<br>4. `subject.commonName` | • Look at section title<br>• Check if qualified (e.g., "DNS name", "URI name") |
| "email" / "email address" / "emailAddress" / "electronic mail address" | 1. `extensions.subjectAltName.rfc822Name` ⚠️ **PRIMARY**<br>2. `subject.emailAddress` (deprecated) | • **DEFAULT**: rfc822Name (RFC 5280 recommendation)<br>• Section "Subject Alternative Name" → rfc822Name<br>• Explicitly mentions "subject DN" or "subject field" → subject.emailAddress<br>• **CRITICAL**: "conforming implementations...MUST use rfc822Name" → subject is rfc822Name! |
| "extension" | Specific extension (never use generic "extension") | • MUST identify which extension: basicConstraints, keyUsage, etc. |
| "flag" | Specific boolean field | • Identify parent field: basicConstraints.cA, keyUsage.digitalSignature, etc. |

**Subject Extraction Algorithm (RFC 5280 specific):**

**⚠️ CRITICAL: Extract subject based ONLY on rule text, NOT search context!**

**COMMON ERROR**: When searching for "dNSName", rules about URIs may appear in results.
DO NOT extract subject as "dNSName" just because that was the search keyword!
READ THE RULE TEXT CAREFULLY and extract the ACTUAL field mentioned.

**Bad Example**:
```
Search keyword: "dNSName"
Rule text: "The URI MUST NOT be a relative URI"
❌ WRONG: {{"subject": "extensions.subjectAltName.dNSName"}}  // Influenced by search!
✅ CORRECT: {{"subject": "extensions.subjectAltName.uniformResourceIdentifier"}}  // Based on rule text
```

**Subject Format Requirements:**

1. **MUST follow the path format**: `extensions.ExtensionName.FieldName` or special fields
   - ✅ Good: `extensions.subjectAltName.dNSName`
   - ✅ Good: `extensions.issuerAltName`
   - ❌ Bad: `issuerAltName_extension` (wrong format - no underscore!)
   - ❌ Bad: `ConformingCAs` (not a certificate field!)
   - ❌ Bad: `CA` (ambiguous - use `subject` or specific field)

2. **MUST be a concrete certificate field**, not a concept or entity:
   - ✅ Good: `extensions.subjectInfoAccess.Critical`
   - ✅ Good: `subject`
   - ❌ Bad: `ConformingCAs` (concept, not field)
   - ❌ Bad: `Applications` (software entity, not field)
   - ❌ Bad: `issuerAltName_extension` (wrong format)

3. **Special field names** (no "extensions." prefix):
   - `subject` (subject Distinguished Name)
   - `issuer` (issuer Distinguished Name)
   - `validity.notBefore`, `validity.notAfter`
   - `version`, `serialNumber`
   - `signatureAlgorithm`, `signatureValue`

**Extraction Steps:**

1. **Read Section Title**: Identify the certificate component being discussed
   - "4.2.1.6 Subject Alternative Name" → Base path: `extensions.subjectAltName`
   - "4.1.2.4 Issuer" → Base path: `issuer`
   - "4.1.2.5 Validity" → Base path: `validity`

2. **Identify Specific Field**: Look for field mentions in rule text
   - "the dNSName" → Append to base: `extensions.subjectAltName.dNSName`
   - "the notBefore field" → Full path: `validity.notBefore`

3. **Handle Generic Terms**: If rule uses "the field", "the value", "this extension"
   - Use section topic as subject: If section is about "Key Usage", subject is `extensions.keyUsage`

4. **Validate Path**: Ensure subject matches certificate structure above
   - ✅ `extensions.basicConstraints.cA`
   - ❌ `domainName` (missing hierarchy)
   - ❌ `labelConversion` (not a certificate field)

**Examples of Correct Subject Extraction:**

```json
// Rule: "domain name SHALL be considered a 'stored string'"
// Section: "7.2 Internationalized Domain Names in Subject Names"
// → This is about domainComponent in DN, not dNSName in SAN
{{
  "subject": "subject.domainComponent"  // Correct
  // NOT: "domainName"
}}

// Rule: "The name MUST include both a scheme and a scheme-specific-part"
// Section: "4.2.1.6 Subject Alternative Name"
// Context: Discussing URIs
{{
  "subject": "extensions.subjectAltName.uniformResourceIdentifier"  // Correct
  // NOT: "extensions.subjectAltName.name" (too generic)
}}

// Rule: "When the subjectAltName extension contains a domain name system label"
// Section: "4.2.1.6 Subject Alternative Name"
{{
  "subject": "extensions.subjectAltName.dNSName"  // Correct
}}

// Rule: "the implementation MUST perform the 'ToASCII' label conversion"
// Section: "7.3 Internationalized Domain Names in Distinguished Names"
// → This is about encoding DN components, not about a "labelConversion" field
{{
  "subject": "subject.domainComponent"  // Correct (the field being encoded)
  // NOT: "labelConversion" (not a certificate field)
}}
```

### 1. Subject Field Path (CRITICAL)
- **MUST** use complete hierarchical paths for technical fields/components
- **FORBIDDEN**: Generic terms like "field", "value", "component", "element" without specificity
- **REQUIRED FORMAT**: Use the hierarchical notation defined by the standard (e.g., `category.subcategory.fieldName`)
- **For behavioral rules**: Use the actor name (e.g., "CA", "Server", "Client", "Validator", etc.)

**Path Completeness Principle:**
- ✅ Use full path: `parent.child.grandchild` (if that's how the standard structures it)
- ❌ Use fragment: `grandchild` (loses context, creates ambiguity)

**Disambiguation Principle:**
- If the same field name appears in multiple contexts, the full path disambiguates
- Example: If "timestamp" appears in both "header.timestamp" and "body.timestamp", always use the full path

**Generic Term Avoidance:**
- ❌ "field" / "extension" / "attribute" / "component" → Too generic, provides no information
- ✅ Use the actual field name from the standard specification

**Subject Types:**
- **Technical Fields**: Use hierarchical path notation
- **Actors/Entities**: Use the entity name (e.g., "CA", "Server", "Manufacturer")
- **Processes**: May use the process name if the rule constrains the process itself

### 1.0.5 CRITICAL: "subject distinguished name" Mapping

**Common Mistake**: Confusing "subject distinguished name" with other fields

**Correct Mapping**:
- Rule mentions "subject distinguished name" → subject = `subject` (the entire DN)
- Rule mentions "subject field" → subject = `subject`
- Rule mentions "subject DN" → subject = `subject`
- Rule mentions "issuer distinguished name" → subject = `issuer`
- Rule mentions "issuer field" → subject = `issuer`

**WRONG Mappings to AVOID**:
- ❌ "subject distinguished name" → "CA" (CA is an entity, not a field!)
- ❌ "subject distinguished name" → "subjectAltName" (different extension)
- ❌ "subject field" → "subject identity" (not the same thing)

**Example**:
```
// Rule: "the subject distinguished name MUST be empty"
{{
  "subject": "subject",  // Correct - refers to the subject DN field
  // NOT: "CA", "subject identity", "subjectAltName"
}}
```

### 1.1. CRITICAL: URI vs dNSName Disambiguation

**Common Mistake**: Confusing URI rules with dNSName rules

When you see these keywords in rule text, the subject is likely about URI, NOT dNSName:
- "URI" / "uniform resource identifier"
- "scheme" / "scheme-specific-part"
- "authority component"
- "relative URI" / "absolute URI"
- "URL"

**Decision Rule:**
1. Does the rule text mention "URI", "URL", "scheme", or "authority"?
   → YES: subject = `extensions.subjectAltName.uniformResourceIdentifier`
   → NO: Continue to step 2

2. Does the section title contain "URI" or is the context about URIs?
   → YES: subject = `extensions.subjectAltName.uniformResourceIdentifier`
   → NO: May be dNSName (check for "DNS", "domain name system", "label")

**WRONG Examples (Learn from these mistakes):**
- ❌ Rule: "URIs that include an authority MUST include a fully qualified domain name"
  - Wrong: subject = "extensions.subjectAltName.dNSName"
  - Reason: Rule mentions "URIs" explicitly - this is about URI content, not dNSName
  - Correct: subject = "extensions.subjectAltName.uniformResourceIdentifier"

- ❌ Rule: "The name MUST NOT be a relative URI"
  - Wrong: subject = "extensions.subjectAltName.dNSName"
  - Reason: "relative URI" indicates this is about URI format, not dNSName
  - Correct: subject = "extensions.subjectAltName.uniformResourceIdentifier"

**CORRECT Examples:**
- ✅ Rule: "URIs that include an authority MUST include a fully qualified domain name"
  - Correct: subject = "extensions.subjectAltName.uniformResourceIdentifier"

- ✅ Rule: "The name MUST be in preferred name syntax per RFC1034"
  - Correct: subject = "extensions.subjectAltName.dNSName"
  - Reason: RFC1034 defines DNS name syntax, no mention of URI

### 2. Predicate Standardization (CRITICAL)
- **MUST** use ONLY predicates from the standard list below
- **FORBIDDEN**: Creating custom predicates or using free-form text
- **If no standard predicate fits**: Use the closest match, then explain in constraint.raw_text

**ALLOWED PREDICATES (EXHAUSTIVE LIST):**
- `must_be_present` - Field/extension must exist
- `must_not_be_present` - Field/extension must not exist
- `must_be_set` - Flag/boolean must be set to true/enabled
- `must_not_be_set` - Flag/boolean must NOT be set (must be false/disabled)
- `must_include` - Must contain specific value/element
- `must_not_include` - Must not contain specific value/element
- `equal` - Must equal specific value
- `not_equal` - Must not equal specific value
- `less_than` - Must be less than (use for "shorter than", "before")
- `less_than_or_equal` - Must be ≤ (use for "no more than", "not longer than", "up to")
- `greater_than` - Must be greater than (use for "longer than", "after")
- `greater_than_or_equal` - Must be ≥ (use for "at least", "minimum")
- `in_range` - Must be within range
- `matches_pattern` - Must match pattern/format
- `conform_to` - Must conform to specification
- `allowed_values` - Must be one of allowed values
- `forbidden_values` - Must not be one of forbidden values

**ANY OTHER PREDICATE WILL BE REJECTED.**

### 2.1. CRITICAL: Value Constraint vs Existence Constraint

**Common Mistake**: Using "must_not_be_present" when the rule is about a specific value

**Decision Rule:**
1. Does the rule specify a particular value that is forbidden/required?
   → YES: Use value-based predicate (equal, not_equal, must_include, must_not_include)
   → NO: Use existence-based predicate (must_be_present, must_not_be_present)

2. Look for these patterns indicating VALUE constraints:
   - "field of [value]" / "field with value [value]"
   - "equal to [value]"
   - "set to [value]"
   - "contain [value]"
   - Specific value mentioned in quotes or explicitly stated

3. Look for these patterns indicating EXISTENCE constraints:
   - "field must exist" / "field must be present"
   - "field must not exist" / "field must be absent"
   - No mention of specific values

**WRONG Examples (Learn from these mistakes):**
- ❌ Rule: "dNSName of ' ' MUST NOT be used"
  - Wrong: predicate = "must_not_be_present"
  - Reason: Rule specifies a particular value (' ') that is forbidden
  - Correct: predicate = "not_equal", constraint = {{"value": " ", "type": "string"}}

- ❌ Rule: "the flag MUST be set to false"
  - Wrong: predicate = "must_not_be_set"
  - Reason: Rule specifies the value (false) explicitly
  - Correct: predicate = "equal", constraint = {{"value": false, "type": "boolean"}}

**CORRECT Examples:**
- ✅ Rule: "dNSName of ' ' MUST NOT be used"
  - Correct: predicate = "not_equal", constraint = {{"value": " ", "type": "string"}}

- ✅ Rule: "the subjectAltName extension MUST be present"
  - Correct: predicate = "must_be_present"
  - Reason: No specific value mentioned, only existence

- ✅ Rule: "the cA flag MUST be set"
  - Correct: predicate = "must_be_set" (or "equal" with value=true)
  - Reason: "set" without specific value means true/enabled

### 3. Constraint Value Extraction (CRITICAL)
- **MUST** extract numeric values separately from units
- **MUST** populate `value` and `unit` fields whenever the rule contains measurable constraints
- **FORBIDDEN**: Leaving `value` as null when a numeric constraint exists
- **FORBIDDEN**: Extracting reference section numbers as constraint values (e.g., "3.5", "Section 4.2.1.6")
- **CORRECT**: Extract the actual specification/format/syntax referenced, not the reference itself

**Correct Examples:**
- ✅ "MUST NOT exceed 397 days" → {{"value": 397, "unit": "days", "type": "time_based"}}
- ✅ "at least 2048 bits" → {{"value": 2048, "unit": "bits", "type": "length"}}
- ✅ "longer than 20 octets" → {{"value": 20, "unit": "octets", "type": "length"}}
- ✅ "equal to 2" → {{"value": 2, "unit": null, "type": "numeric"}}
- ✅ "MUST be in preferred name syntax, as specified by Section 3.5 of [RFC1034]"
  → {{"type": "syntax", "value": "RFC1034 Section 3.5 preferred name syntax", "raw_text": "preferred name syntax per RFC1034 Section 3.5"}}
- ✅ "the AllowUnassigned flag SHALL NOT be set"
  → predicate: `must_not_be_set`, constraint: {{"type": "boolean", "value": false, "raw_text": "AllowUnassigned flag must not be set"}}

**Incorrect Examples:**
- ❌ "397 days" → {{"value": null, "raw_text": "397 days"}} (Missing value extraction!)
- ❌ {{"value": "2048 bits"}} (Value should be numeric, unit separate!)
- ❌ {{"value": "at least 2048"}} (Missing unit!)
- ❌ "MUST be in preferred name syntax, as specified by Section 3.5 of [RFC1034]"
  → {{"value": "3.5"}} (WRONG! Don't extract section numbers as values, extract the actual syntax spec!)
- ❌ "the AllowUnassigned flag SHALL NOT be set"
  → predicate: `shall_not` (WRONG! Use `must_not_be_set` for flag/boolean not-set scenarios)

### 3.0.5. CRITICAL: Email-in-DNS Pattern (EXTREMELY COMMON MISTAKE)

**⚠️ THIS IS ONE OF THE MOST COMMON EXTRACTION ERRORS. READ CAREFULLY! ⚠️**

**Rule Pattern:**
> "the use of the DNS representation for Internet mail addresses (subscriber.example.com instead of subscriber@example.com) MUST NOT be used"

**WRONG Extraction (DO NOT DO THIS):**
```json
{{
  "subject": "extensions.subjectAltName.dNSName",
  "predicate": "must_not_include",
  "constraint": {{
    "type": "format_validation",
    "value": "DNS representation"  // ❌ WRONG! This is descriptive text!
  }}
}}
```

**Why it's wrong:**
- "DNS representation" is a DESCRIPTION of the problem, not a checkable pattern
- You cannot check if something is a "DNS representation" directly
- The LLM will not be able to generate working code from this

**CORRECT Extraction (DO THIS):**
```json
{{
  "subject": "extensions.subjectAltName.dNSName",
  "predicate": "must_not_include",
  "logic": {{
    "type": "format",
    "operator": "must_not_contain"
  }},
  "constraint": {{
    "type": "string",
    "value": "@"  // ✅ CORRECT! Check for the @ character
  }}
}}
```

**Reasoning:**
1. Email addresses contain "@" character (e.g., subscriber@example.com)
2. DNS names do NOT contain "@" character (e.g., subscriber.example.com)
3. To detect "email in DNS format", check if dNSName contains "@"
4. If dNSName contains "@", it's using email format → violation

**Key Insight:**
- When the rule text describes a CONCEPT ("DNS representation for email")
- You must INFER the CONCRETE PATTERN to check ("@" character)
- Ask yourself: "What concrete string pattern distinguishes this case?"

**Similar Cases to Watch For:**
- "DNS representation" → check for "@"
- "relative URI" → check if starts with "/"
- "wildcard domain" → check for "*"
- "IP address format" → check for digits and dots pattern

**Remember:**
- Extract WHAT TO CHECK, not HOW TO DESCRIBE IT
- Descriptive text = ❌
- Concrete pattern = ✅

### 3.1. Avoid Descriptive Text as Constraint Value (CRITICAL)

**FORBIDDEN**: Extracting descriptive phrases, explanations, or permission statements as constraint values

**Descriptive Text Indicators**:
- Contains "may", "also", "other", "such as", "including" without specific values
- Phrases longer than 5 words that describe what something can contain
- Permission/allowance statements rather than validation conditions
- Generic descriptions of field content rather than concrete validation rules

**Correct Examples**:
- ✅ "signatureAlgorithm MUST be AlgorithmIdentifier"
  → {{"type": "type_constraint", "value": "AlgorithmIdentifier"}}
- ✅ "version MUST be 3"
  → {{"type": "numeric", "value": 3}}
- ✅ "cA MUST be set to false"
  → {{"type": "boolean", "value": false}}

**Incorrect Examples**:
- ❌ "other algorithms MAY also be supported"
  → {{"type": "string", "value": "MAY also be supported"}}  // WRONG! This is DESCRIPTIVE
  → This describes permission, not a validation constraint
  → Mark as external_reference or non-lintable instead

- ❌ "fully qualified domain name or IP address"
  → {{"type": "string", "value": "fully qualified domain name or IP address"}}  // WRONG!
  → This describes format, not a concrete value
  → Use: {{"type": "format_validation", "value": "FQDN_or_IP"}}

- ❌ "contains the identifier for the cryptographic algorithm"
  → {{"type": "string", "value": "identifier for the cryptographic algorithm"}}  // WRONG!
  → This DESCRIBES what the field contains, not WHAT to validate
  → This is descriptive, mark as non-lintable

- ❌ "the use of the DNS representation for Internet mail addresses MUST NOT be used"
  → {{"type": "string", "value": "DNS representation"}}  // WRONG!
  → "DNS representation" is descriptive, not a pattern to check
  → Correct: Extract the actual pattern - {{"type": "string", "value": "@"}} (check for @ in dNSName)
  → Reasoning: email addresses have @, DNS names don't - check for this concrete pattern

- ❌ "multiple name forms MAY be included"
  → {{"type": "string", "value": "multiple name forms"}}  // WRONG!
  → This is descriptive text, not a validation pattern
  → Correct: Mark as non-lintable (permission statement, no validation logic)

**Key Rule**: If the "value" describes WHAT the field contains rather than providing a SPECIFIC validation condition, it's descriptive and should NOT be extracted as the constraint value.

**Handling Descriptive Rules**:
1. If rule describes a concept but doesn't provide concrete validation pattern:
   - Try to infer the actual checkable pattern (e.g., "DNS representation for email" → check for "@")
   - If no concrete pattern can be inferred, mark as non-lintable with reason

### 3.2. External Specification References (CRITICAL)

When a rule references external documents as the source of allowed/forbidden values:

**Text Patterns**:
- "listed in [RFC/specification]"
- "[RFC1], [RFC2], and [RFC3] list..."
- "as specified in [external doc]"
- "defined by [external standard]"
- "algorithms/values from [RFC]"

**Correct Extraction**:
```json
{{
  "constraint": {{
    "type": "external_reference",
    "value": ["RFC3279", "RFC4055", "RFC4491"],  // List of referenced specs
    "raw_text": "algorithms listed in RFC3279, RFC4055, RFC4491"
  }}
}}
```

**Example**:
```
// Rule: "[RFC3279], [RFC4055], and [RFC4491] list supported signature
//        algorithms, but other signature algorithms MAY also be supported"

{{
  "subject": "signatureAlgorithm",
  "predicate": "must_be_in_list",
  "constraint": {{
    "type": "external_reference",
    "value": ["RFC3279", "RFC4055", "RFC4491"],
    "raw_text": "algorithms listed in RFC3279, RFC4055, RFC4491"
  }},
  "lint_severity": "Warning",  // Because of "MAY"
  "notes": "Additional algorithms beyond listed ones may be supported"
}}
```

**DO NOT extract**:
- ❌ "MAY also be supported" as the constraint value
- ❌ "other signature algorithms" as the value
- ❌ Descriptive phrases about what the specs contain

### 3.3. Format Validation Constraints (CRITICAL)

When a rule describes a format or pattern requirement:

**Text Patterns**:
- "MUST be a [format type]"
- "fully qualified domain name"
- "valid IP address"
- "X or Y format"
- "in the format [pattern]"
- "valid [type] format"

**Correct Extraction**:
```json
{{
  "constraint": {{
    "type": "format_validation",
    "value": "FQDN",  // Use canonical format identifier
    "raw_text": "fully qualified domain name"
  }}
}}
```

**Format Type Mapping**:
- "fully qualified domain name" → "FQDN"
- "IP address" → "IP"
- "FQDN or IP address" → "FQDN_or_IP"
- "domain name or IP" → "FQDN_or_IP"
- "URI" / "URL" → "URI"
- "email address" → "email"
- "OID" / "object identifier" → "OID"
- "UTC time" / "GeneralizedTime" → "time_format"
- "distinguished name" / "DN" → "DN"

**Example**:
```
// Rule: "URIs that include an authority MUST include a fully qualified
//        domain name or IP address as the host"

{{
  "subject": "extensions.subjectAltName.uniformResourceIdentifier",
  "predicate": "must_contain",
  "constraint": {{
    "type": "format_validation",
    "value": "FQDN_or_IP",
    "raw_text": "fully qualified domain name or IP address"
  }}
}}
```

**DO NOT extract**:
- ❌ "fully qualified domain name or IP address" as a string value
- ❌ Descriptive phrases as concrete validation values
- ❌ Format descriptions without canonical identifier

### 3.4. Concrete Constraint vs Descriptive Text (Decision Guide)

**Ask yourself**: "Can this be directly validated by inspecting the certificate?"

**Concrete Constraints** (EXTRACT as constraint value):
- ✅ Specific value: "MUST be 3", "MUST equal false"
- ✅ Specific type: "MUST be AlgorithmIdentifier"
- ✅ Numeric bound: "MUST NOT exceed 397 days"
- ✅ Presence check: "MUST be present", "MUST be absent"
- ✅ Format pattern: "MUST be FQDN", "MUST match [regex]"
- ✅ External list: "MUST be in list defined by RFC3279"

**Descriptive Text** (DO NOT extract as constraint value):
- ❌ Permission statement: "MAY also be supported", "can include"
- ❌ General description: "contains algorithm identifier"
- ❌ Abstract concept: "implement validation process"
- ❌ Open-ended: "other values may be present"
- ❌ Multi-word phrase without specific value: "such as domain name or IP"
- ❌ Explanation of what field does: "used to identify...", "represents..."

**When in doubt**:
- If the text has > 5 words and uses "or", "such as", "including" → likely descriptive
- If the text explains WHAT a field contains rather than HOW to validate → descriptive
- If you cannot write a simple if/else statement to check it → descriptive
- If it describes possibilities rather than requirements → descriptive

### 4. Single Rule Per Output (CRITICAL)
- **MUST** output exactly one normative statement per JSON object
- **If input contains multiple sentences**: Extract only the PRIMARY normative statement
- **FORBIDDEN**: Outputting table headers, descriptions, or multiple requirements in one IR

### 5. Special Pattern Recognition (CRITICAL)

**These patterns require special handling to generate correct IR:**

#### Pattern A: Extension Critical Property Check

When a rule states that an extension should be marked as critical or non-critical:

**Text Pattern**: "mark [extension_name] extension as (non-)critical"

**Examples**:
- "issuers SHOULD mark the issuerAltName extension as non-critical"
- "CAs MUST mark the basicConstraints extension as critical"

**Correct Extraction**:
```json
{{
  "subject": "extensions.[extension_name].Critical",
  "predicate": "equal",
  "constraint": {{
    "type": "boolean",
    "value": false  // for "non-critical"
    // OR
    "value": true   // for "critical"
  }}
}}
```

**Key Points**:
- Subject MUST be `extensions.[extension_name].Critical` (note the capital C)
- Predicate MUST be `equal` (not `must_be_set` or `must_not_be_set`)
- Constraint type MUST be `boolean`
- Value is `false` for "non-critical", `true` for "critical"

#### Pattern B: MAY Rules (Permissive Requirements)

**CRITICAL: Distinguish between two types of MAY rules:**

**Type 1: Permission Statements (NON-LINTABLE)**
Rules that only state what is *allowed* without any validation condition:

**CRITICAL Indicators** (If ANY matches → NON-LINTABLE):
- States "X MAY be included/present" without conditions
- Says "X is permitted" or "X is allowed"
- Describes optional features without constraints
- Uses phrases like "also", "other options", "alternative forms"
- **Meta-statements**: "Other options exist...", "...are not addressed by this specification"
- **Descriptive**: "Multiple name forms... MAY be included"
- **Open-ended**: "Applications with specific requirements MAY use..."

**Examples**:
❌ "Multiple name forms, and multiple instances of each name form, MAY be included"
  - This is pure permission - says what's *allowed*, not what to *check*
  - Extraction: `{{"rule_category": "non_lintable", "reason": "Permission statement without validation logic"}}`

❌ "Other options exist, including completely local definitions; Multiple name forms... MAY be included"
  - "Other options exist" = meta-statement (descriptive, not normative)
  - "MAY be included" = pure permission
  - Extraction: `{{"rule_category": "non_lintable", "reason": "Meta-statement and permission without constraint"}}`

❌ "the semantics... are not addressed by this specification; Applications with specific requirements MAY use..."
  - "not addressed by this specification" = meta-statement about scope
  - "MAY use" = open-ended permission
  - Extraction: `{{"rule_category": "non_lintable", "reason": "Specification scope statement, not a certificate constraint"}}`

❌ "Other algorithms MAY also be supported"
  - Pure permissive - no validation condition
  - Extraction: `{{"rule_category": "non_lintable", "reason": "Permissive MAY without constraint"}}`

**Type 2: Optional Requirements (LINTABLE with Warning)**
Rules with "MAY" that still have checkable constraints:

**Indicators**:
- "MAY" followed by specific constraints: "MAY be present **if** condition"
- "MAY be set **to** specific value"
- "MAY contain **only** specific format"

**Examples**:
✅ "The extension MAY be marked as critical if the subject DN is empty"
  - Has checkable condition
  - Extraction: `{{"lint_severity": "Warning", "constraint": {{"type": "conditional", ...}}}}`

✅ "If present, the field MAY only contain printable strings"
  - Has format constraint
  - Extraction: `{{"lint_severity": "Warning", "predicate": "must_match_format", ...}}`

**Decision Rule**:
1. Does the MAY rule state a specific checkable constraint?
   → YES: Extract as lintable with `"lint_severity": "Warning"`
   → NO: Mark as `{{"rule_category": "non_lintable"}}`

2. Is it a pure permission/allowance statement (e.g., "X MAY be included")?
   → YES: Mark as non_lintable
   → NO: Extract with constraint

#### STEP 0A: MANDATORY FIRST CHECK - Conditional Logic Detection

**BEFORE doing anything else, check if the rule contains conditional logic!**

**MANDATORY QUESTION**: Does the rule text contain ANY of these conditional keywords?
- "if...then..."
- "whenever..."
- "when...MUST/SHALL..." (when + obligation)
- "...MUST/SHALL...if..." (reverse condition)

**If YES → Rule is CONDITIONAL:**
- **MUST set `constraint.type = "conditional"`**
- **MUST extract `constraint.condition`** (the if/when/whenever clause)
- **MUST extract `constraint.consequence`** (the then/main clause)
- **DO NOT use types like "presence", "equality", etc. for conditional rules!**

**If NO → Rule is NON-CONDITIONAL:**
- Proceed with normal extraction using appropriate constraint type

---

#### Pattern C: Conditional Logic (If-Then Patterns) - DETAILED GUIDE

**This section provides detailed examples for CONDITIONAL rules (detected in STEP 0A above)**

**Text Patterns**:
- "if [condition], then [consequence] MUST/SHOULD..."
- "[consequence] MUST... if [condition]"
- "when [condition], [consequence] MUST..."
- "whenever [condition], [consequence] MUST..."

**Extraction Steps**:

1. **Identify the consequence field** (this becomes the `subject`):
   - Look for the field mentioned in the "then" clause or main requirement
   - This is what needs to be checked/validated

2. **Extract the condition** (goes in `constraint.condition`):
   - The "if" or "when" clause
   - Must be checkable from certificate fields
   - Use clear, specific language

3. **Extract the consequence** (goes in `constraint.consequence`):
   - The requirement that applies when condition is true
   - Usually the main clause with MUST/SHOULD

**Example 1: Subject must be empty**
Rule text: "If the only subject identity included in the certificate is an alternative name form, then the subject distinguished name MUST be empty"

**Correct Extraction**:
```json
{{
  "subject": "subject",
  "predicate": "must_be_empty",
  "constraint": {{
    "type": "conditional",
    "condition": "SubjectAltName extension is present and contains identities",
    "consequence": "subject distinguished name must be empty (empty sequence)",
    "value": null
  }}
}}
```

**Key points**:
- Subject is "subject" (the field being constrained in the THEN clause)
- Predicate is "must_be_empty" (what the subject must satisfy)
- Condition describes WHEN this requirement applies
- Consequence describes WHAT must be true

**Example 2: Flag must not be set**
Rule text: "If the subject public key is only to be used for verifying signatures on certificates and/or CRLs, then the digitalSignature bit SHOULD NOT be set"

**Correct Extraction**:
```json
{{
  "subject": "extensions.keyUsage.digitalSignature",
  "predicate": "must_not_be_set",
  "constraint": {{
    "type": "conditional",
    "condition": "subject public key is only for verifying cert/CRL signatures",
    "consequence": "digitalSignature bit should not be set",
    "value": false
  }}
}}
```

**Example 3: "Whenever" condition**
Rule text: "Whenever such identities are used, the issuer alternative name extension MUST be used"

**Correct Extraction**:
```json
{{
  "subject": "extensions.issuerAltName",
  "predicate": "must_be_present",
  "constraint": {{
    "type": "conditional",
    "condition": "such identities (alternative name forms) are used in issuer",
    "consequence": "issuerAltName extension must be present",
    "value": null
  }}
}}
```

**Key point**: "Whenever" = condition! Not simple presence check!

**Example 4: Email address conditional requirement**
Rule text: "Conforming implementations generating new certificates with electronic mail addresses MUST use the rfc822Name in the subject alternative name extension"

**Correct Extraction**:
```json
{{
  "subject": "extensions.subjectAltName.rfc822Name",
  "predicate": "must_be_used",
  "constraint": {{
    "type": "conditional",
    "condition": "certificate contains electronic mail addresses",
    "consequence": "email must be in rfc822Name (not subject.emailAddress)",
    "value": null
  }}
}}
```

**Key points**:
- "Conforming implementations...with X..." = condition!
- Subject is rfc822Name (NOT dNSName!), because rule explicitly says "electronic mail addresses"
- This is a conditional requirement (only applies to certs with emails)

**WRONG Examples to AVOID**:
❌ Rule: "If the only subject identity is in SAN, then subject DN MUST be empty"
Wrong extraction:
```json
{{
  "subject": "subject",
  "predicate": "must_be_empty",  // Missing conditional type!
  "constraint": {{
    "type": "presence",  // WRONG! Should be "conditional"
    "value": null
  }}
}}
```
This loses the conditional logic entirely!

**Decision Rule for Lintability**:
- CAN the condition be checked from certificate fields alone? → Lintable
- Does condition require external data (revocation status, time, etc.)? → Non-lintable

#### STEP 0: MANDATORY Pre-Check for Implementation Requirements

**BEFORE analyzing any rule, perform this mandatory check:**

**Question**: Does the rule text match ANY of these patterns?

1. **主语是"implementation(s)"**:
   - "Implementations MUST support..."
   - "Conforming implementations MUST..."
   - "Implementation MUST allow..."
   - "Implementation MUST be able to..."
   - "Implementation MUST perform..."

2. **主语是"application(s)"** (when referring to software, not certificate content):
   - "Applications MUST..."
   - "Applications...MUST be able to..."  ⚠️ CRITICAL: "be able to" = capability requirement
   - "Applications conforming to this profile MUST..."
   - "Application software SHALL..."
   - "Applications with specific requirements MAY..."

3. **主语是"relying party/parties"** or **"certificate users"**:
   - "Relying parties MUST..."
   - "Certificate users MUST..."
   - "Verifiers MUST..."

4. **实现行为描述** (describes HOW implementations should behave):
   - "When comparing...implementations MUST..."  ⚠️ CRITICAL: comparison is behavior, not certificate content
   - "When evaluating...implementations MUST..."
   - "When processing...implementations MUST..."
   - "When verifying...implementations MUST..."
   - "conforming implementations MUST perform..."  ⚠️ CRITICAL: "perform" = action, not state

5. **实现语义状态** (internal semantic states, not observable in certificate):
   - "...SHALL be considered a 'stored string'"  ⚠️ CRITICAL: semantic state
   - "...SHALL be considered..."  ⚠️ ANY use of "SHALL be considered"
   - "...MUST be treated as..."
   - "...is to be interpreted as..."
   - "...is considered a..."
   - "...treated as a..."

   **Why non-lintable**: "Considered/treated as" describes implementation's INTERNAL semantic interpretation,
   not observable certificate CONTENT. Certificate linters can only check WHAT data is present,
   not HOW implementation interprets it.

6. **描述处理标志** (flags used during creation, not stored in cert):
   - "AllowUnassigned flag SHALL NOT be set"
   - "UseSTD3ASCIIRules flag MUST be set"
   - Any "flag MUST/SHALL be set"

7. **描述转换/编码过程**:
   - "MUST convert...to..."
   - "MUST perform...conversion"
   - "before storage in" (indicates a pre-storage process)
   - "ToASCII conversion"
   - "ToUnicode operation"

8. **元叙述和说明性文本** (meta-statements about specification scope):
   - "...are not addressed by this specification"
   - "...is not addressed in this specification"
   - "This specification does not..."
   - "semantics...are not addressed"
   - "Other options exist..."  ⚠️ CRITICAL: Descriptive, not normative

**If ANY pattern matches → IMMEDIATELY mark as:**
```json
{{
  "rule_category": "implementation_process",
  "is_lintable": false,
  "non_lintable_reason": "[specific reason - e.g., 'Implementation capability requirement', 'Encoding process flag', etc.]"
}}
```

**DO NOT proceed to extract subject, predicate, constraint.** Stop here.

---

#### Pattern D: Implementation Process Requirements (Non-Lintable)

After passing STEP 0, some rules may still describe implementation process requirements. These CANNOT be verified by inspecting the certificate and MUST be marked as non-lintable.

**CRITICAL - Lintability Test**: Ask yourself: "Can I verify this rule by looking ONLY at the certificate content?"
- If YES → The rule IS lintable (can generate zlint code)
- If NO → The rule is NOT lintable (mark as implementation_process)

**Non-Lintable Text Patterns**:
- Processing flags that don't appear in certificates:
  - "AllowUnassigned flag SHALL NOT be set"
  - "UseSTD3ASCIIRules flag MUST be set"
- Implementation capabilities:
  - "Implementations MUST allow for..."
  - "Implementations MUST be able to..."
- Encoding/conversion processes:
  - "implementation MUST perform the ToASCII conversion" (process, not result)
- Verification process requirements:
  - "all parts MUST be verified by the CA" (CA behavior, not certificate content)

**LINTABLE Examples** (can be verified from certificate):
- ✅ "The name MUST be in the 'preferred name syntax'" → Can check dNSName format
- ✅ "DNS representation for mail addresses MUST NOT be used" → Can check if dNSName looks like email
- ✅ "If subject is empty, subjectAltName MUST be present" → Can check both fields
- ✅ "Whenever such identities are used, issuerAltName MUST be used" → Can check presence

**NON-LINTABLE Examples** (cannot be verified from certificate):
- ❌ "AllowUnassigned flag SHALL NOT be set" → Flag is used during creation, not stored in cert
- ❌ "Implementations MUST allow for increased space" → About implementation capability
- ❌ "CA MUST verify all parts of SAN" → About CA process, not cert content
- ❌ "implementation MUST perform ToASCII conversion" → About encoding process
- ❌ "When comparing DNS names, conforming implementations MUST perform a case-insensitive match" → About HOW to compare, not WHAT is in cert
- ❌ "domain name SHALL be considered a 'stored string'" → About semantic state, not observable content
- ❌ "When evaluating name constraints, implementations MUST perform..." → About evaluation process, not cert content

**CRITICAL - Correct Handling for Non-Lintable Rules**:
```json
{{
  "rule_category": "implementation_process",  // ⚠️ Use this ONLY if truly non-lintable
  "subject": "[appropriate_field_being_processed]",
  "predicate": "[appropriate_predicate]",
  "constraint": {{
    "raw_text": "[full_text]",
    "type": "process_requirement",
    "value": null
  }},
  "is_lintable": false,  // ⚠️ Set to false ONLY if cannot verify from cert
  "non_lintable_reason": "Implementation process requirement - cannot be verified from certificate content"
}}
```

**Key Decision Criteria**:
- Can you check this rule by READING the certificate? → Lintable
- Does this rule describe HOW to CREATE the certificate? → Non-lintable
- Does this rule describe IMPLEMENTATION CAPABILITY? → Non-lintable
- Does this rule describe CA/PROCESS BEHAVIOR? → Non-lintable
- Does this rule describe CERTIFICATE FIELD CONTENT? → Lintable

## IMPORTANT: Filter Out Non-Rule Content

**DO NOT extract** the following types of content:
1. **RFC 2119 keyword definitions** - Sentences like "The key words MUST, MUST NOT, REQUIRED..."
2. **Technical syntax definitions** - ASN.1 ("::="), BNF, schema definitions
3. **Pure informational text** - Introductions, overviews, background, terminology definitions
4. **Metadata** - Page numbers, section headers, document titles, version info, copyright, author names (e.g., "Cooper, et al")
5. **Examples and illustrations** - Unless they explicitly state normative requirements
6. **Structural navigation** - "This document...", "See Section...", "As described in...", "The following table...", "As specified in..."
7. **Definitions** - "X means...", "Y is defined as...", "Z refers to...", "For purposes of this..."
8. **Audit process requirements** - Rules about undergoing audits, audit reports, attestation (unless they're about technical artifact content/structure)
9. **Document structure** - "This section describes...", "The table below shows...", "For example..."
10. **Effective date tables** - Lists of dates and version changes like "2017-09-08 ... CAs MUST ...", "Effective [date]: ..." (these are just change logs, not standalone rules)
11. **Document roadmaps** - Table of contents, section summaries, "this section covers..."
12. **Informational preambles** - Scope statements, purpose statements, document history, acknowledgments
13. **Compliance schedules** - Timelines showing when requirements take effect (unless the text itself is the actual requirement)
14. **Summary tables** - Tables that list multiple requirements with dates/sections (extract from the actual requirement sections instead)
15. **Changelog entries** - Version history, amendments, "Changed in version X.Y"
16. **Bullet point lists merged with metadata** - Text containing multiple "* in step X" patterns combined with page footers or author names. These are implementation step lists that were incorrectly merged during text extraction.

**CRITICAL CHECKS before extracting:**
- Is this text from an introductory/informational section (e.g., Section 1-2, Appendix, Definitions)?
- Does the text list multiple dates and section references? (Likely a changelog/roadmap)
- Is the sentence a complete, standalone normative requirement?
- Can you identify a clear subject, obligation, and constraint?

**Only extract** actual normative requirements that specify:
- Technical artifact content obligations (what MUST/SHOULD/MAY be in the artifact/document/structure)
- Constraints (allowed/forbidden values, formats, behaviors)
- Validation and verification procedures (how to validate/verify technical correctness)
- Security requirements (cryptographic parameters, algorithm requirements, signature constraints)
- Actor behavioral requirements (what entities/systems MUST/SHOULD/MAY do when performing actions)

## Your Responsibilities

- Parse conditions (if/unless/except)
- Resolve pronouns (this/such/these)
- Normalize semantics
- Fill IR fields
- Determine if convertible to automated validation

## CRITICAL: Section Topic Propagation and Pronoun Resolution

**Section Topic Awareness:**
When a rule is in a section with a specific topic (e.g., "X.Y.Z Specific Component Name"), and the rule uses:
- Pronouns like "the value", "this field", "such entries"
- Generic terms like "the component", "these items"

**YOU MUST** infer that these refer to the section's main topic.

**Pattern:**
- Section "[Hierarchical.Path Component Name]"
  - Rule: "The value MUST conform to [constraint]"
  - **Subject should be**: `hierarchical.path.component` (NOT generic "value")

- Section "[Parent Container - Specific Field]"
  - Rule: "This field MUST contain [requirement]"
  - **Subject should be**: `parent.specificField` (NOT generic "field")

**Pronoun Resolution Steps:**
1. Check if the sentence contains pronouns ("the value", "this field", "such", "these")
2. Look at the section title/topic - does it mention a specific technical field or component?
3. If yes, use that field as the subject with full hierarchical path
4. If the section discusses multiple related items in a list, check if previous sentences in the context mention a specific item

**List Item Inheritance:**
If a rule is part of a bulleted/numbered list under a header that mentions a specific component, all list items inherit that component as their subject unless they explicitly mention a different field.

**Field/Subject Normalization Principles:**

When extracting the subject field, follow these normalization rules:

1. **Use Technical Terms, Not Colloquial Names:**
   - Prefer the formal field name from the standard over informal descriptions
   - Example: If standard defines "maximumTransferUnit", use that instead of "packet size" or "MTU"

2. **Preserve Hierarchical Paths:**
   - If the standard uses hierarchical/dotted notation (e.g., "A.B.C"), preserve it
   - Don't flatten the path (e.g., use "container.subfield" not just "subfield")

3. **Expand Abbreviations:**
   - If the rule text uses an abbreviation (e.g., "ID", "URL", "FQN") and you know the full form, use the full form
   - Keep abbreviations only if that's the canonical name in the standard

4. **Avoid Synonyms:**
   - If the standard uses multiple terms for the same concept, pick the most precise/technical one
   - Example: If both a colloquial description and a technical field name are used, prefer the technical field name

5. **Context-Specific Disambiguation:**
   - If the same term appears in multiple contexts (e.g., "name" in different sections), qualify it with its container
   - Use dot notation for hierarchy: `container.field` not just `field`


## CRITICAL: Generic Subject Identification Through Context Analysis

**When the rule text uses generic or ambiguous terms, you MUST analyze the context to determine the precise subject (the specific field/component/entity being constrained).**

### Universal Subject Identification Algorithm

Apply these steps in order (highest priority first):

#### Priority 1: Explicit Field/Component Mentions in Rule Text

Look for explicit mentions of specific fields/components in the rule sentence:

**Pattern: "in the [X]" / "[X] field" / "[X] attribute" / "[X] component"**
- Extract X as the subject
- Preserve the full hierarchical path if given (e.g., "container.specificField" not just "specificField")

**Pattern: "the [X] MUST/SHALL/SHOULD..."**
- If X is a specific noun (not just "field"/"value"), X is likely the subject
- Check if X is a technical term from the standard

#### Priority 2: Section Title Analysis

Parse the section title for scope clues:

**Pattern: "[Topic] in [Container/Location]"**
- The rule is likely about [Topic] within the scope of [Container]
- Subject should reflect both: `[Container].[Topic]` or `[Container].[specific-field]`
- Example logic: If discussing "Timestamps in Configuration", and rule mentions "the timestamp", subject is likely the timestamp field within Configuration

**Pattern: "[Specific Field/Component Name]"**
- If the section title is just a field name, all rules in that section are likely about that field
- Use the section title as the base subject path

**Pattern: "[Process/Procedure Name]"**
- If section describes a process (e.g., "Validation", "Processing"), rules may not have a static subject
- Subject might be about the actor ("CA", "Relying Party") or the process itself

#### Priority 3: Contextual Field Inheritance

Look at surrounding sentences and paragraphs:

1. **Scan previous sentences in the same paragraph** (up to 3 sentences back)
   - Has a specific field been explicitly mentioned?
   - If yes, and current rule uses a pronoun/generic term, inherit that field

2. **Check for list/enumeration context**
   - Is this rule part of a bulleted/numbered list?
   - Does the list have a header indicating the subject? (e.g., "For the X field:")

3. **Check for subordinate clause structure**
   - Does the sentence start with "When [condition about field X]..."?
   - Then X is likely the subject, even if later text uses pronouns

#### Priority 4: Disambiguation by Semantic Patterns

When multiple interpretations are possible, use these heuristics:

**Location Markers:**
- "in [Container]" suggests subject is a component of Container
- "of [Parent]" suggests subject is a property/attribute of Parent
- "within [Scope]" suggests subject is constrained to that scope

**Same Noun, Different Contexts:**
- If the same term appears in multiple section titles with different qualifiers (e.g., "X in A" vs "X in B"), they refer to DIFFERENT subjects
- Distinguish them by their containers: `A.X` vs `B.X`

**Avoid Over-Generalization:**
- Don't assume all instances of a term across different sections refer to the same field
- Always consider the section scope first

### Resolution Decision Tree

```
1. Does the rule sentence explicitly mention a field/component?
   ├─ YES → Use that field as subject
   └─ NO → Go to 2

2. Does the section title indicate a specific field/component?
   ├─ YES → Use that as subject (unless rule contradicts)
   └─ NO → Go to 3

3. Do previous sentences in context mention a specific field?
   ├─ YES → Inherit that field
   └─ NO → Go to 4

4. Can you infer from section title pattern "[X] in [Y]"?
   ├─ YES → Subject is likely `Y.X` or a component within Y
   └─ NO → Mark as uncertain, use most general term from rule text
```

### Anti-Pattern: Avoid Cross-Context Conflation

**CRITICAL: The same terminology in different contexts may refer to completely different entities.**

**Identifying Different Contexts:**
1. Different section titles using qualifier phrases ("in X" vs "in Y")
2. Different hierarchical levels in the standard structure
3. Different chapters/parts of the standard

**Rule: When in doubt, prioritize section-level context over document-level assumptions.**

### CRITICAL: Certificate Field vs CA Behavior Disambiguation

**Common Mistake**: Classifying CA behavior rules as certificate field rules

**Decision Rule - Use this checklist:**

1. **Who is the subject of the obligation?**
   - Certificate field/content → `certificate_field`
   - CA/Issuer/Authority → `ca_behavior`
   - Process/Procedure → `process_rule`

2. **What is being constrained?**
   - Certificate content (what's IN the certificate) → `certificate_field`
   - CA actions (what CA DOES) → `ca_behavior`
   - Validation/verification process → `validation_method` or `process_rule`

3. **Look for these CA behavior keywords:**
   - "CA MUST verify/validate/check"
   - "Issuer SHALL perform"
   - "Authority MUST ensure"
   - "CA MUST confirm"
   - "before issuance"
   - "during validation"
   - "verified by the CA"

**WRONG Examples (Learn from these mistakes):**
- ❌ Rule: "all parts of the subject alternative name MUST be verified by the CA"
  - Wrong: rule_category = "certificate_field", subject = "extensions.subjectAltName.dNSName"
  - Reason: "verified by the CA" indicates this is about CA behavior, not certificate content
  - Correct: rule_category = "ca_behavior", subject = "CA"

- ❌ Rule: "The CA MUST confirm that the Applicant controls the domain"
  - Wrong: rule_category = "certificate_field"
  - Reason: "CA MUST confirm" is a CA action, not certificate content
  - Correct: rule_category = "ca_behavior" or "validation_method"

**CORRECT Examples:**
- ✅ Rule: "the dNSName MUST be in preferred name syntax"
  - Correct: rule_category = "certificate_field", subject = "extensions.subjectAltName.dNSName"
  - Reason: Constrains certificate content, not CA behavior

- ✅ Rule: "all parts of the subject alternative name MUST be verified by the CA"
  - Correct: rule_category = "ca_behavior", subject = "CA"
  - Reason: Constrains what CA must do, not what's in the certificate

## CRITICAL: Rule Classification

**Before extracting the IR, you MUST classify each rule into one of the following categories:**

**IMPORTANT**: You MUST use the exact category names below in your JSON output. These names originated from PKI standards but represent universal concepts applicable to ANY technical standard.

### Rule Categories:

1. **certificate_field** - Static Technical Content Rules
   - **Universal meaning**: Rules that constrain **STATIC CONTENT** of technical artifacts (certificates, documents, packets, data structures, configuration files, etc.)
   - Subject is a field/component path that can be read from the artifact
   - Can potentially be automatically validated by inspecting the artifact
   - **Key indicator**: Rule describes what MUST/SHOULD BE in a field, not what someone must DO
   - Examples across domains:
     - PKI: Certificate field presence, value constraints, format requirements
     - Networking: Packet header values, protocol field constraints
     - Data formats: JSON/XML structure, document schema requirements
     - Configuration: Config file field values, parameter constraints

2. **ca_behavior** - Actor/Entity Behavior Rules
   - **Universal meaning**: Rules that constrain **ACTIONS/BEHAVIOR** of actors/entities (CAs, servers, clients, issuers, validators, manufacturers, service providers, etc.)
   - Subject is an entity name (e.g., "CA", "Server", "Client", "Issuer", "Validator", "Manufacturer")
   - About what the actor must DO (implement, establish, verify, confirm, maintain, etc.)
   - Cannot be validated by inspecting a static artifact alone
   - **Key indicator**: Action verbs describing what an entity must do
   - Examples: "X MUST verify...", "Y SHALL implement...", "Z MUST maintain..."

3. **process_rule** - Procedural/Workflow Rules
   - **Universal meaning**: Rules about PROCEDURES/WORKFLOWS in any domain
   - Contains temporal/procedural conditions ("before", "when", "after", "during", "upon")
   - About procedures, workflows, timing, sequencing
   - Cannot be validated by inspecting a static artifact alone
   - **Key indicator**: Temporal markers or workflow descriptions
   - Examples across domains:
     - PKI: "Before issuing, CA MUST verify...", "When certificate expires..."
     - Networking: "Before sending packet, validate checksum...", "Upon connection timeout..."
     - Manufacturing: "After assembly, perform quality check...", "During production..."

4. **organizational** - Organizational Management Rules
   - **Universal meaning**: Rules about ORGANIZATIONAL/ADMINISTRATIVE MANAGEMENT (applicable to any type of organization)
   - About personnel, training, documentation, policies, governance
   - Not about technical content or technical processes
   - **Key indicator**: Management/administrative concepts
   - Examples across domains:
     - Training requirements, documentation requirements, policy requirements
     - Audit requirements, record-keeping, personnel qualifications

5. **validation_method** - Validation Method Rules
   - **Universal meaning**: Rules about HOW TO VALIDATE/VERIFY something (applicable to any validation context)
   - About validation methods, verification procedures, checking algorithms
   - Describes the method itself, not the result
   - **Key indicator**: "HOW" to validate, not "WHAT" to validate
   - Examples: "MAY use method X to verify...", "MUST perform check Y using...", "SHALL validate by..."

### Classification Decision Tree:

```
1. Does the rule describe WHAT must be in a technical field/component?
   ├─ YES → certificate_field
   └─ NO → Go to 2

2. Does the rule describe WHAT an entity must DO (action verb)?
   ├─ YES → Go to 3
   └─ NO → Go to 5

3. Is it about management/admin (training, docs, policies)?
   ├─ YES → organizational
   └─ NO → Go to 4

4. Does it describe HOW to validate/verify something?
   ├─ YES → validation_method
   └─ NO → Check for temporal markers

5. Does it have temporal/procedural markers ("before", "when", "after")?
   ├─ YES → process_rule
   └─ NO → ca_behavior (default for behavioral rules)
```

### Output Fields for Classification:

**CRITICAL**: The `rule_category` field MUST be one of these 5 exact values:
- `"certificate_field"`
- `"ca_behavior"`
- `"process_rule"`
- `"organizational"`
- `"validation_method"`

Do NOT use alternative names like "technical_content" or "actor_behavior" - these will cause parsing errors.

```json
{{
  "rule_category": "certificate_field",  // REQUIRED: Must be one of the 5 exact values listed above
  "subject": "container.component.field",      // Hierarchical field path OR actor name (e.g., "CA", "Server")
  ...
}}
```

**CRITICAL EXAMPLES:**

Example 1 - Technical Content Rule:
```json
{{
  "rule_category": "certificate_field",
  "subject": "container.timeField.endTime",
  "predicate": "less_than_or_equal",
  "constraint": {{"raw_text": "MUST NOT exceed 397 days", "type": "time_based", "value": 397, "unit": "days"}}
}}
```

Example 2 - Actor Behavior Rule:
```json
{{
  "rule_category": "ca_behavior",
  "subject": "ServiceProvider",
  "predicate": "must_include",
  "constraint": {{"raw_text": "implement a validation process", "type": "string", "value": "validation process"}}
}}
```

Example 3 - Process Rule:
```json
{{
  "rule_category": "process_rule",
  "subject": "Issuer",
  "predicate": "must_include",
  "constraint": {{"raw_text": "verify authenticity before approval", "type": "string", "value": "authenticity verification"}}
}}
```

## Input Format

You will receive {num_rules} rules. Each rule has:
- `sentence`: The normative sentence
- `keyword`: RFC2119 keyword (MUST/SHALL/etc.)
- `section`: Section number
- `context`: Surrounding text (if needed)

## Output Format (JSON array)

Return a JSON array with EXACTLY {num_rules} objects:

```json
[
  {{
    "rule_category": "certificate_field",
    "subject": "security.permissions.readAccess",
    "predicate": "must_be_present",
    "constraint": {{
      "raw_text": "The readAccess permission MUST be present",
      "type": "presence",
      "value": null
    }},
    "conditions": []
  }}
]
```

**Note**:
- Do NOT include "obligation" field - it will be automatically extracted from the RFC2119 keyword
- Do NOT extract references (like "RFC 5280 Section 4.2.1.3") - they will be extracted separately using pattern matching
- ALWAYS include rule_category field

**CRITICAL - Rule Independence**:
- Each rule below is INDEPENDENT - extract constraints ONLY from that specific sentence
- Do NOT reuse constraints from previous rules in the batch
- Do NOT assume rules in the same section have the same constraint
- Each rule MUST have its OWN unique constraint based on ITS OWN sentence text
- Example: If Rule 5 says "MUST be used" and Rule 6 says "MUST match syntax X", they have DIFFERENT constraints

---

## Rules to Extract

**IMPORTANT**: Process each rule independently. Do NOT copy constraints between rules.

"""

        # 添加规则列表
        for i, context in enumerate(contexts, 1):
            skeleton = context.skeleton
            base = context.base_context
            extended = context.extended_context

            prompt += f"\n### Rule {i} of {num_rules}\n"
            prompt += f"- Sentence: \"{skeleton.sentence}\"\n"
            prompt += f"- Keyword: {skeleton.keyword}\n"
            prompt += f"- Section: {base.get('section', 'N/A')}\n"

            # 添加 section_title（关键！用于主题传播）
            section_title = base.get('section_title')
            if section_title:
                prompt += f"- Section Title: \"{section_title}\"\n"

            # 添加 section_topic（如果有）
            section_topic = extended.get('section_topic')
            if section_topic:
                prompt += f"- Section Topic: {section_topic}\n"

            # 添加扩展上下文（如果有）
            if extended.get('condition_context'):
                prompt += f"- Condition Context: \"{extended['condition_context'][:200]}...\"\n"
            if extended.get('pronoun_context'):
                prompt += f"- Pronoun Context: \"{extended['pronoun_context'][:200]}...\"\n"
            if extended.get('list_context'):
                prompt += f"- List Context: \"{extended['list_context'][:200]}...\"\n"

            # 添加 GraphRAG 上下文（如果有）
            if extended.get('graphrag_context'):
                prompt += f"- Knowledge Graph Context:\n{extended['graphrag_context']}\n"

        prompt += f"\n---\n\n**Output JSON array with EXACTLY {num_rules} objects NOW (no explanations, no additional rules):**\n"

        return prompt

    def _call_llm(self, prompt: str, batch_size: int = 1, retry_count: int = 0, max_retries: int = 2) -> str:
        """
        调用 LLM API（带重试机制）

        Args:
            prompt: 提示词
            batch_size: 批次中的规则数量（用于日志）
            retry_count: 当前重试次数
            max_retries: 最大重试次数
        """
        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json"
        }

        # 根据prompt实际大小计算输出token
        # 1 token ≈ 4 chars（英文），中文可能更少，这里保守估计
        prompt_chars = len(prompt)
        prompt_tokens = prompt_chars // 4

        # 输出token = 总上下文窗口 - 输入token - 安全余量(10%)
        safety_margin = int(self.context_window * 0.1)
        max_tokens = max(2000, self.context_window - prompt_tokens - safety_margin)

        payload = {
            "model": self.model,
            "messages": [{
                "role": "user",
                "content": prompt
            }],
            "temperature": 0.1,
            "max_tokens": max_tokens
        }

        app_logger.debug(
            f"[RuleSkeletonLLMExtractor] Calling LLM: batch_size={batch_size}, "
            f"prompt_tokens≈{prompt_tokens}, max_tokens={max_tokens}, "
            f"context_window={self.context_window}"
        )

        try:
            response = requests.post(
                self.api_endpoint,
                headers=headers,
                json=payload,
                timeout=1200.0  # 20分钟超时
            )

            response.raise_for_status()
            result_json = response.json()
            llm_output = result_json['choices'][0]['message']['content']

            # 诊断信息：检查finish_reason和token使用情况
            finish_reason = result_json['choices'][0].get('finish_reason', 'unknown')
            usage = result_json.get('usage', {})

            app_logger.info(
                f"[RuleSkeletonLLMExtractor] LLM response: "
                f"output_length={len(llm_output)} chars, "
                f"finish_reason={finish_reason}, "
                f"prompt_tokens={usage.get('prompt_tokens', 'N/A')}, "
                f"completion_tokens={usage.get('completion_tokens', 'N/A')}, "
                f"total_tokens={usage.get('total_tokens', 'N/A')}"
            )

            if finish_reason == 'length':
                app_logger.warning(
                    f"[RuleSkeletonLLMExtractor] Output truncated! "
                    f"max_tokens={payload['max_tokens']} was insufficient. "
                    f"Batch contained {batch_size} rules but output was cut off."
                )

            return llm_output

        except requests.exceptions.Timeout as e:
            if retry_count < max_retries:
                app_logger.warning(
                    f"[RuleSkeletonLLMExtractor] LLM timeout (attempt {retry_count + 1}/{max_retries + 1}), retrying..."
                )
                return self._call_llm(prompt, batch_size, retry_count + 1, max_retries)
            else:
                app_logger.error(f"[RuleSkeletonLLMExtractor] LLM timeout after {max_retries + 1} attempts")
                raise

        except Exception as e:
            app_logger.error(f"[RuleSkeletonLLMExtractor] LLM API error: {e}")
            raise

    def _parse_llm_response(self, response: str) -> List[Dict[str, Any]]:
        """解析 LLM 响应为规则列表（增强容错性）"""
        try:
            # 移除markdown代码围栏（LLM可能返回```json ... ```格式）
            response_cleaned = response.strip()
            if response_cleaned.startswith('```'):
                # 移除开头的```json或```
                lines = response_cleaned.split('\n')
                if lines[0].startswith('```'):
                    lines = lines[1:]
                # 移除结尾的```
                if lines and lines[-1].strip() == '```':
                    lines = lines[:-1]
                response_cleaned = '\n'.join(lines)

            # 提取 JSON 数组
            json_match = re.search(r'\[.*\]', response_cleaned, re.DOTALL)
            if json_match:
                json_str = json_match.group(0)

                # 尝试直接解析
                try:
                    rules = json.loads(json_str)
                    if isinstance(rules, list):
                        return rules
                except json.JSONDecodeError as e:
                    app_logger.warning(f"[RuleSkeletonLLMExtractor] First JSON parse attempt failed: {e}")

                    # 尝试修复常见的 JSON 格式问题
                    json_str_fixed = json_str

                    # 1. 修复字符串值中的未转义双引号和换行符（使用状态机方法）
                    result = []
                    in_string = False
                    in_field_name = False
                    escape_next = False

                    i = 0
                    while i < len(json_str_fixed):
                        char = json_str_fixed[i]

                        if escape_next:
                            result.append(char)
                            escape_next = False
                            i += 1
                            continue

                        if char == '\\':
                            result.append(char)
                            escape_next = True
                            i += 1
                            continue

                        # 处理换行符：在字符串内替换为空格，在字符串外移除
                        if char in '\n\r':
                            if in_string:
                                result.append(' ')  # 字符串内：换行替换为空格
                            # 字符串外：直接跳过
                            i += 1
                            continue

                        if char == '"':
                            if not in_string:
                                in_string = True
                                # 判断是字段名还是字段值
                                j = len(result) - 1
                                while j >= 0 and result[j] in ' \t\n\r':
                                    j -= 1
                                in_field_name = (j >= 0 and result[j] in '{,')
                                result.append(char)
                            elif in_field_name:
                                # 字段名结束
                                in_string = False
                                in_field_name = False
                                result.append(char)
                            else:
                                # 检查后面是否跟着冒号或逗号或右括号
                                j = i + 1
                                while j < len(json_str_fixed) and json_str_fixed[j] in ' \t\n\r':
                                    j += 1
                                if j < len(json_str_fixed) and json_str_fixed[j] in ',:}]':
                                    # 这是字符串结束
                                    in_string = False
                                    result.append(char)
                                else:
                                    # 这是字符串内的引号，需要转义
                                    result.append('\\')
                                    result.append(char)
                        else:
                            result.append(char)

                        i += 1

                    json_str_fixed = ''.join(result)

                    # 2. 移除其他控制字符（除了已处理的换行符）
                    json_str_fixed = re.sub(r'[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]', '', json_str_fixed)

                    # 3. 移除尾部逗号 (trailing commas)
                    json_str_fixed = re.sub(r',\s*([}\]])', r'\1', json_str_fixed)

                    # 4. 修复缺少前导0的小数（如 .95 → 0.95）
                    json_str_fixed = re.sub(r':\s*\.(\d+)', r': 0.\1', json_str_fixed)
                    json_str_fixed = re.sub(r',\s*\.(\d+)', r', 0.\1', json_str_fixed)
                    json_str_fixed = re.sub(r'\[\s*\.(\d+)', r'[0.\1', json_str_fixed)

                    # 5. 修复空值（将 : , 替换为 : null,）
                    json_str_fixed = re.sub(r':\s*,', r': null,', json_str_fixed)
                    json_str_fixed = re.sub(r':\s*}', r': null}', json_str_fixed)
                    json_str_fixed = re.sub(r':\s*]', r': null]', json_str_fixed)

                    # 6. 修复双逗号
                    json_str_fixed = re.sub(r',+', r',', json_str_fixed)

                    # 7. 修复数组字段中的未闭合引号（常见于conditions字段）
                    # 查找 "conditions": [ ... 模式，确保数组元素正确闭合
                    def fix_array_elements(match):
                        """修复数组元素中的引号问题"""
                        field_name = match.group(1)
                        array_content = match.group(2)

                        # 如果数组内容看起来不完整（奇数个引号），尝试修复
                        quote_count = array_content.count('"')
                        if quote_count % 2 == 1:
                            # 奇数个引号，在末尾添加缺失的引号
                            app_logger.debug(f"[JSON Fix] Detected unclosed quote in {field_name} array, fixing...")
                            array_content = array_content + '"'

                        return f'"{field_name}": [{array_content}]'

                    # 应用到 conditions 和 references 等数组字段
                    json_str_fixed = re.sub(
                        r'"(conditions|references)"\s*:\s*\[(.*?)\]',
                        fix_array_elements,
                        json_str_fixed,
                        flags=re.DOTALL
                    )

                    # 8. 修复未闭合的对象（检测最后一个 { 是否有对应的 }）
                    open_braces = json_str_fixed.count('{')
                    close_braces = json_str_fixed.count('}')
                    if open_braces > close_braces:
                        app_logger.debug(f"[JSON Fix] Adding {open_braces - close_braces} missing closing braces")
                        json_str_fixed = json_str_fixed + '}' * (open_braces - close_braces)

                    # 9. 修复未闭合的数组
                    open_brackets = json_str_fixed.count('[')
                    close_brackets = json_str_fixed.count(']')
                    if open_brackets > close_brackets:
                        app_logger.debug(f"[JSON Fix] Adding {open_brackets - close_brackets} missing closing brackets")
                        json_str_fixed = json_str_fixed + ']' * (open_brackets - close_brackets)


                    try:
                        rules = json.loads(json_str_fixed)
                        if isinstance(rules, list):
                            app_logger.info(f"[RuleSkeletonLLMExtractor] JSON parsing succeeded after fixing")
                            return rules
                    except json.JSONDecodeError as e2:
                        # 降级为WARNING（因为有容错机制会尝试恢复）
                        app_logger.warning(
                            f"[RuleSkeletonLLMExtractor] JSON parse failed after auto-fixing: {e2} "
                            f"(will attempt element-by-element recovery)"
                        )
                        # 记录部分 JSON 用于调试
                        app_logger.debug(f"Problematic JSON (first 500 chars): {json_str[:500]}")
                        app_logger.debug(f"Problematic JSON (around error): {json_str[max(0, e2.pos-100):min(len(json_str), e2.pos+100)]}")

                        # 尝试逐个元素解析（最后的容错手段）
                        app_logger.info("[RuleSkeletonLLMExtractor] Attempting element-by-element recovery...")
                        rules = self._parse_individual_elements(json_str)
                        if rules:
                            app_logger.info(
                                f"[RuleSkeletonLLMExtractor] ✓ Successfully recovered {len(rules)} rules "
                                f"by parsing individual elements"
                            )
                            return rules
                        else:
                            # 只有在容错机制也失败时才记录ERROR
                            app_logger.error(
                                f"[RuleSkeletonLLMExtractor] All recovery attempts failed: "
                                f"could not parse any rules from LLM output"
                            )
                        return []
            else:
                app_logger.error("[RuleSkeletonLLMExtractor] No JSON array found in LLM output")
                app_logger.debug(f"LLM output (first 500 chars): {response[:500]}")
                return []

        except Exception as e:
            app_logger.error(f"[RuleSkeletonLLMExtractor] Unexpected error parsing LLM response: {e}")
            return []

        return []

    def _parse_individual_elements(self, json_str: str) -> List[Dict[str, Any]]:
        """尝试逐个解析JSON数组中的元素（最后的容错手段）"""
        try:
            # 移除最外层的 [ ]
            inner = json_str.strip()
            if inner.startswith('['):
                inner = inner[1:]
            if inner.endswith(']'):
                inner = inner[:-1]

            # 尝试按 },{ 分割（假设每个元素都是对象）
            elements = []
            current = ""
            depth = 0
            in_string = False
            escape_next = False

            for i, char in enumerate(inner):
                # 处理字符串内的引号
                if char == '"' and not escape_next:
                    in_string = not in_string
                elif char == '\\' and in_string:
                    escape_next = True
                    current += char
                    continue

                escape_next = False
                current += char

                if not in_string:
                    if char == '{':
                        depth += 1
                    elif char == '}':
                        depth -= 1
                        if depth == 0 and current.strip():
                            # 一个完整的对象
                            obj_str = current.strip().rstrip(',').strip()
                            if obj_str:
                                try:
                                    # 尝试修复常见问题
                                    obj_str_fixed = obj_str
                                    # 修复空值
                                    obj_str_fixed = re.sub(r':\s*,', r': null,', obj_str_fixed)
                                    obj_str_fixed = re.sub(r':\s*}', r': null}', obj_str_fixed)
                                    # 移除尾部逗号
                                    obj_str_fixed = re.sub(r',\s*}', r'}', obj_str_fixed)

                                    obj = json.loads(obj_str_fixed)
                                    if isinstance(obj, dict):
                                        elements.append(obj)
                                        app_logger.debug(f"Successfully parsed element {len(elements)}")
                                except Exception as e:
                                    app_logger.debug(f"Failed to parse element at position {i}: {e}")
                                    app_logger.debug(f"Problematic object: {obj_str[:200]}...")
                            current = ""

            app_logger.info(f"Individual element parsing recovered {len(elements)} rules")
            return elements

        except Exception as e:
            app_logger.debug(f"Individual element parsing failed: {e}")
            return []

    def _build_ir_from_llm_output(
        self,
        rule_data: Dict[str, Any],
        context: RuleContext
    ) -> Optional[IntermediateRepresentation]:
        """从 LLM 输出构建 IR"""
        try:
            skeleton = context.skeleton

            # 提取字段（不再从LLM获取obligation，直接使用skeleton.keyword）
            subject = rule_data.get('subject')
            predicate_str = rule_data.get('predicate')
            constraint_data = rule_data.get('constraint', {})

            # 提取规则分类字段
            rule_category = rule_data.get('rule_category', 'certificate_field')

            if not all([subject, predicate_str]):
                app_logger.warning(
                    f"[RuleSkeletonLLMExtractor] Missing required fields for rule: {skeleton.rule_id}"
                )
                return None

            # 直接使用 Regex 提取的 keyword 作为 obligation（更准确，无需验证）
            obligation_str = skeleton.keyword

            # 解析枚举（尝试解析，失败则降级为字符串）
            try:
                obligation = ObligationType(obligation_str)
            except ValueError:
                app_logger.debug(f"Unknown obligation '{obligation_str}', using as string")
                obligation = obligation_str  # 降级为字符串

            try:
                predicate = PredicateType(predicate_str)
            except ValueError:
                app_logger.debug(f"Unknown predicate '{predicate_str}', using as string")
                predicate = predicate_str  # 降级为字符串

            # 构建约束（constraint.type 也支持降级）
            constraint_type_str = constraint_data.get('type', 'presence')
            try:
                constraint_type = ConstraintType(constraint_type_str)
            except ValueError:
                app_logger.debug(f"Unknown constraint type '{constraint_type_str}', using as string")
                constraint_type = constraint_type_str  # 降级为字符串

            constraint = IRConstraint(
                raw_text=constraint_data.get('raw_text', skeleton.sentence),
                type=constraint_type,
                value=constraint_data.get('value'),
                unit=constraint_data.get('unit'),
            )

            # 使用 Regex 从规则文本中提取引用（Stage B 只提取原始文本）
            references = self._extract_references_from_text(skeleton.sentence)

            # 解析条件（处理字符串或字典格式）
            conditions = []
            for cond_data in rule_data.get('conditions', []):
                if isinstance(cond_data, dict):
                    # 已经是字典格式
                    conditions.append(cond_data)
                elif isinstance(cond_data, str):
                    # 字符串格式，转换为字典
                    conditions.append({
                        'raw': cond_data,
                        'type': 'unknown'
                    })
                else:
                    # 其他类型，跳过
                    app_logger.debug(f"Skipping invalid condition type: {type(cond_data)}")

            # 构建 provenance
            provenance = IRProvenance(
                source_id=skeleton.rule_id.split('-')[0],  # 从 rule_id 提取 doc_id
                section=skeleton.section,
                title=skeleton.section_title,
                line_start=skeleton.sentence_index,
                line_end=skeleton.sentence_index,
                chunk_id=None,  # 不再基于 chunk
                extractor_type='llm_skeleton',
                extraction_timestamp=datetime.now(),
            )

            # 构建 IR
            ir = IntermediateRepresentation(
                rule_id=skeleton.rule_id,  # 使用 skeleton 的 rule_id
                stage=IRStage.RAW,
                rule_category=rule_category,
                # 核心四元组
                subject=subject,
                obligation=obligation,
                predicate=predicate,
                constraint=constraint,
                references=references,
                rule_text=skeleton.sentence,
                conditions=conditions,  # 使用处理后的conditions
                context=(
                    # 优先使用通用上下文，如果没有则使用条件上下文，最后fallback到None
                    context.extended_context.get('general_context') or
                    context.extended_context.get('condition_context')
                ),
                provenance=[provenance],
            )

            return ir

        except Exception as e:
            app_logger.error(f"[RuleSkeletonLLMExtractor] Error building IR: {e}")
            return None
# Trigger reload after optimization
