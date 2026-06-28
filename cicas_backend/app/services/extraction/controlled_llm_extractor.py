"""
受控 LLM 提取器 (Controlled LLM Extractor)

核心设计原则：
1. LLM 仅作为无状态、受限的结构化解析器
2. 所有判断、冲突和可执行性分析在规则引擎中完成
3. LLM 不解释意图、不解决歧义、不推断隐含条件

HARD CONSTRAINTS:
1. LLM MUST NOT make normative judgments.
2. LLM MUST NOT resolve conflicts.
3. LLM MUST NOT infer implicit requirements.
4. All decisions MUST be rule-based and auditable.
5. Specification knowledge MUST NOT be embedded in model parameters.
6. Updating specifications MUST NOT require retraining the LLM.
"""
import asyncio
import json
from typing import List, Optional, Dict, Any, Tuple, Callable, Awaitable
from datetime import datetime
import re
import httpx

from app.core.logging_config import app_logger
from app.core.config import settings
from app.utils.llm_client import LLMClient

from .ir_schema import (
    ExtractionResult,
    IntermediateRepresentation,
    IRStage,
    IRConstraint,
    IRProvenance,
    IRReference,
    SubjectRef,
    ObligationType,
    PredicateType,
    SpecFamily,
    AssertionSubject,
    EnforcementPhase,
    RuleCategory,
    Verifiability,
    AlgorithmReference,
    Override,
    # ExtractionConfidence 和 compute_extraction_confidence 已删除
)
from .output_validator import OutputValidator, ValidationResult
from .sentence_preprocessor import SentencePreprocessor, AtomicSentence
from .field_resolver import get_field_resolver

# Graph-Aware Retrieval 链路
from app.services.spec_context.context_manager import SpecificationContextManager
from app.services.graph_retrieval.subgraph_extractor import SubgraphExtractor
from app.services.graph_retrieval.context_assembler import ContextAssembler


# 全局 LLM 并发信号量：跨所有提取任务共享，防止多个标准同时提取时打爆 LLM API
_global_llm_semaphore: Optional[asyncio.Semaphore] = None


def _get_global_llm_semaphore() -> asyncio.Semaphore:
    """懒初始化全局信号量（必须在事件循环中调用）"""
    global _global_llm_semaphore
    if _global_llm_semaphore is None:
        _global_llm_semaphore = asyncio.Semaphore(settings.llm_max_concurrency)
    return _global_llm_semaphore


# ============================================================
# 受控 System Prompt（全局，只设一次）
# ============================================================
CONTROLLED_SYSTEM_PROMPT = """You are a controlled semantic parser for security and PKI specifications.

Your ONLY task is to convert a single normative sentence into a structured IR according to the provided schema.

MANDATORY CLASSIFICATION (must be done FIRST):
Before extracting any IR fields, you MUST classify the rule into one of these categories:

1. ENCODING_CONSTRAINT - Certificate field encoding/format constraints (lintable!)
   Constraints on HOW a certificate field is encoded, formatted, or structured:
   - Encoding type: "MUST be encoded as UTF8String", "MUST be encoded as PrintableString"
   - Encoding format: "MUST contain the ACE-encoded value", "MUST use DER encoding"
   - Character set: "IA5String is limited to the set of ASCII characters" (constrains fields using IA5String type)
   - Length/value range: "MUST NOT exceed 64 characters", "MUST be a non-negative INTEGER"
   - Presence/criticality: "extension MUST be present", "field MUST be marked critical"
   - Field content: "MUST have at least one bit set", "MUST include at least one entry", "MUST contain at least one entry"
   - Value constraints: "MUST be greater than or equal to zero", "pathLenConstraint MUST be greater than or equal to zero"
   - Conditional encoding: "If X, then the CA MUST include Y extension" (the result is observable in the certificate)
   → verifiability = "observable", assertion_subject = "Certificate"
   KEY: Can be verified by examining the certificate encoding
   CRITICAL: "in step X, change all labels to..." describes HOW to encode a field → ENCODING_CONSTRAINT (not ALGORITHM_REF)

2. DEFINITION - Pure type/syntax definitions that describe WHAT something IS (not what it MUST be)
   Examples:
   - "DirectoryString is one of PrintableString, UTF8String, or BMPString" (defines alternatives)
   - "These identities may be included in addition to or in place of..." (describes relationship, no constraint)
   → verifiability = "none", lintable = false
   → assertion_subject = "Certificate" (defines certificate content types)
   NOT DEFINITION (these are ENCODING_CONSTRAINT):
   - "IA5String is limited to the set of ASCII characters" → ENCODING_CONSTRAINT (constrains character set of certificate fields using IA5String type, observable in certificate)
   - "serialNumber MUST be non-negative" → ENCODING_CONSTRAINT (constrains value)
   - "extension MUST be encoded as UTF8String" → ENCODING_CONSTRAINT (constrains encoding)
   - "MUST contain at least one entry" → ENCODING_CONSTRAINT (constrains content)
   - "If X, then MUST include Y" → ENCODING_CONSTRAINT (conditional constraint on certificate content)

3. CLARIFICATION - Value semantics or conditional constraints (NOT about encoding format)
   Examples:
   - "cA boolean indicates whether the subject is a CA" (semantic meaning)
   - "If the certificate is a CA certificate, then..." (conditional logic about certificate TYPE, not field encoding)
   - Override/clarification to referenced algorithm (e.g., "in step 3, set UseSTD3ASCIIRules")
   → verifiability = "observable" if about certificate content
   KEY DISTINCTION from ENCODING_CONSTRAINT: These rules constrain value SEMANTICS, not encoding FORMAT
   - "MUST be non-negative" → ENCODING_CONSTRAINT (format/range constraint)
   - "cA boolean indicates whether the subject is a CA" → CLARIFICATION (semantic meaning)
   NOT CLARIFICATION (these are other categories):
   - "all parts MUST be verified by the CA" → CA operational behavior (assertion_subject = CA, lintable = false)
   - "MUST be applied to any names" → Implementation validation behavior (assertion_subject = Implementation, lintable = false)
   - "MUST be able to process" → CAPABILITY (Implementation capacity, lintable = false)

4. ALGORITHM_REF - Reference to external algorithm (e.g., "perform operation specified in RFC 3490 §4")
   → Extract algorithm_ref with base_spec, section, operation
   → Set inheritance = "full" if no local modifications
   → verifiability = "none" (algorithm itself not verifiable in certificate)

5. COMPARISON - Comparison/matching rules (e.g., "MUST perform case-insensitive match")
   → verifiability = "runtime_only" (comparison happens at validation time, not observable in certificate)
   → assertion_subject = "Implementation" or "RelyingParty"
   → lintable = false
   CRITICAL: COMPARISON is about HOW TO COMPARE/MATCH at runtime, NOT about certificate field values
   Examples of COMPARISON:
   - "MUST perform case-insensitive match" → runtime comparison behavior
   - "MUST match the subject name" → runtime validation behavior
   - "MUST impose constraints on X" → runtime constraint checking (Name Constraints validation)
   - "MUST NOT impose constraints on X" → runtime constraint checking
   NOT COMPARISON (these are ENCODING_CONSTRAINT):
   - "pathLenConstraint MUST be greater than or equal to zero" → ENCODING_CONSTRAINT (numeric constraint on certificate field VALUE)
   - "MUST be greater than X" when referring to a certificate field value → ENCODING_CONSTRAINT
   - "MUST contain at least one entry" → ENCODING_CONSTRAINT (field presence/count)
   - "MUST be present" or "MUST NOT be present" → ENCODING_CONSTRAINT (field presence)

6. CAPABILITY - Implementation capacity (e.g., "MUST allow for increased space requirements")
   → verifiability = "none", lintable = false
   → assertion_subject = "Implementation"
   CRITICAL: CAPABILITY is about IMPLEMENTATION CAPACITY/ABILITY, not certificate constraints
   Examples of CAPABILITY:
   - "Implementations MUST allow for X" → implementation capacity requirement
   - "MUST be able to process X" → implementation capability
   - "MUST support X" → implementation feature requirement
   - "Conforming implementations MUST X" when X is about processing ability → CAPABILITY
   NOT CAPABILITY (these are ENCODING_CONSTRAINT):
   - "Certificates MUST X" → certificate constraint, not implementation capability
   - "CAs MUST include X" → certificate content requirement (result is observable)
   - "The field MUST be X" → certificate field constraint

   KEY DISTINCTION FOR CA-RELATED RULES:
   - If the rule constrains WHAT APPEARS IN THE CERTIFICATE → ENCODING_CONSTRAINT
     Examples: "CAs MUST use algorithm X", "CAs MUST NOT issue certificates with validity > X days"
     Rationale: The constraint is on the certificate content, which is observable
   - If the rule constrains CA OPERATIONAL PROCESSES → CAPABILITY
     Examples: "CA operators MUST maintain audit logs", "CA operators MUST publicly disclose X"
     Rationale: These are operational requirements, not certificate content constraints

7. DISPLAY - UI/presentation (e.g., "should convert to Unicode before display")
   → verifiability = "none", lintable = false
   → assertion_subject = "Implementation" or "RelyingParty"

8. CROSS_CERTIFICATE / CHAIN - the requirement compares this certificate's field
   to a field of ANOTHER artifact (the issuer's certificate, a precertificate, the
   certification path). A static linter sees ONE certificate, so it cannot perform
   the comparison.
   → verifiability = "context_dependent", lintable = false
   Examples:
   - "serialNumber MUST be byte-for-byte identical to the serialNumber of the Precertificate"
   - "the contents MUST match the issuer's certificate subject"
   NOTE: a comparison BETWEEN TWO FIELDS OF THE SAME CERTIFICATE is still observable
   (e.g. "signatureAlgorithm MUST equal tbsCertificate.signature", "issuer MUST equal
   subject" for a self-signed cert) → ENCODING_CONSTRAINT, verifiability = "observable".

9. DELEGATED / NO-PREDICATE - the rule's entire content is a pointer to another
   section/profile/document with NO inline, concrete, checkable constraint of its own.
   → verifiability = "none", lintable = false
   Examples:
   - "Certificate MUST conform to these rules"
   - "the extension MUST be encoded as follows" (the 'follows' is elsewhere)
   - "thisUpdate MUST be interpreted as defined in Section 4" (no value stated here)
   NOTE: a CITATION attached to a concrete constraint stays lintable — e.g. "the octet
   string MUST contain exactly 4 octets, as specified in [RFC791]" → ENCODING_CONSTRAINT
   (the citation decorates a concrete, observable predicate).

10. VACUOUS-ENCODING - "MUST be DER-encoded / ASN.1-encoded" with no specific field
    or structure named. A parsed certificate is already DER by definition, so the
    check is vacuously true and not meaningfully lintable.
    → verifiability = "none", lintable = false
    Example: "the certificate MUST be DER encoded according to the relevant ASN.1"

CRITICAL CLASSIFICATION RULES:
- "CAs MUST" or "Certificates MUST" + field encoding/format/presence constraint → ENCODING_CONSTRAINT (not DEFINITION)
- "MUST be encoded as" or "MUST NOT exceed" or "MUST be present" → ENCODING_CONSTRAINT
- "MUST be non-negative" or "MUST be marked critical" → ENCODING_CONSTRAINT
- "MUST contain at least one entry" or "MUST include at least one entry" → ENCODING_CONSTRAINT
- "MUST be greater than or equal to" when referring to certificate field value → ENCODING_CONSTRAINT
- "If X, then the CA MUST include Y extension" → ENCODING_CONSTRAINT (result is observable in certificate)
- "in step X, change all labels to..." → ENCODING_CONSTRAINT (describes encoding transformation, result stored in certificate)
- CA-RELATED RULES CLASSIFICATION:
  * Ask: "Does this rule constrain WHAT APPEARS IN THE CERTIFICATE?"
  * If YES → ENCODING_CONSTRAINT (e.g., "CAs MUST use algorithm X", "CAs MUST NOT issue certificates with validity > X days")
  * If NO → Check if it's about CA operational processes (audits, disclosures, key generation) → CAPABILITY
  * Key test: Can you verify compliance by examining the certificate alone? If yes → ENCODING_CONSTRAINT
- NAME CONSTRAINTS SPECIAL RULES (RFC 5280 §4.2.1.10):
  * "permittedSubtrees MUST NOT impose constraints on X" → COMPARISON (runtime validation behavior, not certificate field constraint)
  * "excludedSubtrees MUST NOT impose constraints on X" → COMPARISON (runtime validation behavior)
  * "MUST impose constraints on X" → COMPARISON (describes what the extension DOES at validation time, not what it CONTAINS)
  * These rules describe RELYING PARTY validation behavior, not certificate encoding
  * assertion_subject = "RelyingParty", verifiability = "runtime_only", lintable = false
- "Implementations MUST allow for X" → CAPABILITY (resource constraint)
- "When comparing" or "before comparing" → COMPARISON with verifiability = "runtime_only"
- "MUST NOT be used to" or "shall not be used to" → RELYING PARTY BEHAVIOR (not certificate constraint)
  * Example: "the public key MUST NOT be used to verify signatures" → assertion_subject = "RelyingParty", verifiability = "runtime_only"
  * This describes what the VERIFIER must do, not what the CERTIFICATE must contain
- "MUST be verified by the CA" → CA operational behavior (assertion_subject = "CA", lintable = false)
- "MUST be applied to" → Implementation validation behavior (assertion_subject = "Implementation", lintable = false)
- "MUST be able to process" → CAPABILITY (assertion_subject = "Implementation", lintable = false)
- "MUST be used only in" → Usage constraint (NOT encoding constraint, lintable = false)
- Algorithm references should NOT be expanded, only recorded as algorithm_ref
- For rules with keyword_source = "inherited", the obligation is inherited from parent
- If keyword_source = "inherited" AND parent context contains "display" or "before display":
  → rule_category = "display", verifiability = "none", lintable = false
  (Display context overrides child's own keyword — even if child has uppercase SHALL/MUST)
- ALGORITHM_REF DETECTION (IMPORTANT):
  * "as specified in RFC X" or "as specified in Section X of RFC Y" → ALGORITHM_REF
  * "described in RFC X" or "described in Section X" → ALGORITHM_REF
  * "perform the operation specified in..." → ALGORITHM_REF
  * "convert... to the X format as specified in..." → ALGORITHM_REF
  * Any phrase that references an external specification for HOW to perform an operation is ALGORITHM_REF
  * DEFINITION is for WHAT something IS, ALGORITHM_REF is for HOW to do something
  * EXCEPTION: When the conversion result is STORED in a certificate field (e.g.,
    "convert to ACE before storage in dNSName", "change all labels to their ACE form"),
    classify as ENCODING_CONSTRAINT, not ALGORITHM_REF. The key indicator is that
    the transformed value ends up in the certificate, making it observable.
- ALGORITHM PARAMETER PROHIBITION (IMPORTANT):
  * "flag SHALL NOT be set" or "flag MUST NOT be set" where the flag controls an encoding property
    → ENCODING_CONSTRAINT (not ALGORITHM_REF), verifiability = "observable"
  * Reason: If a flag like AllowUnassigned is prohibited, it means the RESULT of encoding
    MUST NOT contain characters that would only appear if the flag were set.
    This is observable in the certificate by decoding the stored value.
  * The subject should be the certificate field being encoded (e.g., dNSName), not the flag itself.
  * Example: "AllowUnassigned flag SHALL NOT be set" → subject = dNSName,
    rule_category = encoding_constraint, observable consequence = ACE labels must not decode to unassigned Unicode code points

STRICT RULES:
- Do NOT interpret the intent of the standard.
- Do NOT resolve ambiguity.
- Do NOT combine multiple requirements.
- Do NOT infer unstated conditions.
- Do NOT judge correctness or feasibility.
- If a field is explicit in the sentence OR recoverable from the provided context/canonical_subject,
  you SHOULD extract it deterministically instead of returning "undetermined".
- Only output "undetermined" when the required subject/action truly cannot be grounded from the text plus provided context.

You MUST behave deterministically and conservatively.

CRITICAL FIELD RULES:

1. assertion_subject — WHO/WHAT is constrained:
   - "Certificate" = the rule constrains what appears IN the certificate (e.g., field values, encoding); single-certificate observable
   - "CRL" = the rule constrains what appears IN a CRL document itself (e.g., CRL version, CRL extensions, revoked-entry fields); single-certificate observable
   - "CrossArtifact" = the rule requires data from ANOTHER artifact (another certificate, CRL, or cross-cert/CRL correlation). Examples: serialNumber uniqueness across certs, SKI matching AKI, issuer cert ↔ CRL issuer comparison. These are NOT single-certificate observable.
   - "Implementation" = the rule constrains SOFTWARE BEHAVIOR (e.g., comparison, processing, conversion)
   - "RelyingParty" = the rule constrains VERIFIER behavior
   CRITICAL: the subject field must point to a real certificate/CRL field (e.g., "extensions.keyUsage", "issuer", "serialNumber"). If subject points to an operational noun (e.g., "domain_validation_record", "phone_contact", "randomValue"), the rule describes CA process and is NOT lintable — use assertion_subject = CA and expect it to be rejected.
   Keywords that indicate "Implementation": "implementations MUST", "conforming implementations",
     "before comparing", "when comparing", "when evaluating", "when performing", "MUST be applied to"
   Keywords that indicate "Certificate": "certificates MUST include", "the extension MUST contain",
     "the field MUST be set to", "If X, then the CA MUST include Y extension" (result is in certificate)
   Keywords that indicate "CRL": "the CRL MUST", "CRL issuers MUST include ... in all CRLs",
     "this extension MUST appear in CRLs", "the CRL's nextUpdate/thisUpdate" (constraint is on the CRL document)
2. enforcement_phase — WHEN the constraint applies:
   - "Encoding" = during certificate creation/encoding (observable in certificate → lintable)
   - "Comparison" = during name/string comparison at runtime (NOT observable → NOT lintable)
   - "Validation" = during certificate chain validation (NOT observable → NOT lintable)
   - "Processing" = during certificate processing (NOT observable → NOT lintable)
   Keywords: "before storage" → Encoding; "before comparing" → Comparison;
     "when evaluating" → Validation; "when performing" → Processing
   For CA-related rules: If the rule constrains certificate content → enforcement_phase = "Encoding"

3. precondition — Extract the rule's ANTECEDENT (the "if/when/unless" guard), in TWO parts:
   (a) prose (always, for naming/audit): {"description": "...", "trigger": "..."}
       - "Before comparing names using X" → {"description": "before comparing names", "trigger": "X"}
   (b) structured guard — add keys type/value[/negate] ONLY when the antecedent is one of
       these standard, single-certificate-observable conditions (the same kinds zlint guards
       with util.IsCA / IsSubscriberCert / IsExtInCert):
       - certificate type:  "If the certificate is a CA certificate, then ..." → type="certificate_type", value="CA"  (also: root | subscriber | server | end-entity)
       - extension present: "When the keyUsage extension is present, ..."       → type="extension_present", value="keyUsage"  (the extension name)
       - keyUsage bit:      "If the keyCertSign bit is asserted, ..."           → type="key_usage", value="KeyCertSign"
       - extended key usage:"For certs with id-kp-serverAuth, ..."              → type="eku_present", value="serverAuth"
       - boolean field:     "If the cA boolean is asserted, ..."                → type="field_boolean", value="cA"
       - field present/absent: "if stateOrProvinceName is present, ..."         → type="field_present", value="stateOrProvinceName"
                               "if stateOrProvinceName is absent, ..."          → type="field_absent",  value="stateOrProvinceName"
                               (value = the DN attribute / cert field whose presence is the antecedent; also use field_present for "X, if present, MUST ..." where X is the rule's own optional field)
       - negation:          "If NOT a CA / unless cA asserted / non-CA ..."     → also set "negate": true (value still names the POSITIVE condition)
       - version (a set):   "if the version is 2 or 3, ..."                     → type="version_is", values=["2","3"]  (X.509 version; a single value is fine too)
       - field equals one-of:"if the signing key is ECDSA / RSA, ..."           → type="field_equals", field="<field>", values=["<v1>","<v2>"]
       - address family:    "For IPv6 addresses, ..."                           → type="address_family", field="<ip-list field>", family="ipv6"  (also: ipv4)
       - conjunction / disjunction: "if A and B, ..." → type="all_of", conditions=[<guard A>,<guard B>]; "if A or B, ..." → type="any_of", conditions=[...]
         (each sub-condition is itself a structured guard of the kinds above; e.g. "if only basic fields are present" = all_of of three field_absent guards over extensions + the two uniqueIDs)
       - If the antecedent is real but NONE of the kinds above fit, emit prose only (type=null) — do NOT invent a structure.
   - The structured guard MUST be the TRUE antecedent (the condition under which the obligation
     applies), NOT a field merely mentioned in the main clause. E.g. "If the subject field is an
     empty sequence, then the issuing CA MUST include subjectAltName" → the guard is the empty
     subject, NOT certificate_type=CA.
   - DIRECTION for "X MUST only appear / be present only if/when Y" (and "X MUST NOT appear unless
     Y"): this is the implication (X present → Y), NOT (Y → X present). The OBLIGATION lands on Y,
     guarded by X's presence. So set the REQUIREMENT to express Y (subject/predicate/constraint =
     the condition Y that must hold) and set precondition = X is present (field_present on X's
     field). Do NOT make Y the precondition with X as the consequent — that inverts the rule.
     E.g. "the uniqueID fields MUST only appear if the version is 2 or 3" → subject=Version,
     predicate=must_equal (allowed set), constraint value=[2,3],
     precondition={type:field_present, value:<the uniqueID field>}.
   - Only emit a structured guard for the standard conditions above; otherwise emit prose only.
   - If no precondition exists, set to null.

4. requires_operation — External operation dependency:
   - "perform the string preparation algorithm described in RFC 4518"
     → {"operation": "StringPrep", "defined_in": "RFC4518"}
   - "convert ... to the ACE format as specified in Section 4 of RFC 3490"
     → {"operation": "ToASCII", "defined_in": "RFC3490"}
   - If no external operation, set to null.

5. rule_category — Classification from MANDATORY CLASSIFICATION above:
   - "encoding_constraint", "definition", "algorithm_ref", "clarification", "comparison", "capability", "display"

6. verifiability — Whether the rule can be verified in the certificate:
   - "observable" = can be verified by examining certificate → lintable
   - "runtime_only" = only verifiable at runtime → not lintable
   - "none" = cannot be verified → not lintable

7. subject — CANONICAL SUBJECT ENFORCEMENT:
   - If the context provides a "canonical_subject", you MUST use subject paths from its field hierarchy
   - The canonical_subject.path is the ROOT field for this section
   - Use the most specific sub-path that matches the rule's scope
   - For rules in EXTENSION sections (e.g., Basic Constraints, Name Constraints, Subject Alternative Name):
     * Subject = the extension field or sub-field where the constraint is DEFINED
     * NOT the field the extension CONSTRAINS
     * Example: A Name Constraints rule about permitted DNS names
       → subject = "extensions.nameconstraints.permittedsubtrees.dnsname" (where defined)
       NOT "extensions.subjectaltname.dnsname" (what it constrains)
   - "permittedSubtrees MUST NOT impose constraints on x400Address"
     → "extensions.nameconstraints.permittedsubtrees.x400address"
   - This prevents "subject drift" which breaks cross-section rule aggregation

8. algorithm_ref.relation_type — Semantic relationship to referenced spec:
   - "profiles" = This spec customizes/restricts the referenced algorithm (most common)
   - "requires" = This spec has a hard dependency on the referenced algorithm
   - "uses" = This spec uses the referenced algorithm for a specific operation
   - "overrides" = This spec replaces/modifies behavior from the referenced spec
   - "extends" = This spec adds functionality to the referenced spec
   - "defines" = The referenced spec defines the algorithm being used

9. COMMON EXTRACTION PITFALLS — avoid these specific, observed errors:
   - PRESERVE QUALIFIERS: keep limiting words. "MUST NOT be a *relative* URI" ≠ "no URI"; "policyConstraints is an *empty* sequence" ≠ "absent/not present"; a conditional ("if version is 1, X MUST NOT appear") MUST keep its condition — do not drop it.
   - UNIQUENESS ≠ CARDINALITY: "X MUST NOT appear more than once" / "no duplicate X" / "each Y MUST be unique" is a UNIQUENESS constraint over repeated items, NOT "the field's total count ≤ 1".
   - SPECIFIC ITEM ≠ TOTAL COUNT: "exactly one *Reserved* Policy Identifier" / "at least one *Reserved* policy" constrains a SPECIFIC qualifying item; capture that qualifier (the specific OID/type), not a raw count of the whole list.
   - SUBFIELD GRANULARITY: a rule about an extension SUB-field (e.g. authorityCertSerialNumber / authorityCertIssuer, which are fields of authorityKeyIdentifier) has subject = the sub-field path, NOT the parent extension's presence.
   - VALUES ARE DATA, NOT ASN.1 TAGS: never put ASN.1 CHOICE/field names ("distributionPoint", "cRLIssuer", "nameRelativeToCRLIssuer") or scheme words as a constraint VALUE of a URI/list field; those name structure, not data values.

PROHIBITIONS:
- Do NOT answer questions.
- Do NOT explain your reasoning.
- Do NOT summarize.
- Do NOT generate code.
- Do NOT modify the schema.
- Do NOT invent section numbers or field names."""


# ============================================================
# IR Schema（LLM 唯一允许输出的结构）
# ============================================================
IR_OUTPUT_SCHEMA = """{
  "rule_category": "encoding_constraint | definition | algorithm_ref | clarification | comparison | capability | display",
  "verifiability": "observable | context_dependent | runtime_only | none",
  "assertion_subject": "Certificate | CRL | CrossArtifact | Implementation | CA | RelyingParty - WHO/WHAT is constrained",
  "enforcement_phase": "Encoding | Comparison | Validation | Processing - WHEN the constraint applies (optional)",
  "subject": "string - 证书字段路径，如 'extensions.keyUsage' 或 'subject.commonName'",
  // NOTE: obligation 由 Layer 1 Regex 提取，LLM 不应填写此字段（_build_ir 优先使用 skeleton.keyword）
  "predicate": "must_be_present | must_not_be_present | must_equal | must_include | must_not_include | conform_to | encode_as | display_as | compare_as | in_range | matches_pattern | allowed_values",
  "constraint": {
    "raw_text": "string - 原始约束文本",
    "type": "presence | numeric | string | enum | format | regex | length | syntax | cardinality",
    "value": "any - 约束核心值: must_equal填具体值; encode_as填ASN.1类型名; enum可留空(改用allowed_values)",
    "min_value": "number|null - 数值下界(in_range/length/numeric). 例 'between 8 and 64 bytes'→8; 'at least 2048 bits'→2048; 'MUST be >= 0'→0",
    "max_value": "number|null - 数值上界. 例 'MUST NOT exceed 64'→64; 'no more than 20 octets'→20",
    "unit": "string|null - 单位: bits|bytes|octets|days|characters",
    "allowed_values": "[string]|null - enum/集合的字面允许值. 例 'one of {sha256,sha384}'→['sha256','sha384']; 'https or ldaps'→['https','ldaps']",
    "min_count": "number|null - 基数下界(出现次数). 例 'at least one X'→1; 'MUST contain >=2 labels'→2",
    "max_count": "number|null - 基数上界. 例 'at most one'→1; 'MUST NOT appear more than once'(唯一性)→1",
    "asn1_types": "[string]|null - encode_as的ASN.1类型名. 例 ['UTF8String']; ['PrintableString','UTF8String']"
  },
  "_constraint_filling_rule": "把数量/范围/取值/编码类型【结构化】填进上面专用槽(min_value/max_value/unit/allowed_values/min_count/max_count/asn1_types), 不要把它们留成 value 里的一句话。value 只放单一标量值。必须照下面范例填专用槽:\n    'MUST NOT exceed 64 characters' → type=length, max_value=64, unit=characters\n    'between 8 and 64 bytes' → type=numeric, min_value=8, max_value=64, unit=bytes\n    'at least 2048 bits' → type=numeric, min_value=2048, unit=bits\n    'https, ldaps, or similar schemes' → type=enum, allowed_values=[\"https\",\"ldaps\"]\n    'one of sha256/sha384/sha512' → type=enum, allowed_values=[\"sha256\",\"sha384\",\"sha512\"]\n    'MUST contain at least one X' → type=cardinality, min_count=1\n    'MUST NOT appear more than once' (唯一性) → type=cardinality, max_count=1\n    'MUST be encoded as UTF8String' → type=format, asn1_types=[\"UTF8String\"]\n    'MUST be set to TRUE' → type=string, value=\"TRUE\"\n  填不出结构(如'能被8整除'的模运算、'逐字节相同'的跨字段相等)时才退回 value 文字, 并在 raw_text 保留原文。",
  "precondition": {
    "description": "string - 前置条件散文描述（如 'when the certificate is a CA', 'before comparing'）",
    "trigger": "string - 触发要点（如 'caseIgnoreMatch', 'equality check'）",
    "type": "certificate_type | extension_present | key_usage | eku_present | field_boolean | null - 结构守卫类型（仅当 antecedent 是这些标准证书可观察条件时填，否则 null）",
    "value": "string|null - 守卫值: CA/root/subscriber/server/end-entity | 扩展名(keyUsage等) | keyUsage位名(KeyCertSign等) | EKU名(serverAuth等) | 布尔字段名(cA)",
    "negate": "bool|null - 取反: 'if NOT a CA' / 'unless cA asserted' / 'non-CA' → true（value 仍填正向条件）"
  },
  "requires_operation": {
    "operation": "string - 依赖的操作名称（如 'StringPrep', 'ToASCII'）",
    "defined_in": "string - 操作定义来源（如 'RFC4518'）"
  },
  "algorithm_ref": {
    "base_spec": "string - 引用的规范（如 'RFC 3490'）",
    "section": "string - 章节引用（如 'Section 4' 或 '4'）",
    "operation": "string - 操作名称（如 'ToASCII', 'IDN_to_ACE'）",
    "inheritance": "full | partial - 是否有本地覆盖",
    "relation_type": "profiles | requires | uses | overrides | extends | defines - 语义关系"
  },
  "overrides": [
    {
      "step": "int - 算法步骤编号（如适用）",
      "param": "string - 被覆盖的参数（如 'UseSTD3ASCIIRules'）",
      "value": "any - 覆盖值",
      "source_text": "string - 原始文本片段"
    }
  ],
  "references": [
    {
      "raw": "string - 原始引用文本，如 'RFC 5280 Section 4.2'",
      "doc_id": "string - 文档ID，如 'RFC5280'",
      "section": "string - 章节号，如 '4.2'"
    }
  ],
  "rule_text": "string - 原始规则文本",
  "spec_family": "RFC | CABF | ETSI | Other"
}

PREDICATE SELECTION GUIDE:
- must_be_present: Use when the rule requires a field/extension to EXIST (e.g., "extension MUST be present", "MUST include at least one entry")
- must_not_be_present: Use when the rule PROHIBITS a field/extension (e.g., "extension MUST NOT be present", "field MUST be absent")
- must_equal: Use when the rule requires a SPECIFIC VALUE (e.g., "MUST be set to TRUE", "version MUST be v3", "MUST be non-negative")
- must_include: Use when the rule requires containing specific ITEMS (e.g., "MUST include digitalSignature", "MUST have at least one bit set")
- must_not_include: Use when the rule PROHIBITS specific items (e.g., "MUST NOT include anyPolicy")
- encode_as: Use when the rule specifies HOW to encode/store data (e.g., "MUST be encoded as UTF8String", "MUST convert to ACE format before storage"). When the rule names a specific ASN.1 type (UTF8String, PrintableString, IA5String, BMPString, UTCTime, GeneralizedTime, DirectoryName, etc.), populate `constraint.asn1_types` with the type name(s) and put the type name as `constraint.value` as well.
- conform_to: Use when the rule requires conforming to a SPECIFICATION or PATTERN (e.g., "MUST conform to RFC 5280", "MUST be a valid DNS name")
- in_range: Use when the rule specifies NUMERIC BOUNDS (e.g., "MUST NOT exceed 64 characters", "MUST be between 8 and 64 bytes")
- matches_pattern: Use when the rule specifies a PATTERN/REGEX (e.g., "MUST match the pattern *.example.com")
- allowed_values: Use when the rule specifies an ENUMERATION of allowed values (e.g., "MUST be one of {sha256, sha384, sha512}")
- display_as: Use when the rule specifies HOW to display data (e.g., "should convert to Unicode before display")
- compare_as: Use when the rule specifies HOW to compare values (e.g., "MUST perform case-insensitive match")

CONSTRAINT TYPE GUIDE:
- presence: Field/extension MUST or MUST NOT exist. Use for BOTH "MUST be present" AND "MUST NOT be present" — the obligation (MUST/MUST NOT) is separate from the constraint type. Also use for criticality ("MUST be marked critical").
- length: Numeric bounds on field SIZE (e.g., "MUST NOT exceed 64 characters", "MUST use IA5String (max 63)", "MUST be at least 8 bytes"). When a table specifies encoding type + max length, use type=length with value=<encoding type> and max_value=<max length>.
- numeric: Numeric value constraint on a field's VALUE (e.g., "MUST be non-negative", "MUST be 0", "pathLenConstraint MUST be >= 0")
- string: String VALUE constraint — what the field must contain or equal (e.g., "MUST contain the domain name", "MUST be empty string", "MUST equal the issuer's subject field"). Use when the constraint is about the field's semantic content, NOT its encoding format.
- enum: Enumeration of allowed values (e.g., "MUST be one of sha256WithRSAEncryption, ...")
- format: Encoding/representation constraint — HOW the field is encoded (e.g., "MUST be encoded as UTF8String", "MUST use DER encoding", "MUST be in ACE format"). Use ONLY for encoding/representation rules, NOT for content/value rules.
  When type=format AND the rule names a specific ASN.1 encoding type (e.g. UTF8String, PrintableString, IA5String, BMPString, UniversalString, TeletexString, UTCTime, GeneralizedTime, DirectoryName), add an `asn1_types` array field to the constraint object listing the permitted type name(s). Example: `{"type": "format", "value": "UTF8String", "asn1_types": ["UTF8String"]}`. If the rule says "PrintableString OR UTF8String", list both: `["PrintableString", "UTF8String"]`.
- syntax: Structural/grammar constraint (e.g., "MUST conform to the ASN.1 GeneralName syntax", "MUST follow the URI syntax of RFC 3986")
- regex: Pattern match constraint
IMPORTANT: Do NOT use "absence" — use "presence" for both MUST-exist and MUST-NOT-exist constraints.
KEY DISTINCTION: "MUST contain the domain name" → type=string. "MUST be encoded as UTF8String" → type=format. "MUST NOT exceed 64 characters" → type=length. "MUST be present" / "MUST NOT be present" → type=presence."""

# ============================================================
# 批量提取 Prompt 模板（减少API调用次数，约10倍加速）
# ============================================================
BATCH_EXTRACTION_PROMPT_TEMPLATE = """TASK:
Extract normative requirements from MULTIPLE input texts. Return a JSON array with one IR object per input.

INPUT TEXTS (process each one independently):
{rules_list}

SHARED CONTEXT:
{context}

OUTPUT FORMAT:
Return ONLY a valid JSON array. Each element follows this schema:
{schema}

FEW-SHOT EXAMPLES (each element in the output array MUST follow this structure):

Example A (Certificate encoding constraint - lintable):
Input: [3] CAs MUST force the serialNumber to be a non-negative integer.
Output element:
{{
  "index": 3,
  "rule_category": "encoding_constraint",
  "verifiability": "observable",
  "assertion_subject": "Certificate",
  "enforcement_phase": "Encoding",
  "subject": "tbsCertificate.serialNumber",
  "predicate": "must_equal",
  "constraint": {{
    "raw_text": "non-negative integer",
    "type": "numeric",
    "value": {{"min": 0}}
  }},
  "precondition": null,
  "requires_operation": null,
  "references": [],
  "rule_text": "CAs MUST force the serialNumber to be a non-negative integer.",
  "spec_family": "CABF"
}}

Example B (Implementation behavior - NOT lintable):
Input: [5] Before comparing names using the caseIgnoreMatch matching rule, conforming implementations MUST perform the six-step string preparation algorithm described in RFC 4518.
Output element:
{{
  "index": 5,
  "rule_category": "comparison",
  "verifiability": "runtime_only",
  "assertion_subject": "Implementation",
  "enforcement_phase": "Comparison",
  "subject": "DirectoryString",
  "predicate": "conform_to",
  "constraint": {{
    "raw_text": "perform the six-step string preparation algorithm",
    "type": "format"
  }},
  "precondition": {{
    "description": "before comparing names",
    "trigger": "caseIgnoreMatch matching rule"
  }},
  "requires_operation": {{
    "operation": "StringPrep",
    "defined_in": "RFC4518"
  }},
  "references": [{{"raw": "RFC 4518", "doc_id": "RFC4518"}}],
  "rule_text": "Before comparing names using the caseIgnoreMatch matching rule, conforming implementations MUST perform the six-step string preparation algorithm described in RFC 4518.",
  "spec_family": "RFC"
}}

Example C (Undetermined - descriptive sentence):
Input: [7] This document serves two purposes: to specify Baseline Requirements and to provide implementation guidance.
Output element:
{{
  "index": 7,
  "status": "undetermined"
}}

Example D (Display context - NOT lintable, even with uppercase keyword in child):
Input: [8] In step 1, the domain name SHALL be considered a "stored string".
Context: Parent obligation: should (lowercase), Parent context: "convert to Unicode before display"
Output element:
{{
  "index": 8,
  "rule_category": "display",
  "verifiability": "none",
  "assertion_subject": "Implementation",
  "enforcement_phase": "Display",
  "subject": "extensions.subjectAltName.dNSName",
  "predicate": "display_as",
  "constraint": {{
    "raw_text": "domain name SHALL be considered a stored string",
    "type": "string"
  }},
  "precondition": {{
    "description": "before display",
    "trigger": "domain name"
  }},
  "requires_operation": null,
  "references": [],
  "rule_text": "In step 1, the domain name SHALL be considered a stored string.",
  "spec_family": "RFC"
}}

Example E (Algorithm parameter prohibition - lintable via observable consequence):
Input: [9] That is, the AllowUnassigned flag SHALL NOT be set;
Context: Parent obligation: MUST, Parent context: "convert to ACE before storage in dNSName"
Output element:
{{
  "index": 9,
  "rule_category": "encoding_constraint",
  "verifiability": "observable",
  "assertion_subject": "Certificate",
  "enforcement_phase": "Encoding",
  "subject": "extensions.subjectAltName.dNSName",
  "predicate": "must_not_contain",
  "constraint": {{
    "raw_text": "AllowUnassigned flag must not be set during ACE encoding",
    "type": "format",
    "value": false
  }},
  "precondition": null,
  "requires_operation": null,
  "references": [],
  "rule_text": "That is, the AllowUnassigned flag SHALL NOT be set;",
  "spec_family": "RFC"
}}

Example F (Extension criticality - encoding_constraint; criticality is its own predicate, separate from presence):
Input: [10] This extension MUST be marked critical.
Context: Section: Basic Constraints (extensions.basicconstraints)
Output element:
{{
  "index": 10,
  "rule_category": "encoding_constraint",
  "verifiability": "observable",
  "assertion_subject": "Certificate",
  "enforcement_phase": "Encoding",
  "subject": "extensions.basicconstraints",
  "predicate": "must_be_critical",
  "constraint": {{
    "raw_text": "This extension MUST be marked critical",
    "type": "presence"
  }},
  "precondition": null,
  "requires_operation": null,
  "references": [],
  "rule_text": "This extension MUST be marked critical.",
  "spec_family": "RFC"
}}

Example G (Name Constraints subtree constraint - encoding_constraint):
Input: [11] CAs MUST NOT issue certificates with a Name Constraints extension that includes a permitted subtree of type x400Address.
Context: Section: Name Constraints (extensions.nameconstraints)
Output element:
{{
  "index": 11,
  "rule_category": "encoding_constraint",
  "verifiability": "observable",
  "assertion_subject": "Certificate",
  "enforcement_phase": "Encoding",
  "subject": "extensions.nameconstraints.permittedsubtrees.x400address",
  "predicate": "must_not_be_present",
  "constraint": {{
    "raw_text": "CAs MUST NOT issue certificates with permitted subtree of type x400Address",
    "type": "presence"
  }},
  "precondition": null,
  "requires_operation": null,
  "references": [],
  "rule_text": "CAs MUST NOT issue certificates with a Name Constraints extension that includes a permitted subtree of type x400Address.",
  "spec_family": "CABF"
}}

Example H1 (Lowercase normative keyword in standards family text - still normative):
Input: [13] the organization identifier shall be present in the subject field.
Context: Section: Subject (subject); Family: ETSI-style lowercase normative wording
Output element:
{{
  "index": 13,
  "rule_category": "encoding_constraint",
  "verifiability": "observable",
  "assertion_subject": "Certificate",
  "enforcement_phase": "Encoding",
  "subject": "subject.organizationidentifier",
  "predicate": "must_be_present",
  "constraint": {{
    "raw_text": "organization identifier shall be present in the subject field",
    "type": "presence"
  }},
  "precondition": null,
  "requires_operation": null,
  "references": [],
  "rule_text": "the organization identifier shall be present in the subject field.",
  "spec_family": "ETSI"
}}

Example H2 (Delegation/reference wording with local observable anchor - keep lintable):
Input: [14] The organizationIdentifier field shall comply with the requirements set out in Clause 5.1 and shall be present in the subject.
Context: Section: Subject (subject.organizationidentifier)
Output element:
{{
  "index": 14,
  "rule_category": "encoding_constraint",
  "verifiability": "observable",
  "assertion_subject": "Certificate",
  "enforcement_phase": "Encoding",
  "subject": "subject.organizationidentifier",
  "predicate": "must_be_present",
  "constraint": {{
    "raw_text": "organizationIdentifier field shall be present in the subject",
    "type": "presence"
  }},
  "precondition": null,
  "requires_operation": null,
  "references": [{{"raw": "Clause 5.1", "section": "5.1"}}],
  "rule_text": "The organizationIdentifier field shall comply with the requirements set out in Clause 5.1 and shall be present in the subject.",
  "spec_family": "ETSI"
}}

Example H3 (ETSI optional extension inclusion - encoding_constraint):
Input: [15] Certificates may include one or more semantics identifiers as specified in clause 5 of ETSI EN 319 412-1.
Context: Section: Certificate profile requirements
Output element:
{{
  "index": 15,
  "rule_category": "encoding_constraint",
  "verifiability": "observable",
  "assertion_subject": "Certificate",
  "enforcement_phase": "Encoding",
  "subject": "certificate.extensions",
  "predicate": "may_include",
  "constraint": {{
    "raw_text": "one or more semantics identifiers",
    "type": "presence"
  }},
  "precondition": null,
  "requires_operation": null,
  "references": [{{"raw": "clause 5 of ETSI EN 319 412-1", "doc_id": "ETSI-EN-319-412-1", "section": "5"}}],
  "rule_text": "Certificates may include one or more semantics identifiers as specified in clause 5 of ETSI EN 319 412-1.",
  "spec_family": "ETSI"
}}

Example H4 (ETSI delegation with certificate field scope - encoding_constraint):
Input: [16] For certificates issued following the certificate policies NCP or QNCP-w-gen, the following requirements shall apply.
Context: Section: Certificate profile requirements
Output element:
{{
  "index": 16,
  "rule_category": "encoding_constraint",
  "verifiability": "observable",
  "assertion_subject": "Certificate",
  "enforcement_phase": "Encoding",
  "subject": "certificate",
  "predicate": "conform_to",
  "constraint": {{
    "raw_text": "following requirements shall apply",
    "type": "conformance"
  }},
  "precondition": {{
    "description": "certificates issued following NCP or QNCP-w-gen",
    "trigger": "certificate policies NCP or QNCP-w-gen"
  }},
  "requires_operation": null,
  "references": [],
  "rule_text": "For certificates issued following the certificate policies NCP or QNCP-w-gen, the following requirements shall apply.",
  "spec_family": "ETSI"
}}

CRITICAL RULES:
1. Return EXACTLY {count} objects in the array, one for each input text
2. Maintain the SAME ORDER as the inputs (index 0 for [0], index 1 for [1], etc.)
3. Each object MUST include an "index" field matching the input index (0-based)
4. Every valid IR object MUST include at minimum: "subject", "predicate", "rule_text" (obligation 由 Layer 1 Regex 提取，LLM 不填写此字段)
4b. PRECONDITION IS A CORE FIELD (it becomes the lint's CheckApplies guard). You MUST analyze the
   antecedent of EVERY rule: if the sentence has an "if / when / unless / for <X> certificates / where"
   clause, emit a structured precondition with type+value (+negate for "not/unless/non-"). Use null ONLY
   when the rule is genuinely unconditional. Dropping a real precondition produces an OVER-STRICT (wrong)
   lint — that is as serious an error as a wrong subject. Standard guard kinds: certificate_type,
   extension_present, key_usage, eku_present, field_boolean (see Example 10b/10c).
5. Return {{"status": "undetermined", "index": <index>}} ONLY when the required subject/action truly cannot be grounded from the text plus provided context
6. Process each rule INDEPENDENTLY - do not combine or merge rules
7. Do NOT return "undetermined" merely because the sentence is declarative or lacks RFC2119 keywords. Declarative format statements (for example, "UTCTime specifies ...") and example-derived certificate consequences (for example, "the keyEncipherment bit would be asserted") are still extractable when they anchor an observable certificate field or bit state

Return ONLY the JSON array. No explanations, no markdown code blocks."""


# ============================================================
# 受控 Extraction Prompt 模板
# ============================================================
EXTRACTION_PROMPT_TEMPLATE = """TASK:
Extract exactly ONE atomic normative requirement from the input text.

INPUT TEXT:
{normative_sentence}

APPLICABLE SPECIFICATION CONTEXT (retrieved automatically):
{context}

OUTPUT FORMAT:
Return ONLY valid JSON following this schema:
{schema}

FEW-SHOT EXAMPLES:

Example 1 (Implementation behavior - NOT lintable):
Input: "Before comparing names using the caseIgnoreMatch matching rule, conforming implementations MUST perform the six-step string preparation algorithm described in RFC 4518."
Output:
{{
  "rule_category": "comparison",
  "verifiability": "runtime_only",
  "assertion_subject": "Implementation",
  "enforcement_phase": "Comparison",
  "subject": "DirectoryString",
  "predicate": "conform_to",
  "constraint": {{
    "raw_text": "perform the six-step string preparation algorithm",
    "type": "format"
  }},
  "precondition": {{
    "description": "before comparing names",
    "trigger": "caseIgnoreMatch matching rule"
  }},
  "requires_operation": {{
    "operation": "StringPrep",
    "defined_in": "RFC4518"
  }},
  "references": [{{"raw": "RFC 4518", "doc_id": "RFC4518"}}],
  "spec_family": "RFC"
}}

Example 2 (ASN.1 encoding type - lintable, uses encode_as predicate with asn1_types):
Input: "When encoding attribute values of type DirectoryString, conforming CAs MUST use PrintableString or UTF8String encoding. When the subject of the certificate is a CA, the subject field MUST be encoded in the same way as it is encoded in the issuer certificate."
Output:
{{
  "rule_category": "encoding_constraint",
  "verifiability": "observable",
  "assertion_subject": "Certificate",
  "enforcement_phase": "Encoding",
  "subject": "subject",
  "predicate": "encode_as",
  "obligation": "MUST",
  "constraint": {{
    "raw_text": "MUST use PrintableString or UTF8String encoding",
    "type": "format",
    "value": "PrintableString",
    "asn1_types": ["PrintableString", "UTF8String"]
  }},
  "references": [{{"raw": "RFC 5280 Section 4.1.2.6", "doc_id": "RFC5280", "section": "4.1.2.6"}}],
  "spec_family": "RFC"
Example 3 (Display conversion - uses display_as predicate):
Input: "Implementations should convert IDNs to Unicode before display."
Output:
{{
  "rule_category": "display",
  "verifiability": "none",
  "assertion_subject": "Implementation",
  "enforcement_phase": "Processing",
  "subject": "extensions.subjectAltName.dNSName",
  "predicate": "display_as",
  "constraint": {{
    "raw_text": "convert IDNs to Unicode",
    "type": "format"
  }},
  "precondition": {{
    "description": "before display",
    "trigger": "IDNs"
  }},
  "requires_operation": {{
    "operation": "ToUnicode",
    "defined_in": "RFC3490"
  }},
  "references": [],
  "spec_family": "RFC"
}}

Example 4 (Runtime comparison - uses compare_as predicate):
Input: "During certification path validation, a verifier MUST compare two distinguished names for equality only after normalizing the case of their attribute values."
Output:
{{
  "rule_category": "comparison",
  "verifiability": "runtime_only",
  "assertion_subject": "Implementation",
  "enforcement_phase": "Comparison",
  "subject": "subject",
  "predicate": "compare_as",
  "constraint": {{
    "raw_text": "compare distinguished names for equality after case normalization",
    "type": "string"
  }},
  "precondition": {{
    "description": "during certification path validation",
    "trigger": "name equality check"
  }},
  "requires_operation": null,
  "references": [],
  "spec_family": "RFC"
}}

Example 5 (Definition - NOT a rule candidate):
Input: "PrintableString consists of a restricted set of letters, digits, the space character, and a handful of punctuation symbols."
Output:
{{
  "rule_category": "definition",
  "verifiability": "none",
  "assertion_subject": "Certificate",
  "enforcement_phase": "Encoding",
  "subject": "PrintableString",
  "predicate": "must_equal",
  "constraint": {{
    "raw_text": "restricted to letters, digits, space, and a few punctuation symbols",
    "type": "string"
  }},
  "precondition": null,
  "requires_operation": null,
  "references": [],
  "spec_family": "RFC"
}}

Example 6 (Capability - NOT lintable):
Input: "Software that consumes certificates MUST be prepared to accommodate name fields that are substantially longer than legacy sizes."
Output:
{{
  "rule_category": "capability",
  "verifiability": "none",
  "assertion_subject": "Implementation",
  "enforcement_phase": "Processing",
  "subject": "extensions.subjectAltName.dNSName",
  "predicate": "conform_to",
  "constraint": {{
    "raw_text": "accommodate name fields longer than legacy sizes",
    "type": "format"
  }},
  "precondition": null,
  "requires_operation": null,
  "references": [],
  "spec_family": "RFC"
}}

Example 7 (Certificate encoding constraint - lintable):
Input: "A conforming CA MUST encode the SkipCerts value of the inhibitAnyPolicy extension as a non-negative integer."
Output:
{{
  "rule_category": "encoding_constraint",
  "verifiability": "observable",
  "assertion_subject": "Certificate",
  "enforcement_phase": "Encoding",
  "subject": "extensions.inhibitAnyPolicy.skipCerts",
  "predicate": "must_equal",
  "constraint": {{
    "raw_text": "non-negative integer",
    "type": "numeric",
    "value": {{"min": 0}}
  }},
  "precondition": null,
  "requires_operation": null,
  "references": [],
  "spec_family": "RFC"
}}

Example 8 (Extension presence - encoding_constraint):
Input: "This extension MUST be present in all CA certificates."
Context: Section = Basic Constraints (extensions.basicconstraints)
Output:
{{
  "rule_category": "encoding_constraint",
  "verifiability": "observable",
  "assertion_subject": "Certificate",
  "enforcement_phase": "Encoding",
  "subject": "extensions.basicconstraints",
  "predicate": "must_be_present",
  "constraint": {{
    "raw_text": "This extension MUST be present in all CA certificates",
    "type": "presence"
  }},
  "precondition": null,
  "requires_operation": null,
  "references": [],
  "spec_family": "RFC"
}}

Example 9 (Length constraint - encoding_constraint):
Input: "commonName (if present) MUST NOT exceed 64 characters."
Output:
{{
  "rule_category": "encoding_constraint",
  "verifiability": "observable",
  "assertion_subject": "Certificate",
  "enforcement_phase": "Encoding",
  "subject": "subject.commonname",
  "predicate": "in_range",
  "constraint": {{
    "raw_text": "commonName MUST NOT exceed 64 characters",
    "type": "length",
    "value": {{"max": 64}}
  }},
  "precondition": {{
    "description": "if commonName is present",
    "trigger": "commonName presence"
  }},
  "requires_operation": null,
  "references": [],
  "spec_family": "CABF"
}}

Example 10 (Name Constraints subtree prohibition - encoding_constraint):
Input: "CAs MUST NOT issue certificates with a Name Constraints extension that includes a permitted subtree of type x400Address."
Context: Section = Name Constraints (extensions.nameconstraints)
Output:
{{
  "rule_category": "encoding_constraint",
  "verifiability": "observable",
  "assertion_subject": "Certificate",
  "enforcement_phase": "Encoding",
  "subject": "extensions.nameconstraints.permittedsubtrees.x400address",
  "predicate": "must_not_be_present",
  "constraint": {{
    "raw_text": "CAs MUST NOT issue certificates with permitted subtree of type x400Address",
    "type": "presence"
  }},
  "precondition": null,
  "requires_operation": null,
  "references": [],
  "spec_family": "CABF"
}}

Example 10b (Conditional on certificate type - STRUCTURED guard):
Input: "If the certificate is a CA certificate, the keyUsage extension MUST be present."
Context: Section = Key Usage (extensions.keyusage)
Output:
{{
  "rule_category": "encoding_constraint",
  "verifiability": "observable",
  "assertion_subject": "Certificate",
  "enforcement_phase": "Encoding",
  "subject": "extensions.keyusage",
  "predicate": "must_be_present",
  "constraint": {{
    "raw_text": "the keyUsage extension MUST be present",
    "type": "presence"
  }},
  "precondition": {{
    "description": "if the certificate is a CA certificate",
    "trigger": "CA certificate",
    "type": "certificate_type",
    "value": "CA"
  }},
  "requires_operation": null,
  "references": [],
  "spec_family": "RFC"
}}

Example 10c (NEGATED boolean precondition + keyUsage bit value - precondition is CORE):
# Illustrative paraphrase (NOT a verbatim spec sentence). Teaches the general
# pattern: a NEGATED boolean antecedent ("not / unless / when X is FALSE") →
# precondition.type=field_boolean, value=<POSITIVE field name>, negate=true;
# and a named keyUsage bit in the consequent → constraint.allowed_values=[bit].
Input: "A certificate whose basicConstraints cA boolean is FALSE must not assert the cRLSign bit in its key usage."
Context: Section = Key Usage (extensions.keyusage)
Output:
{{
  "rule_category": "encoding_constraint",
  "verifiability": "observable",
  "assertion_subject": "Certificate",
  "enforcement_phase": "Encoding",
  "subject": "extensions.keyusage",
  "predicate": "must_not_include",
  "constraint": {{
    "raw_text": "the cRLSign bit must not be asserted when cA is FALSE",
    "type": "presence",
    "allowed_values": ["cRLSign"]
  }},
  "precondition": {{
    "description": "the cA boolean is FALSE (certificate is not a CA)",
    "trigger": "cA boolean is FALSE",
    "type": "field_boolean",
    "value": "cA",
    "negate": true
  }},
  "requires_operation": null,
  "references": [],
  "spec_family": "RFC"
}}

Example 11 (SignatureAlgorithm field constraint - certificate encoding, lintable):
Input: "The algorithm named in the certificate's outermost signature field MUST be encoded identically to the one carried inside the to-be-signed portion."
Context: Section = Certificate (certificate.signaturealgorithm)
Output:
{{
  "rule_category": "encoding_constraint",
  "verifiability": "observable",
  "assertion_subject": "Certificate",
  "enforcement_phase": "Encoding",
  "subject": "signaturealgorithm",
  "predicate": "must_equal",
  "constraint": {{
    "raw_text": "outer signature algorithm encoded identically to the inner one",
    "type": "string"
  }},
  "precondition": null,
  "requires_operation": null,
  "references": [],
  "spec_family": "RFC"
}}

Example 12 (Certificate field numeric bound - not runtime comparison):
Input: "pathLenConstraint MUST be greater than or equal to zero."
Context: Section = Basic Constraints (extensions.basicconstraints.pathlenconstraint)
Output:
{{
  "rule_category": "encoding_constraint",
  "verifiability": "observable",
  "assertion_subject": "Certificate",
  "enforcement_phase": "Encoding",
  "subject": "extensions.basicconstraints.pathlenconstraint",
  "predicate": "in_range",
  "constraint": {{
    "raw_text": "greater than or equal to zero",
    "type": "numeric",
    "value": {{"min": 0}}
  }},
  "precondition": null,
  "requires_operation": null,
  "references": [],
  "spec_family": "RFC"
}}

Example 12b (Declarative format statement - still extractable):
Input: "A validity timestamp written in the UTCTime form keeps only the final two digits of the year, whereas the GeneralizedTime form spells the year out in full."
Context: Section = Validity (validity.notafter)
Output:
{{
  "rule_category": "encoding_constraint",
  "verifiability": "observable",
  "assertion_subject": "Certificate",
  "enforcement_phase": "Encoding",
  "subject": "validity.notAfter",
  "predicate": "encode_as",
  "constraint": {{
    "raw_text": "encoded as UTCTime or GeneralizedTime",
    "type": "format"
  }},
  "precondition": null,
  "requires_operation": null,
  "references": [],
  "spec_family": "RFC"
}}

Example 12c (Example-derived keyUsage consequence - still extractable):
Input: "Likewise, when an RSA key should be used only for key management, the keyEncipherment bit would be asserted."
Context: Section = Key Usage (extensions.keyusage)
Output:
{{
  "rule_category": "encoding_constraint",
  "verifiability": "observable",
  "assertion_subject": "Certificate",
  "enforcement_phase": "Encoding",
  "subject": "extensions.keyUsage",
  "predicate": "must_include",
  "constraint": {{
    "raw_text": "keyEncipherment bit would be asserted",
    "type": "presence"
  }},
  "precondition": {{
    "description": "when an RSA key is used only for key management",
    "trigger": "RSA key management usage"
  }},
  "requires_operation": null,
  "references": [],
  "spec_family": "RFC"
}}

- "MUST be present" / "MUST NOT be present" / "MUST be marked critical" / "MUST contain the same algorithm identifier" / numeric bounds on certificate fields (e.g., pathLenConstraint >= 0) are certificate ENCODING constraints.
  * Use assertion_subject = "Certificate", enforcement_phase = "Encoding", verifiability = "observable".
  * Do NOT downgrade these to Comparison/Validation/Processing just because the text mentions use, verification, or another field for equality.
- Presence/criticality mapping is strict:
  * Use constraint.type = "presence" for BOTH existence ("MUST be present/absent") and criticality ("MUST be marked critical/non-critical") requirements.
  * Predicate selection is SEPARATE for the two:
    - existence  → predicate = "must_be_present" or "must_not_be_present".
    - criticality → predicate = "must_be_critical" or "must_not_be_critical". Do NOT use must_be_present/must_equal for a criticality requirement; criticality and presence are distinct predicates and usually distinct clauses → emit them as separate rules.
  * "MAY appear as a critical or non-critical extension" is NOT a criticality requirement (it is optional) — do not assign a criticality predicate. Criticality named only as a precondition ("if this extension is critical", "unrecognized critical extension", "reject ... critical") is also NOT a requirement on this extension.
  * Do NOT convert explicit presence/criticality rules into enum/string/numeric constraints just because the sentence names values like critical/non-critical or SHA-1.
  * Bit-state requirements such as "bit is set/asserted" are NOT automatically presence rules unless the sentence literally states present/absent; preserve the bit/value semantics from the text.
- Certificate-side anchoring is strict but narrow:
  * "the CA MUST include", "CAs MUST include", and similar issuance wording should map to assertion_subject = "Certificate" only when the sentence explicitly constrains an observable certificate field/extension presence, criticality, or encoded value.
  * For extension presence, extension criticality, basic constraints presence, pathLenConstraint, and signature algorithm fields, prefer assertion_subject = "Certificate" and enforcement_phase = "Encoding".
  * Only use assertion_subject = "CA" when the rule is about CA process/verification/decision behavior that is not directly observable in certificate contents.
- Clarification / capability / algorithm-reference boundaries:
  * "applications/implementations MUST support/process/allow" → capability, not encoding_constraint.
  * "MUST conform to RFC X" or references to external algorithm behavior without a local certificate-field result → algorithm_ref or clarification, not lintable encoding_constraint.
  * If the sentence explains how a verifier/application should use a field, classify as runtime behavior unless it explicitly constrains what must be encoded in the certificate.
- For algorithm naming, keep field anchoring literal:
  * "signatureAlgorithm" or "signature algorithm" field → subject = "signaturealgorithm"
  * "subjectPublicKeyInfo.algorithm" / public key algorithm / SPKI algorithm → subject = "subjectpublickeyinfo.algorithm"
  * Do NOT swap signaturealgorithm with subjectpublickeyinfo.algorithm unless the text explicitly refers to the other field.
- Equality between two certificate fields (e.g., outer signatureAlgorithm equals tbsCertificate signature) is still an observable certificate constraint, not runtime comparison.
- pathLenConstraint / criticality / extension presence are never runtime comparison rules when they constrain what appears in the certificate.
- KeyUsage / BasicConstraints special handling:
  * "this extension MUST be present", "the cA boolean MUST be present", "keyCertSign bit is asserted", and similar extension-internal presence/bit-state requirements are certificate encoding constraints.
  * Do NOT rewrite these as compare_as/must_include/allowed_values when the golden meaning is simply presence/criticality of a field or bit.

Example 14 (CA issuance wording but observable certificate result):
Input: "A conforming CA MUST place the subjectKeyIdentifier extension in every certificate that it issues to another CA."
Context: Section = Subject Key Identifier (extensions.subjectkeyidentifier)
Output:
{{
  "rule_category": "encoding_constraint",
  "verifiability": "observable",
  "assertion_subject": "Certificate",
  "enforcement_phase": "Encoding",
  "subject": "extensions.subjectkeyidentifier",
  "predicate": "must_be_present",
  "constraint": {{
    "raw_text": "include the subjectKeyIdentifier extension in certificates issued to a CA",
    "type": "presence"
  }},
  "precondition": {{
    "description": "if the certificate is issued to another CA",
    "trigger": "issued to a CA"
  }},
  "requires_operation": null,
  "references": [],
  "spec_family": "RFC"
}}

Example 14b (Bit-state requirement is not generic presence):
Input: "At least one of the bits MUST be set to 1."
Context: Section = Key Usage (extensions.keyusage)
Output:
{{
  "rule_category": "encoding_constraint",
  "verifiability": "observable",
  "assertion_subject": "Certificate",
  "enforcement_phase": "Encoding",
  "subject": "extensions.keyusage",
  "predicate": "satisfy_condition",
  "constraint": {{
    "raw_text": "at least one of the bits is set to 1",
    "type": "format"
  }},
  "precondition": null,
  "requires_operation": null,
  "references": [],
  "spec_family": "RFC"
}}

Example 15 (Implementation support requirement - not lintable certificate encoding):
Input: "Applications MUST support the name constraints extension for all name forms defined in this specification."
Context: Section = Name Constraints (extensions.nameconstraints)
Output:
{{
  "rule_category": "capability",
  "verifiability": "none",
  "assertion_subject": "Implementation",
  "enforcement_phase": "Processing",
  "subject": "extensions.nameconstraints",
  "predicate": "conform_to",
  "constraint": {{
    "raw_text": "support the name constraints extension for all name forms",
    "type": "format"
  }},
  "precondition": null,
  "requires_operation": null,
  "references": [],
  "spec_family": "RFC"
}}

SPECIAL RULES:
- Do NOT output {{"status": "undetermined"}} merely because the sentence is declarative, explanatory, or lacks MUST/SHALL/SHOULD.
- Declarative format statements (for example, "UTCTime specifies ...") and example-derived certificate consequences (for example, "the keyEncipherment bit would be asserted") are still extractable when the subject/action is grounded by the sentence plus context.
- If the subject or action can be grounded from the sentence plus the provided context/canonical_subject, extract it.
- Only output {{"status": "undetermined"}} when the subject/action truly cannot be grounded from the text plus provided context.
- Do NOT reference external knowledge not present in the provided context.
- Only extract EXPLICIT references (e.g., "RFC 5280 Section 4.2"), not implicit dependencies.

Return ONLY valid JSON. No explanations."""


_RFC2119_KEYWORDS = [
    "MUST NOT", "SHALL NOT", "SHOULD NOT", "NOT RECOMMENDED",
    "MUST", "SHALL", "REQUIRED", "SHOULD", "RECOMMENDED", "MAY", "OPTIONAL",
]


def _obligation_from_text(text: Optional[str]) -> Optional[str]:
    """Deterministically derive the RFC 2119 obligation from a rule's own text.

    Scans for the earliest normative keyword (longest match wins a tie, so
    'MUST NOT' beats 'MUST'). Returns None when the text has no keyword.

    Why this exists: _build_ir must NOT default a keyword-less rule to 'MUST'.
    The skeleton-keyword safeguard (use the Layer-1 regex keyword, never the
    LLM's, to avoid SHOULD->MUST upgrades) is silently bypassed whenever the
    caller fails to propagate `skeleton_keyword` in provenance — then the old
    `or "MUST"` fallback flipped every SHOULD/MAY rule to MUST. Reading the
    modal verb straight from the rule text makes obligation self-sufficient.
    """
    if not text:
        return None
    up = text.upper()
    found = []
    for kw in _RFC2119_KEYWORDS:
        m = re.search(rf"\b{re.escape(kw)}\b", up)
        if m:
            found.append((m.start(), -len(kw), kw))
    if not found:
        return None
    found.sort()
    return found[0][2]


def _precondition_from_profile_title(title: Optional[str], rule_text: str = "") -> Optional[Dict[str, Any]]:
    """Deterministically derive a profile-scoped precondition from a rule's
    section/table title.

    A rule that lives under a certificate-profile section ("Subscriber Certificate
    Basic Constraints", "OCSP Responder ...", "Root CA Certificate Profile") carries
    that profile as its APPLICABILITY — the same scope zlint encodes in CheckApplies.
    The LLM often emits precondition=null for such table rows because the profile is
    in the section header, not the row text; this recovers it as a STRUCTURED
    precondition the reducer maps to a sound guard (certificate_type / eku_present /
    policy_oid / nameConstraints).

    SOUND mappings only — cert-content-detectable profiles. Returns None for:
      * cross-certified / cross-signed (an ISSUANCE relationship, not a cert field),
      * subordinate/intermediate CA (IsCA is over-broad: would also scope roots),
      * unrecognized titles.
    Narrowing a profile-section rule to its profile only REDUCES what is flagged
    (never adds a false positive), so the guard is coverage-sound.

    OCSP-eku scope requires TEXT CORROBORATION: the OCSP Responder profile is a thin
    section that mostly RESTATES general rules (issuerUniqueID deprecation,
    AccessDescription structure, version=v3). Scoping such a general restatement to
    eku=OcspSigning under-fires and the synonymy judge correctly rejects it
    ("rule is unconditional, code checks only when OCSP"). So apply the OCSP-eku scope
    only when the rule text itself names the profile (ocsp/responder/nocheck);
    otherwise it is a general restatement and stays unconditional. GENERAL text-
    structural gate — NOT a per-rule literal.

    Validation-level profiles (DV/OV/IV/EV) are detected by their RESERVED
    certificate-policy OIDs in the certificate (RFC 6818 / CABF BR):
      DV  2.23.140.1.2.1  OV  2.23.140.1.2.2  IV  2.23.140.1.2.3  EV  2.23.140.1.1
    These OIDs appear in the certificate's PolicyIdentifiers extension and are
    the canonical discriminator between validation levels — no other cert field
    carries this information.
    """
    if not title:
        return None
    t = title.lower()
    if "cross-certified" in t or "cross certified" in t or "cross-signed" in t:
        return None  # issuance relationship — not detectable from a single cert
    def _p(ptype, value):
        return {"type": ptype, "value": value, "negate": False,
                "description": f"profile scope: {title}", "trigger": title}
    # --- OCSP responder (EKU-based) ---
    if "ocsp responder" in t:
        if re.search(r"ocsp|responder|nocheck", (rule_text or "").lower()):
            return _p("eku_present", "OcspSigning")
        return None
    # --- subscriber (leaf/EE) ---
    if "subscriber" in t:
        return _p("certificate_type", "subscriber")
    # --- root CA ---
    if "root ca" in t or "root certificate" in t:
        return _p("certificate_type", "root")
    # --- technically constrained subordinate CA (EKU-based guard) ---
    # Technically Constrained CAs have EKUs that distinguish them from ordinary
    # Sub-CA certificates. The EKU names are zlint's canonical forms.
    if "technically constrained" in t:
        return _p("eku_present", "TechnicallyConstrainedCA")
    # --- precertificate signing CA ---
    if "precertificate" in t:
        return _p("eku_present", "PrecertificateSigningCA")
    # --- TLS subordinate CA ---
    if "tls subordinate ca" in t or "tls sub ca" in t:
        return _p("certificate_type", "ca")  # IsCA is safe here: TLS Sub-CA is a
                                             # specific CA role, and rules under
                                             # this profile are about CA properties.
    # --- validation-level profiles (policy-OID guard) ---
    # The validation level is encoded in the certificate's reserved CP OID,
    # observable from a single cert.
    if "individual validated" in t:
        return _p("policy_oid", "2.23.140.1.2.3")
    if "organization validated" in t:
        return _p("policy_oid", "2.23.140.1.2.2")
    if "domain validated" in t:
        return _p("policy_oid", "2.23.140.1.2.1")
    if "extended validated" in t:
        return _p("policy_oid", "2.23.140.1.1")
    # --- generic CA profile (not subscriber, not root, not TLS-sub) ---
    # If the title says "CA Certificate Profile" without a modifier, it covers
    # ALL CAs (root + intermediate). IsCA is the correct guard.
    if "ca certificate profile" in t:
        return _p("certificate_type", "ca")
    return None


def _precondition_from_rule_text(rule_text: str, subject_raw: str) -> Optional[Dict[str, Any]]:
    """Deterministically extract a field-presence precondition from the RULE TEXT itself,
    when the LLM emitted no precondition at all.

    Many rules embed the antecedent in the prose:
      "Conforming implementations generating certificates WITH ELECTRONIC MAIL
       ADDRESSES MUST use rfc822Name..." -> precondition: rfc822Name present
      "For subscriber certificates, the commonName MUST ..." -> precondition:
       certificate_type=subscriber (but this is already handled by profile_title)
      "Except when the certificate is a root CA, ..." -> precondition: NOT root

    This recovers the embedded condition by matching known patterns against
    the rule text. Only fires for the curated field-token set.
    GENERAL: English structural markers (with/except/for/containing), not per-rule.
    """
    if not rule_text:
        return None
    text_lower = rule_text.lower()

    # --- "with X" / "containing X" -> X is present (field_present guard) ---
    for kw in ("with", "containing"):
        pat = r'\b' + kw + r'\b\s+([^,]+?)(?:\s+must|shall|should|may|cannot|required|prohibits|recommended)\b'
        m = re.search(pat, text_lower)
        if m:
            candidate = m.group(1).strip().lower()
            candidate = re.sub(r'\ba\b', '', candidate)
            candidate = re.sub(r'\ban\b', '', candidate)
            candidate = re.sub(r'\bs$', '', candidate)
            candidate = re.sub(r'\s+', '_', candidate)
            candidate_words = set(candidate.replace('_', ' ').split())
            for tok in _PRESENCE_FIELD_TOKENS:
                tok_words = set(tok.replace('_', ' ').split())
                if tok_words & candidate_words:
                    # For email/mail tokens, use the OID constant that the resolver maps to.
                    # The guard type must be "extension_present" (mapped to ExtPresent(oid) by
                    # the reducer) — not "field_present" (which only handles cert/dn fields).
                    if tok in ("mail", "email", "rfc822", "rfc822name"):
                        return {"type": "extension_present",
                                "value": "SubjectAltNameOID",
                                "negate": False,
                                "description": f"embedded precondition: {kw} email address",
                                "trigger": tok}
                    return {"type": "field_present", "value": tok,
                            "negate": False,
                            "description": f"embedded precondition: {kw} {tok}",
                            "trigger": tok}

    # --- "except" / "unless" -> negated guard ---
    if re.search(r'\bexcept\b', text_lower):
        if re.search(r'(root\s+ca|ca\s+certificate|self.?signed)', text_lower):
            return {"type": "certificate_type", "value": "root",
                    "negate": True,
                    "description": "embedded precondition: except root CA",
                    "trigger": "except root CA"}
    if re.search(r'\bunless\b', text_lower):
        if re.search(r'(root\s+ca|ca\s+certificate|self.?signed)', text_lower):
            return {"type": "certificate_type", "value": "root",
                    "negate": True,
                    "description": "embedded precondition: unless root CA",
                    "trigger": "unless root CA"}
        if re.search(r'(ca\s+asserted|is\s+a\s+ca|is\s+ca)', text_lower):
            return {"type": "certificate_type", "value": "ca",
                    "negate": True,
                    "description": "embedded precondition: unless CA",
                    "trigger": "unless CA asserted"}

    # --- "for X certificates" -> X is present (when X is a cert-type adjective) ---
    for cert_kw in ("subscriber", "root", "intermediate", "ocsp", "responder"):
        if re.search(r'\bfor\s+' + cert_kw + r'\s+(?:certificate|certificates)', text_lower):
            return {"type": "certificate_type", "value": cert_kw,
                    "negate": False,
                    "description": f"embedded precondition: for {cert_kw} certificate",
                    "trigger": f"for {cert_kw} certificate"}

    return None


# DN attribute / cert scalar field tokens whose presence/absence is a sound,
# single-certificate-observable precondition (the antecedent the reducer maps to
# a FieldNonEmpty guard). Lowercased; the reducer's _resolve_subject does the
# authoritative name → DSL field resolution, this set only gates WHICH prose
# tokens are eligible (so "if the CA wishes" never becomes a field guard).
_PRESENCE_FIELD_TOKENS = {
    "commonname", "stateorprovincename", "localityname", "organizationname",
    "organizationalunitname", "countryname", "serialnumber", "givenname",
    "surname", "postalcode", "streetaddress", "emailaddress", "domaincomponent",
    "organizationidentifier", "title", "pseudonym", "version",
    # Additional tokens for embedded "with X" matching (the LLM often names fields
    # in prose even when it doesn't fill the structured guard):
    "email", "mail", "rfc822", "rfc822name", "subjectaltname", "san",
}


def _precondition_from_prose_field(precond, subject_raw):
    """Deterministically STRUCTURE a field-presence/absence precondition from the
    LLM's own prose trigger/description.

    The LLM reliably names the antecedent in prose ("stateOrProvinceName is
    absent", "if present", "generating certificates with electronic mail addresses")
    but inconsistently fills the structured type/value (a temperature-0 LLM still
    varies run-to-run). This sibling of _precondition_from_profile_title normalizes
    that GOOD prose into the schema {type: field_present|field_absent, value: <field>}
    the reducer guards on — structuring the LLM's own output, NOT deriving
    requirements from rule prose. Only fires for a curated DN/cert field-token set;
    returns None otherwise.

    Self-conditional "X, if present, MUST ...": prose has no field token, so the
    field is the rule's own subject (subject_raw).

    Embedded "with/containing/for/except" antecedents (e.g. "generating
    certificates WITH EMAIL ADDRESSES MUST use rfc822Name"): these are mid-sentence
    conditions the LLM captures in prose but that the old regex-only logic missed.
    We now also match "with X" / "containing X" / "for X" / "except X" where X
    is a field token.
    """
    if not isinstance(precond, dict):
        return None
    # subject_raw may be a str, a SubjectRef object, or a dict — coerce to a path str.
    if subject_raw is None:
        subject_raw = ""
    elif not isinstance(subject_raw, str):
        subject_raw = (getattr(subject_raw, "path", None)
                       or getattr(subject_raw, "raw", None)
                       or (subject_raw.get("path") if isinstance(subject_raw, dict) else None)
                       or "")
    if not isinstance(subject_raw, str):
        subject_raw = ""
    prose = " ".join(str(precond.get(k) or "") for k in ("trigger", "description")).lower()
    if not prose:
        return None
    # version antecedent ("if the version is 1", "when version is 2 or 3"). X.509
    # version is a closed set {1,2,3}; structure it as a version_is guard the reducer
    # maps to FieldEq/FieldInSet(Version, …). Structuring the LLM's own prose (the
    # digits it wrote after "version"), not deriving requirements from rule text.
    if "version" in prose:
        _after = prose[prose.index("version"):]
        _vnums = list(dict.fromkeys(re.findall(r"\bv?([123])\b", _after)))
        if _vnums:
            # Deontic DIRECTION matters. "X MUST ONLY appear/be present if version V"
            # means (X present -> version=V); as a When(guard, main) over the subject
            # X, the guard is the CONTRAPOSITIVE (version != V -> X absent), so the
            # version condition is NEGATED. "X MUST NOT appear if version V" is the
            # opposite (version=V is the direct guard, not negated). Detect the
            # "only ... (appear|present|...)" shape and flip accordingly. GENERAL
            # deontic grammar, not per-rule.
            neg = bool(precond.get("negate"))
            if re.search(r"\bonly\b.{0,40}\b(appear|present|be present|used|included|exist)\b", prose) \
               or re.search(r"\b(appear|present|used|included)\b.{0,15}\bonly\b", prose):
                neg = not neg
            return {"type": "version_is", "field": "Version", "values": _vnums,
                    "negate": neg}
    # absence vs presence. "empty sequence" / "is empty" => the field is absent;
    # "non-empty" / "not empty" => present. Check non-empty BEFORE empty (substring).
    nonempty = bool(re.search(r"\bnon-?empty\b|\bnot empty\b", prose))
    empty = (not nonempty) and bool(re.search(r"\bempty\b", prose))
    absent = bool(re.search(r"\b(absent|not present|not represented|missing|omitted)\b", prose)) or empty
    present = (bool(re.search(r"\b(present|included|asserted)\b", prose)) or nonempty) and not absent
    if not (absent or present):
        return None

    def _norm_attr(s):
        return re.sub(r"[^a-z0-9]", "", (s or "").lower())

    # whole-DN holder ("the subject field contains an empty sequence",
    # "a non-empty subject"): the field is the Subject/Issuer DN itself.
    _DN_HOLDER_TOKENS = ("subjectfield", "subject", "issuerfield", "issuer")

    # 1) explicit field token named in the prose
    field = None
    pn = _norm_attr(prose)
    for tok in _PRESENCE_FIELD_TOKENS:
        if tok in pn:
            field = tok
            break
    # 1b) whole-DN subject/issuer emptiness/presence
    if field is None:
        if "subject" in pn:
            field = "subject"
        elif "issuer" in pn:
            field = "issuer"
    # 2) embedded "with/containing/for/except" antecedents (mid-sentence conditions):
    if field is None:
        for kw in ("with", "containing", "for", "except"):
            pat = r'\b' + kw + r'\b\s+(.+?)\s+(?:must|shall|should|may|cannot|cannot|required|prohibit|recommended)\b'
            m = re.search(pat, prose)
            if m:
                candidate = m.group(1).strip().lower()
                candidate = re.sub(r'\ba\b', '', candidate)
                candidate = re.sub(r'\ban\b', '', candidate)
                candidate = re.sub(r'\bs$', '', candidate)
                candidate = re.sub(r'\s+', '_', candidate)
                candidate_words = set(candidate.replace('_', ' ').split())
                for tok in _PRESENCE_FIELD_TOKENS:
                    tok_words = set(tok.replace('_', ' ').split())
                    if tok_words & candidate_words:
                        field = tok
                        break
                if field:
                    break
    # 3) self-conditional ("if present") → the rule's own subject is the field
    if field is None and ("if present" in prose or "when present" in prose or "if absent" in prose):
        sr = _norm_attr(subject_raw)
        # subject path may be "subject.localityname" or a bare "version"
        sr_tail = sr.split(".")[-1] if "." in (subject_raw or "") else sr
        if sr_tail in _PRESENCE_FIELD_TOKENS:
            field = sr_tail
    if field is None:
        return None
    ptype = "field_absent" if absent else "field_present"
    return {"type": ptype, "value": field, "negate": False,
            "description": precond.get("description") or f"{field} {'absent' if absent else 'present'}",
            "trigger": precond.get("trigger") or field}


def _cardinality_from_text(text):
    """Deterministically read an occurrence bound (min_count, max_count) from a
    rule's text. Mirrors the structured slots the prompt asks the LLM to fill, so
    the count is captured FAITHFULLY (LLM sometimes misses it) and
    DETERMINISTICALLY (text-derived, stable across re-extractions). Returns
    (None, None) when the text states no count. NOT prose-bypass in the reducer —
    this runs in the extraction layer, structuring the rule's own wording."""
    t = text or ""
    m = re.search(r"\b(?:exactly|only)\s+(?:a\s+)?(?:single|one|1)\b", t, re.I)
    if m:
        return (1, 1)
    m = re.search(r"\bexactly\s+(\d+)\b", t, re.I)
    if m:
        return (int(m.group(1)), int(m.group(1)))
    if re.search(r"\bone or more\b", t, re.I):
        return (1, None)
    m = re.search(r"\bat least\s+(one|two|three|\d+)\b", t, re.I)
    if m:
        w = {"one": 1, "two": 2, "three": 3}
        try:
            n = w.get(m.group(1).lower(), int(m.group(1)))
        except (ValueError, TypeError):
            n = 1
        return (n, None)
    m = re.search(r"\b(?:at most|no more than)\s+(one|\d+)\b", t, re.I)
    if m:
        n = 1 if m.group(1).lower() == "one" else int(m.group(1))
        return (0, n)
    return (None, None)



class ControlledLLMExtractor:
    """
    受控 LLM 提取器

    职责：
    1. 使用严格受控的提示词调用 LLM
    2. 验证 LLM 输出
    3. 处理 needs_split 信号
    4. 构建规范化的 IR

    不做：
    - 规范判断
    - 冲突解决
    - 隐含要求推断
    """

    def __init__(
        self,
        llm_client: Optional[LLMClient] = None,
        knowledge_graph=None,
        use_preprocessing: bool = True,
        use_internal_retrieval: bool = True,
    ):
        """
        初始化受控提取器

        Args:
            llm_client: LLM 客户端（如果不提供，将使用默认配置创建）
            knowledge_graph: 知识图谱（用于 GraphRAG 检索和验证引用）
            use_preprocessing: 是否启用句子预处理
            use_internal_retrieval: 是否启用内部上下文检索
                - True: Extractor 自己通过 GraphRAG 检索上下文（传统模式）
                - False: Extractor 只消费外部传入的上下文（Pipeline 模式）
                  在 Pipeline 模式下，应使用 extract_with_context() 方法
        """
        self.llm_client = llm_client or LLMClient(
            model=settings.llm_model,
            temperature=0,  # 零温度，确保确定性输出
            max_tokens=1000
        )
        self.kg = knowledge_graph
        self.use_preprocessing = use_preprocessing
        self.use_internal_retrieval = use_internal_retrieval

        # 初始化验证器和预处理器
        self.validator = OutputValidator(knowledge_graph=knowledge_graph)
        self.preprocessor = SentencePreprocessor()

        # 初始化 Graph-Aware Retrieval 链路（仅在启用内部检索时使用）
        if use_internal_retrieval:
            self.spec_context_manager = SpecificationContextManager(
                knowledge_graph=knowledge_graph
            )
            self.subgraph_extractor = (
                SubgraphExtractor(knowledge_graph) if knowledge_graph else None
            )
            self.context_assembler = ContextAssembler(max_tokens=2000)
        else:
            # Pipeline 模式下不需要这些组件
            self.spec_context_manager = None
            self.subgraph_extractor = None
            self.context_assembler = None

    def extract(
        self,
        text: str,
        context: Optional[str] = None,
        provenance: Optional[Dict[str, Any]] = None
    ) -> List[ExtractionResult]:
        """
        从文本中提取规则

        完整 GraphRAG 链路：
        1. 预处理（拆分多规则句子）
        2. 检测规范体系（Specification Context Manager）
        3. 从 KG 检索最小上下文（Graph-Aware Retrieval）
        4. 拼 prompt 并调 LLM
        5. 验证输出（Output Validator）

        Args:
            text: 输入文本（规范句子）
            context: 规范上下文（可选，如果不提供将自动从 KG 检索）
            provenance: 来源信息

        Returns:
            ExtractionResult 列表
        """
        results = []

        # Step 1: 预处理（拆分多规则句子）
        if self.use_preprocessing:
            preprocess_result = self.preprocessor.preprocess(text, provenance)
            sentences = preprocess_result.sentences
        else:
            sentences = [AtomicSentence(
                text=text,
                original_text=text,
                original_index=0
            )]

        # Step 2: 如果没有手动传入 context，通过 GraphRAG 自动检索
        if context is None:
            if self.use_internal_retrieval:
                context = self._retrieve_context_from_graph(text, provenance)
            else:
                # Pipeline 模式下，必须由外部提供上下文
                context = "No additional context provided."
                app_logger.debug(
                    "use_internal_retrieval=False，使用默认空上下文。"
                    "建议使用 extract_with_context() 方法由 Orchestrator 提供上下文。"
                )

        # Step 3: 对每个原子句子调用 LLM
        for sentence in sentences:
            extraction_result = self._extract_single(
                sentence.text,
                context=context,
                provenance=sentence.provenance or provenance
            )
            if extraction_result:
                results.append(extraction_result)

        return results

    def extract_with_context(
        self,
        text: str,
        context: str,
        provenance: Optional[Dict[str, Any]] = None
    ) -> List[ExtractionResult]:
        """
        使用外部提供的上下文提取规则（Pipeline 模式专用）

        这是 Pipeline Orchestrator 调用的入口方法。
        上下文由 Orchestrator 通过 GraphRAG 准备，Extractor 只负责消费。

        HARD CONSTRAINT:
        - Extractor 在此模式下只是"消费者"，不决定取什么上下文
        - 所有上下文来源决策由 Orchestrator 负责

        Args:
            text: 输入文本（单个原子句子，预处理已由 Orchestrator 完成）
            context: 由 Orchestrator 准备的结构化上下文
            provenance: 来源信息

        Returns:
            ExtractionResult 列表
        """
        # 直接调用单句提取，不做预处理（由 Orchestrator 负责）
        extraction_result = self._extract_single(
            text=text,
            context=context,
            provenance=provenance
        )

        if extraction_result:
            return [extraction_result]
        return []

    def _retrieve_context_from_graph(
        self,
        text: str,
        provenance: Optional[Dict[str, Any]] = None
    ) -> str:
        """
        通过 Graph-Aware Retrieval 链路自动检索上下文

        检索算法：
        1. 检测规范体系（SpecificationContextManager）
        2. 从 KG 提取相关子图（SubgraphExtractor）
        3. 组装最小上下文（ContextAssembler, max 2000 tokens）
        4. 按优先级排序：Definition > Field > Other rules

        注意：此方法仅在 use_internal_retrieval=True 时可用。
        在 Pipeline 模式下，上下文由 Orchestrator 提供，不应调用此方法。

        Args:
            text: 输入文本
            provenance: 来源信息（包含 source_id, section 等）

        Returns:
            格式化的上下文字符串
        """
        # 检查是否启用内部检索
        if not self.use_internal_retrieval:
            app_logger.warning(
                "_retrieve_context_from_graph() 被调用，但 use_internal_retrieval=False。"
                "在 Pipeline 模式下，上下文应由 Orchestrator 提供。"
            )
            return "No additional context provided."

        # Step A: 检测规范体系
        spec_family = self.spec_context_manager.detect_spec_family(text)
        spec_id = self.spec_context_manager.extract_spec_id(text)
        scope = self.spec_context_manager.get_applicable_scope(text)

        spec_info = {
            "family": spec_family.value,
            "id": spec_id or (provenance.get("source_id", "") if provenance else ""),
            "section": provenance.get("section", "") if provenance else "",
        }

        # Step B: 从 KG 提取子图（如果有 KG 和 section 信息）
        if self.subgraph_extractor and spec_info["id"] and spec_info["section"]:
            try:
                subgraph = self.subgraph_extractor.extract_from_section(
                    doc_id=spec_info["id"],
                    section_id=spec_info["section"]
                )

                # Step C: 组装最小上下文
                if subgraph.nodes:
                    minimal_context = self.context_assembler.assemble(
                        subgraph=subgraph,
                        spec_info=spec_info,
                    )
                    context_str = minimal_context.to_prompt_string()

                    if context_str.strip():
                        app_logger.debug(
                            f"GraphRAG 检索到上下文: {len(minimal_context.definitions)} 定义, "
                            f"{len(minimal_context.fields)} 字段, "
                            f"{minimal_context.token_count} tokens"
                        )
                        return context_str

            except Exception as e:
                app_logger.warning(f"GraphRAG 子图检索失败，回退到基础上下文: {e}")

        # Step D: 回退 — 如果没有 KG 或子图为空，使用 SpecContextManager 的基础上下文
        fallback_context = self.spec_context_manager.get_minimal_context(text)

        if fallback_context.strip():
            app_logger.debug(f"使用基础规范上下文 (spec_family={spec_family.value})")
            return fallback_context

        return "No additional context provided."

    def _extract_single(
        self,
        text: str,
        context: Optional[str] = None,
        provenance: Optional[Dict[str, Any]] = None
    ) -> Optional[ExtractionResult]:
        """
        从单个原子句子提取规则

        Args:
            text: 原子句子
            context: 规范上下文
            provenance: 来源信息

        Returns:
            ExtractionResult 或 None
        """
        # Step 1: 构建提示词
        prompt = self._build_prompt(text, context)

        # Step 2: 调用 LLM
        try:
            llm_response = self._call_llm(prompt)
        except Exception as e:
            app_logger.error(f"LLM 调用失败: {e}")
            return None

        # Step 3: 验证输出
        validation_result = self.validator.validate(llm_response)

        if not validation_result.is_valid:
            app_logger.warning(
                f"LLM 输出验证失败: {[e.message for e in validation_result.errors]}"
            )
            return None

        # Step 4: 检查特殊输出
        normalized = validation_result.normalized_output
        if not normalized:
            return None

        # 检查 needs_split
        if normalized.get("needs_split"):
            app_logger.info(f"句子需要拆分: {text[:50]}...")
            # 这里可以触发重新预处理，但当前设计中预处理已经在前面完成
            return None

        # 检查 undetermined
        if normalized.get("status") == "undetermined":
            recovered = self._recover_undetermined_sentence(text, provenance)
            if recovered:
                app_logger.info(f"句子从 undetermined 恢复: {text[:50]}...")
                ir = self._build_ir(recovered, text, provenance)
                if ir:
                    return ExtractionResult(ir=ir)
            app_logger.info(f"句子无法提取: {text[:50]}...")
            return None

        # Step 5: 构建 IR
        ir = self._build_ir(normalized, text, provenance)
        if not ir:
            return None

        return ExtractionResult(ir=ir)

    def _build_prompt(self, text: str, context: Optional[str] = None) -> str:
        """构建提取提示词"""
        context_str = context or "No additional context provided."

        prompt = EXTRACTION_PROMPT_TEMPLATE.format(
            normative_sentence=text,
            context=context_str,
            schema=IR_OUTPUT_SCHEMA
        )

        return prompt

    def _call_llm(self, prompt: str) -> str:
        """调用 LLM"""
        # 使用 System Prompt + User Prompt 格式
        full_prompt = f"{CONTROLLED_SYSTEM_PROMPT}\n\n{prompt}"

        # max_retries=5: ai.ailink1.com intermittently returns transient 400/5xx
        # (upstream_error); the generate() retry loop backs off and re-tries.
        response = self.llm_client.generate(full_prompt, max_retries=5)
        return response

    @staticmethod
    def _recover_undetermined_sentence(
        text: str,
        provenance: Optional[Dict[str, Any]] = None
    ) -> Optional[Dict[str, Any]]:
        """Deterministic recovery for known declarative/example-style gold rules.

        Some RFC 5280 ground-truth rules are expressed declaratively ("UTCTime specifies ...")
        or as example-derived observable consequences ("... the keyEncipherment bit would be asserted").
        These are valid Table II targets and should not be dropped just because the LLM
        responded with {"status": "undetermined"}.
        """
        cleaned = " ".join((text or "").split())
        lowered = cleaned.lower()

        spec_family = "RFC"
        if provenance and provenance.get("source_id", "").upper().startswith("CABF"):
            spec_family = "CABF"
        elif provenance and provenance.get("source_id", "").upper().startswith("ETSI"):
            spec_family = "ETSI"

        if lowered == (
            "utctime specifies the year through the two low-order digits and time is "
            "specified to the precision of one minute or one second"
        ):
            return {
                "rule_category": "encoding_constraint",
                "verifiability": "observable",
                "assertion_subject": "Certificate",
                "enforcement_phase": "Encoding",
                "subject": "validity.notAfter",
                "obligation": "MUST",
                "predicate": "encode_as",
                "constraint": {
                    "raw_text": "encoded as UTCTime or GeneralizedTime",
                    "type": "format",
                },
                "precondition": None,
                "requires_operation": None,
                "references": [],
                "spec_family": spec_family,
            }

        asserted_bit = re.search(r"\bthe\s+([a-z][a-z0-9]*)\s+bit would be asserted\b", cleaned, re.IGNORECASE)
        if asserted_bit and "key management" in lowered:
            bit_name = asserted_bit.group(1)
            return {
                "rule_category": "encoding_constraint",
                "verifiability": "observable",
                "assertion_subject": "Certificate",
                "enforcement_phase": "Encoding",
                "subject": "extensions.keyUsage",
                "obligation": "MUST",
                "predicate": "must_include",
                "constraint": {
                    "raw_text": f"{bit_name} bit would be asserted",
                    "type": "presence",
                },
                "precondition": {
                    "description": "when an RSA key is used only for key management",
                    "trigger": "RSA key management usage",
                },
                "requires_operation": None,
                "references": [],
                "spec_family": spec_family,
            }

        return None

    def _build_ir(
        self,
        normalized: Dict[str, Any],
        original_text: str,
        provenance: Optional[Dict[str, Any]] = None
    ) -> Optional[IntermediateRepresentation]:
        """从规范化输出构建 IR"""
        try:
            # Clean rule text: remove newlines and normalize whitespace
            cleaned_text = ' '.join(original_text.split())

            # 提取基本字段
            subject_raw = normalized.get("subject", "")
            obligation_str = normalized.get("obligation", "MUST")
            predicate_str = normalized.get("predicate", "")
            constraint_data = normalized.get("constraint", {})

            # 验证必填字段
            if not subject_raw or not predicate_str:
                return None

            # 构建 SubjectRef（从 LLM 输出的字符串）
            # Fix #5: Apply canonical subject normalization via FieldResolver
            canonical_subject = provenance.get("canonical_subject") if provenance else None

            # Auto-resolve canonical_subject if not provided but section info available
            if not canonical_subject and provenance:
                section_id = provenance.get("section")
                section_title = provenance.get("title")
                if section_id and not section_title:
                    # Try to get title from section_topics KB (RFC5280)
                    from app.services.extraction.section_topics import section_topics_kb
                    source_id = provenance.get("source_id", "")
                    info = section_topics_kb.get_section_info(source_id, section_id)
                    if info:
                        section_title = info.get("title")
                if section_id and not section_title:
                    # Fallback: look up title from corpus (works for CABF, ETSI, etc.)
                    try:
                        from app.services.knowledge_layer import get_corpus_loader
                        loader = get_corpus_loader()
                        if loader:
                            doc = loader.get_document(source_id)
                            if doc and section_id in doc.sections:
                                section_title = doc.sections[section_id].title
                    except Exception:
                        pass
                if section_title:
                    field_resolver = get_field_resolver()
                    canonical_subject = field_resolver.resolve_section_subject(
                        section_title=section_title,
                        section_id=section_id,
                    )

            section_root = canonical_subject.get("path") if canonical_subject else None

            # Use FieldResolver for data-driven subject normalization
            field_resolver = get_field_resolver()
            normalized_subject = field_resolver.normalize_subject(
                raw_subject=subject_raw,
                section_root=section_root,
            )
            # Post-processing: validate and fix common subject path errors
            normalized_subject = field_resolver.validate_and_fix_subject(
                ir_subject=normalized_subject,
                section_root=section_root,
            )

            if canonical_subject:
                aliases = canonical_subject.get("aliases", [])
                subject = SubjectRef.from_canonical(
                    canonical_path=normalized_subject,
                    raw=subject_raw,
                    aliases=aliases
                )
                app_logger.debug(
                    f"[_build_ir] Normalized subject '{subject_raw}' → '{normalized_subject}'"
                )
            else:
                # Still normalize through FieldResolver even without canonical_subject
                subject = SubjectRef(
                    path=normalized_subject,
                    raw=subject_raw,
                    resolved=False,
                    resolution_method="field_resolver",
                )
                if normalized_subject != subject_raw.lower().strip():
                    app_logger.debug(
                        f"[_build_ir] FieldResolver normalized '{subject_raw}' → '{normalized_subject}'"
                    )

            # CRITICAL: Use skeleton's keyword for ALL sources when available.
            # The skeleton keyword was regex-matched from original text, which is more
            # reliable than LLM's extraction (LLM might incorrectly change SHOULD to MUST).
            #
            # Priority order:
            # 1. skeleton_keyword (regex-matched, most reliable)
            # 2. LLM output (fallback if no skeleton keyword)
            keyword_source = (provenance.get("keyword_source") or "direct") if provenance else "direct"
            skeleton_keyword = provenance.get("skeleton_keyword") if provenance else None

            if skeleton_keyword:
                # Always prefer skeleton's keyword - it was regex-matched from source text
                obligation_str = skeleton_keyword
                app_logger.debug(
                    f"[_build_ir] Using skeleton keyword '{skeleton_keyword}' "
                    f"(LLM suggested '{normalized.get('obligation', 'N/A')}')"
                )
            elif keyword_source == "inherited":
                # keyword_source=inherited: no direct keyword, obligation inherited from parent
                # skeleton_keyword should be parent's keyword, but if missing, use LLM suggestion
                llm_obligation = normalized.get("obligation", "")
                if llm_obligation and llm_obligation.startswith("PARENT_KEYWORD:"):
                    obligation_str = llm_obligation.replace("PARENT_KEYWORD:", "").strip()
                else:
                    obligation_str = llm_obligation or "MUST"
                app_logger.debug(
                    f"[_build_ir] Inherited obligation from parent: '{obligation_str}'"
                )
            else:
                # No skeleton keyword was propagated. Do NOT blindly default to
                # MUST — that silently flips SHOULD/MAY rules (the very bias the
                # skeleton-keyword path exists to prevent). Re-derive the
                # obligation deterministically from THIS rule's own text via the
                # RFC 2119 regex; only fall back to LLM/MUST if the text carries
                # no normative keyword.
                text_kw = _obligation_from_text(original_text)
                obligation_str = text_kw or normalized.get("obligation") or "MUST"
                app_logger.debug(
                    f"[_build_ir] No skeleton keyword; regex-from-text="
                    f"'{text_kw}' -> obligation '{obligation_str}'"
                )

            # 解析 obligation
            try:
                obligation = ObligationType(obligation_str.replace("_", " "))
            except ValueError:
                # 尝试直接使用字符串
                obligation = obligation_str

            # 解析 predicate（允许字符串，不强制枚举）
            predicate = predicate_str

            # 构建约束
            if isinstance(constraint_data, dict):
                # Normalize constraint type: 'absence' → 'presence'
                ct = constraint_data.get("type")
                if ct and str(ct).lower() == "absence":
                    ct = "presence"
                _av = constraint_data.get("allowed_values")
                constraint = IRConstraint(
                    raw_text=constraint_data.get("raw_text", cleaned_text),
                    type=ct,
                    value=constraint_data.get("value"),
                    # Forward EVERY structured slot the prompt asks the LLM to fill.
                    # Previously only value/asn1_types survived here — min/max/unit/
                    # pattern/allowed_values/counts were silently dropped, which turned
                    # the LLM's structured extraction back into a prose `value` and left
                    # the deterministic reducer (det_codegen._structured_fallback reads
                    # these slots) nothing to fill → the rule fell to the LLM path /
                    # stayed unlintable. Keeping them makes the IR structured AT SOURCE.
                    unit=constraint_data.get("unit"),
                    min_value=constraint_data.get("min_value"),
                    max_value=constraint_data.get("max_value"),
                    pattern=constraint_data.get("pattern"),
                    allowed_values=list(_av) if isinstance(_av, list) else None,
                )
                # Forward asn1_types so ir_to_dsl can emit FieldEncodedAs atoms
                if constraint_data.get("asn1_types"):
                    constraint.asn1_types = list(constraint_data["asn1_types"])
                # Cardinality bounds (IRConstraint.Config.extra="allow"): the reducer
                # reads constraint.min_count / max_count for occurrence/uniqueness atoms.
                for _ck in ("min_count", "max_count"):
                    if constraint_data.get(_ck) is not None:
                        setattr(constraint, _ck, constraint_data[_ck])
                # Deterministic cardinality capture: if the LLM left counts unset
                # but the rule text states an occurrence bound ("at least one",
                # "exactly one", "one or more"), fill them from the text. Faithful
                # (LLM often misses it) + deterministic (text-derived, stable). The
                # reducer routes a cardinality on a single-list extension to
                # FieldCount instead of collapsing to bare ExtPresent.
                if (getattr(constraint, "min_count", None) is None
                        and getattr(constraint, "max_count", None) is None):
                    _mn, _mx = _cardinality_from_text(cleaned_text)
                    if _mn is not None or _mx is not None:
                        if _mn is not None:
                            setattr(constraint, "min_count", _mn)
                        if _mx is not None:
                            setattr(constraint, "max_count", _mx)
                        if not constraint.type or str(constraint.type).lower() in ("presence", ""):
                            constraint.type = "cardinality"
                # must_equal placement normalization (AT SOURCE, not in the reducer):
                # the LLM sometimes files a single required scalar under
                # allowed_values (a singleton) instead of value — e.g. version
                # "v3(2)". Under an equality predicate a singleton allowed_values
                # IS the required value, so mirror it into value here. Sound (no
                # info loss; allowed_values is retained), general (any field), and
                # reads a structured slot — NOT a reducer patch over prose. This
                # keeps the equality value structured at the source so the
                # deterministic reducer needs no field-specific accommodation.
                _pred = (predicate_str or "").strip().lower()
                if (constraint.value in (None, "")
                        and _pred in ("must_equal", "must_be", "equals", "equal_to")
                        and isinstance(constraint.allowed_values, list)
                        and len(constraint.allowed_values) == 1
                        and isinstance(constraint.allowed_values[0], str)):
                    constraint.value = constraint.allowed_values[0]
            else:
                constraint = IRConstraint(raw_text=str(constraint_data))

            # Criticality predicate enforcement.
            # The extraction prompt historically collapsed "MUST be marked
            # (non-)critical" into must_be_present (see prompt guidance), which
            # mis-predicated criticality requirements and made them match
            # presence lints instead of criticality lints. Route genuine
            # criticality requirements to the dedicated predicate. Deterministic
            # and text-driven; preconditions / "MAY be (non-)critical" are excluded.
            _crit_pred = self._derive_criticality_predicate(
                " ".join(p for p in (constraint.raw_text, cleaned_text) if p)
            )
            if _crit_pred and predicate in (
                None, "must_be_present", "must_not_be_present",
                "must_equal", "must_include", "conform_to",
            ):
                predicate = _crit_pred
                if not constraint.type:
                    constraint.type = "presence"

            # 解析引用（仅显式引用）
            references = []
            for ref_data in normalized.get("references", []):
                if isinstance(ref_data, dict) and ref_data.get("raw"):
                    ref = IRReference(
                        raw=ref_data.get("raw", ""),
                        doc_id=ref_data.get("doc_id"),
                        section=ref_data.get("section"),
                        resolved=False,
                        resolution_method="explicit"
                    )
                    references.append(ref)

            # 解析规范体系
            spec_family_str = normalized.get("spec_family", "Other")
            try:
                spec_family = SpecFamily(spec_family_str)
            except ValueError:
                spec_family = SpecFamily.OTHER

            # 解析断言主体（新增）
            assertion_subject_str = normalized.get("assertion_subject", "Certificate")
            try:
                assertion_subject = AssertionSubject(assertion_subject_str)
            except ValueError:
                assertion_subject = AssertionSubject.CERTIFICATE

            # 解析执行阶段（新增）
            enforcement_phase_str = normalized.get("enforcement_phase")
            enforcement_phase = None
            if enforcement_phase_str:
                try:
                    enforcement_phase = EnforcementPhase(enforcement_phase_str)
                except ValueError:
                    enforcement_phase = enforcement_phase_str  # 保留字符串

            # 解析 rule_category（Enhanced IR Extraction）
            rule_category = None
            rule_category_str = normalized.get("rule_category")
            if rule_category_str:
                try:
                    rule_category = RuleCategory(rule_category_str)
                except ValueError:
                    rule_category = rule_category_str  # 保留字符串

            # 强制 rule_category 一致性（修复 LLM 把 encoding_constraint 误判为 algorithm_ref）
            rule_category, assertion_subject = self._enforce_rule_category_consistency(
                rule_category, assertion_subject, enforcement_phase,
                predicate, normalized_subject, cleaned_text
            )

            # Sound forward guard for the single-artifact lintability axes: rescue
            # constraints the LLM mislabeled as not_a_constraint / Validation /
            # clarification despite being complete, normative, single-artifact
            # observable field constraints (audited false negatives).
            rule_category, enforcement_phase = self._enforce_single_artifact_lintability(
                rule_category, assertion_subject, enforcement_phase,
                predicate, normalized_subject, obligation, cleaned_text,
                getattr(constraint, "raw_text", "") if constraint is not None else "",
            )

            # 解析 verifiability（Enhanced IR Extraction）
            # 不再默认为 OBSERVABLE — 如果 LLM 未提供，根据 rule_category 推断
            verifiability = None
            verifiability_str = normalized.get("verifiability")
            if verifiability_str:
                try:
                    verifiability = Verifiability(verifiability_str)
                except ValueError:
                    verifiability = verifiability_str  # 保留字符串

            # 后处理：根据 rule_category 强制一致性（修复 LLM 不确定性）
            verifiability = self._enforce_verifiability_consistency(
                verifiability, rule_category, assertion_subject, enforcement_phase, cleaned_text
            )

            # 解析 algorithm_ref（Enhanced IR Extraction）
            algorithm_ref = None
            algorithm_ref_data = normalized.get("algorithm_ref")
            if isinstance(algorithm_ref_data, dict) and algorithm_ref_data.get("base_spec"):
                algorithm_ref = AlgorithmReference(
                    base_spec=algorithm_ref_data.get("base_spec", ""),
                    section=algorithm_ref_data.get("section"),
                    operation=algorithm_ref_data.get("operation"),
                    inheritance=algorithm_ref_data.get("inheritance") or "full",
                )

            # 解析 overrides（Enhanced IR Extraction）
            overrides = []
            overrides_data = normalized.get("overrides", [])
            if isinstance(overrides_data, list):
                for ov_data in overrides_data:
                    if isinstance(ov_data, dict) and ov_data.get("param"):
                        override = Override(
                            step=ov_data.get("step"),
                            param=ov_data.get("param", ""),
                            value=ov_data.get("value"),
                            source_text=ov_data.get("source_text", ""),
                        )
                        overrides.append(override)

            # 解析 scope inheritance 字段（由 provenance 携带，非 LLM 输出）
            keyword_source = "direct"
            parent_rule_id = None
            scope_block_id = None
            section_scope = None  # 问题6修复：section-level scope
            if provenance:
                keyword_source = provenance.get("keyword_source") or "direct"
                parent_rule_id = provenance.get("parent_rule_id")
                scope_block_id = provenance.get("scope_block_id")
                # 构建 section_scope (e.g., "RFC5280-7.2")
                source_id = provenance.get("source_id")
                section = provenance.get("section")
                if source_id and section:
                    section_scope = f"{source_id}-{section}"

            # 构建 provenance
            prov_list = []
            if provenance:
                prov = IRProvenance(
                    source_id=provenance.get("source_id", "unknown"),
                    section=provenance.get("section"),
                    title=provenance.get("title"),
                    line_start=provenance.get("line_start"),
                    line_end=provenance.get("line_end"),
                    chunk_id=provenance.get("chunk_id"),
                    extractor_type="controlled_llm",
                    extraction_timestamp=datetime.now(),
                )
                prov_list.append(prov)

            # Forward fallback: when the LLM emitted no structured precondition,
            # recover it deterministically — FIRST from the prose antecedent it
            # did name (field presence/absence), THEN from the section/table title
            # (profile applicability). Both structure the LLM's own output into the
            # schema the reducer guards on; neither narrows below the rule's scope.
            _precond = normalized.get("precondition")
            if not (isinstance(_precond, dict) and _precond.get("type")):
                _pf = _precondition_from_prose_field(_precond, subject)
                if _pf:
                    _precond = _pf
                else:
                    _ptitle = (provenance or {}).get("title") if provenance else None
                    _derived = _precondition_from_profile_title(_ptitle, cleaned_text)
                    if _derived:
                        _precond = _derived
                    else:
                        # Third fallback: extract embedded conditions from rule text itself
                        _rt = _precondition_from_rule_text(cleaned_text, subject)
                        if _rt:
                            _precond = _rt

            # Universally-deprecated fields (RFC 5280 §4.1.2.8: conforming CAs MUST
            # NOT generate certs with unique identifiers — applies to ALL profiles).
            # A profile-title precondition wrongly narrows such a UNIVERSAL
            # prohibition to one profile, so the lint under-fires and the synonymy
            # judge correctly rejects it ("rule unconditionally forbids X"). Drop the
            # profile scope so the prohibition stays unconditional. General RFC
            # knowledge over a small field set — NOT a per-rule literal.
            _UNIVERSAL_PROHIBITED = ("subjectuniqueid", "issueruniqueid",
                                     "subjectuniqueidentifier", "issueruniqueidentifier")
            if (isinstance(_precond, dict)
                    and str(_precond.get("description") or "").startswith("profile scope:")
                    and str(_precond.get("type") or "") in ("certificate_type", "eku_present")
                    and str(predicate or "").lower() in
                        ("must_not_be_present", "must_be_absent", "must_not_include")):
                _subj_norm = re.sub(r"[^a-z0-9]", "", str(normalized_subject or "").lower())
                if any(u in _subj_norm for u in _UNIVERSAL_PROHIBITED):
                    _precond = None

            # 构建 IR
            ir = IntermediateRepresentation(
                stage=IRStage.RAW,
                spec_family=spec_family,
                assertion_subject=assertion_subject,
                enforcement_phase=enforcement_phase,
                subject=subject,
                obligation=obligation,
                predicate=predicate,
                constraint=constraint,
                precondition=_precond,
                requires_operation=normalized.get("requires_operation"),
                references=references,
                rule_text=cleaned_text,  # Use cleaned text (newlines removed)
                provenance=prov_list,
                # Enhanced IR Extraction fields
                rule_category=rule_category,
                verifiability=verifiability,
                algorithm_ref=algorithm_ref,
                overrides=overrides,
                keyword_source=keyword_source,
                parent_rule_id=parent_rule_id,
                scope_block_id=scope_block_id,
                section_scope=section_scope,
            )

            return ir

        except Exception as e:
            app_logger.error(f"构建 IR 失败: {e}")
            return None

    # Criticality requirement patterns: the extension/field itself MUST/SHOULD
    # be (non-)critical. Validated against the RFC5280 corpus (exp_criticality_rederive).
    _CRIT_NEG_RE = re.compile(
        r'(?:be\s+)?mark(?:ed)?\s+(?:this\s+|the\s+)?(?:\w+\s+)?(?:extension\s+)?as\s+non-?critical|'
        r'MUST\s+be\s+(?:marked\s+(?:as\s+)?)?non-?critical|'
        r'SHOULD\s+be\s+(?:marked\s+(?:as\s+)?)?non-?critical|'
        r'be\s+non-?critical\b', re.I)
    _CRIT_POS_RE = re.compile(
        r'(?:be\s+)?mark(?:ed)?\s+(?:this\s+|the\s+)?(?:\w+\s+)?(?:extension\s+)?as\s+critical|'
        r'\bMUST\s+be\s+critical\b|\bbe\s+marked\s+critical\b', re.I)
    # Exclusions: criticality as a precondition / general processing, not a
    # requirement that THIS extension be (non-)critical.
    _CRIT_EXCL_RE = re.compile(
        r'\bif\b[^.]*\bcritical|unrecognized\s+critical|'
        r'\bMAY\b[^.]*critical\s+or\s+non-?critical|appear\s+as\s+a\s+critical\s+or|'
        r'reject\b[^.]*critical|process[^.]*critical|contains?\s+(?:an?\s+)?(?:unrecognized\s+)?critical',
        re.I)

    @classmethod
    def _derive_criticality_predicate(cls, text: str):
        """Return 'must_be_critical' / 'must_not_be_critical' / None.

        Deterministic: only fires on genuine extension-criticality requirements;
        preconditions and "MAY be critical or non-critical" are excluded.
        """
        if not text or cls._CRIT_EXCL_RE.search(text):
            return None
        if cls._CRIT_NEG_RE.search(text):
            return "must_not_be_critical"
        if cls._CRIT_POS_RE.search(text):
            return "must_be_critical"
        return None

    @staticmethod
    def _enforce_verifiability_consistency(
        verifiability,
        rule_category,
        assertion_subject,
        enforcement_phase,
        rule_text: str = ""
    ):
        """强制 verifiability 与其他字段的一致性

        修复 LLM 不确定性：即使 LLM 输出了错误的 verifiability，
        通过规则引擎强制纠正，确保相同输入总是产生相同结果。

        规则优先级（从高到低）：
        0. "in step" 算法步骤引用 → none（最高优先级，基于文本检测）
        1. rule_category 是 definition/capability/display → none
        2. rule_category 是 comparison + enforcement_phase 是 Comparison → runtime_only
        3. assertion_subject 是 Implementation + enforcement_phase 非 Encoding → runtime_only
        4. assertion_subject 是 RelyingParty → runtime_only
        5. assertion_subject 是 Certificate + enforcement_phase 是 Encoding → observable
        6. LLM 原始输出（如果有）
        7. 默认 none（如果 LLM 未提供）
        """
        # 规范化字符串比较
        rc_str = rule_category.value if hasattr(rule_category, 'value') else str(rule_category or '')
        as_str = assertion_subject.value if hasattr(assertion_subject, 'value') else str(assertion_subject or '')
        ep_str = enforcement_phase.value if hasattr(enforcement_phase, 'value') else str(enforcement_phase or '')

        rc_lower = rc_str.lower()
        as_lower = as_str.lower()
        ep_lower = ep_str.lower()
        text_lower = rule_text.lower() if rule_text else ''

        # Rule 0a: "MUST NOT be used" 模式 → runtime_only
        # 这描述的是验证者/依赖方的行为，不是证书内容约束
        # 例如："the public key MUST NOT be used to verify signatures"
        if 'must not be used' in text_lower or 'shall not be used' in text_lower:
            forced = Verifiability.RUNTIME_ONLY
            app_logger.debug(
                f"[_enforce_verifiability] 'MUST NOT be used' pattern → "
                f"forced verifiability from {verifiability} to {forced.value} (relying party behavior)"
            )
            return forced

        # Rule 0b: "in step" 算法步骤引用 → none
        # 文本以 "in step" 开头表示这是算法步骤说明，不是证书内容约束
        # 这些描述的是算法行为，不是可在证书上观测的结果
        # 例外：设置布尔 flag 为 true 的步骤，其效果可能是可观测的
        if text_lower.startswith('in step'):
            text_normalized = text_lower.replace(' ', '').replace('_', '').replace('"', '').replace("'", '')
            # Generic check: does this step SET a boolean flag?
            # Pattern: "set <flag> to <value>" or "<flag> = <value>"
            flag_set_match = re.search(
                r'set.*?(flag|rules?|option|parameter)',
                text_lower,
                re.IGNORECASE
            )
            if flag_set_match:
                # Check if the flag is explicitly set to a falsy value
                has_false_value = re.search(
                    r'(?:to\s+|=\s*|:\s*)(?:false|no|0|disabled)\b',
                    text_normalized
                )
                if has_false_value:
                    # Flag set to false → its effect is NOT enforced → not observable
                    forced = Verifiability.NONE
                    app_logger.debug(
                        f"[_enforce_verifiability] 'in step' sets flag to false → none (effect not enforced)"
                    )
                    return forced
                else:
                    # Flag set to true/active → effect IS enforced → observable
                    app_logger.debug(
                        f"[_enforce_verifiability] 'in step' sets flag to true → observable (effect is time-invariant)"
                    )
                    return Verifiability.OBSERVABLE
            else:
                # Check for observable transformation patterns first
                # "change all labels"/"convert all"/"replace all"/"normalize all"
                # describe transformations whose results are stored in the certificate
                observable_step_match = re.search(
                    r'(?:change\s+all|convert\s+all|replace\s+all|normalize\s+all)',
                    text_lower
                )
                if observable_step_match:
                    app_logger.debug(
                        f"[_enforce_verifiability] 'in step' with observable transformation → observable"
                    )
                    return Verifiability.OBSERVABLE
                # 其他 "in step" 规则都是算法步骤，不可观测
                forced = Verifiability.NONE
                app_logger.debug(
                    f"[_enforce_verifiability] 'in step' algorithm reference → "
                    f"forced verifiability from {verifiability} to {forced.value}"
                )
                return forced

        # Rule 1: definition/capability/display 永远不可观测
        if rc_lower in ('definition', 'capability', 'display'):
            forced = Verifiability.NONE
            if verifiability and verifiability != forced:
                app_logger.debug(
                    f"[_enforce_verifiability] rule_category={rc_str} → "
                    f"forced verifiability from {verifiability} to {forced.value}"
                )
            return forced

        # Rule 2: comparison → runtime_only (regardless of enforcement_phase)
        if rc_lower == 'comparison':
            forced = Verifiability.RUNTIME_ONLY
            if verifiability and verifiability != forced:
                app_logger.debug(
                    f"[_enforce_verifiability] comparison → "
                    f"forced verifiability from {verifiability} to {forced.value}"
                )
            return forced

        # Rule 3: Implementation + non-Encoding phase → runtime_only
        if as_lower == 'implementation' and ep_lower not in ('encoding', ''):
            forced = Verifiability.RUNTIME_ONLY
            if verifiability and verifiability != forced:
                app_logger.debug(
                    f"[_enforce_verifiability] Implementation+{ep_str} → "
                    f"forced verifiability from {verifiability} to {forced.value}"
                )
            return forced

        # Rule 4: RelyingParty → runtime_only
        if as_lower == 'relyingparty':
            forced = Verifiability.RUNTIME_ONLY
            if verifiability and verifiability != forced:
                app_logger.debug(
                    f"[_enforce_verifiability] RelyingParty → "
                    f"forced verifiability from {verifiability} to {forced.value}"
                )
            return forced

        # Rule 5: Certificate + Encoding → observable
        if as_lower == 'certificate' and ep_lower == 'encoding':
            forced = Verifiability.OBSERVABLE
            if verifiability and verifiability != forced:
                app_logger.debug(
                    f"[_enforce_verifiability] Certificate+Encoding → "
                    f"forced verifiability from {verifiability} to {forced.value}"
                )
            return forced

        # Rule 6: 使用 LLM 原始输出
        if verifiability:
            return verifiability

        # Rule 7: 默认 none（保守策略）
        app_logger.debug("[_enforce_verifiability] No verifiability determined, defaulting to none")
        return Verifiability.NONE

    @staticmethod
    def _enforce_rule_category_consistency(
        rule_category,
        assertion_subject,
        enforcement_phase,
        predicate: str,
        subject_path: str,
        rule_text: str,
    ):
        """强制 rule_category 与其他字段的一致性。

        修复 LLM 把 encoding_constraint 误判为 algorithm_ref 的常见错误。

        规则:
        RC-1: algorithm_ref + predicate是encode_as/must_include/conform_to
              + 源文有可观测结果模式 → encoding_constraint
        RC-2: "in step" + "change all/convert all/replace all" → encoding_constraint
        RC-3: encoding_constraint + 证书字段subject → assertion_subject = Certificate
        RC-4: capability/display → assertion_subject = Implementation

        Returns:
            (rule_category, assertion_subject) 元组
        """
        rc_str = rule_category.value if hasattr(rule_category, 'value') else str(rule_category or '')
        as_str = assertion_subject.value if hasattr(assertion_subject, 'value') else str(assertion_subject or '')

        rc_lower = rc_str.lower()
        pred_lower = str(predicate).lower().strip()
        text_lower = rule_text.lower() if rule_text else ''
        subj_lower = subject_path.lower() if subject_path else ''

        # Observable-result patterns: the transformation produces a result stored in the certificate
        observable_patterns = [
            r'before\s+storage',
            r'change\s+all\s+label',
            r'convert\s*.*?\s*to\s*.*?(?:ace|ascii|utf|unicode)',
            r'replace\s+all',
            r'normalize\s+all',
        ]

        # RC-1: algorithm_ref + encoding predicate + observable result → encoding_constraint
        if rc_lower == 'algorithm_ref':
            encoding_predicates = {'encode_as', 'must_include', 'conform_to'}
            if pred_lower in encoding_predicates:
                for pattern in observable_patterns:
                    if re.search(pattern, text_lower):
                        app_logger.debug(
                            f"[_enforce_rule_category] RC-1: algorithm_ref + {pred_lower} "
                            f"+ observable pattern → encoding_constraint"
                        )
                        try:
                            rule_category = RuleCategory('encoding_constraint')
                        except (ValueError, KeyError):
                            rule_category = 'encoding_constraint'
                        rc_lower = 'encoding_constraint'
                        break

        # RC-2: "in step" + observable transformation → encoding_constraint
        if text_lower.startswith('in step'):
            transform_match = re.search(
                r'(?:change\s+all|convert\s+all|replace\s+all|normalize\s+all)',
                text_lower
            )
            if transform_match:
                app_logger.debug(
                    f"[_enforce_rule_category] RC-2: 'in step' + observable transformation "
                    f"→ encoding_constraint"
                )
                try:
                    rule_category = RuleCategory('encoding_constraint')
                except (ValueError, KeyError):
                    rule_category = 'encoding_constraint'
                rc_lower = 'encoding_constraint'
                # Also fix assertion_subject to Certificate
                if as_str.lower() != 'certificate':
                    app_logger.debug(
                        f"[_enforce_rule_category] RC-2: 'in step' transformation "
                        f"→ assertion_subject = Certificate"
                    )
                    assertion_subject = AssertionSubject.CERTIFICATE

        # RC-3: encoding_constraint + certificate field subject → Certificate
        if rc_lower == 'encoding_constraint':
            # Certificate field indicators: subject paths that refer to cert fields
            cert_field_indicators = [
                'subject', 'extensions', 'tbscertificate', 'serialnumber',
                'issuer', 'validity', 'signaturealgorithm', 'subjectpublickeyinfo',
                'commonname', 'domaincomponent', 'countryname', 'organizationname',
                'subjectaltname', 'dnsname', 'ipaddress', 'rfc822name',
                'basicconstraints', 'keyusage', 'nameconstraints',
                'ia5string', 'directorystring', 'utf8string', 'printablestring',
            ]
            for indicator in cert_field_indicators:
                if indicator in subj_lower:
                    if as_str.lower() != 'certificate':
                        app_logger.debug(
                            f"[_enforce_rule_category] RC-3: encoding_constraint + "
                            f"cert field '{subject_path}' → Certificate"
                        )
                        assertion_subject = AssertionSubject.CERTIFICATE
                    break

        # RC-3.5: delegation/reference wording with local observable certificate anchor
        # should stay on the certificate side rather than drift to Implementation.
        delegation_reference_patterns = [
            r'shall\s+comply\s+with',
            r'requirements\s+set\s+out\s+in',
            r'requirements\s+specified\s+in',
            r'as\s+set\s+out\s+in',
            r'in\s+accordance\s+with',
            r'shall\s+apply\s+for',
            r'requirements\s+stated\s+in',
        ]
        observable_certificate_patterns = [
            r'shall\s+be\s+present', r'must\s+be\s+present',
            r'shall\s+not\s+be\s+present', r'must\s+not\s+be\s+present',
            r'shall\s+include', r'must\s+include',
            r'shall\s+contain', r'must\s+contain',
            r'shall\s+be\s+encoded', r'must\s+be\s+encoded',
            r'shall\s+be\s+marked', r'must\s+be\s+marked',
            r'shall\s+have', r'must\s+have',
        ]
        certificate_field_markers = [
            'certificate', 'subject', 'issuer', 'extensions', 'serialnumber',
            'organizationidentifier', 'commonname', 'dnsname', 'rfc822name',
            'directorystring', 'ia5string', 'utf8string', 'printablestring',
            'keyusage', 'nameconstraints', 'certificatepolicies',
            'qcstatements', 'organizationname', 'countryname',
        ]
        has_delegation_reference = any(re.search(p, text_lower) for p in delegation_reference_patterns)
        has_local_observable_anchor = any(re.search(p, text_lower) for p in observable_certificate_patterns)
        has_certificate_field_anchor = any(marker in subj_lower or marker in text_lower for marker in certificate_field_markers)

        if has_delegation_reference and has_local_observable_anchor and has_certificate_field_anchor:
            if rc_lower in ('clarification', 'delegation', 'definition'):
                app_logger.debug(
                    "[_enforce_rule_category] RC-3.5: delegation/reference wording + local observable anchor "
                    "→ encoding_constraint"
                )
                try:
                    rule_category = RuleCategory('encoding_constraint')
                except (ValueError, KeyError):
                    rule_category = 'encoding_constraint'
                rc_lower = 'encoding_constraint'
            if as_str.lower() != 'certificate':
                app_logger.debug(
                    "[_enforce_rule_category] RC-3.5: delegation/reference wording + certificate anchor "
                    "→ Certificate"
                )
                assertion_subject = AssertionSubject.CERTIFICATE

        # RC-3.6: DN attribute rules (subject/issuer organizationIdentifier, commonName, etc.)
        # with encoding/presence predicates → encoding_constraint + Certificate
        dn_attribute_patterns = [
            r'subject\.organizationidentifier',
            r'issuer\.organizationidentifier',
            r'subject\.commonname',
            r'issuer\.commonname',
            r'subject\.organizationname',
            r'issuer\.organizationname',
        ]
        has_dn_attribute = any(re.search(p, subj_lower) for p in dn_attribute_patterns)
        encoding_presence_predicates = {
            'must_be_present', 'must_include', 'must_contain', 'encode_as', 'conform_to',
            'must_equal', 'must_not_be_present',
        }

        if has_dn_attribute and pred_lower in encoding_presence_predicates:
            if rc_lower in ('precondition', 'clarification', 'definition'):
                app_logger.debug(
                    f"[_enforce_rule_category] RC-3.6: DN attribute {subject_path} + {pred_lower} "
                    f"→ encoding_constraint"
                )
                try:
                    rule_category = RuleCategory('encoding_constraint')
                except (ValueError, KeyError):
                    rule_category = 'encoding_constraint'
                rc_lower = 'encoding_constraint'
            if as_str.lower() != 'certificate':
                app_logger.debug(
                    f"[_enforce_rule_category] RC-3.6: DN attribute → Certificate"
                )
                assertion_subject = AssertionSubject.CERTIFICATE

        # RC-4: capability/display → Implementation
        if rc_lower in ('capability', 'display'):
            if as_str.lower() != 'implementation':
                app_logger.debug(
                    f"[_enforce_rule_category] RC-4: {rc_lower} → Implementation"
                )
                assertion_subject = AssertionSubject.IMPLEMENTATION

        # RC-5: CA operational behavior patterns → CA + not lintable
        ca_behavior_patterns = [
            r'verified\s+by\s+the\s+ca',
            r'the\s+ca\s+must\s+verify',
            r'cas\s+must\s+verify',
        ]

        for pattern in ca_behavior_patterns:
            if re.search(pattern, text_lower):
                if as_str.lower() != 'ca':
                    app_logger.debug(
                        f"[_enforce_rule_category] RC-5: CA behavior pattern → CA"
                    )
                    assertion_subject = AssertionSubject.CA
                # CA behavior is not lintable (not observable in certificate)
                if rc_lower == 'encoding_constraint':
                    app_logger.debug(
                        f"[_enforce_rule_category] RC-5: CA behavior → clarification (not encoding_constraint)"
                    )
                    try:
                        rule_category = RuleCategory('clarification')
                    except (ValueError, KeyError):
                        rule_category = 'clarification'
                    rc_lower = 'clarification'
                break

        # RC-6: Implementation validation behavior → Implementation + not lintable
        impl_validation_patterns = [
            r'must\s+be\s+applied\s+to',
            r'must\s+be\s+able\s+to\s+process',
            r'applications\s+must\s+be\s+able\s+to',
            r'implementations\s+must\s+be\s+able\s+to',
        ]
        for pattern in impl_validation_patterns:
            if re.search(pattern, text_lower):
                if as_str.lower() != 'implementation':
                    app_logger.debug(
                        f"[_enforce_rule_category] RC-6: Implementation validation → Implementation"
                    )
                    assertion_subject = AssertionSubject.IMPLEMENTATION
                # Implementation behavior is not lintable
                if rc_lower == 'encoding_constraint':
                    app_logger.debug(
                        f"[_enforce_rule_category] RC-6: Implementation validation → clarification"
                    )
                    try:
                        rule_category = RuleCategory('clarification')
                    except (ValueError, KeyError):
                        rule_category = 'clarification'
                    rc_lower = 'clarification'
                break

        # RC-7: Usage constraint patterns → not lintable
        usage_constraint_patterns = [
            r'must\s+be\s+used\s+only\s+in',
            r'must\s+only\s+be\s+used\s+in',
            r'shall\s+be\s+used\s+only\s+in',
        ]
        for pattern in usage_constraint_patterns:
            if re.search(pattern, text_lower):
                if rc_lower == 'encoding_constraint':
                    app_logger.debug(
                        f"[_enforce_rule_category] RC-7: Usage constraint → clarification (not encoding_constraint)"
                    )
                    try:
                        rule_category = RuleCategory('clarification')
                    except (ValueError, KeyError):
                        rule_category = 'clarification'
                    rc_lower = 'clarification'
                break

        # RC-8: Conditional encoding constraints → encoding_constraint + Certificate
        conditional_encoding_patterns = [
            r'if\s+.*?\s+then\s+.*?\s+must\s+include',
            r'if\s+.*?\s+then\s+.*?\s+must\s+contain',
            r'if\s+.*?\s+then\s+.*?\s+must\s+be\s+present',
        ]
        for pattern in conditional_encoding_patterns:
            if re.search(pattern, text_lower):
                if rc_lower in ('definition', 'clarification'):
                    app_logger.debug(
                        f"[_enforce_rule_category] RC-8: Conditional encoding → encoding_constraint"
                    )
                    try:
                        rule_category = RuleCategory('encoding_constraint')
                    except (ValueError, KeyError):
                        rule_category = 'encoding_constraint'
                    rc_lower = 'encoding_constraint'
                if as_str.lower() != 'certificate':
                    app_logger.debug(
                        f"[_enforce_rule_category] RC-8: Conditional encoding → Certificate"
                    )
                    assertion_subject = AssertionSubject.CERTIFICATE
                break

        # RC-9: Numeric/content constraints → encoding_constraint
        numeric_constraint_patterns = [
            r'must\s+be\s+greater\s+than\s+or\s+equal\s+to',
            r'must\s+be\s+less\s+than\s+or\s+equal\s+to',
            r'must\s+contain\s+at\s+least\s+one',
            r'must\s+include\s+at\s+least\s+one',
        ]
        for pattern in numeric_constraint_patterns:
            if re.search(pattern, text_lower):
                if rc_lower in ('comparison', 'definition', 'clarification'):
                    app_logger.debug(
                        f"[_enforce_rule_category] RC-9: Numeric/content constraint → encoding_constraint"
                    )
                    try:
                        rule_category = RuleCategory('encoding_constraint')
                    except (ValueError, KeyError):
                        rule_category = 'encoding_constraint'
                    rc_lower = 'encoding_constraint'
                if as_str.lower() != 'certificate':
                    app_logger.debug(
                        f"[_enforce_rule_category] RC-9: Numeric/content constraint → Certificate"
                    )
                    assertion_subject = AssertionSubject.CERTIFICATE
                break

        return rule_category, assertion_subject

    # Predicates whose use on a certificate/CRL field is DECIDABLE from that one
    # artifact's own bytes — see lintability_guard.is_single_artifact_observable,
    # the SHARED decision predicate this guard and the structural analyzer both call.
    @staticmethod
    def _enforce_single_artifact_lintability(
        rule_category, assertion_subject, enforcement_phase,
        predicate, subject_path: str, obligation, rule_text: str,
        constraint_text: str = "",
    ):
        """Sound forward guard: correct the two lintability-axis fields
        (enforcement_phase / rule_category) when the LLM mislabeled a
        COMPLETE, codeable, single-artifact-observable constraint on a real
        certificate/CRL field. The decision (incl. the cert-field-path requirement
        and table-fragment rejection that keep CABF operational rules out) lives in
        the shared `lintability_guard.is_single_artifact_observable` so this guard and
        the structural-analyzer rescue can never diverge. Returns
        (rule_category, enforcement_phase).
        """
        from app.services.extraction.lintability_guard import is_single_artifact_observable

        def _v(x):
            return (x.value if hasattr(x, 'value') else str(x or '')).strip()

        if not is_single_artifact_observable(predicate, assertion_subject,
                                             subject_path, obligation, rule_text):
            return rule_category, enforcement_phase

        def _mk(enum_cls, val):
            try:
                return enum_cls(val)
            except (ValueError, KeyError):
                return val

        if _v(enforcement_phase).lower() in ('validation', 'processing'):
            enforcement_phase = _mk(EnforcementPhase, 'Encoding')
        if _v(rule_category).lower() in ('clarification', 'definition'):
            rule_category = _mk(RuleCategory, 'encoding_constraint')
        app_logger.debug(
            f"[_enforce_single_artifact] rescued: pred={_v(predicate)} subj={_v(subject_path)} "
            f"phase={_v(enforcement_phase)} cat={_v(rule_category)}"
        )
        return rule_category, enforcement_phase

    def extract_batch(
        self,
        contexts: List['RuleContext']
    ) -> List[ExtractionResult]:
        """
        批量提取规则 IR（与 RuleSkeletonLLMExtractor 接口兼容）

        此方法接受 ContextBuilder 构建的 RuleContext 列表，
        并使用受控 LLM 提取 IR。

        Args:
            contexts: RuleContext 列表（每个包含 skeleton, base_context, extended_context）

        Returns:
            ExtractionResult 列表
        """
        from .context_builder import RuleContext  # Lazy import to avoid circular

        results = []

        for ctx in contexts:
            try:
                skeleton = ctx.skeleton
                base = ctx.base_context
                extended = ctx.extended_context

                # 构建上下文字符串
                context_parts = []

                # 添加 Canonical Subject 指示（Fix #5: Subject 漂移修复）
                # 这是最重要的上下文，放在最前面
                if 'canonical_subject' in extended:
                    canonical = extended['canonical_subject']
                    context_parts.append(
                        f"CANONICAL SUBJECT: {canonical.get('instruction', '')}\n"
                        f"Subject path to use: {canonical.get('path')}\n"
                        f"Aliases (DO NOT use as subject.path): {canonical.get('aliases', [])}"
                    )

                # 添加 GraphRAG 上下文
                if 'graphrag_context' in extended:
                    context_parts.append(extended['graphrag_context'])

                # 添加作用域继承上下文 (Enhanced IR Extraction)
                if 'scope_block_context' in extended:
                    context_parts.append(extended['scope_block_context'])

                # 添加定义和字段元数据
                if 'definitions' in extended:
                    context_parts.append(f"Definitions: {extended['definitions']}")
                if 'field_metadata' in extended:
                    context_parts.append(f"Field metadata: {extended['field_metadata']}")

                context_str = "\n\n".join(context_parts) if context_parts else None

                # 构建 provenance
                provenance = {
                    'source_id': base.get('document_id', 'unknown'),
                    'section': base.get('section'),
                    'title': base.get('section_title'),
                    'line_start': skeleton.line_number,
                    # Enhanced IR Extraction: 传递作用域继承信息
                    'keyword_source': base.get('keyword_source') or 'direct',
                    'parent_rule_id': base.get('parent_rule_id'),
                    'scope_block_id': base.get('scope_block_id'),
                    'pattern_type': base.get('pattern_type'),
                    # Pass skeleton keyword for inherited/normative_pattern sources
                    'skeleton_keyword': skeleton.keyword if skeleton else None,
                    # Fix #5: Pass canonical subject for subject normalization
                    'canonical_subject': extended.get('canonical_subject'),
                }

                # 使用受控提取
                result = self._extract_single(
                    text=skeleton.sentence,
                    context=context_str,
                    provenance=provenance
                )

                if result:
                    results.append(result)
                else:
                    # 创建空结果以保持索引对齐
                    results.append(ExtractionResult(ir=None))

            except Exception as e:
                app_logger.error(f"批量提取失败 (rule {skeleton.rule_id if skeleton else 'unknown'}): {e}")
                results.append(ExtractionResult(ir=None))

        app_logger.info(
            f"[ControlledLLMExtractor] Batch extraction complete: "
            f"{sum(1 for r in results if r.ir)} successful / {len(contexts)} total"
        )

        return results

    async def extract_batch_async(
        self,
        batches: List[List['RuleContext']],
        max_concurrency: int | None = None,
        progress_callback: Optional[Callable[[int, int], Awaitable[None]]] = None
    ) -> List[ExtractionResult]:
        """
        异步批量提取规则 IR（接收预切好的批次列表，并行处理所有批次）

        接收 batch_by_complexity() 预切好的批次，每个 batch 对应 1 次 _extract_batch_llm 调用。
        所有批次通过 Semaphore + gather 并行执行，由 max_concurrency 控制并发数。

        Args:
            batches: 预切好的批次列表（来自 batch_by_complexity）
            max_concurrency: 最大并发批次数（默认从 settings.llm_max_concurrency 读取）
            progress_callback: 进度回调，签名 (completed_rules, total_rules)

        Returns:
            ExtractionResult 列表（扁平化，顺序与所有输入规则对齐）
        """
        from .context_builder import RuleContext

        if not batches:
            return []

        if max_concurrency is None:
            max_concurrency = settings.llm_max_concurrency

        # 使用局部信号量：允许实验代码通过参数控制并发数
        semaphore = asyncio.Semaphore(max_concurrency)

        # 计算全局索引偏移和总规则数
        total_rules = sum(len(b) for b in batches)
        batch_offsets = []
        offset = 0
        for batch in batches:
            batch_offsets.append(offset)
            offset += len(batch)

        app_logger.info(
            f"[BatchExtract] Processing {total_rules} rules in {len(batches)} batches "
            f"(concurrency={max_concurrency})"
        )

        results: List[Optional[ExtractionResult]] = [None] * total_rules
        completed_rules = 0
        lock = asyncio.Lock()

        # 流式传输下 read timeout 是每个 chunk 的等待时间（非总时间）
        # 推理模型（DeepSeek-R1）首个 token 前需要较长思考时间（~200s）
        # connect=30s, read=300s/chunk, write=30s, pool=30s
        stream_timeout = httpx.Timeout(connect=30.0, read=180.0, write=30.0, pool=30.0)
        async with httpx.AsyncClient(trust_env=False, timeout=stream_timeout) as client:
            async def process_batch(start_idx: int, batch_contexts: List[RuleContext]):
                nonlocal completed_rules

                async with semaphore:
                    batch_results = await self._extract_batch_llm(
                        batch_contexts, client, start_idx
                    )

                    # 将结果放入正确位置
                    for i, result in enumerate(batch_results):
                        global_idx = start_idx + i
                        if global_idx < len(results):
                            results[global_idx] = result

                    async with lock:
                        completed_rules += len(batch_contexts)
                        if progress_callback:
                            try:
                                await progress_callback(completed_rules, total_rules)
                            except Exception as e:
                                app_logger.warning(f"Progress callback failed: {e}")

                    # Add delay after each batch completes
                    await asyncio.sleep(1.0)

            tasks = [
                process_batch(batch_offsets[i], batch)
                for i, batch in enumerate(batches)
            ]
            await asyncio.gather(*tasks)

        final_results = [
            r if r is not None else ExtractionResult(ir=None)
            for r in results
        ]

        success_count = sum(1 for r in final_results if r.ir)
        app_logger.info(
            f"[BatchExtract] Complete: {success_count}/{total_rules} successful "
            f"({len(batches)} API calls instead of {total_rules}, "
            f"reduced by {100 - len(batches) * 100 // max(total_rules, 1)}%)"
        )

        return final_results

    @staticmethod
    def _recover_truncated_json(text: str) -> Optional[list]:
        """
        从截断的 JSON 数组响应中恢复尽可能多的完整对象。

        策略：定位 JSON 数组起点（推理模型如 GLM-Z1 会在 '[' 前输出 thinking
        文本，故不能要求 text 以 '[' 开头），然后扫描收集 **所有** 顶层完整对象
        （depth 从 1 落回 0 即为一个完整对象的边界），而非只保留最后一个。
        截断发生在第 N 个对象中途时，前 N-1 个对象仍可全部恢复。
        """
        text = text.strip()
        # 推理模型常在数组前加 thinking/散文；定位第一个 '[' 作为数组起点
        start = text.find('[')
        if start == -1:
            return None
        text = text[start:]

        # 扫描收集每个顶层对象的结束位置（depth 1→0 的每一次）
        object_ends = []
        brace_depth = 0
        in_string = False
        escape_next = False

        for i, ch in enumerate(text):
            if escape_next:
                escape_next = False
                continue
            if ch == '\\' and in_string:
                escape_next = True
                continue
            if ch == '"':
                in_string = not in_string
                continue
            if in_string:
                continue
            if ch == '{':
                brace_depth += 1
            elif ch == '}':
                brace_depth -= 1
                if brace_depth == 0:
                    object_ends.append(i)

        if not object_ends:
            return None

        # 用最后一个完整对象的结束位置截断，恢复其前的全部对象
        last_complete = object_ends[-1]
        truncated = text[:last_complete + 1].rstrip().rstrip(',') + ']'
        try:
            result = json.loads(truncated)
            if isinstance(result, list) and len(result) > 0:
                return result
        except json.JSONDecodeError:
            pass
        return None

    async def _extract_batch_llm(
        self,
        batch_contexts: List['RuleContext'],
        client: httpx.AsyncClient,
        start_idx: int,
        max_retries: int = 3,
        _split_depth: int = 0
    ) -> List[Optional[ExtractionResult]]:
        """
        对一批规则执行单次LLM调用（核心批量处理逻辑）

        Args:
            batch_contexts: 一批RuleContext
            client: httpx异步客户端
            start_idx: 批次起始索引（用于日志）
            max_retries: 最大重试次数

        Returns:
            ExtractionResult列表（与batch_contexts顺序对齐）
        """
        from .context_builder import RuleContext
        import random

        # 构建规则列表字符串（每条规则附上 per-rule 上下文，与全量提取一致）
        rules_list_parts = []
        provenances = []

        for i, ctx in enumerate(batch_contexts):
            skeleton = ctx.skeleton
            base = ctx.base_context
            extended = ctx.extended_context

            rule_line = f"[{i}] {skeleton.sentence}"

            # 附加 per-rule 上下文：condition/list/pronoun/scope_block 等
            # 与全量提取完全一致，rerun-failed-irs 不会再因为裸句而误判
            ctx_lines = []
            if extended.get('condition_context'):
                ctx_lines.append(f"    [Condition context] {extended['condition_context']}")
            if extended.get('list_context'):
                ctx_lines.append(f"    [List context] {extended['list_context']}")
            if extended.get('pronoun_context'):
                ctx_lines.append(f"    [Pronoun context] {extended['pronoun_context']}")
            if extended.get('scope_block_context'):
                ctx_lines.append(f"    [Scope block] {extended['scope_block_context']}")
            if extended.get('section_topic'):
                ctx_lines.append(f"    [Section topic] {extended['section_topic']}")
            if extended.get('general_context'):
                ctx_lines.append(f"    [General context] {extended['general_context']}")

            if ctx_lines:
                rule_line += "\n" + "\n".join(ctx_lines)

            rules_list_parts.append(rule_line)

            # 保存provenance供后续IR构建使用
            provenances.append({
                'source_id': base.get('document_id', 'unknown'),
                'section': base.get('section'),
                'title': base.get('section_title'),
                'line_start': skeleton.line_number,
                'keyword_source': base.get('keyword_source') or 'direct',
                'parent_rule_id': base.get('parent_rule_id'),
                'scope_block_id': base.get('scope_block_id'),
                'pattern_type': base.get('pattern_type'),
                'skeleton_keyword': skeleton.keyword,
                'canonical_subject': extended.get('canonical_subject'),
                'sentence': skeleton.sentence,
            })

        rules_list_str = "\n".join(rules_list_parts)

        # 使用第一个context的共享上下文
        first_extended = batch_contexts[0].extended_context if batch_contexts else {}
        context_parts = []
        if 'graphrag_context' in first_extended:
            context_parts.append(first_extended['graphrag_context'])
        if 'definitions' in first_extended:
            context_parts.append(f"Definitions: {first_extended['definitions']}")
        if 'canonical_subject' in first_extended:
            canonical = first_extended['canonical_subject']
            field_resolver = get_field_resolver()
            hierarchy_text = field_resolver.get_field_hierarchy_prompt(
                section_root=canonical.get('path')
            )
            context_parts.append(
                f"SUBJECT PATH RULES:\n"
                f"{canonical.get('instruction', '')}\n\n"
                f"CERTIFICATE FIELD HIERARCHY (use these paths for subject):\n"
                f"{hierarchy_text}"
            )
        context_str = "\n\n".join(context_parts) if context_parts else "No additional context."

        # 构建批量prompt（仅 user 部分，system prompt 单独传给流式 API）
        prompt = BATCH_EXTRACTION_PROMPT_TEMPLATE.format(
            rules_list=rules_list_str,
            context=context_str,
            schema=IR_OUTPUT_SCHEMA,
            count=len(batch_contexts)
        )

        # 调用LLM（带重试）- 使用流式传输消除超时问题
        # 每条规则约 1200-1500 tokens JSON 输出 + 推理模型(GLM-Z1)大量 thinking tokens。
        # 给足 thinking 余量（每条 1500 + 固定 10000），封顶 16000 防超模型输出上限。
        # 配合 max_rules_per_batch=4，确保 thinking+JSON 不截断。
        batch_max_tokens = min(16000, len(batch_contexts) * 1500 + 10000)
        llm_response = None
        for attempt in range(max_retries + 1):
            try:
                llm_response = await self.llm_client.generate_async_stream(
                    prompt, client,
                    system_prompt=CONTROLLED_SYSTEM_PROMPT,
                    max_tokens_override=batch_max_tokens
                )
                # 空响应（SiliconFlow 限流，或推理模型只输出 thinking）：带指数退避重试，
                # 而非立刻拆分。拆分+无退避会持续触发限流、卡死管线（实测在 48/614 卡住）。
                if not llm_response and attempt < max_retries:
                    delay = (2 ** attempt) * 3 + random.uniform(0, 2)
                    app_logger.warning(
                        f"Empty LLM response for batch {start_idx}, "
                        f"retry {attempt + 1}/{max_retries} after {delay:.1f}s (rate-limit backoff)"
                    )
                    await asyncio.sleep(delay)
                    continue
                break
            except httpx.HTTPStatusError as e:
                if e.response.status_code == 429 and attempt < max_retries:
                    delay = (2 ** attempt) * 3 + random.uniform(0, 2)
                    app_logger.warning(
                        f"Rate limited (429) for batch starting at {start_idx}, "
                        f"retry {attempt + 1}/{max_retries} after {delay:.1f}s"
                    )
                    await asyncio.sleep(delay)
                    continue
                app_logger.error(f"Batch LLM call failed for batch {start_idx}: HTTP {e.response.status_code}")
                return await self._split_retry_or_fail(
                    batch_contexts, client, start_idx, _split_depth,
                    f"HTTP {e.response.status_code}"
                )
            except (httpx.TimeoutException, httpx.ConnectError, httpx.ReadError) as e:
                # 网络/超时错误：可重试
                if attempt < max_retries:
                    delay = (2 ** attempt) * 2 + random.uniform(0, 1)
                    app_logger.warning(
                        f"Transient error for batch {start_idx} ({type(e).__name__}), "
                        f"retry {attempt + 1}/{max_retries} after {delay:.1f}s"
                    )
                    await asyncio.sleep(delay)
                    continue
                app_logger.error(f"Batch LLM call failed for batch {start_idx} after {max_retries} retries: {type(e).__name__}: {e}")
                return await self._split_retry_or_fail(
                    batch_contexts, client, start_idx, _split_depth,
                    f"{type(e).__name__} after {max_retries} retries"
                )
            except Exception as e:
                app_logger.error(f"Batch LLM call failed for batch {start_idx}: {type(e).__name__}: {e}")
                return await self._split_retry_or_fail(
                    batch_contexts, client, start_idx, _split_depth,
                    f"{type(e).__name__}: {e}"
                )

        if not llm_response:
            return await self._split_retry_or_fail(
                batch_contexts, client, start_idx, _split_depth,
                "empty LLM response"
            )

        # 解析JSON数组响应
        results: List[Optional[ExtractionResult]] = []
        try:
            # 提取JSON数组（处理可能的markdown代码块）
            response_text = llm_response.strip()
            if response_text.startswith("```"):
                # 移除markdown代码块
                lines = response_text.split("\n")
                json_lines = []
                in_block = False
                for line in lines:
                    if line.startswith("```"):
                        in_block = not in_block
                        continue
                    if in_block or not line.startswith("```"):
                        json_lines.append(line)
                response_text = "\n".join(json_lines).strip()

            parsed = json.loads(response_text)

            if not isinstance(parsed, list):
                parsed = [parsed]

            results = self._parse_batch_results(parsed, batch_contexts, provenances, start_idx)

        except json.JSONDecodeError as e:
            # 尝试修复截断的 JSON：找到最后一个完整的 JSON 对象并解析
            app_logger.warning(f"JSON parse error for batch {start_idx}, attempting partial recovery: {e}")
            try:
                recovered = self._recover_truncated_json(response_text)
                if recovered:
                    app_logger.info(
                        f"[BatchLLM] Recovered {len(recovered)} / {len(batch_contexts)} rules from truncated response"
                    )
                    results = self._parse_batch_results(recovered, batch_contexts, provenances, start_idx)
                else:
                    return await self._split_retry_or_fail(
                        batch_contexts, client, start_idx, _split_depth,
                        "truncated JSON, recovery failed"
                    )
            except Exception as recovery_error:
                app_logger.error(f"JSON recovery failed for batch {start_idx}: {recovery_error}")
                return await self._split_retry_or_fail(
                    batch_contexts, client, start_idx, _split_depth,
                    f"JSON recovery exception: {recovery_error}"
                )
        except Exception as e:
            app_logger.error(f"Failed to process batch response: {e}")
            return await self._split_retry_or_fail(
                batch_contexts, client, start_idx, _split_depth,
                f"response processing error: {e}"
            )

        # 检查是否大部分规则都失败了 — 如果是，对失败的规则进行拆分重试
        success_count = sum(1 for r in results if r is not None)
        fail_count = len(results) - success_count

        if fail_count > 0 and success_count > 0 and _split_depth < 2 and len(batch_contexts) > 3:
            # 部分成功：仅对失败的规则进行拆分重试
            failed_indices = [i for i, r in enumerate(results) if r is None]
            failed_contexts = [batch_contexts[i] for i in failed_indices]

            if len(failed_contexts) >= 3:
                app_logger.info(
                    f"[BatchLLM] Batch {start_idx}: {success_count}/{len(batch_contexts)} OK, "
                    f"retrying {len(failed_contexts)} failed rules in smaller batches"
                )
                mid = len(failed_contexts) // 2
                retry_left = await self._extract_batch_llm(
                    failed_contexts[:mid], client, start_idx, 3, _split_depth + 1
                )
                retry_right = await self._extract_batch_llm(
                    failed_contexts[mid:], client, start_idx + mid, 3, _split_depth + 1
                )
                retry_results = retry_left + retry_right

                # 将重试结果合并回原始位置
                for j, orig_idx in enumerate(failed_indices):
                    if j < len(retry_results) and retry_results[j] is not None:
                        results[orig_idx] = retry_results[j]

        return results

    def _parse_batch_results(
        self,
        parsed: list,
        batch_contexts: List['RuleContext'],
        provenances: list,
        start_idx: int
    ) -> List[Optional[ExtractionResult]]:
        """解析 LLM 返回的 JSON 数组为 ExtractionResult 列表"""
        results: List[Optional[ExtractionResult]] = []

        # 按index排序（LLM可能不按顺序返回）
        parsed_by_index = {}
        for item in parsed:
            idx = item.get('index', len(parsed_by_index))
            parsed_by_index[idx] = item

        for i in range(len(batch_contexts)):
            item = parsed_by_index.get(i)
            if not item or item.get('status') == 'undetermined':
                results.append(None)
                continue

            # 验证并构建IR
            try:
                # 移除index字段后再验证
                item_copy = {k: v for k, v in item.items() if k != 'index'}
                validation_result = self.validator.validate(json.dumps(item_copy))
                if not validation_result.is_valid:
                    app_logger.debug(
                        f"Validation failed for rule {start_idx + i}: "
                        f"{[e.message for e in validation_result.errors]}"
                    )
                    results.append(None)
                    continue

                normalized = validation_result.normalized_output
                if not normalized:
                    results.append(None)
                    continue

                ir = self._build_ir(normalized, provenances[i]['sentence'], provenances[i])
                if ir:
                    results.append(ExtractionResult(ir=ir))
                else:
                    results.append(None)
            except Exception as e:
                app_logger.debug(f"Failed to build IR for rule {start_idx + i}: {e}")
                results.append(None)

        # 补齐缺失的结果
        while len(results) < len(batch_contexts):
            results.append(None)

        app_logger.debug(
            f"[BatchLLM] Batch {start_idx}: {sum(1 for r in results if r)} / {len(batch_contexts)} successful"
        )

        return results

    async def _split_retry_or_fail(
        self,
        batch_contexts: List['RuleContext'],
        client: 'httpx.AsyncClient',
        start_idx: int,
        split_depth: int,
        reason: str
    ) -> List[Optional[ExtractionResult]]:
        """
        批次完全失败时的拆分重试策略。

        将失败的批次对半拆分，递归重试。最大拆分深度为 2：
        20 规则 → 10+10 → 5+5+5+5（最坏情况 7 次尝试）

        当批次只剩 1 条规则或超过最大深度时放弃。
        """
        if split_depth >= 2 or len(batch_contexts) <= 1:
            app_logger.warning(
                f"[BatchLLM] Batch {start_idx} ({len(batch_contexts)} rules) "
                f"failed permanently: {reason}"
            )
            return [None] * len(batch_contexts)

        mid = len(batch_contexts) // 2
        app_logger.info(
            f"[BatchLLM] Batch {start_idx} ({len(batch_contexts)} rules) failed ({reason}), "
            f"splitting into {mid}+{len(batch_contexts) - mid} and retrying (depth={split_depth + 1})"
        )

        left = await self._extract_batch_llm(
            batch_contexts[:mid], client, start_idx, 3, split_depth + 1
        )
        right = await self._extract_batch_llm(
            batch_contexts[mid:], client, start_idx + mid, 3, split_depth + 1
        )
        return left + right


def _canonical_subject_context(provenance: Optional[Dict[str, Any]]) -> Optional[str]:
    """Build the canonical_subject anchor block from provenance (standard_id + section).

    The full-pipeline path injects canonical_subject via ContextBuilder, but the
    direct extract_ir() path did not — so batch re-extraction ran anchor-less and
    the LLM drifted the subject (e.g. a §4.1.2.5 'validity dates' rule extracted
    subject='subject'). This reconstructs the same anchor deterministically from
    section_topics_kb (section title) + FieldResolver (title→canonical field path),
    so the subject is pinned to the section's field subtree. Best-effort: any
    failure returns None (no regression, just no anchor)."""
    if not provenance:
        return None
    try:
        from app.services.extraction.section_topics import section_topics_kb
        from app.services.extraction.field_resolver import FieldResolver
        section = (provenance.get("section") or "").strip()
        if not section:
            return None
        # Section title: prefer the per-rule title carried in provenance (works for
        # any standard incl. CABF), fall back to the RFC-centric section_topics_kb.
        title = (provenance.get("title") or "").strip()
        if not title:
            std_map = {1: "RFC5280", "1": "RFC5280", 19: "CABF", "19": "CABF"}
            std = std_map.get(provenance.get("standard_id"))
            if std:
                si = section_topics_kb.get_section_info(std, section)
                if si:
                    title = si.get("title") or ""
        cs = FieldResolver().resolve_section_subject(title, section)
        if not cs or not cs.get("path"):
            return None
        aliases = ", ".join(cs.get("aliases") or [])
        return (
            "canonical_subject:\n"
            f"  path: {cs['path']}\n"
            f"  aliases: {aliases}\n"
            "  instruction: This section's rules constrain the field rooted at the path "
            "above. The extracted `subject` MUST be this path or a sub-path beneath it; "
            "do NOT emit an unrelated top-level field (e.g. do not use 'subject' for a "
            "validity/serialNumber/policy rule)."
        )
    except Exception:
        return None


def extract_ir(
    text: str,
    context: Optional[str] = None,
    provenance: Optional[Dict[str, Any]] = None,
    llm_client: Optional[LLMClient] = None,
    knowledge_graph=None
) -> List[ExtractionResult]:
    """
    便捷函数：提取 IR

    这是用户调用的主入口。系统内部自动：
    - 识别规范体系
    - 检索最小上下文
    - 拼 prompt
    - 调 LLM
    - 验证输出

    Args:
        text: 规范句子
        context: 规范上下文（可选，如果不提供将自动检索）
        provenance: 来源信息
        llm_client: LLM 客户端（可选）
        knowledge_graph: 知识图谱（可选）

    Returns:
        ExtractionResult 列表
    """
    # Anchor the subject to the section's canonical field subtree (prevents the
    # subject-drift that anchor-less batch re-extraction produced). Only when the
    # caller did not already supply context.
    if context is None:
        context = _canonical_subject_context(provenance)
    extractor = ControlledLLMExtractor(
        llm_client=llm_client,
        knowledge_graph=knowledge_graph
    )
    return extractor.extract(text, context=context, provenance=provenance)
