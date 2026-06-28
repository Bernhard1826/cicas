"""
L-Subclass Code Templates for zlint Generation

Provides parameterized Go code templates for each lintable subclass (L1-L7).
Templates are used by ZlintCodeGenerator to produce compilable zlint Go code.

Each template has {{PARAM}} slots that the LLM fills based on IR fields.
The boilerplate (package, imports, init, struct) is shared across all templates.
"""
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, field


# ============================================================
# Source / package / date mapping (mirrors zlint_generator.py)
# ============================================================

SOURCE_MAP = {
    "RFC5280": "RFC5280",
    "RFC": "RFC5280",
    "CABF-TLS-BR": "CABFBaselineRequirements",
    "CABF-SERVER": "CABFBaselineRequirements",
    "CABF-SMIME-BR": "CABFSMIMEBaselineRequirements",
    "CABF-CS": "CABFCSBaselineRequirements",
    "CABF-EV": "CABFEVGuidelines",
    "ETSI-412-4": "EtsiEsi",
    "Mozilla-MRSP": "MozillaRootStorePolicy",
    "Apple": "AppleRootStorePolicy",
}

PACKAGE_MAP = {
    "RFC5280": "rfc",
    "RFC": "rfc",
    "CABF-TLS-BR": "cabf_br",
    "CABF-SERVER": "cabf_br",
    "CABF-SMIME-BR": "cabf_smime_br",
    "CABF-CS": "cabf_cs_br",
    "CABF-EV": "cabf_ev",
    "ETSI-412-4": "etsi",
    "Mozilla-MRSP": "mozilla",
    "Apple": "apple",
}

EFFECTIVE_DATE_MAP = {
    "RFC5280": "RFC5280Date",
    "RFC": "RFC5280Date",
    "CABF-TLS-BR": "CABEffectiveDate",
    "CABF-SERVER": "CABEffectiveDate",
    "CABF-SMIME-BR": "CABF_SMIME_BRs_1_0_0_Date",
    "CABF-CS": "CABF_CS_BRs_1_2_Date",
    "CABF-EV": "CABEffectiveDate",
    "ETSI-412-4": "EtsiEsiEffectiveDate",
    "Mozilla-MRSP": "MozillaPolicy27Date",
    "Apple": "AppleReducedLifetimeDate",
}


# ============================================================
# Template parameter definitions
# ============================================================

@dataclass
class TemplateParam:
    """A parameter slot in a Go template."""
    name: str
    description: str
    example: str
    required: bool = True


@dataclass
class LSubclassTemplate:
    """A parameterized Go code template for one L-subclass."""
    subclass: str  # L1..L7
    description: str
    params: List[TemplateParam]
    execute_template: str  # Go code for Execute() body with {{PARAM}} slots
    check_applies_template: str  # Go code for CheckApplies() body
    extra_imports: List[str] = field(default_factory=list)
    notes: str = ""


# ============================================================
# Shared boilerplate wrapper
# ============================================================

BOILERPLATE_TEMPLATE = '''package {{PACKAGE}}

import (
{{IMPORTS}}
)

type {{STRUCT_NAME}} struct{}

func init() {
\tlint.RegisterCertificateLint(&lint.CertificateLint{
\t\tLintMetadata: lint.LintMetadata{
\t\t\tName:          "{{LINT_NAME}}",
\t\t\tDescription:   "{{DESCRIPTION}}",
\t\t\tCitation:      "{{CITATION}}",
\t\t\tSource:        lint.{{SOURCE}},
\t\t\tEffectiveDate: util.{{EFFECTIVE_DATE}},
\t\t},
\t\tLint: New{{STRUCT_NAME}},
\t})
}

func New{{STRUCT_NAME}}() lint.LintInterface {
\treturn &{{STRUCT_NAME}}{}
}

func (l *{{STRUCT_NAME}}) CheckApplies(c *x509.Certificate) bool {
{{CHECK_APPLIES}}
}

func (l *{{STRUCT_NAME}}) Execute(c *x509.Certificate) *lint.LintResult {
{{EXECUTE}}
}
'''

BASE_IMPORTS = [
    '\t"github.com/zmap/zcrypto/x509"',
    '\t"github.com/zmap/zlint/v3/lint"',
    '\t"github.com/zmap/zlint/v3/util"',
]


# ============================================================
# L1: Presence / absence constraints
# ============================================================

L1_TEMPLATE = LSubclassTemplate(
    subclass="L1",
    description="Check whether a certificate field or extension is present (or absent).",
    params=[
        TemplateParam("FIELD_ACCESS", "Go expression to check for nil/empty", "util.IsExtInCert(c, util.SubjectAlternateNameOID)"),
        TemplateParam("CHECK_TYPE", "'present' or 'absent'", "present"),
        TemplateParam("CHECK_APPLIES_EXPR", "Go boolean expression for CheckApplies", "return true"),
    ],
    check_applies_template="{{CHECK_APPLIES_EXPR}}",
    execute_template="""\t// L1: Presence constraint
\tif {{PRESENCE_CONDITION}} {
\t\treturn &lint.LintResult{Status: {{FAIL_STATUS}}}
\t}
\treturn &lint.LintResult{Status: lint.Pass}""",
    notes="""PRESENCE_CONDITION depends on CHECK_TYPE:
- present: field is nil or missing → fail
- absent: field exists → fail
For extensions, prefer util.IsExtInCert(c, util.XxxOID).
For slice fields (DNSNames), use len(c.DNSNames) == 0.
For pointer fields, use field == nil.""",
)


# ============================================================
# L2: Value equality constraints
# ============================================================

L2_TEMPLATE = LSubclassTemplate(
    subclass="L2",
    description="Check a certificate field equals (or does not equal) a specific value.",
    params=[
        TemplateParam("FIELD_EXPR", "Go expression for the field to check", "c.Version"),
        TemplateParam("EXPECTED_VALUE", "Go literal for expected value", "2"),
        TemplateParam("COMPARISON_OP", "== or !=", "=="),
        TemplateParam("CHECK_APPLIES_EXPR", "Go boolean expression for CheckApplies", "return true"),
    ],
    check_applies_template="{{CHECK_APPLIES_EXPR}}",
    execute_template="""\t// L2: Value equality constraint
\tif {{FIELD_EXPR}} {{COMPARISON_OP}} {{EXPECTED_VALUE}} {
\t\treturn &lint.LintResult{Status: {{FAIL_STATUS}}}
\t}
\treturn &lint.LintResult{Status: lint.Pass}""",
    notes="""For extension Critical flag: use util.GetExtFromCert(c, util.XxxOID).Critical.
For boolean comparisons: true/false (Go lowercase).
For string comparisons: use double quotes.
The comparison logic: if obligation is MUST (field == X), then fail condition is (field != X).""",
)


# ============================================================
# L3: Enumeration constraints
# ============================================================

L3_TEMPLATE = LSubclassTemplate(
    subclass="L3",
    description="Check a certificate field value is in (or not in) an allowed set.",
    params=[
        TemplateParam("FIELD_EXPR", "Go expression for the field", 'c.SignatureAlgorithm.Algorithm.String()'),
        TemplateParam("ALLOWED_VALUES", "Go map or switch cases for allowed values",
                      'map[string]bool{"1.2.840.113549.1.1.11": true}'),
        TemplateParam("MUST_BE_IN_SET", "'true' if value must be in set, 'false' if must NOT be in set", "true"),
        TemplateParam("CHECK_APPLIES_EXPR", "Go boolean expression for CheckApplies", "return true"),
    ],
    check_applies_template="{{CHECK_APPLIES_EXPR}}",
    execute_template="""\t// L3: Enumeration constraint
\tallowed := {{ALLOWED_VALUES}}
\tif {{ENUM_CONDITION}} {
\t\treturn &lint.LintResult{Status: {{FAIL_STATUS}}}
\t}
\treturn &lint.LintResult{Status: lint.Pass}""",
    notes="""ENUM_CONDITION depends on MUST_BE_IN_SET:
- true: !allowed[value] → fail (value must be in allowed set)
- false: allowed[value] → fail (value must NOT be in forbidden set)
Use Go map[string]bool for O(1) lookup.""",
)


# ============================================================
# L4: Encoding / format constraints
# ============================================================

L4_TEMPLATE = LSubclassTemplate(
    subclass="L4",
    description="Check field encoding type or pattern conformance (ASN.1 tag, regex, format).",
    params=[
        TemplateParam("FIELD_EXPR", "Go expression for the field to check", "c.RawSubject"),
        TemplateParam("FORMAT_CHECK_CODE", "Go code block performing the format/encoding check",
                      'matched, _ := regexp.MatchString(`^[a-zA-Z0-9.-]+$`, value)'),
        TemplateParam("CHECK_APPLIES_EXPR", "Go boolean expression for CheckApplies", "return true"),
    ],
    check_applies_template="{{CHECK_APPLIES_EXPR}}",
    execute_template="""\t// L4: Encoding/format constraint
{{FORMAT_CHECK_CODE}}""",
    extra_imports=[],  # dynamically determined from FORMAT_CHECK_CODE
    notes="""This is the most diverse subclass. Common patterns:
1. ASN.1 type check: iterate c.Subject.Names, check .Type tag
2. Regex match: regexp.MatchString on string fields
3. Character set: iterate runes, check range (e.g., ASCII 0-127)
4. Encoding: check specific DER encoding requirements
The FORMAT_CHECK_CODE should be complete Execute body including return statements.""",
)


# ============================================================
# L5: Inclusion / containment constraints
# ============================================================

L5_TEMPLATE = LSubclassTemplate(
    subclass="L5",
    description="Check if a field contains (or does not contain) a specific value or substring.",
    params=[
        TemplateParam("COLLECTION_EXPR", "Go expression for the collection/string to search",
                      "c.ExtKeyUsage"),
        TemplateParam("SEARCH_VALUE", "Go expression for the value to find",
                      "x509.ExtKeyUsageServerAuth"),
        TemplateParam("MUST_CONTAIN", "'true' if must contain, 'false' if must NOT contain", "true"),
        TemplateParam("CHECK_APPLIES_EXPR", "Go boolean expression for CheckApplies", "return true"),
    ],
    check_applies_template="{{CHECK_APPLIES_EXPR}}",
    execute_template="""\t// L5: Inclusion constraint
{{INCLUSION_CHECK_CODE}}""",
    notes="""Common patterns:
1. Slice containment: iterate slice, check for match
2. String contains: strings.Contains(field, substr)
3. OID in extension: check OID list for specific value
INCLUSION_CHECK_CODE should be complete Execute body.
For MUST contain: fail if not found after full iteration.
For MUST NOT contain: fail if found.""",
)


# ============================================================
# L6: Numeric range constraints
# ============================================================

L6_TEMPLATE = LSubclassTemplate(
    subclass="L6",
    description="Check a numeric field is within bounds (min/max/exact).",
    params=[
        TemplateParam("FIELD_EXPR", "Go expression for the numeric field", "c.PublicKey.(*rsa.PublicKey).N.BitLen()"),
        TemplateParam("OPERATOR", "Comparison operator: >=, <=, >, <, ==", ">="),
        TemplateParam("BOUND_VALUE", "Go numeric literal for the bound", "2048"),
        TemplateParam("CHECK_APPLIES_EXPR", "Go boolean expression for CheckApplies", "return true"),
    ],
    check_applies_template="{{CHECK_APPLIES_EXPR}}",
    execute_template="""\t// L6: Numeric range constraint
\tif !({{FIELD_EXPR}} {{OPERATOR}} {{BOUND_VALUE}}) {
\t\treturn &lint.LintResult{Status: {{FAIL_STATUS}}}
\t}
\treturn &lint.LintResult{Status: lint.Pass}""",
    notes="""For key length: use type assertion c.PublicKey.(*rsa.PublicKey).N.BitLen()
For validity period: use time arithmetic c.NotAfter.Sub(c.NotBefore)
May need extra imports (crypto/rsa, math/big, time).""",
)


# ============================================================
# L7: Conditional constraints
# ============================================================

L7_TEMPLATE = LSubclassTemplate(
    subclass="L7",
    description="If a condition holds, then check a constraint. Combines a precondition with an inner check.",
    params=[
        TemplateParam("CONDITION_EXPR", "Go boolean expression for the precondition",
                      "c.IsCA"),
        TemplateParam("INNER_CHECK_CODE", "Go code block for the inner check (runs only when condition is true)",
                      'if !util.IsExtInCert(c, util.BasicConstOID) {\n\t\treturn &lint.LintResult{Status: lint.Error}\n\t}'),
        TemplateParam("CHECK_APPLIES_EXPR", "Go boolean expression for CheckApplies", "return true"),
    ],
    check_applies_template="{{CHECK_APPLIES_EXPR}}",
    execute_template="""\t// L7: Conditional constraint
\tif {{CONDITION_EXPR}} {
\t\t{{INNER_CHECK_CODE}}
\t}
\treturn &lint.LintResult{Status: lint.Pass}""",
    notes="""The precondition can be any boolean expression:
- Certificate type: c.IsCA, util.IsSubscriberCert(c)
- Extension presence: util.IsExtInCert(c, oid)
- Field value: c.Version == 2
- Complex: c.IsCA && util.IsExtInCert(c, util.BasicConstOID)
The inner check code should return on failure, or fall through to Pass.""",
)


# ============================================================
# Template library
# ============================================================

TEMPLATE_REGISTRY: Dict[str, LSubclassTemplate] = {
    "L1": L1_TEMPLATE,
    "L2": L2_TEMPLATE,
    "L3": L3_TEMPLATE,
    "L4": L4_TEMPLATE,
    "L5": L5_TEMPLATE,
    "L6": L6_TEMPLATE,
    "L7": L7_TEMPLATE,
}


class LSubclassTemplateLibrary:
    """Provides parameterized Go code templates for L1-L7 subclasses."""

    def __init__(self):
        self.templates = TEMPLATE_REGISTRY

    def get_template(self, lint_subclass: str) -> Optional[LSubclassTemplate]:
        """Get the template definition for an L-subclass."""
        return self.templates.get(lint_subclass)

    def get_params(self, lint_subclass: str) -> List[TemplateParam]:
        """Get the parameter list for an L-subclass."""
        t = self.templates.get(lint_subclass)
        return t.params if t else []

    def get_available_subclasses(self) -> List[str]:
        """Return list of supported subclasses."""
        return list(self.templates.keys())

    # ----------------------------------------------------------
    # IR → metadata helpers
    # ----------------------------------------------------------

    @staticmethod
    def ir_to_metadata(ir: Dict[str, Any]) -> Dict[str, str]:
        """Extract boilerplate metadata from an IR dict.

        Returns dict with keys: lint_name, struct_name, description,
        citation, source, effective_date, package, fail_status.
        """
        # --- obligation → severity / fail_status ---
        obligation = (ir.get("obligation") or "MUST").upper()
        if obligation in ("MUST", "MUST NOT", "SHALL", "SHALL NOT", "REQUIRED"):
            fail_status = "lint.Error"
            severity_prefix = "e"
        else:
            fail_status = "lint.Warn"
            severity_prefix = "w"

        # --- source / package / date ---
        prov = ir.get("provenance", [{}])
        source_id = prov[0].get("source_id", "") if prov else ""
        if not source_id:
            source_id = ir.get("spec_family", "RFC5280")

        source_const = SOURCE_MAP.get(source_id, "RFC5280")
        package = PACKAGE_MAP.get(source_id, "rfc")
        effective_date = EFFECTIVE_DATE_MAP.get(source_id, "RFC5280Date")

        # --- section ---
        section = prov[0].get("section", "") if prov else ""
        if not section:
            section = ir.get("rule_id", "").split("-")[0] if ir.get("rule_id") else ""

        # --- citation ---
        citation = _format_citation(source_id, section)

        # --- description = rule_text (verbatim original) ---
        description = ir.get("rule_text") or ""
        if not description:
            constraint = ir.get("constraint", {})
            if isinstance(constraint, dict):
                description = constraint.get("raw_text", "")
        # Escape double quotes for Go string literal
        description = description.replace('"', '\\"').replace("\n", " ").strip()
        # Truncate to 500 chars for Go string (zlint convention)
        if len(description) > 500:
            description = description[:497] + "..."

        # --- lint_name ---
        rule_id = ir.get("rule_id", "unknown")
        subject_path = _extract_subject_path(ir)
        predicate = ir.get("predicate", "check")
        base_name = _build_lint_name(subject_path, predicate, rule_id)
        lint_name = f"{severity_prefix}_{base_name}"

        # --- struct_name ---
        struct_name = _to_struct_name(lint_name)

        return {
            "lint_name": lint_name,
            "struct_name": struct_name,
            "description": description,
            "citation": citation,
            "source": source_const,
            "effective_date": effective_date,
            "package": package,
            "fail_status": fail_status,
            "section": section,
            "source_id": source_id,
        }

    # ----------------------------------------------------------
    # Assemble complete Go code
    # ----------------------------------------------------------

    def assemble_go_code(
        self,
        metadata: Dict[str, str],
        check_applies_code: str,
        execute_code: str,
        extra_imports: Optional[List[str]] = None,
    ) -> str:
        """Assemble complete Go source from metadata + function bodies.

        Args:
            metadata: from ir_to_metadata()
            check_applies_code: body of CheckApplies (without func signature)
            execute_code: body of Execute (without func signature)
            extra_imports: additional import lines (e.g., '"strings"')
        """
        # Build imports block
        imports = list(BASE_IMPORTS)
        if extra_imports:
            # Deduplicate and prepend stdlib imports
            for imp in extra_imports:
                imp_line = f'\t"{imp}"' if not imp.startswith('\t') else imp
                if imp_line not in imports:
                    imports.insert(0, imp_line)

        # Auto-detect imports from code
        combined_code = check_applies_code + execute_code
        auto_imports = _detect_imports(combined_code)
        for imp in auto_imports:
            if imp not in imports:
                imports.insert(0, imp)

        imports_block = "\n".join(imports)

        code = BOILERPLATE_TEMPLATE
        code = code.replace("{{PACKAGE}}", metadata["package"])
        code = code.replace("{{IMPORTS}}", imports_block)
        code = code.replace("{{STRUCT_NAME}}", metadata["struct_name"])
        code = code.replace("{{LINT_NAME}}", metadata["lint_name"])
        code = code.replace("{{DESCRIPTION}}", metadata["description"])
        code = code.replace("{{CITATION}}", metadata["citation"])
        code = code.replace("{{SOURCE}}", metadata["source"])
        code = code.replace("{{EFFECTIVE_DATE}}", metadata["effective_date"])
        code = code.replace("{{CHECK_APPLIES}}", check_applies_code)
        code = code.replace("{{EXECUTE}}", execute_code)

        return code


# ============================================================
# Private helpers
# ============================================================

def _format_citation(source_id: str, section: str) -> str:
    """Format citation string for Go code."""
    if not section:
        return source_id
    if source_id.startswith("RFC"):
        return f"RFC 5280: {section}"
    elif "CABF-TLS" in source_id or "CABF-SERVER" in source_id:
        return f"BRs: {section}"
    elif "CABF-CS" in source_id:
        return f"CS BRs: {section}"
    elif "CABF-SMIME" in source_id:
        return f"S/MIME BRs: {section}"
    elif "CABF-EV" in source_id:
        return f"EVGs: {section}"
    elif "ETSI" in source_id:
        return f"ETSI EN 319 412-4: {section}"
    elif "Mozilla" in source_id:
        return f"Mozilla Root Store Policy: {section}"
    return f"{source_id}: {section}"


def _extract_subject_path(ir: Dict[str, Any]) -> str:
    """Get canonical subject path from IR."""
    subject = ir.get("subject", {})
    if isinstance(subject, dict):
        return subject.get("path", "") or subject.get("raw", "")
    return str(subject) if subject else ""


def _build_lint_name(subject_path: str, predicate: str, rule_id: str) -> str:
    """Build a snake_case lint name from IR fields."""
    # Simplify subject path
    parts = subject_path.lower().replace(".", "_").split("_")
    # Remove common prefixes
    skip = {"extensions", "subject", "issuer", "tbscertificate"}
    parts = [p for p in parts if p and p not in skip]

    # Simplify predicate
    pred_parts = predicate.lower().replace("_", " ").split()

    # Combine
    name_parts = parts[:3] + pred_parts[:2]
    if not name_parts:
        # Fallback to rule_id
        name_parts = rule_id.lower().replace("-", "_").replace(".", "_").split("_")

    return "_".join(name_parts)


def _to_struct_name(lint_name: str) -> str:
    """Convert lint name to Go struct name (CamelCase)."""
    # Remove e_ or w_ prefix
    name = lint_name
    if name.startswith("e_") or name.startswith("w_"):
        name = name[2:]
    # Replace dots and hyphens
    name = name.replace(".", "_").replace("-", "_")
    # Skip redundant path segments
    skip = {"extensions", "subjectaltname", "subject", "issuer", "tbscertificate"}
    parts = [p for p in name.split("_") if p.lower() not in skip and p]
    return "".join(p.capitalize() for p in parts)


def _detect_imports(code: str) -> List[str]:
    """Auto-detect needed Go imports from code content."""
    imports = []
    if "strings." in code:
        imports.append('\t"strings"')
    if "regexp." in code:
        imports.append('\t"regexp"')
    if "time." in code:
        imports.append('\t"time"')
    if "fmt." in code:
        imports.append('\t"fmt"')
    if "bytes." in code:
        imports.append('\t"bytes"')
    if "math" in code:
        imports.append('\t"math"')
    if "strconv." in code:
        imports.append('\t"strconv"')
    if "encoding/asn1" in code or "asn1." in code:
        imports.append('\t"encoding/asn1"')
    if "net." in code:
        imports.append('\t"net"')
    if "rsa." in code:
        imports.append('\t"crypto/rsa"')
    if "ecdsa." in code:
        imports.append('\t"crypto/ecdsa"')
    return imports
