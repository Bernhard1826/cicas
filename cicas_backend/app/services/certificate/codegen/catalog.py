"""templates_v2 / catalog.py — typed templates with closed-vocab slots.

Each template:
  - has an id and a short prose description
  - declares typed slots (name + slot kind)
  - validates each slot value against vocab on fill_check()
  - builds a typed DSL.Compound from filled slots via build_dsl()
  - renders an Execute() body via render_body()

Slot kinds (closed vocabulary):
  OID_CONST       : name from vocab.OID_BY_NAME
  DN_FIELD        : name from vocab.DN_BY_NAME
  CERT_FIELD      : name from vocab.CERT_BY_NAME
  STRING_FIELD    : name from CERT_FIELDS|DN_FIELDS with semantic in {string, string_list}
  NUMERIC_FIELD   : name with semantic in {int, bigint}
  LIST_FIELD      : name with semantic in list-like classes
  KU_BIT          : name from vocab.KU_BY_NAME
  EKU_BIT         : name from vocab.EKU_BY_NAME
  ASN1_TYPE       : name from vocab.ASN1_BY_NAME
  DATE_FIELD      : name from vocab.DATE_BY_NAME
  STRING_LIT      : Python str  (no Go-syntax, renderer escapes)
  INT_LIT         : Python int
  INT_OR_MAXINT   : Python int OR the literal string "MAX_INT"
  REGEX_NAMED     : name from vocab.NAMED_REGEX_NAMES (closed pre-audited set;
                    free-form regex literals are NOT allowed)
  STRING_LIT_LIST : list of STRING_LIT
  KU_BIT_LIST     : list of KU_BIT
  EKU_BIT_LIST    : list of EKU_BIT
  ASN1_TYPE_LIST  : list of ASN1_TYPE
  COMPOUND        : nested DSL JSON tree (parsed via dsl.parse, validated)
  FIELD_LABEL     : free human-readable label (statement only, not Go)
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable, Optional

from . import dsl, render, vocab as V


# ---------------------------------------------------------------------
# Slot definition + validation
# ---------------------------------------------------------------------

@dataclass(frozen=True)
class Slot:
    name: str
    kind: str
    desc: str = ""


# kind -> validator(value) -> list[error_str]
def _scalar_in(table_by_name):
    def f(v):
        if not isinstance(v, str):
            return [f"expected string name, got {type(v).__name__}"]
        if v not in table_by_name:
            return [f"unknown name '{v}'; valid: {sorted(table_by_name)[:8]}{'…' if len(table_by_name)>8 else ''}"]
        return []
    return f


def _string_field(v):
    if not isinstance(v, str): return [f"expected string name, got {type(v).__name__}"]
    f = V.lookup_anyfield(v)
    if not f: return [f"unknown FIELD '{v}'"]
    if f.semantic not in ("string", "string_list"):
        return [f"FIELD '{v}' semantic={f.semantic}, must be string or string_list"]
    return []


def _numeric_field(v):
    if not isinstance(v, str): return [f"expected string name, got {type(v).__name__}"]
    f = V.lookup_anyfield(v)
    if not f: return [f"unknown FIELD '{v}'"]
    if f.semantic not in ("int", "bigint"):
        return [f"FIELD '{v}' semantic={f.semantic}, must be int/bigint"]
    return []


def _list_field(v):
    if not isinstance(v, str): return [f"expected string name, got {type(v).__name__}"]
    f = V.lookup_anyfield(v)
    if not f: return [f"unknown FIELD '{v}'"]
    if f.semantic not in ("string_list", "ip_list", "oid_list",
                          "eku_list", "ext_list", "bytes", "subtree_list"):
        return [f"FIELD '{v}' semantic={f.semantic}, must be list-like"]
    return []


def _bytes_field(v):
    if not isinstance(v, str): return [f"expected string name, got {type(v).__name__}"]
    f = V.lookup_anyfield(v)
    if not f: return [f"unknown FIELD '{v}'"]
    if f.semantic != "bytes":
        return [f"FIELD '{v}' semantic={f.semantic}, must be bytes"]
    return []


def _ip_list_field(v):
    if not isinstance(v, str): return [f"expected string name, got {type(v).__name__}"]
    f = V.lookup_anyfield(v)
    if not f: return [f"unknown FIELD '{v}'"]
    if f.semantic != "ip_list":
        return [f"FIELD '{v}' semantic={f.semantic}, must be ip_list"]
    return []


def _oid_list_field(v):
    if not isinstance(v, str): return [f"expected string name, got {type(v).__name__}"]
    f = V.lookup_anyfield(v)
    if not f: return [f"unknown FIELD '{v}'"]
    if f.semantic != "oid_list":
        return [f"FIELD '{v}' semantic={f.semantic}, must be oid_list"]
    return []


def _oid_scalar_field(v):
    """Single OID-typed field (semantic == 'oid'): PublicKeyAlgorithmOID,
    SignatureAlgorithmOID."""
    if not isinstance(v, str): return [f"expected string name, got {type(v).__name__}"]
    f = V.lookup_anyfield(v)
    if not f: return [f"unknown FIELD '{v}'"]
    if f.semantic != "oid":
        return [f"FIELD '{v}' semantic={f.semantic}, must be oid (single OID-typed scalar field)"]
    return []


def _subtree_ip_field(v):
    """NameConstraints subtree IP list: PermittedIPAddresses / ExcludedIPAddresses."""
    if not isinstance(v, str): return [f"expected string name, got {type(v).__name__}"]
    f = V.lookup_anyfield(v)
    if not f: return [f"unknown FIELD '{v}'"]
    if f.go_type != "[]GeneralSubtreeIP":
        return [f"FIELD '{v}' go_type={f.go_type}, must be []GeneralSubtreeIP "
                "(PermittedIPAddresses or ExcludedIPAddresses)"]
    return []


def _string_lit(v):
    return [] if isinstance(v, str) else [f"expected str literal, got {type(v).__name__}"]


def _int_lit(v):
    return [] if isinstance(v, int) and not isinstance(v, bool) \
        else [f"expected int literal, got {type(v).__name__}"]


def _int_or_maxint(v):
    if isinstance(v, int) and not isinstance(v, bool): return []
    if v == "MAX_INT": return []
    return [f"expected int or 'MAX_INT', got {v!r}"]


def _list_of(elem_validator):
    def f(v):
        if not isinstance(v, list):
            return [f"expected list, got {type(v).__name__}"]
        errs = []
        for i, x in enumerate(v):
            for e in elem_validator(x):
                errs.append(f"[{i}]: {e}")
        return errs
    return f


def _compound(v):
    """Parse + validate JSON DSL tree (top-level, not in list-item context)."""
    try:
        node = dsl.parse(v)
    except dsl.DSLError as e:
        return [f"DSL parse error: {e}"]
    return dsl.validate(node)


def _compound_in_item(v):
    """Parse + validate JSON DSL tree as a list-item predicate.
    ItemMatchesRegex/ItemInSet/ItemEq are valid here."""
    try:
        node = dsl.parse(v)
    except dsl.DSLError as e:
        return [f"DSL parse error: {e}"]
    return dsl.validate(node, in_item_context=True)


def _date_or_lit(v):
    if not isinstance(v, str): return [f"expected DATE_FIELD or YYYY-MM-DD literal, got {type(v).__name__}"]
    if v in V.DATE_BY_NAME: return []
    import re as _re
    if _re.fullmatch(r"\d{4}-\d{2}-\d{2}", v):
        return []
    return [f"expected DATE_FIELD ({sorted(V.DATE_BY_NAME)}) or YYYY-MM-DD literal, got '{v}'"]


def _hex_lit(v):
    if not isinstance(v, str): return [f"expected hex string, got {type(v).__name__}"]
    import re as _re
    if not _re.fullmatch(r"[0-9a-fA-F]+", v):
        return [f"hex must contain only [0-9a-fA-F], got {v[:30]!r}"]
    if len(v) % 2 != 0:
        return [f"hex must be even length (got {len(v)})"]
    return []


def _pubkey_alg(v):
    allowed = ("RSA", "DSA", "ECDSA", "Ed25519", "Ed448", "X25519", "X448")
    if v in allowed: return []
    return [f"expected one of {allowed}, got {v!r}"]


def _dn_holder(v):
    if v in ("Subject", "Issuer"): return []
    return [f"expected 'Subject' or 'Issuer', got {v!r}"]


SLOT_VALIDATORS: dict[str, Callable[[Any], list[str]]] = {
    "OID_CONST":         _scalar_in(V.OID_BY_NAME),
    "DN_FIELD":          _scalar_in(V.DN_BY_NAME),
    "CERT_FIELD":        _scalar_in({**V.CERT_BY_NAME, **V.DN_BY_NAME}),
    "STRING_FIELD":      _string_field,
    "NUMERIC_FIELD":     _numeric_field,
    "LIST_FIELD":        _list_field,
    "BYTES_FIELD":       _bytes_field,
    "IP_LIST_FIELD":     _ip_list_field,
    "OID_LIST_FIELD":    _oid_list_field,
    "OID_SCALAR_FIELD":  _oid_scalar_field,
    "SUBTREE_IP_FIELD":  _subtree_ip_field,
    "KU_BIT":            _scalar_in(V.KU_BY_NAME),
    "EKU_BIT":           _scalar_in(V.EKU_BY_NAME),
    "ASN1_TYPE":         _scalar_in(V.ASN1_BY_NAME),
    "DATE_FIELD":        _scalar_in(V.DATE_BY_NAME),
    "STRING_LIT":        _string_lit,
    "INT_LIT":           _int_lit,
    "INT_OR_MAXINT":     _int_or_maxint,
    "REGEX_NAMED":       _scalar_in({n: n for n in V.NAMED_REGEX_NAMES}),
    "STRING_LIT_LIST":   _list_of(_string_lit),
    "KU_BIT_LIST":       _list_of(_scalar_in(V.KU_BY_NAME)),
    "EKU_BIT_LIST":      _list_of(_scalar_in(V.EKU_BY_NAME)),
    "ASN1_TYPE_LIST":    _list_of(_scalar_in(V.ASN1_BY_NAME)),
    "COMPOUND":          _compound,
    "COMPOUND_IN_ITEM":  _compound_in_item,
    "FIELD_LABEL":       _string_lit,
    "DATE_OR_LIT":       _date_or_lit,
    "HEX_LIT":           _hex_lit,
    "PUBKEY_ALG":        _pubkey_alg,
    "DN_HOLDER":         _dn_holder,
}


# ---------------------------------------------------------------------
# Template
# ---------------------------------------------------------------------

@dataclass(frozen=True)
class Template:
    id: str
    handles: str
    slots: tuple   # tuple of Slot
    shape: str     # "compound" | "conditional"
    build: Callable[[dict], "dsl.Compound | tuple"]
    statement: str   # English statement template, slot names in {NAME} form


def fill_check(t: Template, slots: dict) -> list[str]:
    """Validate that every required slot is present and well-typed."""
    errs: list[str] = []
    declared = {s.name: s for s in t.slots}
    for name in declared:
        if name not in slots:
            errs.append(f"missing slot '{name}'")
    for name in slots:
        if name not in declared:
            errs.append(f"unknown slot '{name}'")
    if errs:
        return errs
    for s in t.slots:
        v = slots[s.name]
        v_errs = SLOT_VALIDATORS[s.kind](v)
        for e in v_errs:
            errs.append(f"slot '{s.name}' (kind={s.kind}): {e}")
    return errs


# ---------------------------------------------------------------------
# Body shapes: compound  vs  conditional (NA precondition)
# ---------------------------------------------------------------------

# {severity} is substituted with one of: lint.Error | lint.Warn | lint.Notice
# according to the source rule's prescriptive level (MUST -> Error,
# SHOULD/RECOMMENDED -> Warn, MAY/Notice -> Notice). The Pass branch is
# unchanged across all severities.

_COMPOUND_BODY = """\
        if {expr} {{
            return &lint.LintResult{{Status: lint.Pass}}
        }}
        return &lint.LintResult{{Status: {severity}}}"""

_CONDITIONAL_BODY = """\
        if !({pre}) {{
            return &lint.LintResult{{Status: lint.NA}}
        }}
        if {req} {{
            return &lint.LintResult{{Status: lint.Pass}}
        }}
        return &lint.LintResult{{Status: {severity}}}"""


def render_body(t: Template, slots: dict, severity: str = "lint.Error") -> dict:
    """Build DSL tree, validate, render to Go body, collect imports.
    `severity` is the lint status returned when the requirement is violated;
    one of "lint.Error", "lint.Warn", "lint.Notice".
    Returns:
      {"execute_body": str, "imports": set[str], "dsl_tree": Compound|tuple}
    Raises dsl.DSLError on internal inconsistency.
    """
    if severity not in ("lint.Error", "lint.Warn", "lint.Notice"):
        raise dsl.DSLError(f"unknown severity '{severity}'")
    errs = fill_check(t, slots)
    if errs:
        raise dsl.DSLError(f"slot fill_check errors: {errs}")
    built = t.build(slots)
    if t.shape == "compound":
        node = built
        if isinstance(node, dict):  # COMPOUND slot already JSON
            node = dsl.parse(node)
        v_errs = dsl.validate(node)
        if v_errs:
            raise dsl.DSLError(f"DSL validation errors: {v_errs}")
        expr = render.render(node)
        body = _COMPOUND_BODY.format(expr=expr, severity=severity)
        imps = render.collect_imports(node)
        return {"execute_body": body, "imports": imps, "dsl_tree": node}
    if t.shape == "conditional":
        pre, req = built
        if isinstance(pre, dict): pre = dsl.parse(pre)
        if isinstance(req, dict): req = dsl.parse(req)
        v_errs = dsl.validate(pre) + dsl.validate(req)
        if v_errs:
            raise dsl.DSLError(f"DSL validation errors: {v_errs}")
        body = _CONDITIONAL_BODY.format(pre=render.render(pre),
                                         req=render.render(req),
                                         severity=severity)
        imps = render.collect_imports(pre) | render.collect_imports(req)
        return {"execute_body": body, "imports": imps, "dsl_tree": (pre, req)}
    raise dsl.DSLError(f"unknown shape '{t.shape}'")


# Map requirement levels (RFC 2119 / source-doc strings) to lint severities.
# Anything MUST/MUST NOT/REQUIRED/SHALL/SHALL NOT is Error; SHOULD / SHOULD
# NOT / RECOMMENDED / NOT RECOMMENDED is Warn; MAY / OPTIONAL is Notice.
_LEVEL_TO_SEV = {
    "MUST":            "lint.Error",
    "MUST_NOT":        "lint.Error",
    "MUST NOT":        "lint.Error",
    "REQUIRED":        "lint.Error",
    "SHALL":           "lint.Error",
    "SHALL_NOT":       "lint.Error",
    "SHALL NOT":       "lint.Error",
    "SHOULD":          "lint.Warn",
    "SHOULD_NOT":      "lint.Warn",
    "SHOULD NOT":      "lint.Warn",
    "RECOMMENDED":     "lint.Warn",
    "NOT_RECOMMENDED": "lint.Warn",
    "NOT RECOMMENDED": "lint.Warn",
    "MAY":             "lint.Notice",
    "OPTIONAL":        "lint.Notice",
}

# Heuristic phrases inside rule_text used as a fallback when the structured
# requirement_level field disagrees / is missing.
import re as _re
_TXT_SHOULD = _re.compile(r"\b(SHOULD\s*NOT|SHOULD|RECOMMENDED|NOT\s+RECOMMENDED)\b", _re.I)
_TXT_MUST   = _re.compile(r"\b(MUST\s*NOT|MUST|SHALL\s*NOT|SHALL|REQUIRED)\b", _re.I)


def severity_for(rule_text: str = "", requirement_level: str = "") -> str:
    """Pick lint severity from the rule's prescriptive level.

    Precedence:
      1. Explicit requirement_level lookup
      2. MUST/SHALL phrase in rule_text -> lint.Error
      3. SHOULD / RECOMMENDED phrase in rule_text -> lint.Warn
      4. Default lint.Error (fail-safe)
    """
    lvl = (requirement_level or "").strip().upper()
    if lvl in _LEVEL_TO_SEV:
        return _LEVEL_TO_SEV[lvl]
    txt = rule_text or ""
    has_must   = bool(_TXT_MUST.search(txt))
    has_should = bool(_TXT_SHOULD.search(txt))
    if has_must and not has_should:
        return "lint.Error"
    if has_should and not has_must:
        return "lint.Warn"
    # Mixed / neither -> Error fail-safe
    return "lint.Error"


# ---------------------------------------------------------------------
# Statement rendering (English, separate from Go)
# ---------------------------------------------------------------------

def render_statement(t: Template, slots: dict) -> str:
    return t.statement.format(**slots)


# ---------------------------------------------------------------------
# CATALOG
# ---------------------------------------------------------------------

# Atom helpers
def _A(op, *args):
    """Build a raw DSL atom dict (not parsed yet)."""
    return {"op": op, "args": list(args)}


CATALOG: list[Template] = [
    Template(
        id="T_ext_present",
        handles="extension MUST be present",
        slots=(Slot("OID_CONST", "OID_CONST", "extension OID constant name"),
               Slot("FIELD_LABEL", "FIELD_LABEL", "extension human-readable name")),
        shape="compound",
        build=lambda s: dsl.parse(_A("ExtPresent", s["OID_CONST"])),
        statement="The {FIELD_LABEL} extension MUST be present.",
    ),
    Template(
        id="T_ext_absent",
        handles="extension MUST NOT be present",
        slots=(Slot("OID_CONST", "OID_CONST"),
               Slot("FIELD_LABEL", "FIELD_LABEL")),
        shape="compound",
        build=lambda s: dsl.parse(
            {"op": "Not", "args": [_A("ExtPresent", s["OID_CONST"])]}),
        statement="The {FIELD_LABEL} extension MUST NOT be present.",
    ),
    Template(
        id="T_ext_critical",
        handles="extension MUST be critical (and present)",
        slots=(Slot("OID_CONST", "OID_CONST"),
               Slot("FIELD_LABEL", "FIELD_LABEL")),
        shape="compound",
        build=lambda s: dsl.parse(_A("ExtCritical", s["OID_CONST"])),
        statement="If present, the {FIELD_LABEL} extension MUST be marked critical.",
    ),
    Template(
        id="T_ext_non_critical",
        handles="extension MUST NOT be critical (when present)",
        slots=(Slot("OID_CONST", "OID_CONST"),
               Slot("FIELD_LABEL", "FIELD_LABEL")),
        shape="conditional",
        build=lambda s: (
            dsl.parse(_A("ExtPresent", s["OID_CONST"])),
            dsl.parse(_A("ExtNotCritical", s["OID_CONST"])),
        ),
        statement="When the {FIELD_LABEL} extension is present, it MUST NOT be marked critical.",
    ),

    Template(
        id="T_dn_field_present",
        handles="DN attribute MUST be present (subject or issuer)",
        slots=(Slot("DN_FIELD", "DN_FIELD"),
               Slot("FIELD_LABEL", "FIELD_LABEL")),
        shape="compound",
        build=lambda s: dsl.parse(_A("FieldNonEmpty", s["DN_FIELD"])),
        statement="The {FIELD_LABEL} MUST be present.",
    ),
    Template(
        id="T_dn_field_absent",
        handles="DN attribute MUST NOT be present",
        slots=(Slot("DN_FIELD", "DN_FIELD"),
               Slot("FIELD_LABEL", "FIELD_LABEL")),
        shape="compound",
        build=lambda s: dsl.parse(_A("FieldEmpty", s["DN_FIELD"])),
        statement="The {FIELD_LABEL} MUST NOT be present.",
    ),
    Template(
        id="T_dn_field_eq",
        handles="DN attribute MUST equal a specific value",
        slots=(Slot("DN_FIELD", "DN_FIELD"),
               Slot("EXPECTED", "STRING_LIT"),
               Slot("FIELD_LABEL", "FIELD_LABEL")),
        shape="compound",
        build=lambda s: dsl.parse(_A("FieldEq", s["DN_FIELD"], s["EXPECTED"])),
        statement='The {FIELD_LABEL} MUST equal "{EXPECTED}".',
    ),
    Template(
        id="T_dn_field_in_set",
        handles="DN attribute MUST be one of a fixed set",
        slots=(Slot("DN_FIELD", "DN_FIELD"),
               Slot("VALUES", "STRING_LIT_LIST"),
               Slot("FIELD_LABEL", "FIELD_LABEL")),
        shape="compound",
        build=lambda s: dsl.parse(_A("FieldInSet", s["DN_FIELD"], list(s["VALUES"]))),
        statement="The {FIELD_LABEL} MUST be one of: {VALUES}.",
    ),

    Template(
        id="T_field_eq",
        handles="cert field MUST equal a specific value",
        slots=(Slot("FIELD", "CERT_FIELD"),
               Slot("EXPECTED", "STRING_LIT"),
               Slot("FIELD_LABEL", "FIELD_LABEL")),
        shape="compound",
        build=lambda s: dsl.parse(_A("FieldEq", s["FIELD"], s["EXPECTED"])),
        statement="{FIELD_LABEL} MUST equal {EXPECTED}.",
    ),
    Template(
        id="T_field_eq_int",
        handles="numeric cert field MUST equal a specific int",
        slots=(Slot("FIELD", "NUMERIC_FIELD"),
               Slot("EXPECTED", "INT_LIT"),
               Slot("FIELD_LABEL", "FIELD_LABEL")),
        shape="compound",
        build=lambda s: dsl.parse(_A("FieldEq", s["FIELD"], s["EXPECTED"])),
        statement="{FIELD_LABEL} MUST equal {EXPECTED}.",
    ),
    Template(
        id="T_field_in_range",
        handles="numeric cert field MUST be in [lo, hi]",
        slots=(Slot("FIELD", "NUMERIC_FIELD"),
               Slot("LO", "INT_LIT"),
               Slot("HI", "INT_OR_MAXINT"),
               Slot("FIELD_LABEL", "FIELD_LABEL")),
        shape="compound",
        build=lambda s: dsl.parse(
            _A("FieldNumericInRange", s["FIELD"], s["LO"], s["HI"])),
        statement="{FIELD_LABEL} MUST be in [{LO}, {HI}].",
    ),
    Template(
        id="T_field_len_in_range",
        handles="list/string cert field len MUST be in [lo, hi]",
        slots=(Slot("FIELD", "LIST_FIELD"),
               Slot("LO", "INT_LIT"),
               Slot("HI", "INT_OR_MAXINT"),
               Slot("FIELD_LABEL", "FIELD_LABEL")),
        shape="compound",
        build=lambda s: dsl.parse(
            _A("FieldLenInRange", s["FIELD"], s["LO"], s["HI"])),
        statement="len({FIELD_LABEL}) MUST be in [{LO}, {HI}].",
    ),
    Template(
        id="T_field_match_regex",
        handles="string cert field MUST match a NAMED_REGEX (no free-form regex)",
        slots=(Slot("FIELD", "STRING_FIELD"),
               Slot("PATTERN", "REGEX_NAMED"),
               Slot("FIELD_LABEL", "FIELD_LABEL")),
        shape="compound",
        build=lambda s: dsl.parse(
            _A("FieldMatchesRegex", s["FIELD"], s["PATTERN"])),
        statement="{FIELD_LABEL} MUST match the named regex {PATTERN}.",
    ),
    Template(
        id="T_field_in_set",
        handles="cert field MUST be one of a fixed set",
        slots=(Slot("FIELD", "CERT_FIELD"),
               Slot("VALUES", "STRING_LIT_LIST"),
               Slot("FIELD_LABEL", "FIELD_LABEL")),
        shape="compound",
        build=lambda s: dsl.parse(
            _A("FieldInSet", s["FIELD"], list(s["VALUES"]))),
        statement="{FIELD_LABEL} MUST be one of: {VALUES}.",
    ),
    Template(
        id="T_field_not_in_set",
        handles="cert field MUST NOT be in a forbidden set",
        slots=(Slot("FIELD", "CERT_FIELD"),
               Slot("VALUES", "STRING_LIT_LIST"),
               Slot("FIELD_LABEL", "FIELD_LABEL")),
        shape="compound",
        build=lambda s: dsl.parse(
            _A("FieldNotInSet", s["FIELD"], list(s["VALUES"]))),
        statement="{FIELD_LABEL} MUST NOT be any of: {VALUES}.",
    ),
    Template(
        id="T_field_encoded_as",
        handles="string cert field MUST be encodable as one of given ASN.1 string types",
        slots=(Slot("FIELD", "STRING_FIELD"),
               Slot("TYPES", "ASN1_TYPE_LIST"),
               Slot("FIELD_LABEL", "FIELD_LABEL")),
        shape="compound",
        build=lambda s: dsl.parse(
            _A("FieldEncodedAs", s["FIELD"], list(s["TYPES"]))),
        statement="{FIELD_LABEL} MUST be encoded as one of: {TYPES}.",
    ),

    Template(
        id="T_keyusage_required",
        handles="KeyUsage extension MUST contain all listed bits (and be present)",
        slots=(Slot("BITS", "KU_BIT_LIST"),
               Slot("FIELD_LABEL", "FIELD_LABEL")),
        shape="compound",
        build=lambda s: dsl.parse(
            {"op": "And",
             "args": [_A("KeyUsageHas", b) for b in s["BITS"]]}),
        statement="{FIELD_LABEL} KeyUsage MUST include: {BITS}.",
    ),
    Template(
        id="T_keyusage_forbidden",
        handles="KeyUsage extension MUST NOT contain any listed bits",
        slots=(Slot("BITS", "KU_BIT_LIST"),
               Slot("FIELD_LABEL", "FIELD_LABEL")),
        shape="compound",
        build=lambda s: dsl.parse(
            {"op": "Not",
             "args": [{"op": "Or",
                       "args": [_A("KeyUsageHas", b) for b in s["BITS"]]}]}),
        statement="{FIELD_LABEL} KeyUsage MUST NOT include: {BITS}.",
    ),
    Template(
        id="T_eku_required",
        handles="ExtendedKeyUsage MUST contain all listed bits",
        slots=(Slot("BITS", "EKU_BIT_LIST"),
               Slot("FIELD_LABEL", "FIELD_LABEL")),
        shape="compound",
        build=lambda s: dsl.parse(
            {"op": "And",
             "args": [_A("ExtKeyUsageHas", b) for b in s["BITS"]]}),
        statement="{FIELD_LABEL} ExtKeyUsage MUST include: {BITS}.",
    ),
    Template(
        id="T_eku_forbidden",
        handles="ExtendedKeyUsage MUST NOT contain any listed bits",
        slots=(Slot("BITS", "EKU_BIT_LIST"),
               Slot("FIELD_LABEL", "FIELD_LABEL")),
        shape="compound",
        build=lambda s: dsl.parse(
            {"op": "Not",
             "args": [{"op": "Or",
                       "args": [_A("ExtKeyUsageHas", b) for b in s["BITS"]]}]}),
        statement="{FIELD_LABEL} ExtKeyUsage MUST NOT include: {BITS}.",
    ),

    Template(
        id="T_list_all_match",
        handles="every element of LIST_FIELD MUST satisfy a predicate",
        slots=(Slot("FIELD", "LIST_FIELD"),
               Slot("PREDICATE", "COMPOUND_IN_ITEM",
                    "DSL Compound using ItemMatchesRegex/ItemInSet/ItemEq"),
               Slot("FIELD_LABEL", "FIELD_LABEL")),
        shape="compound",
        build=lambda s: dsl.parse(
            _A("ListAllMatch", s["FIELD"], s["PREDICATE"])),
        statement="Every {FIELD_LABEL} MUST satisfy the given predicate.",
    ),
    Template(
        id="T_list_any_match",
        handles="at least one element of LIST_FIELD MUST satisfy a predicate",
        slots=(Slot("FIELD", "LIST_FIELD"),
               Slot("PREDICATE", "COMPOUND_IN_ITEM"),
               Slot("FIELD_LABEL", "FIELD_LABEL")),
        shape="compound",
        build=lambda s: dsl.parse(
            _A("ListAnyMatch", s["FIELD"], s["PREDICATE"])),
        statement="At least one {FIELD_LABEL} MUST satisfy the given predicate.",
    ),
    Template(
        id="T_list_unique",
        handles="elements of LIST_FIELD MUST be pairwise distinct",
        slots=(Slot("FIELD", "LIST_FIELD"),
               Slot("FIELD_LABEL", "FIELD_LABEL")),
        shape="compound",
        build=lambda s: dsl.parse(_A("ListUnique", s["FIELD"])),
        statement="Each {FIELD_LABEL} MUST be unique.",
    ),

    Template(
        id="T_date_after",
        handles="one date MUST be after another",
        slots=(Slot("LATER", "DATE_FIELD"),
               Slot("EARLIER", "DATE_FIELD"),
               Slot("LATER_LABEL", "FIELD_LABEL"),
               Slot("EARLIER_LABEL", "FIELD_LABEL")),
        shape="compound",
        build=lambda s: dsl.parse(_A("DateAfter", s["LATER"], s["EARLIER"])),
        statement="{LATER_LABEL} MUST be after {EARLIER_LABEL}.",
    ),

    Template(
        id="T_compound",
        handles="general single requirement; LLM gives a Compound DSL tree",
        slots=(Slot("REQUIREMENT", "COMPOUND",
                    "DSL Compound; the whole thing must be true for Pass"),
               Slot("REQUIREMENT_LABEL", "FIELD_LABEL")),
        shape="compound",
        build=lambda s: dsl.parse(s["REQUIREMENT"]),
        statement="The certificate MUST satisfy: {REQUIREMENT_LABEL}.",
    ),
    Template(
        id="T_conditional",
        handles="when PRECONDITION holds, REQUIREMENT MUST hold (NA otherwise)",
        slots=(Slot("PRECONDITION", "COMPOUND"),
               Slot("REQUIREMENT", "COMPOUND"),
               Slot("PRECONDITION_LABEL", "FIELD_LABEL"),
               Slot("REQUIREMENT_LABEL", "FIELD_LABEL")),
        shape="conditional",
        build=lambda s: (
            dsl.parse(s["PRECONDITION"]),
            dsl.parse(s["REQUIREMENT"]),
        ),
        statement="When {PRECONDITION_LABEL}, the certificate MUST satisfy: {REQUIREMENT_LABEL}.",
    ),

    Template(
        id="T_two_byte_fields_eq",
        handles="two []byte cert fields MUST be byte-for-byte equal (e.g. SubjectKeyId == AuthorityKeyId)",
        slots=(Slot("FIELD_A", "BYTES_FIELD"),
               Slot("FIELD_B", "BYTES_FIELD"),
               Slot("FIELD_LABEL", "FIELD_LABEL")),
        shape="compound",
        build=lambda s: dsl.parse(_A("BytesEq", s["FIELD_A"], s["FIELD_B"])),
        statement="{FIELD_LABEL}: {FIELD_A} MUST equal {FIELD_B}.",
    ),
    Template(
        id="T_ip_octet_count",
        handles="every IP in an ip_list field has the given octet count (4 or 16)",
        slots=(Slot("FIELD", "IP_LIST_FIELD"),
               Slot("COUNT", "INT_LIT"),
               Slot("FIELD_LABEL", "FIELD_LABEL")),
        shape="compound",
        build=lambda s: dsl.parse(
            _A("IPListAllOctetCount", s["FIELD"], s["COUNT"])),
        statement="Every {FIELD_LABEL} MUST be exactly {COUNT} octets.",
    ),
    Template(
        id="T_oid_list_contains",
        handles="oid_list field contains the named OID constant",
        slots=(Slot("FIELD", "OID_LIST_FIELD"),
               Slot("OID_CONST", "OID_CONST"),
               Slot("FIELD_LABEL", "FIELD_LABEL")),
        shape="compound",
        build=lambda s: dsl.parse(
            _A("OidListContains", s["FIELD"], s["OID_CONST"])),
        statement="{FIELD_LABEL} MUST contain OID {OID_CONST}.",
    ),

    Template(
        id="T_date_before",
        handles="one date is strictly before another (DATE_FIELD or YYYY-MM-DD literal on either side)",
        slots=(Slot("EARLIER", "DATE_OR_LIT"),
               Slot("LATER",   "DATE_OR_LIT"),
               Slot("EARLIER_LABEL", "FIELD_LABEL"),
               Slot("LATER_LABEL",   "FIELD_LABEL")),
        shape="compound",
        build=lambda s: dsl.parse(_A("DateBefore", s["EARLIER"], s["LATER"])),
        statement="{EARLIER_LABEL} MUST be before {LATER_LABEL}.",
    ),
    Template(
        id="T_bytes_equals_hex",
        handles="a []byte cert field equals a specific hex literal byte-for-byte",
        slots=(Slot("FIELD", "BYTES_FIELD"),
               Slot("HEX",   "HEX_LIT"),
               Slot("FIELD_LABEL", "FIELD_LABEL")),
        shape="compound",
        build=lambda s: dsl.parse(_A("BytesEqualsHex", s["FIELD"], s["HEX"])),
        statement="{FIELD_LABEL} MUST equal hex {HEX}.",
    ),
    Template(
        id="T_bytes_contains_hex",
        handles="a []byte cert field contains a specific hex sub-sequence",
        slots=(Slot("FIELD", "BYTES_FIELD"),
               Slot("HEX",   "HEX_LIT"),
               Slot("FIELD_LABEL", "FIELD_LABEL")),
        shape="compound",
        build=lambda s: dsl.parse(_A("BytesContainsHex", s["FIELD"], s["HEX"])),
        statement="{FIELD_LABEL} MUST contain hex {HEX}.",
    ),
    Template(
        id="T_pubkey_algorithm",
        handles="public key algorithm equals one of the named algorithms",
        slots=(Slot("ALG", "PUBKEY_ALG"),
               Slot("FIELD_LABEL", "FIELD_LABEL")),
        shape="compound",
        build=lambda s: dsl.parse(_A("PublicKeyAlgorithmIs", s["ALG"])),
        statement="{FIELD_LABEL} (PublicKeyAlgorithm) MUST be {ALG}.",
    ),
    Template(
        id="T_dn_empty",
        handles="the entire Subject or Issuer DN is empty (an empty SEQUENCE)",
        slots=(Slot("HOLDER", "DN_HOLDER"),
               Slot("FIELD_LABEL", "FIELD_LABEL")),
        shape="compound",
        build=lambda s: dsl.parse(_A("DNEmpty", s["HOLDER"])),
        statement="The {HOLDER} distinguished name MUST be empty.",
    ),

    Template(
        id="T_ext_raw_value_equals_hex",
        handles="extension's raw extnValue bytes equal a specific hex literal byte-for-byte (e.g. 'basicConstraints with cA=FALSE MUST be encoded as the empty SEQUENCE 3000')",
        slots=(Slot("OID_CONST", "OID_CONST"),
               Slot("HEX",       "HEX_LIT"),
               Slot("FIELD_LABEL", "FIELD_LABEL")),
        shape="compound",
        build=lambda s: dsl.parse(_A("ExtRawValueEqualsHex", s["OID_CONST"], s["HEX"])),
        statement="The raw extnValue of {FIELD_LABEL} MUST equal hex {HEX}.",
    ),
    Template(
        id="T_ext_raw_value_contains_hex",
        handles="extension's raw extnValue bytes contain a specific hex sub-sequence (e.g. NameConstraints permittedSubtrees MUST contain a zero IPv4 range)",
        slots=(Slot("OID_CONST", "OID_CONST"),
               Slot("HEX",       "HEX_LIT"),
               Slot("FIELD_LABEL", "FIELD_LABEL")),
        shape="compound",
        build=lambda s: dsl.parse(_A("ExtRawValueContainsHex", s["OID_CONST"], s["HEX"])),
        statement="The raw extnValue of {FIELD_LABEL} MUST contain hex {HEX}.",
    ),
    Template(
        id="T_oid_field_eq",
        handles="single OID-typed cert field MUST equal a named OID constant (e.g. PublicKeyAlgorithmOID == OidRSAEncryption, SignatureAlgorithmOID == OidSignatureSHA256WithRSAEncryption)",
        slots=(Slot("FIELD",     "OID_SCALAR_FIELD"),
               Slot("OID_CONST", "OID_CONST"),
               Slot("FIELD_LABEL", "FIELD_LABEL")),
        shape="compound",
        build=lambda s: dsl.parse(_A("OidEq", s["FIELD"], s["OID_CONST"])),
        statement="{FIELD_LABEL} MUST equal OID {OID_CONST}.",
    ),
    Template(
        id="T_subtree_ip_octet_count",
        handles="a NameConstraints IP subtree (PermittedIPAddresses / ExcludedIPAddresses) MUST include at least one entry of N octets — used for the BR rule 'IPv6 zero range MUST appear in excludedSubtrees as 32 zero octets', etc. count: 8 = IPv4 addr+mask, 32 = IPv6 addr+mask",
        slots=(Slot("FIELD",     "SUBTREE_IP_FIELD"),
               Slot("COUNT",     "INT_LIT"),
               Slot("FIELD_LABEL", "FIELD_LABEL")),
        shape="compound",
        build=lambda s: dsl.parse(_A("SubtreeIPListAnyHasOctetCount", s["FIELD"], s["COUNT"])),
        statement="The NameConstraints {FIELD_LABEL} MUST include an entry of {COUNT} octets (IP+mask).",
    ),
    Template(
        id="T_bytes_contains_oid_der",
        handles="a bytes-typed cert field MUST contain the DER encoding of a named OID (e.g. RawSubjectPublicKeyInfo MUST embed namedCurve secp384r1) — the renderer computes the DER bytes from the OID name; do NOT write hex literals",
        slots=(Slot("FIELD",     "BYTES_FIELD"),
               Slot("OID_CONST", "OID_CONST"),
               Slot("FIELD_LABEL", "FIELD_LABEL")),
        shape="compound",
        build=lambda s: dsl.parse(_A("BytesContainsOidDer", s["FIELD"], s["OID_CONST"])),
        statement="{FIELD_LABEL} MUST contain the DER encoding of OID {OID_CONST}.",
    ),
    Template(
        id="T_field_encoded_max_len",
        handles="string field MUST be encoded as one of N ASN.1 types AND length <= MAX_LEN — used for BR table rules like 'organizationName MUST use UTF8String or PrintableString, max 64 chars' (combines FieldEncodedAs + FieldLenInRange so the LLM cannot drop either clause)",
        slots=(Slot("FIELD",     "STRING_FIELD"),
               Slot("TYPES",     "ASN1_TYPE_LIST"),
               Slot("MAX_LEN",   "INT_LIT"),
               Slot("FIELD_LABEL", "FIELD_LABEL")),
        shape="compound",
        build=lambda s: dsl.parse({"op":"And","args":[
            _A("FieldEncodedAs", s["FIELD"], s["TYPES"]),
            _A("FieldLenInRange", s["FIELD"], 0, s["MAX_LEN"]),
        ]}),
        statement="{FIELD_LABEL} MUST be encoded as one of {TYPES} AND length <= {MAX_LEN}.",
    ),
]

CATALOG_BY_ID: dict[str, Template] = {t.id: t for t in CATALOG}


# ---------------------------------------------------------------------
# Self-test
# ---------------------------------------------------------------------

if __name__ == "__main__":
    print(f"templates: {len(CATALOG)}")
    for t in CATALOG:
        kinds = ", ".join(f"{s.name}:{s.kind}" for s in t.slots)
        print(f"  {t.id:30s} shape={t.shape:11s} slots: {kinds}")

    print("\n=== Test: T_ext_non_critical on AIA ===")
    t = CATALOG_BY_ID["T_ext_non_critical"]
    slots = {"OID_CONST": "AiaOID", "FIELD_LABEL": "Authority Information Access"}
    errs = fill_check(t, slots)
    print("fill_check errors:", errs)
    out = render_body(t, slots)
    print("imports:", sorted(out["imports"]))
    print("statement:", render_statement(t, slots))
    print("body:")
    print(out["execute_body"])

    print("\n=== Test: T_compound with And of FieldNonEmpty + ExtCritical ===")
    t = CATALOG_BY_ID["T_compound"]
    slots = {
        "REQUIREMENT": {
            "op": "And",
            "args": [
                {"op": "ExtPresent", "args": ["CertPolicyOID"]},
                {"op": "ExtCritical", "args": ["CertPolicyOID"]},
                {"op": "FieldNonEmpty", "args": ["Subject.Province"]},
            ],
        },
        "REQUIREMENT_LABEL": "policy ext critical and Province present",
    }
    print("fill_check:", fill_check(t, slots))
    out = render_body(t, slots)
    print("imports:", sorted(out["imports"]))
    print("body:")
    print(out["execute_body"])

    print("\n=== Test: T_keyusage_required = digitalSignature + keyEncipherment ===")
    t = CATALOG_BY_ID["T_keyusage_required"]
    slots = {"BITS": ["DigitalSignature", "KeyEncipherment"],
             "FIELD_LABEL": "TLS Server"}
    print("fill_check:", fill_check(t, slots))
    out = render_body(t, slots)
    print("body:")
    print(out["execute_body"])

    print("\n=== Test: T_dn_field_present on Subject.Province (the v8 R4664 win) ===")
    t = CATALOG_BY_ID["T_dn_field_present"]
    slots = {"DN_FIELD": "Subject.Province", "FIELD_LABEL": "stateOrProvinceName"}
    print("fill_check:", fill_check(t, slots))
    out = render_body(t, slots)
    print("body:")
    print(out["execute_body"])

    print("\n=== Test: bad slot value caught at fill_check ===")
    bad = {"DN_FIELD": "Subject.StateOrProvinceName",  # not in vocab
           "FIELD_LABEL": "stateOrProvinceName"}
    print("fill_check:", fill_check(t, bad))
