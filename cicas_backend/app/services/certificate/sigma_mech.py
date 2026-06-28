"""
Deterministic Mechanical Translation Operator σ_mech

Translates a DSL atom tree into a PKI natural-language summary.
Replaces the LLM-based σ by applying pre-defined phrase templates
recursively over the DSL tree structure.

Key property (from Paper §8.13):
  - Total function & determinism: same atom tree → same output
  - Polarity correctness: handles negation conditions via "WHEN NOT" template
  - Reversibility: DSL tree recoverable from σ_mech output at atom-equivalence level
"""
import json
import re
from typing import Dict, Any, Optional, List
from dataclasses import dataclass


# ================================================================
# Phrase Dictionary μ : Atom → NL
# Built from observed DB atoms + zlint community patterns
# ================================================================

# Field name normalization: internal DSL → human-readable
FIELD_DISPLAY_NAMES: Dict[str, str] = {
    "Subject.CommonName": "certificate subject common name",
    "Subject.Organization": "certificate subject organization",
    "Subject.OrganizationalUnit": "certificate subject organizational unit",
    "Subject.Country": "certificate subject country",
    "Subject.StateOrProvince": "certificate subject state or province",
    "Subject.Locality": "certificate subject locality",
    "Subject.SerialNumber": "certificate subject serial number",
    "Issuer.CommonName": "certificate issuer common name",
    "Issuer.Organization": "certificate issuer organization",
    "TBSCertificate.SerialNumber": "TBS certificate serial number",
    "TBSCertificate.Signature": "TBS certificate signature",
    "TBSCertificate.Validity.NotBefore": "certificate validity period start",
    "TBSCertificate.Validity.NotAfter": "certificate validity period end",
    "TBSCertificate.Subject": "TBS certificate subject",
    "TBSCertificate.Issuer": "TBS certificate issuer",
    "Extensions.BasicConstraints": "BasicConstraints extension",
    "Extensions.KeyUsage": "KeyUsage extension",
    "Extensions.ExtendedKeyUsage": "ExtendedKeyUsage extension",
    "Extensions.SubjectAlternativeName": "SubjectAlternativeName extension",
    "Extensions.AuthorityKeyIdentifier": "AuthorityKeyIdentifier extension",
    "Extensions.SubjectKeyIdentifier": "SubjectKeyIdentifier extension",
    "Extensions.CRLDistributionPoints": "CRLDistributionPoints extension",
    "Extensions.AuthorityInfoAccess": "AuthorityInfoAccess extension",
    "Extensions.NameConstraints": "NameConstraints extension",
    "Extensions.CertificatePolicies": "CertificatePolicies extension",
    "Extensions.PolicyConstraints": "PolicyConstraints extension",
    "Extensions.InhibitAnyPolicy": "InhibitAnyPolicy extension",
    "Extensions.IssuingDistributionPoint": "IssuingDistributionPoint extension",
    "Extensions.PrecertificatePoison": "PrecertificatePoison extension",
    "Extensions.OcspNoCheck": "OCSPNoCheck extension",
    # Short forms (from DB subjects)
    "CommonName": "certificate subject common name",
    "Organization": "certificate subject organization",
    "Country": "certificate subject country",
    "SerialNumber": "certificate serial number",
    "DNSNames": "subject alternative name DNS entries",
    "IPAddresses": "subject alternative name IP addresses",
    "EmailAddresses": "subject alternative name email addresses",
    "IssuingCertificateURL": "AIA CA Issuers URL",
    "OCSPResponder": "AIA OCSP responder URL",
    "AuthorityKeyIdentifier": "authority key identifier",
    "SubjectKeyIdentifier": "subject key identifier",
    "KeyUsage": "key usage extension",
    "BasicConstraints": "basic constraints extension",
    "ExtendedKeyUsage": "extended key usage extension",
    "SubjectAlternativeName": "subject alternative name extension",
    "NameConstraints": "name constraints extension",
    "AuthorityInfoAccess": "authority info access extension",
    "CertificatePolicies": "certificate policies extension",
    "CRLDistributionPoints": "CRL distribution points extension",
    "BasicConstraints.IsCA": "BasicConstraints cA field",
    "KeyUsage.DigitalSignature": "key usage digital signature bit",
    "KeyUsage.KeyCertSign": "key usage key cert sign bit",
    "KeyUsage.CRLSign": "key usage CRL sign bit",
    "KeyUsage.KeyEncipherment": "key usage key encipherment bit",
    "KeyUsage.DataEncipherment": "key usage data encipherment bit",
    "KeyUsage.KeyAgreement": "key usage key agreement bit",
    "KeyUsage.NonRepudiation": "key usage non-repudiation bit",
    "KeyUsage.EncipherOnly": "key usage encipher only bit",
    "KeyUsage.DecipherOnly": "key usage decipher only bit",
}


def _normalize_field(field: str) -> str:
    """Human-readable field name."""
    return FIELD_DISPLAY_NAMES.get(field, field.replace(".", " ").replace("_", " "))


# ================================================================
# Atom phrase templates
# ================================================================

def _sigma_ext_present(atom: Dict) -> str:
    oid = atom.get("oid", "")
    name = atom.get("extension_name", "")
    if name:
        return f"the {name} extension is present"
    if oid:
        return f"the extension with OID {oid} is present"
    return "a required extension is present"


def _sigma_ext_critical(atom: Dict) -> str:
    name = atom.get("extension_name", "")
    if name:
        return f"the {name} extension is present and marked critical"
    return "a required extension is present and marked critical"


def _sigma_ext_not_critical(atom: Dict) -> str:
    name = atom.get("extension_name", "")
    if name:
        return f"the {name} extension is present and NOT marked critical"
    return "a required extension is present and NOT marked critical"


def _sigma_field_nonempty(atom: Dict) -> str:
    field = _normalize_field(atom.get("field", ""))
    return f"{field} must be present and non-empty"


def _sigma_field_empty(atom: Dict) -> str:
    field = _normalize_field(atom.get("field", ""))
    return f"{field} must be absent or empty"


def _sigma_field_eq(atom: Dict) -> str:
    field = _normalize_field(atom.get("field", ""))
    value = atom.get("value", "")
    return f"{field} equals {value!r}"


def _sigma_field_matches_regex(atom: Dict) -> str:
    field = _normalize_field(atom.get("field", ""))
    pattern = atom.get("pattern_name", "") or atom.get("pattern", "")
    pattern_display = atom.get("display", pattern)
    return f"{field} matches the pattern {pattern_display}"


def _sigma_field_encoded_as(atom: Dict) -> str:
    field = _normalize_field(atom.get("field", ""))
    types = atom.get("types", [])
    if len(types) == 1:
        return f"{field} must be encoded as {types[0]}"
    return f"{field} must be encoded as one of {types}"


def _sigma_field_in_set(atom: Dict) -> str:
    field = _normalize_field(atom.get("field", ""))
    values = atom.get("values", [])
    if not values:
        return f"{field} is in the allowed value set"
    if len(values) <= 3:
        return f"{field} is one of [{', '.join(str(v) for v in values)}]"
    return f"{field} is in the allowed value set"


def _sigma_field_not_in_set(atom: Dict) -> str:
    field = _normalize_field(atom.get("field", ""))
    values = atom.get("values", [])
    if not values:
        return f"{field} must not be in the forbidden value set"
    if len(values) <= 3:
        return f"{field} is NOT one of [{', '.join(str(v) for v in values)}]"
    return f"{field} must not be in the forbidden value set"


def _sigma_field_numeric_in_range(atom: Dict) -> str:
    field = _normalize_field(atom.get("field", ""))
    lo = atom.get("min", atom.get("minimum", ""))
    hi = atom.get("max", atom.get("maximum", ""))
    if lo and hi:
        return f"{field} must be in the range [{lo}, {hi}]"
    elif lo:
        return f"{field} must be ≥ {lo}"
    elif hi:
        return f"{field} must be ≤ {hi}"
    return f"{field} must be within the required numeric range"


def _sigma_field_len_in_range(atom: Dict) -> str:
    field = _normalize_field(atom.get("field", ""))
    lo = atom.get("min", "")
    hi = atom.get("max", "")
    if lo and hi:
        return f"the length of {field} must be in the range [{lo}, {hi}]"
    return f"the length of {field} must be within the required range"


def _sigma_list_all_match(atom: Dict) -> str:
    list_field = _normalize_field(atom.get("list_field", ""))
    inner = atom.get("inner", {})
    inner_summary = sigma_mech(inner)
    return f"every entry of {list_field} satisfies ({inner_summary})"


def _sigma_list_any_match(atom: Dict) -> str:
    list_field = _normalize_field(atom.get("list_field", ""))
    inner = atom.get("inner", {})
    inner_summary = sigma_mech(inner)
    return f"at least one entry of {list_field} satisfies ({inner_summary})"


def _sigma_list_unique(atom: Dict) -> str:
    list_field = _normalize_field(atom.get("list_field", ""))
    return f"all entries in {list_field} must be unique (no duplicates)"


def _sigma_item_matches_regex(atom: Dict) -> str:
    pattern = atom.get("pattern_name", "") or atom.get("pattern", "")
    pattern_display = atom.get("display", pattern)
    return f"item matches the pattern {pattern_display}"


def _sigma_subtree_ip_list_any_has_octet_count(atom: Dict) -> str:
    list_field = _normalize_field(atom.get("list_field", ""))
    n = atom.get("octet_count", "")
    return f"NameConstraints IP subtree {list_field} contains an entry of {n} octets"


def _sigma_subtree_ip_list_any_has_octet_count_not_all_zero(atom: Dict) -> str:
    list_field = _normalize_field(atom.get("list_field", ""))
    n = atom.get("octet_count", "")
    return f"NameConstraints IP subtree {list_field} contains a non-zero entry of {n} octets"


def _sigma_subtree_string_list_all_match_or_empty(atom: Dict) -> str:
    list_field = _normalize_field(atom.get("list_field", ""))
    inner = atom.get("inner", {})
    inner_summary = sigma_mech(inner)
    return f"every entry of {list_field} matches ({inner_summary}) OR {list_field} is empty"


def _sigma_domain_component_ordered(atom: Dict) -> str:
    return "domain components must appear in reverse order (most specific first)"


def _sigma_scalar_in_list(atom: Dict) -> str:
    field = _normalize_field(atom.get("field", ""))
    list_name = atom.get("list_name", "")
    return f"{field} must be contained in {list_name}"


def _sigma_bytes_equals_hex(atom: Dict) -> str:
    field = _normalize_field(atom.get("field", ""))
    hex_val = atom.get("hex_value", "")
    return f"{field} must equal the bytes represented by {hex_val}"


def _sigma_oid_list_contains(atom: Dict) -> str:
    list_field = _normalize_field(atom.get("list_field", ""))
    oid = atom.get("oid", "")
    return f"{list_field} must contain the OID {oid}"


def _sigma_ext_has_key_purpose(atom: Dict) -> str:
    name = atom.get("extension_name", "ExtendedKeyUsage")
    purpose = atom.get("key_purpose", "")
    return f"the {name} extension contains the key purpose {purpose}"


# KeyUsage bit display names (Go uses "keyCertSign" → NL uses "keyCertSign / CA Cert Sign")
_KEY_USAGE_DISPLAY = {
    "DIGITALSIGNATURE": "digitalSignature",
    "CONTENTCOMMITMENT": "nonRepudiation / contentCommitment",
    "KEYENCIPHERMENT": "keyEncipherment",
    "DATAENCIPHERMENT": "dataEncipherment",
    "KEYAGREEMENT": "keyAgreement",
    "CERTSIGN": "keyCertSign / CA Cert Sign",
    "CRLSIGN": "cRLSign",
    "ENCIPHERONLY": "encipherOnly",
    "DECIPHERONLY": "decipherOnly",
}


def _sigma_key_usage_has(atom: Dict) -> str:
    """Handle KeyUsageHas: the key usage bit must be set."""
    bit = atom.get("bit", "")
    # Read meta.ku_bit for richer description (from Go Description enrichment)
    meta = atom.get("meta", {})
    ku_bit = meta.get("ku_bit", bit)
    display = _KEY_USAGE_DISPLAY.get(bit.upper(), ku_bit)
    return f"the key usage bit {display} must be set"


def _read_meta_condition(atom: Dict, inner_str: str) -> str:
    """If the atom has policy-condition meta, prepend the condition.

    Example: meta.policy_oid="2.23.140.1.2.1" + inner_str="Subject.Organization"
    → "When policy 2.23.140.1.2.1 (CA/B BR domain validated) is present,
        Subject.Organization MUST_NOT be present"
    """
    meta = atom.get("meta", {})
    if not meta:
        return inner_str

    policy_oid = meta.get("policy_oid")
    policy_name = meta.get("policy_name", "")
    policy_oblig = meta.get("policy_oblig", "")

    if policy_oid:
        condition = f"When certificate policy {policy_oid}"
        if policy_name:
            condition += f" ({policy_name})"
        condition += " is included: "
        return condition + inner_str

    return inner_str


# ================================================================
# Main σ_mech dispatcher
# ================================================================

SIGMA_ATOM_HANDLERS: Dict[str, callable] = {
    "ExtPresent": _sigma_ext_present,
    "ExtCritical": _sigma_ext_critical,
    "ExtNotCritical": _sigma_ext_not_critical,
    "ExtHasKeyPurpose": _sigma_ext_has_key_purpose,
    "KeyUsageHas": _sigma_key_usage_has,
    "FieldNonEmpty": _sigma_field_nonempty,
    "FieldEmpty": _sigma_field_empty,
    "FieldEncodedAs": _sigma_field_encoded_as,
    "FieldEq": _sigma_field_eq,
    "FieldMatchesRegex": _sigma_field_matches_regex,
    "FieldInSet": _sigma_field_in_set,
    "FieldNotInSet": _sigma_field_not_in_set,
    "FieldNumericInRange": _sigma_field_numeric_in_range,
    "FieldLenInRange": _sigma_field_len_in_range,
    "ListAllMatch": _sigma_list_all_match,
    "ListAnyMatch": _sigma_list_any_match,
    "ListUnique": _sigma_list_unique,
    "ItemMatchesRegex": _sigma_item_matches_regex,
    "SubtreeIPListAnyHasOctetCount": _sigma_subtree_ip_list_any_has_octet_count,
    "SubtreeIPListAnyHasOctetCountAndNotAllZero": _sigma_subtree_ip_list_any_has_octet_count_not_all_zero,
    "SubtreeStringListAllMatchOrEmpty": _sigma_subtree_string_list_all_match_or_empty,
    "DomainComponentOrdered": _sigma_domain_component_ordered,
    "ScalarInList": _sigma_scalar_in_list,
    "BytesEqualsHex": _sigma_bytes_equals_hex,
    "OidListContains": _sigma_oid_list_contains,
}


def sigma_mech(atom: Any) -> str:
    """
    Deterministic mechanical translation: DSL atom tree → NL summary.

    Recursive rules (from Paper §8.13):
      - Atomic: μ(a) from handler table
      - Negation: μ(Not(t)) = "NOT (μ(t))"
      - Conjunction: μ(And(t1, t2)) = "(μ(t1)) AND (μ(t2))"
      - Disjunction: μ(Or(t1, t2)) = "(μ(t1)) OR (μ(t2))"
      - Conditional binary (pre, pred): special "WHEN NOT" template
    """
    if atom is None:
        return "(unknown condition)"

    # Handle string (raw atom JSON)
    if isinstance(atom, str):
        try:
            atom = json.loads(atom)
        except json.JSONDecodeError:
            return atom

    # Handle list (top-level: e.g., from DB constraint_value JSON array)
    if isinstance(atom, list):
        if len(atom) == 1:
            return sigma_mech(atom[0])
        parts = [sigma_mech(a) for a in atom]
        return f"({' AND '.join(parts)})"

    # Handle dict
    if isinstance(atom, dict):
        op = atom.get("op", "")

        # ── Combinators ────────────────────────────────────────────
        # Handle n-ary And/Or (DSL uses "parts" list) FIRST
        if op in ("And", "Or") and "parts" in atom:
            parts_strs = [sigma_mech(p) for p in atom["parts"]]
            connector = " AND " if op == "And" else " OR "
            combined = f"({connector.join(parts_strs)})"
            return _read_meta_condition(atom, combined)

        # Handle binary And/Or (legacy format with left/right or t1/t2)
        if op == "And":
            t1 = sigma_mech(atom.get("left", atom.get("t1", {})))
            t2 = sigma_mech(atom.get("right", atom.get("t2", {})))
            return _read_meta_condition(atom, f"({t1}) AND ({t2})")

        if op == "Or":
            t1 = sigma_mech(atom.get("left", atom.get("t1", {})))
            t2 = sigma_mech(atom.get("right", atom.get("t2", {})))
            return _read_meta_condition(atom, f"({t1}) OR ({t2})")

        if op == "Not":
            inner = sigma_mech(atom.get("inner", atom.get("t", {})))
            return _read_meta_condition(atom, f"NOT ({inner})")

        # ── Conditional binary (pre, pred) ─────────────────────────
        if op == "WhenNot":
            pre = atom.get("pre", {})
            pred = sigma_mech(atom.get("pred", {}))
            pre_inner = pre.get("inner", {}) if isinstance(pre, dict) else {}
            pre_inner_str = sigma_mech(pre_inner)
            return f"WHEN NOT ({pre_inner_str}), THEN {pred}"

        if op == "When":
            pre = sigma_mech(atom.get("pre", {}))
            pred = sigma_mech(atom.get("pred", {}))
            return f"WHEN ({pre}), THEN {pred}"

        # ── Atomic lints (delegated to handler table) ───────────────
        if op in SIGMA_ATOM_HANDLERS:
            try:
                return SIGMA_ATOM_HANDLERS[op](atom)
            except Exception as e:
                return f"[σ_mech error on {op}: {e}]"

        # Fallback: unrecognized op
        return f"[unrecognized atom: {op}]"

    return f"[non-dict non-string atom: {type(atom).__name__}]"


# ================================================================
# High-level API: compare σ_mech output with Go Description
# ================================================================

def sigma_mech_from_json_str(json_str: str) -> str:
    """Convenience wrapper: parses JSON string then translates."""
    try:
        atom = json.loads(json_str)
        return sigma_mech(atom)
    except json.JSONDecodeError as e:
        return f"[parse error: {e}]"


@dataclass
class SigmaComparison:
    """Result of comparing σ_mech(summary) against a reference description."""
    sigma_output: str = ""
    reference_description: str = ""
    direct_similarity: float = 0.0  # difflib ratio
    sigma_output_tokens: int = 0
    reference_tokens: int = 0
    handler_covered: bool = False  # all atoms had handlers


def compare_sigma_to_description(
    dsl_atom_json: str,
    reference_description: str,
) -> SigmaComparison:
    """
    Compare σ_mech(atom) against a reference Go Description string.

    Returns similarity metrics + whether all atoms were covered.
    """
    import difflib

    sigma_output = sigma_mech_from_json_str(dsl_atom_json)
    handler_covered = "[unrecognized atom:" not in sigma_output

    norm_sigma = " ".join(sigma_output.lower().split())
    norm_ref = " ".join((reference_description or "").lower().split())

    similarity = difflib.SequenceMatcher(None, norm_sigma, norm_ref).ratio()

    return SigmaComparison(
        sigma_output=sigma_output,
        reference_description=reference_description,
        direct_similarity=similarity,
        sigma_output_tokens=len(sigma_output.split()),
        reference_tokens=len((reference_description or "").split()),
        handler_covered=handler_covered,
    )


# ================================================================
# Extended atom handlers (discovered from DB scan)
# ================================================================

def _sigma_field_in_set_extended(atom: Dict) -> str:
    field = _normalize_field(atom.get("field", ""))
    values = atom.get("values", [])
    if not values:
        return f"{field} is in the allowed set"
    vstr = ", ".join(str(v) for v in values[:5])
    return f"{field} is one of [{vstr}]"


def _sigma_eku_syn_oid(atom: Dict) -> str:
    """EKU OID check - from DB: e_ca_invalid_eku"""
    oids = atom.get("oids", atom.get("values", []))
    if oids:
        return f"EKU contains one of {oids}"
    return "EKU contains a forbidden OID"


def _sigma_basicconstraints_isc_a(atom: Dict) -> str:
    """From DB: e_ca_is_ca"""
    return "BasicConstraints cA field must be TRUE"


def _sigma_cert_policy_oid_in_set(atom: Dict) -> str:
    """From DB: e_ca_multiple_reserved_policy_oids"""
    return "certificate policy OID must be within the allowed set"


# Extend handlers
SIGMA_ATOM_HANDLERS.update({
    "FieldInSet": _sigma_field_in_set_extended,
    "EkuSynOid": _sigma_eku_syn_oid,
    "BasicConstraints.IsCA": _sigma_basicconstraints_isc_a,
    "CertPolicyOID": _sigma_cert_policy_oid_in_set,
    # Unrecognized from DB scan:
    "ItemNotMatchesRegex": lambda a: f"item does NOT match the pattern {a.get('pattern_name', a.get('pattern', ''))}",
    "ItemMatchesRegex": lambda a: f"item matches the pattern {a.get('pattern_name', a.get('pattern', ''))}",
})


# ================================================================
# Interactive comparison script
# ================================================================

def compare_sigma_vs_go(
    lint_name: str,
    dsl_atom_json: str,
    go_description: str,
) -> dict:
    """
    Full comparison: σ_mech(dsl_atom) vs Go Description.
    
    Returns dict with:
      - sigma_output: deterministic NL from DSL atom
      - go_description: authoritative from Go source  
      - raw_similarity: difflib ratio
      - token_counts: for both
      - mismatches: tokens in sigma not in Go
      - coverage: fraction of Go words covered by sigma
    """
    import difflib
    
    sigma_out = sigma_mech_from_json_str(dsl_atom_json)
    
    norm_sigma = sigma_out.lower()
    norm_go = go_description.lower()
    
    # Token-level coverage
    sigma_tokens = set(re.findall(r'\w+', norm_sigma))
    go_tokens = set(re.findall(r'\w+', norm_go))
    
    # Remove stopwords
    stopwords = {'the', 'a', 'an', 'is', 'are', 'of', 'to', 'and', 'or', 'in', 'that', 'must', 'be'}
    sigma_toks = sigma_tokens - stopwords
    go_toks = go_tokens - stopwords
    
    coverage = len(sigma_toks & go_toks) / len(go_toks) if go_toks else 0
    
    raw_sim = difflib.SequenceMatcher(None, norm_sigma, norm_go).ratio()
    
    return {
        'sigma_output': sigma_out,
        'go_description': go_description,
        'raw_similarity': raw_sim,
        'token_coverage': coverage,
        'sigma_tokens': len(sigma_toks),
        'go_tokens': len(go_toks),
        'sigma_overlap': len(sigma_toks & go_toks),
    }


if __name__ == "__main__":
    """CLI: python -m app.services.certificate.sigma_mech <lint_name>"""
    import sys, psycopg2, os, pathlib, re
    os.environ.setdefault('DATABASE_URL', 'postgresql://postgres:123456@localhost:15432/cicas')
    
    if len(sys.argv) < 2:
        print("Usage: python -m app.services.certificate.sigma_mech <lint_name>")
        sys.exit(1)
    
    lint_name = sys.argv[1]
    
    conn = psycopg2.connect(os.getenv('DATABASE_URL'))
    conn.autocommit = True
    cur = conn.cursor()
    
    cur.execute("""
        SELECT dsl_atom::text 
        FROM zlint_lint_dsl 
        WHERE lint_name = %s AND source = 'CABF-BR'
    """, (lint_name,))
    row = cur.fetchone()
    conn.close()
    
    if not row:
        print(f"Lint {lint_name} not found in DB")
        sys.exit(1)
    
    dsl_json = row[0]
    sigma_out = sigma_mech_from_json_str(dsl_json)
    
    # Read Go source
    zlint_dir = pathlib.Path("/home/bernhard/projects/cicas/cicas_backend/zlint/v3/lints/cabf_br")
    go_name = lint_name[2:] if lint_name.startswith("e_") else lint_name
    go_file = zlint_dir / f"lint_{go_name}.go"
    
    go_desc = ""
    if go_file.exists():
        content = go_file.read_text()
        m = re.search(r'Description:\s*"([^"]*)"', content, re.DOTALL)
        go_desc = m.group(1).strip() if m else "(no description)"
    
    print(f"=== σ_mech Analysis: {lint_name} ===")
    print(f"\nσ_mech output:")
    print(f"  {sigma_out}")
    print(f"\nGo Description:")
    print(f"  {go_desc}")
    
    result = compare_sigma_vs_go(lint_name, dsl_json, go_desc)
    print(f"\nMetrics:")
    print(f"  Raw similarity: {result['raw_similarity']:.3f}")
    print(f"  Token coverage:  {result['token_coverage']:.3f} ({result['sigma_overlap']}/{result['go_tokens']} go tokens)")
