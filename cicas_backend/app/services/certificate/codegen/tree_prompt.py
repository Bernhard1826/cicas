"""templates_v2 / tree_prompt.py — tree-codegen prompt builder.

The LLM's job: read a normative rule and emit a JSON object with a DSL
predicate tree (plus optional precondition tree). No template selection —
the renderer composes the body from the tree directly. This eliminates
the "LLM picks T_field_encoded_as and silently drops length" failure.

Schema:
  {
    "predicate":    <DSL tree>,                        // required
    "precondition": <DSL tree> | null,                 // null if rule has no if/when
    "severity":     "lint.Error"|"lint.Warn"|"lint.Notice",
    "label":        "<one-line human label, English>"
  }
or
  {"no_template": true, "reason": "<one short sentence>"}

A DSL tree is recursive JSON of the form
  Atom : {"op": "<atom name>", "args": [<scalar args...>]}
  Compound : {"op": "And"|"Or"|"Not", "args": [<tree>, ...]}
"""
from __future__ import annotations

from . import dsl, vocab as V


# ---------------------------------------------------------------------
# Vocab block (reused / simplified vs catalog version)
# ---------------------------------------------------------------------

def vocab_block() -> str:
    L = []

    L.append("# CERT_FIELDS (use as field arg in atoms):")
    L.append("  " + ", ".join(f.name for f in V.CERT_FIELDS))

    L.append("")
    L.append("# DN_FIELDS (use as field arg in atoms):")
    sub = [f.name for f in V.DN_FIELDS if f.name.startswith("Subject.")]
    iss = [f.name for f in V.DN_FIELDS if f.name.startswith("Issuer.")]
    L.append("  Subject: " + ", ".join(s.split(".",1)[1] for s in sub))
    L.append("  Issuer:  " + ", ".join(s.split(".",1)[1] for s in iss))

    L.append("")
    L.append("# RDN attribute -> DN_FIELD mapping (CRITICAL):")
    for rdn, go in V.RDN_TO_DN_NAME.items():
        L.append(f"  {rdn:35s} -> Subject.{go}  (or Issuer.{go})")

    L.append("")
    L.append("# DATE_FIELDS:  " + ", ".join(f.name for f in V.DATE_FIELDS))

    L.append("")
    L.append("# KEY_USAGE_BITS: " + ", ".join(f.name for f in V.KEY_USAGE_BITS))
    L.append("# KU aliases (rule -> bit):")
    L.append("#   nonRepudiation -> ContentCommitment   keyCertSign -> CertSign   cRLSign -> CRLSign")

    L.append("")
    L.append("# EKU_BITS: " + ", ".join(f.name for f in V.EKU_BITS))

    L.append("")
    L.append("# ASN1_TYPES: " + ", ".join(f.name for f in V.ASN1_TYPES))

    L.append("")
    L.append("# NAMED_REGEXES (for ItemMatchesRegex / FieldMatchesRegex regex arg):")
    L.append("# Free-form regex literals are FORBIDDEN; pick a name from below or no_template.")
    for name, (pat, desc) in V.NAMED_REGEXES.items():
        L.append(f"  {name:24s} -- {desc}")

    L.append("")
    L.append(f"# OID_CONSTS ({len(V.OID_CONSTS)} total — names of asn1.ObjectIdentifier values):")
    cols = 4
    names = sorted(f.name for f in V.OID_CONSTS)
    for i in range(0, len(names), cols):
        L.append("  " + "  ".join(f"{n:32s}" for n in names[i:i+cols]).rstrip())

    L.append("")
    L.append("# EC NAMED CURVE OIDs (RFC 5480) — DO NOT MIX UP:")
    L.append("#   P-256 / prime256v1 / secp256r1  -> OidEcCurveP256")
    L.append("#   P-384 / secp384r1               -> OidEcCurveP384")
    L.append("#   P-521 / secp521r1               -> OidEcCurveP521")
    L.append("# The algorithm OID for ECC keys is OidEcPublicKey (NOT a curve).")
    return "\n".join(L)


def dsl_block() -> str:
    return dsl.schema_for_llm()


# ---------------------------------------------------------------------
# Output schema + few-shot
# ---------------------------------------------------------------------

OUTPUT_SCHEMA = """\
Output schema (one JSON object on its own, after the ANALYSIS line):

  {
    "predicate":    <Tree>,                  // required, encodes the rule's MUST clause
    "precondition": <Tree> | null,           // null unless rule has if/when/applies-to clause
    "severity":     "lint.Error" | "lint.Warn" | "lint.Notice",
    "label":        "<one-line English label>"
  }

or, if the rule cannot be expressed via the DSL atoms:

  {"no_template": true, "reason": "<one short sentence>"}

A <Tree> is recursively:
  Atom    : {"op": "<atom_name>", "args": [<scalar args...>]}    // see DSL ATOMS list
  Compound: {"op": "And"|"Or"|"Not", "args": [<Tree>, ...]}      // logical composition
  ListIter (only places where Item* atoms are valid):
            {"op": "ListAllMatch"|"ListAnyMatch", "args": [<list_field>, <Tree>]}

Severity rule (auto-assignable from rule level):
  MUST / MUST NOT / SHALL / SHALL NOT / REQUIRED          -> "lint.Error"
  SHOULD / SHOULD NOT / RECOMMENDED / NOT RECOMMENDED     -> "lint.Warn"
  MAY / OPTIONAL                                          -> "lint.Notice"
"""


FEW_SHOT_EXAMPLES = [
    {
        "rule": "An issuing CA is required to emit this extension with its criticality flag set to FALSE. (paraphrased example — extension non-criticality)",
        "answer": {
            "predicate":    {"op": "ExtNotCritical", "args": ["AiaOID"]},
            "precondition": {"op": "ExtPresent",    "args": ["AiaOID"]},
            "severity":     "lint.Error",
            "label":        "AIA extension, when present, MUST be non-critical",
        },
    },
    {
        "rule": "Root CA Certificates MUST NOT include organizationalUnitName in the subject. (CABF-BR §3.2.2.2)",
        "answer": {
            "predicate":    {"op": "Not", "args": [{"op": "FieldNonEmpty", "args": ["Subject.OrganizationalUnit"]}]},
            "precondition": {"op": "IsRootCA", "args": []},
            "severity":     "lint.Error",
            "label":        "Root CA Subject MUST NOT contain organizationalUnitName",
        },
    },
    {
        "rule": "organizationName MUST be encoded as UTF8String or PrintableString and MUST NOT exceed 64 characters.",
        "answer": {
            "predicate": {"op": "And", "args": [
                {"op": "FieldEncodedAs",
                 "args": ["Subject.Organization", ["UTF8String", "PrintableString"]]},
                {"op": "FieldLenInRange",
                 "args": ["Subject.Organization", 0, 64]},
            ]},
            "precondition": None,
            "severity":     "lint.Error",
            "label":        "Subject.Organization MUST be UTF8|Printable AND length <=64",
        },
    },
    {
        "rule": "Whenever such identities are to be bound into a certificate, the subject alternative name (or issuer alternative name) extension MUST be used.",
        "answer": {
            "predicate": {"op": "Or", "args": [
                {"op": "ExtPresent", "args": ["SubjectAlternateNameOID"]},
                {"op": "ExtPresent", "args": ["IssuerAlternateNameOID"]},
            ]},
            "precondition": None,
            "severity":     "lint.Error",
            "label":        "SAN OR IAN extension MUST be present",
        },
    },
    {
        "rule": "When the basicConstraints extension is present and the value of cA is FALSE, the extension value MUST be encoded as the empty SEQUENCE.",
        "answer": {
            "predicate":    {"op": "ExtRawValueEqualsHex",
                             "args": ["BasicConstOID", "3000"]},
            "precondition": {"op": "And", "args": [
                {"op": "ExtPresent",   "args": ["BasicConstOID"]},
                {"op": "FieldEmpty",   "args": ["IsCA"]},
            ]},
            "severity":     "lint.Error",
            "label":        "if BasicConstraints present and cA=FALSE, raw extnValue MUST be 0x3000",
        },
    },
    {
        "rule": "When the UTF8String encoding is used, all character sequences SHOULD be normalized according to Unicode normalization form C (NFC).",
        "answer": {
            "no_template": True,
            "reason": "NFC normalization requires golang.org/x/text/unicode/norm; not expressible with the available DSL atoms or named regexes.",
        },
    },
    {
        "rule": "CN MUST NOT contain the '@' character. (RFC 4519 forbids '@' in PrintableString CN.)",
        "answer": {
            "predicate":    {"op": "Not", "args": [{"op": "FieldContains", "args": ["Subject.CommonName", "@"]}]},
            "precondition": None,
            "severity":     "lint.Error",
            "label":        "CN MUST NOT contain '@'",
        },
    },
    {
        "rule": "Email address field MUST NOT contain underscore '_' character.",
        "answer": {
            "predicate":    {"op": "Not", "args": [{"op": "FieldContains", "args": ["Subject.CommonName", "_"]}]},
            "precondition": None,
            "severity":     "lint.Error",
            "label":        "CN MUST NOT contain '_'",
        },
    },
    {
        # SHOULD example — counters the all-MUST / all-Error example bias above.
        # The modal verb is SHOULD, so severity is lint.Warn (NOT lint.Error).
        # Copy the severity from the rule's modal verb, never default to Error.
        "rule": "In a conforming CA certificate the issuerUniqueID field SHOULD NOT be populated. (paraphrased example — modal verb SHOULD ⇒ lint.Warn)",
        "answer": {
            "predicate":    {"op": "Not", "args": [{"op": "FieldNonEmpty", "args": ["IssuerUniqueId"]}]},
            "precondition": None,
            "severity":     "lint.Warn",
            "label":        "issuerUniqueID SHOULD NOT be present (recommendation ⇒ Warn)",
        },
    },
]


def few_shot_block() -> str:
    import json as _json
    L = ["# WORKED EXAMPLES"]
    for i, ex in enumerate(FEW_SHOT_EXAMPLES, 1):
        L.append(f"\nExample {i}.")
        L.append(f"  RULE: {ex['rule']}")
        L.append("  ANSWER:")
        for ln in _json.dumps(ex["answer"], indent=2, ensure_ascii=False).splitlines():
            L.append(f"    {ln}")
    return "\n".join(L)


# ---------------------------------------------------------------------
# Hard rules
# ---------------------------------------------------------------------

HARD_RULES = """\
HARD RULES (MUST follow):
 1. After the required "ANALYSIS:" line, output exactly ONE JSON object.
    No OTHER prose, no markdown fences. (The ANALYSIS: line is expected and
    does NOT count as "prose around the JSON" — it is required.) The JSON has
    either {predicate, precondition, severity, label} OR
    {no_template, reason} — nothing else. NEVER emit {no_template} merely
    because of an output-format concern; only use it when the rule's MEANING
    genuinely cannot be built from the vocabulary.
 2. ALWAYS include "predicate" — it carries the MUST/SHALL clause. If the
    rule has no precondition (no "if/when/applies to" clause), set
    "precondition": null. Do NOT omit either key.
 3. Every atom-name and atom-arg MUST come from the closed vocabulary
    (DSL ATOMS / CERT_FIELDS / DN_FIELDS / OID_CONSTS / KEY_USAGE_BITS /
    EKU_BITS / ASN1_TYPES / NAMED_REGEXES / DATE_FIELDS). Inventing names
    or writing free-form regex is rejected by the validator.
 4. RDN names from rule text -> DN_FIELD lookup is non-negotiable. e.g.
    stateOrProvinceName -> Subject.Province (NOT Subject.StateOrProvinceName).
 5. Compound predicates: capture EVERY clause. If the rule says
    "X MUST be encoded as Y AND length <= N", emit
    {"op":"And","args":[FieldEncodedAs(...,[Y]), FieldLenInRange(...,0,N)]} —
    do NOT drop the length conjunct.
 6. Bool-typed fields (IsCA, SelfSigned, IsRootCA-via-flat-IsCA, etc.):
    use FieldNonEmpty for "true", FieldEmpty for "false". Never FieldEq.
 7. Direction matters: encode predicate so it is true exactly when the
    rule is COMPLIED with. "X MUST be present" -> FieldNonEmpty(X);
    "X MUST NOT be present" -> Not(FieldNonEmpty(X)) or FieldEmpty(X).
 8. SHOULD / RECOMMENDED -> severity "lint.Warn". MUST -> "lint.Error".
    MAY -> "lint.Notice". Do NOT use Error for SHOULD/RECOMMENDED rules.
 9. AIA caIssuers / OCSP — zcrypto pre-flattens AIA into:
       c.IssuingCertificateURL  (caIssuers URI list)
       c.OCSPServer             (OCSP URI list)
    "AIA contains caIssuers" -> FieldNonEmpty(IssuingCertificateURL)
    "AIA URI is HTTP/LDAP"   -> ListAnyMatch(IssuingCertificateURL,
                                  ItemMatchesRegex(Re_HttpOrLdapUrl))
    For per-method-OID inspection beyond caIssuers/OCSP, AND for SIA
    (id-ad-caRepository / id-ad-timeStamping / etc.), use the
    AccessDescription atom family — it raw-parses the extension and
    handles BOTH AIA and SIA via the ext_oid parameter:
       AIAHasMethodOtherThan(<EXT_OID_CONST>, [<METHOD_OID_CONST>, ...])
       AIAMethodLocationsTagInSet(<EXT_OID_CONST>, <METHOD_OID_CONST>,
                                   [<asn1_tag>, ...])
       AIAMethodLocationsAnyMatchRegex(<EXT_OID_CONST>, <METHOD_OID_CONST>,
                                        <NAMED_REGEX>)
    EXT_OID is AiaOID for AIA-shaped, SubjectInfoAccessOID for SIA.
    Method-OID consts: OidIdAdCaIssuers, OidIdAdOcsp, OidIdAdCaRepository,
    OidIdAdTimeStamping. Do NOT call SIA-specific rules no_template.
10. EC named curves (RFC 5480) — three OID consts only:
       P-256 / prime256v1 / secp256r1 -> OidEcCurveP256
       P-384 / secp384r1              -> OidEcCurveP384
       P-521 / secp521r1              -> OidEcCurveP521
    For "namedCurve MUST be P-X", use BytesContainsOidDer on
    RawSubjectPublicKeyInfo with the curve OID. NEVER pick Microsoft CA
    OIDs, Ed25519/Ed448 unless the rule literally mentions them.
11. ASN.1 tag check on validity dates (UTCTime vs GeneralizedTime) IS
    expressible via:
       ValidityDateAsn1TagInSet(<NotBefore|NotAfter>, [<ASN1_TYPE>, ...])
    Reads the original DER tag from c.RawTBSCertificate (zcrypto exposes
    only the parsed time.Time, losing the tag). Only UTCTime and
    GeneralizedTime are semantically valid. For "dates in 2050+ MUST be
    GeneralizedTime", combine with DateBefore as a precondition / branch.
    Do NOT call this no_template.
12. NFC normalization is NOT expressible — choose no_template.
13. CRL DP nameRelativeToCRLIssuer / DistributionPointName CHOICE
    inspection IS expressible via:
       CRLDPHasNameRelative()                       (zero-arg)
       CRLDPHasNameRelativeWithMultiIssuer()        (zero-arg)
    Both raw-parse the CRL Distribution Points extension because
    zcrypto's c.CRLDistributionPoints flattens to fullName URIs only.
    "MUST/SHOULD NOT use nameRelativeToCRLIssuer" ->
       Not(CRLDPHasNameRelative())
    "MUST NOT use nameRelativeToCRLIssuer when cRLIssuer has >1 DN" ->
       Not(CRLDPHasNameRelativeWithMultiIssuer())
    Do NOT call this no_template.
14. SIA (SubjectInfoAccess) — the EXTENSION OID itself IS available as
    SubjectInfoAccessOID in OID_CONSTS. Use it for presence / criticality
    rules: e.g. "SIA SHOULD be non-critical" -> precondition
    ExtPresent(SubjectInfoAccessOID), predicate ExtNotCritical(SubjectInfoAccessOID).
    Only the per-AccessDescription accessMethod / accessLocation sub-fields
    are NOT exposed — those still need no_template.
15. AuthorityKeyIdentifier keyIdentifier sub-field IS exposed: the field
    c.AuthorityKeyId ([]byte) holds the keyIdentifier value. So "AKI
    keyIdentifier MUST be present" -> FieldNonEmpty(AuthorityKeyId). Do
    NOT call this no_template.
16. SerialNumber non-negative ("MUST be a positive integer" / "MUST NOT
    be negative") IS expressible: FieldNumericInRange(SerialNumber, 0,
    MAX_INT) renders to a big.Int Cmp >= 0 check. Do NOT call this
    no_template just because it sounds like a sign-bit check.
17. iPAddresses field mixes IPv4 (4 octets) and IPv6 (16 octets). For
    rules like "each iPAddress MUST be IPv4 (4 octets) or IPv6 (16
    octets)" (BOTH versions constrained), use IPListAllOctetCountIn
    (IPAddresses, [4, 16]). When the rule (or atomic_text) constrains
    ONLY ONE version (e.g. atomic says only "IPv6 MUST be 16 octets"
    with no parallel IPv4 clause), do NOT use IPListAllOctetCountIn
    [4,16] — the judge will see it as also checking IPv4 which the
    atomic does not say. Instead use the asymmetric form with the
    self-tautology pattern on the unconstrained branch:
       IPv4Conditional(IPAddresses, ItemLenIn([4]), ItemLenIn([16]))
    for IPv6-only-constrained (the IPv4 branch ItemLenIn([4]) is a
    self-tautology since net.IP guarantees IPv4 entries are 4 bytes),
    or
       IPv4Conditional(IPAddresses, ItemLenIn([4]), ItemLenIn([16]))
    with the IPv6 ItemLenIn being the self-tautology for IPv4-only-
    constrained — see rule 27.
18. NameConstraints "MUST include iPAddress of N zero octets" markers
    (CABF-BR for permittedSubtrees marker entries). The rule semantics
    is "permittedSubtrees MUST contain a real IPvN entry OR the all-zero
    marker entry" — the marker is only required when there is no real
    entry. Express as a closed Or over two complementary atoms:
       IPv4 0.0.0.0/0 marker rule (R4632) ->
         Or(SubtreeIPListAnyHasOctetCountAndNotAllZero(<field>, 8),
            SubtreeIPListAnyAllZero(<field>, 8))
       IPv6 ::0/0 marker rule (R4633) ->
         Or(SubtreeIPListAnyHasOctetCountAndNotAllZero(<field>, 32),
            SubtreeIPListAnyAllZero(<field>, 32))
    Do NOT use SubtreeIPListAnyHasOctetCount alone (length only, not
    all-zero pattern). Do NOT use SubtreeIPListAnyAllZero alone (over-
    strict — forces marker even when a real entry is present). Do NOT
    use Or(HasOctetCount, AllZero) — HasOctetCount subsumes AllZero so
    the all-zero requirement collapses. The HasOctetCountAndNotAllZero
    atom is the "real entry" counterpart of AllZero; together they
    cover the rule's full semantics.
19. URI strict-scheme rules: when the rule cites RFC 2616 (HTTP) and
    RFC 4516 (LDAP) without TLS variants, use Re_HttpOrLdapStrict
    (matches http:// or ldap:// only, NOT https / ldaps). Re_HttpOrLdapUrl
    is the lenient form that includes https / ldaps. Do NOT call this
    rule no_template just because Re_HttpOrLdapUrl is too lenient.
19a. LDAP URL with dn + single attrdesc rules (R4397: "MUST include a
    <dn> field AND a single <attrdesc>"): use the COMBINED regex
       Re_LdapUrlWithDnAndSingleAttrdesc
    inside an OR-guard so non-LDAP entries pass freely:
       ListAllMatch(CRLDistributionPoints, Or(
           ItemNotMatchesRegex(Re_LdapUrl),                       # not LDAP -> pass
           ItemMatchesRegex(Re_LdapUrlWithDnAndSingleAttrdesc)))  # LDAP -> dn+single attrdesc
    Do NOT use Re_LdapUrlWithDn AND Re_LdapUrlWithAttrs separately —
    those check presence of "dn=" and "attributes=" query keys but the
    rule per RFC 4516 §2.5.1 grammar is positional: ldap://host/<dn>?<attrs>
    where <attrs> is comma-separated and "single attrdesc" means no comma.
    The combined regex enforces non-empty <dn> path component AND a
    single (no-comma) attrdesc.
20. "valid URI per RFC 3986" full-syntax check: use Re_Rfc3986Uri
    (validates scheme + optional authority/path/query/fragment + no
    whitespace). Re_AnyUri only checks the scheme prefix — too loose
    for full RFC 3986 conformance.
21. NameConstraints subtree string iteration ("permitted/excluded
    subtree entries MUST satisfy <regex/set>"):
       SubtreeStringListAllMatch(<subtree_string_list>, <Item* predicate>)
       SubtreeStringListAnyMatch(<subtree_string_list>, <Item* predicate>)
    Use these when the rule constrains every (or any) entry in
    PermittedDNSNames / ExcludedDNSNames / PermittedURIs / etc. The
    item variable inside the predicate is the .Data string of each
    GeneralSubtreeString. Item* atoms (ItemMatchesRegex, ItemEq,
    ItemInSet) are valid here — same rules as ListAllMatch on flat
    string lists. Do NOT call this no_template just because the field
    is a subtree_list type.
22. NameConstraints subtree IP "every entry is IPv4 or IPv6" rules:
       SubtreeIPListAllOctetCountIn(<subtree_ip_list>, [8, 32])
    Each entry has total bytes (IP + Mask) of 8 (IPv4 + 4-byte mask)
    or 32 (IPv6 + 16-byte mask). Use [32] alone for "all entries are
    IPv6 (32 octets)" / [8] for "all IPv4". Distinct from
    SubtreeIPListAnyAllZero (which checks all-zero byte content) and
    SubtreeIPListAnyHasOctetCount (which only requires AT LEAST ONE
    entry of given count).
    ASYMMETRIC variant — when the rule's atomic_text constrains ONLY
    ONE subtree-IP version (e.g. atomic only says "IPv6 NameConstraints
    iPAddress MUST contain 32 octets" with no parallel IPv4 clause),
    use SubtreeIPv4Conditional with ItemLenIn on each branch — the
    branch matching the unconstrained version uses the canonical size
    as a self-tautology:
       SubtreeIPv4Conditional(PermittedIPAddresses,
           ItemLenIn([8]),     # IPv4 subtree: total 8 bytes (canonical)
           ItemLenIn([32]))    # IPv6 subtree: total 32 bytes (canonical)
    Item byte-length inside each branch refers to total IP+Mask bytes.
    See rule 27 for IPv4Conditional semantics.
22a. NameConstraints subtree IP "encoded in the style of RFC 4632 (CIDR)"
    rules (R4007: "IPv4 ... MUST contain 8 octets, encoded in the style
    of RFC 4632 (CIDR) to represent an address range"):
       SubtreeIPMaskValidCIDR(<subtree_ip_list>)
    Asserts that EVERY entry's mask portion (Data.Mask) is a valid CIDR
    mask: contiguous high-order 1-bits followed by zeros. IP-version
    agnostic — same atom works for IPv4 (4-byte mask) and IPv6 (16-byte
    mask) subtrees. Combine with SubtreeIPListAllOctetCountIn for the
    octet-count clause:
       And(SubtreeIPListAllOctetCountIn(PermittedIPAddresses, [8]),
           SubtreeIPMaskValidCIDR(PermittedIPAddresses))
    For rules covering both IPv4 and IPv6 subtree CIDR encoding, use
    [8, 32] octet counts. Empty list = vacuous true (rule does not
    require any subtree IP entry). Do NOT call this no_template — RFC
    4632 mask validity is expressible.
23. "String MUST NOT contain character X" rules (e.g. '@' or '_' in
    PrintableString fields):
       FieldContains(<STRING_FIELD>, "<char>")
    For "MUST NOT contain '@'", the predicate is simply:
       FieldContains(<STRING_FIELD>, "@")
    Do NOT say "no atom exists" — FieldContains DOES check whether
    the field value contains the given substring. It works for Subject.CN
    and other STRING_FIELD types. Do NOT use FieldNotMatchesRegex for
    single-character prohibition — FieldContains is the right atom.
    For rules requiring multiple forbidden characters, use
    FieldNotMatchesRegex with an appropriate NAMED_REGEX.
24. "String field MUST NOT match a forbidden pattern" rules:
       FieldNotMatchesRegex(<STRING_FIELD>, <NAMED_REGEX>)
    Use for "FQDN MUST be composed only of P-Labels or Non-Reserved LDH
    labels" (R4717), "root zone label MUST NOT appear" (R4718), etc.
    The pattern must be a name from NAMED_REGEXES — free-form regex is
    not allowed. Available regexes for character/set exclusion:
       Re_NoAtSign        — no '@' character (R4188)
       Re_NoUnderscore    — no '_' character (R4188)
       Re_FQDN_PunyOrNonReservedLDH — FQDN (dot-joined) where each label
                              is P-Label (xn--) or Non-Reserved LDH (no
                              '--' anywhere, no trailing '-'); use for
                              R4717 ("FQDN MUST be composed of P-Labels
                              or Non-Reserved LDH Labels") via
                              ListAllMatch(DNSNames, ItemMatchesRegex(...))
                              — DO apply to whole DNSNames entries
       Re_ReservedLDH_Excluded — SINGLE LABEL variant: P-Labels (xn--) OR
                              non-Punycode label with no '--' / trailing
                              '-' (no dots allowed). Use ONLY inside
                              already-split single-label contexts
                              (WildcardFilter wildcard label, R4829).
                              DO NOT apply to whole FQDNs — it has no
                              dot in the pattern and will reject every
                              multi-label FQDN.
       Re_NoConsecutiveDots — no '..', no trailing dot (R4718)
    Do NOT say "no atom exists" — these regexes are pre-defined and ready.
    For R4188: FieldNotMatchesRegex(Subject.CommonName, "Re_NoAtSign") and
              FieldNotMatchesRegex(Subject.CommonName, "Re_NoUnderscore").
              (Both conditions must hold — CN MUST NOT contain '@' AND MUST NOT contain '_'.)
25. Wildcard-only filtering (R4829):
       WildcardFilter(<LIST_FIELD>, "<prefix>", <predicate>)
    If any entry starts with prefix (e.g. "*. " for wildcard DNS),
    that entry MUST satisfy the predicate. Non-matching entries pass
    freely. The predicate can be And()/Or() of any Item* atoms.
    For "wildcard LDH labels must be valid FQDN" rules:
       WildcardFilter(DNSNames, "*.", And(
           {"op": "ItemMatchesRegex",   "args": ["Re_ReservedLDH_Excluded"]},
           {"op": "ItemNotMatchesRegex", "args": ["Re_NoConsecutiveDots"]}
       ))
    ItemNotMatchesRegex is the "MUST NOT match" counterpart of
    ItemMatchesRegex — use it to forbid patterns within a list iteration.
    Do NOT say this is not expressible — WildcardFilter + ItemNotMatchesRegex
    handle this. Do NOT call this no_template.
25a. NameConstraints subtree entry checks (R4629):
       SubtreeStringListAnyMatch(<SUBTREE_LIST>, ItemEq(""))
    To check whether a subtree_list (PermittedDNSNames, ExcludedDNSNames,
    PermittedIPAddresses, ExcludedIPAddresses, PermittedEmailAddresses, etc.)
    contains a zero-length entry, use SubtreeStringListAnyMatch with ItemEq("").
    Example for R4629 (zero-length dNSName not permitted):
       SubtreeStringListAnyMatch(PermittedDNSNames, ItemEq(""))
    SubtreeStringListAnyMatch iterates every entry in the list, accessing
    the .Data field of each GeneralSubtreeString. ItemEq("") checks the
    string is empty. Use SubtreeStringListAllMatch for "all entries non-empty".
    Do NOT say this requires DER parsing — zcrypto already parsed the
    subtree structure; .Data is directly accessible.
25b. CN-or-SAN rule ("if CN is present, it MUST appear in SAN DNSNames"):
       ScalarInList(<scalar_field>, <list_field>)
    If the scalar field is empty, returns true (vacuously satisfied).
    If non-empty, all elements in the list must contain the scalar value.
    Use for "commonName if present MUST be in SAN DNSNames" (R5116).
    IMPORTANT: CrossFieldEq requires both fields to be scalar (string/int)
    — it does NOT work for CN-vs-DNSNames because DNSNames is a string_list.
    Always use ScalarInList for CN-or-SAN rules. Do NOT call this
    no_template just because CrossFieldEq does not work.
27. IP address version rules (IPv4 vs IPv6 within the same field):
       IPv4Conditional(<IPAddresses>, <ipv4_pred>, <ipv6_pred>)
    Takes a list of IPs; for each IP: if 4 bytes, evaluate ipv4_pred;
    if 16 bytes, evaluate ipv6_pred. Rule "all IPs must be 4 or 16
    bytes" (R5151) — use ItemLenIn([4]) for the IPv4 predicate and
    ItemLenIn([16]) for the IPv6 predicate:
       IPv4Conditional(IPAddresses,
           {"op": "ItemLenIn", "args": [[4]]},   # IPv4 check
           {"op": "ItemLenIn", "args": [[16]]})  # IPv6 check
    ItemLenIn checks the byte-length of each iteration variable.
    ItemEq is for STRING equality — do NOT use ItemEq for IP length.
    Do NOT say this is not expressible — IPv4Conditional handles it.
    Empty IPAddresses list = vacuous true (rule does not require IP
    presence). For NameConstraints subtree IP lists, use the parallel
    SubtreeIPv4Conditional atom — see rule 22.

    ASYMMETRIC IP-version rules — when the atomic_text constrains
    ONLY ONE version, use ItemLenIn with the canonical size on the
    unconstrained branch as a self-tautology (always true given Go
    net.IP type guarantees: IPv4 entries are 4 bytes, IPv6 are 16):
       IPv4Conditional(IPAddresses, ItemLenIn([4]), ItemLenIn([16]))
    expresses "atomic says IPv6 MUST be 16 octets, IPv4 unconstrained
    (canonical 4-byte tautology)". This pattern is judge-accepted
    because the IPv4 branch is structurally vacuous — net.IP enforces
    the canonical byte length so no real constraint is added.
28. IPAddresses are []net.IP: len(ip)==4 for IPv4, len(ip)==16
    for IPv6. Use ItemLenIn([4]) or ItemLenIn([16]) inside ListAllMatch
    predicates to check byte-length. ItemEq is for string equality
    — use ItemLenIn for IP length checks. Do NOT use SubtreeIPList*
    for iPAddress fields — those are only for NameConstraints subtree lists.
29. CN-or-SAN rule ("if CN is present, it MUST appear in SAN"):
       ScalarInList(<scalar_field>, <list_field>)
    If the scalar field is empty, returns true (vacuously satisfied).
    If non-empty, all elements in the list must contain the scalar value.
    Use for R5116 type rules. Do NOT call this no_template.
30. SAN GeneralName CHOICE tag checks — TWO distinct atoms (do NOT
    confuse them):
    (a) ENCODING check ("rfc822Name MUST be IA5String"):
           ExtHasGeneralNameWithTag(<OID_CONST>, <tag_int>)
        Wraps zlint util.AllAlternateNameWithTagAreIA5 — returns true
        iff EVERY entry with that tag is IA5String-encoded. Vacuously
        true when zero entries of the tag are present, so this atom
        CANNOT detect presence/absence.
    (b) PRESENCE check ("SAN has any directoryName"):
           ExtHasAnyGeneralNameOfTag(<OID_CONST>, <tag_int>)
        Raw-parses the extension SEQUENCE OF GeneralName and returns
        true iff at least one entry has the given CHOICE tag. Use for
        rules about presence/absence of a GeneralName type that zcrypto
        does not pre-flatten (directoryName, otherName, ediPartyName,
        registeredID).
    RFC 5280 §4.2.1.6 GeneralName CHOICE tag numbers:
       0=otherName, 1=rfc822Name, 2=dNSName, 3=x400Address,
       4=directoryName, 5=ediPartyName, 6=uniformResourceIdentifier,
       7=iPAddress, 8=registeredID
    Common usages: rfc822Name IA5 check (tag 1, atom (a)); dNSName IA5
    check (tag 2, atom (a)); SAN directoryName presence (tag 4, atom
    (b) wrapped in Not for "NOT RECOMMENDED" rules).
31. DomainComponent ordering (contiguous sequence check):
       DomainComponentOrdered()
    Zero args. Returns true iff c.Subject.OriginalRDNS contains domainComponent
    entries in a single contiguous block (no non-DC RDNs between them).
    Gaps before the block are allowed. OID "0.9.2342.19200300.100.1.25"
    (id-at-domainComponent, RFC 4519) is used in the Go code.
    Use for R4660 and similar "domainComponent fields MUST be in ordered
    sequence" rules.
32. Structure type (MANDATORY — validator rejects violations):
       TYPE_A: predicate = single atom, precondition = null
       TYPE_B: precondition = ExtPresent(OID), predicate = ExtNotCritical/ExtCritical(OID)
       TYPE_C: separate precondition AND predicate (if/when clause present)
       TYPE_D: atoms like FieldInSet, FieldMatchesRegex, FieldLenInRange, FieldEncodedAs
       TYPE_E: ListAllMatch / ListAnyMatch / SubtreeStringListAllMatch (iteration rules)
       TYPE_F: predicate = And(atom1, atom2, ...) — ALL clauses, NO omissions
       TYPE_G: Not() / FieldEmpty / FieldNotInSet — negation rules
       TYPE_H: CrossFieldEq / IPv4Conditional / WildcardFilter / FieldContains / ScalarInList
    Your output structure (predicate/precondition/null) must match the type above.
33. Scope-precondition (CRITICAL — top failure mode in 2026-05-22 audit):
    if the rule names a PROFILE, ALGORITHM, CERT-TYPE, or KEY-TYPE scope,
    the predicate MUST be wrapped in the matching precondition atom from
    the closed vocabulary, else the lint over-triggers on out-of-scope
    certificates. Mappings:
      "subscriber certificate"               -> IsSubscriberCert()
      "CA certificate" / "conforming CA"     -> IsCA()
      "Root CA"                              -> IsRootCA()
      "TLS server certificate"               -> IsServerCert()
      "OCSP responder certificate"           -> NO atom exists -> no_template
      "Cross-Certified Sub-CA"               -> NO atom exists -> no_template
      "self-issued"                          -> NO atom exists -> no_template
      "for RSA keys" / "RSA public key"      -> PublicKeyAlgorithmIs("RSA")
      "for ECDSA / EC keys"                  -> PublicKeyAlgorithmIs("ECDSA")
      "for P-256 / secp256r1"                -> NO curve-specific atom ->
          gate via BytesContainsOidDer(RawSubjectPublicKeyInfo, OidEcCurveP256)
          IN THE PRECONDITION (not predicate)
      "for P-384"                            -> precondition = BytesContainsOidDer(..., OidEcCurveP384)
      "for P-521"                            -> precondition = BytesContainsOidDer(..., OidEcCurveP521)
      "for ECDSA-with-SHA256 algorithm"      -> NO atom exists -> no_template
      "IPv4 / IP version 4 octet string"     -> per-item version filter
                                                NOT EXPRESSIBLE -> no_template
      "IPv6 / IP version 6 octet string"     -> NOT EXPRESSIBLE -> no_template
    If the rule's scope cannot be expressed by any precondition atom in
    the vocabulary, choose no_template — do NOT silently emit an
    unconditional predicate. An unconditional predicate that body-matches
    the rule but ignores its scope is exactly the §6.6 "scope-precondition
    omission" defect that fails strict EXPRESSES audit despite passing
    the GLM judge. The judge does not detect missing preconditions;
    you must.
34. Exhaust creative composition before declaring no_template.
    A scope you cannot name 1-to-1 in the precondition vocabulary may
    still be expressible by COMPOSING existing atoms. Common patterns:
      "OCSP responder certificate"   -> ExtKeyUsageHas(OcspSigning)
                                        (RFC 6960: an OCSP responder
                                        cert is identifiable by carrying
                                        the id-kp-OCSPSigning EKU)
      "self-issued certificate"      -> BytesEq(RawIssuer, RawSubject)
                                        (RFC 5280 §3.2: self-issued =
                                        issuer DN byte-equal to subject
                                        DN; comparison is WITHIN the
                                        same certificate, NOT across
                                        certificates)
      "TLS server certificate"       -> IsServerCert() (already exists,
                                        check first)
      "subscriber certificate"       -> IsSubscriberCert() (exists)
      "string MUST NOT contain '@'"  -> FieldNotMatchesRegex(field,
                                        Re_NoAtSign)
      "string MUST NOT contain '_'"  -> FieldNotMatchesRegex(field,
                                        Re_NoUnderscore)
      "non-reserved LDH label"       -> ItemMatchesRegex(...,
                                        Re_ReservedLDH_Excluded)  # single label
      "FQDN of non-reserved labels"  -> ItemMatchesRegex(...,
                                        Re_FQDN_PunyOrNonReservedLDH)
                                        # whole DNSNames entries (R4717)
      "directory name absent in SAN" -> FieldEmpty(DirectoryNames)
                                        (and similar for IAN/permitted/
                                        excluded directory name slots)
    Decision flow: BEFORE emitting no_template:
      (a) is the scope a NAMED PKI cert-type? -> check named cert-type
          atoms (IsCA, IsRootCA, IsServerCert, IsSubscriberCert) AND
          the EKU compositions above.
      (b) is the scope an EQUALITY between two same-cert fields? ->
          BytesEq / CrossFieldEq covers it.
      (c) is the rule a NEGATIVE character/pattern check? -> check
          NAMED_REGEXES first; many "MUST NOT contain X" rules already
          have a regex.
      (d) only if (a)–(c) all fail AND the scope is genuinely unnamed
          in zcrypto's exposed surface, emit no_template.
    A no_template emitted while skipping (a)–(c) is a soft failure of
    discipline, not a true ceiling.
35. Drop redundant ExtPresent preconditions (top false-DOES_NOT_EXPRESS
    cause). When the predicate is `Not(<X-aware-atom>)` and the
    candidate precondition would be `ExtPresent(X)` for the SAME
    extension X, OMIT the precondition (set "precondition": null). The
    X-aware atom already returns FALSE when extension X is absent, so
    Not(atom) is vacuous-true on absent X — the ExtPresent guard is
    runtime-redundant AND causes the judge to mis-read the rule's scope
    as "only when X is present" (narrower than the rule's text).
    X-aware atoms (whose body checks for / re-parses extension X):
       AIAHasMethodOtherThan, AIAMethodLocationsTagInSet,
       AIAMethodLocationsAnyMatchRegex (X = ext_oid arg)
       CRLDPHasNameRelative, CRLDPHasNameRelativeWithMultiIssuer
         (X = OidExtCrlDistributionPoints, hardwired)
       CertPolicyExplicitTextHasEncodingTagInSet (X = CertPolicyOID)
       ExtHasAnyGeneralNameOfTag, ExtHasGeneralNameWithTag (X = oid arg)
       ExtRawValueEqualsHex, ExtRawValueContainsHex (X = oid arg)
    This rule does NOT apply when the precondition is a different
    cert-class atom (IsCA, IsRootCA, IsServerCert, IsSubscriberCert,
    PublicKeyAlgorithmIs) — those carry real scope from the rule text
    and MUST be kept.
36. IR-fidelity (CRITICAL — 2026-05-27 R4686 audit fallout):
    The predicate MUST express EXACTLY the clauses in the rule's atomic
    IR description, no more. Do NOT add extra constraints that you can
    "see" in the broader rule_text, the label, or a nearby clause —
    even if they look related (sibling fields in the same table, paired
    requirements, "obvious" implications). If a field is mentioned in
    rule_text but the atomic IR description does not constrain it, the
    field does NOT belong in the predicate. This rule is the inverse
    of rule 5 (which forbids DROPPING clauses): rule 5 says capture
    every clause that IR states; rule 36 says capture ONLY the clauses
    IR states. Violation pattern from R4686: rule says cA MUST be
    FALSE, predicate also asserts pathLenConstraint constraints — the
    pathLenConstraint clause is in rule_text but not in the atomic
    description, so it must NOT be in the predicate.
"""


# ---------------------------------------------------------------------
# Build prompt
# ---------------------------------------------------------------------

PROMPT_HEAD = """\
You are a structurally-correct PKI lint generator. Read the structured
IR (PRIMARY INPUT) below and emit ONE JSON object containing a DSL
predicate tree (plus optional precondition tree). The validator +
renderer turn your JSON into Go. You never write Go.

The IR is the AUTHORITATIVE source: ir.predicate tells you the
operator, ir.subject the field, ir.constraint the value/range/format,
ir.obligation the modality. The natural-language `Text:` line is
provided AFTERWARDS as auxiliary context only — use it to disambiguate
when the IR is under-specified, but do NOT add clauses that appear in
the text but not in the IR (those belong to a different rule and are
out of scope here).

================ DSL ATOMS / COMPOUNDS ================
{dsl}
=======================================================

================ VOCAB ================
{vocab}
=======================================

================ IR PREDICATE -> ATOM CANDIDATES (mu map) ================
The ir.predicate is a closed-vocabulary symbol. Pick atom candidates
from the mapping below before consulting the natural-language text:

  must_be_present       -> ExtPresent / FieldNonEmpty
  must_not_be_present   -> Not(ExtPresent) / FieldEmpty
  must_equal / must_be  -> FieldEq / BytesEq / OidEq / ItemEq /
                           FieldEncodedAs / IsCA / IsRootCA /
                           PublicKeyAlgorithmIs / KeyUsageHas / ExtKeyUsageHas
  must_not_equal        -> Not(FieldEq) / Not(BytesEq) / Not(OidEq) /
                           FieldNotInSet
  must_include          -> FieldContains / OidListContains /
                           ListAnyMatch / ScalarInList /
                           ScalarInAnyOfLists
  must_not_include      -> Not(FieldContains) / Not(OidListContains) /
                           FieldNotMatchesRegex / ItemNotMatchesRegex
  in_range              -> FieldNumericInRange / FieldLenInRange /
                           ItemLenIn / IPListAllOctetCountIn /
                           SubtreeIPListAllOctetCountIn
  conform_to            -> FieldMatchesRegex / ItemMatchesRegex /
                           FieldEncodedAs / ListAllMatch /
                           SubtreeStringListAllMatch / WildcardFilter

The mu map is a HINT, not a constraint — the final atom choice
depends on the field's go_type / semantic. If ir.constraint.value
is a numeric range, use FieldNumericInRange / FieldLenInRange /
ItemLenIn; if it is a regex/pattern name, use *MatchesRegex; if it
is a string/bytes literal, use FieldEq / BytesEq / FieldContains;
if it is an enum/set, use FieldInSet / ItemInSet / OidListContains.
==========================================================================

{few_shot}

================ INPUT (IR primary, Text auxiliary) ================
"""


PROMPT_TAIL = """\
============================================

STEP 1 (REQUIRED THINK-ALOUD, written BEFORE the JSON):
Output a single line starting with "ANALYSIS:" that captures (in pipe-
separated key=value form):

  ANALYSIS: target=<the cert field/extension/bit the rule targets>; \
direction=<MUST present|MUST absent|MUST equal|MUST NOT contain|byte-equal|other>; \
precondition=<the if/when clause, or "none">; \
level=<MUST|MUST NOT|SHOULD|...>; \
clauses=<list of distinct conjunct/disjunct conditions>

CLAUSES is critical: enumerate every condition the rule imposes. If
clauses count > 1 then your "predicate" MUST be an And/Or tree covering
ALL of them — dropping a clause is a hard error.

STEP 2: Output the JSON object exactly as specified below.

{output_schema}
"""

PROMPT_FIX_HEAD = """\
You PREVIOUSLY answered this rule with the JSON below, but the binary
synonymy judge rejected it because of MISSING / WRONG components. Re-emit
a corrected JSON object (same schema as before) addressing every issue
in the feedback. Do NOT lose clauses that were correct — only fix what
the judge flagged.

================ PREVIOUS ANSWER ================
{prior_json}

================ JUDGE FEEDBACK ================
verdict: DOES_NOT_EXPRESS
missing_or_wrong: {missing}
why: {why}

================ DSL ATOMS / COMPOUNDS ================
{dsl}
=======================================================

================ VOCAB ================
{vocab}
=======================================

================ INPUT RULE ================
"""


def _fmt_constraint(c) -> str:
    """Render ir.constraint dict as a few short lines. constraint is a
    typed object: {type, value, raw_text, max_value, min_value, pattern,
    allowed_values, unit, expanded}. Keep only fields the LLM can act on."""
    if not isinstance(c, dict) or not c:
        return "(none)"
    keep = []
    for k in ("type", "value", "max_value", "min_value", "pattern",
              "allowed_values", "unit", "raw_text"):
        v = c.get(k)
        if v in (None, "", [], {}): continue
        sv = v if isinstance(v, str) else __import__("json").dumps(v, ensure_ascii=False)
        if len(sv) > 220: sv = sv[:220] + "..."
        keep.append(f"  .{k}: {sv}")
    return "\n".join(keep) if keep else "(none)"


def rule_input_block(rule: dict) -> str:
    """Render the per-rule input section. IR is primary; rule_text is
    auxiliary context. The order matters: LLM should consult IR first."""
    ir = rule.get("ir") or {}
    src = rule.get("source") or ""
    sec = rule.get("section") or ""
    lvl = rule.get("requirement_level") or "MUST"
    rid = rule.get("id") or 0

    # Subject: prefer subject_path (Go field expression), fallback to
    # subject_ref.path / subject (canonicalized dotted path).
    subj_ref = ir.get("subject_ref") or {}
    subj_path = ir.get("subject_path") or (subj_ref.get("path") if isinstance(subj_ref, dict) else "") or ""
    subj_canonical = ir.get("subject") or (subj_ref.get("path") if isinstance(subj_ref, dict) else "") or ""

    refs = ir.get("references") or []
    ref_strs = []
    for r in refs[:3]:
        if isinstance(r, dict):
            doc = r.get("document") or r.get("doc_id") or ""
            sect = r.get("section") or ""
            if doc: ref_strs.append(f"{doc}{(' '+sect) if sect else ''}".strip())
        elif isinstance(r, str):
            ref_strs.append(r)

    L = []
    L.append(f"Rule ID: R{rid}   Source: {src}   Section: {sec}   Level: {lvl}")
    L.append("")
    L.append("---- STRUCTURED IR (PRIMARY) ----")
    L.append(f"  ir.subject:           {subj_canonical}")
    L.append(f"  ir.subject_path:      {subj_path}")
    L.append(f"  ir.predicate:         {ir.get('predicate') or '(unset)'}")
    L.append(f"  ir.obligation:        {ir.get('obligation') or lvl}")
    L.append(f"  ir.applies_to:        {ir.get('applies_to') or 'All'}")
    precond = ir.get("precondition") or {}
    if isinstance(precond, dict) and precond.get("type"):
        neg = " NEGATED(i.e. guard is the logical NOT of this)" if precond.get("negate") else ""
        L.append(f"  ir.precondition:      GUARD type={precond.get('type')} value={precond.get('value')}{neg}")
        L.append(f"                        -> emit this as the 'precondition' tree (the rule applies ONLY when the guard holds); do NOT drop it")
    elif isinstance(precond, dict) and (precond.get("description") or precond.get("trigger")):
        L.append(f"  ir.precondition:      (prose) {precond.get('description') or ''} / {precond.get('trigger') or ''}")
    L.append(f"  ir.assertion_subject: {ir.get('assertion_subject') or '(unset)'}")
    L.append(f"  ir.extension_oid:     {ir.get('extension_oid_const') or '(unset)'}")
    L.append(f"  ir.rule_category:     {ir.get('rule_category') or '(unset)'}")
    L.append(f"  ir.lint_subclass:     {ir.get('lint_subclass') or '(unset)'}")
    if ref_strs:
        L.append(f"  ir.references:        {', '.join(ref_strs)}")
    L.append(f"  ir.constraint:")
    L.append(_fmt_constraint(ir.get("constraint")))
    L.append("")
    L.append("---- AUXILIARY CONTEXT (use only if IR is ambiguous) ----")
    L.append(f"Text: {(rule.get('text') or '')[:1500]}")
    return "\n".join(L)


def build_prompt_first(rule: dict | None = None,
                       *,
                       rule_text: str = "",
                       source: str = "",
                       section: str = "",
                       level: str = "MUST") -> str:
    # Back-compat: accept either a full rule dict or legacy kwargs.
    if rule is None:
        rule = {"id": 0, "text": rule_text, "source": source,
                "section": section, "requirement_level": level, "ir": {}}
    head = PROMPT_HEAD.format(
        dsl=dsl_block(),
        vocab=vocab_block(),
        few_shot=few_shot_block(),
    )
    rule_line = rule_input_block(rule)
    tail = PROMPT_TAIL.format(output_schema=OUTPUT_SCHEMA)
    return HARD_RULES + "\n" + head + rule_line + "\n" + tail


def build_prompt_fix(rule: dict | None = None,
                     *,
                     rule_text: str = "",
                     source: str = "",
                     section: str = "",
                     level: str = "MUST",
                     prior_json: str = "",
                     missing: str = "",
                     why: str = "") -> str:
    if rule is None:
        rule = {"id": 0, "text": rule_text, "source": source,
                "section": section, "requirement_level": level, "ir": {}}
    head = PROMPT_FIX_HEAD.format(
        prior_json=prior_json,
        missing=missing,
        why=why,
        dsl=dsl_block(),
        vocab=vocab_block(),
    )
    rule_line = rule_input_block(rule)
    tail = PROMPT_TAIL.format(output_schema=OUTPUT_SCHEMA)
    return HARD_RULES + "\n" + head + rule_line + "\n" + tail


if __name__ == "__main__":
    p = build_prompt_first(
        rule_text="Conforming CAs MUST mark this extension as non-critical.",
        source="RFC", section="4.2.2.1", level="MUST",
    )
    print(f"prompt length: {len(p)} chars  ~{len(p)//4} tokens")
