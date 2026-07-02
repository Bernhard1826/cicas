"""templates_v2 / vocab.py — closed enumerations for codegen slot values.

Sourced from `experiments/results/zcrypto_cert_api.json` and
`experiments/results/zlint_util_whitelist.json`. No free-form Go is
allowed anywhere; every slot value the LLM may emit must come from one
of these closed sets, identified by its symbolic `name`.

Each entry carries:
  name        : symbolic identifier the LLM uses (string token)
  go_expr     : the Go fragment the renderer substitutes
  go_type     : Go type for type-checking compatibility between slots
  semantic    : abstract semantic class for slot-type matching

Types layered:
  CERT_FIELDS    : top-level fields of *x509.Certificate
  DN_FIELDS      : c.Subject.X / c.Issuer.X (pkix.Name fields)
  LIST_FIELDS    : subset of CERT_FIELDS / DN_FIELDS that yield slices
  STRING_FIELDS  : subset that yield a single string
  NUMERIC_FIELDS : subset that yield int / *big.Int (with conversion meta)
  DATE_FIELDS    : c.NotBefore | c.NotAfter | time.Now()
  KEY_USAGE_BITS : x509.KeyUsage{DigitalSignature, ...}
  EKU_BITS       : x509.ExtKeyUsage{ServerAuth, ...} + util OIDs for unknowns
  ASN1_TYPES     : printableString | ia5String | utf8String | ...
  OID_CONSTS     : util.X OID constants (67)
  UTIL_FUNCS     : util.X functions (83) — renderer-internal, not LLM-facing
"""
from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

R = Path(__file__).resolve().parent.parent / "results"


@dataclass(frozen=True)
class FieldDef:
    name: str         # LLM-facing symbolic name
    go_expr: str      # Go fragment substituted by renderer
    go_type: str      # Go type
    semantic: str     # abstract class: string | string_list | int | bigint |
                      # time | bool | oid | oid_list | keyusage_bits |
                      # eku_list | ip_list | bytes | dn | ext_list

    def __str__(self): return self.name


# ---------------------------------------------------------------------
# CERT_FIELDS — top-level *x509.Certificate fields
# ---------------------------------------------------------------------

CERT_FIELDS: list[FieldDef] = [
    FieldDef("Version",                 "c.Version",                 "int",                       "int"),
    FieldDef("SerialNumber",            "c.SerialNumber",            "*big.Int",                  "bigint"),
    FieldDef("NotBefore",               "c.NotBefore",               "time.Time",                 "time"),
    FieldDef("NotAfter",                "c.NotAfter",                "time.Time",                 "time"),
    FieldDef("ValidityPeriod",          "c.ValidityPeriod",          "int",                       "int"),
    FieldDef("KeyUsage",                "c.KeyUsage",                "x509.KeyUsage",             "keyusage_bits"),
    FieldDef("ExtKeyUsage",             "c.ExtKeyUsage",             "[]x509.ExtKeyUsage",        "eku_list"),
    FieldDef("UnknownExtKeyUsage",      "c.UnknownExtKeyUsage",      "[]asn1.ObjectIdentifier",   "oid_list"),
    FieldDef("BasicConstraintsValid",   "c.BasicConstraintsValid",   "bool",                      "bool"),
    FieldDef("IsCA",                    "c.IsCA",                    "bool",                      "bool"),
    FieldDef("MaxPathLen",              "c.MaxPathLen",              "int",                       "int"),
    FieldDef("MaxPathLenZero",          "c.MaxPathLenZero",          "bool",                      "bool"),
    FieldDef("SelfSigned",              "c.SelfSigned",              "bool",                      "bool"),
    FieldDef("SubjectKeyId",            "c.SubjectKeyId",            "[]byte",                    "bytes"),
    FieldDef("AuthorityKeyId",          "c.AuthorityKeyId",          "[]byte",                    "bytes"),
    FieldDef("OCSPServer",              "c.OCSPServer",              "[]string",                  "string_list"),
    FieldDef("IssuingCertificateURL",   "c.IssuingCertificateURL",   "[]string",                  "string_list"),
    FieldDef("DNSNames",                "c.DNSNames",                "[]string",                  "string_list"),
    FieldDef("EmailAddresses",          "c.EmailAddresses",          "[]string",                  "string_list"),
    FieldDef("URIs",                    "c.URIs",                    "[]string",                  "string_list"),
    FieldDef("IPAddresses",             "c.IPAddresses",             "[]net.IP",                  "ip_list"),
    FieldDef("Extensions",              "c.Extensions",              "[]pkix.Extension",          "ext_list"),
    FieldDef("SignatureAlgorithm",      "c.SignatureAlgorithm",      "x509.SignatureAlgorithm",   "sigalg"),
    FieldDef("SignatureAlgorithmOID",   "c.SignatureAlgorithmOID",   "asn1.ObjectIdentifier",     "oid"),
    FieldDef("PublicKeyAlgorithm",      "c.PublicKeyAlgorithm",      "x509.PublicKeyAlgorithm",   "pubkeyalg"),
    FieldDef("PublicKeyAlgorithmOID",   "c.PublicKeyAlgorithmOID",   "asn1.ObjectIdentifier",     "oid"),

    # CRL Distribution Points (RFC 5280 §4.2.1.13) — zcrypto exposes the
    # parsed URI list directly on Certificate.
    FieldDef("CRLDistributionPoints",   "c.CRLDistributionPoints",   "[]string",                  "string_list"),
    # Certificate Policies — top-level OID list (the policy OIDs themselves;
    # CPS URIs / explicit texts are nested arrays we don't expose here).
    FieldDef("PolicyIdentifiers",       "c.PolicyIdentifiers",       "[]asn1.ObjectIdentifier",   "oid_list"),
    # Issuer Alternative Name parsed sub-fields
    FieldDef("IANDNSNames",             "c.IANDNSNames",             "[]string",                  "string_list"),
    FieldDef("IANEmailAddresses",       "c.IANEmailAddresses",       "[]string",                  "string_list"),
    FieldDef("IANURIs",                 "c.IANURIs",                 "[]string",                  "string_list"),
    FieldDef("IANIPAddresses",          "c.IANIPAddresses",          "[]net.IP",                  "ip_list"),
    # Name Constraints critical bit
    FieldDef("NameConstraintsCritical", "c.NameConstraintsCritical", "bool",                      "bool"),
    # Pre-certificate (RFC 6962 poison) marker
    FieldDef("IsPrecert",               "c.IsPrecert",               "bool",                      "bool"),
    # Unique IDs from TBSCertificate (asn1.BitString.Bytes for presence check)
    FieldDef("IssuerUniqueId",          "c.IssuerUniqueId.Bytes",    "[]byte",                    "bytes"),
    FieldDef("SubjectUniqueId",         "c.SubjectUniqueId.Bytes",   "[]byte",                    "bytes"),

    # Raw DER bytes of subcomponents (for byte-level encoding equality checks)
    FieldDef("RawSubject",              "c.RawSubject",              "[]byte",                    "bytes"),
    FieldDef("RawIssuer",               "c.RawIssuer",               "[]byte",                    "bytes"),
    FieldDef("RawTBSCertificate",       "c.RawTBSCertificate",       "[]byte",                    "bytes"),
    FieldDef("RawSubjectPublicKeyInfo", "c.RawSubjectPublicKeyInfo", "[]byte",                    "bytes"),

    # NameConstraints permitted/excluded subtrees (already parsed by zcrypto;
    # each is a slice of GeneralSubtree* structs. Use FieldNonEmpty / FieldEmpty
    # to check "this name-type subtree is present / absent". For deeper checks
    # (e.g. "contains IPv4 zero range") use RawExtensionValueContainsHex on
    # NameConstOID.)
    FieldDef("PermittedDNSNames",       "c.PermittedDNSNames",       "[]GeneralSubtreeString",    "subtree_list"),
    FieldDef("ExcludedDNSNames",        "c.ExcludedDNSNames",        "[]GeneralSubtreeString",    "subtree_list"),
    FieldDef("PermittedEmailAddresses", "c.PermittedEmailAddresses", "[]GeneralSubtreeString",    "subtree_list"),
    FieldDef("ExcludedEmailAddresses",  "c.ExcludedEmailAddresses",  "[]GeneralSubtreeString",    "subtree_list"),
    FieldDef("PermittedURIs",           "c.PermittedURIs",           "[]GeneralSubtreeString",    "subtree_list"),
    FieldDef("ExcludedURIs",            "c.ExcludedURIs",            "[]GeneralSubtreeString",    "subtree_list"),
    FieldDef("PermittedIPAddresses",    "c.PermittedIPAddresses",    "[]GeneralSubtreeIP",        "subtree_list"),
    FieldDef("ExcludedIPAddresses",     "c.ExcludedIPAddresses",     "[]GeneralSubtreeIP",        "subtree_list"),
    FieldDef("PermittedDirectoryNames", "c.PermittedDirectoryNames", "[]GeneralSubtreeName",      "subtree_list"),
    FieldDef("ExcludedDirectoryNames",  "c.ExcludedDirectoryNames",  "[]GeneralSubtreeName",      "subtree_list"),
    FieldDef("PermittedRegisteredIDs",  "c.PermittedRegisteredIDs",  "[]GeneralSubtreeOid",       "subtree_list"),
    FieldDef("ExcludedRegisteredIDs",   "c.ExcludedRegisteredIDs",   "[]GeneralSubtreeOid",       "subtree_list"),

    # CertificatePolicies parsed sub-arrays (per-policy lists).
    # Use ListAnyMatch on CPSuri[i] etc. is awkward; for now expose only
    # the top-level OID list (PolicyIdentifiers) which is already above.
    # ParsedExplicitTexts is [][]string - flattened access via NestedListAnyNonEmpty.
]

# ---------------------------------------------------------------------
# DN_FIELDS — c.Subject.X / c.Issuer.X (pkix.Name fields)
# ---------------------------------------------------------------------

_PKIX_NAME_FIELDS = [
    # (field,                go_type,      semantic)
    ("Country",              "[]string",   "string_list"),
    ("Organization",         "[]string",   "string_list"),
    ("OrganizationalUnit",   "[]string",   "string_list"),
    ("Locality",             "[]string",   "string_list"),
    ("Province",             "[]string",   "string_list"),
    ("StreetAddress",        "[]string",   "string_list"),
    ("PostalCode",           "[]string",   "string_list"),
    ("DomainComponent",      "[]string",   "string_list"),
    ("EmailAddress",         "[]string",   "string_list"),
    ("CommonName",           "string",     "string"),
    ("SerialNumber",         "string",     "string"),
    ("CommonNames",          "[]string",   "string_list"),
    ("SerialNumbers",        "[]string",   "string_list"),
    ("GivenName",            "[]string",   "string_list"),
    ("Surname",              "[]string",   "string_list"),
    ("OrganizationIDs",      "[]string",   "string_list"),
    ("JurisdictionLocality", "[]string",   "string_list"),
    ("JurisdictionProvince", "[]string",   "string_list"),
    ("JurisdictionCountry",  "[]string",   "string_list"),
]

DN_FIELDS: list[FieldDef] = []
for _holder in ("Subject", "Issuer"):
    for _f, _gt, _sem in _PKIX_NAME_FIELDS:
        DN_FIELDS.append(FieldDef(
            name=f"{_holder}.{_f}",
            go_expr=f"c.{_holder}.{_f}",
            go_type=_gt,
            semantic=_sem,
        ))

# RDN ATTRIBUTE → DN_FIELD lookup (LLM-facing helper for IR mapping)
RDN_TO_DN_NAME = {
    "commonName":                       "CommonName",
    "stateOrProvinceName":              "Province",
    "countryName":                      "Country",
    "organizationName":                 "Organization",
    "organizationalUnitName":           "OrganizationalUnit",
    "localityName":                     "Locality",
    "streetAddress":                    "StreetAddress",
    "postalCode":                       "PostalCode",
    "domainComponent":                  "DomainComponent",
    "emailAddress":                     "EmailAddress",
    "serialNumber":                     "SerialNumber",
    "givenName":                        "GivenName",
    "surname":                          "Surname",
    "organizationIdentifier":           "OrganizationIDs",
    "jurisdictionLocalityName":         "JurisdictionLocality",
    "jurisdictionStateOrProvinceName":  "JurisdictionProvince",
    "jurisdictionCountryName":          "JurisdictionCountry",
}

# ---------------------------------------------------------------------
# CRL_FIELDS — fields of *x509.RevocationList (zcrypto), for the CRL lint
# harness. The renderer's value emitters (_emit_field_*) are go_expr-based and
# reused verbatim; only the field-name lookup and the extension atoms differ
# (CRL extensions are checked by iterating c.Extensions, see crl_render.py).
# ---------------------------------------------------------------------

CRL_FIELDS: list[FieldDef] = [
    FieldDef("CRLNumber",            "c.Number",              "*big.Int",                 "bigint"),
    FieldDef("ThisUpdate",           "c.ThisUpdate",          "time.Time",                "time"),
    FieldDef("NextUpdate",           "c.NextUpdate",          "time.Time",                "time"),
    FieldDef("RevokedCertificates",  "c.RevokedCertificates", "[]x509.RevokedCertificate", "ext_list"),
    FieldDef("AuthorityKeyId",       "c.AuthorityKeyId",      "[]byte",                   "bytes"),
    FieldDef("RawIssuer",            "c.RawIssuer",           "[]byte",                   "bytes"),
    FieldDef("Signature",            "c.Signature",           "[]byte",                   "bytes"),
]
# Issuer.X DN sub-fields on the CRL (same pkix.Name layout as cert DN).
for _f, _gt, _sem in _PKIX_NAME_FIELDS:
    CRL_FIELDS.append(FieldDef(f"Issuer.{_f}", f"c.Issuer.{_f}", _gt, _sem))

# ---------------------------------------------------------------------
# DATE_FIELDS — usable as date arguments to DateAfter etc.
# ---------------------------------------------------------------------

DATE_FIELDS: list[FieldDef] = [
    FieldDef("c.NotBefore",  "c.NotBefore",  "time.Time", "time"),
    FieldDef("c.NotAfter",   "c.NotAfter",   "time.Time", "time"),
    FieldDef("now",          "time.Now()",   "time.Time", "time"),
]

# ---------------------------------------------------------------------
# KEY_USAGE_BITS / EXT_KEY_USAGE_BITS
# ---------------------------------------------------------------------

KEY_USAGE_BITS: list[FieldDef] = [
    FieldDef(name, f"x509.KeyUsage{name}", "x509.KeyUsage", "keyusage_bit")
    for name in [
        "DigitalSignature", "ContentCommitment", "KeyEncipherment",
        "DataEncipherment", "KeyAgreement",      "CertSign",
        "CRLSign",           "EncipherOnly",      "DecipherOnly",
    ]
]

EKU_BITS: list[FieldDef] = [
    FieldDef(name, f"x509.ExtKeyUsage{go_suffix}", "x509.ExtKeyUsage", "eku_bit")
    for name, go_suffix in [
        ("Any",                "Any"),
        ("ServerAuth",         "ServerAuth"),
        ("ClientAuth",         "ClientAuth"),
        ("CodeSigning",        "CodeSigning"),
        ("EmailProtection",    "EmailProtection"),
        ("IpsecTunnel",        "IpsecTunnel"),
        ("IpsecUser",          "IpsecUser"),
        ("TimeStamping",       "TimeStamping"),
        ("OcspSigning",        "OcspSigning"),
    ]
]

# ---------------------------------------------------------------------
# ASN1_TYPES — for encoding-as checks
# ---------------------------------------------------------------------

ASN1_TYPES: list[FieldDef] = [
    # Universal-class ASN.1 tag numbers. Using int literals rather than
    # asn1.Tag* constants because (a) stdlib encoding/asn1 only exports
    # a subset (e.g. no TagVisibleString / TagUniversalString), (b) ints
    # work in both stdlib and zcrypto/encoding/asn1 contexts without
    # the named-type cross-package conflict.
    FieldDef("PrintableString", "19", "int", "asn1_tag"),
    FieldDef("IA5String",        "22", "int", "asn1_tag"),
    FieldDef("UTF8String",       "12", "int", "asn1_tag"),
    FieldDef("BMPString",        "30", "int", "asn1_tag"),
    FieldDef("T61String",        "20", "int", "asn1_tag"),
    FieldDef("TeletexString",     "20", "int", "asn1_tag"),  # alias of T61String (X.680 §41); same universal tag 20
    FieldDef("UniversalString",  "28", "int", "asn1_tag"),
    FieldDef("NumericString",    "18", "int", "asn1_tag"),
    FieldDef("VisibleString",    "26", "int", "asn1_tag"),
    FieldDef("UTCTime",          "23", "int", "asn1_tag"),
    FieldDef("GeneralizedTime",  "24", "int", "asn1_tag"),
]

# ---------------------------------------------------------------------
# NAMED_REGEXES — closed pre-audited regex set for ItemMatchesRegex /
# FieldMatchesRegex. Replaces free-form REGEX_LIT to prevent LLM from
# tunneling arbitrary semantics through generic regex slots. The LLM
# may now ONLY name a regex from this table; anything outside → no_template.
# ---------------------------------------------------------------------

NAMED_REGEXES: dict[str, tuple[str, str]] = {
    # name                  : (regex,                                                                       description)
    "Re_LDH_Label":           (r"^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$",
                               "single LDH label (RFC 5890): letters/digits/hyphens, no leading/trailing hyphen, <=63"),
    "Re_LDH_Hostname":        (r"^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)+$",
                               "FQDN composed of LDH labels separated by '.', at least 2 labels"),
    "Re_PunyOrLDH_Label":     (r"^(xn--[a-zA-Z0-9-]+|[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)$",
                               "P-Label (xn-- prefix) OR LDH label"),
    "Re_PunyOrLDH_Hostname":  (r"^(xn--[a-zA-Z0-9-]+|[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)(\.(xn--[a-zA-Z0-9-]+|[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?))*$",
                               "FQDN of P-Labels and/or LDH labels (ACE-encoded form)"),
    "Re_AsciiOnly":           (r"^[\x00-\x7F]+$",
                               "ASCII-only (proxy for ACE-encoded form: no non-ASCII bytes)"),
    "Re_HttpUrl":             (r"^https?://",
                               "string starts with http:// or https://"),
    "Re_HttpUrlStrict":       (r"^http://",
                               "string starts with http:// only (NOT https)"),
    "Re_LdapUrl":             (r"^ldaps?://",
                               "string starts with ldap:// or ldaps://"),
    "Re_LdapUrlStrict":       (r"^ldap://",
                               "string starts with ldap:// only (NOT ldaps)"),
    "Re_HttpOrLdapUrl":       (r"^(https?|ldaps?)://",
                               "string starts with http://, https://, ldap:// or ldaps://"),
    "Re_AnyUri":              (r"^[a-zA-Z][a-zA-Z0-9+.-]*:",
                               "any RFC 3986 URI shape (scheme followed by ':'); use only when rule says 'valid URI per RFC 3986' and you don't have a scheme-specific regex"),
    "Re_LdapUrlWithDn":       (r"^ldaps?://[^?]*\?[^?]*\bdn=",
                               "LDAP URL whose query string contains a 'dn=' field (RFC 4516)"),
    "Re_LdapUrlWithAttrs":    (r"^ldaps?://[^?]*\?[^?]*\battributes?=",
                               "LDAP URL whose query string contains an 'attributes=' field (RFC 4516)"),
    # R4397: RFC 4516 LDAP URL syntax `ldap://host/dn?attrs?scope?filter?exts`
    # where attrs is a single attrdesc (no comma-separated list). Per RFC
    # 4516 §2.5.1, attrdesc may carry options separated by ';' (e.g.
    # 'cACertificate;binary') but NOT comma — comma indicates multiple
    # attrdescs. Combined check: dn part non-empty AND attrs part contains
    # exactly one attrdesc (no comma).
    "Re_LdapUrlWithDnAndSingleAttrdesc": (r"^ldaps?://[^/?]*/[^/?]+\?[^?,]+(\?[^?]*){0,3}$",
                               "LDAP URL with a non-empty <dn> path component AND a single <attrdesc> in the attrs portion (no comma-separated attribute list); optional scope/filter/exts allowed; for 'CRL DP LDAP URI MUST include dn AND single attrdesc' rules (R4397)"),
    "Re_HttpOrLdapStrict":    (r"^(http|ldap)://",
                               "string starts with http:// or ldap:// ONLY (excludes https / ldaps); use when rule cites RFC2616+RFC4516 schemes specifically"),
    "Re_Rfc3986Uri":          (r"^[a-zA-Z][a-zA-Z0-9+.\-]*:(//[^?#\s]*)?[^?#\s]*(\?[^#\s]*)?(#[^\s]*)?$",
                               "valid full RFC 3986 URI: scheme + optional authority/path/query/fragment, no whitespace; stricter than Re_AnyUri"),
    # Character-set exclusion checks
    "Re_NoAtSign":            (r"^[^@]+$",
                               "string contains NO '@' character; use for PrintableString MUST NOT contain '@' rules (R4188)"),
    "Re_NoUnderscore":        (r"^[^_]+$",
                               "string contains NO '_' underscore character; use for PrintableString MUST NOT contain '_' rules (R4188)"),
    # LDH label + FQDN variants for R4717/R4718/R4829 (reserved-label / root-zone exclusion)
    "Re_ASCII_LDH_Label":     (r"^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$",
                               "ASCII-only LDH label (no punycode xn-- prefix, no leading/trailing hyphen, <=63 chars); use for 'composed only of non-reserved LDH labels' rules (R4717, R4718, R4829)"),
    "Re_ASCII_LDH_Hostname":   (r"^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)+$",
                               "ASCII-only FQDN of LDH labels (no punycode); at least 2 labels; use for 'wildcard domains must be valid FQDN' rules (R4829)"),
    # R4717: Reserved LDH Labels excluded (per RFC 5891 §4.3): non-Punycode
    # LDH labels must NOT contain "--" in character positions 3-4 (which
    # effectively means: if it starts with "xn--", it's a P-Label (allowed);
    # otherwise, the label must not contain "--" anywhere, must not end with
    # hyphen, and single-char labels are allowed).
    # RE2 rewrite (no negative lookahead — Go RE2 doesn't support it):
    #   Non-P-Label = [a-zA-Z0-9](?:-?[a-zA-Z0-9]){0,31}
    # After the first alphanumeric, each "step" is an optional hyphen followed
    # by an alphanumeric. This structurally prevents both "--" (would require
    # two hyphens with no alphanumeric between) and trailing "-" (every step
    # ends on alphanumeric). Max length 1+31*2=63 matches RFC 5891 §4.3.
    # Earlier version `(?!.*--)(?!.*-$)` used Perl negative lookahead which
    # panics MustCompile in Go (regexp/syntax error) — all lints using this
    # regex (R4717, R4829) panicked at runtime; round36 audit caught this.
    "Re_ReservedLDH_Excluded": (r"^(xn--[a-zA-Z0-9]+|[a-zA-Z0-9](?:-?[a-zA-Z0-9]){0,31})$",
                               "ASCII LDH label (single): P-Labels (xn-- prefix) allowed; non-P-Labels must have NO '--' anywhere and no trailing hyphen; allows single-char and two-char labels; for use inside per-label iteration (WildcardFilter / ListAllMatch over already-split labels). Do NOT apply to whole FQDNs — use Re_FQDN_PunyOrNonReservedLDH instead (R4829)"),
    # R4717: FQDN-shaped variant — same per-label semantics, dot-joined.
    # Each label between dots must be P-Label or Non-Reserved LDH.
    "Re_FQDN_PunyOrNonReservedLDH": (r"^(xn--[a-zA-Z0-9]+|[a-zA-Z0-9](?:-?[a-zA-Z0-9]){0,31})(\.(xn--[a-zA-Z0-9]+|[a-zA-Z0-9](?:-?[a-zA-Z0-9]){0,31}))*$",
                               "FQDN composed entirely of P-Labels (xn-- prefix) or Non-Reserved LDH labels (no '--' anywhere, no trailing hyphen) joined by '.'; use for 'FQDN MUST be composed of P-Labels or Non-Reserved LDH Labels' rules (R4717). Apply to whole DNSNames entries via ItemMatchesRegex inside ListAllMatch"),
    # R4718: no zero-length / empty labels (no consecutive dots, no trailing dot)
    "Re_NoConsecutiveDots":   (r"^[^.]+(\.[^.]+)*$",
                               "string with NO consecutive dots (..) and NO trailing dot; rejects '..', 'foo..bar', 'foo.'; use for 'root-zone zero-length label MUST NOT be included' (R4718)"),
    # R4038 + R4455: RFC 5321 Mailbox format — Local-part@Domain shape with
    # ASCII LDH (or P-Label) domain labels. Rejects: phrases, parenthesized
    # comments, angle-bracket wrapping, multiple addresses in one entry,
    # non-ASCII (pre-ACE IDN) domain labels, missing @, whitespace.
    # Domain part requires >=2 labels (a.b at minimum), consistent with how
    # X.509 rfc822Name is used in practice.
    # Vacuous test on 1325 zlint testdata PEMs (88 email-bearing certs, 97
    # email values): 92/97 pass, 5/97 fail (all 5 are genuine PKI violations
    # — SANWithSpace, twoEmailAddresses, country-code-in-EmailAddress, etc.).
    "Re_Rfc5321Mailbox":      (r"^[A-Za-z0-9!#$%&'*+/=?^_`{|}~.\-]+@"
                               r"[A-Za-z0-9]([A-Za-z0-9\-]{0,61}[A-Za-z0-9])?"
                               r"(\.[A-Za-z0-9]([A-Za-z0-9\-]{0,61}[A-Za-z0-9])?)+$",
                               "RFC 5321 Mailbox shape (Local-part@Domain) with ASCII LDH or P-Label domain "
                               "labels; rejects angle-bracket wrapping, phrases, parenthesized comments, "
                               "multiple addresses in one entry, non-ASCII (pre-ACE) domain labels, "
                               "whitespace; use for rfc822Name / subjectDN EmailAddress format checks "
                               "(R4038 RFC 5321 Mailbox, R4455 IDN-to-ACE host-part)"),
    # R29804: Tor v3 onion address syntax (RFC 7686). v3 onion addresses use
    # 56 base32 characters (encoding 32 bytes of key material) followed by
    # ".onion". Total format: <base32-56chars>.onion
    "Re_TorV3Onion":          (r"^[a-z2-7]{56}\.onion$",
                               "Tor v3 onion address: exactly 56 base32 characters (a-z, 2-7) "
                               "followed by .onion (RFC 7686). Use for subjectAltName dNSName "
                               "Tor hidden service address checks (R29804)."),
    # R4719: CN=serialNumber requirement — checks that a DN component's value
    # is a decimal string of digits. Matches RFC 4519 serialNumber syntax.
    "Re_SerialNumberString":  (r"^[0-9]+$",
                               "Decimal digit string only (RFC 4519 serialNumber syntax). "
                               "Use for DN AttributeTypeAndValue serialNumber field checks."),
    # R4059: FQDN with at least 2 labels where rightmost label is a valid
    # TLD (at least 2 chars, no leading hyphen, alphanumeric at ends).
    "Re_FQDN_AtLeastTwoLabels": (r"^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\."
                                  r"([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)+$",
                               "FQDN with at least 2 dot-separated labels; each label "
                               "is an LDH label (1-63 chars, no leading/trailing hyphen); "
                               "use for multi-label DNS name format checks (R4059)."),
}

NAMED_REGEX_NAMES: set[str] = set(NAMED_REGEXES.keys())


# ---------------------------------------------------------------------
# OID_CONSTS — load from util whitelist (LLM-facing)
# ---------------------------------------------------------------------

def _load_whitelist():
    return json.loads((R / "zlint_util_whitelist.json").read_text())

_WL = _load_whitelist()

OID_CONSTS: list[FieldDef] = [
    FieldDef(c["name"], f"util.{c['name']}", "asn1.ObjectIdentifier", "oid")
    for c in _WL["consts_vars"]
    if c["name"].endswith("OID")
       or c["name"].endswith("Oid")
       or c["name"].startswith("Oid")  # OidRSAEncryption, OidSHA256WithRSAEncryption, etc.
]

# ---------------------------------------------------------------------
# EXTRA_OID_CONSTS — well-known OIDs not in zlint util but required by
# CABF-BR / RFC 5280 etc. (sourced from RFC 5480 §2.1, RFC 5912 §B,
# CABF-BR §7.1.3.1). Renderer emits these as inline asn1.ObjectIdentifier
# literals (no util reference).
# ---------------------------------------------------------------------

_EXTRA_OIDS = [
    # ECDSA / EC curves (RFC 5480)
    ("OidEcPublicKey",                "asn1.ObjectIdentifier{1, 2, 840, 10045, 2, 1}"),
    ("OidEcCurveP256",                "asn1.ObjectIdentifier{1, 2, 840, 10045, 3, 1, 7}"),    # prime256v1 / secp256r1
    ("OidEcCurveP384",                "asn1.ObjectIdentifier{1, 3, 132, 0, 34}"),             # secp384r1
    ("OidEcCurveP521",                "asn1.ObjectIdentifier{1, 3, 132, 0, 35}"),             # secp521r1
    # ECDSA-with-SHA signature algorithm OIDs (zlint util only has SHA-224)
    ("OidSignatureSHA256withECDSA",   "asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 2}"),
    ("OidSignatureSHA384withECDSA",   "asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 3}"),
    ("OidSignatureSHA512withECDSA",   "asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 4}"),
    # Edwards-curve sig (RFC 8410) — for completeness
    ("OidEd25519",                    "asn1.ObjectIdentifier{1, 3, 101, 112}"),
    ("OidEd448",                      "asn1.ObjectIdentifier{1, 3, 101, 113}"),
    # Certificate Transparency Precertificate Signing Certificate EKU.
    # zlint exposes this as util.PreCertificateSigningCertificateEKU, but the
    # generic OID whitelist only imports *OID/*Oid constants.
    ("PreCertificateSigningCertificateEKU", "asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 11129, 2, 4, 4}"),
    # AIA access-method OIDs (RFC 5280 §4.2.2.1, RFC 5697). Needed by
    # AIAHasMethodOtherThan / AIAMethodLocations* atoms — zlint util has
    # only the extension OID (AiaOID) and not the per-method ids.
    ("OidIdAdCaIssuers",              "asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 48, 2}"),
    ("OidIdAdOcsp",                   "asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 48, 1}"),
    ("OidIdAdTimeStamping",           "asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 48, 3}"),
    ("OidIdAdCaRepository",           "asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 48, 5}"),
    # CRL Distribution Points extension OID (RFC 5280 §4.2.1.13). Used by
    # CRLDPHasNameRelative* atoms which re-parse the raw extension DER.
    ("OidExtCrlDistributionPoints",   "asn1.ObjectIdentifier{2, 5, 29, 31}"),
    # CABF BR §7.1.6.1 Reserved Certificate Policy Identifiers. Needed to reduce
    # "MUST contain exactly one Reserved Certificate Policy Identifier" to a real
    # value check (FieldCount AND OidListContains), not bare presence.
    ("OidPolicyDomainValidated",       "asn1.ObjectIdentifier{2, 23, 140, 1, 2, 1}"),  # DV
    ("OidPolicyOrganizationValidated", "asn1.ObjectIdentifier{2, 23, 140, 1, 2, 2}"),  # OV
    ("OidPolicyIndividualValidated",   "asn1.ObjectIdentifier{2, 23, 140, 1, 2, 3}"),  # IV
    ("OidPolicyExtendedValidation",    "asn1.ObjectIdentifier{2, 23, 140, 1, 1}"),     # EV
    # Policy qualifier OIDs (RFC 5280 §4.2.1.4) — needed by PolicyQualifierOIDInSet/NotInSet.
    # Override the util.* references from the whitelist with actual inline OID literals.
    ("CpsOID",                        "asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 2, 1}"),  # CPS
    ("UserNoticeOID",                 "asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 2, 2}"),  # UserNotice
]

OID_CONSTS.extend(
    FieldDef(name, expr, "asn1.ObjectIdentifier", "oid")
    for name, expr in _EXTRA_OIDS
)

# Override existing CpsOID/UserNoticeOID entries that came from the whitelist
# (they have util.* references; we need inline OID literals for rendering)
_extra_names = {name for name, _ in _EXTRA_OIDS}
OID_CONSTS = [f for f in OID_CONSTS if f.name not in _extra_names]
OID_CONSTS.extend(
    FieldDef(name, expr, "asn1.ObjectIdentifier", "oid")
    for name, expr in _EXTRA_OIDS
)

# Non-OID util constants (LLM-facing for INT/STRING substitution where applicable)
NAMED_CONSTS: list[FieldDef] = [
    FieldDef(c["name"], f"util.{c['name']}", "?", "named_const")
    for c in _WL["consts_vars"]
    if not (c["name"].endswith("OID") or c["name"].endswith("Oid"))
]

UTIL_FUNCS_BY_NAME: dict[str, dict] = {f["name"]: f for f in _WL["funcs"]}
OID_CONST_NAMES: set[str] = {f.name for f in OID_CONSTS}


# ---------------------------------------------------------------------
# Lookup helpers
# ---------------------------------------------------------------------

def by_name(table: list[FieldDef]) -> dict[str, FieldDef]:
    return {f.name: f for f in table}


CERT_BY_NAME    = by_name(CERT_FIELDS)
DN_BY_NAME      = by_name(DN_FIELDS)
DATE_BY_NAME    = by_name(DATE_FIELDS)
# Tolerant aliases: LLM often writes 'NotBefore' instead of 'c.NotBefore'.
for _alias_short, _alias_full in (("NotBefore","c.NotBefore"),
                                   ("NotAfter","c.NotAfter")):
    if _alias_full in DATE_BY_NAME and _alias_short not in DATE_BY_NAME:
        DATE_BY_NAME[_alias_short] = DATE_BY_NAME[_alias_full]
KU_BY_NAME      = by_name(KEY_USAGE_BITS)
EKU_BY_NAME     = by_name(EKU_BITS)
ASN1_BY_NAME    = by_name(ASN1_TYPES)
OID_BY_NAME     = by_name(OID_CONSTS)

# ---------------------------------------------------------------------
# App-side OID const aliases. The hand-written deterministic ir_to_dsl
# (cicas_backend/app/services/certificate/dsl/rule_ir_to_dsl.py, also used by
# the zlint coverage matcher) names some standard extension OIDs differently
# from zlint util. Each alias points at the util FieldDef for the SAME OID arc
# — values verified against zlint/v3/util/oid.go — so the renderer resolves the
# app-emitted name to the correct util.<Const>. Sound by construction (identical
# OID value); pure reference-data reconciliation, no per-rule logic.
# ---------------------------------------------------------------------
_APP_OID_ALIASES = {
    "SubjectAltNameOID":    "SubjectAlternateNameOID",  # 2.5.29.17
    "SubjectKeyIdOID":      "SubjectKeyIdentityOID",    # 2.5.29.14
    "IssuerAltNameOID":     "IssuerAlternateNameOID",   # 2.5.29.18
    "anyPolicyOID":         "AnyPolicyOID",             # 2.5.29.32.0
    "PolicyMappingsOID":    "PolicyMapOID",             # 2.5.29.33
    "AuthorityKeyIdOID":    "AuthkeyOID",               # 2.5.29.35
    "BasicConstraintsOID":  "BasicConstOID",            # 2.5.29.19
    "PolicyConstraintsOID": "PolicyConstOID",           # 2.5.29.36
    "FreshestCRLOID":       "FreshCRLOID",              # 2.5.29.46
    # CRL extension OIDs (app-side names used by ir_to_dsl on CRL-document rules)
    "IssuingDistributionPoint": "IssuingDistOID",       # 2.5.29.28
    "DeltaCRLIndicator":        "DeltaCRLIndicatorOID", # 2.5.29.27
}
for _app_oid, _util_oid in _APP_OID_ALIASES.items():
    if _util_oid in OID_BY_NAME and _app_oid not in OID_BY_NAME:
        OID_BY_NAME[_app_oid] = OID_BY_NAME[_util_oid]


def lookup_anyfield(name: str) -> Optional[FieldDef]:
    """Try CERT_FIELDS, then DN_FIELDS, return None if unknown."""
    return CERT_BY_NAME.get(name) or DN_BY_NAME.get(name)


CRL_BY_NAME = by_name(CRL_FIELDS)


def lookup_crlfield(name: str) -> Optional[FieldDef]:
    """Resolve a field name against the CRL (*x509.RevocationList) vocab; falls
    back to the shared Issuer.* DN fields. Returns None if unknown (the CRL
    renderability gate then demotes the rule to the LLM path)."""
    return CRL_BY_NAME.get(name)


# Subsets by semantic class (used by template slot type-checking)

def fields_with_semantic(*semantics: str) -> list[FieldDef]:
    return [f for f in (CERT_FIELDS + DN_FIELDS) if f.semantic in semantics]


STRING_FIELDS:      list[FieldDef] = fields_with_semantic("string")
STRING_LIST_FIELDS: list[FieldDef] = fields_with_semantic("string_list")
NUMERIC_FIELDS:     list[FieldDef] = fields_with_semantic("int", "bigint")
LIST_FIELDS:        list[FieldDef] = fields_with_semantic(
    "string_list", "ip_list", "oid_list", "eku_list", "ext_list", "bytes",
    "subtree_list")
BOOL_FIELDS:        list[FieldDef] = fields_with_semantic("bool")
TIME_FIELDS:        list[FieldDef] = fields_with_semantic("time")


# ---------------------------------------------------------------------
# Self-test on import
# ---------------------------------------------------------------------

if __name__ == "__main__":
    print(f"CERT_FIELDS:        {len(CERT_FIELDS)}")
    print(f"DN_FIELDS:          {len(DN_FIELDS)}")
    print(f"DATE_FIELDS:        {len(DATE_FIELDS)}")
    print(f"KEY_USAGE_BITS:     {len(KEY_USAGE_BITS)}")
    print(f"EKU_BITS:           {len(EKU_BITS)}")
    print(f"ASN1_TYPES:         {len(ASN1_TYPES)}")
    print(f"OID_CONSTS:         {len(OID_CONSTS)}")
    print(f"NAMED_CONSTS:       {len(NAMED_CONSTS)}")
    print(f"STRING_FIELDS:      {len(STRING_FIELDS)}")
    print(f"STRING_LIST_FIELDS: {len(STRING_LIST_FIELDS)}")
    print(f"NUMERIC_FIELDS:     {len(NUMERIC_FIELDS)}")
    print(f"LIST_FIELDS:        {len(LIST_FIELDS)}")
    print(f"TIME_FIELDS:        {len(TIME_FIELDS)}")
    print(f"BOOL_FIELDS:        {len(BOOL_FIELDS)}")
    # quick sample
    print()
    print("first 3 CERT_FIELDS:", [(f.name, f.semantic) for f in CERT_FIELDS[:3]])
    print("first 3 DN_FIELDS:  ", [(f.name, f.semantic) for f in DN_FIELDS[:3]])
    print("Province exists?    ", "Subject.Province" in DN_BY_NAME)
    print("RDN map count:      ", len(RDN_TO_DN_NAME))
