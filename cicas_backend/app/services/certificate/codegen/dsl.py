"""templates_v2 / dsl.py — typed ATOM/COMPOUND DSL.

The LLM never writes Go. It outputs JSON tree of ATOMs / COMPOUNDs whose
node types are a closed set, every leaf argument referencing a name in
`vocab` (CERT_FIELDS / DN_FIELDS / OID_CONSTS / KU_BITS / etc.) or a
typed literal.

Validation:
  - parse(json_obj)  -> Compound  (or raises DSLError)
  - validate(node)   -> list[str] of errors  (empty = OK)
  - schema_for_llm() -> compact human-readable schema string for prompt embedding

Renderer lives in render.py.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, fields
from typing import Any, Optional, Union

from . import vocab as V


class DSLError(ValueError):
    pass


# =====================================================================
# ATOMS
# =====================================================================

@dataclass(frozen=True)
class ExtPresent:
    """True iff certificate has the extension with given OID."""
    oid: str  # OID_CONST name


@dataclass(frozen=True)
class HasAnyExtension:
    """True iff certificate has at least one extension (version >= 3 with non-empty
    Extensions field). Used for version guards: 'when extensions are used, version
    MUST be 3' maps to When(HasAnyExtension(), FieldEq(Version, 2)).

    GENERIC ATOM: parameter-free, applies universally to X.509 v3 certificates.
    Cert-oracle verified: can be tested on real certificates by checking
    len(cert.Extensions) > 0."""
    pass


@dataclass(frozen=True)
class ExtContentNonEmpty:
    """True iff the named extension's parsed content is a non-empty SEQUENCE
    (>=1 element) — for 'MUST NOT be an empty sequence' rules. Renderer is sound
    only for OIDs whose content zcrypto exposes (nameConstraints); refuses others."""
    oid: str  # OID_CONST name


@dataclass(frozen=True)
class ExtCritical:
    """True iff extension is present AND marked Critical."""
    oid: str


@dataclass(frozen=True)
class ExtNotCritical:
    """True iff extension is present AND NOT critical."""
    oid: str


@dataclass(frozen=True)
class IsCA:
    """True iff cert is a CA (BasicConstraints.IsCA == true)."""


@dataclass(frozen=True)
class IsRootCA:
    """True iff cert is a self-signed CA."""


@dataclass(frozen=True)
class IsSubCA:
    """True iff cert is a subordinate CA (CA certificate, not self-signed root)."""


@dataclass(frozen=True)
class PathLenConstraintPresent:
    """True iff basicConstraints carries a pathLenConstraint field. zcrypto exposes
    it via MaxPathLen (>=0 when present) / MaxPathLenZero (true when present and 0);
    absent encodes as MaxPathLen==-1 && !MaxPathLenZero. Universal PKI concept,
    observable from a single certificate."""


@dataclass(frozen=True)
class IsServerCert:
    """True iff cert has ExtKeyUsage ServerAuth."""


@dataclass(frozen=True)
class IsSubscriberCert:
    """True iff cert is a subscriber (non-CA) cert."""


@dataclass(frozen=True)
class IsEndEntity:
    """True iff cert is an end-entity (not a CA, i.e., subscriber/leaf)."""


@dataclass(frozen=True)
class KeyUsageHas:
    """True iff KeyUsage bitmap has the named bit set."""
    bit: str  # KEY_USAGE_BIT name


@dataclass(frozen=True)
class ExtKeyUsageHas:
    """True iff ExtKeyUsage list contains the named usage."""
    bit: str  # EKU_BIT name


@dataclass(frozen=True)
class FieldEq:
    """True iff CERT_FIELD or DN_FIELD equals literal value."""
    field: str
    value: Union[int, str]


@dataclass(frozen=True)
class FieldNonEmpty:
    """True iff field is set / list non-empty / string non-empty."""
    field: str


@dataclass(frozen=True)
class FieldEmpty:
    field: str


@dataclass(frozen=True)
class FieldMatchesRegex:
    """True iff string field value matches the named regex."""
    field: str
    pattern: str  # NAMED_REGEX name (validated against V.NAMED_REGEX_NAMES)


@dataclass(frozen=True)
class FieldInSet:
    field: str
    values: tuple


@dataclass(frozen=True)
class FieldNotInSet:
    field: str
    values: tuple


@dataclass(frozen=True)
class FieldLenInRange:
    """For LIST_FIELD or string field, len in [lo, hi] inclusive."""
    field: str
    lo: int
    hi: Union[int, str]   # int OR "MAX_INT"


@dataclass(frozen=True)
class FieldNumericInRange:
    """For numeric CERT_FIELD (int / bigint via cmp), value in [lo, hi]."""
    field: str
    lo: int
    hi: Union[int, str]


# =====================================================================
# SERIAL NUMBER CONSTRAINTS
# =====================================================================

@dataclass(frozen=True)
class SerialNumberPositive:
    """True iff serialNumber > 0 (positive integer per CABF BR 7.1 + RFC 5280).

    Handles the common "serial number MUST be a positive integer" constraint.
    serialNumber is a bigint in zcrypto; zero is represented as nil or 0.
    NON-GENERIC: corpus-specific shortcut for FieldNumericInRange(SerialNumber, 1, MAX_INT).

    cert-oracle verified: tested against certs with SN=1, SN=2^128, SN=0."""
    pass


@dataclass(frozen=True)
class SerialNumberOctetLengthInRange:
    """True iff the serialNumber's big-endian encoding fits in [lo, hi] octets.

    Handles "serialNumber MUST NOT be longer than 20 octets" (RFC 5380 s4.1.2.4).
    Vacuously true for empty/no serialNumber (nil big.Int).
    NON-GENERIC: scoped to serialNumber length rules.

    cert-oracle verified: tested against 8-octet, 16-octet, 20-octet, 21-octet certs."""
    lo: int
    hi: int


@dataclass(frozen=True)
class FieldCount:
    """Occurrence count (cardinality) of a LIST_FIELD in [lo, hi] inclusive.

    len(list) for a list-valued field ("at least one X", "no more than N X").
    Renders only for list semantics; non-list fields are refused (occurrence
    count is undefined there)."""
    field: str
    lo: int
    hi: Union[int, str]


@dataclass(frozen=True)
class RSAModulusBitsInRange:
    """RSA public-key modulus bit-length in [lo, hi]. Vacuously true for non-RSA
    keys (the constraint scopes to RSA keys; key type is a separate rule).
    General CABF/RFC concept (e.g. 'modulus MUST be >= 2048 bits'); zcrypto
    exposes the key via c.PublicKey.(*rsa.PublicKey).N.BitLen()."""
    lo: int
    hi: Union[int, str]


@dataclass(frozen=True)
class RSAPublicExponentInRange:
    """RSA public exponent value in [lo, hi]. Vacuously true for non-RSA keys.
    General concept (e.g. 'exponent MUST be an odd number >= 3'); reads
    c.PublicKey.(*rsa.PublicKey).E."""
    lo: int
    hi: Union[int, str]


@dataclass(frozen=True)
class FieldEncodedAs:
    """True iff field is encoded with one of the given ASN.1 string types."""
    field: str
    types: tuple


@dataclass(frozen=True)
class DNDirectoryStringValuesEncodedAs:
    """Every DN attribute value WHOSE X.520 syntax is DirectoryString is encoded
    with one of the given ASN.1 string tags; attributes with a non-DirectoryString
    syntax (countryName→PrintableString, domainComponent/emailAddress→IA5String,
    serialNumber→PrintableString, etc.) are SKIPPED, not failed.

    Models the common CABF/RFC 5280 §4.1.2.4 requirement "attribute values of type
    DirectoryString MUST use PrintableString or UTF8String, with exceptions" — the
    exceptions are exactly the non-DirectoryString attributes, so scoping the tag
    check to DirectoryString-syntax attributes is sound and general (driven by the
    X.520 attribute-OID→syntax table, not per-rule). dn ∈ {Subject, Issuer}."""
    dn: str
    types: tuple


@dataclass(frozen=True)
class DateAfter:
    """True iff later > earlier."""
    later: str    # DATE_FIELD name
    earlier: str


@dataclass(frozen=True)
class DateBefore:
    """True iff earlier < later. Either side may be a DATE_FIELD name OR a
    YYYY-MM-DD string literal."""
    earlier: str
    later: str


@dataclass(frozen=True)
class ListAllMatch:
    """For each item in LIST_FIELD, predicate must hold."""
    list_field: str
    predicate: 'Compound'


@dataclass(frozen=True)
class ListAnyMatch:
    list_field: str
    predicate: 'Compound'


@dataclass(frozen=True)
class ListUnique:
    """True iff list elements are pairwise distinct."""
    list_field: str


@dataclass(frozen=True)
class ItemMatchesRegex:
    """Inside ListAll/Any predicate: current item matches NAMED_REGEX."""
    pattern: str


@dataclass(frozen=True)
class ItemInSet:
    """Inside ListAll/Any predicate: current item is in literal set."""
    values: tuple


@dataclass(frozen=True)
class ItemEq:
    value: Union[int, str]


@dataclass(frozen=True)
class ItemLenIn:
    """Inside list iteration on an ip_list or ip_typed list: the item's
    byte-length must be in the given set. Used as the predicate in
    IPv4Conditional (e.g., IPv4 entries have len 4, IPv6 have len 16).
    item_var is always a []byte in this context."""
    counts: tuple   # tuple of ints, e.g. (4, 16)


@dataclass(frozen=True)
class ItemNotMatchesRegex:
    """Inside WildcardFilter/ListAllMatch predicate: item does NOT match the
    named regex. Use for 'MUST NOT contain forbidden pattern' in list
    contexts (e.g. R4718: DNS names with zero-length/empty labels)."""
    pattern: str   # NAMED_REGEX name


@dataclass(frozen=True)
class BytesEq:
    """Byte-wise equality between two []byte CERT_FIELDs (e.g. SKI vs AKI)."""
    field_a: str
    field_b: str


@dataclass(frozen=True)
class IPListAllOctetCount:
    """Every element of an ip_list field has byte length == count."""
    field: str
    count: int


@dataclass(frozen=True)
class OidListContains:
    """oid_list field contains the named OID constant."""
    field: str
    oid: str


@dataclass(frozen=True)
class OidListCountInSet:
    """The number of entries in an OID-list field whose OID is in allowed_oids is
    in [lo, hi] inclusive. Expresses "exactly one / at least N of {set}" — e.g.
    'contains exactly one Reserved Certificate Policy Identifier' over
    PolicyIdentifiers. allowed_oids: tuple[str] of OID_CONST names."""
    field: str
    allowed_oids: tuple
    lo: int
    hi: Union[int, str]


@dataclass(frozen=True)
class BytesEqualsHex:
    """True iff a []byte field's content equals the given hex literal."""
    field: str
    hex_lit: str


@dataclass(frozen=True)
class BytesContainsHex:
    """True iff a []byte field's content contains the given hex literal."""
    field: str
    hex_lit: str


@dataclass(frozen=True)
class ExtensionURISchemeNotInSet:
    """True iff no extension's extnValue contains a URI whose scheme is in the
    given set (negation of ExtensionURISchemeInSet). Used for 'SHOULD NOT
    include https:// / ldaps:// URIs in extensions' (r28449). Walks the raw
    DER of each extension looking for ia5String-encoded URI content, then checks
    the scheme prefix."""
    schemes: tuple  # e.g. ("https", "ldaps") — forbidden schemes


@dataclass(frozen=True)
class PublicKeyAlgorithmIs:
    """True iff c.PublicKeyAlgorithm equals one of the named algorithms.
    Allowed names: RSA, DSA, ECDSA, Ed25519, Ed448, X25519, X448."""
    algorithm: str


@dataclass(frozen=True)
class DNEmpty:
    """True iff the entire DN (Subject or Issuer) is the empty SEQUENCE."""
    holder: str  # "Subject" or "Issuer"


@dataclass(frozen=True)
class ExtRawValueEqualsHex:
    """True iff the named extension is present AND its raw extnValue bytes
    equal the given hex literal."""
    oid: str
    hex_lit: str


@dataclass(frozen=True)
class ExtRawValueContainsHex:
    """True iff the named extension is present AND its raw extnValue bytes
    contain the given hex literal as a sub-slice."""
    oid: str
    hex_lit: str


@dataclass(frozen=True)
class AlgorithmIdentifierBytesMatch:
    """True iff a specified algorithm identifier OID (e.g. PublicKeyAlgorithmOID,
    SignatureAlgorithmOID) has DER bytes equal to the given OID constant literal.
    For 'AlgorithmIdentifier MUST be byte-for-byte identical to {hex DER of OID}'
    rules.  Re-parses the AlgorithmIdentifier.algorithm field DER.
    GENERAL: valid for any OID constant; validated at construction."""
    oid_const: str   # e.g. "IdEcPublicKey", "IdSha256WithRSAEncryption"
    neg: bool = False  # True → "MUST NOT be these bytes"


@dataclass(frozen=True)
class PolicyQualifierOIDInSet:
    """True iff a CertificatePolicies extension's PolicyInformation entries each
    have PolicyQualifiers containing at least one qualifier with the given OID
    (e.g. IdQtCps, IdQtUnotice).  Used for rules like 'MUST contain only CPS
    pointer qualifiers' or 'MUST NOT contain User Notice qualifiers'.
    GENERAL: OID constants are standard PKI vocabulary. Re-parses the raw DER
    to walk PolicyInformation → PolicyQualifiers → PolicyQualifierInfo →
    policyQualifierId."""
    oid_const: str   # e.g. "IdQtCps" or "IdQtUnotice"


@dataclass(frozen=True)
class PolicyQualifierOIDNotInSet:
    """Negation of PolicyQualifierOIDInSet: at least one qualifier is present
    with the forbidden OID.  Convenience atom so the Not() wrapper is explicit
    in the tree rather than buried in the handler logic."""
    oid_const: str


@dataclass(frozen=True)
class ExtSubfieldPresent:
    """True iff the named extension is present AND its raw extnValue DER carries
    a context-tagged sub-element. Universal: parameterized by extension OID +
    ASN.1 context tag number + a human subfield label. The raw DER survives even
    when zcrypto's high-level parse discards the sub-field (e.g. AuthorityKeyId
    keeps only keyIdentifier, dropping authorityCertIssuer[1] and
    authorityCertSerialNumber[2]). Fail-closed: extension absent or undecodable
    DER ⇒ sub-field NOT present (never a false positive).

    path="" → context tag sits directly under the extnValue SEQUENCE (AKI)."""
    oid: str
    tag: int
    subfield: str = ""
    path: str = ""


@dataclass(frozen=True)
class AIAHasMethodOtherThan:
    """True iff the AccessDescription-shaped extension (AIA or SIA, named
    by ext_oid) is present AND it contains at least one AccessDescription
    whose accessMethod OID is NOT in the supplied allow-list. Operates on
    the raw extension DER (re-parsed via encoding/asn1) because zcrypto's
    parsed Certificate keeps only the caIssuers and ocsp methods for AIA,
    dropping caRepository / timeStamping / others. Generic shape: works
    for any rule that says 'extension MUST NOT include access methods
    other than {S}'. (Name retained for compatibility — applies to any
    AccessDescription-shaped extension, not just AIA.)"""
    ext_oid: str          # OID_CONST name (AiaOID or SubjectInfoAccessOID)
    allowed_oids: tuple   # tuple[str], each an OID_CONST name


@dataclass(frozen=True)
class AIAMethodLocationsTagInSet:
    """True iff every AccessDescription whose accessMethod equals
    method_oid (within the extension named by ext_oid) has a GeneralName
    tag in the allowed-tag set. Vacuously true when no entries of that
    method are present. Tags follow RFC 5280 GeneralName CHOICE numbering
    (1=rfc822Name, 2=dNSName, 4=directoryName, 6=URI, 7=iPAddress,
    8=registeredID). Generic shape: works for any rule of form
    'when accessMethod is M in extension E, accessLocation MUST be a
    {N1,...} name'."""
    ext_oid: str          # OID_CONST name
    method_oid: str       # OID_CONST name
    allowed_tags: tuple   # tuple[int]


@dataclass(frozen=True)
class AIAMethodLocationsAnyMatchRegex:
    """True iff AT LEAST ONE AccessDescription whose accessMethod equals
    method_oid (within the extension named by ext_oid) is a
    uniformResourceIdentifier (tag 6) AND whose bytes match NAMED_REGEX.
    Returns false when no matching method entries are present. Generic
    shape: works for any rule of form 'at least one accessLocation of
    method M in extension E SHOULD be a {scheme} URI'."""
    ext_oid: str       # OID_CONST name
    method_oid: str    # OID_CONST name
    pattern: str       # NAMED_REGEX name


@dataclass(frozen=True)
class CRLDPHasNameRelative:
    """True iff the CRL Distribution Points extension (OID 2.5.29.31) is
    present AND contains at least one DistributionPoint whose
    distributionPoint CHOICE is nameRelativeToCRLIssuer ([1]) rather
    than fullName ([0]). zcrypto's parsed CRLDistributionPoints exposes
    only fullName URIs; this atom re-parses the raw extension DER to see
    the CHOICE alternative. Zero-arg. Generic shape: any rule of form
    'CAs MUST/SHOULD NOT use nameRelativeToCRLIssuer'."""
    pass


@dataclass(frozen=True)
class CRLDPHasNameRelativeWithMultiIssuer:
    """True iff the CRL Distribution Points extension is present AND
    contains at least one DistributionPoint whose distributionPoint
    CHOICE is nameRelativeToCRLIssuer AND whose cRLIssuer field contains
    more than one GeneralName. Re-parses raw DER. Zero-arg. Generic
    shape: 'MUST NOT use nameRelativeToCRLIssuer when cRLIssuer contains
    more than one distinguished name'."""
    pass


@dataclass(frozen=True)
class ValidityDateAsn1TagInSet:
    """True iff the ASN.1 universal-class tag of the named validity-date
    field's encoding (read from c.RawTBSCertificate) is in the allowed
    asn1_tag set. Tags follow the ASN.1 universal class: UTCTime (23)
    or GeneralizedTime (24). Re-parses TBSCertificate raw DER because
    zcrypto exposes c.NotBefore / c.NotAfter as parsed time.Time, losing
    the original ASN.1 tag. Generic shape: any rule of form 'validity
    date <field> MUST/MUST NOT be encoded as {tag1, ...}'."""
    date_field: str       # "NotBefore" or "NotAfter"
    allowed_tags: tuple   # tuple[str] of ASN1_TYPE names


@dataclass(frozen=True)
class CertPolicyExplicitTextHasEncodingTagInSet:
    """True iff CertificatePolicies extension is present AND contains at
    least one explicitText (within UserNotice user qualifier, OID
    id-qt-unotice 1.3.6.1.5.5.7.2.2) whose DisplayText CHOICE tag is in
    the allowed asn1_tag set. DisplayText is a CHOICE of IA5String /
    VisibleString / BMPString / UTF8String — the CHOICE tag is the
    encoding's universal-class tag (22 / 26 / 30 / 12 respectively).
    Re-parses certificatePolicies extension raw DER, walks through
    PolicyInformation / PolicyQualifierInfo / UserNotice. Zero-arg
    extension targeting (uses id-ce-certificatePolicies). Generic shape:
    any rule of form 'explicitText MUST NOT be encoded as {types}'."""
    allowed_tags: tuple   # tuple[str] of ASN1_TYPE names


@dataclass(frozen=True)
class AlgorithmIdentifierBytesMatch:
    """True iff a specified algorithm identifier OID (e.g. PublicKeyAlgorithmOID,
    SignatureAlgorithmOID) has DER bytes equal to the given OID constant literal.
    For 'AlgorithmIdentifier MUST be byte-for-byte identical to {hex DER of OID}'
    rules.  Re-parses the AlgorithmIdentifier.algorithm field DER.
    GENERAL: valid for any OID constant; validated at construction."""
    oid_const: str   # e.g. "IdEcPublicKey", "IdSha256WithRSAEncryption"
    neg: bool = False  # True → "MUST NOT be these bytes"


@dataclass(frozen=True)
class OidEq:
    """True iff a single OID-typed cert field equals the named OID constant."""
    field: str
    oid: str


@dataclass(frozen=True)
class SubtreeIPListAnyHasOctetCount:
    """True iff at least one entry in a NameConstraints subtree IP list has
    total bytes (IP+Mask) == count. count: 8 = IPv4 addr+mask, 32 = IPv6."""
    field: str
    count: int


@dataclass(frozen=True)
class BytesContainsOidDer:
    """True iff bytes-typed cert field contains the DER encoding of a named OID."""
    field: str
    oid: str


@dataclass(frozen=True)
class IPListAllOctetCountIn:
    """Every element of an ip_list field has byte length in the given allowed set.
    Used for "each iPAddress is either 4 (IPv4) or 16 (IPv6) octets" type rules
    where the list mixes versions and a single octet count is too strict."""
    field: str
    counts: tuple   # tuple of ints, e.g. (4,16)


@dataclass(frozen=True)
class SubtreeIPListAnyAllZero:
    """True iff at least one entry in a NameConstraints subtree IP list has
    total bytes (IP+Mask) == count AND every byte is zero. Used for the
    'must include iPAddress of N zero octets indicating range 0/0' rules."""
    field: str
    count: int  # 8 = IPv4 0.0.0.0/0, 32 = IPv6 ::0/0


@dataclass(frozen=True)
class SubtreeIPListAnyHasOctetCountAndNotAllZero:
    """True iff at least one entry in a NameConstraints subtree IP list has
    total bytes (IP+Mask) == count AND has at least one non-zero byte. The
    'real entry' counterpart to SubtreeIPListAnyAllZero. Use as the left arm
    of an Or with SubtreeIPListAnyAllZero to express the rule
    'permittedSubtrees MUST contain a real IPv6 entry OR the ::0/0 marker'
    (R4633), and similarly for IPv4 (R4632)."""
    field: str
    count: int  # 8 = IPv4, 32 = IPv6


@dataclass(frozen=True)
class SubtreeStringListAllMatch:
    """For each entry in a subtree_list (string-typed: PermittedDNSNames,
    ExcludedDNSNames, PermittedURIs, ...), apply predicate to its .Data
    string. Used for 'permitted subtree entries MUST be FQDN' style rules."""
    field: str
    predicate: 'Compound'


@dataclass(frozen=True)
class SubtreeStringListAnyMatch:
    field: str
    predicate: 'Compound'


@dataclass(frozen=True)
class SubtreeStringListAllMatchOrEmpty:
    """Like SubtreeStringListAllMatch but vacuously TRUE when the subtree
    list is empty. Use for NameConstraints "if X is constrained in
    permittedSubtrees/excludedSubtrees, all entries must be Y" rules where
    only the populated side(s) need to satisfy the constraint — combine
    with And over (permitted, excluded) to express "every populated
    side has all-valid entries"."""
    field: str
    predicate: 'Compound'


@dataclass(frozen=True)
class SubtreeIPListAllOctetCountIn:
    """Every entry in a NameConstraints subtree IP list has total bytes
    (IP+Mask) in the given allowed set. Used for "each iPAddress entry
    MUST be IPv4 (8 octets total) or IPv6 (32 octets total)" rules."""
    field: str
    counts: tuple


@dataclass(frozen=True)
class SubtreeIPMaskValidCIDR:
    """Every entry in a NameConstraints subtree IP list has its mask
    portion (Data.Mask) in valid CIDR form: contiguous high-order 1-bits
    followed by zeros (per RFC 4632). Used for "iPAddress MUST be encoded
    in the style of RFC 4632 (CIDR)" rules (R4007 IPv4 NameConstraints
    subtree, also applies to IPv6 subtree masks). IP-version-agnostic:
    operates on whatever mask bytes the entry carries (4 bytes for IPv4
    subtree, 16 bytes for IPv6). Vacuously TRUE when the field is empty."""
    field: str


@dataclass(frozen=True)
class NotAfterIsNoExpirySentinel:
    """True iff the certificate's notAfter is the RFC 5280 §4.1.2.5 "no
    well-defined expiration date" sentinel — the GeneralizedTime value
    99991231235959Z (year 9999, Dec 31, 23:59:59 UTC). Zero-arg: zcrypto exposes
    notAfter as time.Time, so the check is c.NotAfter year/month/day/time match.
    General RFC concept (the does-not-expire marker), not per-rule."""


@dataclass(frozen=True)
class CrossFieldEq:
    """True iff two scalar fields have equal values (string-to-string or
    int-to-int). NOT for scalar-vs-list. Use ScalarInList for "CN in DNSNames".
    Used for cross-field comparisons (R5116 if CN and SAN are separate scalars
    rather than a list)."""
    field_a: str
    field_b: str


@dataclass(frozen=True)
class SigAlgMatchesTBSSignature:
    """True iff the certificate's signatureAlgorithm field is byte-for-byte
    identical to the tbsCertificate.signature field (RFC 5280 §4.1.1.2/§4.1.2.3).
    Zero-arg: the comparison re-parses the cert DER (mirrors zlint's
    e_mismatched_signature_algorithm_identifier). Unconditional / always-applies."""


@dataclass(frozen=True)
class CommonNameFromSAN:
    """True iff subject commonName, when present, equals one of the SAN
    dNSName / iPAddress entries (RFC 5280 §4.2.1.6; CABF BR — commonName MUST
    contain a value from the subjectAltName extension). Zero-arg within-cert
    cross-field check; mirrors zlint's e_subject_common_name_not_from_san.
    Vacuously true when commonName is empty."""


@dataclass(frozen=True)
class FieldContains:
    """True iff the string field value (or each string in the list) contains
    the given character substring. Used for rules like "CN MUST NOT contain
    '@' or '_' characters" (R4188) where a character-set check is needed."""
    field: str
    substring: str   # a single character or short string to search for


@dataclass(frozen=True)
class FieldNotMatchesRegex:
    """True iff string field value does NOT match the named regex.
    Used for rules like "FQDN MUST be composed only of non-reserved LDH
    labels" (R4717) where forbidden patterns must be absent."""
    field: str
    pattern: str      # NAMED_REGEX name (validated against V.NAMED_REGEX_NAMES)


@dataclass(frozen=True)
class WildcardFilter:
    """For LIST_FIELD: if any entry starts with prefix (e.g. '*.' for
    wildcard DNS names), that entry MUST satisfy predicate. Non-matching
    entries pass automatically. Used for "wildcard domains must be valid
    LDH-labels" rules where only wildcard entries are constrained (R4829)."""
    list_field: str
    prefix: str       # e.g. "*." — entries starting with this prefix are checked
    predicate: 'Compound'


@dataclass(frozen=True)
class ScalarInList:
    """True iff the scalar_field value (when non-empty) appears as an element
    in list_field. Used for 'CN must appear in DNSNames' (R5116): the
    Subject.CommonName string must equal at least one DNSNames entry.

    The predicate is true when: scalar_field is empty OR scalar_field
    appears in list_field. This naturally handles the CN-if-present
    semantics via a ListAnyMatch wrapping.

    Scalar must be string|bigint semantic; list must be string_list."""
    scalar_field: str   # e.g. "Subject.CommonName"
    list_field: str     # e.g. "DNSNames"


@dataclass(frozen=True)
class ScalarInAnyOfLists:
    """True iff the scalar_field value (when non-empty) appears as an element
    in AT LEAST ONE of the named list_fields. Generalizes ScalarInList over
    multiple list fields with an implicit OR. Use for "CN must be derived
    from subjectAltName (any SAN type)" rules where the scalar must appear
    in DNSNames OR EmailAddresses OR URIs OR ..."""
    scalar_field: str
    list_fields: tuple   # tuple of str list-field names


@dataclass(frozen=True)
class IPv4Conditional:
    """For ip_list fields: if the list contains any IPv4 entries (4-byte
    items), each MUST satisfy ipv4_predicate; if it contains any IPv6
    entries (16-byte), each MUST satisfy ipv6_predicate. Both predicates
    must apply to ALL entries of their respective version (cross-check).
    Used for "if IPv4 present, each must be 4 bytes; if IPv6, each 16"
    (R5151) style rules."""
    field: str
    ipv4_predicate: 'Compound'
    ipv6_predicate: 'Compound'


@dataclass(frozen=True)
class SubtreeIPv4Conditional:
    """Mirror of IPv4Conditional for NameConstraints subtree IP lists
    (go_type []GeneralSubtreeIP). For each entry _s in the subtree list:
    if len(_s.Data.IP) == 4 (IPv4 subtree), ipv4_predicate must hold;
    if len(_s.Data.IP) == 16 (IPv6 subtree), ipv6_predicate must hold.
    Item predicates are evaluated with iteration variable equal to the
    total subtree-entry byte length (len(IP) + len(Mask)) — so
    ItemLenIn([8]) means "total 8 bytes" (IPv4 subtree canonical:
    4 IP + 4 mask). Use for "IPv4 subtree MUST be 8 octets, IPv6 subtree
    MUST be 32 octets" rules where one or both clauses are constrained.
    For asymmetric rules (atomic constrains only one version), use the
    self-tautology pattern: ItemLenIn([CANONICAL_SIZE]) on the
    unconstrained branch (always true given net.IP type guarantees)."""
    field: str
    ipv4_predicate: 'Compound'
    ipv6_predicate: 'Compound'


@dataclass(frozen=True)
class ExtHasGeneralNameWithTag:
    """ENCODING CHECK (NOT a presence check). True iff EVERY GeneralName
    CHOICE entry in the named extension that has the specified tag is
    IA5String-encoded. Wraps zlint util.AllAlternateNameWithTagAreIA5.
    The function returns vacuously TRUE when there are zero entries of
    the given tag — so this atom CANNOT be used to detect presence /
    absence of a GeneralName type. Use ExtHasAnyGeneralNameOfTag for
    presence checks. Tag numbering follows RFC 5280 §4.2.1.6 GeneralName
    CHOICE: 0=otherName, 1=rfc822Name, 2=dNSName, 3=x400Address,
    4=directoryName, 5=ediPartyName, 6=URI, 7=iPAddress, 8=registeredID.
    Use for "rfc822Name MUST be IA5String"-shape rules where the rule
    constrains the encoding of one CHOICE alternative."""
    oid: str   # extension OID constant
    tag: int   # ASN.1 CHOICE tag number


@dataclass(frozen=True)
class ExtHasAnyGeneralNameOfTag:
    """PRESENCE CHECK. True iff the named extension is present AND
    contains at least one GeneralName CHOICE entry with the specified
    tag. Re-parses the raw extension SEQUENCE OF GeneralName because
    zcrypto's parsed Certificate exposes only a few CHOICE alternatives
    (DNSNames, EmailAddresses, URIs, IPAddresses) — directoryName,
    otherName, ediPartyName, registeredID are dropped at parse time.
    Tag numbering follows RFC 5280 §4.2.1.6 GeneralName CHOICE:
    0=otherName, 1=rfc822Name, 2=dNSName, 3=x400Address, 4=directoryName,
    5=ediPartyName, 6=URI, 7=iPAddress, 8=registeredID. Use for
    "directoryName NOT RECOMMENDED in SAN" / "MUST contain at least one
    dNSName" shape rules."""
    oid: str   # extension OID constant (SubjectAlternateNameOID etc.)
    tag: int   # ASN.1 CHOICE tag number


@dataclass(frozen=True)
class DomainComponentOrdered:
    """True iff the Subject DN contains domainComponent fields in a single
    contiguous ordered sequence (no gaps, no intervening non-DC RDN types).
    Empty Organization is allowed as a precondition. The rule requires
    "domainComponent fields MUST be in a single ordered sequence" (R4660)."""


@dataclass(frozen=True)
class RDNCountInRange:
    """True iff the RDNSequence (Subject or Issuer) contains a number of
    RelativeDistinguishedName entries in [lo, hi] inclusive. Used for
    "Subject DN MUST NOT contain more than one RDN" style rules (R29771:
    uniqueness of AttributeTypeAndValue across all RDNs). Vacuously true
    when the DN is empty.

    NON_GENERIC: encodes RDN cardinality semantics specific to DN uniqueness
    rules, not a general-purpose counter over arbitrary lists."""
    holder: str        # "Subject" or "Issuer"
    lo: int
    hi: Union[int, str]


@dataclass(frozen=True)
class RDNHasSingleAttribute:
    """True iff every RelativeDistinguishedName in the holder DN contains
    exactly one AttributeTypeAndValue element (no multi-AV RDNs). Used for
    R29558: "Each RDN MUST contain exactly one AttributeTypeAndValue".

    Vacuously true when the DN is empty. NON_GENERIC: RDN cardinality
    semantics pinned to the single-AV requirement of RFC 5280 §4.1.2.6."""
    holder: str        # "Subject" or "Issuer"


@dataclass(frozen=True)
class RDNSequenceHasCountryBefore:
    """True iff in the RDNSequence of the holder DN, if there exists an RDN
    containing a countryName AttributeTypeAndValue AND an RDN containing a
    stateOrProvinceName AttributeTypeAndValue, the countryName RDN appears
    BEFORE the stateOrProvinceName RDN (lexicographically earlier in the
    sequence). Used for R29559: "countryName RDN MUST be encoded before
    stateOrProvinceName RDN in the RDNSequence".

    Vacuously true when either attribute type is absent. NON_GENERIC:
    pinned to the country-before-state ordering constraint of RFC 6818."""
    holder: str        # "Subject" or "Issuer"


# =====================================================================
# COMPOUNDS
# =====================================================================

@dataclass(frozen=True)
class Not:
    inner: 'Compound'


@dataclass(frozen=True)
class When:
    """Conditional: when cond holds, main must hold. Bridge-equivalent to app-side
    dsl.When (same field order, same semantics)."""
    cond: 'Compound'
    main: 'Compound'


@dataclass(frozen=True)
class And:
    parts: tuple
    # Normalize list→tuple so the field is always a tuple, regardless of how the
    # constructor is called (direct, from dict, or via parse()).  Python 3.12+
    # disallows __post_init__(self, parts) for frozen=True; __new__ intercepts
    # before the frozen lock so we can re-assign via object.__setattr__.
    def __new__(cls, **kw):
        if 'parts' in kw and isinstance(kw['parts'], list):
            kw = dict(kw, parts=tuple(kw['parts']))
        return super().__new__(cls)


@dataclass(frozen=True)
class Or:
    parts: tuple
    def __new__(cls, **kw):
        if 'parts' in kw and isinstance(kw['parts'], list):
            kw = dict(kw, parts=tuple(kw['parts']))
        return super().__new__(cls)


# =====================================================================
# Type registry
# =====================================================================

Atom = Union[
    ExtPresent, ExtCritical, ExtNotCritical, ExtContentNonEmpty,
    IsCA, IsRootCA, IsSubCA, PathLenConstraintPresent, IsServerCert, IsSubscriberCert, IsEndEntity,
    KeyUsageHas, ExtKeyUsageHas,
    FieldEq, FieldNonEmpty, FieldEmpty,
    FieldMatchesRegex, FieldNotMatchesRegex, FieldInSet, FieldNotInSet,
    FieldLenInRange, FieldNumericInRange, FieldCount, FieldEncodedAs, DNDirectoryStringValuesEncodedAs, FieldContains,
    CrossFieldEq,
    DateAfter, DateBefore,
    ListAllMatch, ListAnyMatch, ListUnique, WildcardFilter,
    ItemMatchesRegex, ItemInSet, ItemEq, ItemLenIn, ItemNotMatchesRegex,
    BytesEq, IPListAllOctetCount, OidListContains, OidListCountInSet,
    BytesEqualsHex, BytesContainsHex, ExtensionURISchemeNotInSet,
    PublicKeyAlgorithmIs, DNEmpty,
    ExtRawValueEqualsHex, ExtRawValueContainsHex, ExtSubfieldPresent,
    AIAHasMethodOtherThan, AIAMethodLocationsTagInSet,
    AIAMethodLocationsAnyMatchRegex,
    CRLDPHasNameRelative, CRLDPHasNameRelativeWithMultiIssuer,
    ValidityDateAsn1TagInSet, CertPolicyExplicitTextHasEncodingTagInSet,
    PolicyQualifierOIDInSet, PolicyQualifierOIDNotInSet,
    OidEq, SubtreeIPListAnyHasOctetCount,
    BytesContainsOidDer,
    IPListAllOctetCountIn, SubtreeIPListAnyAllZero,
    SubtreeIPListAnyHasOctetCountAndNotAllZero,
    SubtreeStringListAllMatch, SubtreeStringListAnyMatch,
    SubtreeStringListAllMatchOrEmpty,
    SubtreeIPListAllOctetCountIn, SubtreeIPMaskValidCIDR,
    ScalarInList, ScalarInAnyOfLists, IPv4Conditional,
    SubtreeIPv4Conditional,
    ExtHasGeneralNameWithTag, ExtHasAnyGeneralNameOfTag, DomainComponentOrdered,
    RSAModulusBitsInRange, RSAPublicExponentInRange,
    SigAlgMatchesTBSSignature, NotAfterIsNoExpirySentinel,
    CommonNameFromSAN,
    RDNCountInRange, RDNHasSingleAttribute, RDNSequenceHasCountryBefore,
]
Compound = Union[Atom, Not, And, Or]

ATOM_CLASSES: dict[str, type] = {cls.__name__: cls for cls in [
    ExtPresent, HasAnyExtension, ExtCritical, ExtNotCritical, ExtContentNonEmpty,
    IsCA, IsRootCA, IsSubCA, PathLenConstraintPresent, IsServerCert, IsSubscriberCert, IsEndEntity,
    KeyUsageHas, ExtKeyUsageHas,
    FieldEq, FieldNonEmpty, FieldEmpty,
    FieldMatchesRegex, FieldNotMatchesRegex, FieldInSet, FieldNotInSet,
    FieldLenInRange, FieldNumericInRange, FieldCount, FieldEncodedAs, DNDirectoryStringValuesEncodedAs, FieldContains,
    CrossFieldEq,
    DateAfter, DateBefore,
    ListAllMatch, ListAnyMatch, ListUnique, WildcardFilter,
    ItemMatchesRegex, ItemInSet, ItemEq, ItemLenIn, ItemNotMatchesRegex,
    BytesEq, IPListAllOctetCount, OidListContains, OidListCountInSet,
    BytesEqualsHex, BytesContainsHex, ExtensionURISchemeNotInSet,
    PublicKeyAlgorithmIs, DNEmpty,
    ExtRawValueEqualsHex, ExtRawValueContainsHex, ExtSubfieldPresent,
    AIAHasMethodOtherThan, AIAMethodLocationsTagInSet,
    AIAMethodLocationsAnyMatchRegex,
    CRLDPHasNameRelative, CRLDPHasNameRelativeWithMultiIssuer,
    ValidityDateAsn1TagInSet, CertPolicyExplicitTextHasEncodingTagInSet,
    PolicyQualifierOIDInSet, PolicyQualifierOIDNotInSet,
    OidEq, SubtreeIPListAnyHasOctetCount,
    BytesContainsOidDer,
    IPListAllOctetCountIn, SubtreeIPListAnyAllZero,
    SubtreeIPListAnyHasOctetCountAndNotAllZero,
    SubtreeStringListAllMatch, SubtreeStringListAnyMatch,
    SubtreeStringListAllMatchOrEmpty,
    SubtreeIPListAllOctetCountIn, SubtreeIPMaskValidCIDR,
    ScalarInList, ScalarInAnyOfLists, IPv4Conditional,
    SubtreeIPv4Conditional,
    ExtHasGeneralNameWithTag, ExtHasAnyGeneralNameOfTag, DomainComponentOrdered,
    RSAModulusBitsInRange, RSAPublicExponentInRange,
    SigAlgMatchesTBSSignature, NotAfterIsNoExpirySentinel,
    CommonNameFromSAN,
    RDNCountInRange, RDNHasSingleAttribute, RDNSequenceHasCountryBefore,
    SerialNumberPositive, SerialNumberOctetLengthInRange,
]}

COMPOUND_CLASSES: dict[str, type] = {"Not": Not, "And": And, "Or": Or}

# ---------------------------------------------------------------------
# Atom genericity classification (GENERIC vs NON_GENERIC).
#
# Judged by the two-axis rule (NOT by argument count): an atom is GENERIC iff
#   (1) it denotes a *general* PKI concept — a class of certificate-attribute
#       judgement reusable across rules — AND
#   (2) it is parameterised over a field/value and bound to no specific rule_id
#       / corpus-specific OID / single clause.
# An atom is NON_GENERIC when its logic is specialised to one extension's inner
# structure or a single RFC/CABF clause (even if it takes parameters, the
# semantics are pinned to that one construct). Zero-arg atoms can be EITHER
# (IsCA is generic; NotAfterIsNoExpirySentinel is non-generic).
#
# NON_GENERIC atoms are admissible in codegen (per the 2026-06-22 authorisation)
# but MUST be labelled as such. This set is the single source of truth; the
# assertion below guarantees it stays a partition of ATOM_CLASSES.
# ---------------------------------------------------------------------
NON_GENERIC_ATOMS: frozenset[str] = frozenset({
    "CommonNameFromSAN",                 # CABF CN-must-come-from-SAN, single requirement
    "SigAlgMatchesTBSSignature",         # RFC5280 sigAlg==tbsCert.signature, single structural rule
    "NotAfterIsNoExpirySentinel",        # RFC5280 §4.1.2.5 99991231235959Z sentinel, single value
    "DomainComponentOrdered",            # DC contiguous-ordered, single rule
    "DNDirectoryStringValuesEncodedAs",  # DirectoryString per-attr + fixed exception-OID table
    "CertPolicyExplicitTextHasEncodingTagInSet",  # certPolicies UserNotice explicitText, one construct
    "PolicyQualifierOIDInSet",           # certPolicies policyQualifierId OID set, specific extension
    "PolicyQualifierOIDNotInSet",        # certPolicies policyQualifierId OID exclusion, specific
    "CRLDPHasNameRelative",              # CRLDP nameRelativeToCRLIssuer, one construct
    "CRLDPHasNameRelativeWithMultiIssuer",
    "AIAHasMethodOtherThan",             # AIA accessMethod-specific
    "AIAMethodLocationsAnyMatchRegex",
    "AIAMethodLocationsTagInSet",
    "IPv4Conditional",                   # IPv4-specific conditional shape
    "SubtreeIPv4Conditional",
    "SubtreeIPListAnyAllZero",           # NameConstraints 0/0 range marker, specific
    "SubtreeIPListAnyHasOctetCountAndNotAllZero",
    "SubtreeIPMaskValidCIDR",            # NameConstraints mask CIDR validity, specific
    "WildcardFilter",                    # wildcard-specific
    "RDNCountInRange",                   # RDN cardinality in DN uniqueness rules, specific
    "RDNHasSingleAttribute",             # single-AV-per-RDN requirement, RFC 5280 §4.1.2.6
    "RDNSequenceHasCountryBefore",       # country-before-state ordering, RFC 6818
    "SerialNumberPositive",              # serialNumber > 0, RFC 5280 + CABF BR 7.1
    "SerialNumberOctetLengthInRange",    # serialNumber byte length, RFC 5280 §4.1.2.4
})
GENERIC_ATOMS: frozenset[str] = frozenset(ATOM_CLASSES) - NON_GENERIC_ATOMS

# Partition integrity: every NON_GENERIC name must be a real atom, and the two
# sets must together cover ATOM_CLASSES with no overlap.
assert NON_GENERIC_ATOMS <= set(ATOM_CLASSES), (
    "NON_GENERIC_ATOMS contains unknown atom(s): "
    f"{NON_GENERIC_ATOMS - set(ATOM_CLASSES)}")
assert GENERIC_ATOMS | NON_GENERIC_ATOMS == set(ATOM_CLASSES)
assert not (GENERIC_ATOMS & NON_GENERIC_ATOMS)


def atom_genericity(name: str) -> str:
    """Return 'GENERIC' / 'NON_GENERIC' for an atom class name (or 'UNKNOWN')."""
    if name in NON_GENERIC_ATOMS:
        return "NON_GENERIC"
    if name in GENERIC_ATOMS:
        return "GENERIC"
    return "UNKNOWN"


# =====================================================================
# Parse (JSON -> typed tree)
# =====================================================================

def _expect_args(fname: str, args: list, n: int, sig: str):
    if len(args) != n:
        raise DSLError(f"{fname} expects {n} args ({sig}), got {len(args)}")


def _lit(v):
    if isinstance(v, (int, str)):
        return v
    raise DSLError(f"literal must be int or string, got {type(v).__name__}: {v!r}")


_RESERVED_POLICY_OIDS = (
    "OidPolicyDomainValidated",
    "OidPolicyOrganizationValidated",
    "OidPolicyIndividualValidated",
    "OidPolicyExtendedValidation",
)

_OID_ALIASES = {
    "2.5.29.32.0": "AnyPolicyOID",
    "anypolicy": "AnyPolicyOID",
    "anypolicyoid": "AnyPolicyOID",
    "any policy": "AnyPolicyOID",
    "2.23.140.1.2.1": "OidPolicyDomainValidated",
    "2.23.140.1.2.2": "OidPolicyOrganizationValidated",
    "2.23.140.1.2.3": "OidPolicyIndividualValidated",
    "2.23.140.1.1": "OidPolicyExtendedValidation",
    "reserved certificate policy identifier": "__RESERVED_POLICY_SET__",
    "reserved policy identifier": "__RESERVED_POLICY_SET__",
    "cabf reserved certificate policy identifier": "__RESERVED_POLICY_SET__",
}

_OP_ALIASES = {
    "OidListCountIn": "OidListCountInSet",
}


def _norm_oid_name(v) -> str:
    if not isinstance(v, str):
        raise DSLError(f"OID_CONST must be string, got {type(v).__name__}: {v!r}")
    s = v.strip().strip("`")
    if s in V.OID_BY_NAME:
        return s
    key = re.sub(r"[_-]+", " ", s.lower()).strip()
    key = re.sub(r"\s+", " ", key)
    return _OID_ALIASES.get(key, s)


def _norm_oid_list(v) -> tuple:
    if not isinstance(v, list):
        raise DSLError("OID list arg must be list")
    out = []
    for item in v:
        name = _norm_oid_name(item)
        if name == "__RESERVED_POLICY_SET__":
            out.extend(_RESERVED_POLICY_OIDS)
        else:
            out.append(name)
    return tuple(out)


def _int_or_maxint(v):
    if isinstance(v, int):
        return v
    if isinstance(v, str) and v == "MAX_INT":
        return "MAX_INT"
    raise DSLError(f"expected int or 'MAX_INT', got {v!r}")


def parse(obj: Any) -> Compound:
    """Parse a JSON object/dict into a typed DSL Compound node.
    Raises DSLError on shape errors."""
    if not isinstance(obj, dict):
        raise DSLError(f"expected dict, got {type(obj).__name__}: {obj!r}")
    op = obj.get("op")
    args = obj.get("args", [])
    if not isinstance(op, str):
        raise DSLError(f"missing 'op' field, got {obj!r}")
    op = _OP_ALIASES.get(op, op)
    if not isinstance(args, list):
        raise DSLError(f"'args' must be a list, got {type(args).__name__}")

    # Compounds first
    if op == "Not":
        _expect_args(op, args, 1, "<compound>")
        return Not(inner=parse(args[0]))
    if op == "And":
        if len(args) < 1:
            raise DSLError("And needs at least 1 arg")
        return And(parts=tuple(parse(a) for a in args))
    if op == "Or":
        if len(args) < 1:
            raise DSLError("Or needs at least 1 arg")
        return Or(parts=tuple(parse(a) for a in args))
    if op == "When":
        _expect_args(op, args, 2, "<cond> <main>")
        return When(cond=parse(args[0]), main=parse(args[1]))

    if op not in ATOM_CLASSES:
        raise DSLError(f"unknown op '{op}'. valid: "
                       f"{sorted(set(ATOM_CLASSES) | set(COMPOUND_CLASSES))}")

    cls = ATOM_CLASSES[op]
    fname = op

    # zero-arg predicates
    if cls in (IsCA, IsRootCA, IsSubCA, PathLenConstraintPresent, IsServerCert, IsSubscriberCert, IsEndEntity,
               SigAlgMatchesTBSSignature, NotAfterIsNoExpirySentinel, CommonNameFromSAN):
        _expect_args(fname, args, 0, "(no args)")
        return cls()

    if cls in (ExtPresent, ExtCritical, ExtNotCritical, ExtContentNonEmpty):
        _expect_args(fname, args, 1, "<OID_CONST>")
        return cls(oid=str(args[0]))

    if cls is KeyUsageHas:
        _expect_args(fname, args, 1, "<KEY_USAGE_BIT>")
        return cls(bit=str(args[0]))
    if cls is ExtKeyUsageHas:
        _expect_args(fname, args, 1, "<EKU_BIT>")
        return cls(bit=str(args[0]))

    if cls is FieldEq:
        _expect_args(fname, args, 2, "<FIELD> <int|str literal>")
        return cls(field=str(args[0]), value=_lit(args[1]))
    if cls in (FieldNonEmpty, FieldEmpty):
        _expect_args(fname, args, 1, "<FIELD>")
        return cls(field=str(args[0]))
    if cls is FieldMatchesRegex:
        _expect_args(fname, args, 2, "<STRING_FIELD> <NAMED_REGEX>")
        regex_name = str(args[1])
        if regex_name not in V.NAMED_REGEX_NAMES:
            raise DSLError(
                f"FieldMatchesRegex: unknown named regex '{regex_name}'. "
                f"Free-form regex literals are not allowed; pick one of: "
                f"{sorted(V.NAMED_REGEX_NAMES)}")
        return cls(field=str(args[0]), pattern=regex_name)
    if cls in (FieldInSet, FieldNotInSet):
        _expect_args(fname, args, 2, "<FIELD> [<lit>...]")
        if not isinstance(args[1], list):
            raise DSLError(f"{fname}: second arg must be list")
        return cls(field=str(args[0]), values=tuple(_lit(v) for v in args[1]))
    if cls is FieldLenInRange:
        _expect_args(fname, args, 3, "<LIST_FIELD> <lo:int> <hi:int|MAX_INT>")
        return cls(field=str(args[0]), lo=int(args[1]), hi=_int_or_maxint(args[2]))
    if cls is FieldCount:
        _expect_args(fname, args, 3, "<LIST_FIELD> <lo:int> <hi:int|MAX_INT>")
        return cls(field=str(args[0]), lo=int(args[1]), hi=_int_or_maxint(args[2]))
    if cls is FieldNumericInRange:
        _expect_args(fname, args, 3, "<NUMERIC_FIELD> <lo:int> <hi:int|MAX_INT>")
        return cls(field=str(args[0]), lo=int(args[1]), hi=_int_or_maxint(args[2]))
    if cls in (RSAModulusBitsInRange, RSAPublicExponentInRange):
        _expect_args(fname, args, 2, "<lo:int> <hi:int|MAX_INT>")
        return cls(lo=int(args[0]), hi=_int_or_maxint(args[1]))
    if cls is FieldEncodedAs:
        _expect_args(fname, args, 2, "<FIELD> [<ASN1_TYPE>...]")
        if not isinstance(args[1], list):
            raise DSLError(f"{fname}: second arg must be list of ASN1_TYPEs")
        return cls(field=str(args[0]), types=tuple(str(t) for t in args[1]))

    if cls is DNDirectoryStringValuesEncodedAs:
        _expect_args(fname, args, 2, "<dn:Subject|Issuer> [<ASN1_TYPE>...]")
        if not isinstance(args[1], list):
            raise DSLError(f"{fname}: second arg must be list of ASN1_TYPEs")
        return cls(dn=str(args[0]), types=tuple(str(t) for t in args[1]))

    if cls is DateAfter:
        _expect_args(fname, args, 2, "<later DATE_FIELD> <earlier DATE_FIELD>")
        return cls(later=str(args[0]), earlier=str(args[1]))
    if cls is DateBefore:
        _expect_args(fname, args, 2, "<earlier DATE|YYYY-MM-DD> <later DATE|YYYY-MM-DD>")
        return cls(earlier=str(args[0]), later=str(args[1]))

    if cls in (ListAllMatch, ListAnyMatch):
        _expect_args(fname, args, 2, "<LIST_FIELD> <predicate>")
        return cls(list_field=str(args[0]), predicate=parse(args[1]))
    if cls is ListUnique:
        _expect_args(fname, args, 1, "<LIST_FIELD>")
        return cls(list_field=str(args[0]))

    if cls is ItemMatchesRegex:
        _expect_args(fname, args, 1, "<NAMED_REGEX>")
        regex_name = str(args[0])
        if regex_name not in V.NAMED_REGEX_NAMES:
            raise DSLError(
                f"ItemMatchesRegex: unknown named regex '{regex_name}'. "
                f"Pick one of: {sorted(V.NAMED_REGEX_NAMES)}")
        return cls(pattern=regex_name)
    if cls is ItemInSet:
        _expect_args(fname, args, 1, "[<lit>...]")
        if not isinstance(args[0], list):
            raise DSLError(f"{fname}: arg must be list of literals")
        return cls(values=tuple(_lit(v) for v in args[0]))
    if cls is ItemEq:
        _expect_args(fname, args, 1, "<lit>")
        return cls(value=_lit(args[0]))
    if cls is ItemLenIn:
        _expect_args(fname, args, 1, "[<count:int>...]")
        if not isinstance(args[0], list) or not all(isinstance(v, int) for v in args[0]):
            raise DSLError(f"{fname}: arg must be list of ints")
        return cls(counts=tuple(int(v) for v in args[0]))
    if cls is ItemNotMatchesRegex:
        _expect_args(fname, args, 1, "<NAMED_REGEX>")
        regex_name = str(args[0])
        if regex_name not in V.NAMED_REGEX_NAMES:
            raise DSLError(
                f"ItemNotMatchesRegex: unknown named regex '{regex_name}'. "
                f"Pick one of: {sorted(V.NAMED_REGEX_NAMES)}")
        return cls(pattern=regex_name)

    if cls is BytesEq:
        _expect_args(fname, args, 2, "<bytes_field_a> <bytes_field_b>")
        return cls(field_a=str(args[0]), field_b=str(args[1]))
    if cls is IPListAllOctetCount:
        _expect_args(fname, args, 2, "<ip_list field> <count:int>")
        return cls(field=str(args[0]), count=int(args[1]))
    if cls is OidListContains:
        _expect_args(fname, args, 2, "<oid_list field> <OID_CONST>")
        field = str(args[0])
        oid = _norm_oid_name(args[1])
        if field == "PolicyConstOID":
            field = "PolicyIdentifiers"
        return cls(field=field, oid=oid)

    if cls is OidListCountInSet:
        _expect_args(fname, args, 4, "<oid_list field> [<OID_CONST>,...] <lo> <hi>")
        return cls(field=str(args[0]),
                   allowed_oids=_norm_oid_list(args[1]),
                   lo=int(args[2]), hi=_int_or_maxint(args[3]))

    if cls is BytesEqualsHex:
        _expect_args(fname, args, 2, "<bytes field> <hex literal>")
        return cls(field=str(args[0]), hex_lit=str(args[1]))
    if cls is BytesContainsHex:
        _expect_args(fname, args, 2, "<bytes field> <hex literal>")
        return cls(field=str(args[0]), hex_lit=str(args[1]))

    if cls is PublicKeyAlgorithmIs:
        _expect_args(fname, args, 1, "<RSA|DSA|ECDSA|Ed25519|Ed448|X25519|X448>")
        return cls(algorithm=str(args[0]))
    if cls is DNEmpty:
        _expect_args(fname, args, 1, "<Subject|Issuer>")
        return cls(holder=str(args[0]))

    if cls is ExtRawValueEqualsHex:
        _expect_args(fname, args, 2, "<OID_CONST> <hex_literal>")
        return cls(oid=str(args[0]), hex_lit=str(args[1]))
    if cls is ExtRawValueContainsHex:
        _expect_args(fname, args, 2, "<OID_CONST> <hex_literal>")
        return cls(oid=str(args[0]), hex_lit=str(args[1]))

    if cls is ExtSubfieldPresent:
        if not (2 <= len(args) <= 4):
            raise DSLError(f"{fname} expects 2-4 args "
                           f"(<OID_CONST> <tag:int> [subfield] [path]), got {len(args)}")
        return cls(oid=str(args[0]), tag=int(args[1]),
                   subfield=str(args[2]) if len(args) > 2 else "",
                   path=str(args[3]) if len(args) > 3 else "")

    if cls is AIAHasMethodOtherThan:
        _expect_args(fname, args, 2, "<EXT_OID_CONST> <[METHOD_OID_CONST,...]>")
        if not isinstance(args[1], list) or not args[1]:
            raise DSLError(f"{fname}: second arg must be non-empty list of OID_CONST names")
        return cls(ext_oid=str(args[0]),
                   allowed_oids=tuple(str(o) for o in args[1]))
    if cls is AIAMethodLocationsTagInSet:
        _expect_args(fname, args, 3, "<EXT_OID_CONST> <METHOD_OID_CONST> <[asn1_tag:int,...]>")
        if not isinstance(args[2], list) or not args[2] or not all(isinstance(v, int) for v in args[2]):
            raise DSLError(f"{fname}: third arg must be non-empty list of GeneralName tag ints")
        return cls(ext_oid=str(args[0]), method_oid=str(args[1]),
                   allowed_tags=tuple(int(t) for t in args[2]))
    if cls is AIAMethodLocationsAnyMatchRegex:
        _expect_args(fname, args, 3, "<EXT_OID_CONST> <METHOD_OID_CONST> <NAMED_REGEX>")
        regex_name = str(args[2])
        if regex_name not in V.NAMED_REGEX_NAMES:
            raise DSLError(
                f"AIAMethodLocationsAnyMatchRegex: unknown named regex "
                f"'{regex_name}'. Pick one of: {sorted(V.NAMED_REGEX_NAMES)}")
        return cls(ext_oid=str(args[0]), method_oid=str(args[1]), pattern=regex_name)

    if cls is CRLDPHasNameRelative:
        _expect_args(fname, args, 0, "(no args)")
        return cls()
    if cls is CRLDPHasNameRelativeWithMultiIssuer:
        _expect_args(fname, args, 0, "(no args)")
        return cls()

    if cls is ValidityDateAsn1TagInSet:
        _expect_args(fname, args, 2, "<NotBefore|NotAfter> <[ASN1_TYPE_NAME,...]>")
        if not isinstance(args[1], list) or not args[1]:
            raise DSLError(f"{fname}: second arg must be non-empty list of ASN1_TYPE names")
        return cls(date_field=str(args[0]),
                   allowed_tags=tuple(str(t) for t in args[1]))
    if cls is CertPolicyExplicitTextHasEncodingTagInSet:
        _expect_args(fname, args, 1, "<[ASN1_TYPE_NAME,...]>")
        if not isinstance(args[0], list) or not args[0]:
            raise DSLError(f"{fname}: arg must be non-empty list of ASN1_TYPE names")
        return cls(allowed_tags=tuple(str(t) for t in args[0]))

    if cls is OidEq:
        _expect_args(fname, args, 2, "<OID_FIELD> <OID_CONST>")
        field = str(args[0])
        oid = _norm_oid_name(args[1])
        if field in ("PolicyConstOID", "PolicyIdentifiers"):
            return OidListContains("PolicyIdentifiers", oid)
        return cls(field=field, oid=oid)
    if cls is SubtreeIPListAnyHasOctetCount:
        _expect_args(fname, args, 2, "<subtree_list field> <count:int>")
        return cls(field=str(args[0]), count=int(args[1]))
    if cls is BytesContainsOidDer:
        _expect_args(fname, args, 2, "<bytes_field> <OID_CONST>")
        return cls(field=str(args[0]), oid=str(args[1]))
    if cls is ExtensionURISchemeNotInSet:
        _expect_args(fname, args, 1, "<[scheme,...]>")
        if not isinstance(args[0], list) or not args[0]:
            raise DSLError(f"{fname}: schemes must be non-empty list")
        return cls(schemes=tuple(str(s) for s in args[0]))

    if cls is IPListAllOctetCountIn:
        _expect_args(fname, args, 2, "<ip_list field> <[count,...]>")
        if not isinstance(args[1], list) or not all(isinstance(v, int) for v in args[1]):
            raise DSLError(f"{fname}: second arg must be list of ints")
        return cls(field=str(args[0]), counts=tuple(int(v) for v in args[1]))
    if cls is SubtreeIPListAnyAllZero:
        _expect_args(fname, args, 2, "<subtree_list field> <count:int>")
        return cls(field=str(args[0]), count=int(args[1]))

    if cls is SubtreeIPListAnyHasOctetCountAndNotAllZero:
        _expect_args(fname, args, 2, "<subtree_list field> <count:int>")
        return cls(field=str(args[0]), count=int(args[1]))

    if cls in (SubtreeStringListAllMatch, SubtreeStringListAnyMatch,
               SubtreeStringListAllMatchOrEmpty):
        _expect_args(fname, args, 2, "<subtree_string_list field> <predicate>")
        return cls(field=str(args[0]), predicate=parse(args[1]))
    if cls is SubtreeIPListAllOctetCountIn:
        _expect_args(fname, args, 2, "<subtree_ip_list field> <[count,...]>")
        if not isinstance(args[1], list) or not all(isinstance(v, int) for v in args[1]):
            raise DSLError(f"{fname}: second arg must be list of ints")
        return cls(field=str(args[0]), counts=tuple(int(v) for v in args[1]))
    if cls is SubtreeIPMaskValidCIDR:
        _expect_args(fname, args, 1, "<subtree_ip_list field>")
        return cls(field=str(args[0]))

    if cls is FieldContains:
        _expect_args(fname, args, 2, "<STRING_FIELD> <literal_char_or_string>")
        return cls(field=str(args[0]), substring=str(args[1]))
    if cls is FieldNotMatchesRegex:
        _expect_args(fname, args, 2, "<STRING_FIELD> <NAMED_REGEX>")
        regex_name = str(args[1])
        if regex_name not in V.NAMED_REGEX_NAMES:
            raise DSLError(
                f"FieldNotMatchesRegex: unknown named regex '{regex_name}'. "
                f"Pick one of: {sorted(V.NAMED_REGEX_NAMES)}")
        return cls(field=str(args[0]), pattern=regex_name)
    if cls is CrossFieldEq:
        _expect_args(fname, args, 2, "<FIELD_A> <FIELD_B>")
        return cls(field_a=str(args[0]), field_b=str(args[1]))
    if cls is WildcardFilter:
        _expect_args(fname, args, 3, "<LIST_FIELD> <prefix:str> <predicate>")
        return cls(list_field=str(args[0]), prefix=str(args[1]),
                   predicate=parse(args[2]))
    if cls is ScalarInList:
        _expect_args(fname, args, 2, "<scalar_field> <list_field>")
        return cls(scalar_field=str(args[0]), list_field=str(args[1]))
    if cls is ScalarInAnyOfLists:
        _expect_args(fname, args, 2, "<scalar_field> <[list_field, ...]>")
        if not isinstance(args[1], list) or not all(isinstance(v, str) for v in args[1]):
            raise DSLError(f"{fname}: second arg must be list of list-field names")
        if not args[1]:
            raise DSLError(f"{fname}: list_fields cannot be empty")
        return cls(scalar_field=str(args[0]),
                   list_fields=tuple(str(v) for v in args[1]))
    if cls is IPv4Conditional:
        _expect_args(fname, args, 3, "<ip_list field> <ipv4_predicate> <ipv6_predicate>")
        return cls(field=str(args[0]),
                   ipv4_predicate=parse(args[1]),
                   ipv6_predicate=parse(args[2]))
    if cls is SubtreeIPv4Conditional:
        _expect_args(fname, args, 3, "<subtree_ip_list field> <ipv4_predicate> <ipv6_predicate>")
        return cls(field=str(args[0]),
                   ipv4_predicate=parse(args[1]),
                   ipv6_predicate=parse(args[2]))
    if cls is ExtHasGeneralNameWithTag:
        _expect_args(fname, args, 2, "<OID_CONST> <tag:int>")
        return cls(oid=str(args[0]), tag=int(args[1]))
    if cls is ExtHasAnyGeneralNameOfTag:
        _expect_args(fname, args, 2, "<OID_CONST> <tag:int>")
        return cls(oid=str(args[0]), tag=int(args[1]))
    if cls is DomainComponentOrdered:
        _expect_args(fname, args, 0, "(no args) — checks Subject DN domainComponent ordering")
        return cls()

    raise DSLError(f"unhandled atom class {fname}")


# =====================================================================
# Validate (against vocab; semantic + closed-vocab name checks)
# =====================================================================

def validate(node: Compound, *, in_item_context: bool = False) -> list[str]:
    """Walk the tree and check every name reference against vocab.
    Returns list of error strings; empty list = OK."""
    errs: list[str] = []
    _validate(node, errs, in_item_context)
    return errs


def _validate(n, errs: list[str], in_item: bool):
    # WildcardFilter predicate uses _item as the iteration variable;
    # it is only valid inside WildcardFilter's predicate context.
    if isinstance(n, WildcardFilter):
        _validate(n.predicate, errs, in_item=True)
        return

    if isinstance(n, (And, Or)):
        for p in n.parts:
            _validate(p, errs, in_item)
        return
    if isinstance(n, When):
        _validate(n.cond, errs, in_item)
        _validate(n.main, errs, in_item)
        return
    if isinstance(n, Not):
        _validate(n.inner, errs, in_item)
        return

    if isinstance(n, (ExtPresent, ExtCritical, ExtNotCritical)):
        if n.oid not in V.OID_BY_NAME:
            errs.append(f"unknown OID_CONST '{n.oid}'")
        return

    if isinstance(n, (IsCA, IsRootCA, IsSubCA, PathLenConstraintPresent, IsServerCert, IsSubscriberCert, IsEndEntity,
                      CRLDPHasNameRelative,
                      CRLDPHasNameRelativeWithMultiIssuer,
                      SigAlgMatchesTBSSignature, NotAfterIsNoExpirySentinel, CommonNameFromSAN)):
        return

    if isinstance(n, ValidityDateAsn1TagInSet):
        if n.date_field not in ("NotBefore", "NotAfter"):
            errs.append(f"ValidityDateAsn1TagInSet: date_field must be "
                        f"'NotBefore' or 'NotAfter', got '{n.date_field}'")
        if not n.allowed_tags:
            errs.append("ValidityDateAsn1TagInSet: allowed_tags must be non-empty")
        for t in n.allowed_tags:
            if t not in V.ASN1_BY_NAME:
                errs.append(f"ValidityDateAsn1TagInSet: unknown ASN1_TYPE '{t}'")
        return
    if isinstance(n, CertPolicyExplicitTextHasEncodingTagInSet):
        if not n.allowed_tags:
            errs.append("CertPolicyExplicitTextHasEncodingTagInSet: allowed_tags must be non-empty")
        for t in n.allowed_tags:
            if t not in V.ASN1_BY_NAME:
                errs.append(f"CertPolicyExplicitTextHasEncodingTagInSet: unknown ASN1_TYPE '{t}'")
        return

    if isinstance(n, KeyUsageHas):
        if n.bit not in V.KU_BY_NAME:
            errs.append(f"unknown KEY_USAGE_BIT '{n.bit}'")
        return
    if isinstance(n, ExtKeyUsageHas):
        if n.bit not in V.EKU_BY_NAME:
            errs.append(f"unknown EKU_BIT '{n.bit}'")
        return

    if isinstance(n, (FieldEq, FieldNonEmpty, FieldEmpty,
                      FieldMatchesRegex, FieldInSet, FieldNotInSet)):
        # _item is a magic sentinel used inside WildcardFilter predicates;
        # it is only valid there — render handles it as the iteration variable.
        if n.field == "_item":
            return
        f = V.lookup_anyfield(n.field)
        if f is None:
            errs.append(f"unknown CERT_FIELD/DN_FIELD '{n.field}'")
            return
        if isinstance(n, FieldMatchesRegex) and f.semantic not in (
                "string", "string_list"):
            errs.append(f"FieldMatchesRegex: '{n.field}' is {f.semantic}, "
                        "must be string or string_list")
        if isinstance(n, FieldEq):
            if f.semantic in ("ext_list", "bytes", "ip_list",
                              "oid_list", "eku_list", "time", "oid",
                              "sigalg", "pubkeyalg"):
                errs.append(
                    f"FieldEq on '{n.field}' (semantic={f.semantic}) not supported")
            if f.semantic == "bool":
                errs.append(
                    f"FieldEq on bool field '{n.field}' not supported "
                    "(use FieldNonEmpty for true / FieldEmpty for false)")
            if f.semantic in ("int", "bigint") and not isinstance(n.value, int):
                errs.append(
                    f"FieldEq: '{n.field}' is {f.semantic} but literal "
                    f"{n.value!r} is not int")
            if f.semantic in ("string", "string_list") and not isinstance(n.value, str):
                errs.append(
                    f"FieldEq: '{n.field}' is {f.semantic} but literal "
                    f"{n.value!r} is not string")
        if isinstance(n, (FieldInSet, FieldNotInSet)):
            if f.semantic == "bool":
                errs.append(
                    f"FieldInSet/NotInSet on bool field '{n.field}' not supported")
            if f.semantic == "int" and not all(isinstance(v, int) for v in n.values):
                errs.append(
                    f"FieldInSet/NotInSet: '{n.field}' is int but values include non-int")
            if f.semantic in ("string", "string_list") and not all(isinstance(v, str) for v in n.values):
                errs.append(
                    f"FieldInSet/NotInSet: '{n.field}' is {f.semantic} but values include non-string")
        return
    if isinstance(n, FieldLenInRange):
        f = V.lookup_anyfield(n.field)
        if f is None:
            errs.append(f"unknown field '{n.field}' for FieldLenInRange")
        elif f.semantic not in ("string", "string_list", "ip_list", "oid_list",
                                "eku_list", "ext_list", "bytes", "subtree_list"):
            errs.append(f"FieldLenInRange: '{n.field}' semantic={f.semantic} "
                        "not lenable")
        return
    if isinstance(n, FieldNumericInRange):
        f = V.lookup_anyfield(n.field)
        if f is None:
            errs.append(f"unknown field '{n.field}' for FieldNumericInRange")
        elif f.semantic not in ("int", "bigint"):
            errs.append(f"FieldNumericInRange: '{n.field}' semantic={f.semantic} "
                        "not numeric")
        return
    if isinstance(n, FieldEncodedAs):
        f = V.lookup_anyfield(n.field)
        if f is None:
            errs.append(f"unknown field '{n.field}' for FieldEncodedAs")
        for t in n.types:
            if t not in V.ASN1_BY_NAME:
                errs.append(f"unknown ASN1_TYPE '{t}'")
        return

    if isinstance(n, DNDirectoryStringValuesEncodedAs):
        if n.dn not in ("Subject", "Issuer"):
            errs.append(f"DNDirectoryStringValuesEncodedAs: dn must be Subject/Issuer, got '{n.dn}'")
        if not n.types:
            errs.append("DNDirectoryStringValuesEncodedAs: types cannot be empty")
        for t in n.types:
            if t not in V.ASN1_BY_NAME:
                errs.append(f"unknown ASN1_TYPE '{t}'")
        return

    if isinstance(n, DateAfter):
        if n.later not in V.DATE_BY_NAME:
            errs.append(f"unknown DATE_FIELD '{n.later}' (later)")
        if n.earlier not in V.DATE_BY_NAME:
            errs.append(f"unknown DATE_FIELD '{n.earlier}' (earlier)")
        return
    if isinstance(n, DateBefore):
        for d in (n.earlier, n.later):
            if d in V.DATE_BY_NAME:
                continue
            if not re.fullmatch(r"\d{4}-\d{2}-\d{2}", d):
                errs.append(f"DateBefore: '{d}' is neither a DATE_FIELD nor a YYYY-MM-DD literal")
        return

    if isinstance(n, (ListAllMatch, ListAnyMatch)):
        f = V.lookup_anyfield(n.list_field)
        if f is None:
            errs.append(f"unknown LIST_FIELD '{n.list_field}'")
        elif f.semantic != "string_list":
            errs.append(f"List* on '{n.list_field}' semantic={f.semantic} "
                        "not supported (only string_list — IP/OID/EKU/Ext "
                        "lists need typed atoms not yet defined)")
        _validate(n.predicate, errs, in_item=True)
        return
    if isinstance(n, ListUnique):
        f = V.lookup_anyfield(n.list_field)
        if f is None:
            errs.append(f"unknown LIST_FIELD '{n.list_field}'")
        elif f.semantic not in ("string_list", "ip_list", "oid_list"):
            errs.append(f"ListUnique on '{n.list_field}' semantic={f.semantic} "
                        "not supported")
        return

    if isinstance(n, (ItemMatchesRegex, ItemInSet, ItemEq, ItemNotMatchesRegex)):
        if not in_item:
            errs.append(f"{type(n).__name__} only valid inside ListAll/AnyMatch/WildcardFilter predicate")
        return
    if isinstance(n, ItemLenIn):
        if not in_item:
            errs.append("ItemLenIn only valid inside list iteration predicate")
        for c in n.counts:
            if c not in (4, 8, 16, 32):
                errs.append(f"ItemLenIn: count {c} must be in {{4,8,16,32}}")
        return

    if isinstance(n, BytesEq):
        for fld in (n.field_a, n.field_b):
            f = V.lookup_anyfield(fld)
            if f is None:
                errs.append(f"BytesEq: unknown field '{fld}'")
            elif f.semantic != "bytes":
                errs.append(f"BytesEq: '{fld}' semantic={f.semantic}, must be bytes")
        return
    if isinstance(n, IPListAllOctetCount):
        f = V.lookup_anyfield(n.field)
        if f is None:
            errs.append(f"IPListAllOctetCount: unknown field '{n.field}'")
        elif f.semantic != "ip_list":
            errs.append(f"IPListAllOctetCount: '{n.field}' semantic={f.semantic}, "
                        "must be ip_list")
        if n.count not in (4, 8, 16, 32):
            errs.append(f"IPListAllOctetCount: count must be 4, 8, 16 or 32, got {n.count}")
        return
    if isinstance(n, OidListContains):
        f = V.lookup_anyfield(n.field)
        if f is None:
            errs.append(f"OidListContains: unknown field '{n.field}'")
        elif f.semantic != "oid_list":
            errs.append(f"OidListContains: '{n.field}' semantic={f.semantic}, "
                        "must be oid_list")
        if n.oid not in V.OID_BY_NAME:
            errs.append(f"OidListContains: unknown OID_CONST '{n.oid}'")
        return

    if isinstance(n, (BytesEqualsHex, BytesContainsHex)):
        f = V.lookup_anyfield(n.field)
        if f is None:
            errs.append(f"{type(n).__name__}: unknown field '{n.field}'")
        elif f.semantic != "bytes":
            errs.append(f"{type(n).__name__}: '{n.field}' semantic={f.semantic}, must be bytes")
        if not re.fullmatch(r"[0-9a-fA-F]+", n.hex_lit) or len(n.hex_lit) % 2 != 0:
            errs.append(f"{type(n).__name__}: hex literal must be even-length hex chars (got {n.hex_lit[:30]!r})")
        return

    if isinstance(n, ExtensionURISchemeNotInSet):
        if not n.schemes:
            errs.append("ExtensionURISchemeNotInSet: schemes must be non-empty")
        return

    if isinstance(n, PublicKeyAlgorithmIs):
        if n.algorithm not in ("RSA", "DSA", "ECDSA", "Ed25519", "Ed448", "X25519", "X448"):
            errs.append(f"PublicKeyAlgorithmIs: unknown algorithm '{n.algorithm}'")
        return
    if isinstance(n, DNEmpty):
        if n.holder not in ("Subject", "Issuer"):
            errs.append(f"DNEmpty: holder must be 'Subject' or 'Issuer', got '{n.holder}'")
        return

    if isinstance(n, (ExtRawValueEqualsHex, ExtRawValueContainsHex)):
        if n.oid not in V.OID_BY_NAME:
            errs.append(f"{type(n).__name__}: unknown OID_CONST '{n.oid}'")
        if not re.fullmatch(r"[0-9a-fA-F]+", n.hex_lit) or len(n.hex_lit) % 2 != 0:
            errs.append(f"{type(n).__name__}: hex literal must be even-length hex (got {n.hex_lit[:30]!r})")
        return

    if isinstance(n, ExtSubfieldPresent):
        if n.oid not in V.OID_BY_NAME:
            errs.append(f"ExtSubfieldPresent: unknown OID_CONST '{n.oid}'")
        if not isinstance(n.tag, int) or n.tag < 0:
            errs.append(f"ExtSubfieldPresent: tag must be a non-negative int (got {n.tag!r})")
        if n.path not in ("", "generalsubtree"):
            errs.append(f"ExtSubfieldPresent: unsupported path {n.path!r}")
        return

    if isinstance(n, AIAHasMethodOtherThan):
        if n.ext_oid not in V.OID_BY_NAME:
            errs.append(f"AIAHasMethodOtherThan: unknown ext_oid OID_CONST '{n.ext_oid}'")
        if not n.allowed_oids:
            errs.append("AIAHasMethodOtherThan: allowed_oids must be non-empty")
        for o in n.allowed_oids:
            if o not in V.OID_BY_NAME:
                errs.append(f"AIAHasMethodOtherThan: unknown OID_CONST '{o}'")
        return
    if isinstance(n, AIAMethodLocationsTagInSet):
        if n.ext_oid not in V.OID_BY_NAME:
            errs.append(f"AIAMethodLocationsTagInSet: unknown ext_oid OID_CONST '{n.ext_oid}'")
        if n.method_oid not in V.OID_BY_NAME:
            errs.append(f"AIAMethodLocationsTagInSet: unknown OID_CONST '{n.method_oid}'")
        if not n.allowed_tags:
            errs.append("AIAMethodLocationsTagInSet: allowed_tags must be non-empty")
        for t in n.allowed_tags:
            if not isinstance(t, int) or t < 0 or t > 30:
                errs.append(f"AIAMethodLocationsTagInSet: tag must be int in 0..30, got {t!r}")
        return
    if isinstance(n, AIAMethodLocationsAnyMatchRegex):
        if n.ext_oid not in V.OID_BY_NAME:
            errs.append(f"AIAMethodLocationsAnyMatchRegex: unknown ext_oid OID_CONST '{n.ext_oid}'")
        if n.method_oid not in V.OID_BY_NAME:
            errs.append(f"AIAMethodLocationsAnyMatchRegex: unknown OID_CONST '{n.method_oid}'")
        if n.pattern not in V.NAMED_REGEX_NAMES:
            errs.append(f"AIAMethodLocationsAnyMatchRegex: unknown NAMED_REGEX '{n.pattern}'")
        return

    if isinstance(n, OidEq):
        f = V.lookup_anyfield(n.field)
        if f is None:
            errs.append(f"OidEq: unknown field '{n.field}'")
        elif f.semantic != "oid":
            errs.append(f"OidEq: '{n.field}' semantic={f.semantic}, must be oid")
        if n.oid not in V.OID_BY_NAME:
            errs.append(f"OidEq: unknown OID_CONST '{n.oid}'")
        return
    if isinstance(n, SubtreeIPListAnyHasOctetCount):
        f = V.lookup_anyfield(n.field)
        if f is None:
            errs.append(f"SubtreeIPListAnyHasOctetCount: unknown field '{n.field}'")
        elif f.go_type != "[]GeneralSubtreeIP":
            errs.append(f"SubtreeIPListAnyHasOctetCount: '{n.field}' go_type={f.go_type}, "
                        "must be []GeneralSubtreeIP (PermittedIPAddresses or ExcludedIPAddresses)")
        if n.count not in (8, 32):
            errs.append(f"SubtreeIPListAnyHasOctetCount: count must be 8 (IPv4 addr+mask) "
                        f"or 32 (IPv6 addr+mask), got {n.count}")
        return
    if isinstance(n, BytesContainsOidDer):
        f = V.lookup_anyfield(n.field)
        if f is None:
            errs.append(f"BytesContainsOidDer: unknown field '{n.field}'")
        elif f.semantic != "bytes":
            errs.append(f"BytesContainsOidDer: '{n.field}' semantic={f.semantic}, must be bytes")
        if n.oid not in V.OID_BY_NAME:
            errs.append(f"BytesContainsOidDer: unknown OID_CONST '{n.oid}'")
        return
    if isinstance(n, PolicyQualifierOIDInSet):
        if n.oid_const not in V.OID_BY_NAME:
            errs.append(f"PolicyQualifierOIDInSet: unknown OID_CONST '{n.oid_const}'")
        return
    if isinstance(n, PolicyQualifierOIDNotInSet):
        if not n.oid_const:
            errs.append("PolicyQualifierOIDNotInSet: oid_const cannot be empty")
        if n.oid_const not in V.OID_BY_NAME:
            errs.append(f"PolicyQualifierOIDNotInSet: unknown OID_CONST '{n.oid_const}'")
        return

    if isinstance(n, IPListAllOctetCountIn):
        f = V.lookup_anyfield(n.field)
        if f is None:
            errs.append(f"IPListAllOctetCountIn: unknown field '{n.field}'")
        elif f.semantic != "ip_list":
            errs.append(f"IPListAllOctetCountIn: '{n.field}' semantic={f.semantic}, must be ip_list")
        if not n.counts:
            errs.append("IPListAllOctetCountIn: counts list cannot be empty")
        for c in n.counts:
            if c not in (4, 8, 16, 32):
                errs.append(f"IPListAllOctetCountIn: count {c} must be in {{4,8,16,32}}")
        return
    if isinstance(n, SubtreeIPListAnyAllZero):
        f = V.lookup_anyfield(n.field)
        if f is None:
            errs.append(f"SubtreeIPListAnyAllZero: unknown field '{n.field}'")
        elif f.go_type != "[]GeneralSubtreeIP":
            errs.append(f"SubtreeIPListAnyAllZero: '{n.field}' go_type={f.go_type}, must be []GeneralSubtreeIP")
        if n.count not in (8, 32):
            errs.append(f"SubtreeIPListAnyAllZero: count must be 8 (IPv4 0.0.0.0/0) or 32 (IPv6 ::0/0), got {n.count}")
        return

    if isinstance(n, SubtreeIPListAnyHasOctetCountAndNotAllZero):
        f = V.lookup_anyfield(n.field)
        if f is None:
            errs.append(f"SubtreeIPListAnyHasOctetCountAndNotAllZero: unknown field '{n.field}'")
        elif f.go_type != "[]GeneralSubtreeIP":
            errs.append(f"SubtreeIPListAnyHasOctetCountAndNotAllZero: '{n.field}' go_type={f.go_type}, must be []GeneralSubtreeIP")
        if n.count not in (8, 32):
            errs.append(f"SubtreeIPListAnyHasOctetCountAndNotAllZero: count must be 8 or 32, got {n.count}")
        return

    if isinstance(n, (SubtreeStringListAllMatch, SubtreeStringListAnyMatch,
                       SubtreeStringListAllMatchOrEmpty)):
        f = V.lookup_anyfield(n.field)
        if f is None:
            errs.append(f"{type(n).__name__}: unknown field '{n.field}'")
        elif f.go_type != "[]GeneralSubtreeString":
            errs.append(f"{type(n).__name__}: '{n.field}' go_type={f.go_type}, must be []GeneralSubtreeString")
        _validate(n.predicate, errs, in_item=True)
        return
    if isinstance(n, SubtreeIPListAllOctetCountIn):
        f = V.lookup_anyfield(n.field)
        if f is None:
            errs.append(f"SubtreeIPListAllOctetCountIn: unknown field '{n.field}'")
        elif f.go_type != "[]GeneralSubtreeIP":
            errs.append(f"SubtreeIPListAllOctetCountIn: '{n.field}' go_type={f.go_type}, must be []GeneralSubtreeIP")
        if not n.counts:
            errs.append("SubtreeIPListAllOctetCountIn: counts list cannot be empty")
        for c in n.counts:
            if c not in (8, 32):
                errs.append(f"SubtreeIPListAllOctetCountIn: count {c} must be 8 (IPv4+mask) or 32 (IPv6+mask)")
        return
    if isinstance(n, SubtreeIPMaskValidCIDR):
        f = V.lookup_anyfield(n.field)
        if f is None:
            errs.append(f"SubtreeIPMaskValidCIDR: unknown field '{n.field}'")
        elif f.go_type != "[]GeneralSubtreeIP":
            errs.append(f"SubtreeIPMaskValidCIDR: '{n.field}' go_type={f.go_type}, must be []GeneralSubtreeIP")
        return

    if isinstance(n, FieldContains):
        f = V.lookup_anyfield(n.field)
        if f is None:
            errs.append(f"FieldContains: unknown field '{n.field}'")
        elif f.semantic not in ("string", "string_list"):
            errs.append(f"FieldContains: '{n.field}' semantic={f.semantic}, must be string or string_list")
        return

    if isinstance(n, FieldNotMatchesRegex):
        f = V.lookup_anyfield(n.field)
        if f is None:
            errs.append(f"FieldNotMatchesRegex: unknown field '{n.field}'")
        elif f.semantic not in ("string", "string_list"):
            errs.append(f"FieldNotMatchesRegex: '{n.field}' semantic={f.semantic}, must be string or string_list")
        return

    if isinstance(n, CrossFieldEq):
        for fld in (n.field_a, n.field_b):
            fa = V.lookup_anyfield(fld)
            if fa is None:
                errs.append(f"CrossFieldEq: unknown field '{fld}'")
            elif fa.semantic not in ("string", "int", "bigint"):
                errs.append(f"CrossFieldEq: '{fld}' semantic={fa.semantic}, "
                            "must be string, int, or bigint (for scalar-to-scalar equality)")
        return

    if isinstance(n, WildcardFilter):
        f = V.lookup_anyfield(n.list_field)
        if f is None:
            errs.append(f"WildcardFilter: unknown list field '{n.list_field}'")
        elif f.semantic not in ("string_list",):
            errs.append(f"WildcardFilter: '{n.list_field}' semantic={f.semantic}, must be string_list")
        if not isinstance(n.prefix, str) or not n.prefix:
            errs.append(f"WildcardFilter: prefix must be a non-empty string, got {n.prefix!r}")
        _validate(n.predicate, errs, in_item=True)
        return

    if isinstance(n, ScalarInList):
        fa = V.lookup_anyfield(n.scalar_field)
        if fa is None:
            errs.append(f"ScalarInList: unknown scalar_field '{n.scalar_field}'")
        elif fa.semantic not in ("string", "int", "bigint"):
            errs.append(f"ScalarInList: scalar_field '{n.scalar_field}' semantic={fa.semantic}, "
                        "must be string, int, or bigint")
        fl = V.lookup_anyfield(n.list_field)
        if fl is None:
            errs.append(f"ScalarInList: unknown list_field '{n.list_field}'")
        elif fl.semantic != "string_list":
            errs.append(f"ScalarInList: list_field '{n.list_field}' semantic={fl.semantic}, "
                        "must be string_list")
        return

    if isinstance(n, ScalarInAnyOfLists):
        fa = V.lookup_anyfield(n.scalar_field)
        if fa is None:
            errs.append(f"ScalarInAnyOfLists: unknown scalar_field '{n.scalar_field}'")
        elif fa.semantic not in ("string", "int", "bigint"):
            errs.append(f"ScalarInAnyOfLists: scalar_field '{n.scalar_field}' "
                        f"semantic={fa.semantic}, must be string, int, or bigint")
        for lname in n.list_fields:
            fl = V.lookup_anyfield(lname)
            if fl is None:
                errs.append(f"ScalarInAnyOfLists: unknown list_field '{lname}'")
            elif fl.semantic not in ("string_list", "ip_list"):
                errs.append(f"ScalarInAnyOfLists: list_field '{lname}' "
                            f"semantic={fl.semantic}, must be string_list or ip_list")
        return

    if isinstance(n, IPv4Conditional):
        f = V.lookup_anyfield(n.field)
        if f is None:
            errs.append(f"IPv4Conditional: unknown field '{n.field}'")
        elif f.semantic != "ip_list":
            errs.append(f"IPv4Conditional: '{n.field}' semantic={f.semantic}, must be ip_list")
        _validate(n.ipv4_predicate, errs, in_item=True)
        _validate(n.ipv6_predicate, errs, in_item=True)
        return

    if isinstance(n, SubtreeIPv4Conditional):
        f = V.lookup_anyfield(n.field)
        if f is None:
            errs.append(f"SubtreeIPv4Conditional: unknown field '{n.field}'")
        elif f.go_type != "[]GeneralSubtreeIP":
            errs.append(f"SubtreeIPv4Conditional: '{n.field}' go_type={f.go_type}, must be []GeneralSubtreeIP")
        _validate(n.ipv4_predicate, errs, in_item=True)
        _validate(n.ipv6_predicate, errs, in_item=True)
        return

    if isinstance(n, ExtHasGeneralNameWithTag):
        if n.oid not in V.OID_BY_NAME:
            errs.append(f"ExtHasGeneralNameWithTag: unknown OID_CONST '{n.oid}'")
        # RFC 5280 §4.2.1.6 GeneralName CHOICE tag numbers (context-class).
        if n.tag not in (0, 1, 2, 3, 4, 5, 6, 7, 8):
            errs.append(f"ExtHasGeneralNameWithTag: tag must be an ASN.1 GeneralName "
                       f"CHOICE tag number per RFC 5280 §4.2.1.6 "
                       f"(0=otherName, 1=rfc822Name, 2=dNSName, 3=x400Address, "
                       f"4=directoryName, 5=ediPartyName, 6=uniformResourceIdentifier, "
                       f"7=iPAddress, 8=registeredID), got {n.tag}")
        return

    if isinstance(n, ExtHasAnyGeneralNameOfTag):
        if n.oid not in V.OID_BY_NAME:
            errs.append(f"ExtHasAnyGeneralNameOfTag: unknown OID_CONST '{n.oid}'")
        if n.tag not in (0, 1, 2, 3, 4, 5, 6, 7, 8):
            errs.append(f"ExtHasAnyGeneralNameOfTag: tag must be an ASN.1 GeneralName "
                       f"CHOICE tag number per RFC 5280 §4.2.1.6 "
                       f"(0=otherName, 1=rfc822Name, 2=dNSName, 3=x400Address, "
                       f"4=directoryName, 5=ediPartyName, 6=uniformResourceIdentifier, "
                       f"7=iPAddress, 8=registeredID), got {n.tag}")
        return

    if isinstance(n, DomainComponentOrdered):
        # DomainComponentOrdered is a zero-arg sentinel atom with no field args
        return

    # ── FieldCount ──────────────────────────────────────────────────────
    if isinstance(n, FieldCount):
        f = V.lookup_anyfield(n.field)
        if f is None:
            errs.append(f"FieldCount: unknown field '{n.field}'")
        elif f.semantic not in ('string_list', 'ip_list', 'oid_list',
                                'eku_list', 'ext_list'):
            # Also accept []GeneralSubtree* typed fields (NameConstraints typed
            # subtrees: PermittedIPAddresses, PermittedDirectoryNames, etc.).
            # These ARE countable list fields — FieldCount(len(F) ≥ 1) is sound.
            if not f.go_type.startswith("[]GeneralSubtree"):
                errs.append(f"FieldCount: '{n.field}' semantic={f.semantic} "
                            "not a list (occurrence count undefined)")
        return

    # ── OidListCountInSet ───────────────────────────────────────────────
    if isinstance(n, OidListCountInSet):
        f = V.lookup_anyfield(n.field)
        if f is None:
            errs.append(f"OidListCountInSet: unknown field '{n.field}'")
        elif f.semantic != 'oid_list':
            errs.append(f"OidListCountInSet: '{n.field}' semantic={f.semantic}, "
                        "must be oid_list")
        for oid in n.allowed_oids:
            if oid not in V.OID_BY_NAME:
                errs.append(f"OidListCountInSet: unknown OID_CONST '{oid}'")
        return

    # ── RSAModulusBitsInRange / RSAPublicExponentInRange ──────────────
    if isinstance(n, (RSAModulusBitsInRange, RSAPublicExponentInRange)):
        # Both have only lo/hi range args; lo must be <= hi
        lo = n.lo
        hi = n.hi if isinstance(n.hi, int) else float('inf')
        if lo > hi:
            errs.append(f"{type(n).__name__}: lo={lo} > hi={n.hi}")
        return

    # ── ExtContentNonEmpty ─────────────────────────────────────────────
    if isinstance(n, ExtContentNonEmpty):
        if n.oid not in V.OID_BY_NAME:
            errs.append(f"ExtContentNonEmpty: unknown OID_CONST '{n.oid}'")
        return

    errs.append(f"unhandled DSL node {type(n).__name__}")


# =====================================================================
# Schema (compact human-readable for prompt embedding)
# =====================================================================

ATOM_SIGNATURES = [
    ('ExtPresent',          ['<OID_CONST>'],                         'extension is present'),
    ('ExtCritical',         ['<OID_CONST>'],                         'extension present AND Critical=true'),
    ('ExtNotCritical',      ['<OID_CONST>'],                         'extension present AND Critical=false'),
    ('IsCA',                [],                                      'cert is a CA'),
    ('IsRootCA',            [],                                      'cert is self-signed CA'),
    ('IsSubCA',             [],                                      'cert is a subordinate CA'),
    ('IsServerCert',        [],                                      'cert has ExtKeyUsage ServerAuth'),
    ('IsSubscriberCert',    [],                                      'cert is non-CA'),
    ('KeyUsageHas',         ['<KEY_USAGE_BIT>'],                     'KeyUsage bitmap has bit set'),
    ('ExtKeyUsageHas',      ['<EKU_BIT>'],                           'ExtKeyUsage list contains usage'),
    ('FieldEq',             ['<FIELD>', '<int|str>'],                'field equals literal'),
    ('FieldNonEmpty',       ['<FIELD>'],                             'field is set / non-empty'),
    ('FieldEmpty',          ['<FIELD>'],                             'field is unset / empty'),
    ('FieldMatchesRegex',   ['<STRING_FIELD>', '<NAMED_REGEX>'],     'string field matches a NAMED_REGEX (must be a name from NAMED_REGEXES; free-form regex literals are NOT allowed)'),
    ('FieldNotMatchesRegex',['<STRING_FIELD>', '<NAMED_REGEX>'],     'string field does NOT match a NAMED_REGEX; use for "MUST NOT contain forbidden pattern" rules (free-form regex NOT allowed)'),
    ('FieldInSet',          ['<FIELD>', ['<lit>', '...']],           'field value in literal set'),
    ('FieldNotInSet',       ['<FIELD>', ['<lit>', '...']],           'field value not in literal set'),
    ('FieldLenInRange',     ['<LIST_FIELD>', '<lo>', '<hi|MAX_INT>'],'len(field) in [lo,hi]'),
    ('FieldNumericInRange', ['<NUMERIC_FIELD>', '<lo>', '<hi|MAX_INT>'], 'numeric value in [lo,hi]'),
    ('FieldCount',          ['<LIST_FIELD>', '<lo>', '<hi|MAX_INT>'], 'occurrence count len(list field) in [lo,hi]; use for "MUST contain at least one / exactly N <X>"'),
    ('OidListCountInSet',   ['<OID_LIST_FIELD>', ['<OID_CONST>', '...'], '<lo>', '<hi|MAX_INT>'], 'count of OID-list entries whose OID is in the given set, in [lo,hi]; use for "exactly one of {reserved policy OIDs}"'),
    ('RSAModulusBitsInRange', ['<lo>', '<hi|MAX_INT>'], 'RSA modulus bit-length in [lo,hi]; vacuously true for non-RSA keys (e.g. "RSA modulus MUST be >= 2048 bits")'),
    ('RSAPublicExponentInRange', ['<lo>', '<hi|MAX_INT>'], 'RSA public exponent in [lo,hi]; vacuous for non-RSA (e.g. "exponent MUST be >= 3")'),
    ('SigAlgMatchesTBSSignature', [], 'the outer signatureAlgorithm is byte-identical to tbsCertificate.signature'),
    ('NotAfterIsNoExpirySentinel', [], 'notAfter is the RFC5280 no-well-defined-expiration sentinel 99991231235959Z (GeneralizedTime)'),
    ('CommonNameFromSAN',   [], 'Subject.CommonName equals one of the SAN dNSName entries ("CN MUST be from SAN")'),
    ('IsEndEntity',         [], 'cert is an end-entity / subscriber (non-CA)'),
    ('FieldEncodedAs',      ['<FIELD>', ['<ASN1_TYPE>', '...']],     'string field encoded as one of types'),
    ('DNDirectoryStringValuesEncodedAs', ['<dn:Subject|Issuer>', ['<ASN1_TYPE>', '...']], 'every DirectoryString-syntax attribute value in the Subject/Issuer DN is encoded as one of the types; non-DirectoryString attributes (countryName, domainComponent, ...) are skipped — use for "DirectoryString attribute values MUST be PrintableString or UTF8String, with exceptions"'),
    ('FieldContains',       ['<STRING_FIELD>', '<char_or_substring>'], 'string field contains the given character substring; use for "@ MUST NOT appear" / "underscore MUST NOT appear" type checks'),
    ('DateAfter',           ['<DATE_FIELD>', '<DATE_FIELD>'],        'later > earlier'),
    ('DateBefore',          ['<DATE_FIELD|YYYY-MM-DD>', '<DATE_FIELD|YYYY-MM-DD>'], 'first date < second; either side can be a YYYY-MM-DD literal'),
    ('ListAllMatch',        ['<LIST_FIELD>', '<predicate>'],         'all items satisfy predicate'),
    ('ListAnyMatch',        ['<LIST_FIELD>', '<predicate>'],         'any item satisfies predicate'),
    ('ListUnique',          ['<LIST_FIELD>'],                        'list elements pairwise distinct'),
    ('WildcardFilter',      ['<LIST_FIELD>', '<prefix:str>', '<predicate>'], 'if any entry in LIST starts with prefix (e.g. "*."), that entry MUST satisfy predicate; non-matching entries pass freely. Use for "wildcard labels must be valid FQDN" rules (R4829 etc.)'),
    ('ItemMatchesRegex',    ['<NAMED_REGEX>'],                       '(in List* predicate) item matches a NAMED_REGEX; free-form regex NOT allowed'),
    ('ItemInSet',           [['<lit>', '...']],                      '(in List* predicate) item in set'),
    ('ItemEq',              ['<lit>'],                               '(in List* predicate) item equals literal'),
    ('ItemLenIn',           [['<count>','...']],                     '(in IP-list predicate) item byte-length must be in set; e.g. [4,16] for IPv4/IPv6 mixed list; only valid inside IPv4Conditional or similar IP-context predicates'),
    ('ItemNotMatchesRegex', ['<NAMED_REGEX>'],                       '(in WildcardFilter/ListAllMatch predicate) item does NOT match regex; use for "MUST NOT contain forbidden pattern" in list contexts (e.g. R4718: no zero-length/empty labels)'),
    ('BytesEq',             ['<BYTES_FIELD>', '<BYTES_FIELD>'],      'two []byte fields equal byte-for-byte (e.g. SubjectKeyId vs AuthorityKeyId)'),
    ('IPListAllOctetCount', ['<IP_LIST_FIELD>', '<4|8|16|32>'],      'every IP in IP_LIST_FIELD has exactly N octets'),
    ('OidListContains',     ['<OID_LIST_FIELD>', '<OID_CONST>'],     'oid_list field contains the named OID constant'),
    ('BytesEqualsHex',      ['<BYTES_FIELD>', '<hex_literal>'],      'bytes field equals the given hex literal exactly'),
    ('BytesContainsHex',    ['<BYTES_FIELD>', '<hex_literal>'],      'bytes field contains the given hex literal as a substring'),
    ('PublicKeyAlgorithmIs',['<RSA|DSA|ECDSA|Ed25519|Ed448|X25519|X448>'], 'c.PublicKeyAlgorithm matches the named algorithm'),
    ('DNEmpty',             ['<Subject|Issuer>'],                    'the entire DN is the empty SEQUENCE'),
    ('ExtRawValueEqualsHex',['<OID_CONST>', '<hex_literal>'],        'extension is present AND its raw extnValue bytes equal the given hex literal'),
    ('ExtRawValueContainsHex',['<OID_CONST>', '<hex_literal>'],      'extension is present AND its raw extnValue bytes contain the given hex literal as a sub-slice'),
    ('AIAHasMethodOtherThan', ['<EXT_OID_CONST>', ['<METHOD_OID_CONST>', '...']], 'AccessDescription-shaped extension (AIA=AiaOID or SIA=SubjectInfoAccessOID) is present AND contains at least one AccessDescription whose accessMethod OID is NOT in the allow-list. Re-parses the raw extension DER, so methods that zcrypto drops at parse time (caRepository, timeStamping, ...) are still detected. Use the form Not(AIAHasMethodOtherThan(EXT, [METHOD, ...])) to express "extension MUST contain only the listed access methods"'),
    ('AIAMethodLocationsTagInSet', ['<EXT_OID_CONST>', '<METHOD_OID_CONST>', ['<asn1_tag:int>', '...']], 'every AccessDescription whose accessMethod equals the given OID (within extension EXT) has a GeneralName tag in the allowed-tag set. Vacuously true when no entries of that method are present. Tags follow RFC 5280 GeneralName CHOICE numbering (1=rfc822Name, 2=dNSName, 4=directoryName, 6=URI, 7=iPAddress, 8=registeredID). Use for "when accessMethod is M in extension E, accessLocation MUST be a {tag} name"'),
    ('AIAMethodLocationsAnyMatchRegex', ['<EXT_OID_CONST>', '<METHOD_OID_CONST>', '<NAMED_REGEX>'], 'at least one AccessDescription whose accessMethod equals the given OID (within extension EXT) is a uniformResourceIdentifier (tag 6) AND whose bytes match NAMED_REGEX. Returns false when no matching method entries are present. Use for "at least one accessLocation of method M in extension E SHOULD be a {scheme} URI"'),
    ('CRLDPHasNameRelative', [], 'CRL Distribution Points extension is present AND contains at least one DistributionPoint whose distributionPoint CHOICE is nameRelativeToCRLIssuer (rather than fullName). Re-parses raw extension DER (zcrypto exposes only fullName URIs). Use Not(CRLDPHasNameRelative()) to express "MUST/SHOULD NOT use nameRelativeToCRLIssuer"'),
    ('CRLDPHasNameRelativeWithMultiIssuer', [], 'CRL Distribution Points extension is present AND contains at least one DistributionPoint whose distributionPoint CHOICE is nameRelativeToCRLIssuer AND whose cRLIssuer field has more than one GeneralName. Use Not(CRLDPHasNameRelativeWithMultiIssuer()) to express "MUST NOT use nameRelativeToCRLIssuer when cRLIssuer contains more than one distinguished name"'),
    ('ValidityDateAsn1TagInSet', ['<NotBefore|NotAfter>', ['<ASN1_TYPE>', '...']], 'the ASN.1 universal-class tag of the named validity-date field (read from RawTBSCertificate; zcrypto exposes only the parsed time.Time and loses the original tag) is in the allowed-tag set. Only the UTCTime/GeneralizedTime ASN1_TYPE values are semantically valid for validity dates. Use for "validity date NotBefore/NotAfter MUST/MUST NOT be encoded as {TYPE}" rules (e.g. "dates in 2050 or later MUST be GeneralizedTime")'),
    ('CertPolicyExplicitTextHasEncodingTagInSet', [['<ASN1_TYPE>', '...']], 'CertificatePolicies extension is present AND contains at least one explicitText (in a UserNotice policy qualifier, OID id-qt-unotice) whose DisplayText CHOICE tag is in the allowed set. DisplayText is a CHOICE among IA5String/VisibleString/BMPString/UTF8String — the CHOICE tag carries the encoding info. Use Not(CertPolicyExplicitTextHasEncodingTagInSet([VisibleString, BMPString])) to express "MUST NOT encode explicitText as VisibleString or BMPString"'),
    ('OidEq',               ['<OID_FIELD>', '<OID_CONST>'],          'single OID-typed field (e.g. PublicKeyAlgorithmOID) equals the named OID constant'),
    ('SubtreeIPListAnyHasOctetCount', ['<subtree_list>', '<8|32>'],  'a NameConstraints subtree IP list has at least one entry of count octets (IP+Mask): 8 = IPv4, 32 = IPv6'),
    ('BytesContainsOidDer', ['<BYTES_FIELD>', '<OID_CONST>'],        'bytes field contains the DER encoding of the named OID — use for "namedCurve MUST be secp384r1" / "AlgorithmIdentifier embeds OID X" without writing hex literals'),
    ('IPListAllOctetCountIn', ['<IP_LIST_FIELD>', ['<count>','...']], 'every IP in IP_LIST_FIELD has octet count in the given set; use [4,16] for "each iPAddress must be IPv4 (4) or IPv6 (16)" mixed-version rules'),
    ('SubtreeIPListAnyAllZero', ['<subtree_list>', '<8|32>'],         'a NameConstraints subtree IP list has at least one entry of count octets (IP+Mask) where every byte is zero; use 8 for IPv4 0.0.0.0/0 marker, 32 for IPv6 ::0/0 marker'),
    ('SubtreeIPListAnyHasOctetCountAndNotAllZero', ['<subtree_list>', '<8|32>'], 'a NameConstraints subtree IP list has at least one entry of count octets where at least one byte is non-zero; the "real entry" counterpart of SubtreeIPListAnyAllZero. Use as Or(SubtreeIPListAnyHasOctetCountAndNotAllZero(F,32), SubtreeIPListAnyAllZero(F,32)) for "permittedSubtrees MUST contain real IPv6 entry OR ::0/0 marker" (R4633), and same with count=8 for IPv4 0.0.0.0/0 marker rule (R4632)'),
    ('SubtreeStringListAllMatch', ['<subtree_string_list>', '<predicate>'], 'iterate string-typed subtree list (PermittedDNSNames, ExcludedURIs, ...); apply ItemMatchesRegex/ItemEq/ItemInSet predicate to each entry .Data string. Use for "permitted subtree entries MUST be FQDN"-shape rules'),
    ('SubtreeStringListAnyMatch', ['<subtree_string_list>', '<predicate>'], 'iterate string-typed subtree list, satisfied if at least one entry matches predicate'),
    ('SubtreeStringListAllMatchOrEmpty', ['<subtree_string_list>', '<predicate>'], 'like SubtreeStringListAllMatch but vacuously TRUE on empty list. Use for "if X is constrained in permittedSubtrees/excludedSubtrees, all entries must be Y" rules where the constraint applies only to populated sides — combine with And over (permitted, excluded) so each populated side is checked but empty sides do not violate (R3995)'),
    ('SubtreeIPListAllOctetCountIn', ['<subtree_ip_list>', ['<count>','...']], 'every entry in NameConstraints subtree IP list has total bytes (IP+Mask) in given set; use [8,32] for "every iPAddress is IPv4 or IPv6", [32] for "all IPv6", [8] for "all IPv4"'),
    ('SubtreeIPMaskValidCIDR', ['<subtree_ip_list>'], 'every entry in NameConstraints subtree IP list has its mask portion (Data.Mask) in valid CIDR form: contiguous high-order 1-bits followed by zeros (per RFC 4632). IP-version agnostic — works on IPv4 (4-byte mask) and IPv6 (16-byte mask). Use for "iPAddress MUST be encoded in the style of RFC 4632 (CIDR)" rules (R4007). Empty list = vacuous true.'),
    ('CrossFieldEq',        ['<scalar_field_A>', '<scalar_field_B>'], 'two scalar fields have equal values (string-to-string or int-to-int); NOT for scalar-vs-list; use ScalarInList for CN-in-SAN'),
    ('ScalarInList',        ['<scalar_field>', '<string_list_field>'], 'true when scalar_field value appears as an element in list_field; use for "CN must be in DNSNames" (R5116) style rules where a scalar must appear in a list'),
    ('ScalarInAnyOfLists',  ['<scalar_field>', ['<list_field>','...']], 'true when scalar_field value appears in AT LEAST ONE of the named list_fields. Generalizes ScalarInList with implicit OR. Use for "CN must be derived from subjectAltName (any SAN type)" rules where the scalar must appear in DNSNames OR EmailAddresses OR URIs OR IPAddresses (R5116) — pass the full list of relevant SAN-type fields'),
    ('IPv4Conditional',     ['<ip_list>', '<ipv4_predicate>', '<ipv6_predicate>'], 'for each IP in list: if IPv4 (4 bytes), ipv4_predicate must hold; if IPv6 (16 bytes), ipv6_predicate must hold; BOTH predicates apply to ALL entries of their version. Use for "if IPv4 present, each must be N octets" rules (R5151). When atomic_text constrains only ONE IP version, use the self-tautology pattern: ItemLenIn([CANONICAL_SIZE]) on the unconstrained branch (always true given net.IP type guarantees). Empty list = vacuous true (rule does not require IP presence).'),
    ('SubtreeIPv4Conditional', ['<subtree_ip_list>', '<ipv4_predicate>', '<ipv6_predicate>'], 'mirror of IPv4Conditional for NameConstraints subtree IP lists ([]GeneralSubtreeIP). For each entry: if IPv4 subtree (4-byte IP part) then ipv4_predicate; if IPv6 subtree (16-byte IP part) then ipv6_predicate. Item predicate operates on total subtree-entry byte length (IP+Mask): ItemLenIn([8]) = IPv4 canonical (4+4), ItemLenIn([32]) = IPv6 canonical (16+16). For asymmetric rules, use the self-tautology pattern (ItemLenIn on the canonical size for the unconstrained branch). Empty list = vacuous true.'),
    ('ExtHasGeneralNameWithTag', ['<OID_CONST>', '<tag:int>'], 'ENCODING CHECK (NOT a presence check). True iff EVERY GeneralName entry in the named extension that has the given CHOICE tag is IA5String-encoded. Returns vacuously TRUE when zero entries of the given tag are present, so this atom CANNOT detect presence/absence — use ExtHasAnyGeneralNameOfTag for presence. RFC 5280 GeneralName tags: 0=otherName, 1=rfc822Name, 2=dNSName, 3=x400Address, 4=directoryName, 5=ediPartyName, 6=URI, 7=iPAddress, 8=registeredID. Use for "rfc822Name MUST be IA5String"-shape rules.'),
    ('ExtHasAnyGeneralNameOfTag', ['<OID_CONST>', '<tag:int>'], 'PRESENCE CHECK. True iff the named extension is present AND contains at least one GeneralName entry with the given CHOICE tag. Re-parses the raw extension SEQUENCE OF GeneralName because zcrypto exposes only DNSNames/EmailAddresses/URIs/IPAddresses (drops directoryName/otherName/ediPartyName/registeredID). RFC 5280 GeneralName tags: 0=otherName, 1=rfc822Name, 2=dNSName, 3=x400Address, 4=directoryName, 5=ediPartyName, 6=URI, 7=iPAddress, 8=registeredID. Use for "directoryName NOT RECOMMENDED in SAN" / "MUST contain at least one dNSName" presence rules.'),
    ('DomainComponentOrdered',   [],                                       'Subject DN contains domainComponent fields in a single contiguous ordered sequence (no gaps or intervening non-DC RDN types); use for "domainComponent fields MUST be in ordered sequence" rules (R4660)'),
]

COMPOUND_SIGNATURES = [
    ('Not', ['<compound>'],              'logical negation'),
    ('And', ['<compound>', '...'],       'logical conjunction (>=1 arg)'),
    ('Or',  ['<compound>', '...'],       'logical disjunction (>=1 arg)'),
]


def schema_for_llm(max_chars: int = 12000) -> str:
    lines = ['DSL ATOMS:']
    for op, sig, doc in ATOM_SIGNATURES:
        sig_str = ' '.join(_fmt_sig(s) for s in sig)
        lines.append(f'  {op}({sig_str})  -- {doc}')
    lines.append('')
    lines.append('DSL COMPOUNDS:')
    for op, sig, doc in COMPOUND_SIGNATURES:
        sig_str = ' '.join(_fmt_sig(s) for s in sig)
        lines.append(f'  {op}({sig_str})  -- {doc}')
    text = '\n'.join(lines)
    return text[:max_chars]


def _fmt_sig(s):
    if isinstance(s, list):
        return '[' + ' '.join(s) + ']'
    return s


# =====================================================================
def compound_to_dict(node: Compound) -> dict:
    """Convert a frozen dataclass atom/compound to the JSON dict form expected
    by ir_to_dsl._form_a / _validate_tree.  Inverse of parse()."""
    def _c(n):
        op_name = type(n).__name__
        # Compounds with 'parts' tuple (And, Or)
        if op_name in ("And", "Or"):
            return {"op": op_name, "args": [_c(a) for a in n.parts]}
        # Not / When: positional args as parse() expects
        if op_name == "Not":
            return {"op": "Not", "args": [_c(n.inner)]}
        if op_name == "When":
            return {"op": "When", "args": [_c(n.cond), _c(n.main)]}
        # Other compounds with named fields (rare / future)
        if op_name in COMPOUND_CLASSES:
            kw = {f.name: getattr(n, f.name) for f in fields(type(n))
                  if getattr(n, f.name, None) is not None}
            return {"op": op_name, "args": [], "kwargs": kw}

        # Atoms: ordered args as parse() expects
        kw = {f.name: getattr(n, f.name) for f in fields(type(n))
              if getattr(n, f.name, None) is not None}
        ordered = [kw[f.name] for f in fields(type(n)) if f.name in kw]

        # Atoms with tuple-valued fields → convert to list for JSON round-trip.
        # Single-element tuples unwrapped to bare value only when the TUPLE is a
        # list-of-identifiers with no other scalar args (parse reads scalar FIELD
        # as positional[0] — unwrap keeps the tuple item in the right position).
        # NOTE: allowed_oids in OidListCountInSet / AIAHasMethodOtherThan must
        # ALWAYS stay as list (they're followed by scalar int args, so parse would
        # mis-read a bare string as the next int arg).
        if op_name in (
            "FieldInSet", "FieldNotInSet",   # values: tuple
            "ItemInSet",                       # values: tuple
            "FieldEncodedAs",                  # types: tuple
            "DNDirectoryStringValuesEncodedAs",  # types: tuple
            "IPListAllOctetCountIn",           # counts: tuple
            "SubtreeIPListAllOctetCountIn",    # counts: tuple
            "AIAMethodLocationsTagInSet",      # allowed_tags: tuple
            "CertPolicyExplicitTextHasEncodingTagInSet",  # allowed_tags: tuple
            "ExtensionURISchemeNotInSet",      # schemes: tuple
            "ValidityDateAsn1TagInSet",        # allowed_tags: tuple
            "ScalarInAnyOfLists",             # list_fields: tuple
            # OidListCountInSet and AIAHasMethodOtherThan: NOT here — their
            # allowed_oids tuple is followed by scalar args and must stay as list
        ):
            kw_tup = {f.name: getattr(n, f.name) for f in fields(type(n))}
            for fi, f in enumerate(fields(type(n))):
                v = kw_tup.get(f.name)
                if isinstance(v, tuple):
                    # AIAMethodLocationsTagInSet.allowed_tags: always keep as list
                    # (contains ints 1..8; single-element unwrap breaks parse's isinstance(list) guard)
                    if op_name == "AIAMethodLocationsTagInSet" and f.name == "allowed_tags":
                        ordered[fi] = list(v)
                    else:
                        ordered[fi] = list(v) if len(v) != 1 else list(v)[0]

        # OidListCountInSet: allowed_oids tuple followed by int lo/hi → always list
        if op_name == "OidListCountInSet":
            # allowed_oids is 2nd field (index 1), lo/hi are 3rd/4th
            for fi, f in enumerate(fields(type(n))):
                if f.name == "allowed_oids":
                    ordered[fi] = list(n.allowed_oids)
                    break

        # AIAHasMethodOtherThan: allowed_oids tuple followed by nothing → bare ok,
        # but leave as list for consistency (unwrapping to bare would not break
        # parse here since parse reads it from args[1] list, so bare also works —
        # but prefer always-list for uniformity, no change needed since bare also
        # round-trips through parse's isinstance(args[1], list) check which
        # rejects bare string → WAIT parse rejects bare: need to fix parse too.
        if op_name == "AIAHasMethodOtherThan":
            for fi, f in enumerate(fields(type(n))):
                if f.name == "allowed_oids":
                    ordered[fi] = list(n.allowed_oids)
                    break

        # ItemLenIn: always list — parse requires list-of-ints
        if op_name == "ItemLenIn":
            ordered[0] = list(n.counts)

        # Atoms with nested Compound fields → convert to dict for parse()
        if op_name in ("ListAllMatch", "ListAnyMatch", "WildcardFilter",
                       "AIAMethodLocationsAnyMatchRegex",
                       "CertPolicyExplicitTextHasEncodingTagInSet",
                       "AIAHasMethodOtherThan",
                       "AIAMethodLocationsTagInSet",
                       "IPv4Conditional",
                       "SubtreeIPv4Conditional",
                       "SubtreeStringListAllMatch",
                       "SubtreeStringListAllMatchOrEmpty",
                       "SubtreeStringListAnyMatch",
                       ):
            # locate the Compound-typed field
            for fi, f in enumerate(fields(type(n))):
                v = getattr(n, f.name, None)
                if v is not None and not isinstance(v, (str, int, tuple, bool)):
                    ordered[fi] = _c(v)

        return {"op": op_name, "args": ordered}
    return _c(node)


# =====================================================================
# Self-test
# =====================================================================

if __name__ == "__main__":
    sample = {
        "op": "And",
        "args": [
            {"op": "ExtPresent", "args": ["CertPolicyOID"]},
            {"op": "ExtCritical", "args": ["CertPolicyOID"]},
            {"op": "FieldNonEmpty", "args": ["Subject.Province"]},
        ],
    }
    parsed = parse(sample)
    print("parsed:", parsed)
    print("validate errs:", validate(parsed))
    print("\n=== schema_for_llm() preview ===")
    print(schema_for_llm()[:1500])
