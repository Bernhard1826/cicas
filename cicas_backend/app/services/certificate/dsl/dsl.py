"""app/services/certificate/dsl/dsl.py — typed ATOM/COMPOUND DSL (backend port).

Minimal version: only the atoms + compounds that relate() needs.
No Go-codegen deps. Compare with experiments/templates_v2/dsl.py (full version).
"""
from __future__ import annotations

from dataclasses import dataclass, fields
from typing import Any, Union


class DSLError(ValueError):
    pass


# =====================================================================
# ATOMS — frozen dataclasses (canonical form for relate())
# =====================================================================

@dataclass(frozen=True)
class ExtPresent:
    """True iff certificate has the extension with given OID."""
    oid: str


@dataclass(frozen=True)
class ExtContentNonEmpty:
    """True iff the named extension's parsed content is a non-empty SEQUENCE
    (>=1 element) — for 'MUST NOT be an empty sequence' rules. Faithful only
    where zcrypto exposes the extension's content (e.g. nameConstraints subtree
    lists); the renderer refuses OIDs whose content it cannot reach."""
    oid: str


@dataclass(frozen=True)
class ExtHasAnyGeneralNameOfTag:
    """True iff the named extension is present AND contains at least one
    GeneralName of the given context tag. RFC 5280 §4.2.1.6 GeneralName CHOICE:
    0=otherName,1=rfc822Name,2=dNSName,3=x400Address,4=directoryName,
    5=ediPartyName,6=uniformResourceIdentifier,7=iPAddress,8=registeredID.
    Re-parses the raw extension DER by tag (renderer walks SEQUENCE OF
    GeneralName) — sound for SAN/IAN GeneralName-subtype presence rules,
    avoiding the over-claim of Not(ExtPresent(SAN)) for a single subtype."""
    oid: str
    tag: int


@dataclass(frozen=True)
class ExtCritical:
    """True iff extension is present AND marked Critical."""
    oid: str


@dataclass(frozen=True)
class ExtNotCritical:
    """True iff extension is present AND NOT critical."""
    oid: str


@dataclass(frozen=True)
class ExtRawValueEqualsHex:
    """True iff extension raw DER bytes equal the given hex string."""
    oid: str
    hex: str


@dataclass(frozen=True)
class ExtSubfieldPresent:
    """True iff the named extension is present AND its raw extnValue DER carries
    a context-tagged sub-element. Universal: parameterized by extension OID +
    ASN.1 context tag number + a human subfield label; the raw DER survives even
    when zcrypto's high-level parse discards the sub-field (e.g. AKI keeps only
    keyIdentifier, dropping authorityCertIssuer[1]/authorityCertSerialNumber[2]).

    path="" → the context tag sits directly under the extnValue SEQUENCE
    (e.g. AuthorityKeyIdentifier members). Fail-closed: if the extension is
    absent or the DER cannot be decoded, the sub-field is reported NOT present
    (never a false positive)."""
    oid: str
    tag: int
    subfield: str = ""
    path: str = ""


@dataclass(frozen=True)
class KeyUsageHas:
    """True iff keyUsage bit is set."""
    bit: str  # e.g. "DigitalSignature"


@dataclass(frozen=True)
class ExtKeyUsageHas:
    """True iff extendedKeyUsage OID is present."""
    oid: str


@dataclass(frozen=True)
class FieldEmpty:
    """True iff the named field is absent / empty."""
    field: str


@dataclass(frozen=True)
class FieldNonEmpty:
    """True iff the named field is present and non-empty."""
    field: str


@dataclass(frozen=True)
class FieldEq:
    """True iff field equals the given value."""
    field: str
    value: Any


@dataclass(frozen=True)
class FieldInSet:
    """True iff field value is in the given set."""
    field: str
    values: tuple


@dataclass(frozen=True)
class FieldNotInSet:
    """True iff field value is NOT in the given set."""
    field: str
    values: tuple


@dataclass(frozen=True)
class FieldLenInRange:
    """True iff len(field) ∈ [lo, hi] (hi="MAX_INT" means unbounded)."""
    field: str
    lo: int
    hi: Union[int, str]  # int or "MAX_INT"


@dataclass(frozen=True)
class FieldNumericInRange:
    """True iff numeric(field) ∈ [lo, hi]."""
    field: str
    lo: int
    hi: Union[int, str]


@dataclass(frozen=True)
class FieldCount:
    """True iff the number of items in a repeated/list field ∈ [lo, hi].

    General cardinality atom (universal PKI concept): 'at least one X' -> lo=1;
    'MUST NOT appear more than once' (uniqueness) -> hi=1; 'exactly one' -> lo=hi=1.
    hi='MAX_INT' means unbounded above. Driven by IR min_count/max_count, not text."""
    field: str
    lo: int
    hi: Union[int, str]


@dataclass(frozen=True)
class RSAModulusBitsInRange:
    """RSA modulus bit-length in [lo, hi] (codegen-only; positional parity with
    templates_v2.dsl for the app->tv bridge). Fields: lo, hi."""
    lo: int
    hi: Union[int, str]


@dataclass(frozen=True)
class RSAPublicExponentInRange:
    """RSA public exponent in [lo, hi] (codegen-only; bridge parity). Fields: lo, hi."""
    lo: int
    hi: Union[int, str]


@dataclass(frozen=True)
class FieldMatchesRegex:
    """True iff field value matches the named regex."""
    field: str
    pattern_name: str


@dataclass(frozen=True)
class ItemMatchesRegex:
    """True iff each list item matches the named regex."""
    pattern_name: str


@dataclass(frozen=True)
class FieldNotMatchesRegex:
    """True iff field value does NOT match the named regex."""
    field: str
    pattern_name: str


@dataclass(frozen=True)
class ItemNotMatchesRegex:
    """True iff each list item does NOT match the named regex."""
    pattern_name: str


@dataclass(frozen=True)
class FieldEncodedAs:
    """True iff field is encoded as one of the given ASN.1 tag types."""
    field: str
    types: tuple  # e.g. ("IA5String", "UTF8String")


@dataclass(frozen=True)
class IsCA:
    """True iff certificate is a CA (BasicConstraintsValid && IsCA)."""
    pass


@dataclass(frozen=True)
class IsRootCA:
    """True iff certificate is a self-signed CA root."""
    pass


@dataclass(frozen=True)
class PathLenConstraintPresent:
    """True iff basicConstraints carries a pathLenConstraint field. zcrypto exposes
    it via MaxPathLen (>=0 when present) / MaxPathLenZero (true when present and 0);
    absent encodes as MaxPathLen==-1 && !MaxPathLenZero. Universal PKI concept,
    observable from a single certificate."""


@dataclass(frozen=True)
class IsEndEntity:
    """True iff certificate is an end-entity (not a CA, i.e., subscriber/leaf)."""
    pass


@dataclass(frozen=True)
class IsServerCert:
    """True iff certificate is a TLS server certificate (subscriber with server purpose)."""
    pass


@dataclass(frozen=True)
class IsSubscriberCert:
    """True iff certificate is a subscriber/end-entity certificate (not a CA)."""
    pass


@dataclass(frozen=True)
class DNEmpty:
    """True iff the DN component is empty."""
    holder: str  # "Subject" or "Issuer"


@dataclass(frozen=True)
class DomainComponentOrdered:
    """True iff DomainComponent RDN values are in DNS-order."""
    pass


@dataclass(frozen=True)
class CRLDPHasNameRelative:
    """True iff the CRLDistributionPoints extension contains at least one
    DistributionPoint using the nameRelativeToCRLIssuer alternative (not fullName).
    Construction-side mirror for the app→tv bridge (renders/validates in the
    codegen + templates_v2 stacks)."""
    pass


@dataclass(frozen=True)
class BytesEq:
    """True iff two fields' raw DER bytes are equal."""
    field_a: str
    field_b: str


@dataclass(frozen=True)
class BytesContainsOidDer:
    """True iff field's raw bytes contain the given OID in DER encoding."""
    field: str
    oid_const: str


@dataclass(frozen=True)
class ExtensionURISchemeInSet:
    """True iff at least one extension's extnValue contains a URI matching one
    of the given schemes. Used for 'SHOULD NOT include https:// URIs in
    extensions' (r28449) — walks the raw DER of each extension looking for
    ia5String-encoded URI content, then checks the scheme prefix."""
    schemes: tuple  # e.g. ("https", "ldaps") — schemes to check for


@dataclass(frozen=True)
class OidEq:
    """True iff OID field equals the given OID constant."""
    field: str
    oid_const: str


@dataclass(frozen=True)
class OidListContains:
    """True iff field (OID list) contains the given OID constant."""
    field: str
    oid_const: str


@dataclass(frozen=True)
class OidListCountInSet:
    """Number of entries in an OID-list field whose OID is in allowed_oids is in
    [lo, hi] inclusive ("exactly one / >=N of {set}"). Field order MUST match
    templates_v2.dsl.OidListCountInSet (positional bridge in det_codegen)."""
    field: str
    allowed_oids: tuple   # tuple[str] of OID_CONST names
    lo: int
    hi: object            # int OR "MAX_INT"


@dataclass(frozen=True)
class CertPolicyExplicitTextHasEncodingTagInSet:
    """True iff at least one explicitText in CertPolicy is encoded as one of the given types."""
    types: tuple

@dataclass(frozen=True)
class CertPolicyExplicitTextHasEncodingTagNotInSet:
    """True iff all explicitText in CertPolicy are encoded as types NOT in the given set."""
    excluded_types: tuple


@dataclass(frozen=True)
class ListAllMatch:
    """True iff ALL items in list_field satisfy the inner atom."""
    list_field: str
    inner: object


@dataclass(frozen=True)
class ListAnyMatch:
    """True iff AT LEAST ONE item in list_field satisfies the inner atom."""
    list_field: str
    inner: object


@dataclass(frozen=True)
class IPListAllOctetCount:
    """True iff ALL IP addresses in list_field have exactly cnt octets."""
    list_field: str
    count: int


@dataclass(frozen=True)
class IPListAllOctetCountIn:
    """True iff ALL IP addresses in list_field have an octet count in the given set."""
    list_field: str
    allowed_counts: tuple


@dataclass(frozen=True)
class SubtreeIPListAnyHasOctetCount:
    """True iff at least one IP in the NameConstraints subtree has cnt octets."""
    field: str
    count: int


@dataclass(frozen=True)
class SubtreeIPListAnyHasOctetCountIn:
    """True iff at least one IP in the NameConstraints subtree has an octet count in the given set."""
    field: str
    allowed_counts: tuple


@dataclass(frozen=True)
class AIAMethodLocationsAnyMatchRegex:
    """True iff at least one SIA method of given type has URL matching pattern."""
    field: str
    method_oid_const: str
    pattern_name: str


@dataclass(frozen=True)
class AIAHasMethodOtherThan:
    """True iff the AccessDescription-shaped extension (AIA or SIA, named by
    ext_oid) contains an accessMethod OID NOT in allowed_oids. Re-parses the raw
    extension DER (zcrypto keeps only ocsp/caIssuers for AIA). General shape for
    'extension MUST NOT include access methods other than {S}'. Field order MUST
    match templates_v2.dsl.AIAHasMethodOtherThan (positional bridge in det_codegen)."""
    ext_oid: str          # OID_CONST name (AiaOID / SubjectInfoAccessOID)
    allowed_oids: tuple   # tuple[str], each an OID_CONST name


@dataclass(frozen=True)
class CrossFieldEq:
    """True iff two fields have equal values."""
    field_a: str
    field_b: str


@dataclass(frozen=True)
class ScalarInList:
    """True iff scalar field value appears in the string-list field."""
    scalar_field: str
    list_field: str


@dataclass(frozen=True)
class SigAlgMatchesTBSSignature:
    """True iff the certificate's signatureAlgorithm field is byte-for-byte
    identical to the tbsCertificate.signature field (RFC 5280 §4.1.1.2 /
    §4.1.2.3).  Zero-arg: the comparison re-parses the cert DER, mirroring
    zlint's e_mismatched_signature_algorithm_identifier."""


@dataclass(frozen=True)
class CommonNameFromSAN:
    """True iff subject commonName, when present, equals one of the SAN
    dNSName / iPAddress entries (RFC 5280 §4.2.1.6; CABF BR — commonName MUST
    contain a value from the subjectAltName). Zero-arg within-certificate
    cross-field check; mirrors zlint's e_subject_common_name_not_from_san.
    Vacuously true when commonName is empty."""


@dataclass(frozen=True)
class CRLNumberInRange:
    """True iff CRLNumber integer field is within [lo, hi]."""
    lo: int
    hi: Union[int, str]  # "MAX_INT" allowed


@dataclass(frozen=True)
class CRLDPHasNameRelativeWithMultiIssuer:
    """True iff the CRL Distribution Points extension is present AND
    contains at least one DistributionPoint whose distributionPoint
    CHOICE is nameRelativeToCRLIssuer AND whose cRLIssuer field contains
    more than one GeneralName. Re-parses raw DER. Zero-arg. Generic
    shape: 'MUST NOT use nameRelativeToCRLIssuer when cRLIssuer contains
    more than one distinguished names'."""
    pass


@dataclass(frozen=True)
class SerialNumberInRange:
    """True iff SerialNumber octet length is within [lo, hi]."""
    lo: int
    hi: Union[int, str]  # "MAX_INT" allowed


@dataclass(frozen=True)
class PathLenConstraintHas:
    """True iff BasicConstraints pathLenConstraint satisfies the given operator.

    op: one of "eq", "le", "lt", "ge", "gt"
    value: integer (None means not present / no constraint)
    """
    op: str
    value: Union[int, None]


@dataclass(frozen=True)
class TimeZoneUTC:
    """True iff validity times are encoded in UTC/GMT timezone (Zulu, no fractional seconds)."""
    pass


@dataclass(frozen=True)
class URISchemeNotInSet:
    """True iff no URI in the list field uses any of the forbidden schemes."""
    list_field: str
    excluded_schemes: tuple  # e.g. ("http", "ldap")


@dataclass(frozen=True)
class CrossFieldMatch:
    """True iff field_a value matches field_b value (string equality)."""
    field_a: str
    field_b: str
    op: str
    value: Union[int, None]


# =====================================================================
# COMPOUNDS
# =====================================================================

@dataclass(frozen=True)
class And:
    """True iff ALL parts are true."""
    parts: tuple


@dataclass(frozen=True)
class Or:
    """True iff AT LEAST ONE part is true."""
    parts: tuple


@dataclass(frozen=True)
class Not:
    """True iff the inner is false."""
    inner: object


@dataclass(frozen=True)
class When:
    """Conditional: true iff `cond` holds, then `main` must hold.

    Models "X MUST be Y when Z is present" — the lint should check Y only
    if condition Z holds. In relate()/canon(), When(cond, main) is treated
    equivalently to the main atom (the condition is a scoping precondition,
    not a separate constraint on the cert).
    """
    cond: object
    main: object


# =====================================================================
# Helpers
# =====================================================================

def field_name(a) -> str:
    """Return the field name for an atom (used in canonical sorting)."""
    return getattr(a, "field", getattr(a, "list_field", getattr(a, "oid", "")))


def atom_eq(a, b) -> bool:
    """Deep equality for atoms (handles tuples inside)."""
    if type(a) is not type(b):
        return False
    for f in fields(a):
        va = getattr(a, f.name)
        vb = getattr(b, f.name)
        if isinstance(va, tuple) and isinstance(vb, tuple):
            if va != vb:
                return False
        elif va != vb:
            return False
    return True


def compound_to_json(node) -> dict:
    """Convert a DSL node to a JSON-serializable dict."""
    if isinstance(node, (And, Or)):
        return {"op": type(node).__name__, "parts": [compound_to_json(p) for p in node.parts]}
    if isinstance(node, Not):
        return {"op": "Not", "inner": compound_to_json(node.inner)}
    # Atom
    d = {"op": type(node).__name__}
    for f in fields(node):
        v = getattr(node, f.name)
        if isinstance(v, tuple):
            d[f.name] = list(v)
        elif hasattr(v, "__dataclass_fields__"):  # nested DSL node (atom or compound)
            d[f.name] = compound_to_json(v)
        else:
            d[f.name] = v
    return d


def json_to_compound(d: dict):
    """Parse a JSON dict back to a DSL node."""
    if not isinstance(d, dict):
        return d
    op = d.get("op", "")
    if op == "And":
        return And(tuple(json_to_compound(p) for p in d.get("parts", [])))
    if op == "Or":
        return Or(tuple(json_to_compound(p) for p in d.get("parts", [])))
    if op == "Not":
        return Not(json_to_compound(d.get("inner", {})))
    # Atom
    cls = _ATOM_BY_NAME.get(op)
    if cls is None:
        raise DSLError(f"unknown atom op {op!r}")
    kwargs = {k: v for k, v in d.items() if k != "op"}
    # convert lists back to tuples
    for fld in fields(cls):
        if fld.name in kwargs and isinstance(kwargs[fld.name], list):
            kwargs[fld.name] = tuple(kwargs[fld.name])
    return cls(**kwargs)


_ATOM_BY_NAME: dict[str, type] = {}


def _register_atoms():
    for _name, _cls in globals().items():
        if isinstance(_cls, type) and _cls.__name__[0].isupper() and _cls.__name__ not in ("DSLError",):
            _ATOM_BY_NAME[_cls.__name__] = _cls


_register_atoms()


# =====================================================================
# Validation
# =====================================================================

def validate(node) -> list[str]:
    """Return list of errors (empty = OK)."""
    if isinstance(node, (And, Or)):
        if not node.parts:
            return [f"empty {type(node).__name__}"]
        return [e for p in node.parts for e in validate(p)]
    if isinstance(node, Not):
        return validate(node.inner)
    if not hasattr(type(node), "__dataclass_fields__"):
        return [f"not a DSL node: {type(node).__name__}"]
    return []


# =====================================================================
# Self-test
# =====================================================================

if __name__ == "__main__":
    A = FieldNonEmpty("subject.cn")
    B = ExtCritical("KeyUsageOID")
    tree = And((A, B))
    j = compound_to_json(tree)
    print("json:", j)
    restored = json_to_compound(j)
    print("restored:", restored)
    print("equal:", atom_eq(tree, restored))
    print("validate:", validate(tree))