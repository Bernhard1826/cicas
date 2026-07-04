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
class IsSubCA:
    """True iff certificate is a subordinate CA (not a trust anchor)."""
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
class ExtensionURISchemeNotInSet:
    """True iff no URI carried inside any extension uses a forbidden scheme."""
    schemes: tuple


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


# =====================================================================
# POLICY QUALIFIER ATOMS — CertificatePolicies extension
# =====================================================================

@dataclass(frozen=True)
class CertPolicyHasQualifierOfType:
    """True iff at least one PolicyInformation in CertificatePolicies extension
    has a qualifier of the given type (CPSPointer=1 or UserNotice=2 per RFC 5280 §4.2.1.4).
    GENERAL ATOM: parameterized by qualifier type integer, applies universally."""
    qualifier_type: int  # 1=CPSPointer, 2=UserNotice


@dataclass(frozen=True)
class CertPolicyAnyQualifierOfType:
    """True iff at least one policy identifier in CertificatePolicies extension
    has a qualifier of the given type. Scans all PolicyInformation entries."""
    qualifier_type: int  # 1=CPSPointer, 2=UserNotice


@dataclass(frozen=True)
class CertPolicyQualifierOidsInSet:
    """True iff all policyQualifier OIDs in CertificatePolicies are in allowed_oids.
    GENERAL ATOM: parameterized by OID tuple, sound for policy qualifier restrictions."""
    allowed_oids: tuple  # tuple of OID strings


@dataclass(frozen=True)
class CertPolicyHasOnlyAllowedQualifiers:
    """True iff each PolicyInformation in CertificatePolicies has only qualifiers
    from the allowed set. Enforces that no disallowed qualifier types appear."""
    allowed_qualifier_types: tuple  # tuple of int (1=CPSPointer, 2=UserNotice)


# =====================================================================
# LIST OPERATORS
# =====================================================================

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
# NEW GENERIC ATOMS — for no_template gap closure
# =====================================================================

@dataclass(frozen=True)
class PolicyHasQualifierOID:
    """True iff the CertificatePolicies extension contains at least one PolicyInformation
    entry whose policyQualifiers SEQUENCE contains a qualifier with the given OID.

    Used for 'MUST contain only permitted policyQualifiers from the table' rules
    (e.g., cPSurl / userNotice). Re-parses the raw DER to extract qualifier OIDs.
    Generic: parameterized by OID constant name, applies to any CertPolicy extension."""
    oid_const: str  # e.g. "CpsQualifierOID" (1.3.6.1.5.5.7.3.1 or custom)


@dataclass(frozen=True)
class PolicyQualifierCountInRange:
    """True iff the number of policyQualifiers in at least one PolicyInformation
    entry is within [lo, hi].

    Used for 'MUST contain exactly N qualifiers' / 'MUST NOT have more than M'.
    Re-parses raw DER of CertPolicy extension content."""
    lo: int
    hi: Union[int, str]  # "MAX_INT" for unbounded


@dataclass(frozen=True)
class PolicyQualifierOIDNotInSet:
    """True iff no policyQualifier in any PolicyInformation entry has an OID
    from the forbidden set.

    Used for 'Any other qualifier MUST NOT be present' rules. Re-parses raw DER.
    Generic: parameterized by forbidden OID set, applies universally to CertPolicy."""
    forbidden_oids: tuple  # e.g. ("otherQualifierOID1", "otherQualifierOID2")


@dataclass(frozen=True)
class PolicyQualifierEncodedAsTag:
    """True iff at least one policyQualifier's qualifier field is encoded as
    one of the given ASN.1 tag types (e.g., ia5String for CPS pointer,
    SEQUENCE for userNotice).

    Used for 'MUST be formatted as follows' qualifier encoding rules.
    Generic: parameterized by allowed ASN.1 type tags, universally applicable."""
    types: tuple  # e.g. ("IA5String", "SEQUENCE")


@dataclass(frozen=True)
class PolicyQualifierOIDInSet:
    """True iff each policyQualifier OID is in the allowed set.
    When forbid_other=True, additionally asserts that no qualifier with an
    OID outside the allowed set may appear — implements 'any other qualifier
    MUST NOT be present'.

    Used for 'policyQualifiers MUST only be CPS or UserNotice' and
    'any other qualifier MUST NOT be present' rules. Re-parses raw DER.
    Generic: parameterized by allowed OID tuple + forbid_other flag."""
    allowed_oid_consts: tuple  # e.g. ("IdQtCps", "IdQtUnotice")
    forbid_other: bool = False  # True → all non-listed OIDs must be absent


@dataclass(frozen=True)
class ExtKeyUsageCountInRange:
    """True iff the ExtKeyUsage extension contains between lo and hi entries inclusive.
    Supports checking cardinality of EKU list (e.g., 'anyExtendedKeyUsage must be
    the only EKU when present').
    Generic: lo and hi are integers, handles any range check."""
    lo: int
    hi: object  # int OR "MAX_INT"


@dataclass(frozen=True)
class RDNHasSingleAttributeType:
    """True iff each RelativeDistinguishedName in the RDN Sequence contains
    exactly one AttributeTypeAndValue (i.e., no multi-AV RDN).

    Used for 'Each RDN MUST contain exactly one AttributeTypeAndValue' rules.
    Universal: single-certificate observable, no cross-certificate dependencies."""
    pass


@dataclass(frozen=True)
class DNNoDuplicateAttributeTypes:
    """True iff no AttributeType appears in more than one RDN across the
    full Distinguished Name.

    Used for 'Each Name MUST NOT contain more than one instance of a given
    AttributeTypeAndValue across all RDNs' rules. General PKI concept."""
    pass


@dataclass(frozen=True)
class ExtAccessLocationMatchesType:
    """True iff each AccessDescription in the extension has accessLocation
    encoded as the specified GeneralName CHOICE type.

    Used for 'each accessLocation MUST be encoded as the specified GeneralName type'.
    Parameterized by expected tag number (e.g., 6 for uniformResourceIdentifier).
    Generic: applies to AIA, SIA, and any extension with AccessDescription SEQUENCE."""
    tag: int  # GeneralName CHOICE tag: 0=otherName,1=rfc822Name,2=dNSName,3=x400Address,
    # 4=directoryName,5=ediPartyName,6=uniformResourceIdentifier,7=iPAddress,8=registeredID


@dataclass(frozen=True)
class ExtAccessDescriptionOrdered:
    """True iff AccessDescription entries in the extension are sorted by
    accessMethod OID in ascending order.

    Used for 'AccessDescription entries MUST be ordered by accessMethod priority'.
    Generic: applies to AIA/SIA extensions with AccessDescription SEQUENCE."""
    pass


@dataclass(frozen=True)
class OIDBytesMatchHex:
    """True iff the OID constant's DER bytes equal the given hex string.

    Used for 'AlgorithmIdentifier MUST be byte-for-byte identical with hex:...'
    rules. Re-parses the OID to DER and compares. Generic: parameterized by
    hex literal, universally applicable to any OID field."""
    oid_const: str   # OID constant name (e.g., "OidEcdsaWithSHA256")
    hex_bytes: str   # hex-encoded DER bytes (e.g., "300a06082a8648ce3d040302")


@dataclass(frozen=True)
class DNComponentOrderMatches:
    """True iff the sequence of DN components (RDNs or AVA order) matches
    the specified canonical order (e.g., country before locality, DNS reversed).

    Used for 'Domain Labels MUST be encoded in reverse order to DNS protocol'.
    Generic: parameterized by expected ordering rule, applies to Subject/Issuer DNs."""
    order_type: str  # e.g., "dns_reverse", "rfc2253", "profile_section_7"


@dataclass(frozen=True)
class FieldMatchesNoForbiddenChars:
    """True iff the string field contains none of the forbidden characters.

    Used for 'MUST NOT contain colons, spaces, or line feeds' rules.
    Generic: parameterized by forbidden character set, applies to any string field."""
    field: str
    forbidden_chars: tuple  # e.g. (":", " ", "\n")


@dataclass(frozen=True)
class ExtPolicyQualifierOIDInSet:
    """True iff the Certificate Policies extension contains a policy qualifier
    with one of the specified OIDs (CPS pointer or UserNotice).

    Used for 'policy qualifiers MUST be either CPS or UserNotice' rules.
    Generic: parameterized by allowed OID set, applies to CertPolicy extension."""
    allowed_oid_consts: tuple  # e.g. ("CpsOID", "UserNoticeOID")


@dataclass(frozen=True)
class ExtPolicyQualifierOIDNotInSet:
    """True iff the Certificate Policies extension does NOT contain any
    policy qualifier with the specified OID.

    Used for 'MUST NOT have CPS pointer' rules.
    Generic: parameterized by forbidden OID, applies to CertPolicy extension."""
    forbidden_oid_const: str  # e.g. "CpsOID"


@dataclass(frozen=True)
class ExtKeyUsageHasBit:
    """True iff the KeyUsage extension has the specified bit set.

    Used for 'keyUsage MUST have digitalSignature set' rules.
    Generic: parameterized by bit name, applies to KeyUsage extension."""
    bit: str  # e.g. "DigitalSignature", "KeyCertSign", "CRLSign"


@dataclass(frozen=True)
class ExtKeyUsageNotHasBit:
    """True iff the KeyUsage extension does NOT have the specified bit set.

    Used for 'keyUsage MUST NOT have keyCertSign for end-entity' rules.
    Generic: parameterized by bit name, applies to KeyUsage extension."""
    bit: str  # e.g. "KeyCertSign", "CRLSign"


@dataclass(frozen=True)
class ExtKeyUsageAllBitsInSet:
    """True iff the KeyUsage extension has EXACTLY the specified bits set.

    Used for 'keyUsage MUST have only digitalSignature and keyEncipherment' rules.
    Generic: parameterized by allowed bit set, applies to KeyUsage extension."""
    bits: tuple  # e.g. ("DigitalSignature", "KeyEncipherment")


@dataclass(frozen=True)
class SerialNumberLengthInRange:
    """True iff the serial number byte length is within [lo, hi].

    Used for 'serialNumber MUST be at least 8 octets' rules.
    Generic: parameterized by byte length range."""
    lo: int
    hi: int


@dataclass(frozen=True)
class ExtHasAllGeneralNameTags:
    """True iff the extension (SAN / subjectAltName) contains ALL of the
    specified GeneralName tag types.

    Used for 'subjectAlternativeName MUST contain both dNSName and iPAddress' rules.
    Generic: parameterized by required tag set, applies to subjectAltName extension."""
    required_tags: tuple  # e.g. (7,) for IPAddress, (2,) for rfc822Name


@dataclass(frozen=True)
class ExtHasAnyGeneralNameTags:
    """True iff the extension (SAN / subjectAltName) contains AT LEAST ONE
    of the specified GeneralName tag types.

    Used for 'subjectAlternativeName MUST contain either dNSName or iPAddress' rules.
    Generic: parameterized by allowed tag set, applies to subjectAltName extension."""
    allowed_tags: tuple  # e.g. (2, 7) for email or IP


@dataclass(frozen=True)
class SubjectCommonNameMatchesSAN:
    """True iff the Subject CommonName matches at least one SAN entry.

    Used for 'commonName MUST match a subjectAlternativeName entry' rules.
    Generic: no parameters, compares CN against existing SAN entries."""
    pass  # No parameters needed


@dataclass(frozen=True)
class IssuerOrgMatchesSAN:
    """True iff the Issuer Organization (O) matches the domain of a SAN entry.

    Used for 'issuer organization MUST match the domain in SAN' rules.
    Generic: no parameters, checks SAN domains against issuer O field."""
    pass  # No parameters needed


@dataclass(frozen=True)
class ExtAIAHasOCSPNoHTTP:
    """True iff the Authority Information Access extension has an OCSP
    responder URL that does NOT use HTTP scheme.

    Used for 'OCSP responder MUST NOT use HTTP' rules.
    Generic: no parameters, checks AIA OCSP URLs for scheme."""
    pass  # No parameters needed


@dataclass(frozen=True)
class ExtHasDuplicateGeneralNames:
    """True iff the extension (SAN) contains duplicate GeneralName values.

    Used for 'subjectAlternativeName MUST NOT contain duplicate DNS names' rules.
    Generic: no parameters, checks for duplicates within the SAN extension."""
    pass  # No parameters needed


@dataclass(frozen=True)
class ExtNotPresentOrHasProperty:
    """True iff the extension is absent, OR present AND satisfies the property.

    Used for 'if the extension is present, it MUST have property X' rules.
    Generic: parameterized by the property check."""
    oid: str  # e.g. "AiaOID"
    property: object  # nested atom to check if extension is present


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
