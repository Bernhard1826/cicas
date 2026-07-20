"""Single-artifact lintability rescue — shared decision predicate.

Both the controlled extractor (`controlled_llm_extractor._enforce_single_artifact_lintability`)
and the structural analyzer (`structural_analyzer._apply_strict_lintability_rules`) call this
ONE function so their criteria can never diverge. It decides whether a rule the LLM mislabeled
on a lintability axis (enforcement_phase=Validation off a purpose word /
rule_category=clarification) is in fact a COMPLETE, codeable, single-artifact-observable
constraint on a real certificate/CRL field — i.e. something a zlint check could actually be
written for.

SOUND BY CONSTRUCTION — returns True only when ALL hold:
  * predicate is observable on one artifact. ``conform_to`` is normally excluded because it
    may defer to an external specification, except when its source names another concrete field
    of the same certificate (for example subject.commonName derived from subjectAltName);
  * assertion_subject is Certificate / CRL / CA (CrossArtifact excluded);
  * obligation is normative (RFC2119, MAY/OPTIONAL excluded);
  * the subject's ROOT segment is a recognised certificate/CRL structural field — this is the
    tightening that rejects CABF *operational* rescues whose "subject" is an operational noun
    (domain_validation_record / phone_contact / randomValue / requestToken …): those are about
    CA process or the request, not certificate content, so NOT lintable;
  * the rule text is NOT a markdown table-row fragment (" | " cell delimiter) and not a stub
    (< 15 chars) — profile-table fragments like "1 | MUST" / "policyQualifiers | NOT RECOMMENDED"
    are not standalone codeable rules;
  * NO cross-artifact / runtime marker is present (uniqueness across certs, issuer-cert/CRL
    correlation, network/OCSP/time/availability).
"""
from __future__ import annotations
import re

# Observable single-artifact predicates (the proven-lintable vocabulary of the lintable corpus).
OBSERVABLE_PREDICATES = {
    "must_equal", "must_include", "must_be_present", "must_not_be_present",
    "must_not_include", "encode_as", "allowed_values",
    "must_be_critical", "must_not_be_critical", "in_range", "matches_pattern",
}


def _same_certificate_field_conformance(predicate, subject_path, rule_text) -> bool:
    """Whether ``conform_to`` denotes a closed relation between cert fields.

    A generic ``conform_to`` can require a runtime algorithm or a real-world
    fact, and is therefore not lintable.  This narrow exception only admits a
    source rule that names ``subjectAltName`` while constraining another
    recognised certificate field.  Both values live in the same certificate
    DER, so the relation is independently observable without issuer, chain, or
    external state.  It is a field-relation criterion, not a rule-id mapping.
    """
    if _norm(predicate).lower() != "conform_to":
        return False
    subject = _norm(subject_path).lower()
    if not subject or subject.split(".")[0] not in CERT_FIELD_ROOTS:
        return False
    text = _primary_rule_text(rule_text).lower()
    return bool(re.search(r"\bsubjectaltname\b", text, re.IGNORECASE))

# Normative obligations (MAY / OPTIONAL excluded).
NORMATIVE_OBLIGATIONS = {
    "MUST", "MUST NOT", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT",
    "RECOMMENDED", "NOT RECOMMENDED",
}

# Recognised certificate / CRL structural field ROOTS (first path segment of the subject).
# This is the discriminator that separates a real field constraint from a CABF operational
# rule whose subject is an operational noun. Mirrors the cert/CRL ASN.1 structure, NOT rule ids.
CERT_FIELD_ROOTS = {
    # certificate structure
    "certificate", "tbscertificate", "cert",
    "version", "serialnumber", "serial_number", "signature",
    "signaturealgorithm", "signaturevalue",
    "issuer", "validity", "notbefore", "notafter",
    "subject", "subjectpublickeyinfo", "publickey",
    "issueruniqueid", "subjectuniqueid", "extensions", "extension",
    # CRL document structure
    "tbscertlist", "crl", "thisupdate", "nextupdate", "crlnumber",
    "revokedcertificates", "revokedcertificate", "crlextensions", "crlentry",
}

# Cross-artifact / runtime markers — presence means the check needs >1 artifact or runtime state.
CROSS_OR_RUNTIME_MARKERS = [
    r"unique\s+for\s+each", r"unique\s+to\s+each", r"other\s+certificate",
    r"each\s+certificate\s+issued", r"issued\s+by\s+(?:a\s+|the\s+)?(?:given\s+)?ca\b",
    r"encoding\s+in\s+(?:the\s+)?issuer\s+field", r"same\s+as\s+the\s+encoding",
    r"strictly\s+increasing", r"delta\s+crl", r"complete\s+crl", r"same\s+scope",
    r"available\s+via\s+(?:http|ftp|ldap|electronic\s+mail)", r"\bis\s+revoked\b",
    r"\bocsp\b", r"current\s+time", r"\bnetwork\b", r"external\s+registr",
    r"cross[\s-]?certif", r"corresponding\s+certificate",
    r"when\s+comparing", r"case-insensitive", r"comparing\s+dns\s+names",
    r"evaluating\s+name\s+constraints", r"label-by-label", r"for\s+equality",
]
_MARKER_RE = re.compile("|".join(CROSS_OR_RUNTIME_MARKERS), re.I)

CROSS_ARTIFACT_RELATION_PATTERNS = [
    r"certificates?\s+issued\s+by\s+the\s+subject\s+of\s+this\s+certificate",
    r"certificates?\s+issued\s+by\s+the\s+subject\s+ca\b",
    r"crls?\s+issued\s+by\s+the\s+subject\s+crl\s+issuer\b",
    r"certificates?\s+issued\s+by\s+this\s+certificate",
    r"certificates?\s+issued\s+by\s+(?:the\s+)?issuer",
    r"of\s+another\s+certificate",
    r"of\s+the\s+precertificate",
    r"of\s+the\s+issuer\s+certificate",
    r"corresponding\s+certificate",
]
_CROSS_ARTIFACT_RELATION_RE = re.compile("|".join(CROSS_ARTIFACT_RELATION_PATTERNS), re.I)


# High-precision NEGATIVE patterns: rule text that a single-certificate linter
# cannot observe, regardless of how the LLM labeled the axes. Each was validated
# to flag ZERO of the codegen-proven-synonymous rules and only genuinely
# un-observable rules (CA process/recordkeeping, CA-verifies-applicant, "MUST NOT
# be used to issue", user/application behavior, randomness/entropy, signing-key /
# cross-cert / runtime, and real-world semantic content like "MUST contain the
# Subject's actual locality"). These force lintable=False so they never reach
# codegen. Deliberately high-precision (modest recall) — the nuanced remainder is
# handled by the strict LLM lintability judge gate on the codegen target.
_NOT_OBSERVABLE_PATTERNS = [
    # CA / issuer PROCESS conduct (recordkeeping, vetting), not certificate content
    r"\b(CAs?|Issuing CA|Issuers?)\b[^.]{0,60}\b(SHALL|MUST|SHOULD)\b[^.]{0,40}\b(maintain|retain|keep a record|keep records|record|log|archive|audit|monitor|store records)\b",
    r"\b(CAs?|Issuing CA|Issuers?)\b[^.]{0,40}\b(SHALL|MUST|SHOULD)\b[^.]{0,40}\b(confirm|verify|determine|ensure|establish|obtain)\b[^.]{0,40}\b(that the |the )?(Applicant|Subscriber|requester|requestor|domain|identity|control|ownership)\b",
    r"\bApplicant information\b[^.]{0,80}\b(SHALL|MUST|SHOULD)\b[^.]{0,80}\b(include|contain|identify|provide)\b",
    r"\b(?:DNS\s+)?(?:TXT\s+)?record\b[^.]{0,80}\b(SHALL|MUST|SHOULD)\b[^.]{0,80}\b(?:placed|published|located)\b[^.]{0,120}\b(?:Authorization Domain Name|domain name|label)\b",
    r"\bMUST NOT be used to issue\b|\bSHALL NOT be used to issue\b",
    # application / relying-party / user runtime behavior
    r"\b(users?|applications?|relying part(y|ies)|clients?)\b[^.]{0,50}\b(SHALL|MUST|SHOULD)\b[^.]{0,40}\b(be prepared|be able to|process|accept|reject|support|recognize)\b",
    # randomness / entropy — not observable from one encoded value
    r"\b(CSPRNG|non-sequential|unpredictab|entropy)\b|\bat least \d+ bits of (output|entropy)\b",
    # cross-certificate / signing-key / runtime
    r"\b(signing key|issued by (a |the )?(given )?ca|corresponding certificate|during (validation|path|chain)|when validating|chain build|\bis revoked\b|current time)\b",
    r"\b(?:CA\s+)?Private Key\b[^.]{0,80}\b(SHALL|MUST)\s+NOT\b[^.]{0,80}\bbe used to sign\b",
    r"\bcertificates?\s+issued\s+by\s+the\s+subject\s+ca\b",
    r"\bcrls?\s+issued\s+by\s+the\s+subject\s+crl\s+issuer\b",
    # cross-artifact: cert<->CRL issuer identity comparison (knowing "the CRL issuer"
    # needs the external CRL, not this certificate's bytes) and CRLDP/AIA rules whose
    # requirement is about what the URI POINTS TO (an external DER CRL / LDAP directory
    # entry), not the certificate's own encoded bytes. These should be
    # assertion_subject=CrossArtifact; this high-precision gate corrects them.
    r"\bcertificate issuer is (also |not )?the crl issuer\b",
    r"\bURI MUST point to\b",
    r"\bdirectory entry where (the )?crl is located\b",
    r"\bURI MUST include a <\w+>",
    # aspirational / actor-intent / external-directory / real-world antecedents whose
    # applicability or truth is NOT decidable from one certificate's bytes:
    #   "wherever possible"            — no determinate predicate (aspirational SHOULD)
    #   "whenever ... are to be bound" — depends on issuer intent, not cert content
    #   "the entry holding the CRL"    — names an external directory entry's content
    #   "value derived from ..."       — real-world derivation (truth not in the bytes),
    #                                    except when the source value is explicitly
    #                                    another certificate field such as
    #                                    subjectAltName.
    r"\bwherever possible\b",
    r"whenever .{0,30}identities are to be bound",
    r"the entry holding the\b",
    r"\bmust contain a value derived from\b(?![^.]{0,120}\bsubjectAltName\b)",
    # real-world SEMANTIC content (truth not mechanically checkable)
    r"\bMUST (contain|include|reflect|represent)\b[^.]{0,40}\bthe (Subject|Applicant|Organization|certificate holder)\W?s?\b[^.]{0,45}(actual|real|true|legal|official|verified)?\s*(name|locality|location|address|identity|information|jurisdiction)\b",
    # actor / key-usage INTENT antecedent — the rule's applicability turns on what
    # the key is "only to be used for", which is intent, not decidable from the
    # certificate's bytes (the keyUsage bits are observable, but the triggering
    # purpose is not). Often a definition of bit semantics, not a codeable check.
    r"\bonly to be used\b",
    # OPEN-ENDED ENUMERATION: "https, ldaps, or similar schemes" / "or similar
    # values" does not define a closed machine-checkable set. A lint can check
    # the named examples, but it cannot be strictly equivalent to the open-ended
    # "similar" class without extra policy vocabulary outside the certificate.
    r"\bor similar (?:schemes?|values?|methods?|types?|forms?)\b",
    # certificate categorisation by real-world PURPOSE ("certificates for <X>
    # purposes" / "for infrastructure purposes") — the cert's purpose is not in its
    # bytes; the clause names a category of certs, not a field constraint. NOTE:
    # "for the purposes of this profile" is scoping prose and is NOT matched (it has
    # no "certificate(s) for <word> purposes" / "for <category> purposes" shape).
    r"\bcertificates?\s+for\s+\w+\s+purposes\b",
    r"\bfor\s+(?:administrative|infrastructure|internal|operational)\b[^.]{0,40}\bpurposes\b",
    # IDNA2008 processing PARAMETER, not a certificate field: the AllowUnassigned
    # flag governs how a validator maps unassigned code points during name
    # comparison (RFC 5280 §7.2 / RFC 5891); it is never encoded in the
    # certificate, so "the AllowUnassigned flag SHALL NOT be set" is not
    # single-certificate observable. (matches exactly R31308 corpus-wide)
    r"\ballowunassigned flag\b",
    # ISSUER-INTENT antecedent: "to indicate that a certificate has no
    # well-defined expiration date, the notAfter SHOULD be 99991231235959Z" is
    # conditional guidance keyed on what the issuer WANTS TO CONVEY. The intent
    # is not decidable from the bytes (a normal notAfter is not a violation), so
    # the obligation is not observable. (matches exactly R31150 corpus-wide)
    r"no well-defined expiration date",
    # HISTORICAL SUBJECT STATE: "certificates for new subjects" / "previously
    # established" depends on issuance history outside the presented certificate.
    # A single certificate exposes its current subject name encoding, but not
    # whether that subject/attribute was new or already established elsewhere.
    r"\bcertificates?\s+for\s+new\s+subjects?\b",
    r"\bpreviously\s+established\b",
    # CROSS-ORGANISATION relationship: "CA certificates issued to other
    # organizations" turns on the issuer/subject organisational relationship,
    # which is not decidable from a single certificate's bytes.
    # (matches exactly R30979 corpus-wide)
    r"issued to other organizations",
    # CROSS-ARTIFACT: the requirement compares the certificate to the external
    # certificate REQUEST (CSR) — e.g. "Token SHALL incorporate the key used in
    # the certificate request". The request is not part of the issued
    # certificate's bytes, so this is not single-certificate observable.
    # (matches exactly R28783 corpus-wide)
    r"key used in the certificate request",
    # ENCODING BYTE-ORDER not observable post-parse: "the address MUST be stored
    # in the octet string in network byte order" constrains the raw octet-string
    # byte order, but zcrypto exposes a parsed net.IP (byte order already
    # interpreted / lost); a validly-parsed IP is network-byte-order by
    # definition, so the obligation is tautological/unobservable.
    # (matches exactly R31391 corpus-wide)
    r"network byte order",
]
_NOT_OBSERVABLE_RE = re.compile("|".join(_NOT_OBSERVABLE_PATTERNS), re.I)
_OPEN_ENDED_ENUMERATION_RE = re.compile(
    r"\bor similar (?:schemes?|values?|methods?|types?|forms?)\b",
    re.I,
)
_EXTERNAL_AVAILABILITY_RE = re.compile(
    r"\b(?:where|when|if)\b[^.]{0,80}\bavailable via\s+"
    r"(?:HTTP|HTTPS|FTP|LDAP|electronic mail|email)\b",
    re.I,
)
_PREFERENCE_ORDER_RE = re.compile(
    r"\bordered in priority\b|\bmost-preferred\b",
    re.I,
)
_UNEXPANDED_SECTION_REFERENCE_RE = re.compile(
    r"\b(?:encoded|formatted) as specified in \[?Section\s+\d"
    r"|\bas specified in \[?Section\s+\d",
    re.I,
)
_TABLE_FORMAT_REFERENCE_RE = re.compile(
    r"\bformatted as follows:\s*(?:Table\b)?",
    re.I,
)
_CROSS_CERTIFIED_PROFILE_RE = re.compile(
    r"\bcross[\s-]?(?:certified|signed)\b",
    re.I,
)
_CRL_DOCUMENT_STRUCTURE_RE = re.compile(
    r"\b(?:CertificateList|TBSCertList|tbsCertList|crlEntryExtensions|"
    r"crlExtensions|revokedCertificates)\b",
    re.I,
)
_CRL_VERSION_FRAGMENT_RE = re.compile(
    r"^\s*(?:--\s*)?if present,\s*(?:version\s+)?MUST\s+be\s+v2\s*$",
    re.I,
)
_PRECERT_SIGNING_CA_CONTEXT_RE = re.compile(
    r"\bPrecertificates?\s+issued\s+by\s+a\s+Precertificate\s+Signing\s+CA\b"
    r"|\bfrom\s+a\s+Precertificate\s+Signing\s+CA\s+Certificate\b",
    re.I,
)
_NON_TLS_TECHNICALLY_CONSTRAINED_PROFILE_RE = re.compile(
    r"\bTechnically\s+Constrained\s+Non-TLS\s+Subordinate\s+CA\b"
    r"|\bwill\s+not\s+be\s+used\s+to\s+issue\s+TLS\s+certificates?\s+directly\s+or\s+transitively\b",
    re.I,
)
_TLS_TECHNICALLY_CONSTRAINED_PROFILE_RE = re.compile(
    r"\bTechnically\s+Constrained\s+TLS\s+Subordinate\s+CA\b"
    r"|\bwill\s+be\s+used\s+to\s+issue\s+TLS\s+certificates?\s+directly\s+or\s+transitively\b",
    re.I,
)
_PRECERT_SIGNING_CA_PROFILE_RE = re.compile(
    r"\bTechnically\s+Constrained\s+Precertificate\s+Signing\s+CA\b"
    r"|\bwill\s+be\s+used\s+as\s+a\s+Precertificate\s+Signing\s+CA\b",
    re.I,
)
_VALIDATION_LEVEL_PROFILE_RE = re.compile(
    r"\bFor\s+a\s+Subscriber\s+Certificate\s+to\s+be\s+"
    r"(?:(?:Domain|Individual|Organization)\s+Validated|Extended\s+Validation)\b"
    r"|\b(?:(?:Domain|Individual|Organization)\s+Validated|Extended\s+Validation)\b",
    re.I,
)
_VALIDATION_POLICY_ASSERTION_RE = re.compile(
    r"\bMUST\s+assert\b.{0,180}\bReserved\s+Certificate\s+Policy\s+Identifier\b"
    r"(?:.{0,160}\bpolicyIdentifier\b)?",
    re.I,
)
_DIRECTORYSTRING_ALLOWED_ENCODING_RE = re.compile(
    r"(?=.*\bDirectoryString\b)(?=.*\bPrintableString\b)(?=.*\bUTF8String\b)",
    re.I | re.S,
)
_DIRECTORYSTRING_LEGACY_EXCEPTION_RE = re.compile(
    r"\bpreviously\s+(?:issued|established)\b|"
    r"\bpreserve\s+backward\s+compatibility\b",
    re.I,
)
_CABF_NAME_ENCODING_RULE_RE = re.compile(
    r"\b(?:Name|RelativeDistinguishedName|RDNSequence|AttributeTypeAndValue)\b",
    re.I,
)
_CABF_NAME_ENCODING_EXTERNAL_SCOPE_RE = re.compile(
    r"\bdoes\s+not\s+include\s+certificates\s+issued\s+by\s+such\s+CA\s+Certificates\b"
    r"|\bCross-Certified\s+Subordinate\s+CA\s+Certificate\b.{0,160}\bexception\b",
    re.I | re.S,
)
_CABF_RSA_SIGNATURE_ALGID_RULE_RE = re.compile(
    r"\bsignature\s+algorithms?\s+and\s+encodings?\b"
    r"|\bAlgorithmIdentifier\b.{0,120}\bbyte-for-byte\s+identical\b",
    re.I | re.S,
)
_CABF_RSA_ALLOWED_SET_RULE_RE = re.compile(
    r"\b(?:CA\s+)?(?:SHALL|MUST)\s+use\s+one\s+of\s+the\s+following\s+"
    r"signature\s+algorithms?\s+and\s+encodings?\b"
    r"|\bNo\s+other\s+encodings\s+are\s+permitted\b",
    re.I | re.S,
)
_CABF_RSA_SHA1_TEMPORARY_DEADLINE_RE = re.compile(
    r"\b(?:Until|Prior\s+to)\s+2026[-\u2010-\u2015]09[-\u2010-\u2015]15\b",
    re.I,
)
_CABF_RSA_SHA1_EXCEPTION_ALG_RE = re.compile(
    r"\bRSASSA-PKCS1-v1_5\s+with\s+SHA-1\b",
    re.I,
)
_CABF_RSA_SHA1_EXTERNAL_CONDITION_RE = re.compile(
    r"\b(?:Cross-Certificate|existing\s+Certificate|BasicOCSPResponse|"
    r"CertificateList|TBSCertList|same\s+issuing\s+CA\s+Certificate|"
    r"Root\s+CA\s+or\s+Subordinate\s+CA\s+Certificate\s+has\s+issued)\b",
    re.I,
)
_CABF_ECDSA_SIGNING_KEY_CONTEXT_RE = re.compile(
    r"\bIf\s+the\s+signing\s+key\s+is\s+P-(?:256|384|521)\b"
    r"|\bbased\s+upon\s+the\s+signing\s+key\s+used\b",
    re.I,
)
_CABF_ECDSA_ALGID_BYTE_ROW_RE = re.compile(
    r"\bAlgorithmIdentifier\b.{0,120}\bbyte-for-byte\s+identical\b"
    r".{0,120}\b300a06082a8648ce3d04030[234]\b",
    re.I | re.S,
)
_RFC_SUBJECT_NAMING_ONLY_SAN_RE = re.compile(
    r"\bsubject\s+naming\s+information\s+is\s+present\s+only\s+in\s+"
    r"(?:the\s+)?subjectAltName\s+extension\b",
    re.I,
)
_RFC_SUBJECT_NAMING_ONLY_SAN_EXAMPLE_RE = re.compile(
    r"\be\.g\.\s*,?\s*a\s+key\s+bound\s+only\s+to\s+an\s+email\s+address\s+or\s+URI\b",
    re.I,
)
_RFC_ONLY_SUBJECT_IDENTITY_ALTNAME_RE = re.compile(
    r"\bonly\s+subject\s+identity\s+included\s+in\s+the\s+certificate\s+is\s+"
    r"an\s+alternative\s+name\s+form\b",
    re.I,
)
_RFC_BASICCONSTRAINTS_CA_ROLE_PRESENCE_RE = re.compile(
    r"\bMUST\s+include\s+this\s+extension\s+in\s+all\s+CA\s+certificates\s+"
    r"that\s+contain\s+public\s+keys\s+used\s+to\s+validate\s+digital\s+"
    r"signatures\s+on\s+certificates\b",
    re.I,
)
_CSR_KEY_REQUEST_RE = re.compile(
    r"key used in the certificate request",
    re.I,
)
_IP_NETWORK_BYTE_ORDER_RE = re.compile(
    r"network byte order",
    re.I,
)
_SAN_SEMANTIC_IDENTITY_CHOICE_RE = re.compile(
    r"\bsubjectAltName\b.{0,100}\bcontains?\b.{0,100}\b"
    r"(?:Internet\s+mail\s+address|domain\s+name\s+system\s+label|"
    r"DNS\s+representation\s+for\s+Internet\s+mail\s+addresses)\b"
    r".{0,160}\b(?:MUST|SHALL)\b.{0,80}\b"
    r"(?:stored|encoded)\s+in\s+(?:the\s+)?"
    r"(?:rfc822Name|dNSName|uniformResourceIdentifier|iPAddress)\b",
    re.I | re.S,
)


def context_lintability_assertion_subject(reason: str | None) -> str:
    if reason and "CRL/TBSCertList" in reason:
        return "CRL"
    return "CrossArtifact"


def non_single_artifact_context_lintability_reason(*texts) -> str | None:
    """Return a C2 lintability reason from source-owned context.

    Some profile names define applicability by an issuance/trust relationship
    rather than by bytes in the certificate being linted.  The rule body can be
    a normal certificate-field predicate, but a final zlint lint cannot be
    strictly equivalent because it cannot decide whether the certificate belongs
    to that profile from one artifact alone.
    """
    context = " ".join(str(t or "") for t in texts if t)
    rule_text = _primary_rule_text(texts[1] if len(texts) > 1 else (texts[0] if texts else ""))
    direct_reason = non_single_artifact_lintability_reason(rule_text)
    if direct_reason:
        return direct_reason
    if (
        any(_CRL_VERSION_FRAGMENT_RE.search(_primary_rule_text(t or "")) for t in texts)
        and _CRL_DOCUMENT_STRUCTURE_RE.search(context)
    ):
        return (
            "rule target is a CRL/TBSCertList ASN.1 field, a separate CRL "
            "artifact outside the certificate-lint denominator"
        )
    if (
        _VALIDATION_POLICY_ASSERTION_RE.search(rule_text)
        and _VALIDATION_LEVEL_PROFILE_RE.search(context)
    ):
        return (
            "rule applicability is scoped to a subscriber validation-level "
            "profile, but this rule asserts the same Reserved Certificate "
            "Policy Identifier used as the profile's certificate-encoded "
            "discriminator; a missing-policy-OID violation is not decidable "
            "from one certificate's encoded bytes without external validation "
            "type context"
        )
    if (
        _DIRECTORYSTRING_ALLOWED_ENCODING_RE.search(rule_text)
        and re.search(r"\bexceptions?\b", rule_text, re.I)
        and _DIRECTORYSTRING_LEGACY_EXCEPTION_RE.search(context)
    ):
        return (
            "rule allows DirectoryString legacy encodings under previously "
            "issued/previously established name compatibility exceptions, "
            "which require issuance-history context not decidable from one "
            "certificate's encoded bytes"
        )
    if (
        _CABF_NAME_ENCODING_RULE_RE.search(rule_text)
        and _CABF_NAME_ENCODING_EXTERNAL_SCOPE_RE.search(context)
    ):
        return (
            "CABF Name Encoding applicability inherits Section 7.1.2 scope, "
            "the exclusion for certificates issued by Technically Constrained "
            "Non-TLS Subordinate CA Certificates, and the Cross-Certified "
            "Subordinate CA exception, which require issuance/profile context "
            "not decidable from one certificate's encoded bytes"
        )
    if (
        _CABF_RSA_SIGNATURE_ALGID_RULE_RE.search(rule_text)
        and (
            _CABF_RSA_ALLOWED_SET_RULE_RE.search(rule_text)
            or _CABF_RSA_SHA1_EXCEPTION_ALG_RE.search(rule_text)
        )
        and _CABF_RSA_SHA1_TEMPORARY_DEADLINE_RE.search(context)
        and _CABF_RSA_SHA1_EXCEPTION_ALG_RE.search(context)
        and _CABF_RSA_SHA1_EXTERNAL_CONDITION_RE.search(context)
    ):
        return (
            "CABF RSA Signature AlgorithmIdentifier allowed-set requirements "
            "have a temporary SHA-1 exception before 2026-09-15 whose "
            "applicability depends on cross-certificate, existing-certificate, "
            "OCSP, or CRL context not decidable from one certificate's encoded "
            "bytes"
        )
    if (
        _CABF_ECDSA_ALGID_BYTE_ROW_RE.search(rule_text)
        and _CABF_ECDSA_SIGNING_KEY_CONTEXT_RE.search(context)
    ):
        return (
            "CABF ECDSA Signature AlgorithmIdentifier applicability is keyed "
            "to the issuer/signing-key curve, which is not encoded in the "
            "issued certificate; a single certificate exposes the chosen "
            "signatureAlgorithm OID but not whether it matches the external "
            "signing key"
        )
    if _CROSS_CERTIFIED_PROFILE_RE.search(context):
        return (
            "rule applicability is scoped to a cross-certified/cross-signed "
            "certificate profile, an issuance/trust relationship that is not "
            "decidable from one certificate's encoded bytes"
        )
    if _PRECERT_SIGNING_CA_CONTEXT_RE.search(context):
        return (
            "rule applicability depends on whether the Precertificate was "
            "issued by a Precertificate Signing CA, which requires issuer or "
            "chain context not decidable from one certificate's encoded bytes"
        )
    if _NON_TLS_TECHNICALLY_CONSTRAINED_PROFILE_RE.search(context):
        return (
            "rule applicability is scoped to the Technically Constrained "
            "Non-TLS Subordinate CA profile, whose 'will not be used to issue "
            "TLS certificates directly or transitively' condition is not "
            "decidable from one certificate's encoded bytes"
        )
    if _TLS_TECHNICALLY_CONSTRAINED_PROFILE_RE.search(context):
        return (
            "rule applicability is scoped to the Technically Constrained TLS "
            "Subordinate CA profile, whose 'will be used to issue TLS "
            "certificates directly or transitively' condition is not decidable "
            "from one certificate's encoded bytes"
        )
    if _PRECERT_SIGNING_CA_PROFILE_RE.search(context):
        return (
            "rule applicability is scoped to the Technically Constrained "
            "Precertificate Signing CA profile, whose intended-use condition "
            "is not decidable from one certificate's encoded bytes"
        )
    if (
        _RFC_SUBJECT_NAMING_ONLY_SAN_RE.search(rule_text)
        and _RFC_SUBJECT_NAMING_ONLY_SAN_EXAMPLE_RE.search(rule_text)
    ):
        return (
            "RFC 5280 subject-empty applicability depends on whether subject "
            "naming information is present only in subjectAltName; the email/URI "
            "phrase is a non-exhaustive example, so the triggering condition is "
            "not a closed single-certificate byte predicate"
        )
    return None


def non_single_artifact_lintability_reason(rule_text) -> str | None:
    """Return a source-grounded reason when rule text is not strictly lintable.

    This is intentionally pattern-class based, not rule-id based. The caller uses
    the reason after re-extraction/re-judgment to keep denominator changes
    auditable instead of directly editing metrics.
    """
    text = _primary_rule_text(rule_text)
    if _CSR_KEY_REQUEST_RE.search(text):
        return (
            "rule compares the issued certificate to the external certificate "
            "request/CSR key, which is not present in one certificate's encoded "
            "bytes"
        )
    if _IP_NETWORK_BYTE_ORDER_RE.search(text):
        return (
            "rule constrains the semantic byte order of an iPAddress value; "
            "without the externally intended address, any valid 4- or 16-octet "
            "GeneralName iPAddress is already a network-order address value, "
            "so the stated obligation is not independently decidable from one "
            "certificate"
        )
    if _SAN_SEMANTIC_IDENTITY_CHOICE_RE.search(text):
        return (
            "rule requires a semantic identity in subjectAltName, such as an "
            "Internet mail address or DNS label, to be encoded using a specific "
            "GeneralName choice; a single certificate exposes the chosen "
            "GeneralName tag and value, but not the issuer's external identity "
            "intent before that choice was made, so strict equivalence is not "
            "decidable from one certificate's encoded bytes"
        )
    if _RFC_ONLY_SUBJECT_IDENTITY_ALTNAME_RE.search(text):
        return (
            "rule applicability depends on whether the only subject identity is "
            "an alternative name form; that issuer identity-selection condition "
            "is not an independent closed single-certificate predicate, so a "
            "strictly equivalent non-vacuous lint cannot be generated"
        )
    if _RFC_BASICCONSTRAINTS_CA_ROLE_PRESENCE_RE.search(text):
        return (
            "rule requires BasicConstraints presence for certificates that are CA "
            "certificates by role and whose keys validate certificate signatures; "
            "when BasicConstraints is absent, that CA-role applicability is not "
            "independently decidable from one certificate's encoded bytes"
        )
    if _OPEN_ENDED_ENUMERATION_RE.search(text):
        return (
            "rule text contains an open-ended 'or similar ...' set, so the "
            "allowed/disallowed values are not closed enough for strict "
            "single-certificate linting"
        )
    if _EXTERNAL_AVAILABILITY_RE.search(text):
        return (
            "rule text is conditional on external information being available "
            "via a network protocol, which is not decidable from one "
            "certificate's encoded bytes"
        )
    if _PREFERENCE_ORDER_RE.search(text):
        return (
            "rule text depends on issuer preference or priority ordering, which "
            "is not independently observable from the certificate encoding"
        )
    if _UNEXPANDED_SECTION_REFERENCE_RE.search(text):
        return (
            "rule text delegates the actual constraint to another standards "
            "section rather than stating one closed atomic certificate predicate"
        )
    if _TABLE_FORMAT_REFERENCE_RE.search(text):
        return (
            "rule text is a table-format parent requirement; its concrete "
            "certificate predicates must be extracted from the table rows rather "
            "than treated as one atomic lint"
        )
    if _NOT_OBSERVABLE_RE.search(text):
        return (
            "rule text describes a non-single-certificate-observable "
            "requirement (CA process / runtime / cross-cert / real-world "
            "semantic content)"
        )
    return None


def definitely_not_single_artifact_lintable(rule_text) -> bool:
    """True iff the rule text matches a high-precision NON-observable pattern (CA
    process, user behavior, randomness, cross-cert/runtime, real-world semantic
    content). Used as a NEGATIVE gate in the lintability decision so such rules are
    never marked lintable and never reach codegen. High-precision by construction;
    returns False (does not demote) for anything it is not confident about."""
    return non_single_artifact_lintability_reason(rule_text) is not None


def has_cross_artifact_relationship(*texts) -> bool:
    """True when the source/constraint text explicitly relates this artifact to
    another certificate/precertificate/issuer artifact.

    This is a C2-axis helper: callers should set assertion_subject=CrossArtifact
    and let the normal lintability predicate recompute the final decision.
    """
    combined = " ".join(_primary_rule_text(t) for t in texts)
    return bool(_CROSS_ARTIFACT_RELATION_RE.search(combined))



def _norm(x) -> str:
    return (x.value if hasattr(x, "value") else str(x or "")).strip()


def _primary_rule_text(x) -> str:
    """Return the target rule sentence, excluding appended section context.

    Some extractors append "[Full section context]" to rule_text for semantic
    auditing. Lintability gates must classify the target atom, not unrelated
    normative words later in the section excerpt.
    """
    text = _norm(x)
    marker = "[Full section context]:"
    if marker in text:
        text = text.split(marker, 1)[0]
    return text.strip()


def is_single_artifact_observable(predicate, assertion_subject, subject_path,
                                  obligation, rule_text) -> bool:
    """True iff this is a complete, codeable, single-artifact observable constraint on a
    real certificate/CRL field (see module docstring for the full soundness contract)."""
    predicate_name = _norm(predicate).lower()
    if (predicate_name not in OBSERVABLE_PREDICATES
            and not _same_certificate_field_conformance(
                predicate_name, subject_path, rule_text)):
        return False
    # CA/RelyingParty are accepted here only as extraction-axis repair candidates. The final
    # lintability gate still requires assertion_subject=Certificate; callers that
    # use this helper must rewrite them to Certificate when the subject path
    # proves the rule constrains certificate bytes rather than actor behavior.
    if _norm(assertion_subject).lower() not in ("certificate", "crl", "ca", "relyingparty"):
        return False
    if _norm(obligation).upper().replace("_", " ") not in NORMATIVE_OBLIGATIONS:
        return False
    subj = _norm(subject_path).lower()
    if not subj:
        return False
    if subj.split(".")[0] not in CERT_FIELD_ROOTS:
        return False                                   # operational noun, not a cert field
    text = _primary_rule_text(rule_text)
    if len(text) < 15 or " | " in text:
        return False                                   # table-row fragment / stub
    if definitely_not_single_artifact_lintable(text):
        return False                                   # CA process / external state
    if _MARKER_RE.search(text):
        return False                                   # genuinely cross-artifact / runtime
    return True
