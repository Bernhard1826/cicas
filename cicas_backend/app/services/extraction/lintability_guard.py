"""Single-artifact lintability rescue — shared decision predicate.

Both the controlled extractor (`controlled_llm_extractor._enforce_single_artifact_lintability`)
and the structural analyzer (`structural_analyzer._apply_strict_lintability_rules`) call this
ONE function so their criteria can never diverge. It decides whether a rule the LLM mislabeled
on a lintability axis (enforcement_phase=Validation off a purpose word /
rule_category=clarification) is in fact a COMPLETE, codeable, single-artifact-observable
constraint on a real certificate/CRL field — i.e. something a zlint check could actually be
written for.

SOUND BY CONSTRUCTION — returns True only when ALL hold:
  * predicate is observable on one artifact (conform_to / compare_as excluded — those defer to
    another spec or are runtime comparison);
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
]
_MARKER_RE = re.compile("|".join(CROSS_OR_RUNTIME_MARKERS), re.I)


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
    r"\bMUST NOT be used to issue\b|\bSHALL NOT be used to issue\b",
    # application / relying-party / user runtime behavior
    r"\b(users?|applications?|relying part(y|ies)|clients?)\b[^.]{0,50}\b(SHALL|MUST|SHOULD)\b[^.]{0,40}\b(be prepared|be able to|process|accept|reject|support|recognize)\b",
    # randomness / entropy — not observable from one encoded value
    r"\b(CSPRNG|non-sequential|unpredictab|entropy)\b|\bat least \d+ bits of (output|entropy)\b",
    # cross-certificate / signing-key / runtime
    r"\b(signing key|issued by (a |the )?(given )?ca|corresponding certificate|during (validation|path|chain)|when validating|chain build|\bis revoked\b|current time)\b",
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
    #   "value derived from ..."       — real-world derivation (truth not in the bytes)
    r"\bwherever possible\b",
    r"whenever .{0,30}identities are to be bound",
    r"the entry holding the\b",
    r"\bmust contain a value derived from\b",
    # real-world SEMANTIC content (truth not mechanically checkable)
    r"\bMUST (contain|include|reflect|represent)\b[^.]{0,40}\bthe (Subject|Applicant|Organization|certificate holder)\W?s?\b[^.]{0,45}(actual|real|true|legal|official|verified)?\s*(name|locality|location|address|identity|information|jurisdiction)\b",
    # actor / key-usage INTENT antecedent — the rule's applicability turns on what
    # the key is "only to be used for", which is intent, not decidable from the
    # certificate's bytes (the keyUsage bits are observable, but the triggering
    # purpose is not). Often a definition of bit semantics, not a codeable check.
    r"\bonly to be used\b",
    # certificate categorisation by real-world PURPOSE ("certificates for <X>
    # purposes" / "for infrastructure purposes") — the cert's purpose is not in its
    # bytes; the clause names a category of certs, not a field constraint. NOTE:
    # "for the purposes of this profile" is scoping prose and is NOT matched (it has
    # no "certificate(s) for <word> purposes" / "for <category> purposes" shape).
    r"\bcertificates?\s+for\s+\w+\s+purposes\b",
    r"\bfor\s+(?:administrative|infrastructure|internal|operational)\b[^.]{0,40}\bpurposes\b",
]
_NOT_OBSERVABLE_RE = re.compile("|".join(_NOT_OBSERVABLE_PATTERNS), re.I)


def definitely_not_single_artifact_lintable(rule_text) -> bool:
    """True iff the rule text matches a high-precision NON-observable pattern (CA
    process, user behavior, randomness, cross-cert/runtime, real-world semantic
    content). Used as a NEGATIVE gate in the lintability decision so such rules are
    never marked lintable and never reach codegen. High-precision by construction;
    returns False (does not demote) for anything it is not confident about."""
    return bool(_NOT_OBSERVABLE_RE.search(_norm(rule_text)))



def _norm(x) -> str:
    return (x.value if hasattr(x, "value") else str(x or "")).strip()


def is_single_artifact_observable(predicate, assertion_subject, subject_path,
                                  obligation, rule_text) -> bool:
    """True iff this is a complete, codeable, single-artifact observable constraint on a
    real certificate/CRL field (see module docstring for the full soundness contract)."""
    if _norm(predicate).lower() not in OBSERVABLE_PREDICATES:
        return False
    if _norm(assertion_subject).lower() not in ("certificate", "crl"):
        return False
    if _norm(obligation).upper().replace("_", " ") not in NORMATIVE_OBLIGATIONS:
        return False
    subj = _norm(subject_path).lower()
    if not subj:
        return False
    if subj.split(".")[0] not in CERT_FIELD_ROOTS:
        return False                                   # operational noun, not a cert field
    text = _norm(rule_text)
    if len(text) < 15 or " | " in text:
        return False                                   # table-row fragment / stub
    if _MARKER_RE.search(text):
        return False                                   # genuinely cross-artifact / runtime
    return True
