"""templates_v2 / binary_judge.py — binary EXPRESSES/DOES_NOT_EXPRESS judge.

In codegen verification, the candidate B is *generated from* rule A with
the explicit goal of expressing A's full meaning. There is no honest
"partial" — a stricter/weaker code is a sub-constraint truncation, an
unjustified-precondition, or a direction error, all of which are codegen
failures. Verdict space is therefore binary:

  EXPRESSES         -- B fully expresses A (same fields, direction, all
                       sub-clauses, no narrowing, no extra preconditions)
  DOES_NOT_EXPRESS  -- anything else, including: subset/superset, partial
                       coverage, sub-constraint truncation, direction flip,
                       different field, narrower or wider constraint
"""
from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(ROOT / "experiments"))
from .synonym_judge import call_llm, parse_json_block


JUDGE_PROMPT = """You are evaluating whether a piece of generated code FULLY
expresses the meaning of a normative rule.

CONTEXT: The code below was AUTO-GENERATED from the rule with the explicit
goal of expressing every clause of the rule. There is no separate
"partially-correct" outcome -- if any clause is missing, reversed, narrowed,
widened, or replaced by an unstated precondition, the code does NOT
faithfully express the rule.

GO FIELD-NAME NOTE: The code references zcrypto cert struct field names.
The following Go field names are EQUIVALENT to the RDN attribute names from
the rule text -- treat them as the same thing:
  c.Subject.Province                 = stateOrProvinceName
  c.Subject.OrganizationalUnit       = organizationalUnitName
  c.Subject.Organization             = organizationName
  c.Subject.Locality                 = localityName
  c.Subject.Country                  = countryName
  c.Subject.CommonName               = commonName
  c.Subject.GivenName                = givenName
  c.Subject.Surname                  = surname
  c.Subject.SerialNumber             = serialNumber
  c.Subject.OrganizationIDs          = organizationIdentifier
  c.Subject.JurisdictionLocality     = jurisdictionLocalityName
  c.Subject.JurisdictionProvince     = jurisdictionStateOrProvinceName
  c.Subject.JurisdictionCountry      = jurisdictionCountryName
  c.Subject.PostalCode               = postalCode
  c.Subject.StreetAddress            = streetAddress
  c.Subject.EmailAddress             = emailAddress
  c.Subject.DomainComponent          = domainComponent
  c.DNSNames                         = SAN dNSName entries
  c.EmailAddresses                   = SAN rfc822Name entries
  c.IPAddresses                      = SAN iPAddress entries
  c.URIs                             = SAN uniformResourceIdentifier entries
  (the same applies for c.Issuer.* on issuer DN attributes)
A check on c.Subject.Province IS a check on stateOrProvinceName -- they are
the same field, just different names in two namespaces.

PRESENCE-CHECK EQUIVALENCE: For list-valued Go fields (e.g. c.Subject.Province
is []string, c.DNSNames is []string, c.URIs is []string), the canonical way
to check "the attribute is PRESENT" is `len(field) > 0` (i.e. "non-empty").
Therefore:
  - "len(c.Subject.Province) > 0"  EXPRESSES  "stateOrProvinceName is present"
  - "len(c.DNSNames) > 0"          EXPRESSES  "dNSName is present in SAN"
  - "len(c.Subject.Country) == 0"  EXPRESSES  "countryName is absent"
Do NOT mark these as DOES_NOT_EXPRESS just because the rule used "present"
and the code uses "non-empty" -- in Go, those are the same thing for lists.

Similarly for scalar string Go fields (c.Subject.CommonName is string):
  - 'c.Subject.CommonName != ""'   EXPRESSES  "commonName is present"

EXTENSION-DERIVED FLAT FIELDS: zcrypto pre-parses several extensions into
flat top-level []byte / []string fields on Certificate. A check on the flat
field IS a check on the parsed sub-field of the extension; do not penalize
the code for "not opening the extension":
  c.AuthorityKeyId         = AKI extension's keyIdentifier sub-field (RFC 5280 §4.2.1.1)
  c.SubjectKeyId           = SKI extension content (RFC 5280 §4.2.1.2)
  c.OCSPServer             = AIA entries with accessMethod=id-ad-ocsp
  c.IssuingCertificateURL  = AIA entries with accessMethod=id-ad-caIssuers
  c.CRLDistributionPoints  = CRLDP distributionPoint URI list
  c.PolicyIdentifiers      = CertificatePolicies policyIdentifier list
  c.DNSNames / c.EmailAddresses / c.URIs / c.IPAddresses
                           = SAN dNSName / rfc822Name / URI / iPAddress entries
A check like "bytes.Equal(c.SubjectKeyId, c.AuthorityKeyId)" therefore
EXPRESSES "subject key identifier MUST equal authority key identifier
keyIdentifier field" -- they are the same bytes after parsing.

DN BYTE EQUALITY: c.RawSubject and c.RawIssuer are the DER-encoded
distinguished names. A check like "bytes.Equal(c.RawSubject, c.RawIssuer)"
EXPRESSES "subject DN MUST be byte-for-byte identical to issuer DN" or
"the encoded `subject` MUST equal the encoded `issuer`" -- this is the
direct mechanical encoding of the rule, not an approximation.

SEVERITY EQUIVALENCE: The lint code may return one of three statuses on
a violation: lint.Error, lint.Warn, lint.Notice. These map directly to
the rule's prescriptive level:
  lint.Error  <=> MUST / MUST NOT / SHALL / SHALL NOT / REQUIRED
  lint.Warn   <=> SHOULD / SHOULD NOT / RECOMMENDED / NOT RECOMMENDED
  lint.Notice <=> MAY / OPTIONAL
A code that returns lint.Warn for a SHOULD-level rule EXPRESSES the rule
faithfully -- do NOT mark it DOES_NOT_EXPRESS just because the check is
"only a Warn"; that's the correct severity for SHOULD/RECOMMENDED. A code
that returns lint.Error for a SHOULD/RECOMMENDED rule is OVER-STRICT
(stricter than the rule says) and DOES NOT EXPRESS faithfully.

REGEX-BASED LIST PREDICATES: When (B) describes a regex check applied to a
list field (e.g. "all DNSNames match a regex that excludes reserved LDH
labels"), the regex IS the semantic content of the check. Do NOT say the
check "doesn't enforce X" just because you can't see the regex pattern
clearly in the semantic summary. Instead, use the semantic description:
  - "all DNSNames match a regex excluding reserved LDH labels"
    => correctly enforces per-label LDH compliance for non-reserved labels
  - "all DNSNames match a regex requiring at least one dot"
    => correctly enforces FQDN (multi-label) requirement
  - "all IPs have byte count in {4, 16}"
    => correctly enforces that IPv6 (16-byte) entries are valid
If the semantic description names the regex's semantic intent (e.g. "excludes
reserved LDH", "requires FQDN dot"), treat it as expressing the underlying
requirement -- do NOT probe for implementation details the semantic summary
doesn't contain.

NAMECONSTRAINTS STRUCTURAL CONTEXT: When (A)'s text references "name
constraints" (e.g. RFC 5280 §4.2.1.10, "specifically for name constraints"),
field-name references like "iPAddress field of GeneralName", "dNSName",
"directoryName", etc. point to entries in the NameConstraints
permittedSubtrees / excludedSubtrees lists — NOT to entries in the
Subject Alternative Name extension and NOT to attribute-value pairs in
the Subject DN. Concretely:
  - "iPAddress field of GeneralName" under name constraints
       <=> entries in c.PermittedIPAddresses / c.ExcludedIPAddresses
           (NOT c.IPAddresses from SAN, NOT c.Subject.*)
  - "dNSName" under name constraints
       <=> c.PermittedDNSNames / c.ExcludedDNSNames
  - "directoryName" under name constraints
       <=> c.PermittedDirectoryNames / c.ExcludedDirectoryNames
A code that checks Permitted/ExcludedIPAddresses for a name-constraints
rule about "the iPAddress field of GeneralName" EXPRESSES the rule
faithfully (correct structural scope per RFC 5280 §4.2.1.10) — do NOT
mark it DOES_NOT_EXPRESS for "checking the wrong field". The clue that
puts the rule in NameConstraints context is either: (i) the rule text
explicitly says "name constraints" / "permittedSubtrees" / "excludedSubtrees",
or (ii) the rule cites RFC 5280 §4.2.1.10 (NameConstraints).

=== (A) RULE (original normative text) ===
{rule_text}

=== (B) CODE-DERIVED SEMANTICS (what the generated Execute function actually checks) ===
{code_sem}

=== DECIDE ===

  EXPRESSES         -> (B) captures the FULL meaning of (A). Same field(s)
                       (treating the Go-name/RDN-name pairs above as
                       equivalent), same direction (MUST vs MUST NOT),
                       every sub-clause of (A) is encoded in (B), no extra
                       preconditions beyond what (A) states, no narrower
                       or wider constraint than (A).

  DOES_NOT_EXPRESS  -> ANY of the following:
                       - (B) drops a sub-clause that (A) requires
                       - (B) reverses a direction (e.g. MUST -> MUST NOT)
                       - (B) targets a different field/extension/bit than (A)
                       - (B) narrows the constraint (B implies A but A does
                         not imply B)
                       - (B) widens the constraint (A implies B but B does
                         not imply A)
                       - (B) adds an unjustified precondition (e.g. NA-when
                         the rule didn't say "when X")
                       - The relationship is "related but different"

EXAMPLES:

  (A) "stateOrProvinceName MUST be present in subject DN."
  (B) "checks Subject.Province is non-empty"
  -> EXPRESSES.  (Province IS the Go name for stateOrProvinceName.)

  (A) "AIA extension MUST be marked non-critical."
  (B) "if AIA present, checks AIA.Critical == false"
  -> EXPRESSES (the if-present scaffold is the natural conditional shape).

  (A) "OrganizationalUnit MUST NOT be present in Root CA certs."
  (B) "if cert is self-signed CA, OU is empty"
  -> EXPRESSES.

  (A) "SerialNumber MUST be a non-negative integer."
  (B) "checks SerialNumber is present"
  -> DOES_NOT_EXPRESS (presence != non-negative; sub-clause truncation).

  (A) "CommonName MUST use UTF8String or PrintableString, max length 64."
  (B) "checks CN length == 64"
  -> DOES_NOT_EXPRESS (drops encoding clause; max -> exact direction error).

  (A) "dataEncipherment bit is NOT RECOMMENDED."
  (B) "KeyUsage MUST NOT include dataEncipherment"
  -> DOES_NOT_EXPRESS (SHOULD-NOT vs MUST-NOT direction; B is stricter).

  (A) "extension MUST contain at least one PolicyInformation."
  (B) "extension is present"
  -> DOES_NOT_EXPRESS (presence != at-least-one-content).

Return ONLY a JSON object, no prose. The verdict value MUST be the string
"EXPRESSES" or "DOES_NOT_EXPRESS" exactly (with the underscore, no spaces).

  {{
    "verdict": "EXPRESSES" | "DOES_NOT_EXPRESS",
    "missing_or_wrong": "<short phrase: which clause is missing/wrong, or 'none' if EXPRESSES>",
    "why": "<one short sentence>"
  }}
"""


def judge_expresses(rule_text: str, code_sem: str, *,
                    model: str | None = None,
                    max_tokens: int = 500) -> dict:
    """Returns dict with keys: verdict, missing_or_wrong, why, raw."""
    import os
    model = model or os.environ.get("JUDGE_MODEL", "THUDM/GLM-Z1-9B-0414")
    # Replace {rule_text} and {code_sem} directly with their values.
    # We can't use str.format() here because code_sem may contain {N} patterns
    # (e.g. "{4, 16}" from IP byte-count checks) that format() mis-parses.
    _rt = (rule_text or "")[:1500]
    _cs = (code_sem or "")[:1000]
    prompt = JUDGE_PROMPT.replace("{rule_text}", _rt).replace("{code_sem}", _cs)
    raw = call_llm(prompt, max_tokens=max_tokens, model=model)
    if isinstance(raw, str) and raw.startswith("__ERROR__"):
        return {"verdict": "ERROR", "missing_or_wrong": "",
                "why": raw[:200], "raw": raw[:200]}
    obj = parse_json_block(raw) or {}
    verdict_raw = (obj.get("verdict") or "").strip()
    # Normalize: uppercase, replace spaces and dashes with underscores so
    # "DOES_NOT EXPRESS" / "does-not-express" / "Does Not Express" all map.
    v_norm = verdict_raw.upper().replace(" ", "_").replace("-", "_")
    while "__" in v_norm:
        v_norm = v_norm.replace("__", "_")
    if v_norm.startswith("DOES_NOT") or v_norm.startswith("NOT_") or v_norm in ("NONE", "PARTIAL", "PARTIALLY_EXPRESSES"):
        verdict = "DOES_NOT_EXPRESS"
    elif v_norm.startswith("EXPRESS") or v_norm in ("FULL", "FULLY_EXPRESSES"):
        verdict = "EXPRESSES"
    else:
        verdict = "PARSE_ERROR"
    return {
        "verdict":          verdict,
        "verdict_raw":      verdict_raw,
        "missing_or_wrong": (obj.get("missing_or_wrong") or "")[:200],
        "why":              (obj.get("why") or "")[:300],
        "raw":              (raw or "")[-300:],
    }


# ---------------------------------------------------------------------
# Self-test
# ---------------------------------------------------------------------

if __name__ == "__main__":
    cases = [
        # (rule, code_sem, expected)
        ("stateOrProvinceName MUST be present in subject DN.",
         "checks Subject.Province is non-empty",
         "EXPRESSES"),
        ("SerialNumber MUST be a non-negative integer.",
         "checks SerialNumber is present",
         "DOES_NOT_EXPRESS"),
        ("CommonName MUST use UTF8String or PrintableString, max length 64.",
         "checks CN length == 64",
         "DOES_NOT_EXPRESS"),
    ]
    for rule, code, expected in cases:
        r = judge_expresses(rule, code)
        ok = "OK" if r["verdict"] == expected else "MISMATCH"
        print(f"[{ok}] expected={expected:18s} got={r['verdict']:18s}  why={r['why'][:80]}")
        print(f"      missing_or_wrong: {r['missing_or_wrong']}")
        print()
