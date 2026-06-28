"""migrate_rules_to_zlint.py — link rules to zlint_lint_dsl via subject+predicate+relate().

For each rule without a zlint_lint_name:
  1. Extract ir_data → (subject, predicate, lintable) — or parse title for field keywords
  2. Normalize the rule subject (strip tbsCertificate prefix, lowercase, dot→camel)
  3. Query zlint_lint_dsl candidates by: same source + normalized subject is prefix of
     zlint_lint_dsl.normalized_subject + predicate compatibility
  4. Score candidates: predicate_match > section_match > title_keyword > relate()
  5. Write best candidate's lint_name → rules.zlint_lint_name

Usage:
  python migrate_rules_to_zlint.py [--dry-run] [--source CABF-BR|RFC] [--min-score 0.5]
  python migrate_rules_to_zlint.py --revert  # undo last migration

Prerequisites:
  - populate_zlint_lint_dsl.py has been run (zlint_lint_dsl table populated)
  - rules table has ir_data (JSONB) with 'ir.subject', 'ir.predicate', 'ir.lintable'
"""
from __future__ import annotations

import json
import os
import re
import sys
from pathlib import Path
from typing import Optional

_backend = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(_backend))
os.environ.setdefault('DATABASE_URL',
                     'postgresql://postgres:123456@localhost:15432/cicas')

import psycopg2
from psycopg2.extras import execute_batch

from app.services.certificate.dsl import dsl
from app.services.certificate.dsl.dsl_compare import canon as _canon, relate, Relation
from app.services.certificate.dsl.rule_ir_to_dsl import ir_to_dsl, json_to_dsl


# ---- Subject path normalization ----

def normalize_path(p: str) -> str:
    """Lowercase + strip tbsCertificate. prefix for path comparison.

    Examples:
      "tbsCertificate.extensions.authorityInfoAccess"
        -> "extensions.authorityinfoaccess"
      "extensions.authoritykeyidentifier"
        -> "extensions.authoritykeyidentifier"
    """
    if not p:
        return ""
    if p.startswith("tbsCertificate."):
        p = p[len("tbsCertificate."):]
    return p.lower()


def path_is_prefix(short: str, long: str) -> bool:
    """True when short is a prefix of long (dot-separated, case-insensitive)."""
    short = short.strip().lower()
    long = long.strip().lower()
    if not short:
        return True
    if not long:
        return False
    # short must match the beginning of long's dot-prefix
    if long.startswith(short):
        if len(long) == len(short):
            return True
        if long[len(short)] == ".":
            return True
        return False
    return False


# ---- Predicate mapping: rule ir_data predicate → zlint_lint_dsl predicate ----
#
# The ir_data.predicate comes from rule extraction (e.g., must_not_be_present).
# The zlint_lint_dsl.predicate comes from zlint IR (e.g., must_be_present,
# must_be_absent, etc.). We need to bridge them.
#
# Key principle: a rule's "must_not_be_present" combined with a lint's predicate
# "must_be_present" is a valid match when the lint's atom encodes Not(ExtPresent(...)).
# Similarly "must_include" ↔ "must_be_present" (MUST modality → positive).
#
# Mapping table derived from existing (rules, zlint_lint_dsl) pairs:

MODALITY_POLARITY = {
    # positive polarity
    "MUST": True,
    "SHALL": True,
    "REQUIRED": True,
    "SHOULD": True,
    "RECOMMENDED": True,
    "MAY": True,
    # negative polarity
    "MUST NOT": False,
    "SHALL NOT": False,
    "SHOULD NOT": False,
    "OPTIONAL": False,
}

# Predicate polarity: what kind of atom does the rule imply?
PREDICATE_POLARITY = {
    # positive: rule says field SHOULD be present / included
    "must_be_present": True,
    "must_include": True,
    "must_be_set": True,
    "must_equal": True,
    "allowed_values": True,
    "conform_to": True,
    "encode_as": True,
    "matches_pattern": True,
    "in_range": True,
    "compare_as": True,
    "must_include_or_absent": True,
    # negative: rule says field SHOULD be absent / not included
    "must_not_be_present": False,
    "must_not_include": False,
    "must_not_be_set": False,
    "must_not_equal": False,
    "must_not_conflict": False,
    "must_not_exceed": False,
    # neutral (lint decides based on cert type)
    "may_include": None,
    "must_not_be_set": False,
}

# Lint name suffix → cert type
CERT_TYPE_PATTERNS = [
    ("root_ca", "Root CA"),
    ("sub_ca", "Sub CA"),
    ("sub_cert", "Subscriber"),
    ("subscriber", "Subscriber"),
    ("_ca", "CA"),
]

# For each cert type, which lint polarity should "MUST INCLUDE" map to?
CERT_TYPE_POLARITY = {
    "Root CA": {
        True: "must_be_absent",   # Root CA: MUST include → no such ext/field present
        False: "must_be_present", # Root CA: MUST NOT → ext/field must be present
        None: "must_be_absent",
    },
    "Sub CA": {
        True: "must_be_present",   # Sub CA: MUST include → ext/field must be present
        False: "must_be_absent",  # Sub CA: MUST NOT → ext/field must not be present
        None: "must_be_present",
    },
    "Subscriber": {
        True: "must_be_present",   # Subscriber: MUST include → ext/field must be present
        False: "must_be_absent",  # Subscriber: MUST NOT → ext/field must not be present
        None: "must_be_present",
    },
    "General": {
        True: "must_be_present",
        False: "must_be_absent",
        None: "must_be_present",
    },
    "CA": {
        True: "must_be_present",
        False: "must_be_absent",
        None: "must_be_present",
    },
}


def extract_cert_type(title: str) -> str:
    """Extract certificate type from a rule title.

    CABF-BR rule titles encode certificate type in the prefix:
      "Root CA ..." → Root CA
      "Cross-Certified Subordinate CA ..." → Sub CA
      "Subscriber ..." → Subscriber
      "CA Certificate ..." → CA (generic CA cert)
      "Technically Constrained ..." → Sub CA
      "CRL ..." → CRL
      General (no prefix) → General
    """
    title_lower = (title or "").lower()
    # Root CA first (more specific)
    if "root ca" in title_lower:
        return "Root CA"
    # Sub CA / Cross-Certified Subordinate CA / Technically Constrained
    if any(kw in title_lower for kw in ["subordinate ca", "sub ca", "cross-certified", "technically constrained"]):
        return "Sub CA"
    # Subscriber
    if "subscriber" in title_lower:
        return "Subscriber"
    # CA certificate (generic, not Root/Sub)
    if title_lower.startswith("ca certificate") or title_lower.startswith("ca ") or "ca " in title_lower:
        return "CA"
    # CRL
    if title_lower.startswith("crl "):
        return "CRL"
    return "General"


def extract_cert_type_from_lint(lint_name: str) -> str:
    """Extract certificate type from a zlint lint_name suffix.

    lint_name patterns:
      e_root_ca_* → Root CA
      e_old_root_ca_* → Root CA
      e_sub_ca_* / n_sub_ca_* / w_sub_ca_* → Sub CA
      e_sub_cert_* / w_sub_cert_* / n_sub_cert_* → Subscriber
      e_* (no suffix) → General
      e_ca_* / n_ca_* → CA
    """
    name_lower = (lint_name or "").lower()
    # Root CA patterns
    if "root_ca" in name_lower or "rootca" in name_lower:
        return "Root CA"
    # Sub CA patterns (before Subscriber since "sub_" matches)
    if "_sub_ca_" in name_lower or "_subca_" in name_lower or "_sub_ca_" in name_lower:
        return "Sub CA"
    # Subscriber patterns
    if "_sub_cert" in name_lower or "_subscriber" in name_lower:
        return "Subscriber"
    # CA patterns
    if "_ca_" in name_lower or "_ca_" in name_lower:
        return "CA"
    return "General"


def predicate_compatible(rule_pred: str, lint_pred: str, modality: str, cert_type: str = "General") -> bool:
    """Check if rule predicate + modality + cert_type is compatible with lint predicate.

    The key insight:
    - For "MUST INCLUDE" rules on Root CA: the lint checks that the field is ABSENT
      (Root CAs should NOT have certain extensions/fields)
    - For "MUST INCLUDE" rules on Sub CA: the lint checks that the field is PRESENT
      (Sub CAs MUST have certain extensions/fields)
    """
    rule_pred = (rule_pred or "").strip().lower()
    lint_pred = (lint_pred or "").strip().lower()
    modality = (modality or "").strip().upper()
    cert_type = cert_type or "General"

    if not rule_pred or not lint_pred:
        return True  # permissive

    pred_polarity = PREDICATE_POLARITY.get(rule_pred, True)
    mod_polarity = MODALITY_POLARITY.get(modality, True)

    # Combined polarity of the rule
    combined_polarity = pred_polarity if pred_polarity is not None else mod_polarity

    # What lint predicate does this rule require for the given cert type?
    required_lint_pred = CERT_TYPE_POLARITY.get(cert_type, CERT_TYPE_POLARITY["General"]).get(
        combined_polarity, lint_pred)

    # Normalize required lint pred for comparison
    if required_lint_pred == "must_be_present":
        ok = lint_pred in ("must_be_present", "must_be_set", "present", "non_empty",
                           "must_include", "encoded_as", "equal_to", "one_of")
    elif required_lint_pred == "must_be_absent":
        ok = lint_pred in ("must_be_absent", "not_present", "absent",
                           "must_not_include", "must_not_be_present", "must_not_be_set")
    else:
        ok = True

    # Direct match always OK
    if rule_pred == lint_pred:
        return True

    # Cross-mapping for equivalent predicates
    EQUIVALENT = {
        "must_include": "must_be_present",
        "must_not_include": "must_be_absent",
        "must_be_set": "must_be_present",
        "must_not_be_set": "must_be_absent",
        "encode_as": "encoded_as",
        "conform_to": "valid_format",
        "matches_pattern": "matches_regex",
        "allowed_values": "one_of",
        "in_range": "length_range",
        "must_be_present": "must_include",
        "must_be_absent": "must_not_include",
    }
    if EQUIVALENT.get(rule_pred, rule_pred) == lint_pred:
        return True

    return ok


# ---- Title → field keyword extraction ----

# OID / field name → canonical field token (for title matching)
FIELD_KEYWORDS = {
    "keyusage": "KeyUsageOID",
    "key usage": "KeyUsageOID",
    "basickconstraints": "BasicConstraintsOID",
    "basic constraints": "BasicConstraintsOID",
    "basicconstraints": "BasicConstraintsOID",
    "subjectaltname": "SubjectAltNameOID",
    "subject alternative name": "SubjectAltNameOID",
    "san": "SubjectAltNameOID",
    "certificate policies": "CertPolicyOID",
    "certpolicies": "CertPolicyOID",
    "certificatepolicies": "CertPolicyOID",
    "crl": "CrlDistOID",
    "crl distribution": "CrlDistOID",
    "authoritykeyidentifier": "AuthorityKeyIdOID",
    "authority key identifier": "AuthorityKeyIdOID",
    "aki": "AuthorityKeyIdOID",
    "authorityinfoaccess": "AiaOID",
    "authority information access": "AiaOID",
    "aia": "AiaOID",
    "extkeyusage": "ExtKeyUsageOID",
    "extended key usage": "ExtKeyUsageOID",
    "eku": "ExtKeyUsageOID",
    "subjectkeyidentifier": "SubjectKeyIdOID",
    "subject key identifier": "SubjectKeyIdOID",
    "ski": "SubjectKeyIdOID",
    "nameconstraints": "NameConstOID",
    "name constraints": "NameConstOID",
    "ocsp": "OCSPServer",
    "aia ocsp": "OCSPServer",
    "issuing certificate url": "IssuingCertificateURL",
    "issuingcertificateurl": "IssuingCertificateURL",
    "caissuers": "IssuingCertificateURL",
    "email": "EmailAddresses",
    "dns": "DNSNames",
    "ip": "IPAddresses",
    "uri": "URIs",
    "serial": "SerialNumber",
    "serial number": "SerialNumber",
    "subject": "Subject",
    "issuer": "Issuer",
    "version": "Version",
    "signature": "SignatureAlgorithm",
    "public key": "PublicKeyAlgorithm",
    "subjectpublickeyinfo": "PublicKeyAlgorithm",
    "revocation": "Revocation",
    "validity": "ValidityPeriod",
    "policy": "CertPolicyOID",
    "organization": "Organization",
    "common name": "CommonName",
    "commonname": "CommonName",
    "country": "Country",
    "distinguished name": "Subject",
    "dn": "Subject",
    "extension": "Extensions",
    "extensions": "Extensions",
    "unique identifier": "SubjectUniqueId",
    "uniqueidentifier": "SubjectUniqueId",
    "ca": "IsCA",
    "is ca": "IsCA",
    "path length": "pathLenConstraint",
    "pathlenconstraint": "pathLenConstraint",
}

# DSL OID → canonical field name (for extracting from lint DSL atom)
OID_TO_FIELD = {
    "KeyUsageOID": "KeyUsage",
    "BasicConstraintsOID": "BasicConstraints",
    "SubjectAltNameOID": "SubjectAltName",
    "CertPolicyOID": "CertPolicy",
    "CrlDistOID": "CRLDistributionPoints",
    "AuthorityKeyIdOID": "AuthorityKeyIdentifier",
    "AiaOID": "AuthorityInfoAccess",
    "ExtKeyUsageOID": "ExtKeyUsage",
    "SubjectKeyIdOID": "SubjectKeyIdentifier",
    "NameConstOID": "NameConstraints",
    "IssuerAltNameOID": "IssuerAltName",
    "PolicyMappingsOID": "PolicyMappings",
    "FreshestCRLOID": "FreshestCRL",
    "ExtCrlDistributionPoints": "CRLDistributionPoints",
}


def extract_field_from_title(title: str) -> set[str]:
    """Extract canonical field tokens from a rule title."""
    title_lower = (title or "").lower()
    fields = set()
    for keyword, field in FIELD_KEYWORDS.items():
        if keyword in title_lower:
            fields.add(field)
    return fields


def extract_field_from_dsl_atom(dsl_atom_json: str) -> set[str]:
    """Extract field/OID names from a DSL atom JSON string."""
    fields = set()
    try:
        atom = json.loads(dsl_atom_json)
    except:
        return fields

    def walk(d):
        if isinstance(d, dict):
            if "oid" in d:
                oid = d["oid"]
                fields.add(oid)
                if oid in OID_TO_FIELD:
                    fields.add(OID_TO_FIELD[oid])
            if "field" in d:
                fld = d["field"]
                fields.add(fld)
                if fld in OID_TO_FIELD:
                    fields.add(OID_TO_FIELD[fld])
                # Also add the canonical OID if field matches a known field name
                for oid, canonical in OID_TO_FIELD.items():
                    if canonical.lower() in fld.lower():
                        fields.add(oid)
            for v in d.values():
                walk(v)
        elif isinstance(d, list):
            for item in d:
                walk(item)
    walk(atom)
    return fields


def title_field_score(rule_title: str, lint_name: str, dsl_atom: str) -> float:
    """Compute 0..1 score for rule title vs lint field coverage."""
    rule_fields = extract_field_from_title(rule_title)
    lint_fields = extract_field_from_dsl_atom(dsl_atom or "")
    if not rule_fields:
        return 0.0
    overlap = rule_fields & lint_fields
    if overlap:
        return len(overlap) / len(rule_fields)
    return 0.0


# ---- relate() verification ----

def _unwrap_not(node) -> tuple:
    """Strip outer Not() wrapper, return (inner, negated).

    Returns (node, False) if not wrapped in Not.
    Returns (inner_node, True) if wrapped in one Not.
    Returns (node, False) if double-NOT (not stripped — caller must handle).
    """
    if isinstance(node, dsl.Not):
        inner = node.inner
        if isinstance(inner, dsl.Not):
            return (inner.inner, False)   # Not(Not(X)) → (X, False)
        return (inner, True)
    return (node, False)


def relate_score(rule_atom, lint_atom) -> float:
    """Compute entailment score using relate().

    lint_atom may be a JSON string (text) or already-parsed dict.

    Scoring:
      - EQUAL / A_ENTAILS_B  (rule ⊨ lint)  → 1.0  (strong alignment)
      - B_ENTAILS_A           (lint ⊨ rule)  → 0.8  (lint captures rule)
      - INCOMPARABLE / NEEDS_REGEX_ORACLE    → 0.0  (no alignment)

    Not-unwrapping: Not(ExtPresent(X)) vs ExtPresent(X) are treated as
    pointing in the same semantic direction (rule forbids X, lint flags X)
    so they are compared as X vs X.  Not(Not(X)) cancels to (X).
    """
    if rule_atom is None or lint_atom is None:
        return 0.0
    try:
        # Normalize lint_atom to dict, then to DSL node
        if isinstance(lint_atom, str):
            lint_atom = json.loads(lint_atom)
        if not isinstance(lint_atom, dict):
            return 0.0
        lint_node = json_to_dsl(lint_atom)

        # Unwrap Not() for both atoms to compare the inner predicates
        rule_inner, rule_neg = _unwrap_not(rule_atom)
        lint_inner, lint_neg = _unwrap_not(lint_node)

        # If one side is Not and the other is not, their negation flags differ.
        # "rule forbids ExtPresent(X)" (Not) vs "lint flags ExtPresent(X)" (plain)
        # points in the SAME semantic direction, so we compare inner atoms.
        # Double-NOT cancels: Not(Not(X)) vs Not(X) also compares X vs X.
        effective_rel = relate(rule_inner, lint_inner)
        if effective_rel == Relation.EQUAL or effective_rel == Relation.A_ENTAILS_B:
            return 1.0
        if effective_rel == Relation.B_ENTAILS_A:
            return 0.8
        return 0.0
    except Exception:
        return 0.0


# ---- Load zlint_lint_dsl into memory for fast lookup ----

def load_zlint_lints(conn, source: str):
    """Load zlint_lint_dsl entries for source into a dict keyed by (subject_norm, predicate)."""
    cur = conn.cursor()
    cur.execute("""
        SELECT lint_name, section, predicate, subject, dsl_atom, dsl_form,
               obligation, constraint_type
        FROM zlint_lint_dsl
        WHERE source = %s AND dsl_form = 'Form_A'
        ORDER BY section, predicate
    """, (source,))
    lints = []
    for row in cur.fetchall():
        lint_name, section, predicate, subject, dsl_atom, dsl_form, obligation, ctype = row
        subject_norm = normalize_path(subject or "")
        lints.append({
            "lint_name": lint_name,
            "section": section,
            "predicate": (predicate or "").strip().lower(),
            "subject": subject or "",
            "subject_norm": subject_norm,
            "dsl_atom": dsl_atom,
            "dsl_form": dsl_form,
            "obligation": obligation,
            "ctype": ctype,
        })
    cur.close()
    return lints


def build_zlint_index(lints):
    """Build nested index: subject_norm → predicate → [lint_entry]."""
    index = {}
    for lint in lints:
        key = (lint["subject_norm"], lint["predicate"])
        if key not in index:
            index[key] = []
        index[key].append(lint)
    return index


# ---- Main matching logic ----

def match_rule_to_zlint(rule: dict, zlint_lints, zlint_index,
                        min_score: float = 0.3) -> Optional[dict]:
    """Find best zlint lint for a rule.

    Returns (lint_entry, score, method) or None.
    """
    source = rule["source"]
    rule_id = rule["id"]
    rule_title = rule["title"] or ""
    rule_modality = (rule["modality"] or "").strip().upper()
    rule_operation = (rule["operation"] or "").strip().lower()
    ir_data = rule.get("ir_data") or {}
    ir = ir_data.get("ir") or ir_data.get("parsed") or {}

    rule_subject = ir.get("subject") or ""
    rule_predicate = ir.get("predicate") or ""
    rule_lintable = ir.get("lintable", False)

    # Extract cert type from rule title
    rule_cert_type = extract_cert_type(rule_title)

    # Skip if already linked
    if rule.get("zlint_lint_name"):
        return None

    subject_norm = normalize_path(rule_subject)

    # Build candidates: subject + predicate matching
    candidates = []
    if subject_norm:
        # Direct subject + predicate
        key = (subject_norm, rule_predicate)
        candidates.extend(zlint_index.get(key, []))

        # Subject match with any predicate
        for lint in zlint_lints:
            if path_is_prefix(subject_norm, lint["subject_norm"]):
                candidates.append(lint)

    # Deduplicate
    seen = set()
    unique_candidates = []
    for c in candidates:
        if c["lint_name"] not in seen:
            seen.add(c["lint_name"])
            unique_candidates.append(c)

    if not unique_candidates:
        return None

    # Score each candidate
    scored = []
    for lint in unique_candidates:
        lint_cert_type = extract_cert_type_from_lint(lint["lint_name"])

        score = 0.0
        method = "unknown"

        # Cert type: exact match bonus (+0.3), mismatch penalty (-0.4)
        if rule_cert_type == lint_cert_type and rule_cert_type != "General":
            score += 0.3
        elif rule_cert_type != "General" and lint_cert_type != "General" and rule_cert_type != lint_cert_type:
            score -= 0.4
            continue  # skip incompatible cert types entirely
        elif lint_cert_type != "General" and lint_cert_type != "General":
            pass  # one is General, OK

        # Predicate match: +0.4
        if predicate_compatible(rule_predicate, lint["predicate"], rule_modality, rule_cert_type):
            score += 0.4

        # Subject exact match: +0.5; prefix match: +0.3
        if subject_norm:
            if subject_norm == lint["subject_norm"]:
                score += 0.5
            elif path_is_prefix(subject_norm, lint["subject_norm"]):
                score += 0.3

        # relate() verification: +0.3 if available
        # _build_rule_atom uses the rule's own ir_data to build its semantic atom,
        # then compares it to the lint's atom.  This is a genuine cross-check,
        # NOT a self-comparison between rule/lint derived from the same lint.
        if lint.get("dsl_atom"):
            rule_atom = _build_rule_atom(rule, ir)
            if rule_atom:
                rel_score = relate_score(rule_atom, lint["dsl_atom"])
                score += rel_score * 0.3
                if rel_score > 0:
                    method = f"relate({rel_score:.2f})"
                else:
                    method = "subject+predicate"
            else:
                method = "subject+predicate"
        else:
            method = "subject+predicate"

        if score >= min_score:
            scored.append((lint, score, method))

    if not scored:
        return None

    # Sort by score descending
    scored.sort(key=lambda x: x[1], reverse=True)
    best_lint, best_score, method = scored[0]
    return {
        "lint": best_lint,
        "score": best_score,
        "method": method,
        "alternatives": scored[1:5],
    }


def _build_rule_atom(rule: dict, ir: dict) -> Optional[object]:
    """Build a DSL atom from a rule's own ir_data to compare with lint's atom.

    Uses rule_ir_to_dsl.ir_to_dsl() to convert the rule's IR (subject + predicate +
    constraint) into a DSL atom.  This atom is the rule's genuine semantic claim,
    not derived from the lint's structure.

    Returns None if the rule's IR cannot be converted (e.g., unresolved subject,
    unsupported predicate type, or ir_data is absent).

    Args:
        rule: rule dict with at least 'id' and 'ir_data'
        ir:   the rule's ir dict (rule['ir_data'].get('ir') or parsed)
    """
    if not ir:
        return None
    return ir_to_dsl(rule.get("id") or 0, ir)


# ---- Main entry point ----

def migrate(dry_run: bool = False, source: str = "CABF-BR",
           min_score: float = 0.3, batch_size: int = 100):
    DATABASE_URL = os.getenv('DATABASE_URL',
                            'postgresql://postgres:123456@localhost:15432/cicas')

    conn = psycopg2.connect(DATABASE_URL)
    cur = conn.cursor()

    try:
        # Load zlint lints
        print(f"Loading zlint_lint_dsl for source={source}...")
        zlint_lints = load_zlint_lints(conn, source)
        zlint_index = build_zlint_index(zlint_lints)
        print(f"  Loaded {len(zlint_lints)} Form_A lints, {len(zlint_index)} unique (subject,predicate) combos")

        # Load rules without zlint_lint_name
        cur.execute("""
            SELECT r.id, r.title, r.operation, r.modality, r.section,
                   r.zlint_lint_name, r.ir_data, s.source
            FROM rules r JOIN standards s ON s.id = r.standard_id
            WHERE s.source = %s AND r.zlint_lint_name IS NULL
            ORDER BY r.section NULLS LAST, r.id
        """, (source,))
        rules = []
        for row in cur.fetchall():
            id_, title, operation, modality, section, zlint_name, ir_data, src = row
            ir_parsed = {}
            if ir_data:
                try:
                    ir_parsed = json.loads(ir_data)
                except:
                    pass
            rules.append({
                "id": id_,
                "title": title,
                "operation": operation,
                "modality": modality,
                "section": section,
                "zlint_lint_name": zlint_name,
                "ir_data": ir_parsed,
                "source": src,
            })
        print(f"  Found {len(rules)} rules without zlint_lint_name")

        # Administrative/process rule titles that should NOT be matched to
        # certificate-field lints (they are about CA/Browser Forum operational
        # procedures, domain validation processes, revocation procedures, etc.)
        ADMIN_KEYWORDS = [
            "registration authorities", "repositories", "identity",
            "time or frequency", "definitions", "procedure for",
            "approval or rejection", "ca key pair generation",
            "public key parameters", "signature algorithmidentifier",
            "frequency or circumstances", "types of records",
            "vulnerability assessments", "self-audits", "retention period",
            "mass revocation", "validating applicant as a domain",
            "email to dns", "phone contact", "agreed-upon change",
            "tls using alpn", "dns labeled", "crl issuance frequency",
            "crl profile", "crl and crl entry", "crl issuing distribution",
            "validation of domain authorization",
            "dns txt record with persistent", "on-line revocation", "crl issuance",
        ]
        GENERIC_EXTENSIONS_TITLES = [
            "other extensions", "precertificate profile extensions",
        ]

        def _is_admin_rule(title: str, modality: str) -> bool:
            if modality == "NOISE_CANDIDATE":
                return True
            tl = (title or "").lower()
            return any(kw in tl for kw in ADMIN_KEYWORDS)

        def _is_generic_extensions(title: str, ir_subject: str) -> bool:
            if ir_subject != "extensions":
                return False
            tl = (title or "").lower()
            return any(kw in tl for kw in GENERIC_EXTENSIONS_TITLES)

        # Match each rule
        results = []
        no_candidates = 0
        admin_skipped = 0
        generic_ext_skipped = 0
        for rule in rules:
            title = rule["title"] or ""
            modality = (rule["modality"] or "").strip()
            ir = rule["ir_data"].get("ir") or rule["ir_data"].get("parsed") or {}
            ir_subject = ir.get("subject", "")

            # Skip administrative/process rules
            if _is_admin_rule(title, modality):
                admin_skipped += 1
                continue
            # Skip rules with generic 'extensions' subject and generic titles
            if _is_generic_extensions(title, ir_subject):
                generic_ext_skipped += 1
                continue

            match = match_rule_to_zlint(rule, zlint_lints, zlint_index, min_score)
            if match is None:
                no_candidates += 1
            else:
                results.append({
                "rule_id": rule["id"],
                "rule_title": rule["title"],
                "rule_section": rule["section"],
                "rule_operation": rule["operation"],
                "rule_modality": rule["modality"],
                "rule_ir_subject": ir_subject,
                "lint_name": match["lint"]["lint_name"],
                "lint_predicate": match["lint"]["predicate"],
                "lint_section": match["lint"]["section"],
                "score": match["score"],
                "method": match["method"],
                "alternatives": [(a[0]["lint_name"], a[1]) for a in match.get("alternatives", [])],
            })

        print(f"\nMatch results:")
        print(f"  No candidates: {no_candidates}")
        print(f"  Above threshold: {len(results)}")
        print(f"  Admin/process skipped: {admin_skipped}")
        print(f"  Generic-extensions skipped: {generic_ext_skipped}")

        if not results:
            print("No matches found. Consider lowering --min-score.")
            return

        # Print top matches
        results.sort(key=lambda x: x["score"], reverse=True)
        print(f"\nTop 20 matches:")
        for r in results[:20]:
            alt_str = ""
            if r["alternatives"]:
                alt_str = f" (alts: {', '.join(a[0] for a in r['alternatives'][:3])})"
            print(f"  #{r['rule_id']:4d} [{str(r['rule_modality'] or ''):15s} {str(r['rule_operation'] or ''):30s}] score={r['score']:.2f} method={r['method']}")
            print(f"       rule: {str(r['rule_title'])[:50]}")
            print(f"       ir_subject: {r['rule_ir_subject']}")
            print(f"       → lint={r['lint_name']} (pred={r['lint_predicate']}, sec={r['lint_section']}){alt_str}")

        if dry_run:
            print(f"\nDry run: would update {len(results)} rules")
            return

        # Batch update
        updates = [(r["lint_name"], r["rule_id"]) for r in results]
        sql = "UPDATE rules SET zlint_lint_name = %s WHERE id = %s"
        execute_batch(cur, sql, updates, page_size=batch_size)
        conn.commit()
        print(f"\nUpdated {len(results)} rules.zlint_lint_name")

        # Verify
        cur.execute("""
            SELECT COUNT(*) FROM rules r
            JOIN standards s ON s.id = r.standard_id
            WHERE s.source = %s AND r.zlint_lint_name IS NOT NULL
        """, (source,))
        new_total = cur.fetchone()[0]
        print(f"Total rules with zlint_lint_name for {source}: {new_total}")

        # Print final stats
        cur.execute("""
            SELECT zlint_lint_name, COUNT(*) as cnt
            FROM rules r JOIN standards s ON s.id = r.standard_id
            WHERE s.source = %s AND r.zlint_lint_name IS NOT NULL
            GROUP BY zlint_lint_name ORDER BY cnt DESC LIMIT 10
        """, (source,))
        print(f"\nTop zlint lints linked for {source}:")
        for row in cur.fetchall():
            print(f"  {row[0]}: {row[1]} rules")

    finally:
        cur.close()
        conn.close()


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--source", default="CABF-BR",
                        choices=["CABF-BR", "RFC", "Apple", "Mozilla"])
    parser.add_argument("--min-score", type=float, default=0.3)
    parser.add_argument("--batch-size", type=int, default=100)
    args = parser.parse_args()
    migrate(dry_run=args.dry_run, source=args.source,
            min_score=args.min_score, batch_size=args.batch_size)