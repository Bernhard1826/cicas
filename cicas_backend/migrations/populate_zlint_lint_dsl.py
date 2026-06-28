"""populate_zlint_lint_dsl.py — populate zlint_lint_dsl table from lint_ir_summaries.json.

For each entry in lint_ir_summaries.json:
  1. Normalize source -> zlint Source constant (CABF-BR, RFC, Apple, etc.)
  2. Parse subject path (tbsCertificate.X -> extensions.X / Subject.X / etc.)
  3. Parse constraint string -> structured {type, value} for DSL
  4. Build DSL atom from (predicate, subject, constraint)
  5. Insert into zlint_lint_dsl

Usage:
  python populate_zlint_lint_dsl.py [--repopulate] [--dry-run]
"""
from __future__ import annotations

import json
import re
import sys
import os
from pathlib import Path
from typing import Optional

# Resolve paths
_backend = Path(__file__).resolve().parent.parent.parent
_root = _backend.parent

# zlint/ is under cicas_backend/, not under _backend
_backend_actual = Path(__file__).resolve().parent.parent  # = cicas_backend

# Add backend to path for imports
_backend_dir = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_backend_dir))
os.environ.setdefault('DATABASE_URL',
                      'postgresql://postgres:123456@localhost:15432/cicas')

import psycopg2
from psycopg2.extras import execute_batch

from app.services.certificate.dsl import dsl
from app.services.certificate.dsl.dsl_compare import canon as _canon, relate, Relation


# =====================================================================
# Go Description Enrichment
# Enriches DSL atoms with semantic markers extracted from Go source.
# This addresses the "policy condition lost" and "cardinality lost" problems.
# =====================================================================

# Source → Go subdirectory mapping
_SOURCE_DIR_MAP = {
    "CABF-BR": "cabf_br",
    "CABF-S/MIME": "cabf_smime_br",
    "Mozilla": "mozilla",
    "Apple": "apple",
    "RFC": "rfc",
    "ETSI": "etsi",
    "Community": "community",
    "PKIlint": "pkilint",
}

# Go Description → semantic marker extraction patterns
_POLICY_COND_RE = re.compile(
    r'If\s+certificate\s+policy\s+([0-9.]+)\s*\(([^)]+)\)\s+is\s+included',
    re.IGNORECASE
)
_POLICY_COND_SHORT_RE = re.compile(
    r'If\s+certificate\s+policy\s+([0-9.]+)\s+is\s+included',
    re.IGNORECASE
)
_POLICY_OBLIGATION_RE = re.compile(
    r'(organization name|MUST NOT|MUST|givenName and surname|SHOULD NOT|SHOULD)',
    re.IGNORECASE
)
_KU_BIT_RE = re.compile(
    r'Bit\s+position\s+for\s+(\w+)\s+is\s+REQUIRED',
    re.IGNORECASE
)
_CARDINALITY_EXACTLY_ONE_RE = re.compile(
    r'\bexactly\s+one\b',
    re.IGNORECASE
)


def _resolve_go_file(lint_name: str, raw_source: str) -> Optional[Path]:
    """Locate the Go source file for a lint.

    Tries: zlint/v3/lints/{source_dir}/lint_{lint_name}.go
    Returns None if not found.
    """
    if not lint_name:
        return None
    # Normalize lint_name: strip "e_" prefix if present
    name_part = lint_name
    if name_part.startswith("e_"):
        name_part = name_part[2:]
    if name_part.startswith("w_"):
        name_part = name_part[2:]
    if name_part.startswith("n_"):
        name_part = name_part[2:]

    source = normalize_source(raw_source)
    source_dir = _SOURCE_DIR_MAP.get(source, source.lower().replace(" ", "_"))

    # Try cicas_backend (where zlint/ lives) then _backend
    for base in [_backend_actual, _backend]:
        go_path = base / "zlint" / "v3" / "lints" / source_dir / f"lint_{lint_name}.go"
        if go_path.exists():
            return go_path
        # Also try without "e_" prefix
        go_path2 = base / "zlint" / "v3" / "lints" / source_dir / f"lint_{name_part}.go"
        if go_path2.exists():
            return go_path2

    return None


def extract_go_description(lint_name: str, raw_source: str) -> str:
    """Extract the Description field from the Go source file for a lint.

    Returns the raw Description string, or "" if not found.
    """
    go_path = _resolve_go_file(lint_name, raw_source)
    if go_path is None:
        return ""

    try:
        src = go_path.read_text(encoding="utf-8", errors="replace")
    except Exception:
        return ""

    # Extract Description: "Description:   \"...\"" (may span multiple lines in the .go file)
    m = re.search(r'Description:\s*"([^"]*)"', src, re.DOTALL)
    if m:
        # Unescape Go string literal
        desc = m.group(1)
        desc = desc.replace('\\n', '\n').replace('\\t', '\t').replace('\\"', '"').replace('\\\\', '\\')
        return desc.strip()
    return ""


def extract_semantic_markers(lint_name: str, raw_source: str,
                              predicate: str, subject: str,
                              obligation: str, constraint_str: str) -> dict:
    """Extract semantic markers from Go Description for enrichment.

    Returns a meta dict with keys like:
      - policy_oid: str  (e.g. "2.23.140.1.2.1")
      - policy_name: str  (e.g. "CA/B BR domain validated")
      - policy_oblig: str  (e.g. "MUST_NOT" or "MUST")
      - policy_field: str  (e.g. "Organization" or "givenName and surname")
      - ku_bit: str  (e.g. "keyCertSign")
      - cardinality: str  (e.g. "exactly_one")
      - go_description: str  (full Description string)
    """
    meta: dict = {}
    desc = extract_go_description(lint_name, raw_source)
    if not desc:
        return meta

    meta["go_description"] = desc

    # ---- Policy conditional: "If certificate policy OID (NAME) is included" ----
    m = _POLICY_COND_RE.search(desc)
    if m:
        meta["policy_oid"] = m.group(1)
        meta["policy_name"] = m.group(2)
    else:
        m = _POLICY_COND_SHORT_RE.search(desc)
        if m:
            meta["policy_oid"] = m.group(1)

    if "policy_oid" in meta:
        # Extract obligation and field from description context
        if "MUST NOT" in desc or "must NOT" in desc:
            meta["policy_oblig"] = "MUST_NOT"
        elif "MUST" in desc or "must" in desc:
            meta["policy_oblig"] = "MUST"
        elif "SHOULD NOT" in desc:
            meta["policy_oblig"] = "SHOULD_NOT"
        elif "SHOULD" in desc:
            meta["policy_oblig"] = "SHOULD"

        # Extract the field being checked
        # "organization name" → "Organization"
        if "organization name" in desc.lower():
            meta["policy_field"] = "Organization"
        elif "givenName and surname" in desc.lower() or "givenname and surname" in desc.lower():
            meta["policy_field"] = "givenName AND surname"
        elif "commonName" in desc:
            meta["policy_field"] = "CommonName"

    # ---- KeyUsage bit required: "Bit position for X is REQUIRED" ----
    m = _KU_BIT_RE.search(desc)
    if m:
        meta["ku_bit"] = m.group(1)

    # ---- Cardinality: "exactly one" ----
    if _CARDINALITY_EXACTLY_ONE_RE.search(desc):
        meta["cardinality"] = "exactly_one"

    return meta


def inject_meta_into_atom(atom_json_str: str, meta: dict) -> str:
    """Inject semantic markers (meta) into a DSL atom JSON string.

    This modifies the atom JSON to include a 'meta' sub-dict with semantic
    enrichment derived from Go Description. sigma_mech reads this for
    richer NL output.
    """
    if not meta:
        return atom_json_str

    atom_dict = json.loads(atom_json_str)
    # Filter out 'go_description' from meta (too verbose for sigma_mech input,
    # but keep it for debugging — sigma_mech only reads specific markers)
    filtered_meta = {k: v for k, v in meta.items() if k != "go_description"}
    if not filtered_meta:
        return atom_json_str

    atom_dict["meta"] = filtered_meta
    return json.dumps(atom_dict, default=str)


# ---- Source normalization ----

def normalize_source(raw_source: str) -> str:
    """Map _raw_source to zlint Source constant.

    Examples:
      "cabf_br:CABFBaselineRequirements" -> "CABF-BR"
      "rfc:RFC5280"                       -> "RFC"
      "apple:AppleRootStorePolicy"         -> "Apple"
      "community:Community"               -> "Community"
      "etsi:EN319412"                     -> "ETSI"
      "mozilla:MozillaRootStorePolicy"    -> "Mozilla"
      "smime_extension:SMIME"              -> "CABF-S/MIME"
    """
    if not raw_source:
        return "Unknown"
    src = raw_source.lower()

    # Known source groups
    if "cabf_br" in src or "cabfb" in src:
        return "CABF-BR"
    if "cabf_smime" in src or "smime_br" in src or "cabf_s/mime" in src:
        return "CABF-S/MIME"
    if "cabf_ev" in src or "cabf_server" in src or "cabf_netsec" in src:
        return "CABF-BR"
    if src.startswith("rfc:"):
        return "RFC"
    if "apple" in src:
        return "Apple"
    if "mozilla" in src:
        return "Mozilla"
    if "etsi" in src or "en_" in src or "ts_" in src:
        return "ETSI"
    if "smime" in src and "cabf" not in src:
        return "CABF-S/MIME"
    if "community" in src:
        return "Community"
    if "x509lint" in src or src.startswith("error:") or src == "error:error":
        return "x509lint"
    if "cablint" in src or "certlint" in src or "pemlint" in src:
        return "certlint"
    if "pkilint" in src:
        return "PKIlint"
    if "warranty" in src or "notice" in src:
        return "Mozilla"

    # Extract the package name after ":"
    if ":" in raw_source:
        pkg = raw_source.split(":")[-1]
        # Map to source
        if pkg in ("RFC5280", "RFC5248", "RFC6818"):
            return "RFC"
        return pkg
    return raw_source


# ---- Subject path conversion ----

def tbs_to_dsl_subject(path: str) -> tuple[str, Optional[str]]:
    """Convert zlint tbsCertificate path to (normalized_subject, sentinel).

    Returns (subject, sentinel) where sentinel is None for normal fields,
    or one of '@SAN_DNS', '@SAN_EMAIL', etc. for nested paths.

    Examples:
      "tbsCertificate.extensions.subjectAltName.dNSName" -> ("DNSNames", "@SAN_DNS")
      "tbsCertificate.subject.commonName"                -> ("Subject.CommonName", None)
      "tbsCertificate.extensions.keyUsage"               -> ("KeyUsage", None)
      "tbsCertificate.extensions.subjectAltName"         -> ("SubjectAlternateNameOID", None)
      "tbsCertificate.validity"                           -> ("ValidityPeriod", None)
      "tbsCertificate.extensions.authorityInfoAccess.caIssuers" -> ("IssuingCertificateURL", None)
    """
    if not path:
        return ("", None)

    # Strip prefix
    p = path
    if p.startswith("tbsCertificate."):
        p = p[len("tbsCertificate."):]

    # Nested SAN/IAN fields
    if "subjectaltname" in p.lower():
        lower = p.lower()
        if "dnsname" in lower or lower.endswith(".dnsname") or ".dnsnames" in lower:
            return ("DNSNames", "@SAN_DNS")
        if "ipaddress" in lower or ".ipaddresses" in lower:
            return ("IPAddresses", "@SAN_IPADDR")
        if "rfc822name" in lower or "emailaddress" in lower or ".emailaddresses" in lower:
            return ("EmailAddresses", "@SAN_EMAIL")
        if "uri" in lower or "uniformresourceidentifier" in lower:
            return ("URIs", "@SAN_URI")
        if "directoryname" in lower:
            return ("SubjectAlternateNameOID", "@SAN_DIRNAME")
        # Just subjectAltName present
        return ("SubjectAlternateNameOID", "@SAN_DNS")

    # AIA nested fields
    if "authorityinfoaccess" in p.lower():
        lower = p.lower()
        if "cacissuers" in lower or "caissuers" in lower:
            return ("IssuingCertificateURL", "@AIA_CAISSUERS")
        if "ocsp" in lower:
            return ("OCSPServer", "@AIA_OCSP")
        return ("IssuingCertificateURL", "@AIA_CAISSUERS")

    # Extensions -> extension OID
    if p.startswith("extensions."):
        ext = p[len("extensions."):]
        # Remove sub-field for OID determination
        ext_base = ext.split(".")[0].lower()

        # Named extensions
        ext_map = {
            "subjectaltname": "SubjectAltNameOID",
            "subjectalternativename": "SubjectAltNameOID",
            "keyusage": "KeyUsageOID",
            "basickconstraints": "BasicConstraintsOID",
            "basicconstraints": "BasicConstraintsOID",
            "certificatepolicies": "CertPolicyOID",
            "certificatedp": "CrlDistOID",
            "crldistributionpoints": "CrlDistOID",
            "authoritykeyidentifier": "AuthorityKeyIdOID",
            "authorityinfoaccess": "AiaOID",
            "extkeyusage": "EkuSynOid",
            "subjectkeyidentifier": "SubjectKeyIdOID",
            "subjectinfoaccess": "SubjectInfoAccessOID",
            "issueraltname": "IssuerAltNameOID",
            "nameconstraints": "NameConstOID",
            "policymappings": "PolicyMappingsOID",
            "freshcrl": "FreshestCRLOID",
        }
        if ext_base in ext_map:
            return (ext_map[ext_base], None)
        return (f"Extension({ext_base})", None)

    # Subject DN fields
    if p.startswith("subject."):
        dn = p[len("subject."):]
        dn_map = {
            "commonname": "CommonName",
            "countryname": "Country",
            "organizationname": "Organization",
            "organizationalunitname": "OrganizationalUnit",
            "localityname": "Locality",
            "province": "Province",
            "streetaddress": "StreetAddress",
            "postalcode": "PostalCode",
            "domaincomponent": "DomainComponent",
            "emailaddress": "EmailAddress",
            "serialnumber": "SerialNumber",
            "organizationidentifier": "OrganizationIDs",
        }
        if dn.lower() in dn_map:
            return (f"Subject.{dn_map[dn.lower()]}", None)
        return (f"Subject.{dn}", None)

    # Issuer DN fields
    if p.startswith("issuer."):
        dn = p[len("issuer."):]
        dn_map = {
            "commonname": "CommonName",
            "countryname": "Country",
            "organizationname": "Organization",
            "organizationalunitname": "OrganizationalUnit",
            "localityname": "Locality",
            "province": "Province",
            "streetaddress": "StreetAddress",
            "postalcode": "PostalCode",
            "domaincomponent": "DomainComponent",
            "emailaddress": "EmailAddress",
            "serialnumber": "SerialNumber",
            "organizationidentifier": "OrganizationIDs",
        }
        if dn.lower() in dn_map:
            return (f"Issuer.{dn_map[dn.lower()]}", None)
        return (f"Issuer.{dn}", None)

    # Top-level fields
    top_map = {
        "validity": "ValidityPeriod",
        "validity.notbefore": "NotBefore",
        "validity.notafter": "NotAfter",
        "serialnumber": "SerialNumber",
        "version": "Version",
        "subject": "Subject",
        "issuer": "Issuer",
        "subjectpublickeyinfo": "PublicKeyAlgorithm",
        "signaturealgorithm": "SignatureAlgorithm",
        "extensions": "Extensions",
    }
    if p.lower() in top_map:
        return (top_map[p.lower()], None)

    # KeyUsage sub-field
    if "keyusage" in p.lower() and "ext" not in p.lower():
        return ("KeyUsage", None)
    if "extkeyusage" in p.lower() or "extendedkeyusage" in p.lower():
        return ("ExtKeyUsage", None)

    return (p, None)


# ---- Constraint string parser ----

def parse_constraint(predicate: str, constraint, subject: str) -> dict:
    """Parse a free-text constraint string into structured form.

    Returns {type, value, raw_text, pattern_name} or {} for empty/no-parse.
    """
    if constraint is None:
        c = ""
    elif isinstance(constraint, str):
        c = constraint.strip()
    elif isinstance(constraint, list):
        c = json.dumps(constraint, default=str)
    elif isinstance(constraint, dict):
        c = json.dumps(constraint, default=str)
    else:
        c = str(constraint)
    if not c:
        return {"type": "presence", "value": "", "raw_text": ""}

    raw_text = c

    # TRUE/FALSE boolean
    if c.upper() == "TRUE":
        return {"type": "bool", "value": True, "raw_text": raw_text}
    if c.upper() == "FALSE":
        return {"type": "bool", "value": False, "raw_text": raw_text}

    # HTTP URL format
    if "http" in c.lower() and "url" in c.lower():
        return {"type": "regex_pattern", "pattern_name": "Re_HttpUrl", "raw_text": raw_text}
    if c.lower() in ("http url", "http url only"):
        return {"type": "regex_pattern", "pattern_name": "Re_HttpUrlStrict", "raw_text": raw_text}
    if c.lower() in ("http://", "https://"):
        return {"type": "regex_pattern", "pattern_name": "Re_HttpUrlStrict", "raw_text": raw_text}
    if c.lower() in ("http:// or https://", "http://, https://"):
        return {"type": "regex_pattern", "pattern_name": "Re_HttpUrl", "raw_text": raw_text}

    # DNS name format
    if "dns" in c.lower() and "name" in c.lower():
        return {"type": "regex_pattern", "pattern_name": "DNS_NAME", "raw_text": raw_text}
    if "dns label" in c.lower() and "reserved" in c.lower():
        return {"type": "regex_pattern", "pattern_name": "Re_ReservedLDH_Excluded", "raw_text": raw_text}
    if "no underscore" in c.lower() or "underscore" in c.lower():
        return {"type": "regex_pattern", "pattern_name": "Re_NoUnderscore", "raw_text": raw_text}
    if "punycode" in c.lower() or "idn" in c.lower():
        return {"type": "regex_pattern", "pattern_name": "Re_PunyOrLDH_Label", "raw_text": raw_text}
    if "fqdn" in c.lower() or "fully qualified" in c.lower():
        return {"type": "regex_pattern", "pattern_name": "Re_LDH_Hostname", "raw_text": raw_text}

    # IP address format
    if "ipv4" in c.lower() or "ipv6" in c.lower() or "ip address" in c.lower():
        return {"type": "regex_pattern", "pattern_name": "IPV4_ADDRESS", "raw_text": raw_text}

    # Email/RFC 822
    if "email" in c.lower() or "rfc 822" in c.lower() or "rfc822" in c.lower():
        return {"type": "regex_pattern", "pattern_name": "RFC_822_NAME", "raw_text": raw_text}
    if "mailbox" in c.lower():
        return {"type": "regex_pattern", "pattern_name": "Re_Rfc5321Mailbox", "raw_text": raw_text}

    # URI
    if "uri" in c.lower() or "uniform resource" in c.lower():
        return {"type": "regex_pattern", "pattern_name": "UNIFORM_RESOURCE_IDENTIFIER", "raw_text": raw_text}

    # Length comparisons
    m_days = re.match(r"<=\s*(\d+)\s*days?", c, re.IGNORECASE)
    if m_days:
        return {"type": "length", "max_value": int(m_days.group(1)), "raw_text": raw_text}
    m_months = re.match(r"(\d+)\s*months?", c, re.IGNORECASE)
    if m_months:
        return {"type": "length", "max_value": int(m_months.group(1)) * 30, "raw_text": raw_text}
    m_le = re.match(r"<=\s*(\d+)", c)
    if m_le:
        return {"type": "length", "max_value": int(m_le.group(1)), "raw_text": raw_text}
    m_ge = re.match(r">=\s*(\d+)", c)
    if m_ge:
        return {"type": "length", "min_value": int(m_ge.group(1)), "raw_text": raw_text}
    m_eq = re.match(r"=\s*(\d+)", c)
    if m_eq:
        return {"type": "length", "value": int(m_eq.group(1)), "raw_text": raw_text}

    # ISO 3166 country codes
    if "iso 3166" in c.lower() or "alpha-2" in c.lower() or "country code" in c.lower():
        # Country code format: 2 uppercase letters
        return {"type": "regex_pattern", "pattern_name": "Re_ASCII_LDH_Label", "raw_text": raw_text}

    # Set membership {a, b, c}
    m_set = re.match(r"\{(.+)\}", c)
    if m_set:
        vals = [v.strip() for v in m_set.group(1).split(",")]
        if predicate in ("one_of", "subset_of", "not_one_of"):
            return {"type": "one_of", "value": vals, "raw_text": raw_text}
        if predicate == "subset_of":
            return {"type": "subset_of", "value": vals, "raw_text": raw_text}

    # No domain label / reserved label prefix
    if "reserved label" in c.lower() or "forbidden" in c.lower():
        return {"type": "regex_pattern", "pattern_name": "Re_FQDN_PunyOrNonReservedLDH", "raw_text": raw_text}

    # Encoding
    if "ia5" in c.lower() or "printable" in c.lower() or "utf8" in c.lower() or "utf-8" in c.lower():
        types = []
        if "ia5" in c.lower(): types.append("IA5String")
        if "printable" in c.lower(): types.append("PrintableString")
        if "utf8" in c.lower() or "utf-8" in c.lower(): types.append("UTF8String")
        if types:
            return {"type": "asn1_type_set", "asn1_types": types, "raw_text": raw_text}

    # ASN.1 encoding tags
    if "encoding" in c.lower() and ("tag" in c.lower() or "type" in c.lower()):
        types = []
        for t in ["PrintableString", "IA5String", "UTF8String", "BMPString"]:
            if t.lower().replace("-", "") in c.lower().replace("-", ""):
                types.append(t)
        if types:
            return {"type": "asn1_type_set", "asn1_types": types, "raw_text": raw_text}

    # LDAP URL
    if "ldap" in c.lower():
        return {"type": "regex_pattern", "pattern_name": "Re_LdapUrl", "raw_text": raw_text}

    # Generic format specifier
    if predicate == "valid_format":
        return {"type": "format", "value": c, "raw_text": raw_text}

    # Default: treat as raw text constraint
    return {"type": "raw_text", "value": c, "raw_text": raw_text}


# ---- DSL atom builder from lint IR ----

def lint_ir_to_atom(predicate: str, subject: str, obligation: str,
                    constraint: str) -> Optional[dsl.AND]:
    """Build a DSL atom from a lint IR entry.

    predicate: must_be_present, must_be_absent, valid_format, equal_to, ...
    subject:  tbsCertificate path
    obligation: MUST, MUST_NOT, SHOULD, SHOULD_NOT
    constraint: free-text constraint string
    """
    pred = (predicate or "").strip().lower()
    if not pred:
        return None

    # Resolve subject
    field, sentinel = tbs_to_dsl_subject(subject)
    if not field and sentinel is None:
        return None

    # Parse constraint
    c = parse_constraint(pred, constraint, field)

    # Map obligation to severity
    sev = "lint.Error"
    obl = (obligation or "").strip().upper()
    if obl in ("MUST_NOT", "PROHIBITED"):
        sev = "lint.Error"
    elif obl in ("SHOULD", "SHOULD_NOT", "RECOMMENDED"):
        sev = "lint.Warn"
    elif obl == "MAY":
        sev = "lint.Notice"

    # ---- Dispatch ----
    atom = _lint_dispatch(pred, field, sentinel, c)

    if atom is None:
        # Irred residual: conforms_to_ref, complex format, etc.
        return None

    return atom


def _lit(values: tuple) -> tuple:
    return values


def _lint_dispatch(pred: str, field: str, sentinel: Optional[str], c: dict):
    """Dispatch lint IR predicate + constraint to DSL atom."""
    ctype = c.get("type", "")
    cval = c.get("value")
    ctype_str = ctype
    pattern_name = c.get("pattern_name", "")
    asn1_types = c.get("asn1_types", [])

    # ---- Extension OID path ----
    if field in ("KeyUsageOID", "BasicConstraintsOID", "SubjectAltNameOID",
                 "CertPolicyOID", "CrlDistOID", "AuthorityKeyIdOID",
                 "EkuSynOid", "AiaOID", "NameConstOID",
                 "SubjectKeyIdOID", "IssuerAltNameOID", "ExtCrlDistributionPoints"):

        oid = field

        if pred == "must_be_present":
            return dsl.ExtPresent(oid)
        if pred == "must_be_absent":
            return dsl.Not(dsl.ExtPresent(oid))
        if pred == "critical":
            return dsl.ExtCritical(oid)
        if pred == "non_critical":
            return dsl.ExtNotCritical(oid)

        # KeyUsage bit set
        if ctype == "bit_set":
            bits = cval if isinstance(cval, list) else []
            valid_ku = [b for b in bits if b.upper() in (
                "DIGITALSIGNATURE", "CONTENTCOMMITMENT", "KEYENCIPHERMENT",
                "DATAENCIPHERMENT", "KEYAGREEMENT", "CERTSIGN",
                "CRLSIGN", "ENCIPHERONLY", "DECIPHERONLY")]
            if oid == "KeyUsageOID" and valid_ku:
                if len(valid_ku) == 1:
                    return dsl.KeyUsageHas(valid_ku[0])
                return dsl.And(tuple(dsl.KeyUsageHas(b) for b in valid_ku))

        # CertPolicy with OID set
        if oid == "CertPolicyOID" and ctype == "oid_ref":
            oid_const = cval
            if oid_const:
                return dsl.OidListContains("PolicyIdentifiers", oid_const)

        # Extension URL list regex
        if pred in ("valid_format", "matches_regex") and pattern_name:
            list_field_map = {
                "AiaOID": "IssuingCertificateURL",
                "CrlDistOID": "CRLDistributionPoints",
                "ExtCrlDistributionPoints": "CRLDistributionPoints",
            }
            list_field = list_field_map.get(oid, "")
            if list_field and pattern_name in (
                "Re_HttpUrl", "Re_HttpUrlStrict", "Re_LdapUrl",
                "Re_LdapUrlStrict", "Re_AnyUri", "Re_Rfc3986Uri",
                "Re_HttpOrLdapUrl", "Re_HttpOrLdapStrict",
            ):
                return dsl.ListAllMatch(list_field, dsl.ItemMatchesRegex(pattern_name))
            return None

        # CertPolicy extension presence (vague format -> presence)
        if pred == "must_be_present" and oid == "CertPolicyOID":
            return dsl.ExtPresent(oid)

        # NameConstraints IP encoding
        if oid == "NameConstOID" and ctype == "byte_count":
            cnt = c.get("count")
            raw = c.get("raw_text", "")
            field_name = "ExcludedIPAddresses" if "excluded" in raw.lower() else "PermittedIPAddresses"
            if isinstance(cnt, int) and cnt in (8, 32):
                return dsl.SubtreeIPListAnyHasOctetCount(field_name, cnt)
            return None

    # ---- Sentinel path ----
    if sentinel:
        sent = sentinel

        if sent == "@SAN_DNS":
            if pred in ("must_be_present", "must_include"):
                return dsl.FieldNonEmpty("DNSNames")
            if pred in ("must_be_absent", "must_not_include"):
                return dsl.FieldEmpty("DNSNames")
            if pred in ("valid_format", "matches_regex"):
                pat = pattern_name or "DNS_NAME"
                return dsl.ListAllMatch("DNSNames", dsl.ItemMatchesRegex(pat))
            if pred == "not_equal_to" and cval in ("http", "https"):
                return dsl.ListAllMatch("DNSNames", dsl.ItemNotMatchesRegex("Re_HttpUrl"))
            if pred == "not_one_of":
                return dsl.ListAllMatch("DNSNames", dsl.ItemNotMatchesRegex("Re_HttpUrl"))

        if sent == "@SAN_EMAIL":
            if pred in ("must_be_present", "must_include"):
                return dsl.FieldNonEmpty("EmailAddresses")
            if pred in ("valid_format", "matches_regex"):
                pat = pattern_name or "RFC_822_NAME"
                return dsl.ListAllMatch("EmailAddresses", dsl.ItemMatchesRegex(pat))

        if sent == "@SAN_IPADDR":
            if pred in ("must_be_present", "must_include"):
                return dsl.FieldNonEmpty("IPAddresses")
            cnt = c.get("count")
            if ctype == "byte_count" and isinstance(cnt, int):
                return dsl.IPListAllOctetCount("IPAddresses", cnt)

        if sent == "@SAN_URI":
            if pred in ("must_be_present", "must_include"):
                return dsl.FieldNonEmpty("URIs")
            if pred in ("valid_format", "matches_regex"):
                pat = pattern_name or "UNIFORM_RESOURCE_IDENTIFIER"
                return dsl.ListAllMatch("URIs", dsl.ItemMatchesRegex(pat))

        if sent == "@AIA_CAISSUERS":
            if pred == "must_be_present":
                return dsl.FieldNonEmpty("IssuingCertificateURL")
            if pred in ("valid_format", "matches_regex"):
                pat = pattern_name or "Re_HttpUrl"
                return dsl.ListAllMatch("IssuingCertificateURL", dsl.ItemMatchesRegex(pat))

        if sent == "@AIA_OCSP":
            if pred == "must_be_present":
                return dsl.FieldNonEmpty("OCSPServer")
            if pred in ("valid_format", "matches_regex"):
                pat = pattern_name or "Re_HttpUrl"
                return dsl.ListAllMatch("OCSPServer", dsl.ItemMatchesRegex(pat))

        if sent == "@SAN_DIRNAME":
            if pred in ("must_be_present", "must_include"):
                return dsl.FieldNonEmpty("SubjectAlternateNameOID")
            return None

    # ---- Certificate / DN field path ----
    if field:

        # Existence
        if pred in ("must_be_present", "must_include"):
            return dsl.FieldNonEmpty(field)
        if pred in ("must_be_absent", "must_be_empty"):
            return dsl.FieldEmpty(field)

        # Equality
        if pred == "equal_to":
            if isinstance(cval, bool):
                if field == "IsCA":
                    return dsl.IsCA() if cval else dsl.Not(dsl.IsCA())
                if field == "BasicConstraintsValid":
                    return dsl.FieldEq(field, cval)
            if isinstance(cval, (str, int)):
                return dsl.FieldEq(field, cval)
            return None

        if pred == "not_equal_to":
            if cval == "http":
                return dsl.ListAllMatch("IssuingCertificateURL",
                                        dsl.ItemNotMatchesRegex("Re_HttpUrlStrict"))
            if isinstance(cval, (str, int)):
                return dsl.FieldNotInSet(field, (cval,))
            return None

        # Set membership
        if pred in ("one_of", "not_one_of"):
            vals = c.get("value", [])
            if isinstance(vals, list) and vals:
                atom = dsl.FieldInSet(field, tuple(vals))
                if pred == "not_one_of":
                    return dsl.Not(atom)
                return atom

        # Subset of
        if pred == "subset_of":
            vals = c.get("value", [])
            if isinstance(vals, list) and vals:
                return dsl.FieldInSet(field, tuple(vals))
            # If cval is a raw text pattern (not parseable), keep as Form B
            return None

        # Format / regex
        if pred in ("valid_format", "matches_regex"):
            # Priority: explicit pattern_name in parsed constraint > cval (raw text)
            pat = c.get("pattern_name") or (cval if ctype == "raw_text" else None)
            if pat in (
                "Re_HttpUrl", "Re_HttpUrlStrict", "Re_LdapUrl", "Re_LdapUrlStrict",
                "Re_Rfc3986Uri", "Re_AnyUri", "Re_HttpOrLdapUrl",
                "Re_NoUnderscore", "Re_ASCII_LDH_Label", "Re_LDH_Label",
                "Re_ReservedLDH_Excluded", "Re_FQDN_PunyOrNonReservedLDH",
                "Re_NoConsecutiveDots", "Re_Rfc5321Mailbox",
                "DNS_NAME", "IDNA2008", "RFC_822_NAME",
                "IPV4_ADDRESS", "IPV6_ADDRESS",
                "UNIFORM_RESOURCE_IDENTIFIER",
            ):
                # List fields use ListAllMatch; single fields use FieldMatchesRegex
                list_fields = {
                    "DNSNames", "EmailAddresses", "URIs", "IPAddresses",
                    "IssuingCertificateURL", "OCSPServer", "CRLDistributionPoints",
                }
                if field in list_fields:
                    return dsl.ListAllMatch(field, dsl.ItemMatchesRegex(pat))
                return dsl.FieldMatchesRegex(field, pat)
            return None

        # Length constraints
        if pred in ("length_le", "length_ge", "length_eq", "length_range"):
            lo = c.get("min_value", 0)
            hi = c.get("max_value", c.get("value", "MAX_INT"))
            if hi == "MAX_INT" or hi is None:
                hi = "MAX_INT"
            if not isinstance(lo, int): lo = 0
            if not isinstance(hi, int) and hi != "MAX_INT":
                try: hi = int(hi)
                except: hi = "MAX_INT"
            if pred in ("length_le", "length_ge", "length_eq"):
                if pred == "length_le":
                    lo = 0
                if pred == "length_eq":
                    hi = lo
            list_fields = {
                "DNSNames", "EmailAddresses", "URIs", "IPAddresses",
                "SerialNumber", "Subject.CommonName",
            }
            if field in list_fields:
                return dsl.FieldLenInRange(field, lo, hi)
            return dsl.FieldNumericInRange(field, lo, hi)

        # ASN.1 encoding
        if pred == "encoded_as":
            if asn1_types:
                return dsl.FieldEncodedAs(field, tuple(asn1_types))
            return None

        # Unique
        if pred == "unique":
            return dsl.FieldNonEmpty(field)

        # DN ordering
        if pred == "dn_ordering":
            return dsl.DomainComponentOrdered()

        # Critical / non-critical
        if pred == "critical":
            return dsl.ExtCritical(field)
        if pred == "non_critical":
            return dsl.ExtNotCritical(field)

    return None


# ---- Main populate ----

def populate(dry_run: bool = False, repopulate: bool = False):
    DATABASE_URL = os.getenv('DATABASE_URL',
                             'postgresql://postgres:123456@localhost:15432/cicas')

    # Load lint_ir_summaries.json
    json_paths = [
        _backend / "experiments" / "results" / "lint_ir_summaries.json",
        _root / "experiments" / "results" / "lint_ir_summaries.json",
    ]
    json_path = None
    for p in json_paths:
        if p.exists():
            json_path = p
            break

    if not json_path:
        print(f"ERROR: lint_ir_summaries.json not found in {json_paths}")
        return

    data = json.load(open(json_path))
    print(f"Loaded {len(data)} entries from {json_path}")

    conn = psycopg2.connect(DATABASE_URL)
    cur = conn.cursor()

    try:
        if repopulate:
            print("Clearing existing zlint_lint_dsl data...")
            cur.execute("DELETE FROM zlint_lint_dsl")

        # Count existing
        cur.execute("SELECT COUNT(*) FROM zlint_lint_dsl")
        existing = cur.fetchone()[0]
        if existing and not repopulate:
            print(f"Table already has {existing} rows. Use --repopulate to replace.")
            return

        rows = []
        form_b_count = 0
        form_a_count = 0
        parse_errors = 0

        for entry in data:
            lint_name = entry.get("rule_id", "")
            raw_source = entry.get("_raw_source", "")
            source = normalize_source(raw_source)

            # Parse section from citation_section (may be comma-separated)
            section = entry.get("citation_section") or ""
            # Take first section if multiple
            if "," in section:
                section = section.split(",")[0].strip()

            obligation = entry.get("obligation", "")
            predicate = entry.get("predicate", "")
            subject = entry.get("subject", "")
            constraint_str = entry.get("constraint", "")

            # Build DSL atom
            atom = lint_ir_to_atom(predicate, subject, obligation, constraint_str)

            # ---- Enrich atom with semantic markers from Go Description ----
            # This restores policy conditions, cardinality, KU bits, etc. that
            # are lost when only the IR predicate/subject/constraint are extracted.
            meta = extract_semantic_markers(lint_name, raw_source,
                                            predicate, subject,
                                            obligation, constraint_str)

            if atom is None:
                # Form B: irred residual
                form_b_count += 1
                dsl_atom_json = None
                dsl_form = "Form_B"
                irred_class = "CONFORMS_TO_REF" if predicate == "conforms_to_ref" else "IR_PREDICATE_UNMAPPED"
            else:
                form_a_count += 1
                dsl_atom_json = json.dumps(dsl.compound_to_json(atom), default=str)
                # Inject meta into atom for richer σ_mech output
                dsl_atom_json = inject_meta_into_atom(dsl_atom_json, meta)
                dsl_form = "Form_A"
                irred_class = None

            # Parse constraint to get structured form
            c = parse_constraint(predicate.lower(), constraint_str, subject)
            ctype = c.get("type", "presence")
            cval = c.get("value", "")
            if isinstance(cval, list):
                cval = json.dumps(cval, default=str)
            constraint_json = json.dumps(c, default=str)

            rows.append((
                lint_name,
                source,
                section,
                raw_source,
                predicate,
                subject,
                obligation,
                ctype,
                constraint_json,
                dsl_atom_json,
                dsl_form,
                irred_class,
            ))

        print(f"\nForm A (DSL): {form_a_count}, Form B (irred): {form_b_count}")

        if dry_run:
            print(f"\nDry run: would insert {len(rows)} rows")
            print("First 3 rows:")
            for r in rows[:3]:
                print(f"  {r[0][:60]} | {r[1]} | {r[2]} | {r[4]} | {r[6]} | {r[10]}")
            return

        # Batch insert
        sql = """
            INSERT INTO zlint_lint_dsl
              (lint_name, source, section, raw_source,
               predicate, subject, obligation, constraint_type,
               constraint_value, dsl_atom, dsl_form, irred_class)
            VALUES
              (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
            ON CONFLICT (lint_name) DO UPDATE SET
              source = EXCLUDED.source,
              section = EXCLUDED.section,
              raw_source = EXCLUDED.raw_source,
              predicate = EXCLUDED.predicate,
              subject = EXCLUDED.subject,
              obligation = EXCLUDED.obligation,
              constraint_type = EXCLUDED.constraint_type,
              constraint_value = EXCLUDED.constraint_value,
              dsl_atom = EXCLUDED.dsl_atom,
              dsl_form = EXCLUDED.dsl_form,
              irred_class = EXCLUDED.irred_class
        """
        from psycopg2.extras import execute_values
        sql = """
            INSERT INTO zlint_lint_dsl
              (lint_name, source, section, raw_source, predicate, subject, obligation,
               constraint_type, constraint_value, dsl_atom, dsl_form, irred_class)
            VALUES %s
            ON CONFLICT (lint_name) DO UPDATE SET
              source = EXCLUDED.source, section = EXCLUDED.section,
              raw_source = EXCLUDED.raw_source, predicate = EXCLUDED.predicate,
              subject = EXCLUDED.subject, obligation = EXCLUDED.obligation,
              constraint_type = EXCLUDED.constraint_type,
              constraint_value = EXCLUDED.constraint_value,
              dsl_atom = EXCLUDED.dsl_atom, dsl_form = EXCLUDED.dsl_form,
              irred_class = EXCLUDED.irred_class
        """
        execute_values(cur, sql, rows, template=None, page_size=100)

        conn.commit()

        cur.execute("SELECT COUNT(*) FROM zlint_lint_dsl")
        total = cur.fetchone()[0]
        cur.execute("SELECT COUNT(*) FROM zlint_lint_dsl WHERE dsl_form='Form_A'")
        form_a = cur.fetchone()[0]
        cur.execute("SELECT COUNT(*) FROM zlint_lint_dsl WHERE dsl_form='Form_B'")
        form_b = cur.fetchone()[0]
        print(f"\nInserted {len(rows)} rows.")
        print(f"Total in DB: {total} (Form_A: {form_a}, Form_B: {form_b})")

    finally:
        cur.close()
        conn.close()


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--repopulate", action="store_true")
    args = parser.parse_args()
    populate(dry_run=args.dry_run, repopulate=args.repopulate)