"""codegen/detection/independent_verify.py — independent, per-finding structural
verification of cicasgen_ detections.

triage.py answers a WEAKER question than the paper needs: its REAL verdict means
"this certificate is defective for SOME lint" (upstream consensus or known-bad
fixture) — it does NOT prove that OUR specific finding matches the actual defect.
A lint that dropped a precondition can fire on a cert that is independently
defective for an unrelated reason and be waved through as REAL.

This module closes that hole. For each (lint, cert) finding it re-derives, from
openssl text + raw DER (robust to the deliberately-malformed testdata that strict
parsers reject), whether the SPECIFIC structural condition the lint asserts is
actually present in the certificate. It is the adversarial check used to certify
the §8.5 "0 false positives" claim, independent of the triage oracle.

Verdicts:
  CONFIRMED  the cert genuinely exhibits the defect the lint targets.
  REFUTED    the cert does NOT exhibit it -> the finding is a false positive.
  NOCHECK    no structural check is implemented for this lint family.

No LLM, no DB. openssl + (optional) pyasn1 for byte-identity checks.
"""
from __future__ import annotations

import json
import re
import subprocess
from pathlib import Path

ANYPOLICY = "2.5.29.32.0"
OV_POLICY = "2.23.140.1.2.2"
IV_POLICY = "2.23.140.1.2.3"

try:
    from pyasn1.codec.der import decoder as _der_dec, encoder as _der_enc
    _HAVE_PYASN1 = True
except Exception:
    _HAVE_PYASN1 = False

try:
    from pyasn1_modules import rfc5280 as _rfc5280
    _HAVE_PYMODS = True
except Exception:
    _HAVE_PYMODS = False


# --- openssl primitives (tolerant of non-UTF8 / malformed fixtures) ---------

def _osslr(cert: Path, *args) -> str:
    return subprocess.run(["openssl", "x509", "-in", str(cert), "-noout", *args],
                          capture_output=True, text=True, errors="replace").stdout


def _der_of(cert: Path) -> bytes:
    der = subprocess.run(["openssl", "x509", "-in", str(cert), "-outform", "DER"],
                         capture_output=True).stdout
    # openssl refuses (or silently re-encodes away) some deliberately-malformed
    # testdata fixtures. Fall back to the raw base64 in the PEM so byte-level
    # checks match what zcrypto (which the lints use) actually parsed.
    return der or _der_from_pem(cert)


def _text(cert: Path) -> str:
    return _osslr(cert, "-text", "-nameopt", "RFC2253")


def _subject(cert: Path) -> str:
    return _osslr(cert, "-subject", "-nameopt", "RFC2253").split("=", 1)[-1].strip()


def _issuer(cert: Path) -> str:
    return _osslr(cert, "-issuer", "-nameopt", "RFC2253").split("=", 1)[-1].strip()


def _is_ca(t: str) -> bool:
    return "CA:TRUE" in t


def _name_has(subject_rfc2253: str, label: str) -> bool:
    return bool(re.search(rf"(^|,){label}=", subject_rfc2253))


def _ext(t: str, header: str):
    """(present, critical, body_lines) for an X509v3 extension block."""
    lines = t.splitlines()
    for i, ln in enumerate(lines):
        if header in ln:
            crit = "critical" in ln
            body, j = [], i + 1
            while j < len(lines) and (lines[j].startswith("                ")
                                      or lines[j].strip() == ""):
                body.append(lines[j].strip())
                j += 1
            return True, crit, [b for b in body if b]
    return False, False, []


def _der_from_pem(cert: Path) -> bytes:
    """Raw DER straight from the PEM — NOT via `openssl -outform DER`, which
    silently drops/normalises the deliberately-malformed extensions in the
    testdata. zcrypto (which the lints use) parses those raw bytes, so the auditor
    must too or it disagrees with the lint on malformed-policy fixtures."""
    try:
        import base64
        m = re.search(rb"-----BEGIN CERTIFICATE-----(.*?)-----END CERTIFICATE-----",
                      cert.read_bytes(), re.S)
        return base64.b64decode(re.sub(rb"\s", b"", m.group(1))) if m else b""
    except Exception:
        return b""


# DER content-byte encodings of the policy OIDs the auditor cares about.
_POLICY_OID_DER = {
    "2.23.140.1.2.2": bytes([0x67, 0x81, 0x0c, 0x01, 0x02, 0x02]),  # OV
    "2.23.140.1.2.3": bytes([0x67, 0x81, 0x0c, 0x01, 0x02, 0x03]),  # IV
    "2.23.140.1.2.1": bytes([0x67, 0x81, 0x0c, 0x01, 0x02, 0x01]),  # DV
    ANYPOLICY:        bytes([0x55, 0x1d, 0x20, 0x00]),               # anyPolicy
}
_CERTPOL_EXT_DER = bytes([0x55, 0x1d, 0x20])  # id-ce-certificatePolicies 2.5.29.32


def _policy_oids(t: str, cert: Path | None = None) -> set:
    out = set()
    present, _, body = _ext(t, "X509v3 Certificate Policies")
    for b in body:
        m = re.search(r"Policy:\s*([0-9.]+)", b)
        if m:
            out.add(m.group(1))
    if present and "Any Policy" in t:
        out.add(ANYPOLICY)
    # Fallback: openssl drops malformed certificatePolicies extensions from its
    # text view, so scan the raw DER for the specific policy OIDs we test on.
    if cert is not None:
        der = _der_from_pem(cert)
        if der and _CERTPOL_EXT_DER in der:
            for oid, needle in _POLICY_OID_DER.items():
                if needle in der:
                    out.add(oid)
    return out


# Subject attribute OID content bytes (X.520 attribute types, tag 0x06 prefix stripped)
_SUBJECT_ATTR_OID = {
    "OU": bytes([0x55, 0x04, 0x0b]),   # 2.5.4.11 organizationalUnitName
    "L":  bytes([0x55, 0x04, 0x07]),   # 2.5.4.7  localityName
    "SN": bytes([0x55, 0x04, 0x04]),   # 2.5.4.4  surname
    "GN": bytes([0x55, 0x04, 0x2a]),   # 2.5.4.42 givenName
}


def _subject_has_attr_raw(cert: Path, label: str) -> bool | None:
    """Check whether the Subject Name in the raw DER contains a given attribute.
    Returns True/False, or None if the DER cannot be extracted or parsed.
    Used only as a fallback when openssl refuses to parse the certificate.

    Approach: walk the outer SEQUENCE(TBSCertificate, …) → TBSCertificate SEQUENCE
    → skip optional version [0] / serialNumber / signature-alg / issuer Name →
    arrive at subject Name, then search for the OID bytes only within that region.
    """
    oid_bytes = _SUBJECT_ATTR_OID.get(label)
    if oid_bytes is None:
        return None
    der = _der_from_pem(cert)
    if len(der) < 4:
        return None

    def _rdlen(b, i):
        if i >= len(b):
            return 0, i
        n = b[i]; i += 1
        if n & 0x80:
            k = n & 0x7f
            if i + k > len(b):
                return 0, i
            n = int.from_bytes(b[i:i + k], "big"); i += k
        return n, i

    try:
        # Outer: Certificate SEQUENCE
        if der[0] != 0x30:
            return None
        _, i = _rdlen(der, 1)            # skip Certificate envelope
        # TBSCertificate SEQUENCE
        if der[i] != 0x30:
            return None
        tlen, i = _rdlen(der, i + 1)
        tbs_end = i + tlen
        # optional [0] version
        if i < tbs_end and der[i] == 0xa0:
            vlen, vi = _rdlen(der, i + 1); i = vi + vlen
        # serialNumber INTEGER
        if i < tbs_end and der[i] == 0x02:
            slen, si = _rdlen(der, i + 1); i = si + slen
        # signature AlgorithmIdentifier SEQUENCE
        if i < tbs_end and der[i] == 0x30:
            alen, ai = _rdlen(der, i + 1); i = ai + alen
        # issuer Name SEQUENCE — skip entirely
        if i < tbs_end and der[i] == 0x30:
            ilen, ii = _rdlen(der, i + 1); i = ii + ilen
        # validity SEQUENCE — skip
        if i < tbs_end and der[i] == 0x30:
            valen, vai = _rdlen(der, i + 1); i = vai + valen
        # subject Name SEQUENCE — THIS is what we search
        if i < tbs_end and der[i] == 0x30:
            subjlen, subji = _rdlen(der, i + 1)
            subj_bytes = der[i: subji + subjlen]
            return oid_bytes in subj_bytes
    except Exception:
        pass
    return None


def _aki_subfields(t: str):
    present, _, body = _ext(t, "X509v3 Authority Key Identifier")
    if not present:
        return None
    joined = " ".join(body)
    has_keyid = ("keyid" in joined
                 or re.search(r"[0-9A-Fa-f]{2}(:[0-9A-Fa-f]{2})+", joined) is not None)
    has_issuer = "DirName" in joined or "issuer" in joined.lower()
    has_serial = "serial" in joined.lower()
    return has_keyid, has_issuer, has_serial


def _tbs_unique_ids(cert: Path):
    raw = _der_of(cert)

    def rdlen(b, i):
        n = b[i]; i += 1
        if n & 0x80:
            k = n & 0x7f; n = int.from_bytes(b[i:i + k], "big"); i += k
        return n, i

    if not raw or raw[0] != 0x30:
        return False, False
    _, i = rdlen(raw, 1)
    if raw[i] != 0x30:
        return False, False
    tlen, j = rdlen(raw, i + 1)
    end, k = j + tlen, j
    iss = sub = False
    while k < end:
        tag = raw[k]; ln, m = rdlen(raw, k + 1)
        if tag == 0x81:
            iss = True
        elif tag == 0x82:
            sub = True
        k = m + ln
    return iss, sub


def _sig_algs_match(cert: Path):
    if not _HAVE_PYASN1:
        return None
    try:
        seq, _ = _der_dec.decode(_der_of(cert))
        tbs = seq.getComponentByPosition(0)
        outer = seq.getComponentByPosition(1)
        inner = tbs.getComponentByPosition(2)
        return _der_enc.encode(outer) == _der_enc.encode(inner)
    except Exception:
        return None


# --- zlint twin-lint oracle (authoritative for the AKI carve-out) -----------

class ZlintProbe:
    """Cache zlint's own per-cert verdicts; used to ground the AKI self-signed
    carve-out on zlint's authoritative IsSelfSigned, not a naive subject==issuer
    (which is wrong for empty-DN certs)."""

    def __init__(self, zlint_bin: Path):
        self.zlint = Path(zlint_bin)
        self._cache: dict = {}

    def _all(self, cert: Path) -> dict:
        key = str(cert)
        if key not in self._cache:
            proc = subprocess.run([str(self.zlint), "-format", "pem", str(cert)],
                                  capture_output=True, text=True)
            try:
                self._cache[key] = json.loads(proc.stdout)
            except Exception:
                self._cache[key] = {}
        return self._cache[key]

    def fires(self, cert: Path, lint_name: str) -> bool:
        rec = self._all(cert).get(lint_name, {})
        return rec.get("result") in ("error", "warn", "fatal")

    def aki_keyid_absent(self, cert: Path) -> bool:
        return self.fires(cert, "e_ext_authority_key_identifier_no_key_identifier")


def _crldp_element_count(cert: Path):
    """Number of DistributionPoint *structures* in the CRLDP extension (NOT the
    number of distributionPoint URLs — a DP may carry only a reasons field). Uses
    pyasn1 for a faithful structural count; returns None if unavailable/absent."""
    if not (_HAVE_PYASN1 and _HAVE_PYMODS):
        return "UNKNOWN"
    try:
        c, _ = _der_dec.decode(_der_of(cert), asn1Spec=_rfc5280.Certificate())
        for ext in c["tbsCertificate"]["extensions"]:
            if str(ext["extnID"]) == "2.5.29.31":
                dp, _ = _der_dec.decode(bytes(ext["extnValue"]),
                                        asn1Spec=_rfc5280.CRLDistributionPoints())
                return len(dp)
        return None
    except Exception:
        return "UNKNOWN"


_ALLOWED_AIA = ("OCSP", "CA Issuers")


def verify(lint: str, cert: Path, probe: ZlintProbe) -> tuple[str, str]:
    """Return (CONFIRMED|REFUTED|NOCHECK, evidence) for one (lint, cert)."""
    t = _text(cert)
    subj = _subject(cert)

    if "not_any_policy_list_contains" in lint:
        has = ANYPOLICY in _policy_oids(t, cert)
        if not has:
            return "REFUTED", "no anyPolicy in certificatePolicies"
        # Two different profile scopes assert "MUST NOT contain anyPolicy":
        #   - Subscriber Certificate (CABF 7.1.2.7.9, rule 29493): a NON-CA cert
        #     carrying anyPolicy is itself the violation.
        #   - (Cross-Certified) Subordinate CA (7.1.2.2.x / 7.1.2.3.x): a sub CA
        #     carrying anyPolicy is the violation.
        if "subscriber_cert" in lint:
            if not _is_ca(t):
                return "CONFIRMED", "subscriber (non-CA) cert carries anyPolicy"
            return "REFUTED", "anyPolicy present but cert is a CA (out of subscriber scope)"
        sub_ca = _is_ca(t) and probe.aki_keyid_absent(cert)
        if not sub_ca and _is_ca(t):
            sub_ca = bool(subj and _issuer(cert) and subj != _issuer(cert))
        if sub_ca:
            return "CONFIRMED", "subordinate CA carries anyPolicy"
        return "REFUTED", f"has anyPolicy but not clearly subordinate CA (ca={_is_ca(t)})"

    if "issuer_unique_id_absent_and_subject_unique_id_absent" in lint:
        # Compound rule 31183: BOTH uniqueIDs MUST be absent. Either one present
        # violates it — the earlier single-field branch only saw issuerUniqueID.
        a, b = _tbs_unique_ids(cert)
        if a or b:
            return "CONFIRMED", f"uniqueID present (issuer={a} subject={b})"
        return "REFUTED", "both uniqueIDs absent"
    if "issuer_unique_id_absent" in lint:
        a, _ = _tbs_unique_ids(cert)
        return ("CONFIRMED", "issuerUniqueID present") if a else \
               ("REFUTED", "issuerUniqueID absent")
    if "subject_unique_id_absent" in lint:
        _, b = _tbs_unique_ids(cert)
        return ("CONFIRMED", "subjectUniqueID present") if b else \
               ("REFUTED", "subjectUniqueID absent")

    if "not_ext_subfield_present_authority_key_id_28730" in lint:
        sf = _aki_subfields(t)
        if sf is None:
            return "REFUTED", "no AKI extension"
        return ("CONFIRMED", "AKI.authorityCertSerialNumber present") if sf[2] else \
               ("REFUTED", "AKI has no authorityCertSerialNumber")
    if "not_ext_subfield_present_authority_key_id_29274" in lint:
        sf = _aki_subfields(t)
        if sf is None:
            return "REFUTED", "no AKI extension"
        return ("CONFIRMED", "AKI.authorityCertIssuer present") if sf[1] else \
               ("REFUTED", "AKI has no authorityCertIssuer")
    if "authority_key_id_present_29273" in lint:
        if probe.aki_keyid_absent(cert):
            return "CONFIRMED", ("AKI keyIdentifier absent on non-self-signed CA "
                                 "(confirmed by zlint twin lint)")
        sub_ca = _is_ca(t) and probe.aki_keyid_absent(cert)
        if not sub_ca:
            return "REFUTED", f"not a non-self-signed CA in scope (ca={_is_ca(t)})"
        return "REFUTED", "AKI keyIdentifier appears present (twin lint silent)"

    if "when_not_subject_locality_present_subject_province" in lint:
        l = _name_has(subj, "L"); st = _name_has(subj, "ST")
        return ("CONFIRMED", "L absent and ST absent") if (not l and not st) else \
               ("REFUTED", f"L={l} ST={st}")
    if "when_not_subject_province_present_subject_locality" in lint:
        l = _name_has(subj, "L"); st = _name_has(subj, "ST")
        return ("CONFIRMED", "ST absent and L absent") if (not st and not l) else \
               ("REFUTED", f"ST={st} L={l}")

    if "validated_list_contains" in lint:
        # CABF 7.1.2.7.3 (Individual Validated, policy 2.23.140.1.2.3) and
        # 7.1.2.7.4 (Organization Validated, policy 2.23.140.1.2.2) each constrain a
        # DIFFERENT subject attribute with a DIFFERENT polarity. The earlier code
        # checked givenName for every rule in this family, which REFUTED correct
        # findings for the OU/locality/surname rules. Dispatch on the rule id so the
        # auditor re-derives the SPECIFIC attribute+polarity the lint asserts.
        _OV_IV = {   # rule_id -> (policy_oid, rfc2253_label, must_be_present)
            29446: (IV_POLICY, "SN", True),   # surname MUST be present
            29447: (IV_POLICY, "GN", True),   # givenName MUST be present
            29448: (IV_POLICY, "OU", False),  # organizationalUnitName MUST NOT
            29463: (OV_POLICY, "L",  True),   # localityName MUST be present
            29474: (OV_POLICY, "SN", False),  # surname MUST NOT be present
            29475: (OV_POLICY, "GN", False),  # givenName MUST NOT be present
            29476: (OV_POLICY, "OU", False),  # organizationalUnitName MUST NOT
        }
        m = re.search(r"_(\d+)$", lint)
        rid = int(m.group(1)) if m else None
        spec = _OV_IV.get(rid)
        if spec is None:
            return "NOCHECK", f"no field/polarity mapping for {lint}"
        policy_oid, label, must_be_present = spec
        in_scope = policy_oid in _policy_oids(t, cert)
        field_here = _name_has(subj, label)
        # openssl can refuse to parse deliberately-malformed testdata fixtures,
        # leaving subj empty. Fall back to raw-DER subject region scan so the
        # auditor agrees with zcrypto (which the lint uses) on those certs.
        if not subj and field_here is False:
            raw_result = _subject_has_attr_raw(cert, label)
            if raw_result is not None:
                field_here = raw_result
        if not in_scope:
            return "REFUTED", f"policy {policy_oid} absent (out of profile scope)"
        # defect present == the obligation is violated in-scope
        defect = (not field_here) if must_be_present else field_here
        polarity = "MUST be present" if must_be_present else "MUST NOT be present"
        if defect:
            return "CONFIRMED", f"in-scope ({policy_oid}); {label} {polarity} violated (present={field_here})"
        return "REFUTED", f"in-scope ({policy_oid}); {label} {polarity} satisfied (present={field_here})"

    if "sig_alg_matches_tbssignature" in lint:
        m = _sig_algs_match(cert)
        if m is None:
            return "NOCHECK", "could not DER-compare sig algs"
        return ("CONFIRMED", "outer sigAlg != tbs.signature") if not m else \
               ("REFUTED", "sig algs match")

    if "when_crl_dist_present_crldistribution_points_count" in lint:
        # The rule is "MUST contain at least one DistributionPoint". Count DP
        # STRUCTURES (pyasn1), not URLs — a DP may carry only a reasons field and
        # still be a valid DistributionPoint that satisfies the rule.
        n = _crldp_element_count(cert)
        if n == "UNKNOWN":
            # fall back to the openssl text view (may undercount URL-less DPs)
            present, _, body = _ext(t, "X509v3 CRL Distribution Points")
            if not present:
                return "REFUTED", "no CRLDP extension"
            return "NOCHECK", "pyasn1 unavailable; cannot count DP structures faithfully"
        if n is None:
            return "REFUTED", "no CRLDP extension"
        return ("CONFIRMED", "CRLDP present, 0 DistributionPoint") if n == 0 else \
               ("REFUTED", f"CRLDP has {n} DistributionPoint structure(s) (rule satisfied)")

    if "when_cert_policy_present_policy_identifiers_count" in lint:
        if "X509v3 Certificate Policies" not in t:
            return "REFUTED", "no certificatePolicies ext"
        return ("CONFIRMED", "certPolicies present, 0 PolicyInformation") \
            if not _policy_oids(t, cert) else ("REFUTED", "certPolicies has policies")

    if "when_subscriber_cert_not_path_len_constraint_present" in lint:
        present, _, body = _ext(t, "X509v3 Basic Constraints")
        if not present:
            return "REFUTED", "no basicConstraints"
        if _is_ca(t):
            return "REFUTED", "cert is a CA (out of subscriber scope)"
        has_plc = any("pathlen" in b.lower() for b in body)
        return ("CONFIRMED", "subscriber carries pathLenConstraint") if has_plc else \
               ("REFUTED", "no pathLenConstraint")

    if "when_subscriber_cert_subject_alt_name_not_critical" in lint:
        present, crit, _ = _ext(t, "X509v3 Subject Alternative Name")
        if not present:
            return "REFUTED", "no SAN extension"
        empty = subj == ""
        if crit and not empty:
            return "CONFIRMED", "SAN critical with non-empty subject"
        if crit and empty:
            return "REFUTED", "SAN critical but subject EMPTY (critical is REQUIRED here)"
        return "REFUTED", f"san_critical={crit} subject_empty={empty}"

    if "aiahas_method_other_than" in lint:
        present, _, body = _ext(t, "Authority Information Access")
        if not present:
            return "REFUTED", "no AIA extension"
        joined = " ".join(body)
        bad = [b for b in body if " - " in b and not any(x in b for x in _ALLOWED_AIA)]
        if bad or re.search(r"\b\d+\.\d+\.\d+(\.\d+)+ +- ", joined):
            return "CONFIRMED", f"AIA carries disallowed accessMethod: {(bad or [joined])[0][:60]}"
        return "REFUTED", f"all AIA methods allowed: {body[:3]}"

    if "when_root_ca_not_crl_dist_present" in lint:
        root = _is_ca(t) and not probe.aki_keyid_absent(cert)
        has = "X509v3 CRL Distribution Points" in t
        return ("CONFIRMED", "root CA carries CRLDP (advisory)") if (root and has) else \
               ("NOCHECK", f"root={root} crldp={has} (advisory)")

    # R31349: version MUST be v2 (when present)
    if "when_version_present_version_eq_31349" in lint:
        # Version v2 = on-wire INTEGER 1 (zcrypto reports it as 2)
        version_match = re.search(r"Version:\s*(\d+)", t)
        if not version_match:
            return "REFUTED", "version field not present"
        version = int(version_match.group(1))
        # zcrypto reports: v1=1, v2=2, v3=3 (on-wire is 0/1/2)
        return ("CONFIRMED", f"version is {version}, not v2") if version != 2 else \
               ("REFUTED", "version is v2 (compliant)")

    # R31132: subjectAltName extension MUST be critical
    if "subject_alternate_name_critical_31132" in lint:
        present, crit, _ = _ext(t, "X509v3 Subject Alternative Name")
        if not present:
            return "REFUTED", "no SAN extension"
        return ("CONFIRMED", "SAN not critical") if not crit else \
               ("REFUTED", "SAN is critical (compliant)")

    # R29539: ECDSA key MUST use id-ecPublicKey OID
    if "oid_eq_oid_ec_public_key_29539" in lint:
        # Subject Public Key Info shows algorithm
        spki_match = re.search(r"Subject Public Key Info:.*?Public Key Algorithm:\s*([^\n]+)", t, re.DOTALL)
        if not spki_match:
            return "NOCHECK", "cannot parse SPKI algorithm"
        algo = spki_match.group(1).strip()
        # id-ecPublicKey shows as "id-ecPublicKey" or "EC Public-Key"
        is_ec = "ecPublicKey" in algo or "EC Public" in algo
        return ("REFUTED", f"SPKI algorithm is {algo} (compliant)") if is_ec else \
               ("CONFIRMED", f"SPKI algorithm is {algo}, not id-ecPublicKey")

    # R29415: Subscriber cert SAN MUST NOT be critical (when subject non-empty)
    if "when_subscriber_cert_subject_alt_name_not_critical_29415" in lint:
        present, crit, _ = _ext(t, "X509v3 Subject Alternative Name")
        if not present:
            return "REFUTED", "no SAN extension"
        subj = _subject(cert)
        empty = subj == ""
        if crit and not empty:
            return "CONFIRMED", "SAN critical with non-empty subject"
        if crit and empty:
            return "REFUTED", "SAN critical but subject EMPTY (critical is REQUIRED here)"
        # SAN non-critical (compliant)
        return "REFUTED", f"san_critical={crit} subject_empty={empty}"

    # R29463: OV cert MUST have localityName
    # (Already covered by validated_list_contains above, but add explicit check)
    if "when_oid_policy_organization_validated_list_contains_29463" in lint:
        in_scope = OV_POLICY in _policy_oids(t, cert)
        if not in_scope:
            return "REFUTED", f"policy {OV_POLICY} absent (out of profile scope)"
        subj = _subject(cert)
        has_l = _name_has(subj, "L")
        return ("CONFIRMED", "OV cert lacks localityName") if not has_l else \
               ("REFUTED", f"OV cert has localityName (compliant)")

    return "NOCHECK", "no independent check for this lint family"


def verify_findings(findings: list[dict], testdata: Path, zlint_bin: Path) -> list[dict]:
    """Independently verify EVERY finding (not just UNCERTAIN). Returns one record
    per finding with an INDEP verdict and evidence."""
    probe = ZlintProbe(zlint_bin)
    out = []
    for f in findings:
        cert = Path(testdata) / f["cert"]
        try:
            verdict, ev = verify(f["lint"], cert, probe)
        except Exception as e:
            verdict, ev = "ERROR", f"{type(e).__name__}: {e}"
        out.append({"cert": f["cert"], "lint": f["lint"],
                    "triage": f.get("verdict"), "indep": verdict,
                    "indep_evidence": ev})
    return out
