"""codegen/detection/verify_uncertain.py — cert-grounded reverse-check of the
UNCERTAIN findings from triage.

triage labels a finding UNCERTAIN when the cert is unnamed, no upstream zlint lint
complains, AND the firing fraction is below the over-strictness threshold — i.e.
EITHER a genuine new lint catching what upstream misses OR a false positive. This
module disambiguates each UNCERTAIN finding by re-reading the certificate with
openssl and checking whether the structural condition the lint asserts is actually
present. It is a pure-ish helper (openssl shell-out) with no LLM and no DB.

A finding is CONFIRMED_REAL when the cert genuinely exhibits the defect the lint
targets, and REMAINS_UNCERTAIN otherwise (a human must then look). It NEVER
upgrades a finding to SPURIOUS — that verdict is reserved for triage's
positive-fixture / over-strict signals.

Currently encodes the reverse-check for the two lint families that produce
UNCERTAIN findings on the zlint testdata corpus:
  cicasgen_not_any_policy_list_contains_*  CABF 7.1.2.2.6: a Subordinate CA
      certificate MUST NOT assert anyPolicy (2.5.29.32.0). CONFIRMED_REAL when the
      cert is a non-self-signed CA carrying anyPolicy.
  cicasgen_when_oid_policy_organization_validated_list_contains_* (givenName)
      CABF 7.1.2.7.4: an Organization Validated cert MUST NOT carry givenName.
      CONFIRMED_REAL when the cert carries the OV policy OID and a givenName.
"""
from __future__ import annotations

import subprocess
from pathlib import Path

ANYPOLICY_OID = "2.5.29.32.0"
OV_POLICY_OID = "2.23.140.1.2.2"


def _x509_text(cert: Path) -> str:
    return subprocess.run(["openssl", "x509", "-in", str(cert), "-noout", "-text"],
                          capture_output=True, text=True).stdout


def _subject_issuer(cert: Path) -> tuple[str, str]:
    def field(flag):
        out = subprocess.run(["openssl", "x509", "-in", str(cert), "-noout", flag,
                              "-nameopt", "RFC2253"], capture_output=True, text=True).stdout
        return out.split("=", 1)[-1].strip()
    return field("-subject"), field("-issuer")


def reverse_check(lint: str, cert: Path) -> dict:
    """Return {verdict, evidence} for one UNCERTAIN (lint, cert) pair."""
    if not cert.exists():
        return {"verdict": "REMAINS_UNCERTAIN", "evidence": f"cert not found: {cert.name}"}
    text = _x509_text(cert)
    subj, iss = _subject_issuer(cert)
    self_signed = bool(subj and subj == iss)
    is_ca = "CA:TRUE" in text

    if "not_any_policy_list_contains" in lint:
        has_any = ("anyPolicy" in text or "Any Policy" in text or ANYPOLICY_OID in text)
        if is_ca and not self_signed and has_any:
            return {"verdict": "CONFIRMED_REAL",
                    "evidence": "non-self-signed CA carries anyPolicy "
                                "(CABF 7.1.2.2.6 prohibits it for Subordinate CAs)"}
        return {"verdict": "REMAINS_UNCERTAIN",
                "evidence": f"is_ca={is_ca} self_signed={self_signed} anyPolicy={has_any}"}

    if "organization_validated" in lint:
        ov = OV_POLICY_OID in text
        # givenName == OID 2.5.4.42; openssl renders it GN= in RFC2253 subjects
        has_gn = ("GN=" in subj) or ("givenName" in subj)
        if ov and has_gn:
            return {"verdict": "CONFIRMED_REAL",
                    "evidence": "OV cert (policy 2.23.140.1.2.2) carries givenName "
                                "(CABF 7.1.2.7.4 prohibits it)"}
        return {"verdict": "REMAINS_UNCERTAIN",
                "evidence": f"ov_oid={ov} givenName={has_gn}"}

    return {"verdict": "REMAINS_UNCERTAIN", "evidence": "no reverse-check for this lint family"}


def verify_findings(findings: list[dict], testdata: Path) -> list[dict]:
    """Reverse-check every UNCERTAIN finding; return one record per finding."""
    out = []
    for f in findings:
        if f.get("verdict") != "UNCERTAIN":
            continue
        r = reverse_check(f["lint"], Path(testdata) / f["cert"])
        out.append({"cert": f["cert"], "lint": f["lint"], **r})
    return out
