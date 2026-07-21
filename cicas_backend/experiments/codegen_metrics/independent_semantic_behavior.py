#!/usr/bin/env python3
"""Execute minimal semantic witnesses against every current generated lint.

This is intentionally separate from both the LLM synonymy judge and corpus
certificate detection.  It copies zlint into a temporary directory, injects
the complete generated manifest, and runs tiny package-local Go tests that
call selected emitted ``Execute`` methods directly.  The manifest is also
checked against the audited uncovered coverage domain, so stale generated
files cannot silently become the audit target.
"""
from __future__ import annotations

import json
import re
import shutil
import subprocess
import tempfile
from datetime import datetime, timezone
from pathlib import Path


HERE = Path(__file__).resolve().parent
BACKEND = HERE.parents[1]
RUN_DIR = HERE / "outputs" / "audited_coverage_domain"
ZLINT = BACKEND / "zlint" / "v3"
MANIFEST = RUN_DIR / "all_generated_lints_manifest.json"
OUTPUT = RUN_DIR / "independent_semantic_behavior.json"
COVERAGE_DECISIONS = BACKEND / "experiments" / "coverage_analysis" / "outputs" / "per_rule_coverage.jsonl"


CABF_TEST = r'''package cabf_br

import (
	"crypto/elliptic"
	"encoding/asn1"
	"strings"
	"testing"

	"github.com/zmap/zcrypto/x509"
	"github.com/zmap/zcrypto/x509/pkix"
	"github.com/zmap/zlint/v3/util"
)

func cicasAuditStatus(t *testing.T, caseID string, ruleID int, applies bool, result string) {
	t.Logf("CICAS_AUDIT_CASE|%s|%d|%t|%s", caseID, ruleID, applies, result)
}

func cicasAuditDER(tag byte, content []byte) []byte {
	if len(content) < 128 { return append([]byte{tag, byte(len(content))}, content...) }
	if len(content) <= 255 { return append([]byte{tag, 0x81, byte(len(content))}, content...) }
	return append([]byte{tag, 0x82, byte(len(content) >> 8), byte(len(content))}, content...)
}

func cicasAuditSequence(parts ...[]byte) []byte {
	var content []byte
	for _, part := range parts { content = append(content, part...) }
	return cicasAuditDER(0x30, content)
}

func cicasAuditCertificateWithExtension(ext pkix.Extension) *x509.Certificate {
	return &x509.Certificate{
		Extensions: []pkix.Extension{ext},
		ExtensionsMap: map[string]pkix.Extension{ext.Id.String(): ext},
	}
}

func cicasAuditSubjectAttribute(oid asn1.ObjectIdentifier, valueTag byte, value string) []byte {
	oidDER, err := asn1.Marshal(oid)
	if err != nil { panic(err) }
	valueDER := cicasAuditDER(valueTag, []byte(value))
	return cicasAuditDER(0x30, cicasAuditDER(0x31, cicasAuditSequence(oidDER, valueDER)))
}

func cicasAuditSPKI(alg []byte, key []byte) []byte {
	return cicasAuditSequence(alg, cicasAuditDER(0x03, append([]byte{0x00}, key...)))
}

func TestCicasIndependentSemanticWitnesses(t *testing.T) {
	rsaOID := []byte{0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01}
	pssOID := []byte{0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0a}
	ecOID := []byte{0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01}
	p256OID := []byte{0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07}
	rsaKey := []byte{0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x03}

	akiSerial := cicasAuditCertificateWithExtension(pkix.Extension{Id: util.AuthkeyOID, Value: cicasAuditSequence([]byte{0x82, 0x01, 0x01})})
	l28730 := &CicasGen28730{}
	cicasAuditStatus(t, "r28730_aki_serial_forbidden", 28730, l28730.CheckApplies(akiSerial), l28730.Execute(akiSerial).Status.String())

	akiIssuer := cicasAuditCertificateWithExtension(pkix.Extension{Id: util.AuthkeyOID, Value: cicasAuditSequence([]byte{0xa1, 0x00})})
	l29274 := &CicasGen29274{}
	cicasAuditStatus(t, "r29274_aki_issuer_forbidden", 29274, l29274.CheckApplies(akiIssuer), l29274.Execute(akiIssuer).Status.String())

	c29536 := &x509.Certificate{RawSubjectPublicKeyInfo: cicasAuditSPKI(cicasAuditSequence(rsaOID), rsaKey)}
	l29536 := &CicasGen29536{}
	cicasAuditStatus(t, "r29536_rsa_params_absent", 29536, l29536.CheckApplies(c29536), l29536.Execute(c29536).Status.String())

	c29537 := &x509.Certificate{RawSubjectPublicKeyInfo: cicasAuditSPKI(cicasAuditSequence(rsaOID, []byte{0x05, 0x01, 0x00}), rsaKey)}
	l29537 := &CicasGen29537{}
	cicasAuditStatus(t, "r29537_rsa_params_malformed_null", 29537, l29537.CheckApplies(c29537), l29537.Execute(c29537).Status.String())

	c29538 := &x509.Certificate{RawSubjectPublicKeyInfo: cicasAuditSPKI(cicasAuditSequence(pssOID), rsaKey)}
	l29538 := &CicasGen29538{}
	cicasAuditStatus(t, "r29538_rsa_pss_algorithm", 29538, l29538.CheckApplies(c29538), l29538.Execute(c29538).Status.String())

	p256 := elliptic.P256()
	p256Point := elliptic.Marshal(p256, p256.Params().Gx, p256.Params().Gy)
	c29540 := &x509.Certificate{PublicKeyAlgorithm: x509.ECDSA, RawSubjectPublicKeyInfo: cicasAuditSPKI(cicasAuditSequence(ecOID, []byte{0x05, 0x00}), p256Point)}
	l29540 := &CicasGen29540{}
	cicasAuditStatus(t, "r29540_ec_params_not_named_curve", 29540, l29540.CheckApplies(c29540), l29540.Execute(c29540).Status.String())

	p521 := elliptic.P521()
	p521Point := elliptic.Marshal(p521, p521.Params().Gx, p521.Params().Gy)
	p521WrongCurve := &x509.Certificate{RawSubjectPublicKeyInfo: cicasAuditSPKI(cicasAuditSequence(ecOID, p256OID), p521Point)}
	l29543 := &CicasGen29543{}
	l29546 := &CicasGen29546{}
	cicasAuditStatus(t, "r29543_p521_wrong_named_curve", 29543, l29543.CheckApplies(p521WrongCurve), l29543.Execute(p521WrongCurve).Status.String())
	cicasAuditStatus(t, "r29546_p521_wrong_algorithm_identifier", 29546, l29546.CheckApplies(p521WrongCurve), l29546.Execute(p521WrongCurve).Status.String())

	// A P-521-looking point alone is not an ECDSA SubjectPublicKeyInfo. The
	// curve-specific rows must not constrain a non-id-ecPublicKey algorithm.
	p521NonEC := &x509.Certificate{RawSubjectPublicKeyInfo: cicasAuditSPKI(cicasAuditSequence(rsaOID, []byte{0x05, 0x00}), p521Point)}
	cicasAuditStatus(t, "r29543_non_ec_point_out_of_scope", 29543, l29543.CheckApplies(p521NonEC), l29543.Execute(p521NonEC).Status.String())
	cicasAuditStatus(t, "r29546_non_ec_point_out_of_scope", 29546, l29546.CheckApplies(p521NonEC), l29546.Execute(p521NonEC).Status.String())

	c29562 := &x509.Certificate{RawSubject: cicasAuditSubjectAttribute(asn1.ObjectIdentifier{0, 9, 2342, 19200300, 100, 1, 25}, 0x16, strings.Repeat("a", 64))}
	l29562 := &CicasGen29562{}
	cicasAuditStatus(t, "r29562_domain_component_too_long", 29562, l29562.CheckApplies(c29562), l29562.Execute(c29562).Status.String())

	c29563 := &x509.Certificate{RawSubject: cicasAuditSubjectAttribute(asn1.ObjectIdentifier{2, 5, 4, 6}, 0x13, "USA")}
	l29563 := &CicasGen29563{}
	cicasAuditStatus(t, "r29563_country_too_long", 29563, l29563.CheckApplies(c29563), l29563.Execute(c29563).Status.String())

	c29564 := &x509.Certificate{RawSubject: cicasAuditSubjectAttribute(asn1.ObjectIdentifier{2, 5, 4, 8}, 0x0c, strings.Repeat("x", 129))}
	l29564 := &CicasGen29564{}
	cicasAuditStatus(t, "r29564_state_too_long", 29564, l29564.CheckApplies(c29564), l29564.Execute(c29564).Status.String())
}
'''


RFC_TEST = r'''package rfc

import (
	"encoding/asn1"
	"math/big"
	"net"
	"testing"

	zcryptoasn1 "github.com/zmap/zcrypto/encoding/asn1"
	"github.com/zmap/zcrypto/x509"
	"github.com/zmap/zcrypto/x509/pkix"
	"github.com/zmap/zlint/v3/util"
)

func cicasAuditStatus(t *testing.T, caseID string, ruleID int, applies bool, result string) {
	t.Logf("CICAS_AUDIT_CASE|%s|%d|%t|%s", caseID, ruleID, applies, result)
}

func cicasAuditDER(tag byte, content []byte) []byte {
	if len(content) < 128 { return append([]byte{tag, byte(len(content))}, content...) }
	if len(content) <= 255 { return append([]byte{tag, 0x81, byte(len(content))}, content...) }
	return append([]byte{tag, 0x82, byte(len(content) >> 8), byte(len(content))}, content...)
}

func cicasAuditSequence(parts ...[]byte) []byte {
	var content []byte
	for _, part := range parts { content = append(content, part...) }
	return cicasAuditDER(0x30, content)
}

func cicasAuditCertificateWithExtension(ext pkix.Extension) *x509.Certificate {
	return &x509.Certificate{
		Extensions: []pkix.Extension{ext},
		ExtensionsMap: map[string]pkix.Extension{ext.Id.String(): ext},
	}
}

func cicasAuditPolicyExtension(valueTag byte, value []byte) pkix.Extension {
	userNoticeOID, err := asn1.Marshal(asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 2, 2})
	if err != nil { panic(err) }
	policyOID, err := asn1.Marshal(asn1.ObjectIdentifier{2, 5, 29, 32, 0})
	if err != nil { panic(err) }
	notice := cicasAuditSequence(cicasAuditDER(valueTag, value))
	qualifier := cicasAuditSequence(userNoticeOID, notice)
	policy := cicasAuditSequence(policyOID, cicasAuditSequence(qualifier))
	return pkix.Extension{Id: util.CertPolicyOID, Value: cicasAuditSequence(policy)}
}

func cicasAuditTBSWithValidity(notBefore []byte, notAfter []byte) []byte {
	return cicasAuditSequence(
		[]byte{0x02, 0x01, 0x01},
		[]byte{0x30, 0x00},
		[]byte{0x30, 0x00},
		cicasAuditSequence(notBefore, notAfter),
	)
}

func TestCicasIndependentSemanticWitnesses(t *testing.T) {
	ia5Policy := cicasAuditCertificateWithExtension(cicasAuditPolicyExtension(0x16, []byte("notice")))
	l30982 := &CicasGen30982{}
	cicasAuditStatus(t, "r30982_explicit_text_ia5", 30982, l30982.CheckApplies(ia5Policy), l30982.Execute(ia5Policy).Status.String())

	bmpPolicy := cicasAuditCertificateWithExtension(cicasAuditPolicyExtension(0x1e, []byte{0x00, 0x61}))
	l30984 := &CicasGen30984{}
	cicasAuditStatus(t, "r30984_explicit_text_bmp", 30984, l30984.CheckApplies(bmpPolicy), l30984.Execute(bmpPolicy).Status.String())

	ncExt := pkix.Extension{Id: util.NameConstOID}
	ipv4BadMask := net.IPMask{0xff, 0x00, 0xff, 0x00}
	c31046 := &x509.Certificate{
		Extensions: []pkix.Extension{ncExt}, ExtensionsMap: map[string]pkix.Extension{ncExt.Id.String(): ncExt},
		PermittedIPAddresses: []x509.GeneralSubtreeIP{{Data: net.IPNet{IP: net.IP{192, 0, 2, 0}, Mask: ipv4BadMask}}},
	}
	l31046 := &CicasGen31046{}
	cicasAuditStatus(t, "r31046_ipv4_non_cidr", 31046, l31046.CheckApplies(c31046), l31046.Execute(c31046).Status.String())

	ipv6BadMask := net.IPMask{0xff, 0x00, 0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
	c31047 := &x509.Certificate{
		Extensions: []pkix.Extension{ncExt}, ExtensionsMap: map[string]pkix.Extension{ncExt.Id.String(): ncExt},
		PermittedIPAddresses: []x509.GeneralSubtreeIP{{Data: net.IPNet{IP: net.ParseIP("2001:db8::1").To16(), Mask: ipv6BadMask}}},
	}
	l31047 := &CicasGen31047{}
	cicasAuditStatus(t, "r31047_ipv6_non_cidr", 31047, l31047.CheckApplies(c31047), l31047.Execute(c31047).Status.String())

	policyConstraints := cicasAuditCertificateWithExtension(pkix.Extension{Id: util.PolicyConstOID, Value: []byte{0x30, 0x00}})
	l31056 := &CicasGen31056{}
	cicasAuditStatus(t, "r31056_policy_constraints_empty", 31056, l31056.CheckApplies(policyConstraints), l31056.Execute(policyConstraints).Status.String())

	sanExt := pkix.Extension{Id: util.SubjectAlternateNameOID, Critical: true}
	c31067 := &x509.Certificate{
		Subject: pkix.Name{Names: []pkix.AttributeTypeAndValue{{Type: zcryptoasn1.ObjectIdentifier{2, 5, 4, 3}, Value: "example"}}},
		Extensions: []pkix.Extension{sanExt}, ExtensionsMap: map[string]pkix.Extension{sanExt.Id.String(): sanExt},
	}
	l31067 := &CicasGen31067{}
	cicasAuditStatus(t, "r31067_nonempty_subject_critical_san", 31067, l31067.CheckApplies(c31067), l31067.Execute(c31067).Status.String())

	c31069 := &x509.Certificate{IPAddresses: []net.IP{net.ParseIP("::ffff:192.0.2.1")}}
	l31069 := &CicasGen31069{}
	cicasAuditStatus(t, "r31069_ipv4_mapped_ipv6_out_of_scope", 31069, l31069.CheckApplies(c31069), l31069.Execute(c31069).Status.String())

	c31070 := &x509.Certificate{IPAddresses: []net.IP{{1, 2, 3, 4, 5, 6, 7, 8}}}
	l31070 := &CicasGen31070{}
	cicasAuditStatus(t, "r31070_bad_ipv6_width", 31070, l31070.CheckApplies(c31070), l31070.Execute(c31070).Status.String())

	c31123 := &x509.Certificate{SerialNumber: big.NewInt(-1)}
	l31123 := &CicasGen31123{}
	cicasAuditStatus(t, "r31123_negative_serial", 31123, l31123.CheckApplies(c31123), l31123.Execute(c31123).Status.String())

	nonCriticalSAN := pkix.Extension{Id: util.SubjectAlternateNameOID, Critical: false}
	c31132 := cicasAuditCertificateWithExtension(nonCriticalSAN)
	l31132 := &CicasGen31132{}
	cicasAuditStatus(t, "r31132_empty_subject_noncritical_san", 31132, l31132.CheckApplies(c31132), l31132.Execute(c31132).Status.String())

	// A present but zero-bit issuerUniqueID means the certificate is not in the
	// "only basic fields" branch. Version 2 is therefore outside this rule.
	c31153 := &x509.Certificate{RawTBSCertificate: cicasAuditSequence([]byte{0x81, 0x01, 0x00}), Version: 2}
	l31153 := &CicasGen31153{}
	cicasAuditStatus(t, "r31153_empty_unique_id_not_basic_fields", 31153, l31153.CheckApplies(c31153), l31153.Execute(c31153).Status.String())

	akiIssuer := cicasAuditCertificateWithExtension(pkix.Extension{Id: util.AuthkeyOID, Value: cicasAuditSequence([]byte{0xa1, 0x00})})
	l31160 := &CicasGen31160{}
	cicasAuditStatus(t, "r31160_only_one_aki_pair_member", 31160, l31160.CheckApplies(akiIssuer), l31160.Execute(akiIssuer).Status.String())

	c31161 := &x509.Certificate{SerialNumber: big.NewInt(-1)}
	l31161 := &CicasGen31161{}
	cicasAuditStatus(t, "r31161_negative_serial", 31161, l31161.CheckApplies(c31161), l31161.Execute(c31161).Status.String())

	tbsWithExtensions := cicasAuditSequence([]byte{0xa3, 0x00})
	c31172 := &x509.Certificate{RawTBSCertificate: tbsWithExtensions, Version: 2}
	l31172 := &CicasGen31172{}
	cicasAuditStatus(t, "r31172_extensions_version_v2", 31172, l31172.CheckApplies(c31172), l31172.Execute(c31172).Status.String())

	utcOffset := cicasAuditDER(0x17, []byte("240101000000+0000"))
	c31175 := &x509.Certificate{RawTBSCertificate: cicasAuditTBSWithValidity(utcOffset, utcOffset)}
	l31175 := &CicasGen31175{}
	cicasAuditStatus(t, "r31175_utc_offset_not_zulu", 31175, l31175.CheckApplies(c31175), l31175.Execute(c31175).Status.String())

	c31344 := &x509.Certificate{RawTBSCertificate: tbsWithExtensions, Version: 2}
	l31344 := &CicasGen31344{}
	cicasAuditStatus(t, "r31344_extensions_version_v2", 31344, l31344.CheckApplies(c31344), l31344.Execute(c31344).Status.String())

	c31368 := &x509.Certificate{RawTBSCertificate: cicasAuditSequence([]byte{0x02, 0x01, 0x80})}
	l31368 := &CicasGen31368{}
	cicasAuditStatus(t, "r31368_serial_sign_bit_set", 31368, l31368.CheckApplies(c31368), l31368.Execute(c31368).Status.String())

	rsaAlg := cicasAuditSequence([]byte{0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01})
	pssAlg := cicasAuditSequence([]byte{0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0a})
	tbsForSignature := cicasAuditSequence([]byte{0x02, 0x01, 0x01}, rsaAlg)
	c31396 := &x509.Certificate{Raw: cicasAuditSequence(tbsForSignature, pssAlg, cicasAuditDER(0x03, []byte{0x00}))}
	l31396 := &CicasGen31396{}
	cicasAuditStatus(t, "r31396_mismatched_signature_algorithm", 31396, l31396.CheckApplies(c31396), l31396.Execute(c31396).Status.String())

	c31403 := &x509.Certificate{RawTBSCertificate: tbsWithExtensions, Version: 2}
	l31403 := &CicasGen31403{}
	cicasAuditStatus(t, "r31403_extensions_version_v2", 31403, l31403.CheckApplies(c31403), l31403.Execute(c31403).Status.String())
}
'''


NORMATIVE_EXPECTED = {
    "r28730_aki_serial_forbidden": {"rule_id": 28730, "check_applies": True, "actual": "error"},
    "r29274_aki_issuer_forbidden": {"rule_id": 29274, "check_applies": True, "actual": "error"},
    "r29536_rsa_params_absent": {"rule_id": 29536, "check_applies": True, "actual": "error"},
    "r29537_rsa_params_malformed_null": {"rule_id": 29537, "check_applies": True, "actual": "error"},
    "r29538_rsa_pss_algorithm": {"rule_id": 29538, "check_applies": True, "actual": "error"},
    "r29540_ec_params_not_named_curve": {"rule_id": 29540, "check_applies": True, "actual": "error"},
    "r29543_p521_wrong_named_curve": {"rule_id": 29543, "check_applies": True, "actual": "error"},
    "r29546_p521_wrong_algorithm_identifier": {"rule_id": 29546, "check_applies": True, "actual": "error"},
    "r29543_non_ec_point_out_of_scope": {"rule_id": 29543, "check_applies": True, "actual": "pass"},
    "r29546_non_ec_point_out_of_scope": {"rule_id": 29546, "check_applies": True, "actual": "pass"},
    "r29562_domain_component_too_long": {"rule_id": 29562, "check_applies": True, "actual": "error"},
    "r29563_country_too_long": {"rule_id": 29563, "check_applies": True, "actual": "error"},
    "r29564_state_too_long": {"rule_id": 29564, "check_applies": True, "actual": "error"},
    "r30982_explicit_text_ia5": {"rule_id": 30982, "check_applies": True, "actual": "warn"},
    "r30984_explicit_text_bmp": {"rule_id": 30984, "check_applies": True, "actual": "error"},
    "r31046_ipv4_non_cidr": {"rule_id": 31046, "check_applies": True, "actual": "error"},
    "r31047_ipv6_non_cidr": {"rule_id": 31047, "check_applies": True, "actual": "error"},
    "r31056_policy_constraints_empty": {"rule_id": 31056, "check_applies": True, "actual": "error"},
    "r31067_nonempty_subject_critical_san": {"rule_id": 31067, "check_applies": True, "actual": "warn"},
    "r31069_ipv4_mapped_ipv6_out_of_scope": {"rule_id": 31069, "check_applies": True, "actual": "pass"},
    "r31070_bad_ipv6_width": {"rule_id": 31070, "check_applies": True, "actual": "error"},
    "r31123_negative_serial": {"rule_id": 31123, "check_applies": True, "actual": "error"},
    "r31132_empty_subject_noncritical_san": {"rule_id": 31132, "check_applies": True, "actual": "error"},
    "r31153_empty_unique_id_not_basic_fields": {"rule_id": 31153, "check_applies": False, "actual": "pass"},
    "r31160_only_one_aki_pair_member": {"rule_id": 31160, "check_applies": True, "actual": "error"},
    "r31161_negative_serial": {"rule_id": 31161, "check_applies": True, "actual": "error"},
    "r31172_extensions_version_v2": {"rule_id": 31172, "check_applies": True, "actual": "error"},
    "r31175_utc_offset_not_zulu": {"rule_id": 31175, "check_applies": True, "actual": "error"},
    "r31344_extensions_version_v2": {"rule_id": 31344, "check_applies": True, "actual": "error"},
    "r31368_serial_sign_bit_set": {"rule_id": 31368, "check_applies": True, "actual": "error"},
    "r31396_mismatched_signature_algorithm": {"rule_id": 31396, "check_applies": True, "actual": "error"},
    "r31403_extensions_version_v2": {"rule_id": 31403, "check_applies": True, "actual": "error"},
}


def _inject_manifest(copied: Path, manifest: list[dict]) -> None:
    for stale in (copied / "lints").rglob("lint_cicasgen_*.go"):
        stale.unlink()
    for row in manifest:
        source_path = Path(row["output_path"])
        if not source_path.is_file():
            raise RuntimeError(f"missing manifest lint source: {source_path}")
        package = "rfc" if row["source"] == "RFC5280" else "cabf_br"
        shutil.copyfile(source_path, copied / "lints" / package / row["filename"])


def _parse_cases(output: str) -> dict[str, dict[str, object]]:
    cases: dict[str, dict[str, object]] = {}
    for case_id, rule_id, applies, status in re.findall(
        r"CICAS_AUDIT_CASE\|([A-Za-z0-9_]+)\|(\d+)\|(true|false)\|([^\s]+)", output
    ):
        cases[case_id] = {
            "rule_id": int(rule_id),
            "check_applies": applies == "true",
            "actual": status,
        }
    return cases


def _smoke_test(package: str, names: list[str]) -> str:
    go_names = ", ".join(json.dumps(name) for name in sorted(names))
    return f'''package {package}

import (
	"testing"

	"github.com/zmap/zcrypto/x509"
	"github.com/zmap/zlint/v3/lint"
)

func TestCicasManifestSmoke(t *testing.T) {{
	cert := &x509.Certificate{{}}
	for _, name := range []string{{{go_names}}} {{
		registered := lint.GlobalRegistry().CertificateLints().ByName(name)
		if registered == nil {{ t.Fatalf("missing manifest lint %s", name) }}
		implementation := registered.Lint()
		applies := implementation.CheckApplies(cert)
		result := implementation.Execute(cert)
		if result == nil {{ t.Fatalf("nil result from %s", name) }}
		t.Logf("CICAS_MANIFEST_SMOKE|%s|%t|%s", name, applies, result.Status.String())
	}}
}}
'''


def _parse_smoke_cases(output: str) -> set[str]:
    return set(re.findall(r"CICAS_MANIFEST_SMOKE\|([^|\s]+)\|", output))


def _audited_uncovered_ids() -> set[int]:
    return {
        int(row["id"])
        for line in COVERAGE_DECISIONS.read_text(encoding="utf-8").splitlines()
        if line.strip()
        for row in [json.loads(line)]
        if row.get("audited_lintable") and row.get("audited_coverage") != "full"
    }


def main() -> int:
    manifest = json.loads(MANIFEST.read_text(encoding="utf-8"))
    manifest_ids = {int(row["rule_id"]) for row in manifest}
    domain_ids = _audited_uncovered_ids()
    manifest_matches_audited_domain = manifest_ids == domain_ids
    witness_rule_ids = {expected["rule_id"] for expected in NORMATIVE_EXPECTED.values()}
    witnesses_cover_manifest = witness_rule_ids == manifest_ids
    manifest_names_by_package = {"cabf_br": [], "rfc": []}
    for row in manifest:
        package = "rfc" if row["source"] == "RFC5280" else "cabf_br"
        manifest_names_by_package[package].append(str(row["lint_name"]))
    with tempfile.TemporaryDirectory(prefix="cicas_independent_behavior_") as temp:
        copied = Path(temp) / "zlint-v3"
        shutil.copytree(ZLINT, copied)
        _inject_manifest(copied, manifest)
        (copied / "lints" / "cabf_br" / "cicas_independent_semantic_audit_test.go").write_text(
            CABF_TEST, encoding="utf-8"
        )
        (copied / "lints" / "rfc" / "cicas_independent_semantic_audit_test.go").write_text(
            RFC_TEST, encoding="utf-8"
        )
        for package, names in manifest_names_by_package.items():
            (copied / "lints" / package / "cicas_independent_manifest_smoke_test.go").write_text(
                _smoke_test(package, names), encoding="utf-8"
            )
        proc = subprocess.run(
            [
                "go", "test", "-v", "-run",
                r"TestCicas(IndependentSemanticWitnesses|ManifestSmoke)$",
                "./lints/cabf_br", "./lints/rfc",
            ],
            cwd=copied,
            text=True,
            capture_output=True,
            timeout=600,
        )

    combined = proc.stdout + "\n" + proc.stderr
    observed = _parse_cases(combined)
    smoke_names = _parse_smoke_cases(combined)
    manifest_names = {name for names in manifest_names_by_package.values() for name in names}
    result = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "method": "isolated zlint execution of independently authored minimal witnesses",
        "manifest": str(MANIFEST),
        "command": [
            "go", "test", "-v", "-run",
            r"TestCicas(IndependentSemanticWitnesses|ManifestSmoke)$",
            "./lints/cabf_br", "./lints/rfc",
        ],
        "returncode": proc.returncode,
        "manifest_rule_count": len(manifest_ids),
        "audited_uncovered_rule_count": len(domain_ids),
        "manifest_matches_audited_domain": manifest_matches_audited_domain,
        "only_manifest": sorted(manifest_ids - domain_ids),
        "only_audited_domain": sorted(domain_ids - manifest_ids),
        "semantic_witness_coverage": {
            "witnessed_rules": len(witness_rule_ids),
            "manifest_rule_count": len(manifest_ids),
            "covers_manifest_exactly": witnesses_cover_manifest,
            "missing_witness": sorted(manifest_ids - witness_rule_ids),
            "witness_without_manifest_rule": sorted(witness_rule_ids - manifest_ids),
        },
        "manifest_smoke": {
            "executed": len(smoke_names),
            "expected": len(manifest_names),
            "all_manifest_lints_executed": smoke_names == manifest_names,
            "missing": sorted(manifest_names - smoke_names),
            "unexpected": sorted(smoke_names - manifest_names),
        },
        "observed": {
            case_id: {
                "rule_id": expected["rule_id"],
                "actual": (observed.get(case_id) or {}).get("actual"),
                "check_applies": (observed.get(case_id) or {}).get("check_applies"),
                "normative_expected": expected,
                "matches_source_semantics": (
                    (observed.get(case_id) or {}).get("rule_id") == expected["rule_id"]
                    and (observed.get(case_id) or {}).get("actual") == expected["actual"]
                    and (observed.get(case_id) or {}).get("check_applies") == expected["check_applies"]
                ),
            }
            for case_id, expected in NORMATIVE_EXPECTED.items()
        },
        "stdout": proc.stdout[-10000:],
        "stderr": proc.stderr[-4000:],
    }
    result["all_cases_reported"] = set(observed) == set(NORMATIVE_EXPECTED)
    result["test_ran"] = proc.returncode == 0 and result["all_cases_reported"]
    result["all_cases_match_source"] = all(
        case["matches_source_semantics"] for case in result["observed"].values()
    )
    result["independent_semantic_pass"] = (
        result["test_ran"]
        and result["manifest_matches_audited_domain"]
        and result["semantic_witness_coverage"]["covers_manifest_exactly"]
        and result["manifest_smoke"]["all_manifest_lints_executed"]
        and result["all_cases_match_source"]
    )
    OUTPUT.write_text(json.dumps(result, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({
        "test_ran": result["test_ran"],
        "manifest_matches_audited_domain": result["manifest_matches_audited_domain"],
        "semantic_witness_coverage": result["semantic_witness_coverage"],
        "manifest_smoke": result["manifest_smoke"],
        "all_cases_match_source": result["all_cases_match_source"],
        "independent_semantic_pass": result["independent_semantic_pass"],
        "observed": result["observed"],
        "output": str(OUTPUT),
    }, ensure_ascii=False, indent=2))
    return 0 if result["independent_semantic_pass"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
