#!/usr/bin/env python3
"""
Paper §8.5 — certificate detection as a SAIV gate.

Question: when the synonymous, shipped CICAS lints are run against real
certificates, are their findings genuine defects (including ones upstream zlint
misses), or false positives? A false positive is a SAIV signal: it reverse-blames
the pipeline stage that produced an over-broad lint.

Method (as described in §8.5):
  - The MECHANISM lives in the backend package
    app/services/certificate/codegen/detection (scan / testdata_oracle / triage /
    blame / verify_uncertain); this script ORCHESTRATES it — it does not
    re-implement triage or the oracle.
  - The corpus is zlint's own testdata (adversarial fixtures), scanned with the
    augmented zlint binary built by scripts/system_metrics/inject_and_build.py
    (the in-tree emitter ships only lints proven synonymous with the spec).
  - Triage uses two no-LLM oracles: upstream consensus (did an upstream zlint lint
    also flag the cert?) and testdata intent (is the cert a known-bad or a positive
    fixture?). Findings with neither signal and a narrow firing fraction are
    UNCERTAIN; verify_uncertain.py reverse-checks each with openssl.

This script does NOT rebuild the binary (build = a system step done by
inject_and_build). If the binary is missing it tells you to build it first.

Inputs (snapshot written to inputs/ by --snapshot):
  inputs/cicasgen_manifest.json   the synonymous lints shipped into the binary

Outputs (written to outputs/):
  outputs/detection_summary.json  REAL / SPURIOUS / UNCERTAIN + per-lint table
  outputs/detection_summary.md    the result rendered (paper §8.5)
  outputs/triage_by_lint.json     per-lint firing + verdict counts
  outputs/uncertain_verified.jsonl cert-grounded verdict for each UNCERTAIN finding
  outputs/blame.jsonl             SAIV feedback ledger for any suspect lint (empty = clean)

Run:
  python experiments/cert_detection/run.py            # scan + triage + verify
  python experiments/cert_detection/run.py --snapshot # also refresh inputs/

Expected (current paper snapshot, after the R29273 scope fix and the R29415 +
R29735 quarantines):
  31 synonymous lints shipped; 1128 testdata certs scanned -> 108 findings
  REAL 91 + SPURIOUS 0 + UNCERTAIN 17 ; all 17 UNCERTAIN -> CONFIRMED_REAL
  => 108/108 genuine detections, 0 false positives, blame ledger empty,
  and an INDEPENDENT per-finding structural audit CONFIRMS all 108 (0 refuted,
  0 NOCHECK). The audit is cross-validated by three parsers (openssl /
  cryptography / pyasn1) — see scripts/system_metrics/audit_cross_check.py,
  audit_pyasn1_check.py, audit_negative_control.py.
  Notable new-lint detections upstream zlint misses: 36 anyPolicy-in-Subordinate-CA
  (CABF 7.1.2.2.6) and OV-cert-carries-givenName (CABF 7.1.2.7.4).

  NOTE: earlier snapshots reported 33 lints / 112 findings ("112/112") and then
  32 / 109. The independent audit + cross-parser check REFUTED 3 findings across
  two lints: 29415 fired on compliant empty-subject certs (dropped precondition),
  and 29735 counted distributionPoint URLs instead of DistributionPoint structures
  (codegen bound to the wrong zcrypto field). Both are quarantined; the audit and
  the NOCHECK check are mandatory gates.
"""
import argparse
import json
import sys
from collections import Counter
from pathlib import Path

HERE = Path(__file__).resolve().parent
INPUTS = HERE / "inputs"
OUTPUTS = HERE / "outputs"
BACKEND = HERE.parent.parent              # cicas_backend/
if str(BACKEND) not in sys.path:
    sys.path.insert(0, str(BACKEND))

from app.services.certificate.codegen.detection import (   # noqa: E402
    scan, testdata_oracle, triage as triage_mod, verify_uncertain,
    blame as blame_mod, independent_verify)

ZLINT = BACKEND / "zlint" / "v3" / "zlint"
TESTDATA = BACKEND / "zlint" / "v3" / "testdata"
MANIFEST = BACKEND / "scripts" / "system_metrics" / "cicasgen_manifest.json"


def render_md(summary, by_lint, uncertain_counts, n_shipped, audit_counts=None):
    s = summary
    confirmed = uncertain_counts.get("CONFIRMED_REAL", 0)
    genuine = s["REAL"] + confirmed
    L = []
    L.append("# §8.5 — certificate detection as a SAIV gate\n")
    L.append(f"- synonymous lints shipped into the zlint binary: **{n_shipped}**")
    L.append(f"- testdata certificates scanned: **{s['total_certs']}**")
    L.append(f"- cicasgen_ findings: **{s['total']}**\n")
    L.append("| triage verdict | count |")
    L.append("|---|---:|")
    L.append(f"| REAL (upstream consensus / known-bad fixture) | {s['REAL']} |")
    L.append(f"| SPURIOUS (false positive) | **{s['SPURIOUS']}** |")
    L.append(f"| UNCERTAIN (no oracle signal, narrow firing) | {s['UNCERTAIN']} |\n")
    L.append("UNCERTAIN findings, after cert-grounded reverse-check:\n")
    L.append("| reverse-check verdict | count |")
    L.append("|---|---:|")
    for k, v in sorted(uncertain_counts.items()):
        L.append(f"| {k} | {v} |")
    L.append("")
    if audit_counts is not None:
        L.append("Independent per-finding structural audit (does NOT trust triage; "
                 "re-derives each finding's specific defect from openssl+DER):\n")
        L.append("| independent verdict | count |")
        L.append("|---|---:|")
        for k in ("CONFIRMED", "REFUTED", "NOCHECK", "ERROR"):
            if audit_counts.get(k):
                L.append(f"| {k} | {audit_counts[k]} |")
        L.append("")
    L.append(f"**Result: {genuine}/{s['total']} findings are genuine defects, "
             f"{s['SPURIOUS']} false positives "
             f"(independently confirmed: {(audit_counts or {}).get('CONFIRMED', 0)}/"
             f"{s['total']}).**\n")
    L.append("Per-lint detections (firing on the testdata corpus):\n")
    L.append("| lint | §/source | fires | applies | REAL | SPUR | UNC |")
    L.append("|---|---|---:|---:|---:|---:|---:|")
    for r in sorted(by_lint, key=lambda x: -x["fires"]):
        if r["fires"] == 0:
            continue
        L.append(f"| `{r['lint']}` | — | {r['fires']} | {r['applies']} | "
                 f"{r['REAL']} | {r['SPURIOUS']} | {r['UNCERTAIN']} |")
    return "\n".join(L) + "\n"


def main():
    ap = argparse.ArgumentParser(description="Paper §8.5 cert detection SAIV gate")
    ap.add_argument("--snapshot", action="store_true",
                    help="refresh inputs/ from the shipped-lint manifest")
    ap.add_argument("--limit", type=int, default=0, help="scan only N certs (smoke)")
    args = ap.parse_args()

    if not ZLINT.exists():
        sys.exit(f"[error] augmented zlint binary not found: {ZLINT}\n"
                 f"        build it first: python scripts/system_metrics/"
                 f"inject_and_build.py --emit --build")

    OUTPUTS.mkdir(exist_ok=True)
    if args.snapshot:
        INPUTS.mkdir(exist_ok=True)
        if MANIFEST.exists():
            (INPUTS / "cicasgen_manifest.json").write_text(MANIFEST.read_text())
            print(f"  wrote {INPUTS/'cicasgen_manifest.json'}")

    n_shipped = 0
    if MANIFEST.exists():
        n_shipped = json.loads(MANIFEST.read_text()).get("count", 0)

    print(f"[scan] {ZLINT.name} over {TESTDATA} ...")
    detections = scan.scan_corpus(ZLINT, TESTDATA, limit=args.limit)
    n_findings = sum(len(d["ours"]) for d in detections)
    print(f"[scan] {len(detections)} certs, {n_findings} cicasgen_ findings")

    intent = testdata_oracle.build_intent_map()
    intent.pop("_meta", None)
    t = triage_mod.triage(detections, intent)
    t["summary"]["total_certs"] = len(detections)

    uncertain = verify_uncertain.verify_findings(t["findings"], TESTDATA)
    uc = Counter(x["verdict"] for x in uncertain)

    # INDEPENDENT structural audit of EVERY finding (does NOT trust triage).
    # triage's REAL only proves the cert is defective for *some* lint; this
    # re-derives, per finding, whether OUR specific defect is actually present.
    audit = independent_verify.verify_findings(t["findings"], TESTDATA, ZLINT)
    ua = Counter(x["indep"] for x in audit)
    audit_conflicts = [a for a in audit
                       if a["triage"] in ("REAL", "UNCERTAIN")
                       and a["indep"] in ("REFUTED", "ERROR")]
    # NOCHECK on a shipped finding means the auditor could not INDEPENDENTLY verify
    # it — for the paper's "independently confirmed" claim that is not good enough,
    # so it is a hard failure too (the negative control showed the auditor has
    # blind spots for families it has no structural check for).
    audit_unverified = [a for a in audit if a["indep"] in ("NOCHECK", "ERROR")]

    ledger = blame_mod.blame(t["by_lint"], t["findings"])

    # outputs
    (OUTPUTS / "triage_by_lint.json").write_text(json.dumps(t["by_lint"], indent=2))
    (OUTPUTS / "uncertain_verified.jsonl").write_text(
        "".join(json.dumps(x) + "\n" for x in uncertain))
    (OUTPUTS / "audit_independent.jsonl").write_text(
        "".join(json.dumps(x) + "\n" for x in audit))
    (OUTPUTS / "blame.jsonl").write_text(
        "".join(json.dumps(x) + "\n" for x in ledger))
    summary = {**t["summary"], "n_shipped_lints": n_shipped,
               "uncertain_verified": dict(uc),
               "independent_audit": dict(ua),
               "independent_conflicts": len(audit_conflicts),
               "genuine": t["summary"]["REAL"] + uc.get("CONFIRMED_REAL", 0),
               "false_positives": t["summary"]["SPURIOUS"]}
    (OUTPUTS / "detection_summary.json").write_text(json.dumps(summary, indent=2))
    md = render_md(t["summary"], t["by_lint"], dict(uc), n_shipped, dict(ua))
    (OUTPUTS / "detection_summary.md").write_text(md)

    print(md)
    assert t["summary"]["SPURIOUS"] == 0, "FALSE POSITIVE present — SAIV gate not clean"
    assert uc.get("REMAINS_UNCERTAIN", 0) == 0, "some UNCERTAIN findings unresolved"
    assert not audit_conflicts, (
        f"independent audit refuted {len(audit_conflicts)} finding(s) triage called "
        f"genuine: {[(a['lint'], a['cert']) for a in audit_conflicts]}")
    assert not audit_unverified, (
        f"independent audit could not verify {len(audit_unverified)} shipped "
        f"finding(s) (NOCHECK/ERROR) — add a structural check before claiming them "
        f"independently confirmed: {[(a['lint'], a['cert']) for a in audit_unverified][:10]}")
    print(f"[ok] {summary['genuine']}/{t['summary']['total']} genuine, "
          f"0 false positives; independent audit CONFIRMED={ua.get('CONFIRMED',0)} "
          f"REFUTED={ua.get('REFUTED',0)} NOCHECK={ua.get('NOCHECK',0)}; "
          f"wrote outputs/ -> {OUTPUTS}")


if __name__ == "__main__":
    main()
