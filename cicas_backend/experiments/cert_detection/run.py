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
  Notable detections: OV-cert-carries-givenName (CABF 7.1.2.7.4) — stronger
  signal. 36 anyPolicy-in-Subordinate-CA firings are false positives from an
  overly broad lint (not genuine CABF violations).

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
EXTERNAL_OUTPUTS = HERE.parent / "new_lint_corpus_scan" / "outputs"
BACKEND = HERE.parent.parent              # cicas_backend/
if str(BACKEND) not in sys.path:
    sys.path.insert(0, str(BACKEND))

from app.services.certificate.codegen.detection import (   # noqa: E402
    scan, testdata_oracle, triage as triage_mod, verify_uncertain,
    blame as blame_mod, independent_verify)
from app.services.certificate.codegen import results_attribution as attribution  # noqa: E402

ZLINT = BACKEND / "zlint" / "v3" / "zlint"
TESTDATA = BACKEND / "zlint" / "v3" / "testdata"
MANIFEST = INPUTS / "cicasgen_manifest.json"  # snapshot written by --snapshot


def _safe_name(path: Path) -> str:
    return "".join(c if c.isalnum() or c in "._-" else "_" for c in path.name) or "corpus"


def _default_external_output_name(certs_dir: Path) -> str:
    if certs_dir.name == "certs" and certs_dir.parent.name:
        return _safe_name(certs_dir.parent)
    return _safe_name(certs_dir)


def _manifest_by_lint() -> dict:
    return attribution.load_manifest(MANIFEST)


def _jsonl(rows) -> str:
    return "".join(json.dumps(r, ensure_ascii=False) + "\n" for r in rows)


def _truncate(text, n=96):
    text = (text or "").replace("\n", " ").strip()
    return text if len(text) <= n else text[: n - 1] + "..."


def _generated_finding_seed(detections: list[dict]) -> list[dict]:
    findings = []
    for d in detections:
        for lint, result in d["ours"].items():
            findings.append({
                "cert": d["cert"],
                "lint": lint,
                "result": result,
                "verdict": "EXTERNAL_REPORT",
            })
    return findings


def _annotate_new_lint_findings(detections: list[dict], manifest: dict,
                                audit: list[dict] | None = None) -> list[dict]:
    audit_by_key = {(a.get("cert"), a.get("lint")): a for a in (audit or [])}
    rows = []
    for d in detections:
        upstream_lints = sorted(d["upstream"].keys())
        for lint, result in sorted(d["ours"].items()):
            meta = manifest.get(lint, {})
            a = audit_by_key.get((d["cert"], lint), {})
            rows.append({
                "cert": d["cert"],
                "source": "cicasgen_new_lint",
                "lint": lint,
                "result": result,
                "rule_id": meta.get("rule_id"),
                "standard": meta.get("source"),
                "section": meta.get("section"),
                "rule_text": meta.get("rule_text"),
                "upstream_also_flagged": bool(upstream_lints),
                "upstream_lints": upstream_lints,
                "independent_verdict": a.get("indep"),
                "independent_evidence": a.get("indep_evidence"),
            })
    return rows


def _upstream_findings(detections: list[dict]) -> list[dict]:
    rows = []
    for d in detections:
        for lint, result in sorted(d["upstream"].items()):
            rows.append({
                "cert": d["cert"],
                "source": "upstream_zlint",
                "lint": lint,
                "result": result,
            })
    return rows


def _new_lint_rollup(new_rows: list[dict]) -> list[dict]:
    grouped: dict[str, dict] = {}
    for r in new_rows:
        g = grouped.setdefault(r["lint"], {
            "lint": r["lint"],
            "rule_id": r.get("rule_id"),
            "standard": r.get("standard"),
            "section": r.get("section"),
            "rule_text": r.get("rule_text"),
            "fires": 0,
            "certs_without_upstream": 0,
            "independent": Counter(),
        })
        g["fires"] += 1
        if not r["upstream_also_flagged"]:
            g["certs_without_upstream"] += 1
        if r.get("independent_verdict"):
            g["independent"][r["independent_verdict"]] += 1

    out = []
    for g in grouped.values():
        g = dict(g)
        g["independent"] = dict(g["independent"])
        out.append(g)
    out.sort(key=lambda x: (-x["fires"], x["lint"]))
    return out


def render_new_lint_md(corpus_label: str, total_certs: int, new_rows: list[dict],
                       upstream_rows: list[dict], by_lint: list[dict],
                       audit_counts: dict | None = None) -> str:
    only_new = [r for r in new_rows if not r["upstream_also_flagged"]]
    L = []
    L.append("# New-Lint Findings\n")
    L.append(f"- corpus: **{corpus_label}**")
    L.append(f"- parseable certificates scanned: **{total_certs}**")
    L.append(f"- findings from CICAS-added zlint lints (`cicasgen_`): **{len(new_rows)}**")
    L.append(f"- upstream zlint findings: **{len(upstream_rows)}**")
    L.append(f"- new-lint findings on certs with no upstream finding: **{len(only_new)}**")
    if audit_counts:
        L.append("- independent structural audit over new-lint findings: " +
                 ", ".join(f"{k}={v}" for k, v in sorted(audit_counts.items())))
    L.append("")
    L.append("Per CICAS-added lint:\n")
    L.append("| new lint | rule | section | fires | no-upstream certs | independent | rule text |")
    L.append("|---|---:|---|---:|---:|---|---|")
    for r in by_lint:
        indep = ", ".join(f"{k}:{v}" for k, v in sorted(r.get("independent", {}).items())) or "-"
        rule = r.get("rule_id") if r.get("rule_id") is not None else "-"
        section = r.get("section") or "-"
        L.append(f"| `{r['lint']}` | {rule} | {section} | {r['fires']} | "
                 f"{r['certs_without_upstream']} | {indep} | {_truncate(r.get('rule_text'))} |")
    L.append("")
    L.append("New-lint findings on certs not flagged by upstream zlint "
             "(full list in `new_lint_findings.jsonl`):\n")
    L.append("| cert | new lint | rule | section | independent | evidence |")
    L.append("|---|---|---:|---|---|---|")
    for r in only_new[:100]:
        rule = r.get("rule_id") if r.get("rule_id") is not None else "-"
        L.append(f"| `{r['cert']}` | `{r['lint']}` | {rule} | {r.get('section') or '-'} | "
                 f"{r.get('independent_verdict') or '-'} | "
                 f"{_truncate(r.get('independent_evidence'), 72)} |")
    if len(only_new) > 100:
        L.append(f"| ... | ... | ... | ... | ... | {len(only_new) - 100} more rows in JSONL |")
    return "\n".join(L) + "\n"


def write_new_lint_reports(out_dir: Path, corpus_label: str, detections: list[dict],
                           manifest: dict, audit: list[dict] | None = None) -> dict:
    new_rows = _annotate_new_lint_findings(detections, manifest, audit)
    upstream_rows = _upstream_findings(detections)
    by_lint = _new_lint_rollup(new_rows)
    audit_counts = Counter(a.get("indep") for a in (audit or []) if a.get("indep"))

    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / "new_lint_findings.jsonl").write_text(_jsonl(new_rows))
    (out_dir / "upstream_findings.jsonl").write_text(_jsonl(upstream_rows))
    (out_dir / "new_lint_by_lint.json").write_text(
        json.dumps(by_lint, indent=2, ensure_ascii=False))
    md = render_new_lint_md(corpus_label, len(detections), new_rows,
                            upstream_rows, by_lint, dict(audit_counts))
    (out_dir / "new_lint_findings.md").write_text(md)
    return {
        "new_lint_findings": len(new_rows),
        "upstream_findings": len(upstream_rows),
        "new_lints_fired": len(by_lint),
        "new_lint_certs": len({r["cert"] for r in new_rows}),
        "new_lint_no_upstream_findings": sum(
            1 for r in new_rows if not r["upstream_also_flagged"]),
        "new_lint_independent_audit": dict(audit_counts),
    }


def run_external_corpus(args, manifest: dict):
    certs_dir = Path(args.certs).resolve()
    if not certs_dir.exists():
        sys.exit(f"[error] cert corpus not found: {certs_dir}")
    out_dir = (Path(args.output_dir) if args.output_dir
               else EXTERNAL_OUTPUTS / _default_external_output_name(certs_dir))
    out_dir.mkdir(parents=True, exist_ok=True)

    print(f"[scan] {ZLINT.name} over external corpus {certs_dir} ...", flush=True)
    detections = scan.scan_corpus(
        ZLINT, certs_dir, limit=args.limit, workers=args.workers,
        progress_every=args.progress_every,
        label=_default_external_output_name(certs_dir),
    )
    generated_findings = _generated_finding_seed(detections)
    print(f"[scan] {len(detections)} certs, {len(generated_findings)} cicasgen_ findings",
          flush=True)

    audit = []
    if generated_findings and not args.no_independent_audit:
        print(f"[audit] independently verifying {len(generated_findings)} findings ...",
              flush=True)
        audit = independent_verify.verify_findings(generated_findings, certs_dir, ZLINT)
    report_counts = write_new_lint_reports(out_dir, _default_external_output_name(certs_dir), detections,
                                           manifest, audit)
    summary = {
        "mode": "external_corpus_report",
        "corpus": str(certs_dir),
        "total_certs": len(detections),
        **report_counts,
    }
    (out_dir / "detection_summary.json").write_text(
        json.dumps(summary, indent=2, ensure_ascii=False))
    print((out_dir / "new_lint_findings.md").read_text())
    print(f"[ok] external corpus report wrote {out_dir}")


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
    ap.add_argument("--certs", default=None,
                    help="external flat PEM corpus directory; report-only mode")
    ap.add_argument("--output-dir", default=None,
                    help="output directory for --certs mode "
                         "(default: experiments/new_lint_corpus_scan/outputs/<corpus>)")
    ap.add_argument("--limit", type=int, default=0, help="scan only N certs (smoke)")
    ap.add_argument("--workers", type=int, default=16,
                    help="parallel zlint worker processes for --certs mode")
    ap.add_argument("--progress-every", type=int, default=1000,
                    help="print --certs scan progress every N certs; 0 disables")
    ap.add_argument("--no-independent-audit", action="store_true",
                    help="for --certs mode, report raw zlint/new-lint findings without "
                         "per-finding structural re-verification")
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
    manifest = _manifest_by_lint()
    if MANIFEST.exists():
        n_shipped = json.loads(MANIFEST.read_text()).get("count", 0)

    if args.certs:
        run_external_corpus(args, manifest)
        return

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
