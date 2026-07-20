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
    augmented zlint binary built by cicas_backend/scripts/inject_and_build.py
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
  outputs/strict_reportable_findings.jsonl preliminary structural-screen findings
  outputs/triage_by_lint.json     per-lint firing + verdict counts
  outputs/uncertain_verified.jsonl cert-grounded verdict for each UNCERTAIN finding
  outputs/blame.jsonl             SAIV feedback ledger when DB access is available

Run:
  python3 cicas_backend/experiments/cert_detection/run.py            # scan + triage + verify
  python3 cicas_backend/experiments/cert_detection/run.py --snapshot # also refresh inputs/

Expected current use:
  Rerun coverage first so native-overlap rules are marked lint_covered=true and
  do not enter code generation. This script then audits the generated-lint
  findings that remain. ``strict_reportable_findings.jsonl`` is a preliminary
  structural screen: it limits rows to independently confirmed findings with no
  upstream lint on the same certificate. The paper-facing conclusion additionally
  runs audit_claimed_findings.py against the shipping-manifest source/code review;
  NOCHECK rows remain unverified.
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


def _is_strict_reportable_finding(row: dict, certs_dir: Path | None, manifest: dict) -> bool:
    if row.get("independent_verdict") != "CONFIRMED":
        return False
    lint = row.get("lint")
    if row.get("upstream_also_flagged") is not False:
        return False
    if certs_dir is None:
        return False
    return True


def _strict_reportable_from_audit(audit: list[dict], manifest: dict, certs_dir: Path) -> list[dict]:
    rows = []
    for a in audit:
        lint = a.get("lint")
        meta = manifest.get(lint, {})
        row = {
            "cert": a.get("cert"),
            "lint": lint,
            "rule_id": meta.get("rule_id"),
            "independent_verdict": a.get("indep"),
            "independent_evidence": a.get("indep_evidence"),
        }
        if _is_strict_reportable_finding(row, certs_dir, manifest):
            rows.append(row)
    return rows


def _generated_finding_seed(detections: list[dict], *, only_no_upstream: bool = False) -> list[dict]:
    findings = []
    for d in detections:
        if only_no_upstream and d["upstream"]:
            continue
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
                       audit_counts: dict | None = None,
                       strict_count: int | None = None) -> str:
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
    if strict_count is not None:
        L.append(f"- preliminary structural-screen findings: **{strict_count}** "
                 "(independent CONFIRMED and no any-upstream result)")
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
                           manifest: dict, audit: list[dict] | None = None,
                           certs_dir: Path | None = None) -> dict:
    new_rows = _annotate_new_lint_findings(detections, manifest, audit)
    upstream_rows = _upstream_findings(detections)
    by_lint = _new_lint_rollup(new_rows)
    audit_counts = Counter(a.get("indep") for a in (audit or []) if a.get("indep"))
    strict_rows = [
        r for r in new_rows
        if _is_strict_reportable_finding(r, certs_dir, manifest)
    ]

    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / "new_lint_findings.jsonl").write_text(_jsonl(new_rows))
    (out_dir / "strict_reportable_findings.jsonl").write_text(_jsonl(strict_rows))
    (out_dir / "upstream_findings.jsonl").write_text(_jsonl(upstream_rows))
    (out_dir / "new_lint_by_lint.json").write_text(
        json.dumps(by_lint, indent=2, ensure_ascii=False))
    md = render_new_lint_md(corpus_label, len(detections), new_rows,
                            upstream_rows, by_lint, dict(audit_counts), len(strict_rows))
    (out_dir / "new_lint_findings.md").write_text(md)
    return {
        "new_lint_findings": len(new_rows),
        "strict_reportable_findings": len(strict_rows),
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
    for stale in (
        "new_lint_findings.jsonl",
        "strict_reportable_findings.jsonl",
        "upstream_findings.jsonl",
        "new_lint_by_lint.json",
        "new_lint_findings.md",
        "detection_summary.json",
        "no_upstream_independent_audit.jsonl",
        "no_upstream_independent_audit_summary.json",
        "targeted_independent_audit.jsonl",
        "targeted_independent_audit_summary.json",
    ):
        (out_dir / stale).unlink(missing_ok=True)

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
        only_no_upstream = args.independent_audit_scope == "no-upstream"
        audit_seed = _generated_finding_seed(detections, only_no_upstream=only_no_upstream)
        print(f"[audit] independently verifying {len(audit_seed)} findings "
              f"(scope={args.independent_audit_scope}) ...",
              flush=True)
        audit = independent_verify.verify_findings(audit_seed, certs_dir, ZLINT)
    report_counts = write_new_lint_reports(out_dir, _default_external_output_name(certs_dir), detections,
                                           manifest, audit, certs_dir)
    if audit:
        audit_file = ("no_upstream_independent_audit.jsonl"
                      if args.independent_audit_scope == "no-upstream"
                      else "targeted_independent_audit.jsonl")
        (out_dir / audit_file).write_text(_jsonl(audit))
        audit_summary = {
            "scope": args.independent_audit_scope,
            "findings_audited": len(audit),
            "verdicts": dict(Counter(a.get("indep") for a in audit if a.get("indep"))),
        }
        summary_file = ("no_upstream_independent_audit_summary.json"
                        if args.independent_audit_scope == "no-upstream"
                        else "targeted_independent_audit_summary.json")
        (out_dir / summary_file).write_text(
            json.dumps(audit_summary, indent=2, ensure_ascii=False))
    summary = {
        "mode": "external_corpus_report",
        "corpus": str(certs_dir),
        "total_certs": len(detections),
        "independent_audit_scope": (
            "none" if args.no_independent_audit else args.independent_audit_scope),
        "independent_audit_findings": len(audit),
        **report_counts,
    }
    (out_dir / "detection_summary.json").write_text(
        json.dumps(summary, indent=2, ensure_ascii=False))
    print((out_dir / "new_lint_findings.md").read_text())
    print(f"[ok] external corpus report wrote {out_dir}")


def render_md(summary, by_lint, uncertain_counts, n_shipped, audit_counts=None,
              strict_reportable=0, independent_false_positives=0,
              unresolved_spurious=0):
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
    L.append(f"**Strict reportable result: {strict_reportable} findings are independently "
             f"CONFIRMED and not quality-gated.** Raw triage calls {genuine}/{s['total']} "
             f"genuine and marks {s['SPURIOUS']} finding(s) as weak-oracle SPURIOUS; "
             f"independent audit leaves {independent_false_positives} REFUTED finding(s) "
             f"and {unresolved_spurious} unresolved SPURIOUS finding(s), with "
             f"{(audit_counts or {}).get('NOCHECK', 0)} NOCHECK findings excluded from "
             f"the reliable-claim set.\n")
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
                    help="output directory; for --certs mode defaults to "
                         "experiments/new_lint_corpus_scan/outputs/<corpus>, "
                         "otherwise defaults to experiments/cert_detection/outputs")
    ap.add_argument("--limit", type=int, default=0, help="scan only N certs (smoke)")
    ap.add_argument("--workers", type=int, default=16,
                    help="parallel zlint worker processes for --certs mode")
    ap.add_argument("--progress-every", type=int, default=1000,
                    help="print --certs scan progress every N certs; 0 disables")
    ap.add_argument("--no-independent-audit", action="store_true",
                    help="for --certs mode, report raw zlint/new-lint findings without "
                         "per-finding structural re-verification")
    ap.add_argument("--independent-audit-scope", choices=("all", "no-upstream"),
                    default="all",
                    help="for --certs mode, independently verify all generated findings "
                         "or only generated findings on certs with no upstream zlint finding")
    args = ap.parse_args()
    output_dir = Path(args.output_dir).resolve() if args.output_dir else OUTPUTS

    if not ZLINT.exists():
        sys.exit(f"[error] augmented zlint binary not found: {ZLINT}\n"
                 f"        build it first: python3 cicas_backend/scripts/"
                 f"inject_and_build.py --emit --build")

    output_dir.mkdir(parents=True, exist_ok=True)
    if args.snapshot:
        INPUTS.mkdir(exist_ok=True)
        if MANIFEST.exists():
            (INPUTS / "cicasgen_manifest.json").write_text(MANIFEST.read_text())
            print(f"  wrote {INPUTS/'cicasgen_manifest.json'}")

    manifest = _manifest_by_lint()
    n_shipped = json.loads(MANIFEST.read_text()).get("count", 0) if MANIFEST.exists() else 0

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
    audit_false_positives = [a for a in audit if a["indep"] == "REFUTED"]
    unresolved_spurious = [
        a for a in audit
        if a["triage"] == "SPURIOUS" and a["indep"] != "CONFIRMED"
    ]
    # NOCHECK on a finding means the auditor could not independently verify that
    # family.  It is excluded from strict paper claims rather than counted as a
    # reportable defect.
    audit_unverified = [a for a in audit if a["indep"] in ("NOCHECK", "ERROR")]
    strict_reportable = _strict_reportable_from_audit(audit, manifest, TESTDATA)

    try:
        ledger = blame_mod.blame(t["by_lint"], t["findings"])
    except Exception as e:
        print(f"[warn] blame ledger skipped because DB is unavailable: {e}", flush=True)
        ledger = []

    # outputs
    (output_dir / "triage_by_lint.json").write_text(json.dumps(t["by_lint"], indent=2))
    (output_dir / "uncertain_verified.jsonl").write_text(
        "".join(json.dumps(x) + "\n" for x in uncertain))
    (output_dir / "audit_independent.jsonl").write_text(
        "".join(json.dumps(x) + "\n" for x in audit))
    (output_dir / "strict_reportable_findings.jsonl").write_text(
        _jsonl(strict_reportable))
    (output_dir / "blame.jsonl").write_text(
        "".join(json.dumps(x) + "\n" for x in ledger))
    summary = {**t["summary"], "n_shipped_lints": n_shipped,
               "uncertain_verified": dict(uc),
               "independent_audit": dict(ua),
               "independent_conflicts": len(audit_conflicts),
               "independent_unverified": len(audit_unverified),
               "independent_false_positives": len(audit_false_positives),
               "unresolved_spurious": len(unresolved_spurious),
               "strict_reportable_findings": len(strict_reportable),
               "genuine": t["summary"]["REAL"] + uc.get("CONFIRMED_REAL", 0),
               "triage_spurious": t["summary"]["SPURIOUS"],
               "false_positives": len(audit_false_positives) + len(unresolved_spurious)}
    (output_dir / "detection_summary.json").write_text(json.dumps(summary, indent=2))
    md = render_md(t["summary"], t["by_lint"], dict(uc), n_shipped, dict(ua),
                   len(strict_reportable), len(audit_false_positives),
                   len(unresolved_spurious))
    (output_dir / "detection_summary.md").write_text(md)

    print(md)
    assert not audit_false_positives, (
        f"independent audit REFUTED {len(audit_false_positives)} finding(s): "
        f"{[(a['lint'], a['cert']) for a in audit_false_positives[:10]]}")
    assert not unresolved_spurious, (
        f"{len(unresolved_spurious)} triage-SPURIOUS finding(s) were not independently "
        f"confirmed: {[(a['lint'], a['cert'], a['indep']) for a in unresolved_spurious[:10]]}")
    if uc.get("REMAINS_UNCERTAIN", 0):
        print(f"[warn] {uc.get('REMAINS_UNCERTAIN', 0)} UNCERTAIN finding(s) "
              "remain excluded from strict claims", flush=True)
    assert not audit_conflicts, (
        f"independent audit refuted {len(audit_conflicts)} finding(s) triage called "
        f"genuine: {[(a['lint'], a['cert']) for a in audit_conflicts]}")
    print(f"[ok] strict_reportable={len(strict_reportable)}; "
          f"triage_genuine={summary['genuine']}/{t['summary']['total']}; "
          f"false_positives=0; triage_spurious={t['summary']['SPURIOUS']} "
          f"(independent-confirmed); independent audit CONFIRMED={ua.get('CONFIRMED',0)} "
          f"REFUTED={ua.get('REFUTED',0)} NOCHECK={ua.get('NOCHECK',0)} "
          f"(NOCHECK excluded from reliable claims); "
          f"wrote outputs/ -> {output_dir}")


if __name__ == "__main__":
    main()
