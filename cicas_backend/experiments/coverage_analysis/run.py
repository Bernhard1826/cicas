#!/usr/bin/env python3
"""
Paper §8.2 — lint coverage analysis (Table 2).

Question: of the system's lint-able rules, how many are already implemented by a
*same-source* zlint lint (full coverage), and how many remain as the
code-generation domain (uncovered)?

Method (as described in §8.2):
  - The per-rule coverage verdict (full / partial / none) is computed by the
    BACKEND coverage service — candidate retrieval by source/section, a
    field-level LLM judge (subject / obligation / predicate / constraint), and a
    deterministic "wrong-field" consistency gate that only downgrades. See
    app/services/certificate/zlint_interface.py and
    app/api/zlint_analysis_routes.py (check_batch_coverage). Verdicts are
    persisted on rules.lint_coverage / rules.lint_covered.
  - This script does NOT recompute verdicts; it AGGREGATES the persisted verdicts
    into Table 2 and recomputes the zlint same-source reference counts directly
    from the bundled zlint v3 Go source (Source metadata field).

Inputs (snapshot written to inputs/ by --snapshot):
  inputs/lintable_rules.jsonl   the 336 lint-able rules with their stored verdict
  inputs/zlint_lint_catalog.json zlint v3 lint counts by Source (reference row)

Outputs (written to outputs/):
  outputs/coverage_table.json    Table 2 as data
  outputs/coverage_table.md      Table 2 rendered
  outputs/per_rule_coverage.jsonl per-rule full/none verdict

Run:
  python experiments/coverage_analysis/run.py            # aggregate + render Table 2
  python experiments/coverage_analysis/run.py --snapshot # also refresh inputs/

Expected (current paper snapshot):
  lint-able 336 = CABF 227 + RFC5280 109
  full      132 = CABF  79 + RFC5280  53
  uncovered 204 = CABF 148 + RFC5280  56   (= code-generation domain φ_G)
  zlint same-source reference: CABF 170 lints, RFC5280 122 lints
"""
import argparse
import json
import os
import re
from pathlib import Path

import psycopg2

HERE = Path(__file__).resolve().parent
INPUTS = HERE / "inputs"
OUTPUTS = HERE / "outputs"
# zlint v3 Go source bundled in the repo (two parents up: cicas_backend/)
ZLINT_LINTS_DIR = HERE.parent.parent / "zlint" / "v3" / "lints"

DB_URL = os.environ.get("CICAS_DB_URL", "postgresql://postgres:123456@localhost:15432/cicas")

# standard_id -> human source name (RFC 5280 = 1, CABF BR = 19)
STANDARDS = [(19, "CABF"), (1, "RFC5280")]


def _conn():
    return psycopg2.connect(DB_URL)


def coverage_table():
    """Aggregate persisted coverage verdicts into Table 2."""
    rows = []
    total = {"lintable": 0, "full": 0, "uncovered": 0}
    with _conn() as c:
        cur = c.cursor()
        for sid, name in STANDARDS:
            cur.execute("select count(*) from rules where lintable and standard_id=%s", (sid,))
            lintable = cur.fetchone()[0]
            cur.execute(
                "select count(*) from rules where lintable and lint_covered and standard_id=%s",
                (sid,),
            )
            full = cur.fetchone()[0]
            rows.append({"source": name, "lintable": lintable, "full": full,
                         "uncovered": lintable - full})
            total["lintable"] += lintable
            total["full"] += full
            total["uncovered"] += lintable - full
    return {"by_source": rows, "total": total, "zlint_reference": zlint_source_counts()}


def zlint_source_counts():
    """Count zlint v3 lints by their Source metadata, splitting cert vs CRL.

    A lint is a CRL lint iff its file registers via RegisterRevocationListLint.
    Mirrors §8.2 Table 2's reference row (CABF 170, RFC5280 122).
    """
    src_re = re.compile(r"Source:\s*lint\.([A-Za-z0-9_]+)")
    by_source = {}
    crl_by_source = {}
    if not ZLINT_LINTS_DIR.exists():
        return {"_warning": f"zlint source not found at {ZLINT_LINTS_DIR}"}
    for go in ZLINT_LINTS_DIR.rglob("*.go"):
        if go.name.endswith("_test.go"):
            continue
        text = go.read_text(errors="ignore")
        sources = src_re.findall(text)
        if not sources:
            continue
        is_crl = "RegisterRevocationListLint(" in text
        for s in sources:
            by_source[s] = by_source.get(s, 0) + 1
            if is_crl:
                crl_by_source[s] = crl_by_source.get(s, 0) + 1
    def pack(key):
        tot = by_source.get(key, 0)
        crl = crl_by_source.get(key, 0)
        return {"total": tot, "cert": tot - crl, "crl": crl}
    return {"CABF": pack("CABFBaselineRequirements"), "RFC5280": pack("RFC5280")}


def render_md(table):
    t, ref = table["total"], table["zlint_reference"]
    by = {r["source"]: r for r in table["by_source"]}
    cabf, rfc = by["CABF"], by["RFC5280"]
    rc, rr = ref.get("CABF", {}), ref.get("RFC5280", {})
    L = []
    L.append("# Table 2 — zlint same-source coverage of lint-able rules\n")
    L.append("| 项 | CABF | RFC 5280 | 合计 |")
    L.append("|---|---:|---:|---:|")
    L.append(f"| *zlint 同源 lint 总数（参照）* | *{rc.get('total','?')}* | *{rr.get('total','?')}* | *{rc.get('total',0)+rr.get('total',0)}* |")
    L.append(f"| *　— 其中证书 lint（单证书口径）* | *{rc.get('cert','?')}* | *{rr.get('cert','?')}* | *{rc.get('cert',0)+rr.get('cert',0)}* |")
    L.append(f"| *　— 其中 CRL lint（单证书口径外）* | *{rc.get('crl','?')}* | *{rr.get('crl','?')}* | *{rc.get('crl',0)+rr.get('crl',0)}* |")
    L.append(f"| full（完整覆盖） | {cabf['full']} | {rfc['full']} | **{t['full']}** |")
    L.append(f"| 未覆盖（codegen 定义域） | {cabf['uncovered']} | {rfc['uncovered']} | **{t['uncovered']}** |")
    L.append(f"| 可 lint 合计 | {cabf['lintable']} | {rfc['lintable']} | **{t['lintable']}** |")
    return "\n".join(L) + "\n"


def snapshot_inputs():
    """Archive the experiment inputs (lint-able rules + zlint catalog)."""
    INPUTS.mkdir(exist_ok=True)
    with _conn() as c:
        cur = c.cursor()
        cur.execute(
            "select id, standard_id, section, subsection, title, text, "
            "lint_covered, lint_name, lint_coverage "
            "from rules where lintable order by standard_id, section, id"
        )
        cols = [d[0] for d in cur.description]
        with open(INPUTS / "lintable_rules.jsonl", "w") as f:
            for row in cur.fetchall():
                f.write(json.dumps(dict(zip(cols, row)), default=str, ensure_ascii=False) + "\n")
    (INPUTS / "zlint_lint_catalog.json").write_text(
        json.dumps(zlint_source_counts(), indent=2, ensure_ascii=False))
    print(f"  wrote {INPUTS/'lintable_rules.jsonl'}")
    print(f"  wrote {INPUTS/'zlint_lint_catalog.json'}")


def main():
    ap = argparse.ArgumentParser(description="Paper §8.2 lint coverage analysis")
    ap.add_argument("--snapshot", action="store_true", help="refresh inputs/ snapshot from DB+source")
    args = ap.parse_args()

    OUTPUTS.mkdir(exist_ok=True)
    if args.snapshot:
        print("[snapshot] archiving inputs ...")
        snapshot_inputs()

    table = coverage_table()
    (OUTPUTS / "coverage_table.json").write_text(json.dumps(table, indent=2, ensure_ascii=False))
    md = render_md(table)
    (OUTPUTS / "coverage_table.md").write_text(md)

    # per-rule verdict export
    with _conn() as c:
        cur = c.cursor()
        cur.execute(
            "select id, standard_id, section, lint_covered, lint_name, lint_coverage "
            "from rules where lintable order by standard_id, section, id"
        )
        cols = [d[0] for d in cur.description]
        with open(OUTPUTS / "per_rule_coverage.jsonl", "w") as f:
            for row in cur.fetchall():
                f.write(json.dumps(dict(zip(cols, row)), default=str, ensure_ascii=False) + "\n")

    print(md)
    t = table["total"]
    assert t["lintable"] == t["full"] + t["uncovered"], "conservation broken"
    print(f"[ok] lint-able {t['lintable']} = full {t['full']} + uncovered {t['uncovered']}")
    print(f"[ok] wrote outputs/ -> {OUTPUTS}")


if __name__ == "__main__":
    main()
