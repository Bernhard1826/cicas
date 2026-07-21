#!/usr/bin/env python3
"""Build the strict-audited uncovered codegen domain.

This script does not mutate the database.  It reconstructs the rule-id domain
for code generation from two experiment-owned inputs:

1. The current DB's computed lintable coverage snapshot.
2. The manual strict-native-coverage audit of rows previously counted covered.

The output is a JSON file consumed by run_codegen_synonymy.py --domain-rule-ids.
"""
from __future__ import annotations

import argparse
import json
import os
from collections import Counter
from datetime import date
from pathlib import Path

import psycopg2

HERE = Path(__file__).resolve().parent
BACKEND = HERE.parents[1]
OUTPUTS = HERE / "outputs"
DB_URL = os.environ.get("CICAS_DB_URL", "postgresql://postgres:123456@localhost:15432/cicas")
COVERAGE_OUTPUTS = BACKEND / "experiments/coverage_analysis/outputs"
COVERAGE_TABLE = COVERAGE_OUTPUTS / "coverage_table.json"
ZLINT_CATALOG = BACKEND / "experiments/coverage_analysis/inputs/zlint_lint_catalog.json"

STRICT_AUDIT_FULL = (
    BACKEND
    / "experiments/coverage_analysis/outputs/"
    "native_go_covered_audit_seeded_20260718_machine_full_manual_review.jsonl"
)
STRICT_AUDIT_NONFULL = (
    BACKEND
    / "experiments/coverage_analysis/outputs/"
    "native_go_covered_audit_seeded_20260718_manual_review.jsonl"
)
STRICT_AUDIT_SUMMARY = (
    BACKEND
    / "experiments/coverage_analysis/outputs/"
    "native_go_covered_audit_seeded_20260718_revised_summary.json"
)
STRICT_UNCOVERED_RESCUE_REVIEW = (
    BACKEND
    / "experiments/coverage_analysis/outputs/"
    "strict_uncovered_128_native_go_audit_20260718_manual_review.jsonl"
)

STANDARD_SOURCES = {1: "RFC5280", 19: "CABF-BR"}


def _read_jsonl(path: Path) -> list[dict]:
    rows = []
    for line in path.read_text(encoding="utf-8").splitlines():
        if line.strip():
            rows.append(json.loads(line))
    return rows


def _strict_not_covered_from_audits() -> tuple[set[int], dict]:
    full_rows = _read_jsonl(STRICT_AUDIT_FULL)
    nonfull_rows = _read_jsonl(STRICT_AUDIT_NONFULL)

    full_false = {
        int(row["rule_id"])
        for row in full_rows
        if row.get("counts_as_strict_native_covered") is False
    }
    nonfull_false = {
        int(row["rule_id"])
        for row in nonfull_rows
        if row.get("counts_as_strict_native_full") is False
    }
    full_true = sum(1 for row in full_rows if row.get("counts_as_strict_native_covered") is True)
    nonfull_true = sum(1 for row in nonfull_rows if row.get("counts_as_strict_native_full") is True)
    false_ids = full_false | nonfull_false
    return false_ids, {
        "machine_full_rows": len(full_rows),
        "machine_full_strict_true": full_true,
        "machine_full_not_strict": len(full_false),
        "machine_full_not_strict_rule_ids": sorted(full_false),
        "machine_nonfull_rows": len(nonfull_rows),
        "machine_nonfull_strict_true": nonfull_true,
        "machine_nonfull_not_strict": len(nonfull_false),
        "machine_nonfull_not_strict_rule_ids": sorted(nonfull_false),
        "strict_audit_union_not_counted": len(false_ids),
    }


def _strict_covered_rescues_from_uncovered() -> tuple[set[int], dict]:
    if not STRICT_UNCOVERED_RESCUE_REVIEW.exists():
        return set(), {
            "old_uncovered_rescue_review": str(STRICT_UNCOVERED_RESCUE_REVIEW),
            "old_uncovered_rescue_rows": 0,
            "old_uncovered_rescue_strict_true": 0,
            "old_uncovered_rescue_rule_ids": [],
        }
    rows = _read_jsonl(STRICT_UNCOVERED_RESCUE_REVIEW)
    rescue_ids = {
        int(row["rule_id"])
        for row in rows
        if row.get("counts_as_strict_native_covered") is True
    }
    return rescue_ids, {
        "old_uncovered_rescue_review": str(STRICT_UNCOVERED_RESCUE_REVIEW),
        "old_uncovered_rescue_rows": len(rows),
        "old_uncovered_rescue_strict_true": len(rescue_ids),
        "old_uncovered_rescue_rule_ids": sorted(rescue_ids),
    }


def _load_db_snapshot() -> dict:
    with psycopg2.connect(DB_URL, connect_timeout=3) as conn:
        cur = conn.cursor()
        cur.execute(
            """
            select id, standard_id, section, title, lint_covered
            from rules
            where standard_id in (1, 19)
              and lintable
              and lint_coverage is not null
            order by standard_id, section, id
            """
        )
        rows = [
            {
                "id": int(rid),
                "standard_id": int(standard_id),
                "source": STANDARD_SOURCES.get(int(standard_id), str(standard_id)),
                "section": section or "",
                "title": title or "",
                "lint_covered": bool(lint_covered),
            }
            for rid, standard_id, section, title, lint_covered in cur.fetchall()
        ]
    by_id = {int(row["id"]): row for row in rows}
    return {"rows": rows, "by_id": by_id}


def _load_zlint_reference() -> dict:
    for path in (COVERAGE_TABLE, ZLINT_CATALOG):
        if not path.exists():
            continue
        data = json.loads(path.read_text(encoding="utf-8"))
        ref = data.get("zlint_reference", data)
        if isinstance(ref, dict) and "CABF" in ref and "RFC5280" in ref:
            return ref
    raise SystemExit(
        "cannot find zlint reference counts; run "
        "cicas_backend/experiments/coverage_analysis/run.py first"
    )


def build_domain() -> dict:
    audit_false, audit_meta = _strict_not_covered_from_audits()
    rescue_true, rescue_meta = _strict_covered_rescues_from_uncovered()
    db = _load_db_snapshot()
    rows = db["rows"]
    by_id = db["by_id"]

    old_uncovered = {int(row["id"]) for row in rows if not row["lint_covered"]}
    old_covered = {int(row["id"]) for row in rows if row["lint_covered"]}
    snapshot_ids = set(by_id)
    missing_audit_ids = sorted(audit_false - snapshot_ids)
    audit_false = audit_false & snapshot_ids
    audit_false_not_old_covered = sorted(audit_false - old_covered)
    if audit_false_not_old_covered:
        raise SystemExit(
            "strict audit false ids should come from the old covered set, but found "
            f"{audit_false_not_old_covered}"
        )
    missing_rescue_ids = sorted(rescue_true - snapshot_ids)
    rescue_true = rescue_true & snapshot_ids
    rescue_true_not_old_uncovered = sorted(rescue_true - old_uncovered)
    if rescue_true_not_old_uncovered:
        raise SystemExit(
            "strict rescue true ids should come from the old uncovered set, but found "
            f"{rescue_true_not_old_uncovered}"
        )

    strict_uncovered = (old_uncovered - rescue_true) | audit_false
    strict_covered = (old_covered - audit_false) | rescue_true
    by_source_lintable = Counter(row["source"] for row in rows)
    by_source_strict_covered = Counter(by_id[rid]["source"] for rid in strict_covered)
    by_source = Counter(by_id[rid]["source"] for rid in strict_uncovered)
    by_source_old_covered = Counter(by_id[rid]["source"] for rid in old_covered)
    by_source_old_uncovered = Counter(by_id[rid]["source"] for rid in old_uncovered)
    by_source_newly_uncovered = Counter(by_id[rid]["source"] for rid in audit_false)
    by_source_rescued = Counter(by_id[rid]["source"] for rid in rescue_true)

    source_rows = [
        {
            "rule_id": rid,
            "source": by_id[rid]["source"],
            "section": by_id[rid]["section"],
            "title": by_id[rid]["title"],
            "reason": "old_db_uncovered" if rid in old_uncovered else "strict_native_audit_not_counted",
        }
        for rid in sorted(strict_uncovered, key=lambda x: (by_id[x]["standard_id"], by_id[x]["section"], x))
    ]

    return {
        "generated_at": date.today().isoformat(),
        "db_url": DB_URL,
        "domain_name": "strict_audited_uncovered_20260718",
        "definition": (
            "Current DB rows where standard_id in {RFC5280,CABF-BR}, lintable=true, "
            "lint_coverage is not null, and either DB lint_covered=false or the "
            "2026-07-18 strict native-zlint audit says the old covered row does "
            "not count as strict native coverage."
        ),
        "important_invariants": [
            "This script does not update IR, lintability, or lint_coverage in the database.",
            "CICAS-generated lints are never counted as native zlint coverage.",
            "Rows excluded from strict native coverage come from experiment audit files, not manual DB edits.",
        ],
        "inputs": {
            "strict_audit_machine_full": str(STRICT_AUDIT_FULL),
            "strict_audit_machine_nonfull": str(STRICT_AUDIT_NONFULL),
            "strict_audit_revised_summary": str(STRICT_AUDIT_SUMMARY),
            "strict_uncovered_rescue_review": str(STRICT_UNCOVERED_RESCUE_REVIEW),
        },
        "db_snapshot_counts": {
            "lintable_with_computed_coverage": len(rows),
            "old_db_native_covered": len(old_covered),
            "old_db_uncovered": len(old_uncovered),
        },
        "strict_native_coverage_counts": {
            "strict_native_covered": len(strict_covered),
            "strict_uncovered": len(strict_uncovered),
            "newly_uncovered_from_old_covered": len(audit_false),
            "newly_covered_from_old_uncovered": len(rescue_true),
        },
        "audit_counts": {**audit_meta, **rescue_meta},
        "stale_audit_rows_excluded_by_current_lintability": {
            "strict_audit_not_covered_rule_ids": missing_audit_ids,
            "strict_uncovered_rescue_rule_ids": missing_rescue_ids,
        },
        "by_source": {
            source: {
                "lintable": by_source_lintable[source],
                "strict_native_covered": by_source_strict_covered[source],
                "strict_uncovered": by_source[source],
                "old_db_native_covered": by_source_old_covered[source],
                "old_db_uncovered": by_source_old_uncovered[source],
                "newly_uncovered_from_old_covered": by_source_newly_uncovered[source],
                "newly_covered_from_old_uncovered": by_source_rescued[source],
            }
            for source in sorted(by_source_lintable)
        },
        "rule_ids": [row["rule_id"] for row in source_rows],
        "rows": source_rows,
    }


def build_strict_coverage_table(domain: dict, domain_output: Path | None = None) -> dict:
    ref = _load_zlint_reference()
    source_map = {"CABF": "CABF-BR", "RFC5280": "RFC5280"}
    rows = []
    total = {
        "lintable": 0,
        "strict_native_covered": 0,
        "strict_uncovered": 0,
        "old_db_native_covered": 0,
        "old_db_uncovered": 0,
        "newly_uncovered_from_old_covered": 0,
        "newly_covered_from_old_uncovered": 0,
    }
    for label in ("CABF", "RFC5280"):
        source = source_map[label]
        counts = domain["by_source"].get(source, {})
        row = {
            "source": label,
            "lintable": int(counts.get("lintable", 0)),
            "strict_native_covered": int(counts.get("strict_native_covered", 0)),
            "strict_uncovered": int(counts.get("strict_uncovered", 0)),
            "old_db_native_covered": int(counts.get("old_db_native_covered", 0)),
            "old_db_uncovered": int(counts.get("old_db_uncovered", 0)),
            "newly_uncovered_from_old_covered": int(counts.get("newly_uncovered_from_old_covered", 0)),
            "newly_covered_from_old_uncovered": int(counts.get("newly_covered_from_old_uncovered", 0)),
            "zlint_reference": ref[label],
        }
        rows.append(row)
        for key in total:
            total[key] += row[key]
    total["zlint_reference"] = {
        "total": sum(ref[label]["total"] for label in ("CABF", "RFC5280")),
        "cert": sum(ref[label]["cert"] for label in ("CABF", "RFC5280")),
        "crl": sum(ref[label]["crl"] for label in ("CABF", "RFC5280")),
    }
    return {
        "generated_at": domain["generated_at"],
        "definition": (
            "Table IV strict native-zlint coverage: start from the DB coverage "
            "snapshot, then apply the strict native-Go coverage audit deltas. "
            "CICAS-generated lints are excluded from native zlint counts."
        ),
        "inputs": {
            "db_coverage_snapshot": str(COVERAGE_TABLE),
            "zlint_reference_catalog": str(ZLINT_CATALOG),
            "strict_domain_rule_ids": str(domain_output) if domain_output else None,
            **domain["inputs"],
        },
        "by_source": rows,
        "total": total,
        "zlint_reference": ref,
        "conservation": {
            "lintable_equals_strict_covered_plus_uncovered": (
                total["lintable"]
                == total["strict_native_covered"] + total["strict_uncovered"]
            ),
            "strict_covered_formula": (
                "old_db_native_covered - newly_uncovered_from_old_covered "
                "+ newly_covered_from_old_uncovered"
            ),
            "strict_uncovered_formula": (
                "old_db_uncovered + newly_uncovered_from_old_covered "
                "- newly_covered_from_old_uncovered"
            ),
        },
    }


def render_strict_coverage_md(table: dict) -> str:
    by = {row["source"]: row for row in table["by_source"]}
    cabf, rfc = by["CABF"], by["RFC5280"]
    ref_c, ref_r = cabf["zlint_reference"], rfc["zlint_reference"]
    total = table["total"]
    ref_t = total["zlint_reference"]
    return "\n".join(
        [
            "# Table IV — strict native zlint coverage of lintable rules",
            "",
            "| Item | CABF | RFC 5280 | Total |",
            "|---|---:|---:|---:|",
            f"| zlint cognate lints, total (ref.) | {ref_c['total']} | {ref_r['total']} | {ref_t['total']} |",
            f"| of which cert. lints | {ref_c['cert']} | {ref_r['cert']} | {ref_t['cert']} |",
            f"| of which CRL lints | {ref_c['crl']} | {ref_r['crl']} | {ref_t['crl']} |",
            (
                "| full (full coverage) | "
                f"{cabf['strict_native_covered']} | {rfc['strict_native_covered']} | "
                f"{total['strict_native_covered']} |"
            ),
            (
                "| uncovered (codegen domain) | "
                f"{cabf['strict_uncovered']} | {rfc['strict_uncovered']} | "
                f"{total['strict_uncovered']} |"
            ),
            f"| lintable total | {cabf['lintable']} | {rfc['lintable']} | {total['lintable']} |",
            "",
            "## Provenance",
            "",
            (
                "- DB coverage snapshot: "
                f"{total['old_db_native_covered']} covered / {total['old_db_uncovered']} uncovered."
            ),
            (
                "- Strict audit delta: "
                f"{total['newly_uncovered_from_old_covered']} old-covered rows removed from strict coverage; "
                f"{total['newly_covered_from_old_uncovered']} old-uncovered rows restored as strict coverage."
            ),
            (
                "- Strict result: "
                f"{total['strict_native_covered']} covered / {total['strict_uncovered']} uncovered; "
                f"{total['lintable']} = {total['strict_native_covered']} + {total['strict_uncovered']}."
            ),
        ]
    ) + "\n"


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument(
        "--output",
        default=str(OUTPUTS / "strict_audited_uncovered_20260718" / "domain_rule_ids.json"),
    )
    ap.add_argument(
        "--strict-coverage-output",
        default=str(COVERAGE_OUTPUTS / "strict_coverage_table.json"),
        help="write the Table IV strict coverage aggregate next to coverage outputs",
    )
    args = ap.parse_args()

    out_path = Path(args.output)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    data = build_domain()
    out_path.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")
    summary_path = out_path.with_name("domain_summary.md")
    summary_path.write_text(
        "\n".join(
            [
                "# Strict-Audited Uncovered Codegen Domain",
                "",
                f"- lintable with computed coverage: {data['db_snapshot_counts']['lintable_with_computed_coverage']}",
                f"- old DB native covered: {data['db_snapshot_counts']['old_db_native_covered']}",
                f"- old DB uncovered: {data['db_snapshot_counts']['old_db_uncovered']}",
                f"- strict native covered: {data['strict_native_coverage_counts']['strict_native_covered']}",
                f"- strict uncovered: {data['strict_native_coverage_counts']['strict_uncovered']}",
                f"- newly uncovered from old covered: {data['strict_native_coverage_counts']['newly_uncovered_from_old_covered']}",
                f"- newly covered from old uncovered: {data['strict_native_coverage_counts']['newly_covered_from_old_uncovered']}",
            ]
        )
        + "\n",
        encoding="utf-8",
    )
    strict_table_path = Path(args.strict_coverage_output)
    strict_table_path.parent.mkdir(parents=True, exist_ok=True)
    strict_table = build_strict_coverage_table(data, out_path)
    strict_table_path.write_text(
        json.dumps(strict_table, indent=2, ensure_ascii=False),
        encoding="utf-8",
    )
    strict_table_path.with_suffix(".md").write_text(
        render_strict_coverage_md(strict_table),
        encoding="utf-8",
    )
    print(json.dumps(data["strict_native_coverage_counts"], indent=2, ensure_ascii=False))
    print(f"wrote {out_path}")
    print(f"wrote {strict_table_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
