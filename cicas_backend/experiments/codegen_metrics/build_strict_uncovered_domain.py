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
    by_source = Counter(by_id[rid]["source"] for rid in strict_uncovered)
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
                "strict_uncovered": by_source[source],
                "old_db_uncovered": by_source_old_uncovered[source],
                "newly_uncovered_from_old_covered": by_source_newly_uncovered[source],
                "newly_covered_from_old_uncovered": by_source_rescued[source],
            }
            for source in sorted(by_source)
        },
        "rule_ids": [row["rule_id"] for row in source_rows],
        "rows": source_rows,
    }


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument(
        "--output",
        default=str(OUTPUTS / "strict_audited_uncovered_20260718" / "domain_rule_ids.json"),
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
    print(json.dumps(data["strict_native_coverage_counts"], indent=2, ensure_ascii=False))
    print(f"wrote {out_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
