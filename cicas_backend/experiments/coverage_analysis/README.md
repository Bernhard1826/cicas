# Experiment: lint coverage analysis  →  Paper §8.2 (Table 2)

**Question.** Of the system's lint-able rules, how many are already implemented by
a native zlint lint, and how many remain as the code-generation domain φ_G
(uncovered)?

## Current Result

From `outputs/coverage_table.{json,md}`:

| | CABF | RFC 5280 | total |
|---|---:|---:|---:|
| lint-able rules | 170 | 79 | **249** |
| full native zlint coverage | 106 | 52 | **158** |
| judged uncovered (= codegen domain) | 64 | 27 | **91** |
| pending coverage | 0 | 0 | **0** |
| *native zlint certificate lints (reference denominator)* | *164* | *115* | *279* |
| *CRL lints (outside denominator)* | *6* | *7* | *13* |

CABF-BR rules may be covered by native RFC5280 zlint lints when the RFC lint
logically covers the CABF requirement. This is intentional: the table measures
native zlint coverage, not same-source-only coverage.

## Method
The per-rule coverage verdict (`full` / `partial` / `none`) is produced by the **backend
coverage service**, not by this script:
- candidate retrieval by source/section (CABF-BR also considers RFC5280 lints);
- a field-level LLM judge over subject / obligation / predicate / constraint;
- a deterministic "wrong-field" consistency gate that only downgrades.

See `app/services/certificate/zlint_interface.py` and
`app/api/zlint_analysis_routes.py` (`check_batch_coverage`). Verdicts are persisted on
`rules.lint_coverage` (JSON `{verdict, reason}`) and `rules.lint_covered` (bool).

`run.py` **aggregates** those persisted verdicts into Table 2 and **recomputes** the native zlint
reference counts directly from the bundled zlint v3 Go source
(`zlint/v3/lints`, `Source:` metadata; CRL split via `RegisterRevocationListLint`).
Locally generated `cicasgen_*` lints are excluded from the native zlint reference row.

## Inputs (`inputs/`)
- `lintable_rules.jsonl` — lint-able rules with their stored verdict (DB snapshot).
- `zlint_lint_catalog.json` — zlint v3 lint counts by Source (reference row).
- `lint_ir_summaries.json` — reverse-IR summaries of upstream zlint certificate
  lints, used by the backend coverage judge and the `zlint_lint_dsl` migration.

## Outputs (`outputs/`)
- `coverage_table.{json,md}` — Table 2.
- `per_rule_coverage.jsonl` — per-rule full/none verdict.

## Run
```bash
python3 cicas_backend/experiments/coverage_analysis/run.py            # aggregate + render Table 2
python3 cicas_backend/experiments/coverage_analysis/run.py --snapshot # also refresh inputs/ from DB+source
```
DB defaults to `postgresql://postgres:123456@localhost:15432/cicas` (override `CICAS_DB_URL`).

> Coverage **computation** is system logic in the backend; this directory only re-derives the
> published table. Use `recompute_coverage.py --only-pending` or
> `recompute_coverage.py --only-uncovered` only after changing the backend coverage
> matcher.
