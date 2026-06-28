# Experiment: lint coverage analysis  →  Paper §8.2 (Table 2)

**Question.** Of the system's lint-able rules, how many are already implemented by a
*same-source* zlint lint (full coverage), and how many remain as the code-generation
domain φ_G (uncovered)?

**Result (current snapshot).**

| | CABF | RFC 5280 | total |
|---|---:|---:|---:|
| lint-able rules | 227 | 109 | **336** |
| full (covered by a same-source zlint lint) | 79 | 53 | **132** |
| uncovered (= codegen domain) | 148 | 56 | **204** |
| *zlint same-source lints (reference)* | *170* | *122* | *292* |

## Method
The per-rule coverage verdict (`full` / `partial` / `none`) is produced by the **backend
coverage service**, not by this script:
- candidate retrieval by source/section (no embeddings);
- a field-level LLM judge over subject / obligation / predicate / constraint;
- a deterministic "wrong-field" consistency gate that only downgrades.

See `app/services/certificate/zlint_interface.py` and
`app/api/zlint_analysis_routes.py` (`check_batch_coverage`). Verdicts are persisted on
`rules.lint_coverage` (JSON `{verdict, reason}`) and `rules.lint_covered` (bool).

`run.py` **aggregates** those persisted verdicts into Table 2 and **recomputes** the zlint
same-source reference counts directly from the bundled zlint v3 Go source
(`zlint/v3/lints`, `Source:` metadata; CRL split via `RegisterRevocationListLint`).

## Inputs (`inputs/`)
- `lintable_rules.jsonl` — the 336 lint-able rules with their stored verdict (DB snapshot).
- `zlint_lint_catalog.json` — zlint v3 lint counts by Source (reference row).

## Outputs (`outputs/`)
- `coverage_table.{json,md}` — Table 2.
- `per_rule_coverage.jsonl` — per-rule full/none verdict.

## Run
```bash
python experiments/coverage_analysis/run.py            # aggregate + render Table 2
python experiments/coverage_analysis/run.py --snapshot # also refresh inputs/ from DB+source
```
DB defaults to `postgresql://postgres:123456@localhost:15432/cicas` (override `CICAS_DB_URL`).

> Coverage **computation** is system logic in the backend; this directory only re-derives the
> published table. The codegen rate / synonymy rate over the 204 uncovered rules are **system
> metrics** — see `cicas_backend/scripts/system_metrics/`, not an experiment.
