# Experiment: lint coverage analysis  →  Paper §8.2 (Table 2)

**Question.** Of the system's lint-able rules, how many are already implemented by a
*same-source* zlint lint (full coverage), and how many remain as the code-generation
domain φ_G (uncovered)?

## Experiment Runs

### Run 1 (2026-07-02): 跨标准覆盖分析

**发现**：CABF BR的很多规则"derived from RFC 5280"（如§7.1.2章节），但zlint实现时这些lint被标记为RFC 5280 source。原始算法只在CABF lint池中查找，系统性漏判了RFC 5280 lint对CABF规则的覆盖。

**修改**：让CABF规则同时匹配CABF和RFC 5280的lint（`_coverage_candidates`函数）。

**结果**：
- 所有226条CABF规则的候选数量从170→357（+187个RFC lint）
- 等待重新判断覆盖，预期CABF覆盖率会提升

详见：`RUN1_NOTES.md` 和 `outputs/run1_comparison.md`

---

**Baseline (修改前).**

| | CABF | RFC 5280 | total |
|---|---:|---:|---:|
| lint-able rules | 226 | 93 | **319** |
| full (covered by a same-source zlint lint) | 79 | 50 | **129** |
| judged uncovered (= codegen domain) | 147 | 43 | **190** |
| *zlint same-source certificate lints (reference denominator)* | *164* | *115* | *279* |
| *CRL lints (outside denominator)* | *6* | *7* | *13* |

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
Locally generated `cicasgen_*` lints are excluded from the native zlint reference row.

## Inputs (`inputs/`)
- `lintable_rules.jsonl` — lint-able rules with their stored verdict (DB snapshot).
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
> published table. The codegen rate / synonymy rate over the judged uncovered rules are **system
> metrics** — see `cicas_backend/scripts/system_metrics/`, not an experiment.
