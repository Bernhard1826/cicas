# Code Generation And Synonymy Metrics

This directory is the figures-of-record ledger for deterministic/LLM DSL
generation and LLM synonymy judging over the current codegen domain:

```text
standard_id in {CABF-BR, RFC5280}
AND lintable
AND lint_coverage IS NOT NULL
AND lint_covered = false
```

The domain is downstream of `coverage_analysis/`; rerun coverage first whenever
native zlint coverage changes.

## Current Result

From `outputs/full_current_db/codegen_synonymy_summary.json`:

| metric | value |
|---|---:|
| codegen domain | 91 |
| generated | 91 / 91 = 100.0% |
| deterministic generated | 87 |
| LLM generated | 4 |
| final-shipping strict EXPRESS | 91 / 91 = 100.0% |
| final-shipping strict uncertain | 0 |
| generation failures | 0 |

By source:

| source | domain | generated | final-shipping strict EXPRESS |
|---|---:|---:|---:|
| CABF-BR | 64 | 64 | 64 |
| RFC5280 | 27 | 27 | 27 |

`final-shipping strict` is the paper-facing synonymy metric: the final emitted
in-tree zlint lint (`CheckApplies` + `Execute` + severity/date metadata) is
judged against the original rule text plus source-owned context. Row-fragment
synonymy is not a paper-facing metric; it is retained only in the JSON ledger as
a diagnostic for extraction/codegen debugging.

## Run

Aggregate the existing ledger without calling LLMs:

```bash
python3 cicas_backend/experiments/codegen_metrics/run_codegen_synonymy.py \
  --standards all --run-name full_current_db --summary-only
```

Resume only missing rows:

```bash
python3 cicas_backend/experiments/codegen_metrics/run_codegen_synonymy.py \
  --standards all --run-name full_current_db
```

Retry only generation failures after a codegen fix:

```bash
python3 cicas_backend/experiments/codegen_metrics/run_codegen_synonymy.py \
  --standards all --run-name full_current_db --retry-generation-failures
```

Retry only non-synonymous generated rows after an extraction/scope fix:

```bash
python3 cicas_backend/experiments/codegen_metrics/run_codegen_synonymy.py \
  --standards all --run-name full_current_db --retry-dne
```

Rejudge final in-tree zlint semantics after a strict-judge or renderer-summary
fix:

```bash
python3 cicas_backend/experiments/codegen_metrics/run_codegen_synonymy.py \
  --standards all --run-name full_current_db --rejudge-shipping --rejudge-shipping-all
```

Use `--rule-id <id>` with either retry mode for targeted runs.
Use `--force-rule-id --rule-id <id>` only when a renderer/codegen bug affects an
already-complete row and the lint needs to be regenerated without a full rerun.

After targeted retries, compact the ledger so the output remains one current
domain row per rule and rendered Go files stay aligned with the manifest:

```bash
python3 cicas_backend/experiments/codegen_metrics/run_codegen_synonymy.py \
  --standards all --run-name full_current_db --compact-ledger
```

## Residuals

There are no current final-shipping strict residuals in the codegen domain:
91/91 generated lints are strict-synonymous with the original rule text/context.

Any future denominator reduction must come from re-extraction and lintability
re-adjudication, not from local metric filters. In particular, non-single-
certificate rules must be re-extracted/reclassified as not lintable before they
leave the denominator. `check_scope` is legacy and does not participate in
lintability.
