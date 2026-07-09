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
| codegen domain | 90 |
| generated | 90 / 90 = 100.0% |
| deterministic generated | 87 |
| LLM generated | 3 |
| final-shipping strict EXPRESS | 90 / 90 = 100.0% |
| final-shipping strict DOES_NOT_EXPRESS | 0 |
| final-shipping strict uncertain | 0 |
| final-shipping rejudge errors | 0 |
| final-shipping unanimous EXPRESS | 84 / 90 = 93.3% |
| generation failures | 0 |

By source:

| source | domain | generated | final-shipping strict EXPRESS |
|---|---:|---:|---:|
| CABF-BR | 64 | 64 | 64 |
| RFC5280 | 26 | 26 | 26 |

Atom genericity over final-shipping strict EXPRESS rows:

| atom usage | rules |
|---|---:|
| GENERIC-only | 53 |
| GENERIC + NON_GENERIC | 5 |
| NON_GENERIC-only | 32 |
| unknown | 0 |

`final-shipping strict` is the current paper-facing synonymy gate: the final
emitted in-tree zlint lint (`CheckApplies` + `Execute` + severity/date metadata)
is judged against the original rule text plus source-owned context, and passes
when at least `ceil(0.8*k)` judge votes are EXPRESS. It is not a unanimity
metric. Row-fragment synonymy is retained only in the JSON ledger as a diagnostic
for extraction/codegen debugging.

`shipping_lints_manifest.*` and the compatibility alias
`synonymous_lints_manifest.*` both list the 90 paper-facing final-shipping
strict lints. Row-level diagnostic EXPRESS rows are written separately to
`diagnostic_row_level_lints_manifest.*` and are not a synonymy numerator.

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

There are no current final-shipping strict residuals in the codegen domain.
R31068 (RFC5280 §4.2.1.6) was re-adjudicated through the lintability path as not
lintable: the rule requires recognizing that a semantic Internet mail address
should have been encoded as the `rfc822Name` GeneralName choice, while a single
certificate only exposes the tag that was chosen and its value.

Any future denominator reduction must come from re-extraction and lintability
re-adjudication, not from local metric filters. In particular, non-single-
certificate rules must be re-extracted/reclassified as not lintable before they
leave the denominator. `check_scope` is legacy and does not participate in
lintability.
