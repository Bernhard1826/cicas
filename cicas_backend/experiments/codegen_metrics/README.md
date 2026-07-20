# Code Generation And Synonymy Metrics

This directory is the figures-of-record ledger for deterministic/LLM DSL
generation and LLM synonymy judging over the current codegen domain:

```text
explicit strict-uncovered rule-id domain from
outputs/strict_audited_uncovered_20260718/domain_rule_ids.json
```

The domain is downstream of `coverage_analysis/`.  The current paper-facing
domain combines the current DB lintable coverage snapshot with the 2026-07-18
strict native-zlint coverage audit; it does not mutate DB `lint_covered`.

## Current Result

The paper-facing current run is
`outputs/strict_audited_uncovered_20260718/codegen_synonymy_summary.json`.
Registered `NON_GENERIC` atoms are allowed in generation but are reported
separately from `GENERIC` atoms; unknown atoms are rejected and must remain zero.

Strict native coverage domain:

| metric | value |
|---|---:|
| lintable with computed coverage | 264 |
| old DB native covered | 191 |
| old DB uncovered | 73 |
| strict native covered after audit | 165 |
| strict codegen domain | 99 |
| newly uncovered from old covered | 45 |
| newly covered from old uncovered | 19 |

| metric | value |
|---|---:|
| codegen domain | 99 |
| generated | 90 / 99 = 90.9% |
| deterministic generated | 86 |
| LLM generated | 4 |
| generation failures | 9: 9 `no_template` |
| paper-facing unanimous EXPRESS synonymy | 77 / 90 = 85.6% generated; 77 / 99 = 77.8% domain |
| non-unanimous but 80% EXPRESS diagnostic | 3 |
| final emitted code DOES_NOT_EXPRESS | 8 |
| final emitted code uncertain | 2 |
| final emitted code not judged | 0 |
| final-shipping rejudge errors | 0 |
| shipping compile verification | 77 / 77 passed |

By source:

| source | domain | generated | unanimous EXPRESS |
|---|---:|---:|---:|
| CABF-BR | 84 | 78 | 65 |
| RFC5280 | 15 | 12 | 12 |

Atom genericity over all generated rows:

| atom usage | rules | share of 90 |
|---|---:|---:|
| GENERIC-only | 70 | 77.8% |
| GENERIC + NON_GENERIC | 4 | 4.4% |
| containing GENERIC | 74 | 82.2% |
| NON_GENERIC-only | 16 | 17.8% |
| unknown | 0 | 0.0% |

Atom genericity over paper-facing unanimous EXPRESS rows:

| atom usage | rules | share of 77 |
|---|---:|---:|
| GENERIC-only | 58 | 75.3% |
| GENERIC + NON_GENERIC | 4 | 5.2% |
| containing GENERIC | 62 | 80.5% |
| NON_GENERIC-only | 15 | 19.5% |
| unknown | 0 | 0.0% |

By source:

| source | unanimous EXPRESS | GENERIC-only | GENERIC + NON_GENERIC | containing GENERIC | NON_GENERIC-only |
|---|---:|---:|---:|---:|---:|
| CABF-BR | 65 | 48 (73.8%) | 4 (6.2%) | 52 (80.0%) | 13 (20.0%) |
| RFC5280 | 12 | 10 (83.3%) | 0 (0.0%) | 10 (83.3%) | 2 (16.7%) |

Registered DSL atom templates (`summary.atom_registry`): 149 total = 95
GENERIC + 54 NON_GENERIC. `generic_only_audit.json` is retained as the
compatibility audit filename; its current contents verify the generated-row atom
split above and that unknown atoms are zero.

`final-shipping` names the judged object: the final emitted in-tree zlint lint
(`CheckApplies` + `Execute` + severity/date metadata), rather than the row-level
IR fragment. The paper-facing synonymy numerator is stricter: every judge must
vote EXPRESS. The older 80% EXPRESS gate is retained only as a diagnostic JSON
field (`final_shipping_strict_*` and `atom_genericity_80pct_expresses`) for
extraction/codegen debugging.

`shipping_lints_manifest.*` and the compatibility alias
`synonymous_lints_manifest.*` both list the 77 paper-facing unanimous lints.
Row-level diagnostic EXPRESS rows are written separately to
`diagnostic_row_level_lints_manifest.*` and are not a synonymy numerator.

## Run

Aggregate the existing ledger without calling LLMs:

```bash
python3 cicas_backend/experiments/codegen_metrics/run_codegen_synonymy.py \
    --standards all --run-name strict_audited_uncovered_20260718 \
    --domain-rule-ids cicas_backend/experiments/codegen_metrics/outputs/strict_audited_uncovered_20260718/domain_rule_ids.json \
    --summary-only
```

Resume only missing rows:

```bash
python3 cicas_backend/experiments/codegen_metrics/run_codegen_synonymy.py \
    --standards all --run-name strict_audited_uncovered_20260718 \
    --domain-rule-ids cicas_backend/experiments/codegen_metrics/outputs/strict_audited_uncovered_20260718/domain_rule_ids.json
```

Retry only generation failures after a codegen fix:

```bash
python3 cicas_backend/experiments/codegen_metrics/run_codegen_synonymy.py \
    --standards all --run-name strict_audited_uncovered_20260718 \
    --domain-rule-ids cicas_backend/experiments/codegen_metrics/outputs/strict_audited_uncovered_20260718/domain_rule_ids.json \
    --retry-generation-failures
```

Retry only non-synonymous generated rows after an extraction/scope fix:

```bash
python3 cicas_backend/experiments/codegen_metrics/run_codegen_synonymy.py \
    --standards all --run-name strict_audited_uncovered_20260718 \
    --domain-rule-ids cicas_backend/experiments/codegen_metrics/outputs/strict_audited_uncovered_20260718/domain_rule_ids.json \
    --retry-dne
```

Rejudge final in-tree zlint semantics after a strict-judge or renderer-summary
fix:

```bash
python3 cicas_backend/experiments/codegen_metrics/run_codegen_synonymy.py \
    --standards all --run-name strict_audited_uncovered_20260718 \
    --domain-rule-ids cicas_backend/experiments/codegen_metrics/outputs/strict_audited_uncovered_20260718/domain_rule_ids.json \
    --rejudge-shipping --rejudge-shipping-all
```

Use `--rule-id <id>` with either retry mode for targeted runs.
Use `--force-rule-id --rule-id <id>` only when a renderer/codegen bug affects an
already-complete row and the lint needs to be regenerated without a full rerun.

After targeted retries, compact the ledger so the output remains one current
domain row per rule and rendered Go files stay aligned with the manifest:

```bash
python3 cicas_backend/experiments/codegen_metrics/run_codegen_synonymy.py \
    --standards all --run-name strict_audited_uncovered_20260718 \
    --domain-rule-ids cicas_backend/experiments/codegen_metrics/outputs/strict_audited_uncovered_20260718/domain_rule_ids.json \
    --compact-ledger
```

Verify the paper's headline metrics against the coverage table, current
summary, atom-class audit, and isolated compile result:

```bash
python3 cicas_backend/experiments/codegen_metrics/verify_paper_metrics.py
```

## Residuals

Current generation residual: 9 rows, all retained in the denominator. All nine
are `no_template`. No endpoint errors remain.

Current non-unanimous / `DOES_NOT_EXPRESS` residuals:

Current shipping residuals: 3 non-unanimous 80% EXPRESS diagnostics, 8 final
emitted-code DOES_NOT_EXPRESS rows, 2 uncertain rows, and 0 generated rows
without a final shipping verdict. These rows are not counted in the
paper-facing synonymy numerator.

R31068 (RFC5280 §4.2.1.6) was re-adjudicated through the lintability path as not
lintable: the rule requires recognizing that a semantic Internet mail address
should have been encoded as the `rfc822Name` GeneralName choice, while a single
certificate only exposes the tag that was chosen and its value.

R31065 (RFC5280 §4.2.1.6) and R30970 (RFC5280 §4.2.1.9) were also removed only
through re-extraction/re-adjudication, not by metric filtering. R31065 depends on
the external semantic condition that the only subject identity is an alternative
name form; R30970 depends on a CA-role premise that cannot be independently
observed when the BasicConstraints extension whose presence is being checked is
absent.

Any future denominator reduction must come from re-extraction and lintability
re-adjudication, not from local metric filters. In particular, non-single-
certificate rules must be re-extracted/reclassified as not lintable before they
leave the denominator. `check_scope` is legacy and does not participate in
lintability.
