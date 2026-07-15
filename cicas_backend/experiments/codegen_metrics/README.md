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
| codegen domain | 101 |
| generated | 101 / 101 = 100.0% |
| deterministic generated | 98 |
| LLM generated | 3 |
| paper-facing unanimous EXPRESS synonymy | 87 / 101 = 86.1% generated; 87 / 101 = 86.1% domain |
| non-unanimous but 80% EXPRESS diagnostic | 6 |
| final emitted code DOES_NOT_EXPRESS | 8 |
| final emitted code uncertain | 0 |
| final-shipping rejudge errors | 0 |
| generation failures | 0 |
| shipping compile verification | 87 / 87 passed |

By source:

| source | domain | generated | unanimous EXPRESS |
|---|---:|---:|---:|
| CABF-BR | 76 | 76 | 64 |
| RFC5280 | 25 | 25 | 23 |

Atom genericity over paper-facing unanimous EXPRESS rows:

| atom usage | rules | share of 87 |
|---|---:|---:|
| GENERIC-only | 54 | 62.1% |
| GENERIC + NON_GENERIC | 4 | 4.6% |
| containing GENERIC | 58 | 66.7% |
| NON_GENERIC-only | 29 | 33.3% |
| unknown | 0 | 0.0% |

By source:

| source | unanimous EXPRESS | GENERIC-only | GENERIC + NON_GENERIC | containing GENERIC | NON_GENERIC-only |
|---|---:|---:|---:|---:|---:|
| CABF-BR | 64 | 36 (56.3%) | 4 (6.3%) | 40 (62.5%) | 24 (37.5%) |
| RFC5280 | 23 | 18 (78.3%) | 0 (0.0%) | 18 (78.3%) | 5 (21.7%) |

Registered DSL atom templates (`summary.atom_registry`): 137 total = 83
GENERIC + 54 NON_GENERIC.

`final-shipping` names the judged object: the final emitted in-tree zlint lint
(`CheckApplies` + `Execute` + severity/date metadata), rather than the row-level
IR fragment. The paper-facing synonymy numerator is stricter: every judge must
vote EXPRESS. The older 80% EXPRESS gate is retained only as a diagnostic JSON
field (`final_shipping_strict_*` and `atom_genericity_80pct_expresses`) for
extraction/codegen debugging.

`shipping_lints_manifest.*` and the compatibility alias
`synonymous_lints_manifest.*` both list the 87 paper-facing unanimous lints.
Row-level diagnostic EXPRESS rows are written separately to
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

Current generation residual: none.

Current non-unanimous / `DOES_NOT_EXPRESS` residuals:

Non-unanimous 80% EXPRESS diagnostics, not counted as synonymous and not in the
shipping manifest: R29257, R29409, R29544, R29562, R29766, R31344.

- R29478: the "Any other attribute NOT RECOMMENDED" row is now generated from a
  source-table-derived Subject DN AttributeType allow-list, but it did not pass
  the unanimous final-shipping synonymy gate and is therefore not in the shipping
  manifest.
- R29279: generated code checks CRL Distribution Points presence rather than
  requiring each `fullName` to contain at least one `GeneralName`.
- R29669 and R29670: generated code forbids `commonName` presence, but the rule
  says that if present it must be derived from `subjectAltName`.
- R29791: generated code covers only dNSName/iPAddress SAN values, not the full
  "one of the values contained in subjectAltName" requirement.
- R29802: IPv6 commonName RFC 5952 requirement was rendered as an IPv4 dotted
  decimal check.
- R30022: `anyPolicy` is profile/context-sensitive; the generated predicate is
  too generic.
- R31088: generated code forbids any `rfc822Name` presence rather than only an
  empty `rfc822Name`.

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
