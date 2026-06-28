# Experiment: lintability external validation  →  Paper §8.4 (TABLE III)

**Question.** Do CICAS's lint-ability verdicts agree with an *independent* third-party
gold standard — the zlint maintainers' public CABF BR mapping sheets — across two BR
versions (1.4.8 and 2.0.2)?

**Result (figures of record).**

| version | sheet rows (Yes/No) | backend | recall | TP/FN/FP/TN | agree | κ | P | F1 |
|---|---:|---:|---:|:--:|---:|---:|---:|---:|
| BR 1.4.8 | 122 (75/47) | 422 | 86.9% | 60/9/0/37 | 91.5% | **0.823** | 1.000 | 0.930 |
| BR 2.0.2 | 250 (17/233) | 1024 | 86.8% | 6/6/1/204 | 96.8% | **0.616** | 0.857 | 0.632 |

The two versions match on recall (~87%) but differ in κ: BR 2.0.2's sheet is heavily
No-skewed (6.8% Yes), so its high raw agreement is inflated by class imbalance and κ gives
the more honest read.

## Method
Per sheet row, the maintainer marks lint-scope (Yes/No); CICAS marks whether its
same-clause backend rule is lint-able. The confusion matrix + Cohen's κ are computed over
the **matched** rows (sheet clause routed to a backend rule in the same BR section). The
matched-only view is the figure of record.

## Reproducibility note
The raw third-party inputs are **not retained in-repo**: the maintainer sheets
(`zlint_cabf_br_*.csv`) and the two version-specific backends (CABF-Server-1.4.8 = 422
rules, CABF-Server-2.0.2 = 1024 rules) lived in the now-retired `pki_standards` DB. What is
retained is the **per-row judgment ledger** (sheet label + matched-backend lint-ability
label) under `inputs/`, recovered from the original run. `run.py` recomputes TABLE III
deterministically from that ledger, so the result reproduces without the external artifacts.

## Inputs (`inputs/`)
- `br148_judgments.jsonl` — 122 rows `{row, section, sheet, backend, note}`.
- `br202_judgments.jsonl` — 250 rows, same schema. **These are what `run.py` consumes.**
  - `sheet`: 1 = maintainer Yes/in-scope, 0 = No/out-of-scope.
  - `backend`: 1 = CICAS lint-able, 0 = non-lint-able, `null` = no backend match.
- `cabf_br_1_4_8.md`, `cabf_br_2_0_2.md` — the CA/Browser Forum Baseline Requirements
  **source specifications** for the two validated versions. Provenance only (the clauses the
  judgment ledgers refer to, and the documents the version-specific backends were extracted
  from). They are *not* the maintainer mapping sheet and are not read by `run.py`.

## Outputs (`outputs/`)
- `br148_validation.json`, `br202_validation.json` — per-version metrics.
- `table3.md` — TABLE III.

## Run
```bash
python experiments/external_validation/run.py
```
`run.py` asserts the recorded κ values (0.823 / 0.616) so any drift is caught.
