# Experiment: CICAS new-lint corpus scan

Exploratory, report-only scans over external certificate corpora such as CT-log
samples or Tranco-derived TLS certificates. This directory is intentionally
separate from `experiments/cert_detection/`, which is the SAIV gate over zlint
testdata.

The retained `ct_recent` and `tranco_1m` outputs are used by Paper §8.4 as
external-corpus evidence. Raw `cicasgen_` hits are still inspection candidates
only; paper-facing issue counts come from `strict_reportable_findings.jsonl`
after the no-upstream independent structural audit.

The report answers: which findings came from CICAS-added zlint lints
(`cicasgen_`), and which came from upstream zlint?

## Run

```
python3 cicas_backend/experiments/cert_detection/run.py \
  --certs /path/to/flat-pem-corpus \
  --independent-audit-scope no-upstream
```

Default output:

```
experiments/new_lint_corpus_scan/outputs/<corpus-name>/
```

Key files:

- `new_lint_findings.jsonl` / `new_lint_findings.md` — problems detected by the
  CICAS-added zlint lints, with rule id, section, rule text, upstream-overlap,
  and independent structural-check evidence when implemented.
- `upstream_findings.jsonl` — upstream zlint findings kept separate.
- `new_lint_by_lint.json` — per-`cicasgen_` lint rollup.
- `detection_summary.json` — corpus-level counts.
- `strict_reportable_findings.jsonl` — paper-facing strict confirmed findings.
- `no_upstream_independent_audit*.json*` — independent audit ledger/summary for
  CICAS findings on certificates with no upstream zlint finding.

Input corpus convention: a flat directory of `*.pem` certificates. For CT or
Tranco collection, keep acquisition metadata outside this directory or in a
parallel manifest so the scanner sees only PEM files.

Retained input/output pairs have been rerun with the current 91-lint strict
shipping manifest and the compiled in-tree `cicasgen_` zlint binary:

- `inputs/ct_recent/` -> `outputs/ct_recent/`
- `inputs/tranco_1m/` -> `outputs/tranco_1m/`

Current retained strict-shipping scan result:

- `ct_recent`: 63,327 certs scanned; 57,558 CICAS findings; 283 no-upstream
  findings independently audited; 1 strict reportable finding.
- `tranco_1m`: 47,791 certs scanned; 44,020 CICAS findings; 1,316 no-upstream
  findings independently audited; 6 strict reportable findings.

Strict reportable here means: CICAS-generated lint fired, no upstream zlint lint
fired on the same certificate, and the independent structural auditor confirmed
the specific defect. Findings are not removed because of certificate issuance
time; time/effective-date questions are treated as audit context, not a reporting
filter.

Probe, smoke, generic overwritten `outputs/certs/`, and older corpus runs are
intentionally not kept.

## Collection notes

- `collect_tranco_tls.py` now saves the TLS leaf plus any certificates sent in
  the live server chain by default (`openssl s_client -showcerts`). Use
  `--leaf-only` only when you explicitly need the old subscriber-only corpus.
- `collect_ct_log.py` saves the logged x509/precert object and, by default, the
  issuer chain certificates found in CT `extra_data`. Use `--no-chain` to disable
  that.
- When scanning a `.../<corpus>/certs` directory, the default output directory is
  `outputs/<corpus>/`, not `outputs/certs/`, so Tranco and CT runs no longer
  overwrite each other.
