# Experiment: CICAS new-lint corpus scan

Exploratory, report-only scans over external certificate corpora such as CT-log
samples or Tranco-derived TLS certificates. This directory is intentionally
separate from `experiments/cert_detection/`, which is the SAIV gate over zlint
testdata.

These outputs are **not** paper figures of record. Use them for follow-up
inspection only, and rerun after rebuilding zlint from the current
`codegen_metrics/outputs/full_current_db/shipping_lints_manifest.json`.

The report answers: which findings came from CICAS-added zlint lints
(`cicasgen_`), and which came from upstream zlint?

## Run

```
python3 cicas_backend/experiments/cert_detection/run.py --certs /path/to/flat-pem-corpus
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

Input corpus convention: a flat directory of `*.pem` certificates. For CT or
Tranco collection, keep acquisition metadata outside this directory or in a
parallel manifest so the scanner sees only PEM files.

Retained input/output pairs are current inspection artifacts only:

- `inputs/ct_recent/` -> `outputs/ct_recent/`
- `inputs/tranco_1m/` -> `outputs/tranco_1m/`

Current strict-shipping scan result: CT recent has 21 CICAS findings, all
upstream-overlapping and independently confirmed; Tranco has 68 CICAS findings,
including 1 no-upstream finding independently confirmed for rule 29492
(`*.enter-system.com` lacks a CABF reserved policy OID).

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
