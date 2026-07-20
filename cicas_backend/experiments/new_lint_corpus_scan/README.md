# Experiment: CICAS new-lint corpus scan

Exploratory, report-only scans over external certificate corpora such as CT-log
samples or Tranco-derived TLS certificates. This directory is intentionally
separate from `experiments/cert_detection/`, which is the SAIV gate over zlint
testdata.

The `ct_recent` and `tranco_1m` outputs are retained under
`outputs/current_87_20260716_fixed_rsa/` as external-corpus evidence. Raw
`cicasgen_` hits and the legacy-named `strict_reportable_findings.jsonl` are
inspection candidates only. Final paper claims come from
`cert_detection/audit_claimed_findings.py`, which combines the shipping-manifest
source/code review with DER confirmation and semantic novelty.

The report answers: which findings came from CICAS-added zlint lints
(`cicasgen_`), and which came from upstream zlint?

## Run

```bash
python cicas_backend/experiments/cert_detection/run.py \
  --certs cicas_backend/experiments/new_lint_corpus_scan/inputs/tranco_1m/certs \
  --output-dir cicas_backend/experiments/new_lint_corpus_scan/outputs/current_87_20260716_fixed_rsa/tranco_1m \
  --independent-audit-scope no-upstream \
  --workers 16 --progress-every 10000

python cicas_backend/experiments/cert_detection/run.py \
  --certs cicas_backend/experiments/new_lint_corpus_scan/inputs/ct_recent/certs \
  --output-dir cicas_backend/experiments/new_lint_corpus_scan/outputs/current_87_20260716_fixed_rsa/ct_recent \
  --independent-audit-scope no-upstream \
  --workers 16 --progress-every 10000
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
- `strict_reportable_findings.jsonl` — legacy preliminary structural screen;
  not sufficient for paper-facing problem claims.
- `no_upstream_independent_audit*.json*` — independent audit ledger/summary for
  CICAS findings on certificates with no upstream zlint finding.

Input corpus convention: a flat directory of `*.pem` certificates. For CT or
Tranco collection, keep acquisition metadata outside this directory or in a
parallel manifest so the scanner sees only PEM files.

Current input/output pairs:

- `inputs/ct_recent/` -> `outputs/current_87_20260716_fixed_rsa/ct_recent/`
- `inputs/tranco_1m/` -> `outputs/current_87_20260716_fixed_rsa/tranco_1m/`

Retained 87-lint scan result before the final claimed-finding audit:

- `ct_recent`: 63,327 certs scanned; 9,238 CICAS findings; 45 no-upstream
  findings audited; 1 independently confirmed Warn finding, duplicated from Tranco.
- `tranco_1m`: 47,791 certs scanned; 14,581 CICAS findings; 402 no-upstream
  findings audited; 6 independently confirmed findings: 3 Error and 3 Warn.

The rerun also corrected a local zlint RSA compatibility defect. The local
`zcrypto/x509` parser returns `*zcrypto/rsa.PublicKey`, while 19 native RSA lints
had asserted `*crypto/rsa.PublicKey`; this made
`e_rsa_no_public_key` falsely flag normal RSA certificates and suppressed valid
no-upstream candidates. The native lints now use the parser's actual key type,
and `lints/community/lint_rsa_no_public_key_test.go` provides a real-PEM
regression test. Generated `cicasgen_` code and the 87-lint manifest were not
changed by this compatibility fix.

The legacy strict screen means: CICAS-generated lint fired, no upstream zlint
lint fired on the same certificate, and the independent structural auditor
confirmed the specific DER predicate. The final audit retains these rows only
after the shipping-manifest source/code review; it likewise does not filter on
issuance time in this round.

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
