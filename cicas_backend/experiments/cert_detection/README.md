# Experiment: certificate detection as a SAIV gate

This experiment scans zlint testdata with the augmented zlint binary and
separates upstream findings from CICAS-generated `cicasgen_` findings.

## Archived 87-Lint Snapshot

This directory retains a historical certificate-detection run. It is not the
current paper-facing result. The current strict code-generation result is
recorded under
`experiments/codegen_metrics/outputs/strict_no_hardcode_20260717/` and has 29
unanimous shipping lints. No new certificate-scan claim is made in the paper
until a scan is rerun from that strict manifest.

The archived run is retained under
`outputs/current_87_20260716_fixed_rsa/`. It was generated from the
then-current 87-lint unanimous shipping manifest; it is not a current
`codegen_metrics` result:

| metric | value |
|---|---:|
| shipped `cicasgen_` lints | 87 |
| zlint testdata certs scanned | 1128 |
| `cicasgen_` findings | 1794 |
| triage REAL | 1741 |
| weak-oracle triage SPURIOUS | 29 |
| triage UNCERTAIN | 24 |
| uncertain confirmed real | 2 |
| independent CONFIRMED | 320 |
| independent REFUTED | 0 |
| independent NOCHECK | 1474 |
| unresolved weak-oracle SPURIOUS | 25 |
| verified novel source problems | 0 |

`REFUTED=0` only says that the implemented structural auditor did not refute a
finding. Paper-facing external claims additionally use the shipping-manifest
source/code review and the no-native-result audit below; `NOCHECK` rows remain
unverified rather than clean.

## Targeted Re-Extraction

Only the problematic extraction/codegen rules should be re-extracted, not the
full corpus:

```bash
python scripts/reextract_specific_rules.py --problem-rules --dry-run
python scripts/reextract_specific_rules.py --problem-rules --commit
```

The retained historical targeted re-extraction set for this detection work was:

```text
29324, 29325, 29339, 29342, 29343, 29375, 29415, 29493,
29539, 29735, 31065, 31102, 31349, 31400
```

After successful re-extraction, the script clears the old coverage cache for
those rules so a subsequent incremental coverage run can rejudge only changed
rows.

## Run

Recompute coverage after the deterministic native-coverage fix:

```bash
# via API, or the existing recompute script/route in your setup
# important: rerun coverage before regenerating codegen manifests
```

Build or refresh the shipped manifest after coverage/codegen has been recomputed
and strict shipping synonymy has been judged:

```bash
python cicas_backend/experiments/codegen_metrics/run_codegen_synonymy.py \
  --standards all --run-name strict_no_hardcode_20260717 --summary-only
python cicas_backend/scripts/inject_and_build.py --emit --build
```

Run the paper-facing testdata gate:

```bash
python cicas_backend/experiments/cert_detection/run.py \
  --output-dir cicas_backend/experiments/cert_detection/outputs/current_87_20260716_fixed_rsa
```

Expected behavior today: the command writes all outputs, then exits non-zero
while unresolved weak-oracle `SPURIOUS` rows remain. Those rows are excluded
from strict paper-facing claims.

Derive and cross-check every Paper §8.4 count from the retained outputs:

```bash
python cicas_backend/experiments/cert_detection/audit_claimed_findings.py
python cicas_backend/experiments/cert_detection/verify_paper_counts.py
```

External CT/Tranco-style corpus scans are report-only:

```bash
python cicas_backend/experiments/cert_detection/run.py \
  --certs /path/to/flat-pem-corpus \
  --independent-audit-scope no-upstream
```

## Outputs

- `inputs/cicasgen_manifest.json`: shipped-lint manifest from codegen outputs.
- `outputs/detection_summary.json`: machine-readable summary.
- `outputs/detection_summary.md`: rendered result.
- `outputs/strict_reportable_findings.jsonl`: conservative paper-facing findings.
- `outputs/audit_independent.jsonl`: independent structural audit for all
  post-gate findings.
- `outputs/current_87_20260716_fixed_rsa/paper_counts.json`: consolidated
  paper-facing counts derived by `verify_paper_counts.py`.
- `outputs/current_87_20260716_fixed_rsa/claimed_finding_audit/`: reproducible
  DER/novelty audit used for Paper §8.4. It intentionally excludes issuance-time
  applicability in the current audit round.
- `outputs/triage_by_lint.json`: per-lint firing and triage counts.
- `outputs/uncertain_verified.jsonl`: reverse-check result for UNCERTAIN
  findings.
- `outputs/blame.jsonl`: SAIV feedback ledger when DB access is available.
