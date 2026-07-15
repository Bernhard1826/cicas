# Experiment: certificate detection as a SAIV gate

This experiment scans zlint testdata with the augmented zlint binary and
separates upstream findings from CICAS-generated `cicasgen_` findings.

## Current Status

Retained fixed run (`outputs/detection_summary.{json,md}`). This is a 90-lint
detection snapshot and was not rerun for the current 93-lint strict shipping
manifest used by `experiments/codegen_metrics/`:

| metric | value |
|---|---:|
| shipped `cicasgen_` lints | 90 |
| zlint testdata certs scanned | 1128 |
| `cicasgen_` findings | 2627 |
| triage REAL | 2469 |
| weak-oracle triage SPURIOUS | 133 |
| triage UNCERTAIN | 25 |
| uncertain confirmed real | 2 |
| independent CONFIRMED | 299 |
| independent REFUTED | 0 |
| independent NOCHECK | 2328 |
| unresolved weak-oracle SPURIOUS | 129 |
| strict reportable findings | 0 |

The current run is clean under the hard independent-audit contradiction
criterion (`REFUTED=0`). Paper-facing claims should use only independently
confirmed findings, or explicitly label the remaining `NOCHECK` rows as not
structurally audited.

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
  --standards all --run-name full_current_db --summary-only
python cicas_backend/scripts/inject_and_build.py --emit --build
```

Run the testdata gate:

```bash
python cicas_backend/experiments/cert_detection/run.py
```

Expected behavior today: the command writes all outputs, then exits non-zero
while unresolved weak-oracle `SPURIOUS` rows remain. Those rows are excluded
from strict paper-facing claims.

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
- `outputs/triage_by_lint.json`: per-lint firing and triage counts.
- `outputs/uncertain_verified.jsonl`: reverse-check result for UNCERTAIN
  findings.
- `outputs/blame.jsonl`: SAIV feedback ledger when DB access is available.
