# Experiment: certificate detection as a SAIV gate

This experiment scans zlint testdata with the augmented zlint binary and
separates upstream findings from CICAS-generated `cicasgen_` findings.

## Current Status

The current gate is a **failing regression check**, not a paper success result.

Current run (`outputs/detection_summary.{json,md}`), after rebuilding zlint from
the current 53-lint synonymy manifest:

| metric | value |
|---|---:|
| shipped `cicasgen_` lints | 53 |
| zlint testdata certs scanned | 1128 |
| `cicasgen_` findings | 4563 |
| triage REAL | 4149 |
| triage SPURIOUS | 343 |
| triage UNCERTAIN | 71 |
| independent CONFIRMED | 2047 |
| independent REFUTED | 5 |
| independent NOCHECK | 2511 |
| strict reportable findings | 22 |

The script intentionally exits non-zero while `SPURIOUS > 0`. The highest-firing
false-positive sources are over-broad generated lints with missing applicability
guards, especially version/profile checks, PolicyConstraints sub-field checks,
and SAN criticality/presence checks. Fix those upstream in IR extraction/codegen,
then rebuild and rerun this gate.

## Targeted Re-Extraction

Only the problematic extraction/codegen rules should be re-extracted, not the
full corpus:

```bash
python scripts/reextract_specific_rules.py --problem-rules --dry-run
python scripts/reextract_specific_rules.py --problem-rules --commit
```

The current targeted re-extraction set is:

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

Build or refresh the shipped manifest after coverage/codegen has been recomputed:

```bash
python cicas_backend/scripts/inject_and_build.py --emit --build
```

Run the testdata gate:

```bash
python cicas_backend/experiments/cert_detection/run.py
```

Expected behavior today: the command exits non-zero because the gate finds false
positives. Treat `outputs/` as a regression ledger until `SPURIOUS` returns to 0.

External CT/Tranco-style corpus scans are report-only:

```bash
python cicas_backend/experiments/cert_detection/run.py --certs /path/to/flat-pem-corpus
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
