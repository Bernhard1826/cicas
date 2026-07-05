# Experiment: certificate detection as a SAIV gate

This experiment scans zlint testdata with the augmented zlint binary and
separates upstream findings from CICAS-generated `cicasgen_` findings.

## Current Status

The current gate is a **failing regression check**, not a paper success result.

Current run (`outputs/detection_summary.{json,md}`), after rebuilding zlint from
the strict shipping manifest (`shipping_lints_manifest.json`).  This manifest is
stricter than the row-fragment synonymy manifest: it admits only generated lints
whose final in-tree zlint behavior (`CheckApplies` + `Execute` + severity) has
been judged synonymous with the available original rule context.

| metric | value |
|---|---:|
| shipped `cicasgen_` lints | 25 |
| zlint testdata certs scanned | 1128 |
| `cicasgen_` findings | 875 |
| triage REAL | 868 |
| weak-oracle triage SPURIOUS | 4 |
| triage UNCERTAIN | 3 |
| independent CONFIRMED | 435 |
| independent REFUTED | 0 |
| independent NOCHECK | 440 |
| strict reportable findings | 0 |

The gate is currently clean on zlint testdata under the independent-audit
criterion (`REFUTED=0`, unresolved weak-oracle SPURIOUS=0).  The raw triage
oracle still labels 4 findings SPURIOUS, but all 4 are independently confirmed
real defects.  External CT/Tranco report-only scans with this 25-lint strict
manifest found one non-overlapping, independently confirmed new issue in
Tranco: a subscriber certificate for `*.enter-system.com` has zero CABF reserved
policy OIDs, violating CABF-BR §7.1.2.7.9 / rule 29492.

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

Build or refresh the shipped manifest after coverage/codegen has been recomputed
and strict shipping synonymy has been judged:

```bash
python cicas_backend/experiments/codegen_metrics/run_codegen_synonymy.py --rejudge-shipping --k 5
python cicas_backend/scripts/inject_and_build.py --emit --build
```

Run the testdata gate:

```bash
python cicas_backend/experiments/cert_detection/run.py
```

Expected behavior today: the command exits zero when `SPURIOUS=0`.

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
