# Certificate Scan Outputs

The paper figures of record use run `current_79_20260720/`, with the 79-lint
shipping manifest from
`cicas_backend/experiments/codegen_metrics/outputs/strict_audited_uncovered_20260720/`.
The structured run manifest is
`current_79_20260720/PAPER_RUN_MANIFEST.json`.

Only `current_79_20260720/` is authoritative for manuscript reproduction. Older
scratch outputs are kept outside this `outputs/` tree under
`../superseded_outputs/` and must be excluded from any reviewer-facing artifact
package.

## Paper Counts

- External corpora: Tranco `47,791` certificates plus CT `63,327` certificates,
  for `111,118` deployed certificates.
- Raw generated-lint rows: Tranco `57,583`, CT `80,021`.
- No-upstream candidate rows: Tranco `1,042`, CT `167`.
- Independently confirmed row-level violations: Tranco `8`, CT `2`.
- Cross-corpus de-duplicated external certificate-problem instances: `4`.
- External merged defect classes: one Error-level AKI issuer/serial violation
  and three Warning-level Root CA CRLDP violations.

## Count Units

- `finding type`: a governing-obligation row in the paper table.
- `row-level violation`: one non-pass generated-lint row on one certificate.
- `certificate-problem instance`: duplicate generated rows for the same
  certificate defect collapsed.
- `external merged`: Tranco and CT certificate-problem instances de-duplicated
  across corpora by certificate and defect class.
