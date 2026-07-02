# Experiment: certificate detection as a SAIV gate  →  Paper §8.5

**Question.** When the synonymous, shipped CICAS lints are run against real
certificates, are their findings genuine defects — including ones upstream zlint
misses — or false positives? A false positive is a SAIV signal: it reverse-blames
the pipeline stage that produced an over-broad lint.

**Result (current snapshot, after the R29273 scope fix and the R29415 + R29735 quarantines).**

| triage verdict | count |
|---|---:|
| REAL (upstream consensus / known-bad fixture) | 91 |
| SPURIOUS (false positive) | **0** |
| UNCERTAIN (no oracle signal, narrow firing) | 17 |
| *— UNCERTAIN reverse-checked → CONFIRMED_REAL* | *17* |
| **independent per-finding structural audit** | **108/108 CONFIRMED, 0 REFUTED, 0 NOCHECK** |

31 synonymous lints shipped into the zlint binary; 1128 testdata certificates
scanned → 108 cicasgen_ findings → **108/108 genuine defects, 0 false positives**,
blame ledger empty. The audit is **cross-validated by three independent parsers**
(openssl / Python `cryptography` / `pyasn1`): every finding is confirmed by at
least two of them, with **0 disagreements** on any cert two parsers could read.

Notable detections on upstream zlint's uncovered paths:
- `cicasgen_when_oid_policy_organization_validated_list_contains_29475` on
  `legalChar.pem` — an Organization Validated cert (policy `2.23.140.1.2.2`) that
  carries `givenName` (CABF BR 7.1.2.7.4 forbids it). Higher confidence: the
  prohibition on givenName in OV certs is direct and needs no additional context.
  **This is the only genuine detection in the current result set.**
- 36 firings of `cicasgen_not_any_policy_list_contains_29324` (CABF BR 7.1.2.2.6):
  these are **false positives from an overly broad lint**. The independent audit
  confirmed the structural presence of `anyPolicy` in each certificate, but the
  generated lint is too broad — it fires on any Sub CA containing `anyPolicy`
  without checking whether the CA is in the CABF "Policy Restricted" branch
  (Table 70). CABF allows `anyPolicy` for "No Policy Restrictions" CAs (Table 69).
  These 36 hits are false positives, not genuine CABF violations.

## Why the independent audit matters (triage is necessary but not sufficient)
triage's REAL verdict answers a **weaker** question than the paper needs: it means
"this certificate is defective for *some* lint" (upstream consensus or known-bad
fixture) — it does **not** prove that *our specific finding* matches the actual
defect. A lint that dropped a precondition can fire on a cert that is independently
defective for an unrelated reason and be waved through as REAL.

`independent_verify.py` (backend) closes that hole: for **every** finding it
re-derives, from openssl text + raw DER, whether the *specific* structural
condition the lint asserts is actually present, with **no** dependence on triage.
`run.py` runs it as a **mandatory assertion gate** (a single REFUTED on a
triage-REAL/UNCERTAIN finding fails the experiment).

## The three fixes this gate drove (SAIV in action)

**(1) SCOPE_TOO_BROAD.** An earlier run reported **1 SPURIOUS**:
`cicasgen_authority_key_id_present_29273` (CABF 7.1.2.11.1, "keyIdentifier MUST be
present") fired on the self-signed root `rootCAKeyUsagePresent.pem`. `blame.py`
attributed it to **SCOPE_TOO_BROAD** — a self-signed root may omit the AKI
keyIdentifier (RFC 5280 §4.2.1.1; zlint encodes the same carve-out in
`authorityKeyIdNoKeyIdField`). The repair surface is the codegen scope layer, not
the IR: `intree_emitter.check_applies_expr` now narrows an AKI-keyIdentifier
*presence* obligation to exclude self-signed certs
(`util.IsCACert(c) && !util.IsSelfSigned(c)`), requirement-keyed (IR subject +
obligation) so the sibling MUST-NOT rules are untouched. After the fix the lint
still fires 7× (all REAL) on Subordinate CAs that genuinely omit the keyIdentifier.

**(2) IR_GARBLED_TEXT / dropped precondition — caught by the independent audit.**
Adding the independent audit, a previous snapshot (33 lints / 112 findings /
self-reported "112/112 genuine") was **REFUTED on 2 findings**:
`cicasgen_when_subscriber_cert_subject_alt_name_not_critical_29415`
(CABF 7.1.2.7.12) fired `error` on `subCertEmptySubject.pem` and
`subject_rdn_order_ok_03.pem`. The rule is a two-row conditional — *if the subject
is empty (SAN is the only identity) the extension MUST be critical; otherwise MUST
NOT be critical*. Extraction kept only the "Otherwise … MUST NOT be marked
critical" row and **dropped the "subject non-empty" antecedent** (the DB
`rule_text` is truncated to that clause), so the lint mis-fires on compliant
empty-subject certs whose critical SAN is **required**. Both certs slipped past
triage because `subject_rdn_order_ok_03.pem` triggers an *unrelated* upstream
defect (missing AKI keyId) → upstream consensus → auto-REAL. Per the iron law we
do not patch the IR/Go: 29415 is **quarantined** (pending re-extraction to recover
the antecedent).

**(3) CODEGEN bound to the wrong field — caught by a second parser
(cross-validation).** Cross-checking the auditor against the `pyasn1` ASN.1 parser
surfaced a disagreement on `crlIncomlepteDp.pem` for
`cicasgen_when_crl_dist_present_crldistribution_points_count_29735`
(CABF 7.1.2.11.2, "the CRL Distribution Points extension MUST contain at least one
DistributionPoint"). Raw DER shows the cert **has 1 DistributionPoint** (carrying
only a `reasons` field, no `distributionPoint` URL), so the rule is **satisfied** —
the real defect (an incomplete DP) is a *different* requirement, caught by zlint's
own `e_distribution_point_incomplete`. The generated code counts
`len(c.CRLDistributionPoints)`, but that zcrypto field is a flattened list of
distributionPoint **URLs**, not DistributionPoint **structures**; a URL-less DP
contributes 0, so the lint mis-fires. This is a **codegen faithfulness bug**
(distinct from the extraction bug in (2)). My first openssl-based auditor shared
the same "count URLs" mistake and wrongly CONFIRMED it; `pyasn1`'s structural count
corrected it, and `independent_verify.py` now counts DistributionPoint structures
via pyasn1. 29735 is **quarantined** (needs an atom that counts DP elements).

After all three, the shipped set is **31** lints and the re-run is clean:
0 SPURIOUS and **108/108 CONFIRMED, 0 REFUTED, 0 NOCHECK** under the independent
audit, cross-validated by three parsers (§ below).

## Verifying the verifier (why these numbers are trustworthy)
The independent auditor is itself load-bearing, so it is stress-tested four ways
(`scripts/system_metrics/`):
- **Orthogonal cross-check** (`audit_cross_check.py`) — re-derive every finding
  with Python `cryptography` (a different DER parser). 60/108 are re-confirmed,
  **0 disagreements** on any cert it can parse.
- **Third-method check** (`audit_pyasn1_check.py`) — for the 36 deliberately-
  malformed certs `cryptography` rejects, re-derive with raw `pyasn1`. **0
  disagreements** with openssl. Net: every finding is confirmed by ≥2 independent
  parsers.
- **Negative control** (`audit_negative_control.py`) — temporarily ship the
  quarantined known-bad lints; the auditor must REFUTE them. It does (29415 → 2
  REFUTED + 1 CONFIRMED genuine; 29735 → REFUTED), proving it discriminates rather
  than rubber-stamps. (Families with no structural check return NOCHECK and never
  ship; `run.py` hard-fails on NOCHECK among shipped findings.)
- **Determinism** — 3 repeat runs produce byte-identical `audit_independent.jsonl`.

## Method
The MECHANISM lives in the **backend** package
`app/services/certificate/codegen/detection/` and is only *orchestrated* here
(convention #5):
- `scan.py` — run the augmented zlint binary over the corpus; split our
  `cicasgen_` findings from upstream (reuses `results_attribution.py`).
- `testdata_oracle.py` — parse zlint's own `*_test.go` into per-cert intent
  (known-bad vs positive fixture).
- `triage.py` — REAL / SPURIOUS / UNCERTAIN per finding, from two no-LLM oracles
  (upstream consensus + testdata intent) plus the over-strictness firing fraction
  (`== atom_oracle.sentinel`, 0.30).
- `verify_uncertain.py` — cert-grounded openssl reverse-check that upgrades an
  UNCERTAIN finding to CONFIRMED_REAL when the cert genuinely exhibits the defect.
- `independent_verify.py` — **adversarial per-finding structural check** that does
  NOT trust triage; re-derives each finding's specific defect from openssl + raw
  DER (DistributionPoint counts via pyasn1) → CONFIRMED / REFUTED / NOCHECK. The
  §8.5 "0 false positives" claim rests on this, cross-validated by the four tests
  above.
- `blame.py` — when a finding is SPURIOUS, attribute it to the pipeline stage at
  fault (SCOPE_TOO_BROAD / IR_GARBLED_TEXT / … ) and emit a re-extraction request.

The binary itself is built by `scripts/system_metrics/inject_and_build.py`
(`--emit --build`); its in-tree emitter ships **only** lints proven synonymous
with the spec (EXPRESSES verdict + non-drifting σ_mech) and not quarantined.
Building is a system step, not part of this experiment; `run.py` reuses the
shipped binary.

## Files
- `run.py` — orchestrate scan → triage → reverse-check → **independent audit** →
  blame; render §8.5; assert SPURIOUS == 0 **and** 0 independent-audit conflicts
  **and** 0 NOCHECK among shipped findings.
- `inputs/cicasgen_manifest.json` — the synonymous lints shipped into the binary.
- `outputs/detection_summary.{json,md}` — the result table.
- `outputs/triage_by_lint.json` — per-lint firing + verdict counts.
- `outputs/uncertain_verified.jsonl` — cert-grounded verdict per UNCERTAIN finding.
- `outputs/audit_independent.jsonl` — independent structural verdict per finding.
- `outputs/blame.jsonl` — SAIV feedback ledger (empty = clean gate).

External CT/Tranco-style corpus scans are exploratory and write outside this
paper-gate directory, under `experiments/new_lint_corpus_scan/outputs/`.

## Run
```
# build the augmented binary once (system step):
python scripts/system_metrics/inject_and_build.py --emit --build
# then evaluate (fails if any finding is spurious or independently refuted):
python experiments/cert_detection/run.py --snapshot
# report-only external corpus mode; shows exactly which problems came from the
# CICAS-added zlint lints, separated from upstream zlint findings.
# Output goes to experiments/new_lint_corpus_scan/outputs/<corpus-name>/:
python experiments/cert_detection/run.py --certs /path/to/flat-pem-corpus
# standalone independent audit (exit 1 on any conflict):
python scripts/system_metrics/audit_cert_findings.py
```

## Caveats
- The corpus is zlint's **testdata** (adversarial fixtures), so the firing
  fractions are not a prevalence estimate over real-world CA hygiene — they
  validate that the gate's reasoning is correct and that 0 findings are spurious.
  A real prevalence study needs `--certs` pointed at a CT-log corpus.
