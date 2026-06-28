# §8.5 — certificate detection as a SAIV gate

- synonymous lints shipped into the zlint binary: **31**
- testdata certificates scanned: **1128**
- cicasgen_ findings: **108**

| triage verdict | count |
|---|---:|
| REAL (upstream consensus / known-bad fixture) | 91 |
| SPURIOUS (false positive) | **0** |
| UNCERTAIN (no oracle signal, narrow firing) | 17 |

UNCERTAIN findings, after cert-grounded reverse-check:

| reverse-check verdict | count |
|---|---:|
| CONFIRMED_REAL | 17 |

Independent per-finding structural audit (does NOT trust triage; re-derives each finding's specific defect from openssl+DER):

| independent verdict | count |
|---|---:|
| CONFIRMED | 108 |

**Result: 108/108 findings are genuine defects, 0 false positives (independently confirmed: 108/108).**

Per-lint detections (firing on the testdata corpus):

| lint | §/source | fires | applies | REAL | SPUR | UNC |
|---|---|---:|---:|---:|---:|---:|
| `cicasgen_not_any_policy_list_contains_29324` | — | 36 | 233 | 20 | 0 | 16 |
| `cicasgen_not_ext_subfield_present_authority_key_id_28730` | — | 20 | 257 | 20 | 0 | 0 |
| `cicasgen_issuer_unique_id_absent_29298` | — | 15 | 233 | 15 | 0 | 0 |
| `cicasgen_when_not_subject_locality_present_subject_province_29460` | — | 7 | 215 | 7 | 0 | 0 |
| `cicasgen_when_not_subject_province_present_subject_locality_29465` | — | 7 | 215 | 7 | 0 | 0 |
| `cicasgen_authority_key_id_present_29273` | — | 7 | 233 | 7 | 0 | 0 |
| `cicasgen_when_not_subject_locality_present_subject_province_29433` | — | 4 | 31 | 4 | 0 | 0 |
| `cicasgen_not_ext_subfield_present_authority_key_id_29274` | — | 4 | 257 | 4 | 0 | 0 |
| `cicasgen_when_oid_policy_organization_validated_list_contains_29475` | — | 2 | 215 | 1 | 0 | 1 |
| `cicasgen_sig_alg_matches_tbssignature_29300` | — | 1 | 233 | 1 | 0 | 0 |
| `cicasgen_subject_unique_id_absent_29299` | — | 1 | 233 | 1 | 0 | 0 |
| `cicasgen_when_root_ca_not_crl_dist_present_29288` | — | 1 | 257 | 1 | 0 | 0 |
| `cicasgen_when_cert_policy_present_policy_identifiers_count_29491` | — | 1 | 748 | 1 | 0 | 0 |
| `cicasgen_when_subscriber_cert_not_aiahas_method_other_than_29484` | — | 1 | 748 | 1 | 0 | 0 |
| `cicasgen_when_subscriber_cert_not_path_len_constraint_present_29490` | — | 1 | 748 | 1 | 0 | 0 |
