# §8.5 — certificate detection as a SAIV gate

- synonymous lints shipped into the zlint binary: **26**
- testdata certificates scanned: **1128**
- cicasgen_ findings: **892**

| triage verdict | count |
|---|---:|
| REAL (upstream consensus / known-bad fixture) | 885 |
| SPURIOUS (false positive) | **4** |
| UNCERTAIN (no oracle signal, narrow firing) | 3 |

UNCERTAIN findings, after cert-grounded reverse-check:

| reverse-check verdict | count |
|---|---:|
| CONFIRMED_REAL | 2 |
| REMAINS_UNCERTAIN | 1 |

Independent per-finding structural audit (does NOT trust triage; re-derives each finding's specific defect from openssl+DER):

| independent verdict | count |
|---|---:|
| CONFIRMED | 435 |
| NOCHECK | 457 |

**Strict reportable result: 0 findings are independently CONFIRMED and not quality-gated.** Raw triage calls 887/892 genuine and marks 4 finding(s) as weak-oracle SPURIOUS; independent audit leaves 0 REFUTED finding(s) and 0 unresolved SPURIOUS finding(s), with 457 NOCHECK findings excluded from the reliable-claim set.

Per-lint detections (firing on the testdata corpus):

| lint | §/source | fires | applies | REAL | SPUR | UNC |
|---|---|---:|---:|---:|---:|---:|
| `cicasgen_when_subscriber_cert_oid_list_count_in_set_policy_29492` | — | 353 | 748 | 351 | 2 | 0 |
| `cicasgen_when_subscriber_cert_dnsnames_present_or_ipaddresses_29414` | — | 246 | 748 | 246 | 0 | 0 |
| `cicasgen_when_subscriber_cert_subject_common_name_fqdnmatches_29672` | — | 120 | 748 | 120 | 0 | 0 |
| `cicasgen_not_ku_has_data_encipherment_29411` | — | 49 | 748 | 49 | 0 | 0 |
| `cicasgen_when_subscriber_cert_not_any_policy_list_contains_29493` | — | 26 | 748 | 26 | 0 | 0 |
| `cicasgen_when_oid_policy_individual_validated_list_contains_29446` | — | 18 | 31 | 17 | 1 | 0 |
| `cicasgen_subject_alternate_name_critical_29800` | — | 13 | 62 | 12 | 0 | 1 |
| `cicasgen_ext_key_usage_only_has_usages_in_set_29510` | — | 12 | 12 | 12 | 0 | 0 |
| `cicasgen_when_oid_policy_individual_validated_list_contains_29447` | — | 10 | 31 | 9 | 1 | 0 |
| `cicasgen_when_not_subject_locality_present_subject_province_29460` | — | 7 | 215 | 7 | 0 | 0 |
| `cicasgen_when_not_subject_province_present_subject_locality_29465` | — | 7 | 215 | 7 | 0 | 0 |
| `cicasgen_when_version_present_version_eq_31172` | — | 7 | 1077 | 7 | 0 | 0 |
| `cicasgen_when_version_present_version_in_set_31169` | — | 5 | 1077 | 5 | 0 | 0 |
| `cicasgen_when_not_subject_locality_present_subject_province_29433` | — | 4 | 31 | 4 | 0 | 0 |
| `cicasgen_sig_alg_matches_tbssignature_31396` | — | 4 | 1077 | 4 | 0 | 0 |
| `cicasgen_when_has_any_extension_version_eq_31403` | — | 3 | 1077 | 3 | 0 | 0 |
| `cicasgen_when_oid_policy_organization_validated_list_contains_29474` | — | 2 | 215 | 1 | 0 | 1 |
| `cicasgen_when_oid_policy_organization_validated_list_contains_29475` | — | 2 | 215 | 1 | 0 | 1 |
| `cicasgen_validity_utctime_values_use_zulu_31175` | — | 2 | 1077 | 2 | 0 | 0 |
| `cicasgen_when_cert_policy_present_policy_identifiers_count_29491` | — | 1 | 748 | 1 | 0 | 0 |
| `cicasgen_when_subscriber_cert_not_path_len_constraint_present_29490` | — | 1 | 748 | 1 | 0 | 0 |
