# §8.5 — certificate detection as a SAIV gate

- synonymous lints shipped into the zlint binary: **89**
- testdata certificates scanned: **1128**
- cicasgen_ findings: **7508**

| triage verdict | count |
|---|---:|
| REAL (upstream consensus / known-bad fixture) | 6891 |
| SPURIOUS (false positive) | **539** |
| UNCERTAIN (no oracle signal, narrow firing) | 78 |

UNCERTAIN findings, after cert-grounded reverse-check:

| reverse-check verdict | count |
|---|---:|
| CONFIRMED_REAL | 66 |
| REMAINS_UNCERTAIN | 12 |

Independent per-finding structural audit (does NOT trust triage; re-derives each finding's specific defect from openssl+DER):

| independent verdict | count |
|---|---:|
| CONFIRMED | 2037 |
| REFUTED | 52 |
| NOCHECK | 5419 |

**Strict reportable result: 22 findings are independently CONFIRMED and not quality-gated.** Raw triage calls 6957/7508 genuine, 539 false positives, with 5419 NOCHECK findings excluded from the reliable-claim set.

Per-lint detections (firing on the testdata corpus):

| lint | §/source | fires | applies | REAL | SPUR | UNC |
|---|---|---:|---:|---:|---:|---:|
| `cicasgen_ext_subfield_present_policy_constraints_or_ext_subfield_31056` | — | 1073 | 1077 | 982 | 91 | 0 |
| `cicasgen_when_version_present_version_eq_31346` | — | 1064 | 1077 | 973 | 91 | 0 |
| `cicasgen_when_version_present_version_eq_31349` | — | 1064 | 1077 | 973 | 91 | 0 |
| `cicasgen_subject_alternate_name_critical_31132` | — | 695 | 1077 | 636 | 59 | 0 |
| `cicasgen_subject_alt_name_present_31065` | — | 365 | 1077 | 333 | 32 | 0 |
| `cicasgen_when_subscriber_cert_oid_list_count_in_set_policy_29492` | — | 353 | 748 | 351 | 2 | 0 |
| `cicasgen_when_subscriber_cert_ku_has_digital_signature_29409` | — | 301 | 748 | 300 | 1 | 0 |
| `cicasgen_when_subscriber_cert_dnsnames_present_or_ipaddresses_29414` | — | 246 | 748 | 246 | 0 | 0 |
| `cicasgen_bytes_eq_31102` | — | 240 | 259 | 208 | 32 | 0 |
| `cicasgen_policy_identifiers_count_and_any_policy_list_contains_29339` | — | 200 | 233 | 190 | 10 | 0 |
| `cicasgen_any_policy_list_contains_29321` | — | 197 | 233 | 187 | 10 | 0 |
| `cicasgen_permitted_directory_names_present_29375` | — | 186 | 233 | 160 | 26 | 0 |
| `cicasgen_subtree_string_list_has_non_empty_or_empty_marker_29382` | — | 184 | 233 | 159 | 25 | 0 |
| `cicasgen_rdnhas_single_attribute_subject_29558` | — | 171 | 1034 | 171 | 0 | 0 |
| `cicasgen_oid_list_count_in_set_policy_identifiers_29244` | — | 121 | 257 | 96 | 25 | 0 |
| `cicasgen_oid_list_count_in_set_policy_identifiers_29247` | — | 121 | 257 | 96 | 25 | 0 |
| `cicasgen_when_oid_policy_organization_validated_list_contains_29468` | — | 118 | 215 | 101 | 17 | 0 |
| `cicasgen_when_subscriber_cert_dnsnames_fqdnor_wildcard_portion_29420` | — | 72 | 748 | 69 | 0 | 3 |
| `cicasgen_name_constraints_excluded_subtrees_empty_29388` | — | 68 | 233 | 68 | 0 | 0 |
| `cicasgen_rdnsequence_has_country_before_subject_29559` | — | 65 | 1034 | 61 | 0 | 4 |
| `cicasgen_excluded_directory_names_absent_and_excluded_dnsnames_29269` | — | 53 | 257 | 53 | 0 | 0 |
| `cicasgen_not_ku_has_data_encipherment_29411` | — | 49 | 748 | 49 | 0 | 0 |
| `cicasgen_when_not_has_any_extension_and_issuer_unique_id_absent_31153` | — | 47 | 1077 | 47 | 0 | 0 |
| `cicasgen_policy_identifiers_count_29316` | — | 42 | 233 | 40 | 0 | 2 |
| `cicasgen_not_any_policy_list_contains_29324` | — | 36 | 233 | 20 | 0 | 16 |
| `cicasgen_not_any_policy_list_contains_29325` | — | 36 | 233 | 20 | 0 | 16 |
| `cicasgen_not_any_policy_list_contains_29342` | — | 36 | 233 | 20 | 0 | 16 |
| `cicasgen_not_any_policy_list_contains_29343` | — | 36 | 233 | 20 | 0 | 16 |
| `cicasgen_when_subscriber_cert_not_any_policy_list_contains_29493` | — | 26 | 748 | 26 | 0 | 0 |
| `cicasgen_not_ext_subfield_present_authority_key_id_28730` | — | 20 | 257 | 20 | 0 | 0 |
| `cicasgen_when_oid_policy_individual_validated_list_contains_29446` | — | 18 | 31 | 17 | 1 | 0 |
| `cicasgen_ext_subfield_present_authority_key_id_and_ext_subfield_31160` | — | 18 | 1077 | 18 | 0 | 0 |
| `cicasgen_certificate_policies_has_no_policy_qualifiers_29246` | — | 17 | 257 | 17 | 0 | 0 |
| `cicasgen_issuer_unique_id_absent_29298` | — | 15 | 233 | 15 | 0 | 0 |
| `cicasgen_subject_alternate_name_critical_29800` | — | 13 | 62 | 12 | 0 | 1 |
| `cicasgen_serial_number_len_31163` | — | 13 | 1077 | 13 | 0 | 0 |
| `cicasgen_when_oid_policy_individual_validated_list_contains_29447` | — | 10 | 31 | 9 | 1 | 0 |
| `cicasgen_when_oid_policy_organization_validated_list_contains_29463` | — | 10 | 215 | 8 | 0 | 2 |
| `cicasgen_ext_policy_qualifier_oidin_set_29329` | — | 8 | 233 | 8 | 0 | 0 |
| `cicasgen_ext_policy_qualifier_oidin_set_29347` | — | 8 | 233 | 8 | 0 | 0 |
| `cicasgen_when_not_subject_locality_present_subject_province_29460` | — | 7 | 215 | 7 | 0 | 0 |
| `cicasgen_when_not_subject_province_present_subject_locality_29465` | — | 7 | 215 | 7 | 0 | 0 |
| `cicasgen_when_version_present_version_eq_31172` | — | 7 | 1077 | 7 | 0 | 0 |
| `cicasgen_when_version_present_version_eq_31344` | — | 7 | 1077 | 7 | 0 | 0 |
| `cicasgen_ext_policy_qualifier_oidin_set_29495` | — | 6 | 748 | 6 | 0 | 0 |
| `cicasgen_not_cert_policy_explicit_text_has_encoding_tag_in_set_30984` | — | 6 | 1077 | 6 | 0 | 0 |
| `cicasgen_when_version_present_version_in_set_31169` | — | 5 | 1077 | 5 | 0 | 0 |
| `cicasgen_when_version_present_version_in_set_31342` | — | 5 | 1077 | 5 | 0 | 0 |
| `cicasgen_when_not_subject_locality_present_subject_province_29433` | — | 4 | 31 | 4 | 0 | 0 |
| `cicasgen_not_ext_subfield_present_authority_key_id_29274` | — | 4 | 257 | 4 | 0 | 0 |
| `cicasgen_sig_alg_matches_tbssignature_31396` | — | 4 | 1077 | 4 | 0 | 0 |
| `cicasgen_when_subject_alt_name_present_and_not_dn_empty_subject_31067` | — | 4 | 1077 | 4 | 0 | 0 |
| `cicasgen_when_subscriber_cert_subject_alt_name_not_critical_29415` | — | 3 | 748 | 3 | 0 | 0 |
| `cicasgen_when_has_any_extension_version_eq_31403` | — | 3 | 1077 | 3 | 0 | 0 |
| `cicasgen_when_eku_has_any_ext_key_usage_count_28713` | — | 2 | 233 | 2 | 0 | 0 |
| `cicasgen_when_oid_policy_organization_validated_list_contains_29474` | — | 2 | 215 | 1 | 0 | 1 |
| `cicasgen_when_oid_policy_organization_validated_list_contains_29475` | — | 2 | 215 | 1 | 0 | 1 |
| `cicasgen_serial_number_dersign_bit_zero_31368` | — | 2 | 1077 | 2 | 0 | 0 |
| `cicasgen_serial_number_value_31123` | — | 2 | 1077 | 2 | 0 | 0 |
| `cicasgen_serial_number_value_31161` | — | 2 | 1077 | 2 | 0 | 0 |
| `cicasgen_validity_utctime_values_use_zulu_31175` | — | 2 | 1077 | 2 | 0 | 0 |
| `cicasgen_sig_alg_matches_tbssignature_29300` | — | 1 | 233 | 1 | 0 | 0 |
| `cicasgen_sig_alg_matches_tbssignature_29360` | — | 1 | 233 | 1 | 0 | 0 |
| `cicasgen_sig_alg_matches_tbssignature_29367` | — | 1 | 233 | 1 | 0 | 0 |
| `cicasgen_subject_unique_id_absent_29299` | — | 1 | 233 | 1 | 0 | 0 |
| `cicasgen_subject_unique_id_absent_29333` | — | 1 | 233 | 1 | 0 | 0 |
| `cicasgen_when_cert_policy_present_policy_identifiers_count_29491` | — | 1 | 748 | 1 | 0 | 0 |
| `cicasgen_when_subscriber_cert_not_path_len_constraint_present_29490` | — | 1 | 748 | 1 | 0 | 0 |
