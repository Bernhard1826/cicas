# §8.5 — certificate detection as a SAIV gate

- synonymous lints shipped into the zlint binary: **78**
- testdata certificates scanned: **1128**
- cicasgen_ findings: **4959**

| triage verdict | count |
|---|---:|
| REAL (upstream consensus / known-bad fixture) | 4514 |
| SPURIOUS (false positive) | **347** |
| UNCERTAIN (no oracle signal, narrow firing) | 98 |

UNCERTAIN findings, after cert-grounded reverse-check:

| reverse-check verdict | count |
|---|---:|
| CONFIRMED_REAL | 66 |
| REMAINS_UNCERTAIN | 32 |

Independent per-finding structural audit (does NOT trust triage; re-derives each finding's specific defect from openssl+DER):

| independent verdict | count |
|---|---:|
| CONFIRMED | 507 |
| REFUTED | 4 |
| NOCHECK | 4448 |

**Result: 4580/4959 findings are genuine defects, 347 false positives (independently confirmed: 507/4959).**

Per-lint detections (firing on the testdata corpus):

| lint | §/source | fires | applies | REAL | SPUR | UNC |
|---|---|---:|---:|---:|---:|---:|
| `cicasgen_when_version_present_version_eq_31349` | — | 1075 | 1077 | 984 | 91 | 0 |
| `cicasgen_oid_eq_oid_ec_public_key_29539` | — | 826 | 1034 | 752 | 74 | 0 |
| `cicasgen_subject_alternate_name_critical_31132` | — | 695 | 1077 | 636 | 59 | 0 |
| `cicasgen_subject_alt_name_present_31065` | — | 365 | 1077 | 333 | 32 | 0 |
| `cicasgen_when_subscriber_cert_dnsnames_present_or_ipaddresses_29414` | — | 246 | 748 | 246 | 0 | 0 |
| `cicasgen_bytes_eq_31102` | — | 240 | 259 | 208 | 32 | 0 |
| `cicasgen_when_is_ca_when_is_ca_cross_field_eq_31400` | — | 228 | 1077 | 201 | 1 | 26 |
| `cicasgen_policy_identifiers_count_and_any_policy_list_contains_29339` | — | 200 | 233 | 190 | 10 | 0 |
| `cicasgen_permitted_directory_names_present_29375` | — | 186 | 233 | 160 | 26 | 0 |
| `cicasgen_when_oid_policy_organization_validated_list_contains_29476` | — | 127 | 215 | 107 | 20 | 0 |
| `cicasgen_not_dn_empty_issuer_31108` | — | 90 | 1077 | 89 | 0 | 1 |
| `cicasgen_ku_has_cert_sign_or_ku_has_digital_signature_or_ku_has_29408` | — | 88 | 545 | 88 | 0 | 0 |
| `cicasgen_excluded_directory_names_absent_and_excluded_dnsnames_29269` | — | 53 | 257 | 53 | 0 | 0 |
| `cicasgen_policy_identifiers_count_29316` | — | 42 | 233 | 40 | 0 | 2 |
| `cicasgen_not_any_policy_list_contains_29324` | — | 36 | 233 | 20 | 0 | 16 |
| `cicasgen_not_any_policy_list_contains_29325` | — | 36 | 233 | 20 | 0 | 16 |
| `cicasgen_not_any_policy_list_contains_29342` | — | 36 | 233 | 20 | 0 | 16 |
| `cicasgen_not_any_policy_list_contains_29343` | — | 36 | 233 | 20 | 0 | 16 |
| `cicasgen_when_subscriber_cert_not_any_policy_list_contains_29493` | — | 26 | 748 | 26 | 0 | 0 |
| `cicasgen_issuer_unique_id_absent_and_subject_unique_id_absent_31183` | — | 23 | 1077 | 23 | 0 | 0 |
| `cicasgen_not_ext_subfield_present_authority_key_id_28730` | — | 20 | 257 | 20 | 0 | 0 |
| `cicasgen_when_oid_policy_individual_validated_list_contains_29446` | — | 18 | 31 | 17 | 1 | 0 |
| `cicasgen_when_version_present_version_eq_31172` | — | 18 | 1077 | 18 | 0 | 0 |
| `cicasgen_when_version_present_version_eq_31344` | — | 18 | 1077 | 18 | 0 | 0 |
| `cicasgen_when_version_present_version_in_set_31169` | — | 16 | 1077 | 16 | 0 | 0 |
| `cicasgen_when_version_present_version_in_set_31342` | — | 16 | 1077 | 16 | 0 | 0 |
| `cicasgen_when_oid_policy_individual_validated_list_contains_29448` | — | 15 | 31 | 15 | 0 | 0 |
| `cicasgen_issuer_unique_id_absent_29298` | — | 15 | 233 | 15 | 0 | 0 |
| `cicasgen_issuer_unique_id_absent_29332` | — | 15 | 233 | 15 | 0 | 0 |
| `cicasgen_issuer_unique_id_absent_29358` | — | 15 | 233 | 15 | 0 | 0 |
| `cicasgen_issuer_unique_id_absent_29365` | — | 15 | 233 | 15 | 0 | 0 |
| `cicasgen_subject_alternate_name_critical_29800` | — | 13 | 62 | 12 | 0 | 1 |
| `cicasgen_serial_number_len_31163` | — | 13 | 1077 | 13 | 0 | 0 |
| `cicasgen_when_oid_policy_individual_validated_list_contains_29447` | — | 10 | 31 | 9 | 1 | 0 |
| `cicasgen_when_oid_policy_organization_validated_list_contains_29463` | — | 10 | 215 | 8 | 0 | 2 |
| `cicasgen_when_not_subject_locality_present_subject_province_29460` | — | 7 | 215 | 7 | 0 | 0 |
| `cicasgen_when_not_subject_province_present_subject_locality_29465` | — | 7 | 215 | 7 | 0 | 0 |
| `cicasgen_authority_key_id_present_29273` | — | 7 | 233 | 7 | 0 | 0 |
| `cicasgen_when_subscriber_cert_issuer_unique_id_absent_29397` | — | 6 | 748 | 6 | 0 | 0 |
| `cicasgen_not_cert_policy_explicit_text_has_encoding_tag_in_set_30984` | — | 6 | 1077 | 6 | 0 | 0 |
| `cicasgen_when_not_subject_locality_present_subject_province_29433` | — | 4 | 31 | 4 | 0 | 0 |
| `cicasgen_not_ext_subfield_present_authority_key_id_29274` | — | 4 | 257 | 4 | 0 | 0 |
| `cicasgen_subject_alternate_name_not_critical_31067` | — | 4 | 685 | 4 | 0 | 0 |
| `cicasgen_sig_alg_matches_tbssignature_31396` | — | 4 | 1077 | 4 | 0 | 0 |
| `cicasgen_when_subscriber_cert_subject_alt_name_not_critical_29415` | — | 3 | 748 | 3 | 0 | 0 |
| `cicasgen_when_extensions_present_version_eq_31403` | — | 3 | 1077 | 3 | 0 | 0 |
| `cicasgen_when_eku_has_any_ext_key_usage_count_28713` | — | 2 | 233 | 2 | 0 | 0 |
| `cicasgen_when_oid_policy_organization_validated_list_contains_29474` | — | 2 | 215 | 1 | 0 | 1 |
| `cicasgen_when_oid_policy_organization_validated_list_contains_29475` | — | 2 | 215 | 1 | 0 | 1 |
| `cicasgen_serial_number_value_31123` | — | 2 | 1077 | 2 | 0 | 0 |
| `cicasgen_serial_number_value_31161` | — | 2 | 1077 | 2 | 0 | 0 |
| `cicasgen_sig_alg_matches_tbssignature_29300` | — | 1 | 233 | 1 | 0 | 0 |
| `cicasgen_sig_alg_matches_tbssignature_29334` | — | 1 | 233 | 1 | 0 | 0 |
| `cicasgen_sig_alg_matches_tbssignature_29367` | — | 1 | 233 | 1 | 0 | 0 |
| `cicasgen_subject_unique_id_absent_29299` | — | 1 | 233 | 1 | 0 | 0 |
| `cicasgen_subject_unique_id_absent_29333` | — | 1 | 233 | 1 | 0 | 0 |
| `cicasgen_subject_unique_id_absent_29359` | — | 1 | 233 | 1 | 0 | 0 |
| `cicasgen_subject_unique_id_absent_29366` | — | 1 | 233 | 1 | 0 | 0 |
| `cicasgen_when_crl_dist_present_crldistribution_points_count_29735` | — | 1 | 257 | 1 | 0 | 0 |
| `cicasgen_when_root_ca_not_crl_dist_present_29288` | — | 1 | 257 | 1 | 0 | 0 |
| `cicasgen_when_cert_policy_present_policy_identifiers_count_29491` | — | 1 | 748 | 1 | 0 | 0 |
| `cicasgen_when_pre_certificate_signing_certificate_eku_list_29533` | — | 1 | 981 | 1 | 0 | 0 |
| `cicasgen_when_subscriber_cert_not_aiahas_method_other_than_29484` | — | 1 | 748 | 1 | 0 | 0 |
| `cicasgen_when_subscriber_cert_not_path_len_constraint_present_29490` | — | 1 | 748 | 1 | 0 | 0 |
