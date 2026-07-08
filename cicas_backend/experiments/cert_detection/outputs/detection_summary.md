# §8.5 — certificate detection as a SAIV gate

- synonymous lints shipped into the zlint binary: **91**
- testdata certificates scanned: **1128**
- cicasgen_ findings: **2627**

| triage verdict | count |
|---|---:|
| REAL (upstream consensus / known-bad fixture) | 2469 |
| SPURIOUS (false positive) | **133** |
| UNCERTAIN (no oracle signal, narrow firing) | 25 |

UNCERTAIN findings, after cert-grounded reverse-check:

| reverse-check verdict | count |
|---|---:|
| CONFIRMED_REAL | 2 |
| REMAINS_UNCERTAIN | 23 |

Independent per-finding structural audit (does NOT trust triage; re-derives each finding's specific defect from openssl+DER):

| independent verdict | count |
|---|---:|
| CONFIRMED | 299 |
| NOCHECK | 2328 |

**Strict reportable result: 0 findings are independently CONFIRMED and not quality-gated.** Raw triage calls 2471/2627 genuine and marks 133 finding(s) as weak-oracle SPURIOUS; independent audit leaves 0 REFUTED finding(s) and 129 unresolved SPURIOUS finding(s), with 2328 NOCHECK findings excluded from the reliable-claim set.

Per-lint detections (firing on the testdata corpus):

| lint | §/source | fires | applies | REAL | SPUR | UNC |
|---|---|---:|---:|---:|---:|---:|
| `cicasgen_when_oid_eq_oid_sha256_with_rsaencryption_or_oid_eq_oid_29766` | — | 821 | 821 | 749 | 72 | 0 |
| `cicasgen_subject_alt_name_present_31065` | — | 365 | 1077 | 333 | 32 | 0 |
| `cicasgen_when_subscriber_cert_dnsnames_present_or_ipaddresses_29414` | — | 246 | 748 | 246 | 0 | 0 |
| `cicasgen_when_pubkey_alg_rsa_ku_has_digital_signature_29409` | — | 127 | 545 | 127 | 0 | 0 |
| `cicasgen_when_subscriber_cert_subject_common_name_fqdnmatches_29672` | — | 120 | 748 | 120 | 0 | 0 |
| `cicasgen_when_oid_policy_organization_validated_list_contains_29468` | — | 118 | 215 | 101 | 17 | 0 |
| `cicasgen_when_subscriber_cert_oid_list_count_in_set_policy_29492` | — | 113 | 508 | 112 | 1 | 0 |
| `cicasgen_when_subscriber_cert_certificate_policies_has_no_policy_29757` | — | 91 | 748 | 73 | 6 | 12 |
| `cicasgen_when_subscriber_cert_dnsnames_fqdnor_wildcard_portion_29420` | — | 72 | 748 | 69 | 0 | 3 |
| `cicasgen_name_constraints_excluded_subtrees_empty_29269` | — | 68 | 257 | 68 | 0 | 0 |
| `cicasgen_when_not_has_any_extension_and_issuer_unique_id_absent_31153` | — | 47 | 58 | 47 | 0 | 0 |
| `cicasgen_when_pubkey_alg_rsa_not_ku_has_data_encipherment_29411` | — | 37 | 545 | 37 | 0 | 0 |
| `cicasgen_subtree_iplist_version_all_octet_count_permitted_31046` | — | 30 | 107 | 30 | 0 | 0 |
| `cicasgen_oid_list_count_in_set_policy_identifiers_29244` | — | 27 | 160 | 25 | 0 | 2 |
| `cicasgen_oid_list_count_in_set_policy_identifiers_29247` | — | 27 | 160 | 25 | 0 | 2 |
| `cicasgen_when_subscriber_cert_not_any_policy_list_contains_29493` | — | 26 | 508 | 26 | 0 | 0 |
| `cicasgen_not_ext_subfield_present_authority_key_id_28730` | — | 25 | 1034 | 25 | 0 | 0 |
| `cicasgen_when_oid_policy_individual_validated_list_contains_29446` | — | 18 | 31 | 17 | 1 | 0 |
| `cicasgen_ext_subfield_present_authority_key_id_and_ext_subfield_31160` | — | 18 | 1077 | 18 | 0 | 0 |
| `cicasgen_when_subscriber_cert_ext_policy_qualifier_oidin_set_29495` | — | 17 | 508 | 14 | 1 | 2 |
| `cicasgen_certificate_policies_has_no_policy_qualifiers_29246` | — | 17 | 196 | 17 | 0 | 0 |
| `cicasgen_certificate_policies_has_no_policy_qualifiers_29733` | — | 17 | 196 | 17 | 0 | 0 |
| `cicasgen_when_dn_empty_subject_subject_alternate_name_critical_31132` | — | 14 | 27 | 13 | 1 | 0 |
| `cicasgen_subject_alternate_name_critical_29800` | — | 13 | 15 | 12 | 1 | 0 |
| `cicasgen_serial_number_len_31163` | — | 13 | 1077 | 13 | 0 | 0 |
| `cicasgen_ext_key_usage_only_has_usages_in_set_29510` | — | 12 | 12 | 12 | 0 | 0 |
| `cicasgen_when_oid_policy_individual_validated_list_contains_29447` | — | 10 | 31 | 9 | 1 | 0 |
| `cicasgen_ext_key_usage_only_has_usages_in_set_29257` | — | 9 | 257 | 7 | 0 | 2 |
| `cicasgen_when_not_subject_province_present_subject_locality_29463` | — | 7 | 9 | 7 | 0 | 0 |
| `cicasgen_when_not_subject_province_present_subject_locality_29465` | — | 7 | 9 | 7 | 0 | 0 |
| `cicasgen_when_not_subject_locality_present_subject_province_29460` | — | 7 | 10 | 7 | 0 | 0 |
| `cicasgen_not_ext_subfield_present_authority_key_id_29274` | — | 7 | 1034 | 7 | 0 | 0 |
| `cicasgen_when_version_present_version_eq_31172` | — | 7 | 1066 | 7 | 0 | 0 |
| `cicasgen_cert_policy_explicit_text_all_have_encoding_tag_in_set_30982` | — | 7 | 1077 | 7 | 0 | 0 |
| `cicasgen_not_cert_policy_explicit_text_has_encoding_tag_in_set_30984` | — | 6 | 735 | 6 | 0 | 0 |
| `cicasgen_subject_common_name_fqdnor_wildcard_portion_matches_29566` | — | 5 | 748 | 5 | 0 | 0 |
| `cicasgen_when_version_present_version_in_set_31169` | — | 5 | 1066 | 5 | 0 | 0 |
| `cicasgen_when_not_subject_locality_present_subject_province_29433` | — | 4 | 11 | 4 | 0 | 0 |
| `cicasgen_when_subject_alt_name_present_and_not_dn_empty_subject_31067` | — | 4 | 685 | 4 | 0 | 0 |
| `cicasgen_sig_alg_matches_tbssignature_31396` | — | 4 | 1077 | 4 | 0 | 0 |
| `cicasgen_when_has_any_extension_version_eq_31344` | — | 3 | 1016 | 3 | 0 | 0 |
| `cicasgen_when_has_any_extension_version_eq_31403` | — | 3 | 1016 | 3 | 0 | 0 |
| `cicasgen_when_version_eq_issuer_unique_id_absent_and_subject_31409` | — | 2 | 14 | 2 | 0 | 0 |
| `cicasgen_when_issuer_unique_id_present_or_subject_unique_id_31342` | — | 2 | 23 | 2 | 0 | 0 |
| `cicasgen_when_issuer_unique_id_present_or_subject_unique_id_31444` | — | 2 | 23 | 2 | 0 | 0 |
| `cicasgen_when_oid_policy_organization_validated_list_contains_29474` | — | 2 | 215 | 1 | 0 | 1 |
| `cicasgen_when_oid_policy_organization_validated_list_contains_29475` | — | 2 | 215 | 1 | 0 | 1 |
| `cicasgen_aiamethod_locations_tag_in_set_and_aiamethod_locations_29485` | — | 2 | 431 | 2 | 0 | 0 |
| `cicasgen_dnattribute_values_encoded_as_29564` | — | 2 | 1034 | 2 | 0 | 0 |
| `cicasgen_domain_names_do_not_end_with_ipreverse_zone_suffix_29019` | — | 2 | 919 | 2 | 0 | 0 |
| `cicasgen_serial_number_dersign_bit_zero_31368` | — | 2 | 1077 | 2 | 0 | 0 |
| `cicasgen_serial_number_value_31123` | — | 2 | 1077 | 2 | 0 | 0 |
| `cicasgen_serial_number_value_31161` | — | 2 | 1077 | 2 | 0 | 0 |
| `cicasgen_validity_utctime_values_use_zulu_31175` | — | 2 | 1077 | 2 | 0 | 0 |
| `cicasgen_ext_subfield_present_policy_constraints_or_ext_subfield_31056` | — | 1 | 5 | 1 | 0 | 0 |
| `cicasgen_when_root_ca_not_crl_dist_present_29288` | — | 1 | 24 | 1 | 0 | 0 |
| `cicasgen_sig_alg_matches_tbssignature_29394` | — | 1 | 233 | 1 | 0 | 0 |
| `cicasgen_when_cert_policy_present_policy_identifiers_count_29491` | — | 1 | 508 | 1 | 0 | 0 |
| `cicasgen_when_not_dn_empty_subject_subject_alt_name_not_critical_29415` | — | 1 | 489 | 1 | 0 | 0 |
| `cicasgen_dnattribute_values_encoded_as_29562` | — | 1 | 1034 | 1 | 0 | 0 |
| `cicasgen_spki_rsa_alg_oid_hex_29535` | — | 1 | 814 | 1 | 0 | 0 |
| `cicasgen_spki_rsa_alg_oid_hex_29538` | — | 1 | 1034 | 1 | 0 | 0 |
| `cicasgen_when_subscriber_cert_not_path_len_constraint_present_29490` | — | 1 | 748 | 1 | 0 | 0 |
