# New-Lint Findings

- corpus: **tranco_1m**
- parseable certificates scanned: **47791**
- findings from CICAS-added zlint lints (`cicasgen_`): **57583**
- upstream zlint findings: **96826**
- new-lint findings on certs with no upstream finding: **1042**
- independent structural audit over new-lint findings: CONFIRMED=8, NOCHECK=1034
- preliminary structural-screen findings: **8** (independent CONFIRMED and no any-upstream result)

Per CICAS-added lint:

| new lint | rule | section | fires | no-upstream certs | independent | rule text |
|---|---:|---|---:|---:|---|---|
| `cicasgen_when_oid_eq_oid_sha256_with_rsaencryption_or_oid_eq_oid_29766` | 29766 | 7.1.3.2.1 | 28748 | 473 | NOCHECK:473 | When encoded, the AlgorithmIdentifier MUST be byte-for-byte identical with the specified hex-en... |
| `cicasgen_when_subscriber_cert_validity_period_value_at_most_28763` | 28763 | 6.3.2 | 14158 | 123 | NOCHECK:123 | MUST NOT have a Validity Period greater than 398 days. |
| `cicasgen_when_subscriber_cert_certificate_policies_has_no_policy_29757` | 29757 | 7.1.2.7.9 | 13836 | 117 | NOCHECK:117 | `policyQualifiers` are NOT RECOMMENDED to be present |
| `cicasgen_certificate_policies_has_no_policy_qualifiers_29246` | 29246 | 7.1.2.10.5 | 175 | 95 | NOCHECK:95 | `policyQualifiers` are NOT RECOMMENDED to be present |
| `cicasgen_certificate_policies_has_no_policy_qualifiers_29733` | 29733 | 7.1.2.10.5 | 175 | 95 | NOCHECK:95 | `policyQualifiers` are NOT RECOMMENDED to be present |
| `cicasgen_when_subscriber_cert_dnsnames_fqdnor_wildcard_portion_29420` | 29420 | 7.1.2.7.12 | 146 | 0 | - | The Fully-Qualified Domain Name or the FQDN portion of the Wildcard Domain Name contained in th... |
| `cicasgen_oid_list_count_in_set_policy_identifiers_29244` | 29244 | 7.1.2.10.5 | 60 | 40 | NOCHECK:40 | Regardless of the order of `PolicyInformation` values, the Certificate Policies extension MUST ... |
| `cicasgen_oid_list_count_in_set_policy_identifiers_29247` | 29247 | 7.1.2.10.5 | 60 | 40 | NOCHECK:40 | MUST include exactly one Reserved Certificate Policy Identifier (see [Section 7. |
| `cicasgen_when_root_ca_authority_key_id_present_29220` | 29220 | 7.1.2.1.3 | 58 | 37 | NOCHECK:37 | `keyIdentifier` | MUST be present. |
| `cicasgen_subject_organization_present_29230` | 29230 | 7.1.2.10.2 | 30 | 0 | - | `organizationName` | MUST | The CA's name or DBA. |
| `cicasgen_not_ext_subfield_present_authority_key_id_28730` | 28730 | 7.1.2.11.1 | 17 | 1 | CONFIRMED:1 | `authorityCertSerialNumber` | MUST NOT be present |
| `cicasgen_not_ext_subfield_present_authority_key_id_29274` | 29274 | 7.1.2.11.1 | 17 | 1 | CONFIRMED:1 | `authorityCertIssuer` | MUST NOT be present |
| `cicasgen_crldpfull_name_general_names_all_tags_in_set_and_29282` | 29282 | 7.1.2.11.2 | 13 | 7 | NOCHECK:7 | the scheme of each MUST be "http" |
| `cicasgen_when_pubkey_alg_rsa_ku_has_digital_signature_29409` | 29409 | 7.1.2.7.11 | 11 | 0 | - | `digitalSignature` | Y | SHOULD |
| `cicasgen_when_subscriber_cert_dnsnames_present_or_ipaddresses_29414` | 29414 | 7.1.2.7.12 | 9 | 0 | - | MUST contain at least one `dNSName` or `iPAddress` `GeneralName` |
| `cicasgen_when_root_ca_not_ext_subfield_present_authority_key_id_28729` | 28729 | 7.1.2.1.3 | 8 | 1 | NOCHECK:1 | `authorityCertSerialNumber` | MUST NOT be present |
| `cicasgen_when_root_ca_not_ext_subfield_present_authority_key_id_29221` | 29221 | 7.1.2.1.3 | 8 | 1 | NOCHECK:1 | `authorityCertIssuer` | MUST NOT be present |
| `cicasgen_dn_component_order_dns_reverse_29455` | 29455 | 7.1.2.7.4 | 6 | 0 | - | The Domain Labels MUST be encoded in the reverse order to the on-wire representation of domain ... |
| `cicasgen_when_oid_policy_organization_validated_list_contains_29454` | 29454 | 7.1.2.7.4 | 6 | 0 | - | The `domainComponent` fields for the Domain Name MUST be in a single ordered sequence containin... |
| `cicasgen_when_pubkey_alg_rsa_not_ku_has_data_encipherment_29411` | 29411 | 7.1.2.7.11 | 6 | 0 | - | `dataEncipherment` | Y | NOT RECOMMENDED |
| `cicasgen_when_not_has_any_extension_and_issuer_unique_id_absent_31153` | 31153 | 4.1.2.1 | 5 | 0 | - | If only basic fields are present, the version SHOULD be 1 (the value is omitted from the certif... |
| `cicasgen_when_root_ca_not_crl_dist_present_29276` | 29276 | 7.1.2.11.2 | 5 | 3 | CONFIRMED:3 | extension SHOULD NOT be present in: |
| `cicasgen_when_root_ca_not_crl_dist_present_29288` | 29288 | 7.1.2.11.2 | 5 | 3 | CONFIRMED:3 | Root CA Certificates. |
| `cicasgen_name_const_critical_29260` | 29260 | 7.1.2.10.8 | 4 | 0 | - | this extension SHOULD be marked critical |
| `cicasgen_when_oid_policy_organization_validated_list_contains_29468` | 29468 | 7.1.2.7.4 | 4 | 3 | NOCHECK:3 | `postalCode` | NOT RECOMMENDED | If present |
| `cicasgen_not_cert_policy_explicit_text_has_encoding_tag_in_set_30984` | 30984 | 4.2.1.4 | 3 | 1 | NOCHECK:1 | Conforming CAs MUST NOT encode explicitText as VisibleString or BMPString |
| `cicasgen_oid_list_count_in_set_policy_identifiers_29492` | 29492 | 7.1.2.7.9 | 3 | 1 | NOCHECK:1 | Regardless of the order of `PolicyInformation` values, the Certificate Policies extension MUST ... |
| `cicasgen_basic_constraints_cafalse_or_absent_29507` | 29507 | 7.1.2.8.4 | 1 | 0 | - | certificates MUST NOT be CA certificates |
| `cicasgen_basic_constraints_cafalse_or_absent_29508` | 29508 | 7.1.2.8.4 | 1 | 0 | - | `cA` | MUST be FALSE |
| `cicasgen_ext_key_usage_only_has_usages_in_set_29510` | 29510 | 7.1.2.8.5 | 1 | 0 | - | `Any other value` | Presence | MUST NOT |
| `cicasgen_not_crldphas_distribution_point_field_c_rlissuer_29285` | 29285 | 7.1.2.11.2 | 1 | 0 | - | `cRLIssuer` | MUST NOT | |
| `cicasgen_subject_common_name_fqdnor_wildcard_portion_matches_29566` | 29566 | 7.1.4.3 | 1 | 0 | - | Specifically, all Domain Labels of the Fully-Qualified Domain Name or FQDN portion of the Wildc... |
| `cicasgen_when_access_description_method_present_aiamethod_31377` | 31377 | 4.2.2.1 | 1 | 0 | - | When the id-ad-caIssuers accessMethod is used, at least one instance SHOULD specify an accessLo... |
| `cicasgen_when_has_any_extension_and_has_any_extension_version_eq_31403` | 31403 | 4.1.2.1 | 1 | 0 | - | When extensions are used, as expected in this profile, version MUST be 3 (value is 2) |

New-lint findings on certs not flagged by upstream zlint (full list in `new_lint_findings.jsonl`):

| cert | new lint | rule | section | independent | evidence |
|---|---|---:|---|---|---|
| `0000010_31ad6648f8104138_apple.com_02_chain.pem` | `cicasgen_when_root_ca_authority_key_id_present_29220` | 29220 | 7.1.2.1.3 | NOCHECK | no independent check for this lint family |
| `0000012_28101ee3cd2ff6f2_mail.ru_01_chain.pem` | `cicasgen_certificate_policies_has_no_policy_qualifiers_29246` | 29246 | 7.1.2.10.5 | NOCHECK | no independent check for this lint family |
| `0000012_28101ee3cd2ff6f2_mail.ru_01_chain.pem` | `cicasgen_certificate_policies_has_no_policy_qualifiers_29733` | 29733 | 7.1.2.10.5 | NOCHECK | no independent check for this lint family |
| `0000012_28101ee3cd2ff6f2_mail.ru_01_chain.pem` | `cicasgen_when_oid_eq_oid_sha256_with_rsaencryption_or_oid_eq_oid_29766` | 29766 | 7.1.3.2.1 | NOCHECK | no independent check for this lint family |
| `0000012_4acd8dc6020a545a_mail.ru_03_chain.pem` | `cicasgen_when_oid_eq_oid_sha256_with_rsaencryption_or_oid_eq_oid_29766` | 29766 | 7.1.3.2.1 | NOCHECK | no independent check for this lint family |
| `0000012_d95d0e8eda79525b_mail.ru_02_chain.pem` | `cicasgen_when_oid_eq_oid_sha256_with_rsaencryption_or_oid_eq_oid_29766` | 29766 | 7.1.3.2.1 | NOCHECK | no independent check for this lint family |
| `0000012_d95d0e8eda79525b_mail.ru_02_chain.pem` | `cicasgen_when_root_ca_authority_key_id_present_29220` | 29220 | 7.1.2.1.3 | NOCHECK | no independent check for this lint family |
| `0000013_b83f5a71cbb1aa4b_www.ezviz7.com_00_leaf.pem` | `cicasgen_when_oid_eq_oid_sha256_with_rsaencryption_or_oid_eq_oid_29766` | 29766 | 7.1.3.2.1 | NOCHECK | no independent check for this lint family |
| `0000013_b83f5a71cbb1aa4b_www.ezviz7.com_00_leaf.pem` | `cicasgen_when_subscriber_cert_certificate_policies_has_no_policy_29757` | 29757 | 7.1.2.7.9 | NOCHECK | no independent check for this lint family |
| `0000013_b83f5a71cbb1aa4b_www.ezviz7.com_00_leaf.pem` | `cicasgen_when_subscriber_cert_validity_period_value_at_most_28763` | 28763 | 6.3.2 | NOCHECK | no independent check for this lint family |
| `0000021_38d895f5105bc254_live.com_01_chain.pem` | `cicasgen_when_oid_eq_oid_sha256_with_rsaencryption_or_oid_eq_oid_29766` | 29766 | 7.1.3.2.1 | NOCHECK | no independent check for this lint family |
| `0000022_6ebff927297a5b3a_office.com_01_chain.pem` | `cicasgen_when_oid_eq_oid_sha256_with_rsaencryption_or_oid_eq_oid_29766` | 29766 | 7.1.3.2.1 | NOCHECK | no independent check for this lint family |
| `0000034_fec41e32ca75c295_fastly.net_01_chain.pem` | `cicasgen_when_oid_eq_oid_sha256_with_rsaencryption_or_oid_eq_oid_29766` | 29766 | 7.1.3.2.1 | NOCHECK | no independent check for this lint family |
| `0000037_b0f330a31a0c5098_appsflyersdk.com_01_chain.pem` | `cicasgen_when_oid_eq_oid_sha256_with_rsaencryption_or_oid_eq_oid_29766` | 29766 | 7.1.3.2.1 | NOCHECK | no independent check for this lint family |
| `0000042_83624fd338c8d9b0_wordpress.org_01_chain.pem` | `cicasgen_when_oid_eq_oid_sha256_with_rsaencryption_or_oid_eq_oid_29766` | 29766 | 7.1.3.2.1 | NOCHECK | no independent check for this lint family |
| `0000049_3337d4e4b4ef6a94_gandi.net_01_chain.pem` | `cicasgen_when_oid_eq_oid_sha256_with_rsaencryption_or_oid_eq_oid_29766` | 29766 | 7.1.3.2.1 | NOCHECK | no independent check for this lint family |
| `0000053_aeb1fd7410e83bc9_x.com_01_chain.pem` | `cicasgen_when_oid_eq_oid_sha256_with_rsaencryption_or_oid_eq_oid_29766` | 29766 | 7.1.3.2.1 | NOCHECK | no independent check for this lint family |
| `0000060_ddcd1e8a20638d4a_msn.com_02_chain.pem` | `cicasgen_when_oid_eq_oid_sha256_with_rsaencryption_or_oid_eq_oid_29766` | 29766 | 7.1.3.2.1 | NOCHECK | no independent check for this lint family |
| `0000060_ea7a25255d111fc3_msn.com_01_chain.pem` | `cicasgen_when_oid_eq_oid_sha256_with_rsaencryption_or_oid_eq_oid_29766` | 29766 | 7.1.3.2.1 | NOCHECK | no independent check for this lint family |
| `0000070_238b85a0099c65b9_ntp.org_01_chain.pem` | `cicasgen_when_oid_eq_oid_sha256_with_rsaencryption_or_oid_eq_oid_29766` | 29766 | 7.1.3.2.1 | NOCHECK | no independent check for this lint family |
| `0000072_76b27b80a58027dc_vimeo.com_02_chain.pem` | `cicasgen_when_oid_eq_oid_sha256_with_rsaencryption_or_oid_eq_oid_29766` | 29766 | 7.1.3.2.1 | NOCHECK | no independent check for this lint family |
| `0000081_7cd6cdd25eee2512_qq.com_01_chain.pem` | `cicasgen_oid_list_count_in_set_policy_identifiers_29244` | 29244 | 7.1.2.10.5 | NOCHECK | no independent check for this lint family |
| `0000081_7cd6cdd25eee2512_qq.com_01_chain.pem` | `cicasgen_oid_list_count_in_set_policy_identifiers_29247` | 29247 | 7.1.2.10.5 | NOCHECK | no independent check for this lint family |
| `0000081_7cd6cdd25eee2512_qq.com_01_chain.pem` | `cicasgen_when_oid_eq_oid_sha256_with_rsaencryption_or_oid_eq_oid_29766` | 29766 | 7.1.3.2.1 | NOCHECK | no independent check for this lint family |
| `0000085_ac8ea9f2874fd368_windows.com_01_chain.pem` | `cicasgen_when_oid_eq_oid_sha256_with_rsaencryption_or_oid_eq_oid_29766` | 29766 | 7.1.3.2.1 | NOCHECK | no independent check for this lint family |
| `0000100_c8025f9fc65fdfc9_sentry.io_01_chain.pem` | `cicasgen_oid_list_count_in_set_policy_identifiers_29244` | 29244 | 7.1.2.10.5 | NOCHECK | no independent check for this lint family |
| `0000100_c8025f9fc65fdfc9_sentry.io_01_chain.pem` | `cicasgen_oid_list_count_in_set_policy_identifiers_29247` | 29247 | 7.1.2.10.5 | NOCHECK | no independent check for this lint family |
| `0000100_c8025f9fc65fdfc9_sentry.io_01_chain.pem` | `cicasgen_when_oid_eq_oid_sha256_with_rsaencryption_or_oid_eq_oid_29766` | 29766 | 7.1.3.2.1 | NOCHECK | no independent check for this lint family |
| `0000108_973a41276ffd01e0_t.me_01_chain.pem` | `cicasgen_certificate_policies_has_no_policy_qualifiers_29246` | 29246 | 7.1.2.10.5 | NOCHECK | no independent check for this lint family |
| `0000108_973a41276ffd01e0_t.me_01_chain.pem` | `cicasgen_certificate_policies_has_no_policy_qualifiers_29733` | 29733 | 7.1.2.10.5 | NOCHECK | no independent check for this lint family |
| `0000108_973a41276ffd01e0_t.me_01_chain.pem` | `cicasgen_when_oid_eq_oid_sha256_with_rsaencryption_or_oid_eq_oid_29766` | 29766 | 7.1.3.2.1 | NOCHECK | no independent check for this lint family |
| `0000111_6f9d6055094efcfc_europa.eu_01_chain.pem` | `cicasgen_when_oid_eq_oid_sha256_with_rsaencryption_or_oid_eq_oid_29766` | 29766 | 7.1.3.2.1 | NOCHECK | no independent check for this lint family |
| `0000127_5338ebec8fb2ac60_amazonvideo.com_01_chain.pem` | `cicasgen_when_oid_eq_oid_sha256_with_rsaencryption_or_oid_eq_oid_29766` | 29766 | 7.1.3.2.1 | NOCHECK | no independent check for this lint family |
| `0000127_87dcd4dc74640a32_amazonvideo.com_02_chain.pem` | `cicasgen_when_oid_eq_oid_sha256_with_rsaencryption_or_oid_eq_oid_29766` | 29766 | 7.1.3.2.1 | NOCHECK | no independent check for this lint family |
| `0000133_ebd41040e4bb3ec7_forms.gle_03_chain.pem` | `cicasgen_when_root_ca_authority_key_id_present_29220` | 29220 | 7.1.2.1.3 | NOCHECK | no independent check for this lint family |
| `0000143_868a41400d425a93_www.miit.gov.cn_01_chain.pem` | `cicasgen_when_oid_eq_oid_sha256_with_rsaencryption_or_oid_eq_oid_29766` | 29766 | 7.1.3.2.1 | NOCHECK | no independent check for this lint family |
| `0000146_1b2928021a4b89cf_reg.ru_01_chain.pem` | `cicasgen_when_oid_eq_oid_sha256_with_rsaencryption_or_oid_eq_oid_29766` | 29766 | 7.1.3.2.1 | NOCHECK | no independent check for this lint family |
| `0000148_d3b128216a843f8e_mailinabox.email_01_chain.pem` | `cicasgen_when_oid_eq_oid_sha256_with_rsaencryption_or_oid_eq_oid_29766` | 29766 | 7.1.3.2.1 | NOCHECK | no independent check for this lint family |
| `0000157_1f8eb9e9a8e066cc_paypal.com_01_chain.pem` | `cicasgen_oid_list_count_in_set_policy_identifiers_29244` | 29244 | 7.1.2.10.5 | NOCHECK | no independent check for this lint family |
| `0000157_1f8eb9e9a8e066cc_paypal.com_01_chain.pem` | `cicasgen_oid_list_count_in_set_policy_identifiers_29247` | 29247 | 7.1.2.10.5 | NOCHECK | no independent check for this lint family |
| `0000157_1f8eb9e9a8e066cc_paypal.com_01_chain.pem` | `cicasgen_when_oid_eq_oid_sha256_with_rsaencryption_or_oid_eq_oid_29766` | 29766 | 7.1.3.2.1 | NOCHECK | no independent check for this lint family |
| `0000167_2fe357db13751ff9_applovin.com_01_chain.pem` | `cicasgen_when_oid_eq_oid_sha256_with_rsaencryption_or_oid_eq_oid_29766` | 29766 | 7.1.3.2.1 | NOCHECK | no independent check for this lint family |
| `0000182_5d56499be4d2e08b_webex.com_02_chain.pem` | `cicasgen_when_oid_eq_oid_sha256_with_rsaencryption_or_oid_eq_oid_29766` | 29766 | 7.1.3.2.1 | NOCHECK | no independent check for this lint family |
| `0000182_5d56499be4d2e08b_webex.com_02_chain.pem` | `cicasgen_when_root_ca_authority_key_id_present_29220` | 29220 | 7.1.2.1.3 | NOCHECK | no independent check for this lint family |
| `0000182_8bb2f6883fed289a_webex.com_01_chain.pem` | `cicasgen_certificate_policies_has_no_policy_qualifiers_29246` | 29246 | 7.1.2.10.5 | NOCHECK | no independent check for this lint family |
| `0000182_8bb2f6883fed289a_webex.com_01_chain.pem` | `cicasgen_certificate_policies_has_no_policy_qualifiers_29733` | 29733 | 7.1.2.10.5 | NOCHECK | no independent check for this lint family |
| `0000182_8bb2f6883fed289a_webex.com_01_chain.pem` | `cicasgen_when_oid_eq_oid_sha256_with_rsaencryption_or_oid_eq_oid_29766` | 29766 | 7.1.3.2.1 | NOCHECK | no independent check for this lint family |
| `0000183_5d1bc399274e649e_example.com_02_chain.pem` | `cicasgen_certificate_policies_has_no_policy_qualifiers_29246` | 29246 | 7.1.2.10.5 | NOCHECK | no independent check for this lint family |
| `0000183_5d1bc399274e649e_example.com_02_chain.pem` | `cicasgen_certificate_policies_has_no_policy_qualifiers_29733` | 29733 | 7.1.2.10.5 | NOCHECK | no independent check for this lint family |
| `0000195_f5165fc624453361_forbes.com_01_chain.pem` | `cicasgen_when_oid_eq_oid_sha256_with_rsaencryption_or_oid_eq_oid_29766` | 29766 | 7.1.3.2.1 | NOCHECK | no independent check for this lint family |
| `0000207_cbb522d7b7f127ad_ozon.ru_02_chain.pem` | `cicasgen_when_oid_eq_oid_sha256_with_rsaencryption_or_oid_eq_oid_29766` | 29766 | 7.1.3.2.1 | NOCHECK | no independent check for this lint family |
| `0000207_cbb522d7b7f127ad_ozon.ru_02_chain.pem` | `cicasgen_when_root_ca_authority_key_id_present_29220` | 29220 | 7.1.2.1.3 | NOCHECK | no independent check for this lint family |
| `0000208_8eb2f17d668941c3_ebay.com_01_chain.pem` | `cicasgen_when_oid_eq_oid_sha256_with_rsaencryption_or_oid_eq_oid_29766` | 29766 | 7.1.3.2.1 | NOCHECK | no independent check for this lint family |
| `0000209_8c54c334b66ba4e4_cpanel.net_01_chain.pem` | `cicasgen_when_oid_eq_oid_sha256_with_rsaencryption_or_oid_eq_oid_29766` | 29766 | 7.1.3.2.1 | NOCHECK | no independent check for this lint family |
| `0000210_3ee0278df71fa3c1_pki.goog_02_chain.pem` | `cicasgen_oid_list_count_in_set_policy_identifiers_29244` | 29244 | 7.1.2.10.5 | NOCHECK | no independent check for this lint family |
| `0000210_3ee0278df71fa3c1_pki.goog_02_chain.pem` | `cicasgen_oid_list_count_in_set_policy_identifiers_29247` | 29247 | 7.1.2.10.5 | NOCHECK | no independent check for this lint family |
| `0000210_3ee0278df71fa3c1_pki.goog_02_chain.pem` | `cicasgen_when_oid_eq_oid_sha256_with_rsaencryption_or_oid_eq_oid_29766` | 29766 | 7.1.3.2.1 | NOCHECK | no independent check for this lint family |
| `0000210_e6fe22bf45e4f0d3_pki.goog_01_chain.pem` | `cicasgen_when_oid_eq_oid_sha256_with_rsaencryption_or_oid_eq_oid_29766` | 29766 | 7.1.3.2.1 | NOCHECK | no independent check for this lint family |
| `0000212_0587d6bd2819587a_weather.com_01_chain.pem` | `cicasgen_oid_list_count_in_set_policy_identifiers_29244` | 29244 | 7.1.2.10.5 | NOCHECK | no independent check for this lint family |
| `0000212_0587d6bd2819587a_weather.com_01_chain.pem` | `cicasgen_oid_list_count_in_set_policy_identifiers_29247` | 29247 | 7.1.2.10.5 | NOCHECK | no independent check for this lint family |
| `0000216_516aa665dbd48988_twitch.tv_01_chain.pem` | `cicasgen_when_oid_eq_oid_sha256_with_rsaencryption_or_oid_eq_oid_29766` | 29766 | 7.1.3.2.1 | NOCHECK | no independent check for this lint family |
| `0000235_131fce7784016899_ubuntu.com_01_chain.pem` | `cicasgen_when_oid_eq_oid_sha256_with_rsaencryption_or_oid_eq_oid_29766` | 29766 | 7.1.3.2.1 | NOCHECK | no independent check for this lint family |
| `0000244_ee5f7abd6981bb02_doubleverify.com_03_chain.pem` | `cicasgen_when_oid_eq_oid_sha256_with_rsaencryption_or_oid_eq_oid_29766` | 29766 | 7.1.3.2.1 | NOCHECK | no independent check for this lint family |
| `0000254_072639d0b140d5bf_linktr.ee_02_chain.pem` | `cicasgen_when_oid_eq_oid_sha256_with_rsaencryption_or_oid_eq_oid_29766` | 29766 | 7.1.3.2.1 | NOCHECK | no independent check for this lint family |
| `0000254_13949634d99cd6fd_linktr.ee_01_chain.pem` | `cicasgen_when_oid_eq_oid_sha256_with_rsaencryption_or_oid_eq_oid_29766` | 29766 | 7.1.3.2.1 | NOCHECK | no independent check for this lint family |
| `0000274_953bb2ff81a783da_www.myhuaweicloud.com_00_leaf.pem` | `cicasgen_when_oid_eq_oid_sha256_with_rsaencryption_or_oid_eq_oid_29766` | 29766 | 7.1.3.2.1 | NOCHECK | no independent check for this lint family |
| `0000274_953bb2ff81a783da_www.myhuaweicloud.com_00_leaf.pem` | `cicasgen_when_subscriber_cert_certificate_policies_has_no_policy_29757` | 29757 | 7.1.2.7.9 | NOCHECK | no independent check for this lint family |
| `0000274_953bb2ff81a783da_www.myhuaweicloud.com_00_leaf.pem` | `cicasgen_when_subscriber_cert_validity_period_value_at_most_28763` | 28763 | 6.3.2 | NOCHECK | no independent check for this lint family |
| `0000284_338edb04fb8beaf0_salesforce.com_01_chain.pem` | `cicasgen_oid_list_count_in_set_policy_identifiers_29244` | 29244 | 7.1.2.10.5 | NOCHECK | no independent check for this lint family |
| `0000284_338edb04fb8beaf0_salesforce.com_01_chain.pem` | `cicasgen_oid_list_count_in_set_policy_identifiers_29247` | 29247 | 7.1.2.10.5 | NOCHECK | no independent check for this lint family |
| `0000295_996bb81f161e1dac_alibaba.com_01_chain.pem` | `cicasgen_when_oid_eq_oid_sha256_with_rsaencryption_or_oid_eq_oid_29766` | 29766 | 7.1.3.2.1 | NOCHECK | no independent check for this lint family |
| `0000296_cb3ccbb76031e5e0_dnsmadeeasy.com_02_chain.pem` | `cicasgen_when_oid_eq_oid_sha256_with_rsaencryption_or_oid_eq_oid_29766` | 29766 | 7.1.3.2.1 | NOCHECK | no independent check for this lint family |
| `0000296_cb3ccbb76031e5e0_dnsmadeeasy.com_02_chain.pem` | `cicasgen_when_root_ca_authority_key_id_present_29220` | 29220 | 7.1.2.1.3 | NOCHECK | no independent check for this lint family |
| `0000297_6542d176bed50f19_samsungcloud.com_01_chain.pem` | `cicasgen_when_oid_eq_oid_sha256_with_rsaencryption_or_oid_eq_oid_29766` | 29766 | 7.1.3.2.1 | NOCHECK | no independent check for this lint family |
| `0000297_e793c9b02fd8aa13_samsungcloud.com_03_chain.pem` | `cicasgen_when_oid_eq_oid_sha256_with_rsaencryption_or_oid_eq_oid_29766` | 29766 | 7.1.3.2.1 | NOCHECK | no independent check for this lint family |
| `0000297_e793c9b02fd8aa13_samsungcloud.com_03_chain.pem` | `cicasgen_when_root_ca_authority_key_id_present_29220` | 29220 | 7.1.2.1.3 | NOCHECK | no independent check for this lint family |
| `0000305_05dc9edc0fddfa97_weibo.com_01_chain.pem` | `cicasgen_oid_list_count_in_set_policy_identifiers_29244` | 29244 | 7.1.2.10.5 | NOCHECK | no independent check for this lint family |
| `0000305_05dc9edc0fddfa97_weibo.com_01_chain.pem` | `cicasgen_oid_list_count_in_set_policy_identifiers_29247` | 29247 | 7.1.2.10.5 | NOCHECK | no independent check for this lint family |
| `0000305_05dc9edc0fddfa97_weibo.com_01_chain.pem` | `cicasgen_when_oid_eq_oid_sha256_with_rsaencryption_or_oid_eq_oid_29766` | 29766 | 7.1.3.2.1 | NOCHECK | no independent check for this lint family |
| `0000326_138bdf6e23ac971e_autodesk.com_01_chain.pem` | `cicasgen_when_oid_eq_oid_sha256_with_rsaencryption_or_oid_eq_oid_29766` | 29766 | 7.1.3.2.1 | NOCHECK | no independent check for this lint family |
| `0000332_5539f8c901051834_issuu.com_01_chain.pem` | `cicasgen_when_oid_eq_oid_sha256_with_rsaencryption_or_oid_eq_oid_29766` | 29766 | 7.1.3.2.1 | NOCHECK | no independent check for this lint family |
| `0000334_543d9b7fc2a6471c_telekom.de_02_chain.pem` | `cicasgen_when_oid_eq_oid_sha256_with_rsaencryption_or_oid_eq_oid_29766` | 29766 | 7.1.3.2.1 | NOCHECK | no independent check for this lint family |
| `0000337_762538439509c411_checkpoint.com_01_chain.pem` | `cicasgen_certificate_policies_has_no_policy_qualifiers_29246` | 29246 | 7.1.2.10.5 | NOCHECK | no independent check for this lint family |
| `0000337_762538439509c411_checkpoint.com_01_chain.pem` | `cicasgen_certificate_policies_has_no_policy_qualifiers_29733` | 29733 | 7.1.2.10.5 | NOCHECK | no independent check for this lint family |
| `0000337_762538439509c411_checkpoint.com_01_chain.pem` | `cicasgen_when_oid_eq_oid_sha256_with_rsaencryption_or_oid_eq_oid_29766` | 29766 | 7.1.3.2.1 | NOCHECK | no independent check for this lint family |
| `0000342_111006378afbe8e9_un.org_01_chain.pem` | `cicasgen_when_oid_eq_oid_sha256_with_rsaencryption_or_oid_eq_oid_29766` | 29766 | 7.1.3.2.1 | NOCHECK | no independent check for this lint family |
| `0000342_52f0e1c4e58ec629_un.org_02_chain.pem` | `cicasgen_when_oid_eq_oid_sha256_with_rsaencryption_or_oid_eq_oid_29766` | 29766 | 7.1.3.2.1 | NOCHECK | no independent check for this lint family |
| `0000342_52f0e1c4e58ec629_un.org_02_chain.pem` | `cicasgen_when_root_ca_authority_key_id_present_29220` | 29220 | 7.1.2.1.3 | NOCHECK | no independent check for this lint family |
| `0000348_a883559231f8388d_trueconf.net_02_chain.pem` | `cicasgen_when_oid_eq_oid_sha256_with_rsaencryption_or_oid_eq_oid_29766` | 29766 | 7.1.3.2.1 | NOCHECK | no independent check for this lint family |
| `0000362_87e01cc4dd0c9d92_stanford.edu_01_chain.pem` | `cicasgen_when_oid_eq_oid_sha256_with_rsaencryption_or_oid_eq_oid_29766` | 29766 | 7.1.3.2.1 | NOCHECK | no independent check for this lint family |
| `0000362_d7a7a0fb5d7e2731_stanford.edu_03_chain.pem` | `cicasgen_when_root_ca_authority_key_id_present_29220` | 29220 | 7.1.2.1.3 | NOCHECK | no independent check for this lint family |
| `0000362_d7a7a0fb5d7e2731_stanford.edu_03_chain.pem` | `cicasgen_when_root_ca_not_crl_dist_present_29276` | 29276 | 7.1.2.11.2 | CONFIRMED | root CA carries CRLDP (advisory) |
| `0000362_d7a7a0fb5d7e2731_stanford.edu_03_chain.pem` | `cicasgen_when_root_ca_not_crl_dist_present_29288` | 29288 | 7.1.2.11.2 | CONFIRMED | root CA carries CRLDP (advisory) |
| `0000371_ec9d6bcab9818b7d_dailymotion.com_01_chain.pem` | `cicasgen_when_oid_eq_oid_sha256_with_rsaencryption_or_oid_eq_oid_29766` | 29766 | 7.1.3.2.1 | NOCHECK | no independent check for this lint family |
| `0000388_8346922cb8730bb6_yahoo.co.jp_01_chain.pem` | `cicasgen_certificate_policies_has_no_policy_qualifiers_29246` | 29246 | 7.1.2.10.5 | NOCHECK | no independent check for this lint family |
| `0000388_8346922cb8730bb6_yahoo.co.jp_01_chain.pem` | `cicasgen_certificate_policies_has_no_policy_qualifiers_29733` | 29733 | 7.1.2.10.5 | NOCHECK | no independent check for this lint family |
| `0000388_8346922cb8730bb6_yahoo.co.jp_01_chain.pem` | `cicasgen_when_oid_eq_oid_sha256_with_rsaencryption_or_oid_eq_oid_29766` | 29766 | 7.1.3.2.1 | NOCHECK | no independent check for this lint family |
| `0000406_1a6e1e3107328747_businessinsider.com_01_chain.pem` | `cicasgen_when_oid_eq_oid_sha256_with_rsaencryption_or_oid_eq_oid_29766` | 29766 | 7.1.3.2.1 | NOCHECK | no independent check for this lint family |
| `0000414_944d87943c5b47f4_huawei.com_02_chain.pem` | `cicasgen_when_oid_eq_oid_sha256_with_rsaencryption_or_oid_eq_oid_29766` | 29766 | 7.1.3.2.1 | NOCHECK | no independent check for this lint family |
| `0000414_bae1c37cee8621a3_huawei.com_01_chain.pem` | `cicasgen_certificate_policies_has_no_policy_qualifiers_29246` | 29246 | 7.1.2.10.5 | NOCHECK | no independent check for this lint family |
| ... | ... | ... | ... | ... | 942 more rows in JSONL |
