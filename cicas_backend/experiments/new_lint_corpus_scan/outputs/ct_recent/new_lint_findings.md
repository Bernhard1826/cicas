# New-Lint Findings

- corpus: **ct_recent**
- parseable certificates scanned: **63327**
- findings from CICAS-added zlint lints (`cicasgen_`): **57558**
- upstream zlint findings: **120838**
- new-lint findings on certs with no upstream finding: **283**
- independent structural audit over new-lint findings: CONFIRMED=1, NOCHECK=282
- strict reportable new-lint findings: **1** (independent CONFIRMED and not quality-gated)

Per CICAS-added lint:

| new lint | rule | section | fires | no-upstream certs | independent | rule text |
|---|---:|---|---:|---:|---|---|
| `cicasgen_when_oid_eq_oid_sha256_with_rsaencryption_or_oid_eq_oid_29766` | 29766 | 7.1.3.2.1 | 48141 | 96 | NOCHECK:96 | When encoded, the AlgorithmIdentifier MUST be byte-for-byte identical with the specified hex-en... |
| `cicasgen_when_subscriber_cert_certificate_policies_has_no_policy_29757` | 29757 | 7.1.2.7.9 | 8645 | 0 | - | `policyQualifiers` are NOT RECOMMENDED to be present |
| `cicasgen_when_subscriber_cert_dnsnames_fqdnor_wildcard_portion_29420` | 29420 | 7.1.2.7.12 | 510 | 0 | - | The Fully-Qualified Domain Name or the FQDN portion of the Wildcard Domain Name contained in th... |
| `cicasgen_subject_alt_name_present_31065` | 31065 | 4.2.1.6 | 179 | 142 | NOCHECK:142 | the subjectAltName extension MUST be present |
| `cicasgen_certificate_policies_has_no_policy_qualifiers_29246` | 29246 | 7.1.2.10.5 | 27 | 13 | NOCHECK:13 | `policyQualifiers` are NOT RECOMMENDED to be present |
| `cicasgen_certificate_policies_has_no_policy_qualifiers_29733` | 29733 | 7.1.2.10.5 | 27 | 13 | NOCHECK:13 | `policyQualifiers` are NOT RECOMMENDED to be present |
| `cicasgen_oid_list_count_in_set_policy_identifiers_29244` | 29244 | 7.1.2.10.5 | 11 | 9 | NOCHECK:9 | Regardless of the order of `PolicyInformation` values, the Certificate Policies extension MUST ... |
| `cicasgen_oid_list_count_in_set_policy_identifiers_29247` | 29247 | 7.1.2.10.5 | 11 | 9 | NOCHECK:9 | MUST include exactly one Reserved Certificate Policy Identifier (see [Section 7. |
| `cicasgen_not_ext_subfield_present_authority_key_id_28730` | 28730 | 7.1.2.11.1 | 3 | 0 | - | `authorityCertSerialNumber` | MUST NOT be present |
| `cicasgen_not_ext_subfield_present_authority_key_id_29274` | 29274 | 7.1.2.11.1 | 3 | 0 | - | `authorityCertIssuer` | MUST NOT be present |
| `cicasgen_when_root_ca_not_crl_dist_present_29288` | 29288 | 7.1.2.11.2 | 1 | 1 | CONFIRMED:1 | Root CA Certificates. |

New-lint findings on certs not flagged by upstream zlint (full list in `new_lint_findings.jsonl`):

| cert | new lint | rule | section | independent | evidence |
|---|---|---:|---|---|---|
| `2511248316_aeb1fd7410e83bc9_x509_01_chain_cn_e7_o_let_s_encrypt_c_us.pem` | `cicasgen_subject_alt_name_present_31065` | 31065 | 4.2.1.6 | NOCHECK | no independent check for this lint family |
| `2511248316_aeb1fd7410e83bc9_x509_01_chain_cn_e7_o_let_s_encrypt_c_us.pem` | `cicasgen_when_oid_eq_oid_sha256_with_rsaencryption_or_oid_eq_oid_29766` | 29766 | 7.1.3.2.1 | NOCHECK | no independent check for this lint family |
| `2511248572_96bcec06264976f3_precert_02_chain_cn_isrg_root_x1_o_internet_security_research_group_c_us.pem` | `cicasgen_subject_alt_name_present_31065` | 31065 | 4.2.1.6 | NOCHECK | no independent check for this lint family |
| `2511248572_96bcec06264976f3_precert_02_chain_cn_isrg_root_x1_o_internet_security_research_group_c_us.pem` | `cicasgen_when_oid_eq_oid_sha256_with_rsaencryption_or_oid_eq_oid_29766` | 29766 | 7.1.3.2.1 | NOCHECK | no independent check for this lint family |
| `2511248572_d3b128216a843f8e_precert_01_chain_cn_r13_o_let_s_encrypt_c_us.pem` | `cicasgen_subject_alt_name_present_31065` | 31065 | 4.2.1.6 | NOCHECK | no independent check for this lint family |
| `2511248572_d3b128216a843f8e_precert_01_chain_cn_r13_o_let_s_encrypt_c_us.pem` | `cicasgen_when_oid_eq_oid_sha256_with_rsaencryption_or_oid_eq_oid_29766` | 29766 | 7.1.3.2.1 | NOCHECK | no independent check for this lint family |
| `2511248702_131fce7784016899_x509_01_chain_cn_r12_o_let_s_encrypt_c_us.pem` | `cicasgen_subject_alt_name_present_31065` | 31065 | 4.2.1.6 | NOCHECK | no independent check for this lint family |
| `2511248702_131fce7784016899_x509_01_chain_cn_r12_o_let_s_encrypt_c_us.pem` | `cicasgen_when_oid_eq_oid_sha256_with_rsaencryption_or_oid_eq_oid_29766` | 29766 | 7.1.3.2.1 | NOCHECK | no independent check for this lint family |
| `2511249023_873f0ba80e3ac222_x509_01_chain_cn_sectigo_public_server_authentication_ca_dv_e36_o_sectigo.pem` | `cicasgen_subject_alt_name_present_31065` | 31065 | 4.2.1.6 | NOCHECK | no independent check for this lint family |
| `2511249023_c90f26f0fb1b4018_x509_02_chain_cn_sectigo_public_server_authentication_root_e46_o_sectigo_l.pem` | `cicasgen_subject_alt_name_present_31065` | 31065 | 4.2.1.6 | NOCHECK | no independent check for this lint family |
| `2511249279_83624fd338c8d9b0_x509_01_chain_cn_e8_o_let_s_encrypt_c_us.pem` | `cicasgen_subject_alt_name_present_31065` | 31065 | 4.2.1.6 | NOCHECK | no independent check for this lint family |
| `2511249279_83624fd338c8d9b0_x509_01_chain_cn_e8_o_let_s_encrypt_c_us.pem` | `cicasgen_when_oid_eq_oid_sha256_with_rsaencryption_or_oid_eq_oid_29766` | 29766 | 7.1.3.2.1 | NOCHECK | no independent check for this lint family |
| `2511257983_332f96d9c2105900_x509_01_chain_cn_trustasia_dv_tls_ecc_ca_2025_o_trustasia_technologies_inc.pem` | `cicasgen_subject_alt_name_present_31065` | 31065 | 4.2.1.6 | NOCHECK | no independent check for this lint family |
| `2511262911_0587d6bd2819587a_precert_01_chain_cn_digicert_global_g3_tls_ecc_sha384_2020_ca1_o_digicert_inc.pem` | `cicasgen_oid_list_count_in_set_policy_identifiers_29244` | 29244 | 7.1.2.10.5 | NOCHECK | no independent check for this lint family |
| `2511262911_0587d6bd2819587a_precert_01_chain_cn_digicert_global_g3_tls_ecc_sha384_2020_ca1_o_digicert_inc.pem` | `cicasgen_oid_list_count_in_set_policy_identifiers_29247` | 29247 | 7.1.2.10.5 | NOCHECK | no independent check for this lint family |
| `2511262911_0587d6bd2819587a_precert_01_chain_cn_digicert_global_g3_tls_ecc_sha384_2020_ca1_o_digicert_inc.pem` | `cicasgen_subject_alt_name_present_31065` | 31065 | 4.2.1.6 | NOCHECK | no independent check for this lint family |
| `2511277053_3337d4e4b4ef6a94_x509_01_chain_cn_gandicert_o_gandi_sas_c_fr.pem` | `cicasgen_subject_alt_name_present_31065` | 31065 | 4.2.1.6 | NOCHECK | no independent check for this lint family |
| `2511277053_3337d4e4b4ef6a94_x509_01_chain_cn_gandicert_o_gandi_sas_c_fr.pem` | `cicasgen_when_oid_eq_oid_sha256_with_rsaencryption_or_oid_eq_oid_29766` | 29766 | 7.1.3.2.1 | NOCHECK | no independent check for this lint family |
| `2511287615_7431e5f4c3c1ce46_x509_03_chain_cn_digicert_high_assurance_ev_root_ca_ou_www.digicert.com_o.pem` | `cicasgen_subject_alt_name_present_31065` | 31065 | 4.2.1.6 | NOCHECK | no independent check for this lint family |
| `2511303804_61e97375e9f6da98_x509_01_chain_cn_sectigo_ecc_domain_validation_secure_server_ca_o_sectigo.pem` | `cicasgen_subject_alt_name_present_31065` | 31065 | 4.2.1.6 | NOCHECK | no independent check for this lint family |
| `2511325823_fdc1e2574f397d8b_x509_01_chain_cn_geossl_rsa_domain_validation_secure_server_ca_o_geossl_c.pem` | `cicasgen_subject_alt_name_present_31065` | 31065 | 4.2.1.6 | NOCHECK | no independent check for this lint family |
| `2511325823_fdc1e2574f397d8b_x509_01_chain_cn_geossl_rsa_domain_validation_secure_server_ca_o_geossl_c.pem` | `cicasgen_when_oid_eq_oid_sha256_with_rsaencryption_or_oid_eq_oid_29766` | 29766 | 7.1.3.2.1 | NOCHECK | no independent check for this lint family |
| `2511354812_e4b2a0736f95950d_x509_01_chain_cn_lh.pl_ca_o_lh.pl_sp._z_o.o._c_pl.pem` | `cicasgen_certificate_policies_has_no_policy_qualifiers_29246` | 29246 | 7.1.2.10.5 | NOCHECK | no independent check for this lint family |
| `2511354812_e4b2a0736f95950d_x509_01_chain_cn_lh.pl_ca_o_lh.pl_sp._z_o.o._c_pl.pem` | `cicasgen_certificate_policies_has_no_policy_qualifiers_29733` | 29733 | 7.1.2.10.5 | NOCHECK | no independent check for this lint family |
| `2511354812_e4b2a0736f95950d_x509_01_chain_cn_lh.pl_ca_o_lh.pl_sp._z_o.o._c_pl.pem` | `cicasgen_subject_alt_name_present_31065` | 31065 | 4.2.1.6 | NOCHECK | no independent check for this lint family |
| `2511354812_e4b2a0736f95950d_x509_01_chain_cn_lh.pl_ca_o_lh.pl_sp._z_o.o._c_pl.pem` | `cicasgen_when_oid_eq_oid_sha256_with_rsaencryption_or_oid_eq_oid_29766` | 29766 | 7.1.3.2.1 | NOCHECK | no independent check for this lint family |
| `2511355836_7fd28377c87c898e_x509_01_chain_cn_e-tugra_tls_rsa_subca_r1_o_e-tugra_ebg_bilisim_teknolojil.pem` | `cicasgen_certificate_policies_has_no_policy_qualifiers_29246` | 29246 | 7.1.2.10.5 | NOCHECK | no independent check for this lint family |
| `2511355836_7fd28377c87c898e_x509_01_chain_cn_e-tugra_tls_rsa_subca_r1_o_e-tugra_ebg_bilisim_teknolojil.pem` | `cicasgen_certificate_policies_has_no_policy_qualifiers_29733` | 29733 | 7.1.2.10.5 | NOCHECK | no independent check for this lint family |
| `2511355836_7fd28377c87c898e_x509_01_chain_cn_e-tugra_tls_rsa_subca_r1_o_e-tugra_ebg_bilisim_teknolojil.pem` | `cicasgen_subject_alt_name_present_31065` | 31065 | 4.2.1.6 | NOCHECK | no independent check for this lint family |
| `2511355836_7fd28377c87c898e_x509_01_chain_cn_e-tugra_tls_rsa_subca_r1_o_e-tugra_ebg_bilisim_teknolojil.pem` | `cicasgen_when_oid_eq_oid_sha256_with_rsaencryption_or_oid_eq_oid_29766` | 29766 | 7.1.3.2.1 | NOCHECK | no independent check for this lint family |
| `2511358263_1dfc1605fbad358d_precert_01_chain_cn_we1_o_google_trust_services_c_us.pem` | `cicasgen_subject_alt_name_present_31065` | 31065 | 4.2.1.6 | NOCHECK | no independent check for this lint family |
| `2511358263_349dfa4058c5e263_precert_02_chain_cn_gts_root_r4_o_google_trust_services_llc_c_us.pem` | `cicasgen_subject_alt_name_present_31065` | 31065 | 4.2.1.6 | NOCHECK | no independent check for this lint family |
| `2511358269_35f8cc89610508bc_x509_01_chain_cn_cyber_folks_o_cyber_folks_s.a._c_pl.pem` | `cicasgen_certificate_policies_has_no_policy_qualifiers_29246` | 29246 | 7.1.2.10.5 | NOCHECK | no independent check for this lint family |
| `2511358269_35f8cc89610508bc_x509_01_chain_cn_cyber_folks_o_cyber_folks_s.a._c_pl.pem` | `cicasgen_certificate_policies_has_no_policy_qualifiers_29733` | 29733 | 7.1.2.10.5 | NOCHECK | no independent check for this lint family |
| `2511358269_35f8cc89610508bc_x509_01_chain_cn_cyber_folks_o_cyber_folks_s.a._c_pl.pem` | `cicasgen_subject_alt_name_present_31065` | 31065 | 4.2.1.6 | NOCHECK | no independent check for this lint family |
| `2511358269_35f8cc89610508bc_x509_01_chain_cn_cyber_folks_o_cyber_folks_s.a._c_pl.pem` | `cicasgen_when_oid_eq_oid_sha256_with_rsaencryption_or_oid_eq_oid_29766` | 29766 | 7.1.3.2.1 | NOCHECK | no independent check for this lint family |
| `2511358269_5c58468d55f58e49_x509_03_chain_cn_certum_trusted_network_ca_ou_certum_certification_authori.pem` | `cicasgen_subject_alt_name_present_31065` | 31065 | 4.2.1.6 | NOCHECK | no independent check for this lint family |
| `2511358269_9e852c59dfc6fd6a_x509_02_chain_cn_certum_global_services_ca_sha2_ou_certum_certification_au.pem` | `cicasgen_certificate_policies_has_no_policy_qualifiers_29246` | 29246 | 7.1.2.10.5 | NOCHECK | no independent check for this lint family |
| `2511358269_9e852c59dfc6fd6a_x509_02_chain_cn_certum_global_services_ca_sha2_ou_certum_certification_au.pem` | `cicasgen_certificate_policies_has_no_policy_qualifiers_29733` | 29733 | 7.1.2.10.5 | NOCHECK | no independent check for this lint family |
| `2511358269_9e852c59dfc6fd6a_x509_02_chain_cn_certum_global_services_ca_sha2_ou_certum_certification_au.pem` | `cicasgen_subject_alt_name_present_31065` | 31065 | 4.2.1.6 | NOCHECK | no independent check for this lint family |
| `2511358269_9e852c59dfc6fd6a_x509_02_chain_cn_certum_global_services_ca_sha2_ou_certum_certification_au.pem` | `cicasgen_when_oid_eq_oid_sha256_with_rsaencryption_or_oid_eq_oid_29766` | 29766 | 7.1.3.2.1 | NOCHECK | no independent check for this lint family |
| `2511358387_47fd11ad552ab264_x509_01_chain_cn_amazon_ecdsa_384_m04_o_amazon_c_us.pem` | `cicasgen_subject_alt_name_present_31065` | 31065 | 4.2.1.6 | NOCHECK | no independent check for this lint family |
| `2511358387_543d9b7fc2a6471c_x509_02_chain_cn_amazon_root_ca_4_o_amazon_c_us.pem` | `cicasgen_subject_alt_name_present_31065` | 31065 | 4.2.1.6 | NOCHECK | no independent check for this lint family |
| `2511358387_543d9b7fc2a6471c_x509_02_chain_cn_amazon_root_ca_4_o_amazon_c_us.pem` | `cicasgen_when_oid_eq_oid_sha256_with_rsaencryption_or_oid_eq_oid_29766` | 29766 | 7.1.3.2.1 | NOCHECK | no independent check for this lint family |
| `2511358397_973a41276ffd01e0_x509_01_chain_cn_go_daddy_secure_certificate_authority_-_g2_ou_http_certs.pem` | `cicasgen_certificate_policies_has_no_policy_qualifiers_29246` | 29246 | 7.1.2.10.5 | NOCHECK | no independent check for this lint family |
| `2511358397_973a41276ffd01e0_x509_01_chain_cn_go_daddy_secure_certificate_authority_-_g2_ou_http_certs.pem` | `cicasgen_certificate_policies_has_no_policy_qualifiers_29733` | 29733 | 7.1.2.10.5 | NOCHECK | no independent check for this lint family |
| `2511358397_973a41276ffd01e0_x509_01_chain_cn_go_daddy_secure_certificate_authority_-_g2_ou_http_certs.pem` | `cicasgen_subject_alt_name_present_31065` | 31065 | 4.2.1.6 | NOCHECK | no independent check for this lint family |
| `2511358397_973a41276ffd01e0_x509_01_chain_cn_go_daddy_secure_certificate_authority_-_g2_ou_http_certs.pem` | `cicasgen_when_oid_eq_oid_sha256_with_rsaencryption_or_oid_eq_oid_29766` | 29766 | 7.1.3.2.1 | NOCHECK | no independent check for this lint family |
| `2511358398_1793927a06145497_precert_02_chain_cn_comodo_ecc_certification_authority_o_comodo_ca_limited_l.pem` | `cicasgen_subject_alt_name_present_31065` | 31065 | 4.2.1.6 | NOCHECK | no independent check for this lint family |
| `2511358444_2fe357db13751ff9_precert_01_chain_cn_wr3_o_google_trust_services_c_us.pem` | `cicasgen_subject_alt_name_present_31065` | 31065 | 4.2.1.6 | NOCHECK | no independent check for this lint family |
| `2511358444_2fe357db13751ff9_precert_01_chain_cn_wr3_o_google_trust_services_c_us.pem` | `cicasgen_when_oid_eq_oid_sha256_with_rsaencryption_or_oid_eq_oid_29766` | 29766 | 7.1.3.2.1 | NOCHECK | no independent check for this lint family |
| `2511358444_d947432abde7b7fa_precert_02_chain_cn_gts_root_r1_o_google_trust_services_llc_c_us.pem` | `cicasgen_subject_alt_name_present_31065` | 31065 | 4.2.1.6 | NOCHECK | no independent check for this lint family |
| `2511358444_d947432abde7b7fa_precert_02_chain_cn_gts_root_r1_o_google_trust_services_llc_c_us.pem` | `cicasgen_when_oid_eq_oid_sha256_with_rsaencryption_or_oid_eq_oid_29766` | 29766 | 7.1.3.2.1 | NOCHECK | no independent check for this lint family |
| `2511358445_2a575471e31340bc_precert_02_chain_cn_gts_root_r1_o_google_trust_services_llc_c_us.pem` | `cicasgen_subject_alt_name_present_31065` | 31065 | 4.2.1.6 | NOCHECK | no independent check for this lint family |
| `2511358445_2a575471e31340bc_precert_02_chain_cn_gts_root_r1_o_google_trust_services_llc_c_us.pem` | `cicasgen_when_oid_eq_oid_sha256_with_rsaencryption_or_oid_eq_oid_29766` | 29766 | 7.1.3.2.1 | NOCHECK | no independent check for this lint family |
| `2511358445_b10b6f00e609509e_precert_01_chain_cn_wr1_o_google_trust_services_c_us.pem` | `cicasgen_subject_alt_name_present_31065` | 31065 | 4.2.1.6 | NOCHECK | no independent check for this lint family |
| `2511358445_b10b6f00e609509e_precert_01_chain_cn_wr1_o_google_trust_services_c_us.pem` | `cicasgen_when_oid_eq_oid_sha256_with_rsaencryption_or_oid_eq_oid_29766` | 29766 | 7.1.3.2.1 | NOCHECK | no independent check for this lint family |
| `2511358452_3ee0278df71fa3c1_x509_02_chain_cn_gts_root_r1_o_google_trust_services_llc_c_us.pem` | `cicasgen_oid_list_count_in_set_policy_identifiers_29244` | 29244 | 7.1.2.10.5 | NOCHECK | no independent check for this lint family |
| `2511358452_3ee0278df71fa3c1_x509_02_chain_cn_gts_root_r1_o_google_trust_services_llc_c_us.pem` | `cicasgen_oid_list_count_in_set_policy_identifiers_29247` | 29247 | 7.1.2.10.5 | NOCHECK | no independent check for this lint family |
| `2511358452_3ee0278df71fa3c1_x509_02_chain_cn_gts_root_r1_o_google_trust_services_llc_c_us.pem` | `cicasgen_subject_alt_name_present_31065` | 31065 | 4.2.1.6 | NOCHECK | no independent check for this lint family |
| `2511358452_3ee0278df71fa3c1_x509_02_chain_cn_gts_root_r1_o_google_trust_services_llc_c_us.pem` | `cicasgen_when_oid_eq_oid_sha256_with_rsaencryption_or_oid_eq_oid_29766` | 29766 | 7.1.3.2.1 | NOCHECK | no independent check for this lint family |
| `2511358638_7fa4ff68ec04a99d_x509_01_chain_cn_sectigo_rsa_domain_validation_secure_server_ca_o_sectigo.pem` | `cicasgen_subject_alt_name_present_31065` | 31065 | 4.2.1.6 | NOCHECK | no independent check for this lint family |
| `2511358638_7fa4ff68ec04a99d_x509_01_chain_cn_sectigo_rsa_domain_validation_secure_server_ca_o_sectigo.pem` | `cicasgen_when_oid_eq_oid_sha256_with_rsaencryption_or_oid_eq_oid_29766` | 29766 | 7.1.3.2.1 | NOCHECK | no independent check for this lint family |
| `2511358638_d7a7a0fb5d7e2731_x509_03_chain_cn_aaa_certificate_services_o_comodo_ca_limited_l_salford_st.pem` | `cicasgen_subject_alt_name_present_31065` | 31065 | 4.2.1.6 | NOCHECK | no independent check for this lint family |
| `2511358638_d7a7a0fb5d7e2731_x509_03_chain_cn_aaa_certificate_services_o_comodo_ca_limited_l_salford_st.pem` | `cicasgen_when_root_ca_not_crl_dist_present_29288` | 29288 | 7.1.2.11.2 | CONFIRMED | root CA carries CRLDP (advisory) |
| `2511358700_cbb522d7b7f127ad_precert_02_chain_cn_globalsign_o_globalsign_ou_globalsign_root_ca_-_r3.pem` | `cicasgen_subject_alt_name_present_31065` | 31065 | 4.2.1.6 | NOCHECK | no independent check for this lint family |
| `2511358700_cbb522d7b7f127ad_precert_02_chain_cn_globalsign_o_globalsign_ou_globalsign_root_ca_-_r3.pem` | `cicasgen_when_oid_eq_oid_sha256_with_rsaencryption_or_oid_eq_oid_29766` | 29766 | 7.1.3.2.1 | NOCHECK | no independent check for this lint family |
| `2511358700_f5165fc624453361_precert_01_chain_cn_globalsign_atlas_r3_dv_tls_ca_2025_q4_o_globalsign_nv-sa.pem` | `cicasgen_subject_alt_name_present_31065` | 31065 | 4.2.1.6 | NOCHECK | no independent check for this lint family |
| `2511358700_f5165fc624453361_precert_01_chain_cn_globalsign_atlas_r3_dv_tls_ca_2025_q4_o_globalsign_nv-sa.pem` | `cicasgen_when_oid_eq_oid_sha256_with_rsaencryption_or_oid_eq_oid_29766` | 29766 | 7.1.3.2.1 | NOCHECK | no independent check for this lint family |
| `2511358703_dc9416c2f855126d_precert_01_chain_cn_wr4_o_google_trust_services_c_us.pem` | `cicasgen_subject_alt_name_present_31065` | 31065 | 4.2.1.6 | NOCHECK | no independent check for this lint family |
| `2511358703_dc9416c2f855126d_precert_01_chain_cn_wr4_o_google_trust_services_c_us.pem` | `cicasgen_when_oid_eq_oid_sha256_with_rsaencryption_or_oid_eq_oid_29766` | 29766 | 7.1.3.2.1 | NOCHECK | no independent check for this lint family |
| `2511358772_15d5b8774619ea7d_precert_02_chain_cn_gts_root_r3_o_google_trust_services_llc_c_us.pem` | `cicasgen_subject_alt_name_present_31065` | 31065 | 4.2.1.6 | NOCHECK | no independent check for this lint family |
| `2511358774_54f8ca858bcc7591_precert_01_chain_cn_we2_o_google_trust_services_c_us.pem` | `cicasgen_subject_alt_name_present_31065` | 31065 | 4.2.1.6 | NOCHECK | no independent check for this lint family |
| `2511358780_9d5e86906a1680a8_precert_01_chain_cn_we4_o_google_trust_services_c_us.pem` | `cicasgen_subject_alt_name_present_31065` | 31065 | 4.2.1.6 | NOCHECK | no independent check for this lint family |
| `2511358830_54c660da29d75fc8_precert_01_chain_cn_we3_o_google_trust_services_c_us.pem` | `cicasgen_subject_alt_name_present_31065` | 31065 | 4.2.1.6 | NOCHECK | no independent check for this lint family |
| `2511358832_dfe35c740cf41c0b_precert_01_chain_cn_amazon_ecdsa_384_m01_o_amazon_c_us.pem` | `cicasgen_subject_alt_name_present_31065` | 31065 | 4.2.1.6 | NOCHECK | no independent check for this lint family |
| `2511358832_e35d28419ed02025_precert_02_chain_cn_amazon_root_ca_4_o_amazon_c_us.pem` | `cicasgen_subject_alt_name_present_31065` | 31065 | 4.2.1.6 | NOCHECK | no independent check for this lint family |
| `2511358841_812c212e9e45dc50_precert_01_chain_cn_ae1_o_google_trust_services_c_us.pem` | `cicasgen_subject_alt_name_present_31065` | 31065 | 4.2.1.6 | NOCHECK | no independent check for this lint family |
| `2511358908_a2bdaa59bf9e8c3f_x509_01_chain_cn_trustasia_dv_tls_rsa_ca_2025_o_trustasia_technologies_inc.pem` | `cicasgen_subject_alt_name_present_31065` | 31065 | 4.2.1.6 | NOCHECK | no independent check for this lint family |
| `2511358908_a2bdaa59bf9e8c3f_x509_01_chain_cn_trustasia_dv_tls_rsa_ca_2025_o_trustasia_technologies_inc.pem` | `cicasgen_when_oid_eq_oid_sha256_with_rsaencryption_or_oid_eq_oid_29766` | 29766 | 7.1.3.2.1 | NOCHECK | no independent check for this lint family |
| `2511358957_34d8a73ee208d9bc_precert_02_chain_cn_gts_root_r3_o_google_trust_services_llc_c_us.pem` | `cicasgen_subject_alt_name_present_31065` | 31065 | 4.2.1.6 | NOCHECK | no independent check for this lint family |
| `2511358957_847409e63526f162_precert_01_chain_cn_we5_o_google_trust_services_c_us.pem` | `cicasgen_subject_alt_name_present_31065` | 31065 | 4.2.1.6 | NOCHECK | no independent check for this lint family |
| `2511358963_e6fe22bf45e4f0d3_precert_01_chain_cn_wr2_o_google_trust_services_c_us.pem` | `cicasgen_subject_alt_name_present_31065` | 31065 | 4.2.1.6 | NOCHECK | no independent check for this lint family |
| `2511358963_e6fe22bf45e4f0d3_precert_01_chain_cn_wr2_o_google_trust_services_c_us.pem` | `cicasgen_when_oid_eq_oid_sha256_with_rsaencryption_or_oid_eq_oid_29766` | 29766 | 7.1.3.2.1 | NOCHECK | no independent check for this lint family |
| `2511358964_8d25cd97229dbf70_precert_02_chain_cn_gts_root_r2_o_google_trust_services_llc_c_us.pem` | `cicasgen_subject_alt_name_present_31065` | 31065 | 4.2.1.6 | NOCHECK | no independent check for this lint family |
| `2511358964_8d25cd97229dbf70_precert_02_chain_cn_gts_root_r2_o_google_trust_services_llc_c_us.pem` | `cicasgen_when_oid_eq_oid_sha256_with_rsaencryption_or_oid_eq_oid_29766` | 29766 | 7.1.3.2.1 | NOCHECK | no independent check for this lint family |
| `2511358964_ae0fc852280f1b87_precert_01_chain_cn_wr5_o_google_trust_services_c_us.pem` | `cicasgen_subject_alt_name_present_31065` | 31065 | 4.2.1.6 | NOCHECK | no independent check for this lint family |
| `2511358964_ae0fc852280f1b87_precert_01_chain_cn_wr5_o_google_trust_services_c_us.pem` | `cicasgen_when_oid_eq_oid_sha256_with_rsaencryption_or_oid_eq_oid_29766` | 29766 | 7.1.3.2.1 | NOCHECK | no independent check for this lint family |
| `2511358969_21acc1dbd6944f9a_x509_01_chain_cn_zerossl_rsa_domain_secure_site_ca_o_zerossl_c_at.pem` | `cicasgen_subject_alt_name_present_31065` | 31065 | 4.2.1.6 | NOCHECK | no independent check for this lint family |
| `2511358969_21acc1dbd6944f9a_x509_01_chain_cn_zerossl_rsa_domain_secure_site_ca_o_zerossl_c_at.pem` | `cicasgen_when_oid_eq_oid_sha256_with_rsaencryption_or_oid_eq_oid_29766` | 29766 | 7.1.3.2.1 | NOCHECK | no independent check for this lint family |
| `2511358969_e793c9b02fd8aa13_x509_02_chain_cn_usertrust_rsa_certification_authority_o_the_usertrust_net.pem` | `cicasgen_subject_alt_name_present_31065` | 31065 | 4.2.1.6 | NOCHECK | no independent check for this lint family |
| `2511358969_e793c9b02fd8aa13_x509_02_chain_cn_usertrust_rsa_certification_authority_o_the_usertrust_net.pem` | `cicasgen_when_oid_eq_oid_sha256_with_rsaencryption_or_oid_eq_oid_29766` | 29766 | 7.1.3.2.1 | NOCHECK | no independent check for this lint family |
| `2511359022_5d56499be4d2e08b_precert_02_chain_cn_identrust_commercial_root_ca_1_o_identrust_c_us.pem` | `cicasgen_subject_alt_name_present_31065` | 31065 | 4.2.1.6 | NOCHECK | no independent check for this lint family |
| `2511359022_5d56499be4d2e08b_precert_02_chain_cn_identrust_commercial_root_ca_1_o_identrust_c_us.pem` | `cicasgen_when_oid_eq_oid_sha256_with_rsaencryption_or_oid_eq_oid_29766` | 29766 | 7.1.3.2.1 | NOCHECK | no independent check for this lint family |
| `2511359022_8bb2f6883fed289a_precert_01_chain_cn_hydrantid_server_ca_o1_ou_hydrantid_trusted_certificate_s.pem` | `cicasgen_certificate_policies_has_no_policy_qualifiers_29246` | 29246 | 7.1.2.10.5 | NOCHECK | no independent check for this lint family |
| `2511359022_8bb2f6883fed289a_precert_01_chain_cn_hydrantid_server_ca_o1_ou_hydrantid_trusted_certificate_s.pem` | `cicasgen_certificate_policies_has_no_policy_qualifiers_29733` | 29733 | 7.1.2.10.5 | NOCHECK | no independent check for this lint family |
| `2511359022_8bb2f6883fed289a_precert_01_chain_cn_hydrantid_server_ca_o1_ou_hydrantid_trusted_certificate_s.pem` | `cicasgen_subject_alt_name_present_31065` | 31065 | 4.2.1.6 | NOCHECK | no independent check for this lint family |
| `2511359022_8bb2f6883fed289a_precert_01_chain_cn_hydrantid_server_ca_o1_ou_hydrantid_trusted_certificate_s.pem` | `cicasgen_when_oid_eq_oid_sha256_with_rsaencryption_or_oid_eq_oid_29766` | 29766 | 7.1.3.2.1 | NOCHECK | no independent check for this lint family |
| `2511359215_cb3ccbb76031e5e0_x509_02_chain_cn_digicert_global_root_g2_ou_www.digicert.com_o_digicert_in.pem` | `cicasgen_subject_alt_name_present_31065` | 31065 | 4.2.1.6 | NOCHECK | no independent check for this lint family |
| `2511359215_cb3ccbb76031e5e0_x509_02_chain_cn_digicert_global_root_g2_ou_www.digicert.com_o_digicert_in.pem` | `cicasgen_when_oid_eq_oid_sha256_with_rsaencryption_or_oid_eq_oid_29766` | 29766 | 7.1.3.2.1 | NOCHECK | no independent check for this lint family |
| ... | ... | ... | ... | ... | 183 more rows in JSONL |
