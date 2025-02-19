/*
Copyright 2022 Upbound Inc.
*/

package config

import "github.com/crossplane/upjet/pkg/config"

// ExternalNameConfigs contains all external name configurations for this
// provider.
var ExternalNameConfigs = map[string]config.ExternalName{
	// Import requires using a randomly generated ID from provider: nl-2e21sda
	"akamai_appsec_aap_selected_hostnames": config.IdentifierFromProvider,
	"akamai_appsec_activations":           config.IdentifierFromProvider,
	"akamai_appsec_advanced_settings_attack_payload_logging":     config.IdentifierFromProvider,
	"akamai_appsec_advanced_settings_evasive_path_match":       config.IdentifierFromProvider,
	"akamai_appsec_advanced_settings_logging":       config.IdentifierFromProvider,
	"akamai_appsec_advanced_settings_pii_learning":       config.IdentifierFromProvider,
	"akamai_appsec_advanced_settings_pragma_header":       config.IdentifierFromProvider,
	"akamai_appsec_advanced_settings_prefetch":       config.IdentifierFromProvider,
	"akamai_appsec_advanced_settings_request_body":       config.IdentifierFromProvider,
	"akamai_appsec_api_constraints_protection":       config.IdentifierFromProvider,
	"akamai_appsec_api_request_constraints":       config.IdentifierFromProvider,
	"akamai_appsec_attack_group":       config.IdentifierFromProvider,
	"akamai_appsec_bypass_network_lists":       config.IdentifierFromProvider,
	"akamai_appsec_configuration":       config.IdentifierFromProvider,
	"akamai_appsec_configuration_rename":       config.IdentifierFromProvider,
	"akamai_appsec_custom_deny":       config.IdentifierFromProvider,
	"akamai_appsec_custom_rule":       config.IdentifierFromProvider,
	"akamai_appsec_custom_rule_action":       config.IdentifierFromProvider,
	"akamai_appsec_eval":       config.IdentifierFromProvider,
	"akamai_appsec_eval_group":       config.IdentifierFromProvider,
	"akamai_appsec_eval_penalty_box":       config.IdentifierFromProvider,
	"akamai_appsec_eval_penalty_box_conditions":       config.IdentifierFromProvider,
	"akamai_appsec_eval_rule":       config.IdentifierFromProvider,
	"akamai_appsec_ip_geo":       config.IdentifierFromProvider,
	"akamai_appsec_ip_geo_protection":       config.IdentifierFromProvider,
	"akamai_appsec_malware_policy":       config.IdentifierFromProvider,
	"akamai_appsec_malware_policy_action":       config.IdentifierFromProvider,
	"akamai_appsec_malware_policy_actions":       config.IdentifierFromProvider,
	"akamai_appsec_malware_protection":       config.IdentifierFromProvider,
	"akamai_appsec_match_target":       config.IdentifierFromProvider,
	"akamai_appsec_match_target_sequence":       config.IdentifierFromProvider,
	"akamai_appsec_penalty_box":       config.IdentifierFromProvider,
	"akamai_appsec_penalty_box_conditions":       config.IdentifierFromProvider,
	"akamai_appsec_rapid_rules":       config.IdentifierFromProvider,
	"akamai_appsec_rate_policy":       config.IdentifierFromProvider,
	"akamai_appsec_rate_policy_action":       config.IdentifierFromProvider,
	"akamai_appsec_rate_protection":       config.IdentifierFromProvider,
	"akamai_appsec_reputation_profile":       config.IdentifierFromProvider,
	"akamai_appsec_reputation_profile_action":       config.IdentifierFromProvider,
	"akamai_appsec_reputation_profile_analysis":       config.IdentifierFromProvider,
	"akamai_appsec_reputation_protection":       config.IdentifierFromProvider,
	"akamai_appsec_rule":       config.IdentifierFromProvider,
	"akamai_appsec_rule_upgrade":       config.IdentifierFromProvider,
	"akamai_appsec_security_policy":       config.IdentifierFromProvider,
	"akamai_appsec_security_policy_default_protections":       config.IdentifierFromProvider,
	"akamai_appsec_security_policy_rename":       config.IdentifierFromProvider,
	"akamai_appsec_siem_settings":       config.IdentifierFromProvider,
	"akamai_appsec_slow_post":       config.IdentifierFromProvider,
	"akamai_appsec_slowpost_protection":       config.IdentifierFromProvider,
	"akamai_appsec_threat_intel":       config.IdentifierFromProvider,
	"akamai_appsec_version_notes":       config.IdentifierFromProvider,
	"akamai_appsec_waf_mode":       config.IdentifierFromProvider,
	"akamai_appsec_waf_protection":       config.IdentifierFromProvider,
	"akamai_botman_akamai_bot_category_action":       config.IdentifierFromProvider,
	"akamai_botman_bot_analytics_cookie":       config.IdentifierFromProvider,
	"akamai_botman_bot_category_exception":       config.IdentifierFromProvider,
	"akamai_botman_bot_detection_action":       config.IdentifierFromProvider,
	"akamai_botman_bot_management_settings":       config.IdentifierFromProvider,
	"akamai_botman_challenge_action":       config.IdentifierFromProvider,
	"akamai_botman_challenge_injection_rules":       config.IdentifierFromProvider,
	"akamai_botman_client_side_security":       config.IdentifierFromProvider,
	"akamai_botman_conditional_action":       config.IdentifierFromProvider,
	"akamai_botman_content_protection_javascript_injection_rule":       config.IdentifierFromProvider,
	"akamai_botman_content_protection_rule":       config.IdentifierFromProvider,
	"akamai_botman_content_protection_rule_sequence":       config.IdentifierFromProvider,
	"akamai_botman_custom_bot_category":       config.IdentifierFromProvider,
	"akamai_botman_custom_bot_category_action":       config.IdentifierFromProvider,
	"akamai_botman_custom_bot_category_item_sequence":       config.IdentifierFromProvider,
	"akamai_botman_custom_bot_category_sequence":       config.IdentifierFromProvider,
	"akamai_botman_custom_client":       config.IdentifierFromProvider,
	"akamai_botman_custom_client_sequence":       config.IdentifierFromProvider,
	"akamai_botman_custom_code":       config.IdentifierFromProvider,
	"akamai_botman_custom_defined_bot":       config.IdentifierFromProvider,
	"akamai_botman_custom_deny_action":       config.IdentifierFromProvider,
	"akamai_botman_javascript_injection":       config.IdentifierFromProvider,
	"akamai_botman_recategorized_akamai_defined_bot":       config.IdentifierFromProvider,
	"akamai_botman_serve_alternate_action":       config.IdentifierFromProvider,
	"akamai_botman_transactional_endpoint":       config.IdentifierFromProvider,
	"akamai_botman_transactional_endpoint_protection":       config.IdentifierFromProvider,
	"akamai_clientlist_activation":       config.IdentifierFromProvider,
	"akamai_clientlist_list":       config.IdentifierFromProvider,
	"akamai_cloudlets_application_load_balancer":       config.IdentifierFromProvider,
	"akamai_cloudlets_application_load_balancer_activation":       config.IdentifierFromProvider,
	"akamai_cloudlets_policy":       config.IdentifierFromProvider,
	"akamai_cloudlets_policy_activation":       config.IdentifierFromProvider,
	"akamai_cloudwrapper_activation":       config.IdentifierFromProvider,
	"akamai_cloudwrapper_configuration":       config.IdentifierFromProvider,
	"akamai_cp_code":       config.IdentifierFromProvider,
	"akamai_cps_dv_enrollment":       config.IdentifierFromProvider,
	"akamai_cps_dv_validation":       config.IdentifierFromProvider,
	"akamai_cps_third_party_enrollment":       config.IdentifierFromProvider,
	"akamai_cps_upload_certificate":       config.IdentifierFromProvider,
	"akamai_datastream":       config.IdentifierFromProvider,
	"akamai_dns_record":       config.IdentifierFromProvider,
	"akamai_dns_zone":       config.IdentifierFromProvider,
	"akamai_edge_hostname":       config.IdentifierFromProvider,
	"akamai_edgekv":       config.IdentifierFromProvider,
	"akamai_edgekv_group_items":       config.IdentifierFromProvider,
	"akamai_edgeworker":       config.IdentifierFromProvider,
	"akamai_edgeworkers_activation":       config.IdentifierFromProvider,
	"akamai_gtm_asmap":       config.IdentifierFromProvider,
	"akamai_gtm_cidrmap":       config.IdentifierFromProvider,
	"akamai_gtm_datacenter":       config.IdentifierFromProvider,
	"akamai_gtm_domain":       config.IdentifierFromProvider,
	"akamai_gtm_geomap":       config.IdentifierFromProvider,
	"akamai_gtm_property":       config.IdentifierFromProvider,
	"akamai_gtm_resource":       config.IdentifierFromProvider,
	"akamai_iam_blocked_user_properties":       config.IdentifierFromProvider,
	"akamai_iam_group":       config.IdentifierFromProvider,
	"akamai_iam_ip_allowlist":       config.IdentifierFromProvider,
	"akamai_iam_role":       config.IdentifierFromProvider,
	"akamai_iam_user":       config.IdentifierFromProvider,
	"akamai_imaging_policy_image":       config.IdentifierFromProvider,
	"akamai_imaging_policy_set":       config.IdentifierFromProvider,
	"akamai_imaging_policy_video":       config.IdentifierFromProvider,
	"akamai_networklist_activations":       config.IdentifierFromProvider,
	"akamai_networklist_description":       config.IdentifierFromProvider,
	"akamai_networklist_network_list":       config.IdentifierFromProvider,
	"akamai_networklist_subscription":       config.IdentifierFromProvider,
	"akamai_property":       config.IdentifierFromProvider,
	"akamai_property_activation":       config.IdentifierFromProvider,
	"akamai_property_bootstrap":       config.IdentifierFromProvider,
	"akamai_property_include":       config.IdentifierFromProvider,
	"akamai_property_include_activation":       config.IdentifierFromProvider,
}

// ExternalNameConfigurations applies all external name configs listed in the
// table ExternalNameConfigs and sets the version of those resources to v1beta1
// assuming they will be tested.
func ExternalNameConfigurations() config.ResourceOption {
	return func(r *config.Resource) {
		if e, ok := ExternalNameConfigs[r.Name]; ok {
			r.ExternalName = e
		}
	}
}

// ExternalNameConfigured returns the list of all resources whose external name
// is configured manually.
func ExternalNameConfigured() []string {
	l := make([]string, len(ExternalNameConfigs))
	i := 0
	for name := range ExternalNameConfigs {
		// $ is added to match the exact string since the format is regex.
		l[i] = name + "$"
		i++
	}
	return l
}
