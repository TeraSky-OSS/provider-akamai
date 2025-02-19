package appsecurity

import (
        "github.com/crossplane/upjet/pkg/config"
)

// Configure configures the resource group category resource.
func Configure(p *config.Provider) {
        p.AddResourceConfigurator("akamai_appsec_aap_selected_hostnames", func(r *config.Resource) {
                r.ShortGroup = "appsec"
                r.Kind = "AAPSelectedHostnames"
        })
        p.AddResourceConfigurator("akamai_appsec_activations", func(r *config.Resource) {
                r.ShortGroup = "appsec"
                r.Kind = "Activations"
        })
        p.AddResourceConfigurator("akamai_appsec_advanced_settings_attack_payload_logging", func(r *config.Resource) {
                r.ShortGroup = "appsec"
                r.Kind = "AdvancedSettingsAttackPayloadLogging"
        })
        p.AddResourceConfigurator("akamai_appsec_advanced_settings_evasive_path_match", func(r *config.Resource) {
                r.ShortGroup = "appsec"
                r.Kind = "AdvancedSettingsEvasivePathMatch"
        })
        p.AddResourceConfigurator("akamai_appsec_advanced_settings_logging", func(r *config.Resource) {
                r.ShortGroup = "appsec"
                r.Kind = "AdvancedSettingsLogging"
        })
        p.AddResourceConfigurator("akamai_appsec_advanced_settings_pii_learning", func(r *config.Resource) {
                r.ShortGroup = "appsec"
                r.Kind = "AdvancedSettingsPiiLearning"
        })
        p.AddResourceConfigurator("akamai_appsec_advanced_settings_pragma_header", func(r *config.Resource) {
                r.ShortGroup = "appsec"
                r.Kind = "AdvancedSettingsPragmaHeader"
        })
        p.AddResourceConfigurator("akamai_appsec_advanced_settings_prefetch", func(r *config.Resource) {
                r.ShortGroup = "appsec"
                r.Kind = "AdvancedSettingsPrefetch"
        })
        p.AddResourceConfigurator("akamai_appsec_advanced_settings_request_body", func(r *config.Resource) {
                r.ShortGroup = "appsec"
                r.Kind = "AdvancedSettingsRequestBody"
        })
        p.AddResourceConfigurator("akamai_appsec_api_constraints_protection", func(r *config.Resource) {
                r.ShortGroup = "appsec"
                r.Kind = "ApiConstraintsProtection"
        })
        p.AddResourceConfigurator("akamai_appsec_api_request_constraints", func(r *config.Resource) {
                r.ShortGroup = "appsec"
                r.Kind = "ApiRequestConstraints"
        })
        p.AddResourceConfigurator("akamai_appsec_attack_group", func(r *config.Resource) {
                r.ShortGroup = "appsec"
                r.Kind = "AttackGroup"
        })
        p.AddResourceConfigurator("akamai_appsec_bypass_network_lists", func(r *config.Resource) {
                r.ShortGroup = "appsec"
                r.Kind = "BypassNetworkLists"
        })
        p.AddResourceConfigurator("akamai_appsec_configuration", func(r *config.Resource) {
                r.ShortGroup = "appsec"
                r.Kind = "Configuration"
        })
        p.AddResourceConfigurator("akamai_appsec_configuration_rename", func(r *config.Resource) {
                r.ShortGroup = "appsec"
                r.Kind = "ConfigurationRename"
        })
        p.AddResourceConfigurator("akamai_appsec_custom_deny", func(r *config.Resource) {
                r.ShortGroup = "appsec"
                r.Kind = "CustomDeny"
        })
        p.AddResourceConfigurator("akamai_appsec_custom_rule", func(r *config.Resource) {
                r.ShortGroup = "appsec"
                r.Kind = "CustomRule"
        })
        p.AddResourceConfigurator("akamai_appsec_custom_rule_action", func(r *config.Resource) {
                r.ShortGroup = "appsec"
                r.Kind = "CustomRuleAction"
        })
        p.AddResourceConfigurator("akamai_appsec_eval", func(r *config.Resource) {
                r.ShortGroup = "appsec"
                r.Kind = "Eval"
        })
        p.AddResourceConfigurator("akamai_appsec_eval_group", func(r *config.Resource) {
                r.ShortGroup = "appsec"
                r.Kind = "EvalGroup"
        })
        p.AddResourceConfigurator("akamai_appsec_eval_penalty_box", func(r *config.Resource) {
                r.ShortGroup = "appsec"
                r.Kind = "EvalPenaltyBox"
        })
        p.AddResourceConfigurator("akamai_appsec_eval_penalty_box_conditions", func(r *config.Resource) {
                r.ShortGroup = "appsec"
                r.Kind = "EvalPenaltyBoxConditions"
        })
        p.AddResourceConfigurator("akamai_appsec_eval_rule", func(r *config.Resource) {
                r.ShortGroup = "appsec"
                r.Kind = "EvalRule"
        })
        p.AddResourceConfigurator("akamai_appsec_ip_geo", func(r *config.Resource) {
                r.ShortGroup = "appsec"
                r.Kind = "IPGeo"
        })
        p.AddResourceConfigurator("akamai_appsec_ip_geo_protection", func(r *config.Resource) {
                r.ShortGroup = "appsec"
                r.Kind = "IpGeoProtection"
        })
        p.AddResourceConfigurator("akamai_appsec_malware_policy", func(r *config.Resource) {
                r.ShortGroup = "appsec"
                r.Kind = "MalwarePolicy"
        })
        p.AddResourceConfigurator("akamai_appsec_malware_policy_action", func(r *config.Resource) {
                r.ShortGroup = "appsec"
                r.Kind = "MalwarePolicyAction"
        })
        p.AddResourceConfigurator("akamai_appsec_malware_policy_actions", func(r *config.Resource) {
                r.ShortGroup = "appsec"
                r.Kind = "MalwarePolicyActions"
        })
        p.AddResourceConfigurator("akamai_appsec_malware_protection", func(r *config.Resource) {
                r.ShortGroup = "appsec"
                r.Kind = "MalwareProtection"
        })
        p.AddResourceConfigurator("akamai_appsec_match_target", func(r *config.Resource) {
                r.ShortGroup = "appsec"
                r.Kind = "MatchTarget"
        })
        p.AddResourceConfigurator("akamai_appsec_match_target_sequence", func(r *config.Resource) {
                r.ShortGroup = "appsec"
                r.Kind = "MatchTargetSequence"
        })
        p.AddResourceConfigurator("akamai_appsec_penalty_box", func(r *config.Resource) {
                r.ShortGroup = "appsec"
                r.Kind = "PenaltyBox"
        })
        p.AddResourceConfigurator("akamai_appsec_penalty_box_conditions", func(r *config.Resource) {
                r.ShortGroup = "appsec"
                r.Kind = "PenaltyBoxConditions"
        })
        p.AddResourceConfigurator("akamai_appsec_rapid_rules", func(r *config.Resource) {
                r.ShortGroup = "appsec"
                r.Kind = "RapidRules"
        })
        p.AddResourceConfigurator("akamai_appsec_rate_policy", func(r *config.Resource) {
                r.ShortGroup = "appsec"
                r.Kind = "RatePolicy"
        })
        p.AddResourceConfigurator("akamai_appsec_rate_policy_action", func(r *config.Resource) {
                r.ShortGroup = "appsec"
                r.Kind = "RatePolicyAction"
        })
        p.AddResourceConfigurator("akamai_appsec_rate_protection", func(r *config.Resource) {
                r.ShortGroup = "appsec"
                r.Kind = "RateProtection"
        })
        p.AddResourceConfigurator("akamai_appsec_reputation_profile", func(r *config.Resource) {
                r.ShortGroup = "appsec"
                r.Kind = "ReputationProfile"
        })
        p.AddResourceConfigurator("akamai_appsec_reputation_profile_action", func(r *config.Resource) {
                r.ShortGroup = "appsec"
                r.Kind = "ReputationProfileAction"
        })
        p.AddResourceConfigurator("akamai_appsec_reputation_profile_analysis", func(r *config.Resource) {
                r.ShortGroup = "appsec"
                r.Kind = "ReputationProfileAnalysis"
        })
        p.AddResourceConfigurator("akamai_appsec_reputation_profile_analysis_action", func(r *config.Resource) {
                r.ShortGroup = "appsec"
                r.Kind = "ReputationProfileAnalysisAction"
        })
        p.AddResourceConfigurator("akamai_appsec_reputation_protection", func(r *config.Resource) {
                r.ShortGroup = "appsec"
                r.Kind = "ReputationProtection"
        })
        p.AddResourceConfigurator("akamai_appsec_rule", func(r *config.Resource) {
                r.ShortGroup = "appsec"
                r.Kind = "Rule"
        })
        p.AddResourceConfigurator("akamai_appsec_rule_upgrade", func(r *config.Resource) {
                r.ShortGroup = "appsec"
                r.Kind = "RuleUpgrade"
        })
        p.AddResourceConfigurator("akamai_appsec_security_policy", func(r *config.Resource) {
                r.ShortGroup = "appsec"
                r.Kind = "SecurityPolicy"
        })
        p.AddResourceConfigurator("akamai_appsec_security_policy_default_protections", func(r *config.Resource) {
                r.ShortGroup = "appsec"
                r.Kind = "SecurityPolicyDefaultProtections"
        })
        p.AddResourceConfigurator("akamai_appsec_security_policy_rename", func(r *config.Resource) {
                r.ShortGroup = "appsec"
                r.Kind = "SecurityPolicyRename"
        })
        p.AddResourceConfigurator("akamai_appsec_siem_settings", func(r *config.Resource) {
                r.ShortGroup = "appsec"
                r.Kind = "SiemSettings"
        })
        p.AddResourceConfigurator("akamai_appsec_slow_post", func(r *config.Resource) {
                r.ShortGroup = "appsec"
                r.Kind = "SlowPost"
        })
        p.AddResourceConfigurator("akamai_appsec_slowpost_protection", func(r *config.Resource) {
                r.ShortGroup = "appsec"
                r.Kind = "SlowpostProtection"
        })
        p.AddResourceConfigurator("akamai_appsec_threat_intel", func(r *config.Resource) {
                r.ShortGroup = "appsec"
                r.Kind = "ThreatIntel"
        })
        p.AddResourceConfigurator("akamai_appsec_version_notes", func(r *config.Resource) {
                r.ShortGroup = "appsec"
                r.Kind = "VersionNotes"
        })
        p.AddResourceConfigurator("akamai_appsec_waf_mode", func(r *config.Resource) {
                r.ShortGroup = "appsec"
                r.Kind = "WafMode"
        })
        p.AddResourceConfigurator("akamai_appsec_waf_protection", func(r *config.Resource) {
                r.ShortGroup = "appsec"
                r.Kind = "WafProtection"
        })
}
