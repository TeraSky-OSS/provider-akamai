// SPDX-FileCopyrightText: 2024 The Crossplane Authors <https://crossplane.io>
//
// SPDX-License-Identifier: Apache-2.0

// Code generated by upjet. DO NOT EDIT.

package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"

	v1 "github.com/crossplane/crossplane-runtime/apis/common/v1"
)

type RapidRulesInitParameters struct {

	// Unique identifier of the security configuration
	ConfigID *float64 `json:"configId,omitempty" tf:"config_id,omitempty"`

	// Default action that applies to violations of all rapid rules
	DefaultAction *string `json:"defaultAction,omitempty" tf:"default_action,omitempty"`

	// JSON-formatted list of rule definition (ID, action, action lock and exception)
	RuleDefinitions *string `json:"ruleDefinitions,omitempty" tf:"rule_definitions,omitempty"`

	// Unique identifier of the security policy
	SecurityPolicyID *string `json:"securityPolicyId,omitempty" tf:"security_policy_id,omitempty"`
}

type RapidRulesObservation struct {

	// Unique identifier of the security configuration
	ConfigID *float64 `json:"configId,omitempty" tf:"config_id,omitempty"`

	// Default action that applies to violations of all rapid rules
	DefaultAction *string `json:"defaultAction,omitempty" tf:"default_action,omitempty"`

	// Hidden attribute containing information about rapid rules status enabled/disabled
	Enabled *bool `json:"enabled,omitempty" tf:"enabled,omitempty"`

	ID *string `json:"id,omitempty" tf:"id,omitempty"`

	// JSON-formatted list of rule definition (ID, action, action lock and exception)
	RuleDefinitions *string `json:"ruleDefinitions,omitempty" tf:"rule_definitions,omitempty"`

	// Unique identifier of the security policy
	SecurityPolicyID *string `json:"securityPolicyId,omitempty" tf:"security_policy_id,omitempty"`
}

type RapidRulesParameters struct {

	// Unique identifier of the security configuration
	// +kubebuilder:validation:Optional
	ConfigID *float64 `json:"configId,omitempty" tf:"config_id,omitempty"`

	// Default action that applies to violations of all rapid rules
	// +kubebuilder:validation:Optional
	DefaultAction *string `json:"defaultAction,omitempty" tf:"default_action,omitempty"`

	// JSON-formatted list of rule definition (ID, action, action lock and exception)
	// +kubebuilder:validation:Optional
	RuleDefinitions *string `json:"ruleDefinitions,omitempty" tf:"rule_definitions,omitempty"`

	// Unique identifier of the security policy
	// +kubebuilder:validation:Optional
	SecurityPolicyID *string `json:"securityPolicyId,omitempty" tf:"security_policy_id,omitempty"`
}

// RapidRulesSpec defines the desired state of RapidRules
type RapidRulesSpec struct {
	v1.ResourceSpec `json:",inline"`
	ForProvider     RapidRulesParameters `json:"forProvider"`
	// THIS IS A BETA FIELD. It will be honored
	// unless the Management Policies feature flag is disabled.
	// InitProvider holds the same fields as ForProvider, with the exception
	// of Identifier and other resource reference fields. The fields that are
	// in InitProvider are merged into ForProvider when the resource is created.
	// The same fields are also added to the terraform ignore_changes hook, to
	// avoid updating them after creation. This is useful for fields that are
	// required on creation, but we do not desire to update them after creation,
	// for example because of an external controller is managing them, like an
	// autoscaler.
	InitProvider RapidRulesInitParameters `json:"initProvider,omitempty"`
}

// RapidRulesStatus defines the observed state of RapidRules.
type RapidRulesStatus struct {
	v1.ResourceStatus `json:",inline"`
	AtProvider        RapidRulesObservation `json:"atProvider,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:storageversion

// RapidRules is the Schema for the RapidRuless API. <no value>
// +kubebuilder:printcolumn:name="SYNCED",type="string",JSONPath=".status.conditions[?(@.type=='Synced')].status"
// +kubebuilder:printcolumn:name="READY",type="string",JSONPath=".status.conditions[?(@.type=='Ready')].status"
// +kubebuilder:printcolumn:name="EXTERNAL-NAME",type="string",JSONPath=".metadata.annotations.crossplane\\.io/external-name"
// +kubebuilder:printcolumn:name="AGE",type="date",JSONPath=".metadata.creationTimestamp"
// +kubebuilder:resource:scope=Cluster,categories={crossplane,managed,akamai}
type RapidRules struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`
	// +kubebuilder:validation:XValidation:rule="!('*' in self.managementPolicies || 'Create' in self.managementPolicies || 'Update' in self.managementPolicies) || has(self.forProvider.configId) || (has(self.initProvider) && has(self.initProvider.configId))",message="spec.forProvider.configId is a required parameter"
	// +kubebuilder:validation:XValidation:rule="!('*' in self.managementPolicies || 'Create' in self.managementPolicies || 'Update' in self.managementPolicies) || has(self.forProvider.securityPolicyId) || (has(self.initProvider) && has(self.initProvider.securityPolicyId))",message="spec.forProvider.securityPolicyId is a required parameter"
	Spec   RapidRulesSpec   `json:"spec"`
	Status RapidRulesStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// RapidRulesList contains a list of RapidRuless
type RapidRulesList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []RapidRules `json:"items"`
}

// Repository type metadata.
var (
	RapidRules_Kind             = "RapidRules"
	RapidRules_GroupKind        = schema.GroupKind{Group: CRDGroup, Kind: RapidRules_Kind}.String()
	RapidRules_KindAPIVersion   = RapidRules_Kind + "." + CRDGroupVersion.String()
	RapidRules_GroupVersionKind = CRDGroupVersion.WithKind(RapidRules_Kind)
)

func init() {
	SchemeBuilder.Register(&RapidRules{}, &RapidRulesList{})
}
