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

type CustomRuleInitParameters struct {

	// Unique identifier of the security configuration
	ConfigID *float64 `json:"configId,omitempty" tf:"config_id,omitempty"`

	// JSON-formatted definition of the custom rule
	CustomRule *string `json:"customRule,omitempty" tf:"custom_rule,omitempty"`
}

type CustomRuleObservation struct {

	// Unique identifier of the security configuration
	ConfigID *float64 `json:"configId,omitempty" tf:"config_id,omitempty"`

	// JSON-formatted definition of the custom rule
	CustomRule *string `json:"customRule,omitempty" tf:"custom_rule,omitempty"`

	CustomRuleID *float64 `json:"customRuleId,omitempty" tf:"custom_rule_id,omitempty"`

	ID *string `json:"id,omitempty" tf:"id,omitempty"`
}

type CustomRuleParameters struct {

	// Unique identifier of the security configuration
	// +kubebuilder:validation:Optional
	ConfigID *float64 `json:"configId,omitempty" tf:"config_id,omitempty"`

	// JSON-formatted definition of the custom rule
	// +kubebuilder:validation:Optional
	CustomRule *string `json:"customRule,omitempty" tf:"custom_rule,omitempty"`
}

// CustomRuleSpec defines the desired state of CustomRule
type CustomRuleSpec struct {
	v1.ResourceSpec `json:",inline"`
	ForProvider     CustomRuleParameters `json:"forProvider"`
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
	InitProvider CustomRuleInitParameters `json:"initProvider,omitempty"`
}

// CustomRuleStatus defines the observed state of CustomRule.
type CustomRuleStatus struct {
	v1.ResourceStatus `json:",inline"`
	AtProvider        CustomRuleObservation `json:"atProvider,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:storageversion

// CustomRule is the Schema for the CustomRules API. <no value>
// +kubebuilder:printcolumn:name="SYNCED",type="string",JSONPath=".status.conditions[?(@.type=='Synced')].status"
// +kubebuilder:printcolumn:name="READY",type="string",JSONPath=".status.conditions[?(@.type=='Ready')].status"
// +kubebuilder:printcolumn:name="EXTERNAL-NAME",type="string",JSONPath=".metadata.annotations.crossplane\\.io/external-name"
// +kubebuilder:printcolumn:name="AGE",type="date",JSONPath=".metadata.creationTimestamp"
// +kubebuilder:resource:scope=Cluster,categories={crossplane,managed,akamai}
type CustomRule struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`
	// +kubebuilder:validation:XValidation:rule="!('*' in self.managementPolicies || 'Create' in self.managementPolicies || 'Update' in self.managementPolicies) || has(self.forProvider.configId) || (has(self.initProvider) && has(self.initProvider.configId))",message="spec.forProvider.configId is a required parameter"
	// +kubebuilder:validation:XValidation:rule="!('*' in self.managementPolicies || 'Create' in self.managementPolicies || 'Update' in self.managementPolicies) || has(self.forProvider.customRule) || (has(self.initProvider) && has(self.initProvider.customRule))",message="spec.forProvider.customRule is a required parameter"
	Spec   CustomRuleSpec   `json:"spec"`
	Status CustomRuleStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// CustomRuleList contains a list of CustomRules
type CustomRuleList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []CustomRule `json:"items"`
}

// Repository type metadata.
var (
	CustomRule_Kind             = "CustomRule"
	CustomRule_GroupKind        = schema.GroupKind{Group: CRDGroup, Kind: CustomRule_Kind}.String()
	CustomRule_KindAPIVersion   = CustomRule_Kind + "." + CRDGroupVersion.String()
	CustomRule_GroupVersionKind = CRDGroupVersion.WithKind(CustomRule_Kind)
)

func init() {
	SchemeBuilder.Register(&CustomRule{}, &CustomRuleList{})
}
