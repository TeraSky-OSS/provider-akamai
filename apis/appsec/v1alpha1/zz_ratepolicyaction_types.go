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

type RatePolicyActionInitParameters struct {

	// Unique identifier of the security configuration
	ConfigID *float64 `json:"configId,omitempty" tf:"config_id,omitempty"`

	// Action to be taken for requests coming from an IPv4 address
	IPv4Action *string `json:"ipv4Action,omitempty" tf:"ipv4_action,omitempty"`

	// Action to be taken for requests coming from an IPv6 address
	IPv6Action *string `json:"ipv6Action,omitempty" tf:"ipv6_action,omitempty"`

	// Unique identifier of the rate policy
	RatePolicyID *float64 `json:"ratePolicyId,omitempty" tf:"rate_policy_id,omitempty"`

	// Unique identifier of the security policy
	SecurityPolicyID *string `json:"securityPolicyId,omitempty" tf:"security_policy_id,omitempty"`
}

type RatePolicyActionObservation struct {

	// Unique identifier of the security configuration
	ConfigID *float64 `json:"configId,omitempty" tf:"config_id,omitempty"`

	ID *string `json:"id,omitempty" tf:"id,omitempty"`

	// Action to be taken for requests coming from an IPv4 address
	IPv4Action *string `json:"ipv4Action,omitempty" tf:"ipv4_action,omitempty"`

	// Action to be taken for requests coming from an IPv6 address
	IPv6Action *string `json:"ipv6Action,omitempty" tf:"ipv6_action,omitempty"`

	// Unique identifier of the rate policy
	RatePolicyID *float64 `json:"ratePolicyId,omitempty" tf:"rate_policy_id,omitempty"`

	// Unique identifier of the security policy
	SecurityPolicyID *string `json:"securityPolicyId,omitempty" tf:"security_policy_id,omitempty"`
}

type RatePolicyActionParameters struct {

	// Unique identifier of the security configuration
	// +kubebuilder:validation:Optional
	ConfigID *float64 `json:"configId,omitempty" tf:"config_id,omitempty"`

	// Action to be taken for requests coming from an IPv4 address
	// +kubebuilder:validation:Optional
	IPv4Action *string `json:"ipv4Action,omitempty" tf:"ipv4_action,omitempty"`

	// Action to be taken for requests coming from an IPv6 address
	// +kubebuilder:validation:Optional
	IPv6Action *string `json:"ipv6Action,omitempty" tf:"ipv6_action,omitempty"`

	// Unique identifier of the rate policy
	// +kubebuilder:validation:Optional
	RatePolicyID *float64 `json:"ratePolicyId,omitempty" tf:"rate_policy_id,omitempty"`

	// Unique identifier of the security policy
	// +kubebuilder:validation:Optional
	SecurityPolicyID *string `json:"securityPolicyId,omitempty" tf:"security_policy_id,omitempty"`
}

// RatePolicyActionSpec defines the desired state of RatePolicyAction
type RatePolicyActionSpec struct {
	v1.ResourceSpec `json:",inline"`
	ForProvider     RatePolicyActionParameters `json:"forProvider"`
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
	InitProvider RatePolicyActionInitParameters `json:"initProvider,omitempty"`
}

// RatePolicyActionStatus defines the observed state of RatePolicyAction.
type RatePolicyActionStatus struct {
	v1.ResourceStatus `json:",inline"`
	AtProvider        RatePolicyActionObservation `json:"atProvider,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:storageversion

// RatePolicyAction is the Schema for the RatePolicyActions API. <no value>
// +kubebuilder:printcolumn:name="SYNCED",type="string",JSONPath=".status.conditions[?(@.type=='Synced')].status"
// +kubebuilder:printcolumn:name="READY",type="string",JSONPath=".status.conditions[?(@.type=='Ready')].status"
// +kubebuilder:printcolumn:name="EXTERNAL-NAME",type="string",JSONPath=".metadata.annotations.crossplane\\.io/external-name"
// +kubebuilder:printcolumn:name="AGE",type="date",JSONPath=".metadata.creationTimestamp"
// +kubebuilder:resource:scope=Cluster,categories={crossplane,managed,akamai}
type RatePolicyAction struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`
	// +kubebuilder:validation:XValidation:rule="!('*' in self.managementPolicies || 'Create' in self.managementPolicies || 'Update' in self.managementPolicies) || has(self.forProvider.configId) || (has(self.initProvider) && has(self.initProvider.configId))",message="spec.forProvider.configId is a required parameter"
	// +kubebuilder:validation:XValidation:rule="!('*' in self.managementPolicies || 'Create' in self.managementPolicies || 'Update' in self.managementPolicies) || has(self.forProvider.ipv4Action) || (has(self.initProvider) && has(self.initProvider.ipv4Action))",message="spec.forProvider.ipv4Action is a required parameter"
	// +kubebuilder:validation:XValidation:rule="!('*' in self.managementPolicies || 'Create' in self.managementPolicies || 'Update' in self.managementPolicies) || has(self.forProvider.ipv6Action) || (has(self.initProvider) && has(self.initProvider.ipv6Action))",message="spec.forProvider.ipv6Action is a required parameter"
	// +kubebuilder:validation:XValidation:rule="!('*' in self.managementPolicies || 'Create' in self.managementPolicies || 'Update' in self.managementPolicies) || has(self.forProvider.ratePolicyId) || (has(self.initProvider) && has(self.initProvider.ratePolicyId))",message="spec.forProvider.ratePolicyId is a required parameter"
	// +kubebuilder:validation:XValidation:rule="!('*' in self.managementPolicies || 'Create' in self.managementPolicies || 'Update' in self.managementPolicies) || has(self.forProvider.securityPolicyId) || (has(self.initProvider) && has(self.initProvider.securityPolicyId))",message="spec.forProvider.securityPolicyId is a required parameter"
	Spec   RatePolicyActionSpec   `json:"spec"`
	Status RatePolicyActionStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// RatePolicyActionList contains a list of RatePolicyActions
type RatePolicyActionList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []RatePolicyAction `json:"items"`
}

// Repository type metadata.
var (
	RatePolicyAction_Kind             = "RatePolicyAction"
	RatePolicyAction_GroupKind        = schema.GroupKind{Group: CRDGroup, Kind: RatePolicyAction_Kind}.String()
	RatePolicyAction_KindAPIVersion   = RatePolicyAction_Kind + "." + CRDGroupVersion.String()
	RatePolicyAction_GroupVersionKind = CRDGroupVersion.WithKind(RatePolicyAction_Kind)
)

func init() {
	SchemeBuilder.Register(&RatePolicyAction{}, &RatePolicyActionList{})
}
