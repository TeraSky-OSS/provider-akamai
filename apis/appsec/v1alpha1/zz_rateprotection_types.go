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

type RateProtectionInitParameters struct {

	// Unique identifier of the security configuration
	ConfigID *float64 `json:"configId,omitempty" tf:"config_id,omitempty"`

	Enabled *bool `json:"enabled,omitempty" tf:"enabled,omitempty"`

	// Unique identifier of the security policy
	SecurityPolicyID *string `json:"securityPolicyId,omitempty" tf:"security_policy_id,omitempty"`
}

type RateProtectionObservation struct {

	// Unique identifier of the security configuration
	ConfigID *float64 `json:"configId,omitempty" tf:"config_id,omitempty"`

	Enabled *bool `json:"enabled,omitempty" tf:"enabled,omitempty"`

	ID *string `json:"id,omitempty" tf:"id,omitempty"`

	// Text representation
	OutputText *string `json:"outputText,omitempty" tf:"output_text,omitempty"`

	// Unique identifier of the security policy
	SecurityPolicyID *string `json:"securityPolicyId,omitempty" tf:"security_policy_id,omitempty"`
}

type RateProtectionParameters struct {

	// Unique identifier of the security configuration
	// +kubebuilder:validation:Optional
	ConfigID *float64 `json:"configId,omitempty" tf:"config_id,omitempty"`

	// +kubebuilder:validation:Optional
	Enabled *bool `json:"enabled,omitempty" tf:"enabled,omitempty"`

	// Unique identifier of the security policy
	// +kubebuilder:validation:Optional
	SecurityPolicyID *string `json:"securityPolicyId,omitempty" tf:"security_policy_id,omitempty"`
}

// RateProtectionSpec defines the desired state of RateProtection
type RateProtectionSpec struct {
	v1.ResourceSpec `json:",inline"`
	ForProvider     RateProtectionParameters `json:"forProvider"`
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
	InitProvider RateProtectionInitParameters `json:"initProvider,omitempty"`
}

// RateProtectionStatus defines the observed state of RateProtection.
type RateProtectionStatus struct {
	v1.ResourceStatus `json:",inline"`
	AtProvider        RateProtectionObservation `json:"atProvider,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:storageversion

// RateProtection is the Schema for the RateProtections API. <no value>
// +kubebuilder:printcolumn:name="SYNCED",type="string",JSONPath=".status.conditions[?(@.type=='Synced')].status"
// +kubebuilder:printcolumn:name="READY",type="string",JSONPath=".status.conditions[?(@.type=='Ready')].status"
// +kubebuilder:printcolumn:name="EXTERNAL-NAME",type="string",JSONPath=".metadata.annotations.crossplane\\.io/external-name"
// +kubebuilder:printcolumn:name="AGE",type="date",JSONPath=".metadata.creationTimestamp"
// +kubebuilder:resource:scope=Cluster,categories={crossplane,managed,akamai}
type RateProtection struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`
	// +kubebuilder:validation:XValidation:rule="!('*' in self.managementPolicies || 'Create' in self.managementPolicies || 'Update' in self.managementPolicies) || has(self.forProvider.configId) || (has(self.initProvider) && has(self.initProvider.configId))",message="spec.forProvider.configId is a required parameter"
	// +kubebuilder:validation:XValidation:rule="!('*' in self.managementPolicies || 'Create' in self.managementPolicies || 'Update' in self.managementPolicies) || has(self.forProvider.enabled) || (has(self.initProvider) && has(self.initProvider.enabled))",message="spec.forProvider.enabled is a required parameter"
	// +kubebuilder:validation:XValidation:rule="!('*' in self.managementPolicies || 'Create' in self.managementPolicies || 'Update' in self.managementPolicies) || has(self.forProvider.securityPolicyId) || (has(self.initProvider) && has(self.initProvider.securityPolicyId))",message="spec.forProvider.securityPolicyId is a required parameter"
	Spec   RateProtectionSpec   `json:"spec"`
	Status RateProtectionStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// RateProtectionList contains a list of RateProtections
type RateProtectionList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []RateProtection `json:"items"`
}

// Repository type metadata.
var (
	RateProtection_Kind             = "RateProtection"
	RateProtection_GroupKind        = schema.GroupKind{Group: CRDGroup, Kind: RateProtection_Kind}.String()
	RateProtection_KindAPIVersion   = RateProtection_Kind + "." + CRDGroupVersion.String()
	RateProtection_GroupVersionKind = CRDGroupVersion.WithKind(RateProtection_Kind)
)

func init() {
	SchemeBuilder.Register(&RateProtection{}, &RateProtectionList{})
}
