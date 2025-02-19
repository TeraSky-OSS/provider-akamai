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

type AdvancedSettingsLoggingInitParameters struct {

	// Unique identifier of the security configuration
	ConfigID *float64 `json:"configId,omitempty" tf:"config_id,omitempty"`

	// Whether to enable, disable, or update HTTP header logging settings
	Logging *string `json:"logging,omitempty" tf:"logging,omitempty"`

	// Unique identifier of the security policy
	SecurityPolicyID *string `json:"securityPolicyId,omitempty" tf:"security_policy_id,omitempty"`
}

type AdvancedSettingsLoggingObservation struct {

	// Unique identifier of the security configuration
	ConfigID *float64 `json:"configId,omitempty" tf:"config_id,omitempty"`

	ID *string `json:"id,omitempty" tf:"id,omitempty"`

	// Whether to enable, disable, or update HTTP header logging settings
	Logging *string `json:"logging,omitempty" tf:"logging,omitempty"`

	// Unique identifier of the security policy
	SecurityPolicyID *string `json:"securityPolicyId,omitempty" tf:"security_policy_id,omitempty"`
}

type AdvancedSettingsLoggingParameters struct {

	// Unique identifier of the security configuration
	// +kubebuilder:validation:Optional
	ConfigID *float64 `json:"configId,omitempty" tf:"config_id,omitempty"`

	// Whether to enable, disable, or update HTTP header logging settings
	// +kubebuilder:validation:Optional
	Logging *string `json:"logging,omitempty" tf:"logging,omitempty"`

	// Unique identifier of the security policy
	// +kubebuilder:validation:Optional
	SecurityPolicyID *string `json:"securityPolicyId,omitempty" tf:"security_policy_id,omitempty"`
}

// AdvancedSettingsLoggingSpec defines the desired state of AdvancedSettingsLogging
type AdvancedSettingsLoggingSpec struct {
	v1.ResourceSpec `json:",inline"`
	ForProvider     AdvancedSettingsLoggingParameters `json:"forProvider"`
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
	InitProvider AdvancedSettingsLoggingInitParameters `json:"initProvider,omitempty"`
}

// AdvancedSettingsLoggingStatus defines the observed state of AdvancedSettingsLogging.
type AdvancedSettingsLoggingStatus struct {
	v1.ResourceStatus `json:",inline"`
	AtProvider        AdvancedSettingsLoggingObservation `json:"atProvider,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:storageversion

// AdvancedSettingsLogging is the Schema for the AdvancedSettingsLoggings API. <no value>
// +kubebuilder:printcolumn:name="SYNCED",type="string",JSONPath=".status.conditions[?(@.type=='Synced')].status"
// +kubebuilder:printcolumn:name="READY",type="string",JSONPath=".status.conditions[?(@.type=='Ready')].status"
// +kubebuilder:printcolumn:name="EXTERNAL-NAME",type="string",JSONPath=".metadata.annotations.crossplane\\.io/external-name"
// +kubebuilder:printcolumn:name="AGE",type="date",JSONPath=".metadata.creationTimestamp"
// +kubebuilder:resource:scope=Cluster,categories={crossplane,managed,akamai}
type AdvancedSettingsLogging struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`
	// +kubebuilder:validation:XValidation:rule="!('*' in self.managementPolicies || 'Create' in self.managementPolicies || 'Update' in self.managementPolicies) || has(self.forProvider.configId) || (has(self.initProvider) && has(self.initProvider.configId))",message="spec.forProvider.configId is a required parameter"
	// +kubebuilder:validation:XValidation:rule="!('*' in self.managementPolicies || 'Create' in self.managementPolicies || 'Update' in self.managementPolicies) || has(self.forProvider.logging) || (has(self.initProvider) && has(self.initProvider.logging))",message="spec.forProvider.logging is a required parameter"
	Spec   AdvancedSettingsLoggingSpec   `json:"spec"`
	Status AdvancedSettingsLoggingStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// AdvancedSettingsLoggingList contains a list of AdvancedSettingsLoggings
type AdvancedSettingsLoggingList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []AdvancedSettingsLogging `json:"items"`
}

// Repository type metadata.
var (
	AdvancedSettingsLogging_Kind             = "AdvancedSettingsLogging"
	AdvancedSettingsLogging_GroupKind        = schema.GroupKind{Group: CRDGroup, Kind: AdvancedSettingsLogging_Kind}.String()
	AdvancedSettingsLogging_KindAPIVersion   = AdvancedSettingsLogging_Kind + "." + CRDGroupVersion.String()
	AdvancedSettingsLogging_GroupVersionKind = CRDGroupVersion.WithKind(AdvancedSettingsLogging_Kind)
)

func init() {
	SchemeBuilder.Register(&AdvancedSettingsLogging{}, &AdvancedSettingsLoggingList{})
}
