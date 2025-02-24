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

type SecurityPolicyInitParameters struct {

	// Unique identifier of the security configuration
	ConfigID *float64 `json:"configId,omitempty" tf:"config_id,omitempty"`

	// Unique identifier of the existing security policy being cloned
	CreateFromSecurityPolicyID *string `json:"createFromSecurityPolicyId,omitempty" tf:"create_from_security_policy_id,omitempty"`

	// Whether to assign default settings to the new security policy
	DefaultSettings *bool `json:"defaultSettings,omitempty" tf:"default_settings,omitempty"`

	// Name of the new security policy
	SecurityPolicyName *string `json:"securityPolicyName,omitempty" tf:"security_policy_name,omitempty"`

	// Four-character alphanumeric string prefix used in creating the security policy ID
	SecurityPolicyPrefix *string `json:"securityPolicyPrefix,omitempty" tf:"security_policy_prefix,omitempty"`
}

type SecurityPolicyObservation struct {

	// Unique identifier of the security configuration
	ConfigID *float64 `json:"configId,omitempty" tf:"config_id,omitempty"`

	// Unique identifier of the existing security policy being cloned
	CreateFromSecurityPolicyID *string `json:"createFromSecurityPolicyId,omitempty" tf:"create_from_security_policy_id,omitempty"`

	// Whether to assign default settings to the new security policy
	DefaultSettings *bool `json:"defaultSettings,omitempty" tf:"default_settings,omitempty"`

	ID *string `json:"id,omitempty" tf:"id,omitempty"`

	// Unique identifier of the new security policy
	SecurityPolicyID *string `json:"securityPolicyId,omitempty" tf:"security_policy_id,omitempty"`

	// Name of the new security policy
	SecurityPolicyName *string `json:"securityPolicyName,omitempty" tf:"security_policy_name,omitempty"`

	// Four-character alphanumeric string prefix used in creating the security policy ID
	SecurityPolicyPrefix *string `json:"securityPolicyPrefix,omitempty" tf:"security_policy_prefix,omitempty"`
}

type SecurityPolicyParameters struct {

	// Unique identifier of the security configuration
	// +kubebuilder:validation:Optional
	ConfigID *float64 `json:"configId,omitempty" tf:"config_id,omitempty"`

	// Unique identifier of the existing security policy being cloned
	// +kubebuilder:validation:Optional
	CreateFromSecurityPolicyID *string `json:"createFromSecurityPolicyId,omitempty" tf:"create_from_security_policy_id,omitempty"`

	// Whether to assign default settings to the new security policy
	// +kubebuilder:validation:Optional
	DefaultSettings *bool `json:"defaultSettings,omitempty" tf:"default_settings,omitempty"`

	// Name of the new security policy
	// +kubebuilder:validation:Optional
	SecurityPolicyName *string `json:"securityPolicyName,omitempty" tf:"security_policy_name,omitempty"`

	// Four-character alphanumeric string prefix used in creating the security policy ID
	// +kubebuilder:validation:Optional
	SecurityPolicyPrefix *string `json:"securityPolicyPrefix,omitempty" tf:"security_policy_prefix,omitempty"`
}

// SecurityPolicySpec defines the desired state of SecurityPolicy
type SecurityPolicySpec struct {
	v1.ResourceSpec `json:",inline"`
	ForProvider     SecurityPolicyParameters `json:"forProvider"`
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
	InitProvider SecurityPolicyInitParameters `json:"initProvider,omitempty"`
}

// SecurityPolicyStatus defines the observed state of SecurityPolicy.
type SecurityPolicyStatus struct {
	v1.ResourceStatus `json:",inline"`
	AtProvider        SecurityPolicyObservation `json:"atProvider,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:storageversion

// SecurityPolicy is the Schema for the SecurityPolicys API. <no value>
// +kubebuilder:printcolumn:name="SYNCED",type="string",JSONPath=".status.conditions[?(@.type=='Synced')].status"
// +kubebuilder:printcolumn:name="READY",type="string",JSONPath=".status.conditions[?(@.type=='Ready')].status"
// +kubebuilder:printcolumn:name="EXTERNAL-NAME",type="string",JSONPath=".metadata.annotations.crossplane\\.io/external-name"
// +kubebuilder:printcolumn:name="AGE",type="date",JSONPath=".metadata.creationTimestamp"
// +kubebuilder:resource:scope=Cluster,categories={crossplane,managed,akamai}
type SecurityPolicy struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`
	// +kubebuilder:validation:XValidation:rule="!('*' in self.managementPolicies || 'Create' in self.managementPolicies || 'Update' in self.managementPolicies) || has(self.forProvider.configId) || (has(self.initProvider) && has(self.initProvider.configId))",message="spec.forProvider.configId is a required parameter"
	// +kubebuilder:validation:XValidation:rule="!('*' in self.managementPolicies || 'Create' in self.managementPolicies || 'Update' in self.managementPolicies) || has(self.forProvider.securityPolicyName) || (has(self.initProvider) && has(self.initProvider.securityPolicyName))",message="spec.forProvider.securityPolicyName is a required parameter"
	// +kubebuilder:validation:XValidation:rule="!('*' in self.managementPolicies || 'Create' in self.managementPolicies || 'Update' in self.managementPolicies) || has(self.forProvider.securityPolicyPrefix) || (has(self.initProvider) && has(self.initProvider.securityPolicyPrefix))",message="spec.forProvider.securityPolicyPrefix is a required parameter"
	Spec   SecurityPolicySpec   `json:"spec"`
	Status SecurityPolicyStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// SecurityPolicyList contains a list of SecurityPolicys
type SecurityPolicyList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []SecurityPolicy `json:"items"`
}

// Repository type metadata.
var (
	SecurityPolicy_Kind             = "SecurityPolicy"
	SecurityPolicy_GroupKind        = schema.GroupKind{Group: CRDGroup, Kind: SecurityPolicy_Kind}.String()
	SecurityPolicy_KindAPIVersion   = SecurityPolicy_Kind + "." + CRDGroupVersion.String()
	SecurityPolicy_GroupVersionKind = CRDGroupVersion.WithKind(SecurityPolicy_Kind)
)

func init() {
	SchemeBuilder.Register(&SecurityPolicy{}, &SecurityPolicyList{})
}
