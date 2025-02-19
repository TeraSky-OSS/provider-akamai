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

type ApiRequestConstraintsInitParameters struct {

	// Unique identifier of the API endpoint to which the constraint will be assigned
	APIEndpointID *float64 `json:"apiEndpointId,omitempty" tf:"api_endpoint_id,omitempty"`

	// Action to be taken when the API request constraint is triggered
	Action *string `json:"action,omitempty" tf:"action,omitempty"`

	// Unique identifier of the security configuration
	ConfigID *float64 `json:"configId,omitempty" tf:"config_id,omitempty"`

	// Unique identifier of the security policy
	SecurityPolicyID *string `json:"securityPolicyId,omitempty" tf:"security_policy_id,omitempty"`
}

type ApiRequestConstraintsObservation struct {

	// Unique identifier of the API endpoint to which the constraint will be assigned
	APIEndpointID *float64 `json:"apiEndpointId,omitempty" tf:"api_endpoint_id,omitempty"`

	// Action to be taken when the API request constraint is triggered
	Action *string `json:"action,omitempty" tf:"action,omitempty"`

	// Unique identifier of the security configuration
	ConfigID *float64 `json:"configId,omitempty" tf:"config_id,omitempty"`

	ID *string `json:"id,omitempty" tf:"id,omitempty"`

	// Unique identifier of the security policy
	SecurityPolicyID *string `json:"securityPolicyId,omitempty" tf:"security_policy_id,omitempty"`
}

type ApiRequestConstraintsParameters struct {

	// Unique identifier of the API endpoint to which the constraint will be assigned
	// +kubebuilder:validation:Optional
	APIEndpointID *float64 `json:"apiEndpointId,omitempty" tf:"api_endpoint_id,omitempty"`

	// Action to be taken when the API request constraint is triggered
	// +kubebuilder:validation:Optional
	Action *string `json:"action,omitempty" tf:"action,omitempty"`

	// Unique identifier of the security configuration
	// +kubebuilder:validation:Optional
	ConfigID *float64 `json:"configId,omitempty" tf:"config_id,omitempty"`

	// Unique identifier of the security policy
	// +kubebuilder:validation:Optional
	SecurityPolicyID *string `json:"securityPolicyId,omitempty" tf:"security_policy_id,omitempty"`
}

// ApiRequestConstraintsSpec defines the desired state of ApiRequestConstraints
type ApiRequestConstraintsSpec struct {
	v1.ResourceSpec `json:",inline"`
	ForProvider     ApiRequestConstraintsParameters `json:"forProvider"`
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
	InitProvider ApiRequestConstraintsInitParameters `json:"initProvider,omitempty"`
}

// ApiRequestConstraintsStatus defines the observed state of ApiRequestConstraints.
type ApiRequestConstraintsStatus struct {
	v1.ResourceStatus `json:",inline"`
	AtProvider        ApiRequestConstraintsObservation `json:"atProvider,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:storageversion

// ApiRequestConstraints is the Schema for the ApiRequestConstraintss API. <no value>
// +kubebuilder:printcolumn:name="SYNCED",type="string",JSONPath=".status.conditions[?(@.type=='Synced')].status"
// +kubebuilder:printcolumn:name="READY",type="string",JSONPath=".status.conditions[?(@.type=='Ready')].status"
// +kubebuilder:printcolumn:name="EXTERNAL-NAME",type="string",JSONPath=".metadata.annotations.crossplane\\.io/external-name"
// +kubebuilder:printcolumn:name="AGE",type="date",JSONPath=".metadata.creationTimestamp"
// +kubebuilder:resource:scope=Cluster,categories={crossplane,managed,akamai}
type ApiRequestConstraints struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`
	// +kubebuilder:validation:XValidation:rule="!('*' in self.managementPolicies || 'Create' in self.managementPolicies || 'Update' in self.managementPolicies) || has(self.forProvider.action) || (has(self.initProvider) && has(self.initProvider.action))",message="spec.forProvider.action is a required parameter"
	// +kubebuilder:validation:XValidation:rule="!('*' in self.managementPolicies || 'Create' in self.managementPolicies || 'Update' in self.managementPolicies) || has(self.forProvider.configId) || (has(self.initProvider) && has(self.initProvider.configId))",message="spec.forProvider.configId is a required parameter"
	// +kubebuilder:validation:XValidation:rule="!('*' in self.managementPolicies || 'Create' in self.managementPolicies || 'Update' in self.managementPolicies) || has(self.forProvider.securityPolicyId) || (has(self.initProvider) && has(self.initProvider.securityPolicyId))",message="spec.forProvider.securityPolicyId is a required parameter"
	Spec   ApiRequestConstraintsSpec   `json:"spec"`
	Status ApiRequestConstraintsStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// ApiRequestConstraintsList contains a list of ApiRequestConstraintss
type ApiRequestConstraintsList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []ApiRequestConstraints `json:"items"`
}

// Repository type metadata.
var (
	ApiRequestConstraints_Kind             = "ApiRequestConstraints"
	ApiRequestConstraints_GroupKind        = schema.GroupKind{Group: CRDGroup, Kind: ApiRequestConstraints_Kind}.String()
	ApiRequestConstraints_KindAPIVersion   = ApiRequestConstraints_Kind + "." + CRDGroupVersion.String()
	ApiRequestConstraints_GroupVersionKind = CRDGroupVersion.WithKind(ApiRequestConstraints_Kind)
)

func init() {
	SchemeBuilder.Register(&ApiRequestConstraints{}, &ApiRequestConstraintsList{})
}
