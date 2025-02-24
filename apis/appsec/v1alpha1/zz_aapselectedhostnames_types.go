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

type AAPSelectedHostnamesInitParameters struct {

	// Unique identifier of the security configuration
	ConfigID *float64 `json:"configId,omitempty" tf:"config_id,omitempty"`

	// List of hostnames to be evaluated
	// +listType=set
	EvaluatedHosts []*string `json:"evaluatedHosts,omitempty" tf:"evaluated_hosts,omitempty"`

	// List of hostnames to be protected
	// +listType=set
	ProtectedHosts []*string `json:"protectedHosts,omitempty" tf:"protected_hosts,omitempty"`

	// Unique identifier of the security policy
	SecurityPolicyID *string `json:"securityPolicyId,omitempty" tf:"security_policy_id,omitempty"`
}

type AAPSelectedHostnamesObservation struct {

	// Unique identifier of the security configuration
	ConfigID *float64 `json:"configId,omitempty" tf:"config_id,omitempty"`

	// List of hostnames to be evaluated
	// +listType=set
	EvaluatedHosts []*string `json:"evaluatedHosts,omitempty" tf:"evaluated_hosts,omitempty"`

	ID *string `json:"id,omitempty" tf:"id,omitempty"`

	// List of hostnames to be protected
	// +listType=set
	ProtectedHosts []*string `json:"protectedHosts,omitempty" tf:"protected_hosts,omitempty"`

	// Unique identifier of the security policy
	SecurityPolicyID *string `json:"securityPolicyId,omitempty" tf:"security_policy_id,omitempty"`
}

type AAPSelectedHostnamesParameters struct {

	// Unique identifier of the security configuration
	// +kubebuilder:validation:Optional
	ConfigID *float64 `json:"configId,omitempty" tf:"config_id,omitempty"`

	// List of hostnames to be evaluated
	// +kubebuilder:validation:Optional
	// +listType=set
	EvaluatedHosts []*string `json:"evaluatedHosts,omitempty" tf:"evaluated_hosts,omitempty"`

	// List of hostnames to be protected
	// +kubebuilder:validation:Optional
	// +listType=set
	ProtectedHosts []*string `json:"protectedHosts,omitempty" tf:"protected_hosts,omitempty"`

	// Unique identifier of the security policy
	// +kubebuilder:validation:Optional
	SecurityPolicyID *string `json:"securityPolicyId,omitempty" tf:"security_policy_id,omitempty"`
}

// AAPSelectedHostnamesSpec defines the desired state of AAPSelectedHostnames
type AAPSelectedHostnamesSpec struct {
	v1.ResourceSpec `json:",inline"`
	ForProvider     AAPSelectedHostnamesParameters `json:"forProvider"`
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
	InitProvider AAPSelectedHostnamesInitParameters `json:"initProvider,omitempty"`
}

// AAPSelectedHostnamesStatus defines the observed state of AAPSelectedHostnames.
type AAPSelectedHostnamesStatus struct {
	v1.ResourceStatus `json:",inline"`
	AtProvider        AAPSelectedHostnamesObservation `json:"atProvider,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:storageversion

// AAPSelectedHostnames is the Schema for the AAPSelectedHostnamess API. <no value>
// +kubebuilder:printcolumn:name="SYNCED",type="string",JSONPath=".status.conditions[?(@.type=='Synced')].status"
// +kubebuilder:printcolumn:name="READY",type="string",JSONPath=".status.conditions[?(@.type=='Ready')].status"
// +kubebuilder:printcolumn:name="EXTERNAL-NAME",type="string",JSONPath=".metadata.annotations.crossplane\\.io/external-name"
// +kubebuilder:printcolumn:name="AGE",type="date",JSONPath=".metadata.creationTimestamp"
// +kubebuilder:resource:scope=Cluster,categories={crossplane,managed,akamai}
type AAPSelectedHostnames struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`
	// +kubebuilder:validation:XValidation:rule="!('*' in self.managementPolicies || 'Create' in self.managementPolicies || 'Update' in self.managementPolicies) || has(self.forProvider.configId) || (has(self.initProvider) && has(self.initProvider.configId))",message="spec.forProvider.configId is a required parameter"
	// +kubebuilder:validation:XValidation:rule="!('*' in self.managementPolicies || 'Create' in self.managementPolicies || 'Update' in self.managementPolicies) || has(self.forProvider.securityPolicyId) || (has(self.initProvider) && has(self.initProvider.securityPolicyId))",message="spec.forProvider.securityPolicyId is a required parameter"
	Spec   AAPSelectedHostnamesSpec   `json:"spec"`
	Status AAPSelectedHostnamesStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// AAPSelectedHostnamesList contains a list of AAPSelectedHostnamess
type AAPSelectedHostnamesList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []AAPSelectedHostnames `json:"items"`
}

// Repository type metadata.
var (
	AAPSelectedHostnames_Kind             = "AAPSelectedHostnames"
	AAPSelectedHostnames_GroupKind        = schema.GroupKind{Group: CRDGroup, Kind: AAPSelectedHostnames_Kind}.String()
	AAPSelectedHostnames_KindAPIVersion   = AAPSelectedHostnames_Kind + "." + CRDGroupVersion.String()
	AAPSelectedHostnames_GroupVersionKind = CRDGroupVersion.WithKind(AAPSelectedHostnames_Kind)
)

func init() {
	SchemeBuilder.Register(&AAPSelectedHostnames{}, &AAPSelectedHostnamesList{})
}
