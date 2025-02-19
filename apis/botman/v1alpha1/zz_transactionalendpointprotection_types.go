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

type TransactionalEndpointProtectionInitParameters struct {
	ConfigID *float64 `json:"configId,omitempty" tf:"config_id,omitempty"`

	TransactionalEndpointProtection *string `json:"transactionalEndpointProtection,omitempty" tf:"transactional_endpoint_protection,omitempty"`
}

type TransactionalEndpointProtectionObservation struct {
	ConfigID *float64 `json:"configId,omitempty" tf:"config_id,omitempty"`

	ID *string `json:"id,omitempty" tf:"id,omitempty"`

	TransactionalEndpointProtection *string `json:"transactionalEndpointProtection,omitempty" tf:"transactional_endpoint_protection,omitempty"`
}

type TransactionalEndpointProtectionParameters struct {

	// +kubebuilder:validation:Optional
	ConfigID *float64 `json:"configId,omitempty" tf:"config_id,omitempty"`

	// +kubebuilder:validation:Optional
	TransactionalEndpointProtection *string `json:"transactionalEndpointProtection,omitempty" tf:"transactional_endpoint_protection,omitempty"`
}

// TransactionalEndpointProtectionSpec defines the desired state of TransactionalEndpointProtection
type TransactionalEndpointProtectionSpec struct {
	v1.ResourceSpec `json:",inline"`
	ForProvider     TransactionalEndpointProtectionParameters `json:"forProvider"`
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
	InitProvider TransactionalEndpointProtectionInitParameters `json:"initProvider,omitempty"`
}

// TransactionalEndpointProtectionStatus defines the observed state of TransactionalEndpointProtection.
type TransactionalEndpointProtectionStatus struct {
	v1.ResourceStatus `json:",inline"`
	AtProvider        TransactionalEndpointProtectionObservation `json:"atProvider,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:storageversion

// TransactionalEndpointProtection is the Schema for the TransactionalEndpointProtections API. <no value>
// +kubebuilder:printcolumn:name="SYNCED",type="string",JSONPath=".status.conditions[?(@.type=='Synced')].status"
// +kubebuilder:printcolumn:name="READY",type="string",JSONPath=".status.conditions[?(@.type=='Ready')].status"
// +kubebuilder:printcolumn:name="EXTERNAL-NAME",type="string",JSONPath=".metadata.annotations.crossplane\\.io/external-name"
// +kubebuilder:printcolumn:name="AGE",type="date",JSONPath=".metadata.creationTimestamp"
// +kubebuilder:resource:scope=Cluster,categories={crossplane,managed,akamai}
type TransactionalEndpointProtection struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`
	// +kubebuilder:validation:XValidation:rule="!('*' in self.managementPolicies || 'Create' in self.managementPolicies || 'Update' in self.managementPolicies) || has(self.forProvider.configId) || (has(self.initProvider) && has(self.initProvider.configId))",message="spec.forProvider.configId is a required parameter"
	// +kubebuilder:validation:XValidation:rule="!('*' in self.managementPolicies || 'Create' in self.managementPolicies || 'Update' in self.managementPolicies) || has(self.forProvider.transactionalEndpointProtection) || (has(self.initProvider) && has(self.initProvider.transactionalEndpointProtection))",message="spec.forProvider.transactionalEndpointProtection is a required parameter"
	Spec   TransactionalEndpointProtectionSpec   `json:"spec"`
	Status TransactionalEndpointProtectionStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// TransactionalEndpointProtectionList contains a list of TransactionalEndpointProtections
type TransactionalEndpointProtectionList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []TransactionalEndpointProtection `json:"items"`
}

// Repository type metadata.
var (
	TransactionalEndpointProtection_Kind             = "TransactionalEndpointProtection"
	TransactionalEndpointProtection_GroupKind        = schema.GroupKind{Group: CRDGroup, Kind: TransactionalEndpointProtection_Kind}.String()
	TransactionalEndpointProtection_KindAPIVersion   = TransactionalEndpointProtection_Kind + "." + CRDGroupVersion.String()
	TransactionalEndpointProtection_GroupVersionKind = CRDGroupVersion.WithKind(TransactionalEndpointProtection_Kind)
)

func init() {
	SchemeBuilder.Register(&TransactionalEndpointProtection{}, &TransactionalEndpointProtectionList{})
}
