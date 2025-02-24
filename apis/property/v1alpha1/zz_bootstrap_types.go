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

type BootstrapInitParameters struct {

	// Contract ID to be assigned to the Property
	ContractID *string `json:"contractId,omitempty" tf:"contract_id,omitempty"`

	// Group ID to be assigned to the Property
	GroupID *string `json:"groupId,omitempty" tf:"group_id,omitempty"`

	// Name to give to the Property (must be unique)
	Name *string `json:"name,omitempty" tf:"name,omitempty"`

	// Product ID to be assigned to the Property
	ProductID *string `json:"productId,omitempty" tf:"product_id,omitempty"`
}

type BootstrapObservation struct {

	// ID of the property in the Identity and Access Management API.
	AssetID *string `json:"assetId,omitempty" tf:"asset_id,omitempty"`

	// Contract ID to be assigned to the Property
	ContractID *string `json:"contractId,omitempty" tf:"contract_id,omitempty"`

	// Group ID to be assigned to the Property
	GroupID *string `json:"groupId,omitempty" tf:"group_id,omitempty"`

	ID *string `json:"id,omitempty" tf:"id,omitempty"`

	// Name to give to the Property (must be unique)
	Name *string `json:"name,omitempty" tf:"name,omitempty"`

	// Product ID to be assigned to the Property
	ProductID *string `json:"productId,omitempty" tf:"product_id,omitempty"`
}

type BootstrapParameters struct {

	// Contract ID to be assigned to the Property
	// +kubebuilder:validation:Optional
	ContractID *string `json:"contractId,omitempty" tf:"contract_id,omitempty"`

	// Group ID to be assigned to the Property
	// +kubebuilder:validation:Optional
	GroupID *string `json:"groupId,omitempty" tf:"group_id,omitempty"`

	// Name to give to the Property (must be unique)
	// +kubebuilder:validation:Optional
	Name *string `json:"name,omitempty" tf:"name,omitempty"`

	// Product ID to be assigned to the Property
	// +kubebuilder:validation:Optional
	ProductID *string `json:"productId,omitempty" tf:"product_id,omitempty"`
}

// BootstrapSpec defines the desired state of Bootstrap
type BootstrapSpec struct {
	v1.ResourceSpec `json:",inline"`
	ForProvider     BootstrapParameters `json:"forProvider"`
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
	InitProvider BootstrapInitParameters `json:"initProvider,omitempty"`
}

// BootstrapStatus defines the observed state of Bootstrap.
type BootstrapStatus struct {
	v1.ResourceStatus `json:",inline"`
	AtProvider        BootstrapObservation `json:"atProvider,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:storageversion

// Bootstrap is the Schema for the Bootstraps API. <no value>
// +kubebuilder:printcolumn:name="SYNCED",type="string",JSONPath=".status.conditions[?(@.type=='Synced')].status"
// +kubebuilder:printcolumn:name="READY",type="string",JSONPath=".status.conditions[?(@.type=='Ready')].status"
// +kubebuilder:printcolumn:name="EXTERNAL-NAME",type="string",JSONPath=".metadata.annotations.crossplane\\.io/external-name"
// +kubebuilder:printcolumn:name="AGE",type="date",JSONPath=".metadata.creationTimestamp"
// +kubebuilder:resource:scope=Cluster,categories={crossplane,managed,akamai}
type Bootstrap struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`
	// +kubebuilder:validation:XValidation:rule="!('*' in self.managementPolicies || 'Create' in self.managementPolicies || 'Update' in self.managementPolicies) || has(self.forProvider.contractId) || (has(self.initProvider) && has(self.initProvider.contractId))",message="spec.forProvider.contractId is a required parameter"
	// +kubebuilder:validation:XValidation:rule="!('*' in self.managementPolicies || 'Create' in self.managementPolicies || 'Update' in self.managementPolicies) || has(self.forProvider.groupId) || (has(self.initProvider) && has(self.initProvider.groupId))",message="spec.forProvider.groupId is a required parameter"
	// +kubebuilder:validation:XValidation:rule="!('*' in self.managementPolicies || 'Create' in self.managementPolicies || 'Update' in self.managementPolicies) || has(self.forProvider.name) || (has(self.initProvider) && has(self.initProvider.name))",message="spec.forProvider.name is a required parameter"
	// +kubebuilder:validation:XValidation:rule="!('*' in self.managementPolicies || 'Create' in self.managementPolicies || 'Update' in self.managementPolicies) || has(self.forProvider.productId) || (has(self.initProvider) && has(self.initProvider.productId))",message="spec.forProvider.productId is a required parameter"
	Spec   BootstrapSpec   `json:"spec"`
	Status BootstrapStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// BootstrapList contains a list of Bootstraps
type BootstrapList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []Bootstrap `json:"items"`
}

// Repository type metadata.
var (
	Bootstrap_Kind             = "Bootstrap"
	Bootstrap_GroupKind        = schema.GroupKind{Group: CRDGroup, Kind: Bootstrap_Kind}.String()
	Bootstrap_KindAPIVersion   = Bootstrap_Kind + "." + CRDGroupVersion.String()
	Bootstrap_GroupVersionKind = CRDGroupVersion.WithKind(Bootstrap_Kind)
)

func init() {
	SchemeBuilder.Register(&Bootstrap{}, &BootstrapList{})
}
