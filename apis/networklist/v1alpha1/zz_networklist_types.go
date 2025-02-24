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

type NetworkListInitParameters struct {

	// contract ID
	ContractID *string `json:"contractId,omitempty" tf:"contract_id,omitempty"`

	// A description of the network list
	Description *string `json:"description,omitempty" tf:"description,omitempty"`

	// group ID
	GroupID *float64 `json:"groupId,omitempty" tf:"group_id,omitempty"`

	// A list of IP addresses or locations to be included in the list, added to an existing list, or removed from an existing list
	// +listType=set
	List []*string `json:"list,omitempty" tf:"list,omitempty"`

	// A string specifying the interpretation of the `list` parameter. Must be 'APPEND', 'REPLACE', or 'REMOVE'
	Mode *string `json:"mode,omitempty" tf:"mode,omitempty"`

	// The name to be assigned to the network list
	Name *string `json:"name,omitempty" tf:"name,omitempty"`

	// The type of the network list; must be either 'IP' or 'GEO'
	Type *string `json:"type,omitempty" tf:"type,omitempty"`
}

type NetworkListObservation struct {

	// contract ID
	ContractID *string `json:"contractId,omitempty" tf:"contract_id,omitempty"`

	// A description of the network list
	Description *string `json:"description,omitempty" tf:"description,omitempty"`

	// group ID
	GroupID *float64 `json:"groupId,omitempty" tf:"group_id,omitempty"`

	ID *string `json:"id,omitempty" tf:"id,omitempty"`

	// A list of IP addresses or locations to be included in the list, added to an existing list, or removed from an existing list
	// +listType=set
	List []*string `json:"list,omitempty" tf:"list,omitempty"`

	// A string specifying the interpretation of the `list` parameter. Must be 'APPEND', 'REPLACE', or 'REMOVE'
	Mode *string `json:"mode,omitempty" tf:"mode,omitempty"`

	// The name to be assigned to the network list
	Name *string `json:"name,omitempty" tf:"name,omitempty"`

	// network list ID
	NetworkListID *string `json:"networkListId,omitempty" tf:"network_list_id,omitempty"`

	// sync point
	SyncPoint *float64 `json:"syncPoint,omitempty" tf:"sync_point,omitempty"`

	// The type of the network list; must be either 'IP' or 'GEO'
	Type *string `json:"type,omitempty" tf:"type,omitempty"`

	// unique ID
	Uniqueid *string `json:"uniqueid,omitempty" tf:"uniqueid,omitempty"`
}

type NetworkListParameters struct {

	// contract ID
	// +kubebuilder:validation:Optional
	ContractID *string `json:"contractId,omitempty" tf:"contract_id,omitempty"`

	// A description of the network list
	// +kubebuilder:validation:Optional
	Description *string `json:"description,omitempty" tf:"description,omitempty"`

	// group ID
	// +kubebuilder:validation:Optional
	GroupID *float64 `json:"groupId,omitempty" tf:"group_id,omitempty"`

	// A list of IP addresses or locations to be included in the list, added to an existing list, or removed from an existing list
	// +kubebuilder:validation:Optional
	// +listType=set
	List []*string `json:"list,omitempty" tf:"list,omitempty"`

	// A string specifying the interpretation of the `list` parameter. Must be 'APPEND', 'REPLACE', or 'REMOVE'
	// +kubebuilder:validation:Optional
	Mode *string `json:"mode,omitempty" tf:"mode,omitempty"`

	// The name to be assigned to the network list
	// +kubebuilder:validation:Optional
	Name *string `json:"name,omitempty" tf:"name,omitempty"`

	// The type of the network list; must be either 'IP' or 'GEO'
	// +kubebuilder:validation:Optional
	Type *string `json:"type,omitempty" tf:"type,omitempty"`
}

// NetworkListSpec defines the desired state of NetworkList
type NetworkListSpec struct {
	v1.ResourceSpec `json:",inline"`
	ForProvider     NetworkListParameters `json:"forProvider"`
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
	InitProvider NetworkListInitParameters `json:"initProvider,omitempty"`
}

// NetworkListStatus defines the observed state of NetworkList.
type NetworkListStatus struct {
	v1.ResourceStatus `json:",inline"`
	AtProvider        NetworkListObservation `json:"atProvider,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:storageversion

// NetworkList is the Schema for the NetworkLists API. <no value>
// +kubebuilder:printcolumn:name="SYNCED",type="string",JSONPath=".status.conditions[?(@.type=='Synced')].status"
// +kubebuilder:printcolumn:name="READY",type="string",JSONPath=".status.conditions[?(@.type=='Ready')].status"
// +kubebuilder:printcolumn:name="EXTERNAL-NAME",type="string",JSONPath=".metadata.annotations.crossplane\\.io/external-name"
// +kubebuilder:printcolumn:name="AGE",type="date",JSONPath=".metadata.creationTimestamp"
// +kubebuilder:resource:scope=Cluster,categories={crossplane,managed,akamai}
type NetworkList struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`
	// +kubebuilder:validation:XValidation:rule="!('*' in self.managementPolicies || 'Create' in self.managementPolicies || 'Update' in self.managementPolicies) || has(self.forProvider.description) || (has(self.initProvider) && has(self.initProvider.description))",message="spec.forProvider.description is a required parameter"
	// +kubebuilder:validation:XValidation:rule="!('*' in self.managementPolicies || 'Create' in self.managementPolicies || 'Update' in self.managementPolicies) || has(self.forProvider.mode) || (has(self.initProvider) && has(self.initProvider.mode))",message="spec.forProvider.mode is a required parameter"
	// +kubebuilder:validation:XValidation:rule="!('*' in self.managementPolicies || 'Create' in self.managementPolicies || 'Update' in self.managementPolicies) || has(self.forProvider.name) || (has(self.initProvider) && has(self.initProvider.name))",message="spec.forProvider.name is a required parameter"
	// +kubebuilder:validation:XValidation:rule="!('*' in self.managementPolicies || 'Create' in self.managementPolicies || 'Update' in self.managementPolicies) || has(self.forProvider.type) || (has(self.initProvider) && has(self.initProvider.type))",message="spec.forProvider.type is a required parameter"
	Spec   NetworkListSpec   `json:"spec"`
	Status NetworkListStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// NetworkListList contains a list of NetworkLists
type NetworkListList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []NetworkList `json:"items"`
}

// Repository type metadata.
var (
	NetworkList_Kind             = "NetworkList"
	NetworkList_GroupKind        = schema.GroupKind{Group: CRDGroup, Kind: NetworkList_Kind}.String()
	NetworkList_KindAPIVersion   = NetworkList_Kind + "." + CRDGroupVersion.String()
	NetworkList_GroupVersionKind = CRDGroupVersion.WithKind(NetworkList_Kind)
)

func init() {
	SchemeBuilder.Register(&NetworkList{}, &NetworkListList{})
}
