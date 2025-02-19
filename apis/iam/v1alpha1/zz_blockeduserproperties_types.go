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

type BlockedUserPropertiesInitParameters struct {

	// List of properties to block for a user.
	BlockedProperties []*float64 `json:"blockedProperties,omitempty" tf:"blocked_properties,omitempty"`

	// A unique identifier for a group.
	GroupID *float64 `json:"groupId,omitempty" tf:"group_id,omitempty"`

	// A unique identifier for a user's profile, which corresponds to a user's actual profile or client ID.
	IdentityID *string `json:"identityId,omitempty" tf:"identity_id,omitempty"`
}

type BlockedUserPropertiesObservation struct {

	// List of properties to block for a user.
	BlockedProperties []*float64 `json:"blockedProperties,omitempty" tf:"blocked_properties,omitempty"`

	// A unique identifier for a group.
	GroupID *float64 `json:"groupId,omitempty" tf:"group_id,omitempty"`

	ID *string `json:"id,omitempty" tf:"id,omitempty"`

	// A unique identifier for a user's profile, which corresponds to a user's actual profile or client ID.
	IdentityID *string `json:"identityId,omitempty" tf:"identity_id,omitempty"`
}

type BlockedUserPropertiesParameters struct {

	// List of properties to block for a user.
	// +kubebuilder:validation:Optional
	BlockedProperties []*float64 `json:"blockedProperties,omitempty" tf:"blocked_properties,omitempty"`

	// A unique identifier for a group.
	// +kubebuilder:validation:Optional
	GroupID *float64 `json:"groupId,omitempty" tf:"group_id,omitempty"`

	// A unique identifier for a user's profile, which corresponds to a user's actual profile or client ID.
	// +kubebuilder:validation:Optional
	IdentityID *string `json:"identityId,omitempty" tf:"identity_id,omitempty"`
}

// BlockedUserPropertiesSpec defines the desired state of BlockedUserProperties
type BlockedUserPropertiesSpec struct {
	v1.ResourceSpec `json:",inline"`
	ForProvider     BlockedUserPropertiesParameters `json:"forProvider"`
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
	InitProvider BlockedUserPropertiesInitParameters `json:"initProvider,omitempty"`
}

// BlockedUserPropertiesStatus defines the observed state of BlockedUserProperties.
type BlockedUserPropertiesStatus struct {
	v1.ResourceStatus `json:",inline"`
	AtProvider        BlockedUserPropertiesObservation `json:"atProvider,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:storageversion

// BlockedUserProperties is the Schema for the BlockedUserPropertiess API. <no value>
// +kubebuilder:printcolumn:name="SYNCED",type="string",JSONPath=".status.conditions[?(@.type=='Synced')].status"
// +kubebuilder:printcolumn:name="READY",type="string",JSONPath=".status.conditions[?(@.type=='Ready')].status"
// +kubebuilder:printcolumn:name="EXTERNAL-NAME",type="string",JSONPath=".metadata.annotations.crossplane\\.io/external-name"
// +kubebuilder:printcolumn:name="AGE",type="date",JSONPath=".metadata.creationTimestamp"
// +kubebuilder:resource:scope=Cluster,categories={crossplane,managed,akamai}
type BlockedUserProperties struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`
	// +kubebuilder:validation:XValidation:rule="!('*' in self.managementPolicies || 'Create' in self.managementPolicies || 'Update' in self.managementPolicies) || has(self.forProvider.blockedProperties) || (has(self.initProvider) && has(self.initProvider.blockedProperties))",message="spec.forProvider.blockedProperties is a required parameter"
	// +kubebuilder:validation:XValidation:rule="!('*' in self.managementPolicies || 'Create' in self.managementPolicies || 'Update' in self.managementPolicies) || has(self.forProvider.groupId) || (has(self.initProvider) && has(self.initProvider.groupId))",message="spec.forProvider.groupId is a required parameter"
	// +kubebuilder:validation:XValidation:rule="!('*' in self.managementPolicies || 'Create' in self.managementPolicies || 'Update' in self.managementPolicies) || has(self.forProvider.identityId) || (has(self.initProvider) && has(self.initProvider.identityId))",message="spec.forProvider.identityId is a required parameter"
	Spec   BlockedUserPropertiesSpec   `json:"spec"`
	Status BlockedUserPropertiesStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// BlockedUserPropertiesList contains a list of BlockedUserPropertiess
type BlockedUserPropertiesList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []BlockedUserProperties `json:"items"`
}

// Repository type metadata.
var (
	BlockedUserProperties_Kind             = "BlockedUserProperties"
	BlockedUserProperties_GroupKind        = schema.GroupKind{Group: CRDGroup, Kind: BlockedUserProperties_Kind}.String()
	BlockedUserProperties_KindAPIVersion   = BlockedUserProperties_Kind + "." + CRDGroupVersion.String()
	BlockedUserProperties_GroupVersionKind = CRDGroupVersion.WithKind(BlockedUserProperties_Kind)
)

func init() {
	SchemeBuilder.Register(&BlockedUserProperties{}, &BlockedUserPropertiesList{})
}
