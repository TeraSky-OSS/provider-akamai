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

type ActivationsInitParameters struct {

	// The Akamai network on which the list is activated: STAGING or PRODUCTION
	Network *string `json:"network,omitempty" tf:"network,omitempty"`

	// Unique identifier of the network list
	NetworkListID *string `json:"networkListId,omitempty" tf:"network_list_id,omitempty"`

	// Descriptive text to accompany the activation
	Notes *string `json:"notes,omitempty" tf:"notes,omitempty"`

	// List of email addresses of Control Center users who receive an email when activation of this list is complete
	// +listType=set
	NotificationEmails []*string `json:"notificationEmails,omitempty" tf:"notification_emails,omitempty"`

	// Identifies the sync point of the network list to be activated
	SyncPoint *float64 `json:"syncPoint,omitempty" tf:"sync_point,omitempty"`
}

type ActivationsObservation struct {
	ID *string `json:"id,omitempty" tf:"id,omitempty"`

	// The Akamai network on which the list is activated: STAGING or PRODUCTION
	Network *string `json:"network,omitempty" tf:"network,omitempty"`

	// Unique identifier of the network list
	NetworkListID *string `json:"networkListId,omitempty" tf:"network_list_id,omitempty"`

	// Descriptive text to accompany the activation
	Notes *string `json:"notes,omitempty" tf:"notes,omitempty"`

	// List of email addresses of Control Center users who receive an email when activation of this list is complete
	// +listType=set
	NotificationEmails []*string `json:"notificationEmails,omitempty" tf:"notification_emails,omitempty"`

	// This network list's current activation status in the environment specified by the "network" attribute
	Status *string `json:"status,omitempty" tf:"status,omitempty"`

	// Identifies the sync point of the network list to be activated
	SyncPoint *float64 `json:"syncPoint,omitempty" tf:"sync_point,omitempty"`
}

type ActivationsParameters struct {

	// The Akamai network on which the list is activated: STAGING or PRODUCTION
	// +kubebuilder:validation:Optional
	Network *string `json:"network,omitempty" tf:"network,omitempty"`

	// Unique identifier of the network list
	// +kubebuilder:validation:Optional
	NetworkListID *string `json:"networkListId,omitempty" tf:"network_list_id,omitempty"`

	// Descriptive text to accompany the activation
	// +kubebuilder:validation:Optional
	Notes *string `json:"notes,omitempty" tf:"notes,omitempty"`

	// List of email addresses of Control Center users who receive an email when activation of this list is complete
	// +kubebuilder:validation:Optional
	// +listType=set
	NotificationEmails []*string `json:"notificationEmails,omitempty" tf:"notification_emails,omitempty"`

	// Identifies the sync point of the network list to be activated
	// +kubebuilder:validation:Optional
	SyncPoint *float64 `json:"syncPoint,omitempty" tf:"sync_point,omitempty"`
}

// ActivationsSpec defines the desired state of Activations
type ActivationsSpec struct {
	v1.ResourceSpec `json:",inline"`
	ForProvider     ActivationsParameters `json:"forProvider"`
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
	InitProvider ActivationsInitParameters `json:"initProvider,omitempty"`
}

// ActivationsStatus defines the observed state of Activations.
type ActivationsStatus struct {
	v1.ResourceStatus `json:",inline"`
	AtProvider        ActivationsObservation `json:"atProvider,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:storageversion

// Activations is the Schema for the Activationss API. <no value>
// +kubebuilder:printcolumn:name="SYNCED",type="string",JSONPath=".status.conditions[?(@.type=='Synced')].status"
// +kubebuilder:printcolumn:name="READY",type="string",JSONPath=".status.conditions[?(@.type=='Ready')].status"
// +kubebuilder:printcolumn:name="EXTERNAL-NAME",type="string",JSONPath=".metadata.annotations.crossplane\\.io/external-name"
// +kubebuilder:printcolumn:name="AGE",type="date",JSONPath=".metadata.creationTimestamp"
// +kubebuilder:resource:scope=Cluster,categories={crossplane,managed,akamai}
type Activations struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`
	// +kubebuilder:validation:XValidation:rule="!('*' in self.managementPolicies || 'Create' in self.managementPolicies || 'Update' in self.managementPolicies) || has(self.forProvider.networkListId) || (has(self.initProvider) && has(self.initProvider.networkListId))",message="spec.forProvider.networkListId is a required parameter"
	// +kubebuilder:validation:XValidation:rule="!('*' in self.managementPolicies || 'Create' in self.managementPolicies || 'Update' in self.managementPolicies) || has(self.forProvider.notificationEmails) || (has(self.initProvider) && has(self.initProvider.notificationEmails))",message="spec.forProvider.notificationEmails is a required parameter"
	// +kubebuilder:validation:XValidation:rule="!('*' in self.managementPolicies || 'Create' in self.managementPolicies || 'Update' in self.managementPolicies) || has(self.forProvider.syncPoint) || (has(self.initProvider) && has(self.initProvider.syncPoint))",message="spec.forProvider.syncPoint is a required parameter"
	Spec   ActivationsSpec   `json:"spec"`
	Status ActivationsStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// ActivationsList contains a list of Activationss
type ActivationsList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []Activations `json:"items"`
}

// Repository type metadata.
var (
	Activations_Kind             = "Activations"
	Activations_GroupKind        = schema.GroupKind{Group: CRDGroup, Kind: Activations_Kind}.String()
	Activations_KindAPIVersion   = Activations_Kind + "." + CRDGroupVersion.String()
	Activations_GroupVersionKind = CRDGroupVersion.WithKind(Activations_Kind)
)

func init() {
	SchemeBuilder.Register(&Activations{}, &ActivationsList{})
}
