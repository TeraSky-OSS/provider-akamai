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

	// Unique identifier of the security configuration to be activated
	ConfigID *float64 `json:"configId,omitempty" tf:"config_id,omitempty"`

	// Network on which to activate the configuration version (STAGING or PRODUCTION)
	Network *string `json:"network,omitempty" tf:"network,omitempty"`

	// Note describing the activation. Will use timestamp if omitted.
	Note *string `json:"note,omitempty" tf:"note,omitempty"`

	// List of email addresses to be notified with the results of the activation
	// +listType=set
	NotificationEmails []*string `json:"notificationEmails,omitempty" tf:"notification_emails,omitempty"`

	// Version of the security configuration to be activated
	Version *float64 `json:"version,omitempty" tf:"version,omitempty"`
}

type ActivationsObservation struct {

	// Unique identifier of the security configuration to be activated
	ConfigID *float64 `json:"configId,omitempty" tf:"config_id,omitempty"`

	ID *string `json:"id,omitempty" tf:"id,omitempty"`

	// Network on which to activate the configuration version (STAGING or PRODUCTION)
	Network *string `json:"network,omitempty" tf:"network,omitempty"`

	// Note describing the activation. Will use timestamp if omitted.
	Note *string `json:"note,omitempty" tf:"note,omitempty"`

	// List of email addresses to be notified with the results of the activation
	// +listType=set
	NotificationEmails []*string `json:"notificationEmails,omitempty" tf:"notification_emails,omitempty"`

	// The results of the activation
	Status *string `json:"status,omitempty" tf:"status,omitempty"`

	// Version of the security configuration to be activated
	Version *float64 `json:"version,omitempty" tf:"version,omitempty"`
}

type ActivationsParameters struct {

	// Unique identifier of the security configuration to be activated
	// +kubebuilder:validation:Optional
	ConfigID *float64 `json:"configId,omitempty" tf:"config_id,omitempty"`

	// Network on which to activate the configuration version (STAGING or PRODUCTION)
	// +kubebuilder:validation:Optional
	Network *string `json:"network,omitempty" tf:"network,omitempty"`

	// Note describing the activation. Will use timestamp if omitted.
	// +kubebuilder:validation:Optional
	Note *string `json:"note,omitempty" tf:"note,omitempty"`

	// List of email addresses to be notified with the results of the activation
	// +kubebuilder:validation:Optional
	// +listType=set
	NotificationEmails []*string `json:"notificationEmails,omitempty" tf:"notification_emails,omitempty"`

	// Version of the security configuration to be activated
	// +kubebuilder:validation:Optional
	Version *float64 `json:"version,omitempty" tf:"version,omitempty"`
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
	// +kubebuilder:validation:XValidation:rule="!('*' in self.managementPolicies || 'Create' in self.managementPolicies || 'Update' in self.managementPolicies) || has(self.forProvider.configId) || (has(self.initProvider) && has(self.initProvider.configId))",message="spec.forProvider.configId is a required parameter"
	// +kubebuilder:validation:XValidation:rule="!('*' in self.managementPolicies || 'Create' in self.managementPolicies || 'Update' in self.managementPolicies) || has(self.forProvider.notificationEmails) || (has(self.initProvider) && has(self.initProvider.notificationEmails))",message="spec.forProvider.notificationEmails is a required parameter"
	// +kubebuilder:validation:XValidation:rule="!('*' in self.managementPolicies || 'Create' in self.managementPolicies || 'Update' in self.managementPolicies) || has(self.forProvider.version) || (has(self.initProvider) && has(self.initProvider.version))",message="spec.forProvider.version is a required parameter"
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
