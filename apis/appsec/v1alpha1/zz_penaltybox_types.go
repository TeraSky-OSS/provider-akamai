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

type PenaltyBoxInitParameters struct {

	// Unique identifier of the security configuration
	ConfigID *float64 `json:"configId,omitempty" tf:"config_id,omitempty"`

	// The action to be taken when the penalty box is triggered
	PenaltyBoxAction *string `json:"penaltyBoxAction,omitempty" tf:"penalty_box_action,omitempty"`

	// Whether to enable the penalty box for the specified security policy
	PenaltyBoxProtection *bool `json:"penaltyBoxProtection,omitempty" tf:"penalty_box_protection,omitempty"`

	// Unique identifier of the security policy
	SecurityPolicyID *string `json:"securityPolicyId,omitempty" tf:"security_policy_id,omitempty"`
}

type PenaltyBoxObservation struct {

	// Unique identifier of the security configuration
	ConfigID *float64 `json:"configId,omitempty" tf:"config_id,omitempty"`

	ID *string `json:"id,omitempty" tf:"id,omitempty"`

	// The action to be taken when the penalty box is triggered
	PenaltyBoxAction *string `json:"penaltyBoxAction,omitempty" tf:"penalty_box_action,omitempty"`

	// Whether to enable the penalty box for the specified security policy
	PenaltyBoxProtection *bool `json:"penaltyBoxProtection,omitempty" tf:"penalty_box_protection,omitempty"`

	// Unique identifier of the security policy
	SecurityPolicyID *string `json:"securityPolicyId,omitempty" tf:"security_policy_id,omitempty"`
}

type PenaltyBoxParameters struct {

	// Unique identifier of the security configuration
	// +kubebuilder:validation:Optional
	ConfigID *float64 `json:"configId,omitempty" tf:"config_id,omitempty"`

	// The action to be taken when the penalty box is triggered
	// +kubebuilder:validation:Optional
	PenaltyBoxAction *string `json:"penaltyBoxAction,omitempty" tf:"penalty_box_action,omitempty"`

	// Whether to enable the penalty box for the specified security policy
	// +kubebuilder:validation:Optional
	PenaltyBoxProtection *bool `json:"penaltyBoxProtection,omitempty" tf:"penalty_box_protection,omitempty"`

	// Unique identifier of the security policy
	// +kubebuilder:validation:Optional
	SecurityPolicyID *string `json:"securityPolicyId,omitempty" tf:"security_policy_id,omitempty"`
}

// PenaltyBoxSpec defines the desired state of PenaltyBox
type PenaltyBoxSpec struct {
	v1.ResourceSpec `json:",inline"`
	ForProvider     PenaltyBoxParameters `json:"forProvider"`
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
	InitProvider PenaltyBoxInitParameters `json:"initProvider,omitempty"`
}

// PenaltyBoxStatus defines the observed state of PenaltyBox.
type PenaltyBoxStatus struct {
	v1.ResourceStatus `json:",inline"`
	AtProvider        PenaltyBoxObservation `json:"atProvider,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:storageversion

// PenaltyBox is the Schema for the PenaltyBoxs API. <no value>
// +kubebuilder:printcolumn:name="SYNCED",type="string",JSONPath=".status.conditions[?(@.type=='Synced')].status"
// +kubebuilder:printcolumn:name="READY",type="string",JSONPath=".status.conditions[?(@.type=='Ready')].status"
// +kubebuilder:printcolumn:name="EXTERNAL-NAME",type="string",JSONPath=".metadata.annotations.crossplane\\.io/external-name"
// +kubebuilder:printcolumn:name="AGE",type="date",JSONPath=".metadata.creationTimestamp"
// +kubebuilder:resource:scope=Cluster,categories={crossplane,managed,akamai}
type PenaltyBox struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`
	// +kubebuilder:validation:XValidation:rule="!('*' in self.managementPolicies || 'Create' in self.managementPolicies || 'Update' in self.managementPolicies) || has(self.forProvider.configId) || (has(self.initProvider) && has(self.initProvider.configId))",message="spec.forProvider.configId is a required parameter"
	// +kubebuilder:validation:XValidation:rule="!('*' in self.managementPolicies || 'Create' in self.managementPolicies || 'Update' in self.managementPolicies) || has(self.forProvider.penaltyBoxAction) || (has(self.initProvider) && has(self.initProvider.penaltyBoxAction))",message="spec.forProvider.penaltyBoxAction is a required parameter"
	// +kubebuilder:validation:XValidation:rule="!('*' in self.managementPolicies || 'Create' in self.managementPolicies || 'Update' in self.managementPolicies) || has(self.forProvider.penaltyBoxProtection) || (has(self.initProvider) && has(self.initProvider.penaltyBoxProtection))",message="spec.forProvider.penaltyBoxProtection is a required parameter"
	// +kubebuilder:validation:XValidation:rule="!('*' in self.managementPolicies || 'Create' in self.managementPolicies || 'Update' in self.managementPolicies) || has(self.forProvider.securityPolicyId) || (has(self.initProvider) && has(self.initProvider.securityPolicyId))",message="spec.forProvider.securityPolicyId is a required parameter"
	Spec   PenaltyBoxSpec   `json:"spec"`
	Status PenaltyBoxStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// PenaltyBoxList contains a list of PenaltyBoxs
type PenaltyBoxList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []PenaltyBox `json:"items"`
}

// Repository type metadata.
var (
	PenaltyBox_Kind             = "PenaltyBox"
	PenaltyBox_GroupKind        = schema.GroupKind{Group: CRDGroup, Kind: PenaltyBox_Kind}.String()
	PenaltyBox_KindAPIVersion   = PenaltyBox_Kind + "." + CRDGroupVersion.String()
	PenaltyBox_GroupVersionKind = CRDGroupVersion.WithKind(PenaltyBox_Kind)
)

func init() {
	SchemeBuilder.Register(&PenaltyBox{}, &PenaltyBoxList{})
}
