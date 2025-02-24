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

type EvalPenaltyBoxConditionsInitParameters struct {

	// Unique identifier of the security configuration
	ConfigID *float64 `json:"configId,omitempty" tf:"config_id,omitempty"`

	// Description of evaluation penalty box conditions
	PenaltyBoxConditions *string `json:"penaltyBoxConditions,omitempty" tf:"penalty_box_conditions,omitempty"`

	// Unique identifier of the security policy
	SecurityPolicyID *string `json:"securityPolicyId,omitempty" tf:"security_policy_id,omitempty"`
}

type EvalPenaltyBoxConditionsObservation struct {

	// Unique identifier of the security configuration
	ConfigID *float64 `json:"configId,omitempty" tf:"config_id,omitempty"`

	ID *string `json:"id,omitempty" tf:"id,omitempty"`

	// Description of evaluation penalty box conditions
	PenaltyBoxConditions *string `json:"penaltyBoxConditions,omitempty" tf:"penalty_box_conditions,omitempty"`

	// Unique identifier of the security policy
	SecurityPolicyID *string `json:"securityPolicyId,omitempty" tf:"security_policy_id,omitempty"`
}

type EvalPenaltyBoxConditionsParameters struct {

	// Unique identifier of the security configuration
	// +kubebuilder:validation:Optional
	ConfigID *float64 `json:"configId,omitempty" tf:"config_id,omitempty"`

	// Description of evaluation penalty box conditions
	// +kubebuilder:validation:Optional
	PenaltyBoxConditions *string `json:"penaltyBoxConditions,omitempty" tf:"penalty_box_conditions,omitempty"`

	// Unique identifier of the security policy
	// +kubebuilder:validation:Optional
	SecurityPolicyID *string `json:"securityPolicyId,omitempty" tf:"security_policy_id,omitempty"`
}

// EvalPenaltyBoxConditionsSpec defines the desired state of EvalPenaltyBoxConditions
type EvalPenaltyBoxConditionsSpec struct {
	v1.ResourceSpec `json:",inline"`
	ForProvider     EvalPenaltyBoxConditionsParameters `json:"forProvider"`
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
	InitProvider EvalPenaltyBoxConditionsInitParameters `json:"initProvider,omitempty"`
}

// EvalPenaltyBoxConditionsStatus defines the observed state of EvalPenaltyBoxConditions.
type EvalPenaltyBoxConditionsStatus struct {
	v1.ResourceStatus `json:",inline"`
	AtProvider        EvalPenaltyBoxConditionsObservation `json:"atProvider,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:storageversion

// EvalPenaltyBoxConditions is the Schema for the EvalPenaltyBoxConditionss API. <no value>
// +kubebuilder:printcolumn:name="SYNCED",type="string",JSONPath=".status.conditions[?(@.type=='Synced')].status"
// +kubebuilder:printcolumn:name="READY",type="string",JSONPath=".status.conditions[?(@.type=='Ready')].status"
// +kubebuilder:printcolumn:name="EXTERNAL-NAME",type="string",JSONPath=".metadata.annotations.crossplane\\.io/external-name"
// +kubebuilder:printcolumn:name="AGE",type="date",JSONPath=".metadata.creationTimestamp"
// +kubebuilder:resource:scope=Cluster,categories={crossplane,managed,akamai}
type EvalPenaltyBoxConditions struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`
	// +kubebuilder:validation:XValidation:rule="!('*' in self.managementPolicies || 'Create' in self.managementPolicies || 'Update' in self.managementPolicies) || has(self.forProvider.configId) || (has(self.initProvider) && has(self.initProvider.configId))",message="spec.forProvider.configId is a required parameter"
	// +kubebuilder:validation:XValidation:rule="!('*' in self.managementPolicies || 'Create' in self.managementPolicies || 'Update' in self.managementPolicies) || has(self.forProvider.penaltyBoxConditions) || (has(self.initProvider) && has(self.initProvider.penaltyBoxConditions))",message="spec.forProvider.penaltyBoxConditions is a required parameter"
	// +kubebuilder:validation:XValidation:rule="!('*' in self.managementPolicies || 'Create' in self.managementPolicies || 'Update' in self.managementPolicies) || has(self.forProvider.securityPolicyId) || (has(self.initProvider) && has(self.initProvider.securityPolicyId))",message="spec.forProvider.securityPolicyId is a required parameter"
	Spec   EvalPenaltyBoxConditionsSpec   `json:"spec"`
	Status EvalPenaltyBoxConditionsStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// EvalPenaltyBoxConditionsList contains a list of EvalPenaltyBoxConditionss
type EvalPenaltyBoxConditionsList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []EvalPenaltyBoxConditions `json:"items"`
}

// Repository type metadata.
var (
	EvalPenaltyBoxConditions_Kind             = "EvalPenaltyBoxConditions"
	EvalPenaltyBoxConditions_GroupKind        = schema.GroupKind{Group: CRDGroup, Kind: EvalPenaltyBoxConditions_Kind}.String()
	EvalPenaltyBoxConditions_KindAPIVersion   = EvalPenaltyBoxConditions_Kind + "." + CRDGroupVersion.String()
	EvalPenaltyBoxConditions_GroupVersionKind = CRDGroupVersion.WithKind(EvalPenaltyBoxConditions_Kind)
)

func init() {
	SchemeBuilder.Register(&EvalPenaltyBoxConditions{}, &EvalPenaltyBoxConditionsList{})
}
