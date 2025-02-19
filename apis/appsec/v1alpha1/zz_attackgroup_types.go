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

type AttackGroupInitParameters struct {

	// Unique name of the attack group to be modified
	AttackGroup *string `json:"attackGroup,omitempty" tf:"attack_group,omitempty"`

	// Action to be taken when the attack group is triggered
	AttackGroupAction *string `json:"attackGroupAction,omitempty" tf:"attack_group_action,omitempty"`

	// JSON-formatted condition and exception information for the attack group
	ConditionException *string `json:"conditionException,omitempty" tf:"condition_exception,omitempty"`

	// Unique identifier of the security configuration
	ConfigID *float64 `json:"configId,omitempty" tf:"config_id,omitempty"`

	// Unique identifier of the security policy
	SecurityPolicyID *string `json:"securityPolicyId,omitempty" tf:"security_policy_id,omitempty"`
}

type AttackGroupObservation struct {

	// Unique name of the attack group to be modified
	AttackGroup *string `json:"attackGroup,omitempty" tf:"attack_group,omitempty"`

	// Action to be taken when the attack group is triggered
	AttackGroupAction *string `json:"attackGroupAction,omitempty" tf:"attack_group_action,omitempty"`

	// JSON-formatted condition and exception information for the attack group
	ConditionException *string `json:"conditionException,omitempty" tf:"condition_exception,omitempty"`

	// Unique identifier of the security configuration
	ConfigID *float64 `json:"configId,omitempty" tf:"config_id,omitempty"`

	ID *string `json:"id,omitempty" tf:"id,omitempty"`

	// Unique identifier of the security policy
	SecurityPolicyID *string `json:"securityPolicyId,omitempty" tf:"security_policy_id,omitempty"`
}

type AttackGroupParameters struct {

	// Unique name of the attack group to be modified
	// +kubebuilder:validation:Optional
	AttackGroup *string `json:"attackGroup,omitempty" tf:"attack_group,omitempty"`

	// Action to be taken when the attack group is triggered
	// +kubebuilder:validation:Optional
	AttackGroupAction *string `json:"attackGroupAction,omitempty" tf:"attack_group_action,omitempty"`

	// JSON-formatted condition and exception information for the attack group
	// +kubebuilder:validation:Optional
	ConditionException *string `json:"conditionException,omitempty" tf:"condition_exception,omitempty"`

	// Unique identifier of the security configuration
	// +kubebuilder:validation:Optional
	ConfigID *float64 `json:"configId,omitempty" tf:"config_id,omitempty"`

	// Unique identifier of the security policy
	// +kubebuilder:validation:Optional
	SecurityPolicyID *string `json:"securityPolicyId,omitempty" tf:"security_policy_id,omitempty"`
}

// AttackGroupSpec defines the desired state of AttackGroup
type AttackGroupSpec struct {
	v1.ResourceSpec `json:",inline"`
	ForProvider     AttackGroupParameters `json:"forProvider"`
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
	InitProvider AttackGroupInitParameters `json:"initProvider,omitempty"`
}

// AttackGroupStatus defines the observed state of AttackGroup.
type AttackGroupStatus struct {
	v1.ResourceStatus `json:",inline"`
	AtProvider        AttackGroupObservation `json:"atProvider,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:storageversion

// AttackGroup is the Schema for the AttackGroups API. <no value>
// +kubebuilder:printcolumn:name="SYNCED",type="string",JSONPath=".status.conditions[?(@.type=='Synced')].status"
// +kubebuilder:printcolumn:name="READY",type="string",JSONPath=".status.conditions[?(@.type=='Ready')].status"
// +kubebuilder:printcolumn:name="EXTERNAL-NAME",type="string",JSONPath=".metadata.annotations.crossplane\\.io/external-name"
// +kubebuilder:printcolumn:name="AGE",type="date",JSONPath=".metadata.creationTimestamp"
// +kubebuilder:resource:scope=Cluster,categories={crossplane,managed,akamai}
type AttackGroup struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`
	// +kubebuilder:validation:XValidation:rule="!('*' in self.managementPolicies || 'Create' in self.managementPolicies || 'Update' in self.managementPolicies) || has(self.forProvider.attackGroup) || (has(self.initProvider) && has(self.initProvider.attackGroup))",message="spec.forProvider.attackGroup is a required parameter"
	// +kubebuilder:validation:XValidation:rule="!('*' in self.managementPolicies || 'Create' in self.managementPolicies || 'Update' in self.managementPolicies) || has(self.forProvider.attackGroupAction) || (has(self.initProvider) && has(self.initProvider.attackGroupAction))",message="spec.forProvider.attackGroupAction is a required parameter"
	// +kubebuilder:validation:XValidation:rule="!('*' in self.managementPolicies || 'Create' in self.managementPolicies || 'Update' in self.managementPolicies) || has(self.forProvider.configId) || (has(self.initProvider) && has(self.initProvider.configId))",message="spec.forProvider.configId is a required parameter"
	// +kubebuilder:validation:XValidation:rule="!('*' in self.managementPolicies || 'Create' in self.managementPolicies || 'Update' in self.managementPolicies) || has(self.forProvider.securityPolicyId) || (has(self.initProvider) && has(self.initProvider.securityPolicyId))",message="spec.forProvider.securityPolicyId is a required parameter"
	Spec   AttackGroupSpec   `json:"spec"`
	Status AttackGroupStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// AttackGroupList contains a list of AttackGroups
type AttackGroupList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []AttackGroup `json:"items"`
}

// Repository type metadata.
var (
	AttackGroup_Kind             = "AttackGroup"
	AttackGroup_GroupKind        = schema.GroupKind{Group: CRDGroup, Kind: AttackGroup_Kind}.String()
	AttackGroup_KindAPIVersion   = AttackGroup_Kind + "." + CRDGroupVersion.String()
	AttackGroup_GroupVersionKind = CRDGroupVersion.WithKind(AttackGroup_Kind)
)

func init() {
	SchemeBuilder.Register(&AttackGroup{}, &AttackGroupList{})
}
