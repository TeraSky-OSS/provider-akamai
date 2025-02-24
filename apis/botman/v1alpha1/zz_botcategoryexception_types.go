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

type BotCategoryExceptionInitParameters struct {
	BotCategoryException *string `json:"botCategoryException,omitempty" tf:"bot_category_exception,omitempty"`

	ConfigID *float64 `json:"configId,omitempty" tf:"config_id,omitempty"`

	SecurityPolicyID *string `json:"securityPolicyId,omitempty" tf:"security_policy_id,omitempty"`
}

type BotCategoryExceptionObservation struct {
	BotCategoryException *string `json:"botCategoryException,omitempty" tf:"bot_category_exception,omitempty"`

	ConfigID *float64 `json:"configId,omitempty" tf:"config_id,omitempty"`

	ID *string `json:"id,omitempty" tf:"id,omitempty"`

	SecurityPolicyID *string `json:"securityPolicyId,omitempty" tf:"security_policy_id,omitempty"`
}

type BotCategoryExceptionParameters struct {

	// +kubebuilder:validation:Optional
	BotCategoryException *string `json:"botCategoryException,omitempty" tf:"bot_category_exception,omitempty"`

	// +kubebuilder:validation:Optional
	ConfigID *float64 `json:"configId,omitempty" tf:"config_id,omitempty"`

	// +kubebuilder:validation:Optional
	SecurityPolicyID *string `json:"securityPolicyId,omitempty" tf:"security_policy_id,omitempty"`
}

// BotCategoryExceptionSpec defines the desired state of BotCategoryException
type BotCategoryExceptionSpec struct {
	v1.ResourceSpec `json:",inline"`
	ForProvider     BotCategoryExceptionParameters `json:"forProvider"`
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
	InitProvider BotCategoryExceptionInitParameters `json:"initProvider,omitempty"`
}

// BotCategoryExceptionStatus defines the observed state of BotCategoryException.
type BotCategoryExceptionStatus struct {
	v1.ResourceStatus `json:",inline"`
	AtProvider        BotCategoryExceptionObservation `json:"atProvider,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:storageversion

// BotCategoryException is the Schema for the BotCategoryExceptions API. <no value>
// +kubebuilder:printcolumn:name="SYNCED",type="string",JSONPath=".status.conditions[?(@.type=='Synced')].status"
// +kubebuilder:printcolumn:name="READY",type="string",JSONPath=".status.conditions[?(@.type=='Ready')].status"
// +kubebuilder:printcolumn:name="EXTERNAL-NAME",type="string",JSONPath=".metadata.annotations.crossplane\\.io/external-name"
// +kubebuilder:printcolumn:name="AGE",type="date",JSONPath=".metadata.creationTimestamp"
// +kubebuilder:resource:scope=Cluster,categories={crossplane,managed,akamai}
type BotCategoryException struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`
	// +kubebuilder:validation:XValidation:rule="!('*' in self.managementPolicies || 'Create' in self.managementPolicies || 'Update' in self.managementPolicies) || has(self.forProvider.botCategoryException) || (has(self.initProvider) && has(self.initProvider.botCategoryException))",message="spec.forProvider.botCategoryException is a required parameter"
	// +kubebuilder:validation:XValidation:rule="!('*' in self.managementPolicies || 'Create' in self.managementPolicies || 'Update' in self.managementPolicies) || has(self.forProvider.configId) || (has(self.initProvider) && has(self.initProvider.configId))",message="spec.forProvider.configId is a required parameter"
	// +kubebuilder:validation:XValidation:rule="!('*' in self.managementPolicies || 'Create' in self.managementPolicies || 'Update' in self.managementPolicies) || has(self.forProvider.securityPolicyId) || (has(self.initProvider) && has(self.initProvider.securityPolicyId))",message="spec.forProvider.securityPolicyId is a required parameter"
	Spec   BotCategoryExceptionSpec   `json:"spec"`
	Status BotCategoryExceptionStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// BotCategoryExceptionList contains a list of BotCategoryExceptions
type BotCategoryExceptionList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []BotCategoryException `json:"items"`
}

// Repository type metadata.
var (
	BotCategoryException_Kind             = "BotCategoryException"
	BotCategoryException_GroupKind        = schema.GroupKind{Group: CRDGroup, Kind: BotCategoryException_Kind}.String()
	BotCategoryException_KindAPIVersion   = BotCategoryException_Kind + "." + CRDGroupVersion.String()
	BotCategoryException_GroupVersionKind = CRDGroupVersion.WithKind(BotCategoryException_Kind)
)

func init() {
	SchemeBuilder.Register(&BotCategoryException{}, &BotCategoryExceptionList{})
}
