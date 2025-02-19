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

type CustomCodeInitParameters struct {
	ConfigID *float64 `json:"configId,omitempty" tf:"config_id,omitempty"`

	CustomCode *string `json:"customCode,omitempty" tf:"custom_code,omitempty"`
}

type CustomCodeObservation struct {
	ConfigID *float64 `json:"configId,omitempty" tf:"config_id,omitempty"`

	CustomCode *string `json:"customCode,omitempty" tf:"custom_code,omitempty"`

	ID *string `json:"id,omitempty" tf:"id,omitempty"`
}

type CustomCodeParameters struct {

	// +kubebuilder:validation:Optional
	ConfigID *float64 `json:"configId,omitempty" tf:"config_id,omitempty"`

	// +kubebuilder:validation:Optional
	CustomCode *string `json:"customCode,omitempty" tf:"custom_code,omitempty"`
}

// CustomCodeSpec defines the desired state of CustomCode
type CustomCodeSpec struct {
	v1.ResourceSpec `json:",inline"`
	ForProvider     CustomCodeParameters `json:"forProvider"`
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
	InitProvider CustomCodeInitParameters `json:"initProvider,omitempty"`
}

// CustomCodeStatus defines the observed state of CustomCode.
type CustomCodeStatus struct {
	v1.ResourceStatus `json:",inline"`
	AtProvider        CustomCodeObservation `json:"atProvider,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:storageversion

// CustomCode is the Schema for the CustomCodes API. <no value>
// +kubebuilder:printcolumn:name="SYNCED",type="string",JSONPath=".status.conditions[?(@.type=='Synced')].status"
// +kubebuilder:printcolumn:name="READY",type="string",JSONPath=".status.conditions[?(@.type=='Ready')].status"
// +kubebuilder:printcolumn:name="EXTERNAL-NAME",type="string",JSONPath=".metadata.annotations.crossplane\\.io/external-name"
// +kubebuilder:printcolumn:name="AGE",type="date",JSONPath=".metadata.creationTimestamp"
// +kubebuilder:resource:scope=Cluster,categories={crossplane,managed,akamai}
type CustomCode struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`
	// +kubebuilder:validation:XValidation:rule="!('*' in self.managementPolicies || 'Create' in self.managementPolicies || 'Update' in self.managementPolicies) || has(self.forProvider.configId) || (has(self.initProvider) && has(self.initProvider.configId))",message="spec.forProvider.configId is a required parameter"
	// +kubebuilder:validation:XValidation:rule="!('*' in self.managementPolicies || 'Create' in self.managementPolicies || 'Update' in self.managementPolicies) || has(self.forProvider.customCode) || (has(self.initProvider) && has(self.initProvider.customCode))",message="spec.forProvider.customCode is a required parameter"
	Spec   CustomCodeSpec   `json:"spec"`
	Status CustomCodeStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// CustomCodeList contains a list of CustomCodes
type CustomCodeList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []CustomCode `json:"items"`
}

// Repository type metadata.
var (
	CustomCode_Kind             = "CustomCode"
	CustomCode_GroupKind        = schema.GroupKind{Group: CRDGroup, Kind: CustomCode_Kind}.String()
	CustomCode_KindAPIVersion   = CustomCode_Kind + "." + CRDGroupVersion.String()
	CustomCode_GroupVersionKind = CRDGroupVersion.WithKind(CustomCode_Kind)
)

func init() {
	SchemeBuilder.Register(&CustomCode{}, &CustomCodeList{})
}
