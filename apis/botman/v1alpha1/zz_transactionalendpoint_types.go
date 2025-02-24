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

type TransactionalEndpointInitParameters struct {
	ConfigID *float64 `json:"configId,omitempty" tf:"config_id,omitempty"`

	OperationID *string `json:"operationId,omitempty" tf:"operation_id,omitempty"`

	SecurityPolicyID *string `json:"securityPolicyId,omitempty" tf:"security_policy_id,omitempty"`

	TransactionalEndpoint *string `json:"transactionalEndpoint,omitempty" tf:"transactional_endpoint,omitempty"`
}

type TransactionalEndpointObservation struct {
	ConfigID *float64 `json:"configId,omitempty" tf:"config_id,omitempty"`

	ID *string `json:"id,omitempty" tf:"id,omitempty"`

	OperationID *string `json:"operationId,omitempty" tf:"operation_id,omitempty"`

	SecurityPolicyID *string `json:"securityPolicyId,omitempty" tf:"security_policy_id,omitempty"`

	TransactionalEndpoint *string `json:"transactionalEndpoint,omitempty" tf:"transactional_endpoint,omitempty"`
}

type TransactionalEndpointParameters struct {

	// +kubebuilder:validation:Optional
	ConfigID *float64 `json:"configId,omitempty" tf:"config_id,omitempty"`

	// +kubebuilder:validation:Optional
	OperationID *string `json:"operationId,omitempty" tf:"operation_id,omitempty"`

	// +kubebuilder:validation:Optional
	SecurityPolicyID *string `json:"securityPolicyId,omitempty" tf:"security_policy_id,omitempty"`

	// +kubebuilder:validation:Optional
	TransactionalEndpoint *string `json:"transactionalEndpoint,omitempty" tf:"transactional_endpoint,omitempty"`
}

// TransactionalEndpointSpec defines the desired state of TransactionalEndpoint
type TransactionalEndpointSpec struct {
	v1.ResourceSpec `json:",inline"`
	ForProvider     TransactionalEndpointParameters `json:"forProvider"`
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
	InitProvider TransactionalEndpointInitParameters `json:"initProvider,omitempty"`
}

// TransactionalEndpointStatus defines the observed state of TransactionalEndpoint.
type TransactionalEndpointStatus struct {
	v1.ResourceStatus `json:",inline"`
	AtProvider        TransactionalEndpointObservation `json:"atProvider,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:storageversion

// TransactionalEndpoint is the Schema for the TransactionalEndpoints API. <no value>
// +kubebuilder:printcolumn:name="SYNCED",type="string",JSONPath=".status.conditions[?(@.type=='Synced')].status"
// +kubebuilder:printcolumn:name="READY",type="string",JSONPath=".status.conditions[?(@.type=='Ready')].status"
// +kubebuilder:printcolumn:name="EXTERNAL-NAME",type="string",JSONPath=".metadata.annotations.crossplane\\.io/external-name"
// +kubebuilder:printcolumn:name="AGE",type="date",JSONPath=".metadata.creationTimestamp"
// +kubebuilder:resource:scope=Cluster,categories={crossplane,managed,akamai}
type TransactionalEndpoint struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`
	// +kubebuilder:validation:XValidation:rule="!('*' in self.managementPolicies || 'Create' in self.managementPolicies || 'Update' in self.managementPolicies) || has(self.forProvider.configId) || (has(self.initProvider) && has(self.initProvider.configId))",message="spec.forProvider.configId is a required parameter"
	// +kubebuilder:validation:XValidation:rule="!('*' in self.managementPolicies || 'Create' in self.managementPolicies || 'Update' in self.managementPolicies) || has(self.forProvider.operationId) || (has(self.initProvider) && has(self.initProvider.operationId))",message="spec.forProvider.operationId is a required parameter"
	// +kubebuilder:validation:XValidation:rule="!('*' in self.managementPolicies || 'Create' in self.managementPolicies || 'Update' in self.managementPolicies) || has(self.forProvider.securityPolicyId) || (has(self.initProvider) && has(self.initProvider.securityPolicyId))",message="spec.forProvider.securityPolicyId is a required parameter"
	// +kubebuilder:validation:XValidation:rule="!('*' in self.managementPolicies || 'Create' in self.managementPolicies || 'Update' in self.managementPolicies) || has(self.forProvider.transactionalEndpoint) || (has(self.initProvider) && has(self.initProvider.transactionalEndpoint))",message="spec.forProvider.transactionalEndpoint is a required parameter"
	Spec   TransactionalEndpointSpec   `json:"spec"`
	Status TransactionalEndpointStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// TransactionalEndpointList contains a list of TransactionalEndpoints
type TransactionalEndpointList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []TransactionalEndpoint `json:"items"`
}

// Repository type metadata.
var (
	TransactionalEndpoint_Kind             = "TransactionalEndpoint"
	TransactionalEndpoint_GroupKind        = schema.GroupKind{Group: CRDGroup, Kind: TransactionalEndpoint_Kind}.String()
	TransactionalEndpoint_KindAPIVersion   = TransactionalEndpoint_Kind + "." + CRDGroupVersion.String()
	TransactionalEndpoint_GroupVersionKind = CRDGroupVersion.WithKind(TransactionalEndpoint_Kind)
)

func init() {
	SchemeBuilder.Register(&TransactionalEndpoint{}, &TransactionalEndpointList{})
}
