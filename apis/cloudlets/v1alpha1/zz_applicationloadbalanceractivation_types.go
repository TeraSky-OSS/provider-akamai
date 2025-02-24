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

type ApplicationLoadBalancerActivationInitParameters struct {

	// The network you want to activate the application load balancer version on (options are Staging and Production)
	Network *string `json:"network,omitempty" tf:"network,omitempty"`

	// The conditional origin’s unique identifier
	OriginID *string `json:"originId,omitempty" tf:"origin_id,omitempty"`

	// Cloudlets application load balancer version you want to activate
	Version *float64 `json:"version,omitempty" tf:"version,omitempty"`
}

type ApplicationLoadBalancerActivationObservation struct {
	ID *string `json:"id,omitempty" tf:"id,omitempty"`

	// The network you want to activate the application load balancer version on (options are Staging and Production)
	Network *string `json:"network,omitempty" tf:"network,omitempty"`

	// The conditional origin’s unique identifier
	OriginID *string `json:"originId,omitempty" tf:"origin_id,omitempty"`

	// Activation status for this application load balancer
	Status *string `json:"status,omitempty" tf:"status,omitempty"`

	// Cloudlets application load balancer version you want to activate
	Version *float64 `json:"version,omitempty" tf:"version,omitempty"`
}

type ApplicationLoadBalancerActivationParameters struct {

	// The network you want to activate the application load balancer version on (options are Staging and Production)
	// +kubebuilder:validation:Optional
	Network *string `json:"network,omitempty" tf:"network,omitempty"`

	// The conditional origin’s unique identifier
	// +kubebuilder:validation:Optional
	OriginID *string `json:"originId,omitempty" tf:"origin_id,omitempty"`

	// Cloudlets application load balancer version you want to activate
	// +kubebuilder:validation:Optional
	Version *float64 `json:"version,omitempty" tf:"version,omitempty"`
}

// ApplicationLoadBalancerActivationSpec defines the desired state of ApplicationLoadBalancerActivation
type ApplicationLoadBalancerActivationSpec struct {
	v1.ResourceSpec `json:",inline"`
	ForProvider     ApplicationLoadBalancerActivationParameters `json:"forProvider"`
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
	InitProvider ApplicationLoadBalancerActivationInitParameters `json:"initProvider,omitempty"`
}

// ApplicationLoadBalancerActivationStatus defines the observed state of ApplicationLoadBalancerActivation.
type ApplicationLoadBalancerActivationStatus struct {
	v1.ResourceStatus `json:",inline"`
	AtProvider        ApplicationLoadBalancerActivationObservation `json:"atProvider,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:storageversion

// ApplicationLoadBalancerActivation is the Schema for the ApplicationLoadBalancerActivations API. <no value>
// +kubebuilder:printcolumn:name="SYNCED",type="string",JSONPath=".status.conditions[?(@.type=='Synced')].status"
// +kubebuilder:printcolumn:name="READY",type="string",JSONPath=".status.conditions[?(@.type=='Ready')].status"
// +kubebuilder:printcolumn:name="EXTERNAL-NAME",type="string",JSONPath=".metadata.annotations.crossplane\\.io/external-name"
// +kubebuilder:printcolumn:name="AGE",type="date",JSONPath=".metadata.creationTimestamp"
// +kubebuilder:resource:scope=Cluster,categories={crossplane,managed,akamai}
type ApplicationLoadBalancerActivation struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`
	// +kubebuilder:validation:XValidation:rule="!('*' in self.managementPolicies || 'Create' in self.managementPolicies || 'Update' in self.managementPolicies) || has(self.forProvider.network) || (has(self.initProvider) && has(self.initProvider.network))",message="spec.forProvider.network is a required parameter"
	// +kubebuilder:validation:XValidation:rule="!('*' in self.managementPolicies || 'Create' in self.managementPolicies || 'Update' in self.managementPolicies) || has(self.forProvider.originId) || (has(self.initProvider) && has(self.initProvider.originId))",message="spec.forProvider.originId is a required parameter"
	// +kubebuilder:validation:XValidation:rule="!('*' in self.managementPolicies || 'Create' in self.managementPolicies || 'Update' in self.managementPolicies) || has(self.forProvider.version) || (has(self.initProvider) && has(self.initProvider.version))",message="spec.forProvider.version is a required parameter"
	Spec   ApplicationLoadBalancerActivationSpec   `json:"spec"`
	Status ApplicationLoadBalancerActivationStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// ApplicationLoadBalancerActivationList contains a list of ApplicationLoadBalancerActivations
type ApplicationLoadBalancerActivationList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []ApplicationLoadBalancerActivation `json:"items"`
}

// Repository type metadata.
var (
	ApplicationLoadBalancerActivation_Kind             = "ApplicationLoadBalancerActivation"
	ApplicationLoadBalancerActivation_GroupKind        = schema.GroupKind{Group: CRDGroup, Kind: ApplicationLoadBalancerActivation_Kind}.String()
	ApplicationLoadBalancerActivation_KindAPIVersion   = ApplicationLoadBalancerActivation_Kind + "." + CRDGroupVersion.String()
	ApplicationLoadBalancerActivation_GroupVersionKind = CRDGroupVersion.WithKind(ApplicationLoadBalancerActivation_Kind)
)

func init() {
	SchemeBuilder.Register(&ApplicationLoadBalancerActivation{}, &ApplicationLoadBalancerActivationList{})
}
