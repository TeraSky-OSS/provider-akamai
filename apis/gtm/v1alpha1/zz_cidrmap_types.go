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

type CIDRMapAssignmentInitParameters struct {

	// +listType=set
	Blocks []*string `json:"blocks,omitempty" tf:"blocks,omitempty"`

	DatacenterID *float64 `json:"datacenterId,omitempty" tf:"datacenter_id,omitempty"`

	Nickname *string `json:"nickname,omitempty" tf:"nickname,omitempty"`
}

type CIDRMapAssignmentObservation struct {

	// +listType=set
	Blocks []*string `json:"blocks,omitempty" tf:"blocks,omitempty"`

	DatacenterID *float64 `json:"datacenterId,omitempty" tf:"datacenter_id,omitempty"`

	Nickname *string `json:"nickname,omitempty" tf:"nickname,omitempty"`
}

type CIDRMapAssignmentParameters struct {

	// +kubebuilder:validation:Optional
	// +listType=set
	Blocks []*string `json:"blocks,omitempty" tf:"blocks,omitempty"`

	// +kubebuilder:validation:Optional
	DatacenterID *float64 `json:"datacenterId" tf:"datacenter_id,omitempty"`

	// +kubebuilder:validation:Optional
	Nickname *string `json:"nickname" tf:"nickname,omitempty"`
}

type CIDRMapDefaultDatacenterInitParameters struct {
	DatacenterID *float64 `json:"datacenterId,omitempty" tf:"datacenter_id,omitempty"`

	Nickname *string `json:"nickname,omitempty" tf:"nickname,omitempty"`
}

type CIDRMapDefaultDatacenterObservation struct {
	DatacenterID *float64 `json:"datacenterId,omitempty" tf:"datacenter_id,omitempty"`

	Nickname *string `json:"nickname,omitempty" tf:"nickname,omitempty"`
}

type CIDRMapDefaultDatacenterParameters struct {

	// +kubebuilder:validation:Optional
	DatacenterID *float64 `json:"datacenterId" tf:"datacenter_id,omitempty"`

	// +kubebuilder:validation:Optional
	Nickname *string `json:"nickname,omitempty" tf:"nickname,omitempty"`
}

type CIDRMapInitParameters struct {
	Assignment []CIDRMapAssignmentInitParameters `json:"assignment,omitempty" tf:"assignment,omitempty"`

	DefaultDatacenter []CIDRMapDefaultDatacenterInitParameters `json:"defaultDatacenter,omitempty" tf:"default_datacenter,omitempty"`

	Domain *string `json:"domain,omitempty" tf:"domain,omitempty"`

	Name *string `json:"name,omitempty" tf:"name,omitempty"`

	WaitOnComplete *bool `json:"waitOnComplete,omitempty" tf:"wait_on_complete,omitempty"`
}

type CIDRMapObservation struct {
	Assignment []CIDRMapAssignmentObservation `json:"assignment,omitempty" tf:"assignment,omitempty"`

	DefaultDatacenter []CIDRMapDefaultDatacenterObservation `json:"defaultDatacenter,omitempty" tf:"default_datacenter,omitempty"`

	Domain *string `json:"domain,omitempty" tf:"domain,omitempty"`

	ID *string `json:"id,omitempty" tf:"id,omitempty"`

	Name *string `json:"name,omitempty" tf:"name,omitempty"`

	WaitOnComplete *bool `json:"waitOnComplete,omitempty" tf:"wait_on_complete,omitempty"`
}

type CIDRMapParameters struct {

	// +kubebuilder:validation:Optional
	Assignment []CIDRMapAssignmentParameters `json:"assignment,omitempty" tf:"assignment,omitempty"`

	// +kubebuilder:validation:Optional
	DefaultDatacenter []CIDRMapDefaultDatacenterParameters `json:"defaultDatacenter,omitempty" tf:"default_datacenter,omitempty"`

	// +kubebuilder:validation:Optional
	Domain *string `json:"domain,omitempty" tf:"domain,omitempty"`

	// +kubebuilder:validation:Optional
	Name *string `json:"name,omitempty" tf:"name,omitempty"`

	// +kubebuilder:validation:Optional
	WaitOnComplete *bool `json:"waitOnComplete,omitempty" tf:"wait_on_complete,omitempty"`
}

// CIDRMapSpec defines the desired state of CIDRMap
type CIDRMapSpec struct {
	v1.ResourceSpec `json:",inline"`
	ForProvider     CIDRMapParameters `json:"forProvider"`
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
	InitProvider CIDRMapInitParameters `json:"initProvider,omitempty"`
}

// CIDRMapStatus defines the observed state of CIDRMap.
type CIDRMapStatus struct {
	v1.ResourceStatus `json:",inline"`
	AtProvider        CIDRMapObservation `json:"atProvider,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:storageversion

// CIDRMap is the Schema for the CIDRMaps API. <no value>
// +kubebuilder:printcolumn:name="SYNCED",type="string",JSONPath=".status.conditions[?(@.type=='Synced')].status"
// +kubebuilder:printcolumn:name="READY",type="string",JSONPath=".status.conditions[?(@.type=='Ready')].status"
// +kubebuilder:printcolumn:name="EXTERNAL-NAME",type="string",JSONPath=".metadata.annotations.crossplane\\.io/external-name"
// +kubebuilder:printcolumn:name="AGE",type="date",JSONPath=".metadata.creationTimestamp"
// +kubebuilder:resource:scope=Cluster,categories={crossplane,managed,akamai}
type CIDRMap struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`
	// +kubebuilder:validation:XValidation:rule="!('*' in self.managementPolicies || 'Create' in self.managementPolicies || 'Update' in self.managementPolicies) || has(self.forProvider.defaultDatacenter) || (has(self.initProvider) && has(self.initProvider.defaultDatacenter))",message="spec.forProvider.defaultDatacenter is a required parameter"
	// +kubebuilder:validation:XValidation:rule="!('*' in self.managementPolicies || 'Create' in self.managementPolicies || 'Update' in self.managementPolicies) || has(self.forProvider.domain) || (has(self.initProvider) && has(self.initProvider.domain))",message="spec.forProvider.domain is a required parameter"
	// +kubebuilder:validation:XValidation:rule="!('*' in self.managementPolicies || 'Create' in self.managementPolicies || 'Update' in self.managementPolicies) || has(self.forProvider.name) || (has(self.initProvider) && has(self.initProvider.name))",message="spec.forProvider.name is a required parameter"
	Spec   CIDRMapSpec   `json:"spec"`
	Status CIDRMapStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// CIDRMapList contains a list of CIDRMaps
type CIDRMapList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []CIDRMap `json:"items"`
}

// Repository type metadata.
var (
	CIDRMap_Kind             = "CIDRMap"
	CIDRMap_GroupKind        = schema.GroupKind{Group: CRDGroup, Kind: CIDRMap_Kind}.String()
	CIDRMap_KindAPIVersion   = CIDRMap_Kind + "." + CRDGroupVersion.String()
	CIDRMap_GroupVersionKind = CRDGroupVersion.WithKind(CIDRMap_Kind)
)

func init() {
	SchemeBuilder.Register(&CIDRMap{}, &CIDRMapList{})
}
