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

type GeoMapAssignmentInitParameters struct {

	// +listType=set
	Countries []*string `json:"countries,omitempty" tf:"countries,omitempty"`

	DatacenterID *float64 `json:"datacenterId,omitempty" tf:"datacenter_id,omitempty"`

	Nickname *string `json:"nickname,omitempty" tf:"nickname,omitempty"`
}

type GeoMapAssignmentObservation struct {

	// +listType=set
	Countries []*string `json:"countries,omitempty" tf:"countries,omitempty"`

	DatacenterID *float64 `json:"datacenterId,omitempty" tf:"datacenter_id,omitempty"`

	Nickname *string `json:"nickname,omitempty" tf:"nickname,omitempty"`
}

type GeoMapAssignmentParameters struct {

	// +kubebuilder:validation:Optional
	// +listType=set
	Countries []*string `json:"countries,omitempty" tf:"countries,omitempty"`

	// +kubebuilder:validation:Optional
	DatacenterID *float64 `json:"datacenterId" tf:"datacenter_id,omitempty"`

	// +kubebuilder:validation:Optional
	Nickname *string `json:"nickname" tf:"nickname,omitempty"`
}

type GeoMapDefaultDatacenterInitParameters struct {
	DatacenterID *float64 `json:"datacenterId,omitempty" tf:"datacenter_id"`

	Nickname *string `json:"nickname,omitempty" tf:"nickname"`
}

type GeoMapDefaultDatacenterObservation struct {
	DatacenterID *float64 `json:"datacenterId,omitempty" tf:"datacenter_id,omitempty"`

	Nickname *string `json:"nickname,omitempty" tf:"nickname,omitempty"`
}

type GeoMapDefaultDatacenterParameters struct {

	// +kubebuilder:validation:Optional
	DatacenterID *float64 `json:"datacenterId" tf:"datacenter_id"`

	// +kubebuilder:validation:Optional
	Nickname *string `json:"nickname" tf:"nickname"`
}

type GeoMapInitParameters struct {
	Assignment []GeoMapAssignmentInitParameters `json:"assignment,omitempty" tf:"assignment,omitempty"`

	DefaultDatacenter []GeoMapDefaultDatacenterInitParameters `json:"defaultDatacenter,omitempty" tf:"default_datacenter,omitempty"`

	Domain *string `json:"domain,omitempty" tf:"domain,omitempty"`

	Name *string `json:"name,omitempty" tf:"name,omitempty"`

	WaitOnComplete *bool `json:"waitOnComplete,omitempty" tf:"wait_on_complete,omitempty"`
}

type GeoMapObservation struct {
	Assignment []GeoMapAssignmentObservation `json:"assignment,omitempty" tf:"assignment,omitempty"`

	DefaultDatacenter []GeoMapDefaultDatacenterObservation `json:"defaultDatacenter,omitempty" tf:"default_datacenter,omitempty"`

	Domain *string `json:"domain,omitempty" tf:"domain,omitempty"`

	ID *string `json:"id,omitempty" tf:"id,omitempty"`

	Name *string `json:"name,omitempty" tf:"name,omitempty"`

	WaitOnComplete *bool `json:"waitOnComplete,omitempty" tf:"wait_on_complete,omitempty"`
}

type GeoMapParameters struct {

	// +kubebuilder:validation:Optional
	Assignment []GeoMapAssignmentParameters `json:"assignment,omitempty" tf:"assignment,omitempty"`

	// +kubebuilder:validation:Optional
	DefaultDatacenter []GeoMapDefaultDatacenterParameters `json:"defaultDatacenter,omitempty" tf:"default_datacenter,omitempty"`

	// +kubebuilder:validation:Optional
	Domain *string `json:"domain,omitempty" tf:"domain,omitempty"`

	// +kubebuilder:validation:Optional
	Name *string `json:"name,omitempty" tf:"name,omitempty"`

	// +kubebuilder:validation:Optional
	WaitOnComplete *bool `json:"waitOnComplete,omitempty" tf:"wait_on_complete,omitempty"`
}

// GeoMapSpec defines the desired state of GeoMap
type GeoMapSpec struct {
	v1.ResourceSpec `json:",inline"`
	ForProvider     GeoMapParameters `json:"forProvider"`
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
	InitProvider GeoMapInitParameters `json:"initProvider,omitempty"`
}

// GeoMapStatus defines the observed state of GeoMap.
type GeoMapStatus struct {
	v1.ResourceStatus `json:",inline"`
	AtProvider        GeoMapObservation `json:"atProvider,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:storageversion

// GeoMap is the Schema for the GeoMaps API. <no value>
// +kubebuilder:printcolumn:name="SYNCED",type="string",JSONPath=".status.conditions[?(@.type=='Synced')].status"
// +kubebuilder:printcolumn:name="READY",type="string",JSONPath=".status.conditions[?(@.type=='Ready')].status"
// +kubebuilder:printcolumn:name="EXTERNAL-NAME",type="string",JSONPath=".metadata.annotations.crossplane\\.io/external-name"
// +kubebuilder:printcolumn:name="AGE",type="date",JSONPath=".metadata.creationTimestamp"
// +kubebuilder:resource:scope=Cluster,categories={crossplane,managed,akamai}
type GeoMap struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`
	// +kubebuilder:validation:XValidation:rule="!('*' in self.managementPolicies || 'Create' in self.managementPolicies || 'Update' in self.managementPolicies) || has(self.forProvider.defaultDatacenter) || (has(self.initProvider) && has(self.initProvider.defaultDatacenter))",message="spec.forProvider.defaultDatacenter is a required parameter"
	// +kubebuilder:validation:XValidation:rule="!('*' in self.managementPolicies || 'Create' in self.managementPolicies || 'Update' in self.managementPolicies) || has(self.forProvider.domain) || (has(self.initProvider) && has(self.initProvider.domain))",message="spec.forProvider.domain is a required parameter"
	// +kubebuilder:validation:XValidation:rule="!('*' in self.managementPolicies || 'Create' in self.managementPolicies || 'Update' in self.managementPolicies) || has(self.forProvider.name) || (has(self.initProvider) && has(self.initProvider.name))",message="spec.forProvider.name is a required parameter"
	Spec   GeoMapSpec   `json:"spec"`
	Status GeoMapStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// GeoMapList contains a list of GeoMaps
type GeoMapList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []GeoMap `json:"items"`
}

// Repository type metadata.
var (
	GeoMap_Kind             = "GeoMap"
	GeoMap_GroupKind        = schema.GroupKind{Group: CRDGroup, Kind: GeoMap_Kind}.String()
	GeoMap_KindAPIVersion   = GeoMap_Kind + "." + CRDGroupVersion.String()
	GeoMap_GroupVersionKind = CRDGroupVersion.WithKind(GeoMap_Kind)
)

func init() {
	SchemeBuilder.Register(&GeoMap{}, &GeoMapList{})
}
