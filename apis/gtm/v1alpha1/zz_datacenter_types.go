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

type DatacenterInitParameters struct {
	City *string `json:"city,omitempty" tf:"city,omitempty"`

	CloneOf *float64 `json:"cloneOf,omitempty" tf:"clone_of,omitempty"`

	CloudServerHostHeaderOverride *bool `json:"cloudServerHostHeaderOverride,omitempty" tf:"cloud_server_host_header_override,omitempty"`

	CloudServerTargeting *bool `json:"cloudServerTargeting,omitempty" tf:"cloud_server_targeting,omitempty"`

	Continent *string `json:"continent,omitempty" tf:"continent,omitempty"`

	Country *string `json:"country,omitempty" tf:"country,omitempty"`

	DefaultLoadObject []DefaultLoadObjectInitParameters `json:"defaultLoadObject,omitempty" tf:"default_load_object,omitempty"`

	Domain *string `json:"domain,omitempty" tf:"domain,omitempty"`

	Latitude *float64 `json:"latitude,omitempty" tf:"latitude,omitempty"`

	Longitude *float64 `json:"longitude,omitempty" tf:"longitude,omitempty"`

	Nickname *string `json:"nickname,omitempty" tf:"nickname,omitempty"`

	StateOrProvince *string `json:"stateOrProvince,omitempty" tf:"state_or_province,omitempty"`

	WaitOnComplete *bool `json:"waitOnComplete,omitempty" tf:"wait_on_complete,omitempty"`
}

type DatacenterObservation struct {
	City *string `json:"city,omitempty" tf:"city,omitempty"`

	CloneOf *float64 `json:"cloneOf,omitempty" tf:"clone_of,omitempty"`

	CloudServerHostHeaderOverride *bool `json:"cloudServerHostHeaderOverride,omitempty" tf:"cloud_server_host_header_override,omitempty"`

	CloudServerTargeting *bool `json:"cloudServerTargeting,omitempty" tf:"cloud_server_targeting,omitempty"`

	Continent *string `json:"continent,omitempty" tf:"continent,omitempty"`

	Country *string `json:"country,omitempty" tf:"country,omitempty"`

	DatacenterID *float64 `json:"datacenterId,omitempty" tf:"datacenter_id,omitempty"`

	DefaultLoadObject []DefaultLoadObjectObservation `json:"defaultLoadObject,omitempty" tf:"default_load_object,omitempty"`

	Domain *string `json:"domain,omitempty" tf:"domain,omitempty"`

	ID *string `json:"id,omitempty" tf:"id,omitempty"`

	Latitude *float64 `json:"latitude,omitempty" tf:"latitude,omitempty"`

	Longitude *float64 `json:"longitude,omitempty" tf:"longitude,omitempty"`

	Nickname *string `json:"nickname,omitempty" tf:"nickname,omitempty"`

	PingInterval *float64 `json:"pingInterval,omitempty" tf:"ping_interval,omitempty"`

	PingPacketSize *float64 `json:"pingPacketSize,omitempty" tf:"ping_packet_size,omitempty"`

	ScorePenalty *float64 `json:"scorePenalty,omitempty" tf:"score_penalty,omitempty"`

	ServermonitorLivenessCount *float64 `json:"servermonitorLivenessCount,omitempty" tf:"servermonitor_liveness_count,omitempty"`

	ServermonitorLoadCount *float64 `json:"servermonitorLoadCount,omitempty" tf:"servermonitor_load_count,omitempty"`

	ServermonitorPool *string `json:"servermonitorPool,omitempty" tf:"servermonitor_pool,omitempty"`

	StateOrProvince *string `json:"stateOrProvince,omitempty" tf:"state_or_province,omitempty"`

	Virtual *bool `json:"virtual,omitempty" tf:"virtual,omitempty"`

	WaitOnComplete *bool `json:"waitOnComplete,omitempty" tf:"wait_on_complete,omitempty"`
}

type DatacenterParameters struct {

	// +kubebuilder:validation:Optional
	City *string `json:"city,omitempty" tf:"city,omitempty"`

	// +kubebuilder:validation:Optional
	CloneOf *float64 `json:"cloneOf,omitempty" tf:"clone_of,omitempty"`

	// +kubebuilder:validation:Optional
	CloudServerHostHeaderOverride *bool `json:"cloudServerHostHeaderOverride,omitempty" tf:"cloud_server_host_header_override,omitempty"`

	// +kubebuilder:validation:Optional
	CloudServerTargeting *bool `json:"cloudServerTargeting,omitempty" tf:"cloud_server_targeting,omitempty"`

	// +kubebuilder:validation:Optional
	Continent *string `json:"continent,omitempty" tf:"continent,omitempty"`

	// +kubebuilder:validation:Optional
	Country *string `json:"country,omitempty" tf:"country,omitempty"`

	// +kubebuilder:validation:Optional
	DefaultLoadObject []DefaultLoadObjectParameters `json:"defaultLoadObject,omitempty" tf:"default_load_object,omitempty"`

	// +kubebuilder:validation:Optional
	Domain *string `json:"domain,omitempty" tf:"domain,omitempty"`

	// +kubebuilder:validation:Optional
	Latitude *float64 `json:"latitude,omitempty" tf:"latitude,omitempty"`

	// +kubebuilder:validation:Optional
	Longitude *float64 `json:"longitude,omitempty" tf:"longitude,omitempty"`

	// +kubebuilder:validation:Optional
	Nickname *string `json:"nickname,omitempty" tf:"nickname,omitempty"`

	// +kubebuilder:validation:Optional
	StateOrProvince *string `json:"stateOrProvince,omitempty" tf:"state_or_province,omitempty"`

	// +kubebuilder:validation:Optional
	WaitOnComplete *bool `json:"waitOnComplete,omitempty" tf:"wait_on_complete,omitempty"`
}

type DefaultLoadObjectInitParameters struct {
	LoadObject *string `json:"loadObject,omitempty" tf:"load_object,omitempty"`

	LoadObjectPort *float64 `json:"loadObjectPort,omitempty" tf:"load_object_port,omitempty"`

	LoadServers []*string `json:"loadServers,omitempty" tf:"load_servers,omitempty"`
}

type DefaultLoadObjectObservation struct {
	LoadObject *string `json:"loadObject,omitempty" tf:"load_object,omitempty"`

	LoadObjectPort *float64 `json:"loadObjectPort,omitempty" tf:"load_object_port,omitempty"`

	LoadServers []*string `json:"loadServers,omitempty" tf:"load_servers,omitempty"`
}

type DefaultLoadObjectParameters struct {

	// +kubebuilder:validation:Optional
	LoadObject *string `json:"loadObject,omitempty" tf:"load_object,omitempty"`

	// +kubebuilder:validation:Optional
	LoadObjectPort *float64 `json:"loadObjectPort,omitempty" tf:"load_object_port,omitempty"`

	// +kubebuilder:validation:Optional
	LoadServers []*string `json:"loadServers,omitempty" tf:"load_servers,omitempty"`
}

// DatacenterSpec defines the desired state of Datacenter
type DatacenterSpec struct {
	v1.ResourceSpec `json:",inline"`
	ForProvider     DatacenterParameters `json:"forProvider"`
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
	InitProvider DatacenterInitParameters `json:"initProvider,omitempty"`
}

// DatacenterStatus defines the observed state of Datacenter.
type DatacenterStatus struct {
	v1.ResourceStatus `json:",inline"`
	AtProvider        DatacenterObservation `json:"atProvider,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:storageversion

// Datacenter is the Schema for the Datacenters API. <no value>
// +kubebuilder:printcolumn:name="SYNCED",type="string",JSONPath=".status.conditions[?(@.type=='Synced')].status"
// +kubebuilder:printcolumn:name="READY",type="string",JSONPath=".status.conditions[?(@.type=='Ready')].status"
// +kubebuilder:printcolumn:name="EXTERNAL-NAME",type="string",JSONPath=".metadata.annotations.crossplane\\.io/external-name"
// +kubebuilder:printcolumn:name="AGE",type="date",JSONPath=".metadata.creationTimestamp"
// +kubebuilder:resource:scope=Cluster,categories={crossplane,managed,akamai}
type Datacenter struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`
	// +kubebuilder:validation:XValidation:rule="!('*' in self.managementPolicies || 'Create' in self.managementPolicies || 'Update' in self.managementPolicies) || has(self.forProvider.domain) || (has(self.initProvider) && has(self.initProvider.domain))",message="spec.forProvider.domain is a required parameter"
	Spec   DatacenterSpec   `json:"spec"`
	Status DatacenterStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// DatacenterList contains a list of Datacenters
type DatacenterList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []Datacenter `json:"items"`
}

// Repository type metadata.
var (
	Datacenter_Kind             = "Datacenter"
	Datacenter_GroupKind        = schema.GroupKind{Group: CRDGroup, Kind: Datacenter_Kind}.String()
	Datacenter_KindAPIVersion   = Datacenter_Kind + "." + CRDGroupVersion.String()
	Datacenter_GroupVersionKind = CRDGroupVersion.WithKind(Datacenter_Kind)
)

func init() {
	SchemeBuilder.Register(&Datacenter{}, &DatacenterList{})
}
