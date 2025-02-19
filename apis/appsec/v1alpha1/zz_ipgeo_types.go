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

type IPGeoInitParameters struct {

	// List of IDs of ASN network list to be blocked
	AsnNetworkLists []*string `json:"asnNetworkLists,omitempty" tf:"asn_network_lists,omitempty"`

	// Unique identifier of the security configuration
	ConfigID *float64 `json:"configId,omitempty" tf:"config_id,omitempty"`

	// List of IDs of network list that are always allowed
	ExceptionIPNetworkLists []*string `json:"exceptionIpNetworkLists,omitempty" tf:"exception_ip_network_lists,omitempty"`

	// List of IDs of geographic network list to be blocked
	GeoNetworkLists []*string `json:"geoNetworkLists,omitempty" tf:"geo_network_lists,omitempty"`

	// List of IDs of IP network list to be blocked
	IPNetworkLists []*string `json:"ipNetworkLists,omitempty" tf:"ip_network_lists,omitempty"`

	// Protection mode (block or allow)
	Mode *string `json:"mode,omitempty" tf:"mode,omitempty"`

	// Unique identifier of the security policy
	SecurityPolicyID *string `json:"securityPolicyId,omitempty" tf:"security_policy_id,omitempty"`

	// Action set for Ukraine geo control
	UkraineGeoControlAction *string `json:"ukraineGeoControlAction,omitempty" tf:"ukraine_geo_control_action,omitempty"`
}

type IPGeoObservation struct {

	// List of IDs of ASN network list to be blocked
	AsnNetworkLists []*string `json:"asnNetworkLists,omitempty" tf:"asn_network_lists,omitempty"`

	// Unique identifier of the security configuration
	ConfigID *float64 `json:"configId,omitempty" tf:"config_id,omitempty"`

	// List of IDs of network list that are always allowed
	ExceptionIPNetworkLists []*string `json:"exceptionIpNetworkLists,omitempty" tf:"exception_ip_network_lists,omitempty"`

	// List of IDs of geographic network list to be blocked
	GeoNetworkLists []*string `json:"geoNetworkLists,omitempty" tf:"geo_network_lists,omitempty"`

	ID *string `json:"id,omitempty" tf:"id,omitempty"`

	// List of IDs of IP network list to be blocked
	IPNetworkLists []*string `json:"ipNetworkLists,omitempty" tf:"ip_network_lists,omitempty"`

	// Protection mode (block or allow)
	Mode *string `json:"mode,omitempty" tf:"mode,omitempty"`

	// Unique identifier of the security policy
	SecurityPolicyID *string `json:"securityPolicyId,omitempty" tf:"security_policy_id,omitempty"`

	// Action set for Ukraine geo control
	UkraineGeoControlAction *string `json:"ukraineGeoControlAction,omitempty" tf:"ukraine_geo_control_action,omitempty"`
}

type IPGeoParameters struct {

	// List of IDs of ASN network list to be blocked
	// +kubebuilder:validation:Optional
	AsnNetworkLists []*string `json:"asnNetworkLists,omitempty" tf:"asn_network_lists,omitempty"`

	// Unique identifier of the security configuration
	// +kubebuilder:validation:Optional
	ConfigID *float64 `json:"configId,omitempty" tf:"config_id,omitempty"`

	// List of IDs of network list that are always allowed
	// +kubebuilder:validation:Optional
	ExceptionIPNetworkLists []*string `json:"exceptionIpNetworkLists,omitempty" tf:"exception_ip_network_lists,omitempty"`

	// List of IDs of geographic network list to be blocked
	// +kubebuilder:validation:Optional
	GeoNetworkLists []*string `json:"geoNetworkLists,omitempty" tf:"geo_network_lists,omitempty"`

	// List of IDs of IP network list to be blocked
	// +kubebuilder:validation:Optional
	IPNetworkLists []*string `json:"ipNetworkLists,omitempty" tf:"ip_network_lists,omitempty"`

	// Protection mode (block or allow)
	// +kubebuilder:validation:Optional
	Mode *string `json:"mode,omitempty" tf:"mode,omitempty"`

	// Unique identifier of the security policy
	// +kubebuilder:validation:Optional
	SecurityPolicyID *string `json:"securityPolicyId,omitempty" tf:"security_policy_id,omitempty"`

	// Action set for Ukraine geo control
	// +kubebuilder:validation:Optional
	UkraineGeoControlAction *string `json:"ukraineGeoControlAction,omitempty" tf:"ukraine_geo_control_action,omitempty"`
}

// IPGeoSpec defines the desired state of IPGeo
type IPGeoSpec struct {
	v1.ResourceSpec `json:",inline"`
	ForProvider     IPGeoParameters `json:"forProvider"`
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
	InitProvider IPGeoInitParameters `json:"initProvider,omitempty"`
}

// IPGeoStatus defines the observed state of IPGeo.
type IPGeoStatus struct {
	v1.ResourceStatus `json:",inline"`
	AtProvider        IPGeoObservation `json:"atProvider,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:storageversion

// IPGeo is the Schema for the IPGeos API. <no value>
// +kubebuilder:printcolumn:name="SYNCED",type="string",JSONPath=".status.conditions[?(@.type=='Synced')].status"
// +kubebuilder:printcolumn:name="READY",type="string",JSONPath=".status.conditions[?(@.type=='Ready')].status"
// +kubebuilder:printcolumn:name="EXTERNAL-NAME",type="string",JSONPath=".metadata.annotations.crossplane\\.io/external-name"
// +kubebuilder:printcolumn:name="AGE",type="date",JSONPath=".metadata.creationTimestamp"
// +kubebuilder:resource:scope=Cluster,categories={crossplane,managed,akamai}
type IPGeo struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`
	// +kubebuilder:validation:XValidation:rule="!('*' in self.managementPolicies || 'Create' in self.managementPolicies || 'Update' in self.managementPolicies) || has(self.forProvider.configId) || (has(self.initProvider) && has(self.initProvider.configId))",message="spec.forProvider.configId is a required parameter"
	// +kubebuilder:validation:XValidation:rule="!('*' in self.managementPolicies || 'Create' in self.managementPolicies || 'Update' in self.managementPolicies) || has(self.forProvider.mode) || (has(self.initProvider) && has(self.initProvider.mode))",message="spec.forProvider.mode is a required parameter"
	// +kubebuilder:validation:XValidation:rule="!('*' in self.managementPolicies || 'Create' in self.managementPolicies || 'Update' in self.managementPolicies) || has(self.forProvider.securityPolicyId) || (has(self.initProvider) && has(self.initProvider.securityPolicyId))",message="spec.forProvider.securityPolicyId is a required parameter"
	Spec   IPGeoSpec   `json:"spec"`
	Status IPGeoStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// IPGeoList contains a list of IPGeos
type IPGeoList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []IPGeo `json:"items"`
}

// Repository type metadata.
var (
	IPGeo_Kind             = "IPGeo"
	IPGeo_GroupKind        = schema.GroupKind{Group: CRDGroup, Kind: IPGeo_Kind}.String()
	IPGeo_KindAPIVersion   = IPGeo_Kind + "." + CRDGroupVersion.String()
	IPGeo_GroupVersionKind = CRDGroupVersion.WithKind(IPGeo_Kind)
)

func init() {
	SchemeBuilder.Register(&IPGeo{}, &IPGeoList{})
}
