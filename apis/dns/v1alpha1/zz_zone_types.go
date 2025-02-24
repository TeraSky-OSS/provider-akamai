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

type OutboundZoneTransferInitParameters struct {

	// (Set of String) The access control list, defined as IPv4 and IPv6 CIDR blocks.
	// The access control list, defined as IPv4 and IPv6 CIDR blocks.
	// +listType=set
	ACL []*string `json:"acl,omitempty" tf:"acl,omitempty"`

	// (Boolean) Enables outbound zone transfer.
	// Enables outbound zone transfer.
	Enabled *bool `json:"enabled,omitempty" tf:"enabled,omitempty"`

	// (Set of String) Customer secondary nameservers to notify, if NOTIFY requests are desired. Up to 64 IPv4 or IPv6 addresses. If no targets are specified, you can manually request zone transfer updates as needed.
	// Customer secondary nameservers to notify, if NOTIFY requests are desired. Up to 64 IPv4 or IPv6 addresses. If no targets are specified, you can manually request zone transfer updates as needed.
	// +listType=set
	NotifyTargets []*string `json:"notifyTargets,omitempty" tf:"notify_targets,omitempty"`

	// (Block List, Max: 1) (see below for nested schema)
	// The TSIG key used for outbound zone transfers.
	TsigKey []TsigKeyInitParameters `json:"tsigKey,omitempty" tf:"tsig_key,omitempty"`
}

type OutboundZoneTransferObservation struct {

	// (Set of String) The access control list, defined as IPv4 and IPv6 CIDR blocks.
	// The access control list, defined as IPv4 and IPv6 CIDR blocks.
	// +listType=set
	ACL []*string `json:"acl,omitempty" tf:"acl,omitempty"`

	// (Boolean) Enables outbound zone transfer.
	// Enables outbound zone transfer.
	Enabled *bool `json:"enabled,omitempty" tf:"enabled,omitempty"`

	// (Set of String) Customer secondary nameservers to notify, if NOTIFY requests are desired. Up to 64 IPv4 or IPv6 addresses. If no targets are specified, you can manually request zone transfer updates as needed.
	// Customer secondary nameservers to notify, if NOTIFY requests are desired. Up to 64 IPv4 or IPv6 addresses. If no targets are specified, you can manually request zone transfer updates as needed.
	// +listType=set
	NotifyTargets []*string `json:"notifyTargets,omitempty" tf:"notify_targets,omitempty"`

	// (Block List, Max: 1) (see below for nested schema)
	// The TSIG key used for outbound zone transfers.
	TsigKey []TsigKeyObservation `json:"tsigKey,omitempty" tf:"tsig_key,omitempty"`
}

type OutboundZoneTransferParameters struct {

	// (Set of String) The access control list, defined as IPv4 and IPv6 CIDR blocks.
	// The access control list, defined as IPv4 and IPv6 CIDR blocks.
	// +kubebuilder:validation:Optional
	// +listType=set
	ACL []*string `json:"acl,omitempty" tf:"acl,omitempty"`

	// (Boolean) Enables outbound zone transfer.
	// Enables outbound zone transfer.
	// +kubebuilder:validation:Optional
	Enabled *bool `json:"enabled,omitempty" tf:"enabled,omitempty"`

	// (Set of String) Customer secondary nameservers to notify, if NOTIFY requests are desired. Up to 64 IPv4 or IPv6 addresses. If no targets are specified, you can manually request zone transfer updates as needed.
	// Customer secondary nameservers to notify, if NOTIFY requests are desired. Up to 64 IPv4 or IPv6 addresses. If no targets are specified, you can manually request zone transfer updates as needed.
	// +kubebuilder:validation:Optional
	// +listType=set
	NotifyTargets []*string `json:"notifyTargets,omitempty" tf:"notify_targets,omitempty"`

	// (Block List, Max: 1) (see below for nested schema)
	// The TSIG key used for outbound zone transfers.
	// +kubebuilder:validation:Optional
	TsigKey []TsigKeyParameters `json:"tsigKey,omitempty" tf:"tsig_key,omitempty"`
}

type TsigKeyInitParameters struct {

	// md5, hmac-sha1, hmac-sha224, hmac-sha256, hmac-sha384, hmac-sha512, or HMAC-MD5.SIG-ALG.REG.INT.
	// The algorithm used to encode the TSIG key's secret data. Possible values are: hmac-md5, hmac-sha1, hmac-sha224, hmac-sha256, hmac-sha384, hmac-sha512, or HMAC-MD5.SIG-ALG.REG.INT.
	Algorithm *string `json:"algorithm,omitempty" tf:"algorithm,omitempty"`

	// (String) The zone name.
	// The zone name.
	Name *string `json:"name,omitempty" tf:"name,omitempty"`

	// encoded string of data. When decoded, it needs to contain the correct number of bits for the chosen algorithm. If the input isn't correctly padded, the server applies the padding.
	// A Base64-encoded string of data. When decoded, it needs to contain the correct number of bits for the chosen algorithm. If the input isn't correctly padded, the server applies the padding.
	Secret *string `json:"secret,omitempty" tf:"secret,omitempty"`
}

type TsigKeyObservation struct {

	// md5, hmac-sha1, hmac-sha224, hmac-sha256, hmac-sha384, hmac-sha512, or HMAC-MD5.SIG-ALG.REG.INT.
	// The algorithm used to encode the TSIG key's secret data. Possible values are: hmac-md5, hmac-sha1, hmac-sha224, hmac-sha256, hmac-sha384, hmac-sha512, or HMAC-MD5.SIG-ALG.REG.INT.
	Algorithm *string `json:"algorithm,omitempty" tf:"algorithm,omitempty"`

	// (String) The zone name.
	// The zone name.
	Name *string `json:"name,omitempty" tf:"name,omitempty"`

	// encoded string of data. When decoded, it needs to contain the correct number of bits for the chosen algorithm. If the input isn't correctly padded, the server applies the padding.
	// A Base64-encoded string of data. When decoded, it needs to contain the correct number of bits for the chosen algorithm. If the input isn't correctly padded, the server applies the padding.
	Secret *string `json:"secret,omitempty" tf:"secret,omitempty"`
}

type TsigKeyParameters struct {

	// md5, hmac-sha1, hmac-sha224, hmac-sha256, hmac-sha384, hmac-sha512, or HMAC-MD5.SIG-ALG.REG.INT.
	// The algorithm used to encode the TSIG key's secret data. Possible values are: hmac-md5, hmac-sha1, hmac-sha224, hmac-sha256, hmac-sha384, hmac-sha512, or HMAC-MD5.SIG-ALG.REG.INT.
	// +kubebuilder:validation:Optional
	Algorithm *string `json:"algorithm" tf:"algorithm,omitempty"`

	// (String) The zone name.
	// The zone name.
	// +kubebuilder:validation:Optional
	Name *string `json:"name" tf:"name,omitempty"`

	// encoded string of data. When decoded, it needs to contain the correct number of bits for the chosen algorithm. If the input isn't correctly padded, the server applies the padding.
	// A Base64-encoded string of data. When decoded, it needs to contain the correct number of bits for the chosen algorithm. If the input isn't correctly padded, the server applies the padding.
	// +kubebuilder:validation:Optional
	Secret *string `json:"secret" tf:"secret,omitempty"`
}

type ZoneInitParameters struct {

	// (String)
	Comment *string `json:"comment,omitempty" tf:"comment,omitempty"`

	// (String)
	Contract *string `json:"contract,omitempty" tf:"contract,omitempty"`

	// (String)
	EndCustomerID *string `json:"endCustomerId,omitempty" tf:"end_customer_id,omitempty"`

	// (String)
	Group *string `json:"group,omitempty" tf:"group,omitempty"`

	// (Set of String)
	// +listType=set
	Masters []*string `json:"masters,omitempty" tf:"masters,omitempty"`

	// (Block List, Max: 1) Outbound zone transfer properties. (see below for nested schema)
	// Outbound zone transfer properties.
	OutboundZoneTransfer []OutboundZoneTransferInitParameters `json:"outboundZoneTransfer,omitempty" tf:"outbound_zone_transfer,omitempty"`

	// (Boolean)
	SignAndServe *bool `json:"signAndServe,omitempty" tf:"sign_and_serve,omitempty"`

	// (String)
	SignAndServeAlgorithm *string `json:"signAndServeAlgorithm,omitempty" tf:"sign_and_serve_algorithm,omitempty"`

	// (String)
	Target *string `json:"target,omitempty" tf:"target,omitempty"`

	// (Block List, Max: 1) (see below for nested schema)
	TsigKey []ZoneTsigKeyInitParameters `json:"tsigKey,omitempty" tf:"tsig_key,omitempty"`

	// (String)
	Type *string `json:"type,omitempty" tf:"type,omitempty"`

	// (String)
	Zone *string `json:"zone,omitempty" tf:"zone,omitempty"`
}

type ZoneObservation struct {

	// (String)
	ActivationState *string `json:"activationState,omitempty" tf:"activation_state,omitempty"`

	// (Number)
	AliasCount *float64 `json:"aliasCount,omitempty" tf:"alias_count,omitempty"`

	// (String)
	Comment *string `json:"comment,omitempty" tf:"comment,omitempty"`

	// (String)
	Contract *string `json:"contract,omitempty" tf:"contract,omitempty"`

	// (String)
	EndCustomerID *string `json:"endCustomerId,omitempty" tf:"end_customer_id,omitempty"`

	// (String)
	Group *string `json:"group,omitempty" tf:"group,omitempty"`

	// (String) The ID of this resource.
	ID *string `json:"id,omitempty" tf:"id,omitempty"`

	// (Set of String)
	// +listType=set
	Masters []*string `json:"masters,omitempty" tf:"masters,omitempty"`

	// (Block List, Max: 1) Outbound zone transfer properties. (see below for nested schema)
	// Outbound zone transfer properties.
	OutboundZoneTransfer []OutboundZoneTransferObservation `json:"outboundZoneTransfer,omitempty" tf:"outbound_zone_transfer,omitempty"`

	// (Boolean)
	SignAndServe *bool `json:"signAndServe,omitempty" tf:"sign_and_serve,omitempty"`

	// (String)
	SignAndServeAlgorithm *string `json:"signAndServeAlgorithm,omitempty" tf:"sign_and_serve_algorithm,omitempty"`

	// (String)
	Target *string `json:"target,omitempty" tf:"target,omitempty"`

	// (Block List, Max: 1) (see below for nested schema)
	TsigKey []ZoneTsigKeyObservation `json:"tsigKey,omitempty" tf:"tsig_key,omitempty"`

	// (String)
	Type *string `json:"type,omitempty" tf:"type,omitempty"`

	// (String)
	VersionID *string `json:"versionId,omitempty" tf:"version_id,omitempty"`

	// (String)
	Zone *string `json:"zone,omitempty" tf:"zone,omitempty"`
}

type ZoneParameters struct {

	// (String)
	// +kubebuilder:validation:Optional
	Comment *string `json:"comment,omitempty" tf:"comment,omitempty"`

	// (String)
	// +kubebuilder:validation:Optional
	Contract *string `json:"contract,omitempty" tf:"contract,omitempty"`

	// (String)
	// +kubebuilder:validation:Optional
	EndCustomerID *string `json:"endCustomerId,omitempty" tf:"end_customer_id,omitempty"`

	// (String)
	// +kubebuilder:validation:Optional
	Group *string `json:"group,omitempty" tf:"group,omitempty"`

	// (Set of String)
	// +kubebuilder:validation:Optional
	// +listType=set
	Masters []*string `json:"masters,omitempty" tf:"masters,omitempty"`

	// (Block List, Max: 1) Outbound zone transfer properties. (see below for nested schema)
	// Outbound zone transfer properties.
	// +kubebuilder:validation:Optional
	OutboundZoneTransfer []OutboundZoneTransferParameters `json:"outboundZoneTransfer,omitempty" tf:"outbound_zone_transfer,omitempty"`

	// (Boolean)
	// +kubebuilder:validation:Optional
	SignAndServe *bool `json:"signAndServe,omitempty" tf:"sign_and_serve,omitempty"`

	// (String)
	// +kubebuilder:validation:Optional
	SignAndServeAlgorithm *string `json:"signAndServeAlgorithm,omitempty" tf:"sign_and_serve_algorithm,omitempty"`

	// (String)
	// +kubebuilder:validation:Optional
	Target *string `json:"target,omitempty" tf:"target,omitempty"`

	// (Block List, Max: 1) (see below for nested schema)
	// +kubebuilder:validation:Optional
	TsigKey []ZoneTsigKeyParameters `json:"tsigKey,omitempty" tf:"tsig_key,omitempty"`

	// (String)
	// +kubebuilder:validation:Optional
	Type *string `json:"type,omitempty" tf:"type,omitempty"`

	// (String)
	// +kubebuilder:validation:Optional
	Zone *string `json:"zone,omitempty" tf:"zone,omitempty"`
}

type ZoneTsigKeyInitParameters struct {

	// md5, hmac-sha1, hmac-sha224, hmac-sha256, hmac-sha384, hmac-sha512, or HMAC-MD5.SIG-ALG.REG.INT.
	Algorithm *string `json:"algorithm,omitempty" tf:"algorithm,omitempty"`

	// (String) The zone name.
	Name *string `json:"name,omitempty" tf:"name,omitempty"`

	// encoded string of data. When decoded, it needs to contain the correct number of bits for the chosen algorithm. If the input isn't correctly padded, the server applies the padding.
	Secret *string `json:"secret,omitempty" tf:"secret,omitempty"`
}

type ZoneTsigKeyObservation struct {

	// md5, hmac-sha1, hmac-sha224, hmac-sha256, hmac-sha384, hmac-sha512, or HMAC-MD5.SIG-ALG.REG.INT.
	Algorithm *string `json:"algorithm,omitempty" tf:"algorithm,omitempty"`

	// (String) The zone name.
	Name *string `json:"name,omitempty" tf:"name,omitempty"`

	// encoded string of data. When decoded, it needs to contain the correct number of bits for the chosen algorithm. If the input isn't correctly padded, the server applies the padding.
	Secret *string `json:"secret,omitempty" tf:"secret,omitempty"`
}

type ZoneTsigKeyParameters struct {

	// md5, hmac-sha1, hmac-sha224, hmac-sha256, hmac-sha384, hmac-sha512, or HMAC-MD5.SIG-ALG.REG.INT.
	// +kubebuilder:validation:Optional
	Algorithm *string `json:"algorithm" tf:"algorithm,omitempty"`

	// (String) The zone name.
	// +kubebuilder:validation:Optional
	Name *string `json:"name" tf:"name,omitempty"`

	// encoded string of data. When decoded, it needs to contain the correct number of bits for the chosen algorithm. If the input isn't correctly padded, the server applies the padding.
	// +kubebuilder:validation:Optional
	Secret *string `json:"secret" tf:"secret,omitempty"`
}

// ZoneSpec defines the desired state of Zone
type ZoneSpec struct {
	v1.ResourceSpec `json:",inline"`
	ForProvider     ZoneParameters `json:"forProvider"`
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
	InitProvider ZoneInitParameters `json:"initProvider,omitempty"`
}

// ZoneStatus defines the observed state of Zone.
type ZoneStatus struct {
	v1.ResourceStatus `json:",inline"`
	AtProvider        ZoneObservation `json:"atProvider,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:storageversion

// Zone is the Schema for the Zones API.
// +kubebuilder:printcolumn:name="SYNCED",type="string",JSONPath=".status.conditions[?(@.type=='Synced')].status"
// +kubebuilder:printcolumn:name="READY",type="string",JSONPath=".status.conditions[?(@.type=='Ready')].status"
// +kubebuilder:printcolumn:name="EXTERNAL-NAME",type="string",JSONPath=".metadata.annotations.crossplane\\.io/external-name"
// +kubebuilder:printcolumn:name="AGE",type="date",JSONPath=".metadata.creationTimestamp"
// +kubebuilder:resource:scope=Cluster,categories={crossplane,managed,akamai}
type Zone struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`
	// +kubebuilder:validation:XValidation:rule="!('*' in self.managementPolicies || 'Create' in self.managementPolicies || 'Update' in self.managementPolicies) || has(self.forProvider.contract) || (has(self.initProvider) && has(self.initProvider.contract))",message="spec.forProvider.contract is a required parameter"
	// +kubebuilder:validation:XValidation:rule="!('*' in self.managementPolicies || 'Create' in self.managementPolicies || 'Update' in self.managementPolicies) || has(self.forProvider.type) || (has(self.initProvider) && has(self.initProvider.type))",message="spec.forProvider.type is a required parameter"
	// +kubebuilder:validation:XValidation:rule="!('*' in self.managementPolicies || 'Create' in self.managementPolicies || 'Update' in self.managementPolicies) || has(self.forProvider.zone) || (has(self.initProvider) && has(self.initProvider.zone))",message="spec.forProvider.zone is a required parameter"
	Spec   ZoneSpec   `json:"spec"`
	Status ZoneStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// ZoneList contains a list of Zones
type ZoneList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []Zone `json:"items"`
}

// Repository type metadata.
var (
	Zone_Kind             = "Zone"
	Zone_GroupKind        = schema.GroupKind{Group: CRDGroup, Kind: Zone_Kind}.String()
	Zone_KindAPIVersion   = Zone_Kind + "." + CRDGroupVersion.String()
	Zone_GroupVersionKind = CRDGroupVersion.WithKind(Zone_Kind)
)

func init() {
	SchemeBuilder.Register(&Zone{}, &ZoneList{})
}
