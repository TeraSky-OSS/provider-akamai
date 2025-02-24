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

type UploadCertificateInitParameters struct {

	// Whether to acknowledge change management
	AcknowledgeChangeManagement *bool `json:"acknowledgeChangeManagement,omitempty" tf:"acknowledge_change_management,omitempty"`

	// Whether to acknowledge post-verification warnings
	AcknowledgePostVerificationWarnings *bool `json:"acknowledgePostVerificationWarnings,omitempty" tf:"acknowledge_post_verification_warnings,omitempty"`

	// List of post-verification warnings to be automatically acknowledged
	// +listType=set
	AutoApproveWarnings []*string `json:"autoApproveWarnings,omitempty" tf:"auto_approve_warnings,omitempty"`

	// ECDSA certificate in pem format to be uploaded
	CertificateEcdsaPem *string `json:"certificateEcdsaPem,omitempty" tf:"certificate_ecdsa_pem,omitempty"`

	// RSA certificate in pem format to be uploaded
	CertificateRsaPem *string `json:"certificateRsaPem,omitempty" tf:"certificate_rsa_pem,omitempty"`

	// The unique identifier of the enrollment
	EnrollmentID *float64 `json:"enrollmentId,omitempty" tf:"enrollment_id,omitempty"`

	// Trust chain in pem format for provided ECDSA certificate
	TrustChainEcdsaPem *string `json:"trustChainEcdsaPem,omitempty" tf:"trust_chain_ecdsa_pem,omitempty"`

	// Trust chain in pem format for provided RSA certificate
	TrustChainRsaPem *string `json:"trustChainRsaPem,omitempty" tf:"trust_chain_rsa_pem,omitempty"`

	// Whether to wait for certificate to be deployed
	WaitForDeployment *bool `json:"waitForDeployment,omitempty" tf:"wait_for_deployment,omitempty"`
}

type UploadCertificateObservation struct {

	// Whether to acknowledge change management
	AcknowledgeChangeManagement *bool `json:"acknowledgeChangeManagement,omitempty" tf:"acknowledge_change_management,omitempty"`

	// Whether to acknowledge post-verification warnings
	AcknowledgePostVerificationWarnings *bool `json:"acknowledgePostVerificationWarnings,omitempty" tf:"acknowledge_post_verification_warnings,omitempty"`

	// List of post-verification warnings to be automatically acknowledged
	// +listType=set
	AutoApproveWarnings []*string `json:"autoApproveWarnings,omitempty" tf:"auto_approve_warnings,omitempty"`

	// ECDSA certificate in pem format to be uploaded
	CertificateEcdsaPem *string `json:"certificateEcdsaPem,omitempty" tf:"certificate_ecdsa_pem,omitempty"`

	// RSA certificate in pem format to be uploaded
	CertificateRsaPem *string `json:"certificateRsaPem,omitempty" tf:"certificate_rsa_pem,omitempty"`

	// The unique identifier of the enrollment
	EnrollmentID *float64 `json:"enrollmentId,omitempty" tf:"enrollment_id,omitempty"`

	ID *string `json:"id,omitempty" tf:"id,omitempty"`

	// Trust chain in pem format for provided ECDSA certificate
	TrustChainEcdsaPem *string `json:"trustChainEcdsaPem,omitempty" tf:"trust_chain_ecdsa_pem,omitempty"`

	// Trust chain in pem format for provided RSA certificate
	TrustChainRsaPem *string `json:"trustChainRsaPem,omitempty" tf:"trust_chain_rsa_pem,omitempty"`

	// Whether to wait for certificate to be deployed
	WaitForDeployment *bool `json:"waitForDeployment,omitempty" tf:"wait_for_deployment,omitempty"`
}

type UploadCertificateParameters struct {

	// Whether to acknowledge change management
	// +kubebuilder:validation:Optional
	AcknowledgeChangeManagement *bool `json:"acknowledgeChangeManagement,omitempty" tf:"acknowledge_change_management,omitempty"`

	// Whether to acknowledge post-verification warnings
	// +kubebuilder:validation:Optional
	AcknowledgePostVerificationWarnings *bool `json:"acknowledgePostVerificationWarnings,omitempty" tf:"acknowledge_post_verification_warnings,omitempty"`

	// List of post-verification warnings to be automatically acknowledged
	// +kubebuilder:validation:Optional
	// +listType=set
	AutoApproveWarnings []*string `json:"autoApproveWarnings,omitempty" tf:"auto_approve_warnings,omitempty"`

	// ECDSA certificate in pem format to be uploaded
	// +kubebuilder:validation:Optional
	CertificateEcdsaPem *string `json:"certificateEcdsaPem,omitempty" tf:"certificate_ecdsa_pem,omitempty"`

	// RSA certificate in pem format to be uploaded
	// +kubebuilder:validation:Optional
	CertificateRsaPem *string `json:"certificateRsaPem,omitempty" tf:"certificate_rsa_pem,omitempty"`

	// The unique identifier of the enrollment
	// +kubebuilder:validation:Optional
	EnrollmentID *float64 `json:"enrollmentId,omitempty" tf:"enrollment_id,omitempty"`

	// Trust chain in pem format for provided ECDSA certificate
	// +kubebuilder:validation:Optional
	TrustChainEcdsaPem *string `json:"trustChainEcdsaPem,omitempty" tf:"trust_chain_ecdsa_pem,omitempty"`

	// Trust chain in pem format for provided RSA certificate
	// +kubebuilder:validation:Optional
	TrustChainRsaPem *string `json:"trustChainRsaPem,omitempty" tf:"trust_chain_rsa_pem,omitempty"`

	// Whether to wait for certificate to be deployed
	// +kubebuilder:validation:Optional
	WaitForDeployment *bool `json:"waitForDeployment,omitempty" tf:"wait_for_deployment,omitempty"`
}

// UploadCertificateSpec defines the desired state of UploadCertificate
type UploadCertificateSpec struct {
	v1.ResourceSpec `json:",inline"`
	ForProvider     UploadCertificateParameters `json:"forProvider"`
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
	InitProvider UploadCertificateInitParameters `json:"initProvider,omitempty"`
}

// UploadCertificateStatus defines the observed state of UploadCertificate.
type UploadCertificateStatus struct {
	v1.ResourceStatus `json:",inline"`
	AtProvider        UploadCertificateObservation `json:"atProvider,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:storageversion

// UploadCertificate is the Schema for the UploadCertificates API. <no value>
// +kubebuilder:printcolumn:name="SYNCED",type="string",JSONPath=".status.conditions[?(@.type=='Synced')].status"
// +kubebuilder:printcolumn:name="READY",type="string",JSONPath=".status.conditions[?(@.type=='Ready')].status"
// +kubebuilder:printcolumn:name="EXTERNAL-NAME",type="string",JSONPath=".metadata.annotations.crossplane\\.io/external-name"
// +kubebuilder:printcolumn:name="AGE",type="date",JSONPath=".metadata.creationTimestamp"
// +kubebuilder:resource:scope=Cluster,categories={crossplane,managed,akamai}
type UploadCertificate struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`
	// +kubebuilder:validation:XValidation:rule="!('*' in self.managementPolicies || 'Create' in self.managementPolicies || 'Update' in self.managementPolicies) || has(self.forProvider.enrollmentId) || (has(self.initProvider) && has(self.initProvider.enrollmentId))",message="spec.forProvider.enrollmentId is a required parameter"
	Spec   UploadCertificateSpec   `json:"spec"`
	Status UploadCertificateStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// UploadCertificateList contains a list of UploadCertificates
type UploadCertificateList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []UploadCertificate `json:"items"`
}

// Repository type metadata.
var (
	UploadCertificate_Kind             = "UploadCertificate"
	UploadCertificate_GroupKind        = schema.GroupKind{Group: CRDGroup, Kind: UploadCertificate_Kind}.String()
	UploadCertificate_KindAPIVersion   = UploadCertificate_Kind + "." + CRDGroupVersion.String()
	UploadCertificate_GroupVersionKind = CRDGroupVersion.WithKind(UploadCertificate_Kind)
)

func init() {
	SchemeBuilder.Register(&UploadCertificate{}, &UploadCertificateList{})
}
