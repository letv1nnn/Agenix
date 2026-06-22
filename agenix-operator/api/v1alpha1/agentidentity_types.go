/*
Copyright 2026.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
)

// EDIT THIS FILE!  THIS IS SCAFFOLDING FOR YOU TO OWN!
// NOTE: json tags are required.  Any new fields you add must have json tags for the fields to be serialized.

// TargetRef identifies the Deployment this identity is for
type TargetRef struct {
	APIVersion string `json:"apiVersion"`
	Kind       string `json:"kind"`
	Name       string `json:"name"`
}

// IdentityConfig holds identity settings
type IdentityConfig struct {
	TrustDomain string `json:"trustDomain"`
	TTL         string `json:"ttl"`
	AutoRotate  bool   `json:"autoRotate"`
}

// AgentIdentitySpec defines the desired state of AgentIdentity
type AgentIdentitySpec struct {
	// Important: Run "make" to regenerate code after modifying this file
	// The following markers will use OpenAPI v3 schema to validate the value
	// More info: https://book.kubebuilder.io/reference/markers/crd-validation.html

	// targetRef is a reference to the Deployment this identity is for
	TargetRef TargetRef `json:"targetRef"`
	// identity holds the identity configuration
	Identity IdentityConfig `json:"identity"`
}

// CertificateInfo holds details about the issued certificate
type CertificateInfo struct {
	SerialNumber string      `json:"serialNumber"`
	NotBefore    metav1.Time `json:"notBefore"`
	NotAfter     metav1.Time `json:"notAfter"`
	Fingerprint  string      `json:"fingerprint"`
}

// AgentIdentityStatus defines the observed state of AgentIdentity.
type AgentIdentityStatus struct {
	// phase is the current state: Pending, Provisioned, Verified, Expired, Error
	Phase string `json:"phase,omitempty"`
	// agentID is the generated SPIFFE-style ID
	AgentID string `json:"agentID,omitempty"`
	// certificate holds details about the issued certificate
	Certificate CertificateInfo `json:"certificate,omitempty"`
	// +listType=map
	// +listMapKey=type
	// +optional
	Conditions []metav1.Condition `json:"conditions,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:printcolumn:name="Phase",type=string,JSONPath=".status.phase"
// +kubebuilder:printcolumn:name="Agent-ID",type=string,JSONPath=".status.agentID"

// AgentIdentity is the Schema for the agentidentities API
type AgentIdentity struct {
	metav1.TypeMeta `json:",inline"`

	// metadata is a standard object metadata
	// +optional
	metav1.ObjectMeta `json:"metadata,omitzero"`

	// spec defines the desired state of AgentIdentity
	// +required
	Spec AgentIdentitySpec `json:"spec"`

	// status defines the observed state of AgentIdentity
	// +optional
	Status AgentIdentityStatus `json:"status,omitzero"`
}

// +kubebuilder:object:root=true

// AgentIdentityList contains a list of AgentIdentity
type AgentIdentityList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitzero"`
	Items           []AgentIdentity `json:"items"`
}

func init() {
	SchemeBuilder.Register(func(s *runtime.Scheme) error {
		s.AddKnownTypes(SchemeGroupVersion, &AgentIdentity{}, &AgentIdentityList{})
		return nil
	})
}
