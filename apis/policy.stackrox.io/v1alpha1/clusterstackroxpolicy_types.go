/*
Copyright 2024.

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
)

// ClusterStackroxPolicySpec defines the desired state of ClusterStackroxPolicy
// This is identical to StackroxPolicySpec but for cluster-scoped policies
// Cluster-scoped policies can target resources across all namespaces in the cluster
type ClusterStackroxPolicySpec = StackroxPolicySpec

// ClusterStackroxPolicyStatus defines the observed state of ClusterStackroxPolicy
type ClusterStackroxPolicyStatus struct {
	// Conditions represent the latest available observations of the policy's state
	// +optional
	Conditions []metav1.Condition `json:"conditions,omitempty"`

	// LocalPolicyID is the ID generated locally for this policy
	// This ID is used by sensor for policy evaluation and alert generation
	// +optional
	LocalPolicyID string `json:"localPolicyId,omitempty"`

	// LastEvaluated is the timestamp of the last policy evaluation
	// +optional
	LastEvaluated *metav1.Time `json:"lastEvaluated,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:resource:scope=Cluster,shortName=csrxp;csp
// +kubebuilder:subresource:status
// +kubebuilder:printcolumn:name="Policy Name",type=string,JSONPath=`.spec.policyName`
// +kubebuilder:printcolumn:name="Severity",type=string,JSONPath=`.spec.severity`
// +kubebuilder:printcolumn:name="Accepted",type=string,JSONPath=`.status.conditions[?(@.type=="AcceptedBySensor")].status`
// +kubebuilder:printcolumn:name="Age",type=date,JSONPath=`.metadata.creationTimestamp`

// ClusterStackroxPolicy is the schema for cluster-scoped policies in secured clusters
// These policies are evaluated locally and never sent to Central's policy API
// Policy definitions are sent to Central only when violations occur (embedded in alerts)
// Cluster-scoped policies can target resources across all namespaces
type ClusterStackroxPolicy struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   ClusterStackroxPolicySpec   `json:"spec,omitempty"`
	Status ClusterStackroxPolicyStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// ClusterStackroxPolicyList contains a list of ClusterStackroxPolicy
type ClusterStackroxPolicyList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []ClusterStackroxPolicy `json:"items"`
}

func init() {
	SchemeBuilder.Register(&ClusterStackroxPolicy{}, &ClusterStackroxPolicyList{})
}
