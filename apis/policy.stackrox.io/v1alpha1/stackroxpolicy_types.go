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
	commonv1 "github.com/stackrox/rox/pkg/apis/common/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// StackroxPolicySpec defines the desired state of StackroxPolicy
// This is for secured cluster namespace-scoped policies
type StackroxPolicySpec struct {
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:Pattern=`^[^\n\r\$]{5,128}$`
	// PolicyName is the name of the policy as it appears in alerts
	// This field must be unique within the namespace
	PolicyName string `json:"policyName"`

	// +kubebuilder:validation:Pattern=`^[^\$]{0,800}$`
	// Description is a free-form text description of this policy
	// +optional
	Description string `json:"description,omitempty"`

	// Rationale explains why this policy exists
	// +optional
	Rationale string `json:"rationale,omitempty"`

	// Remediation describes how to remediate a violation of this policy
	// +optional
	Remediation string `json:"remediation,omitempty"`

	// Disabled toggles whether this policy will execute and fire alerts
	// +optional
	Disabled bool `json:"disabled,omitempty"`

	// +kubebuilder:validation:MinItems=1
	// Categories is a list of categories that this policy falls under
	Categories []string `json:"categories"`

	// +kubebuilder:validation:MinItems=1
	// LifecycleStages describes which policy lifecycle stages this policy applies to
	// For secured cluster policies: Only DEPLOY and RUNTIME are allowed (no BUILD)
	LifecycleStages []commonv1.LifecycleStage `json:"lifecycleStages"`

	// EventSource describes which events should trigger execution of this policy
	// +optional
	EventSource commonv1.EventSource `json:"eventSource,omitempty"`

	// Exclusions define deployments or images that should be excluded from this policy
	// Supports workload label selectors for flexible exclusions
	// +optional
	Exclusions []commonv1.Exclusion `json:"exclusions,omitempty"`

	// Scope defines which workloads this policy targets within the policy's namespace
	// Namespace-scoped policies are automatically scoped to their own namespace
	// Only workload selectors are allowed
	// +optional
	Scope []commonv1.NamespaceScopedScope `json:"scope,omitempty"`

	// +kubebuilder:validation:Required
	// +kubebuilder:validation:Enum=UNSET_SEVERITY;LOW_SEVERITY;MEDIUM_SEVERITY;HIGH_SEVERITY;CRITICAL_SEVERITY
	// Severity defines how severe a violation from this policy is
	Severity string `json:"severity"`

	// EnforcementActions lists the enforcement actions to take when a violation is identified
	// +optional
	EnforcementActions []commonv1.EnforcementAction `json:"enforcementActions,omitempty"`

	// Notifiers is a list of names of notifiers that should be triggered
	// when a violation from this policy is identified
	// Note: Notifiers are resolved by sensor when sending alerts to Central
	// +optional
	Notifiers []string `json:"notifiers,omitempty"`

	// +kubebuilder:validation:MinItems=1
	// PolicySections define the violation criteria for this policy
	PolicySections []commonv1.PolicySection `json:"policySections"`

	// MitreAttackVectors maps this policy to the MITRE ATT&CK framework
	// +optional
	MitreAttackVectors []commonv1.MitreAttackVectors `json:"mitreAttackVectors,omitempty"`
}

// DeploymentReference identifies a deployment that violated a policy
type DeploymentReference struct {
	// Name is the deployment name
	// +kubebuilder:validation:Required
	Name string `json:"name"`

	// Namespace is the deployment namespace
	// Only populated for cluster-scoped policies
	// For namespace-scoped policies, the namespace is implicit
	// +optional
	Namespace string `json:"namespace,omitempty"`
}

// DeploymentViolation tracks violation metrics for a specific deployment
type DeploymentViolation struct {
	// DeploymentRef identifies the violating deployment
	// +kubebuilder:validation:Required
	DeploymentRef DeploymentReference `json:"deploymentRef"`

	// ViolationCount is the cumulative count of violations from this deployment
	// +kubebuilder:validation:Minimum=1
	ViolationCount int32 `json:"violationCount"`

	// LastTriggered is the timestamp of the most recent violation
	// +kubebuilder:validation:Required
	LastTriggered *metav1.Time `json:"lastTriggered"`
}

// NamespaceScopedViolationMetrics tracks violations for namespace-scoped policies
// Since these policies are implicitly scoped to their namespace, per-namespace
// violation counts are not meaningful
type NamespaceScopedViolationMetrics struct {
	// TotalViolations is the cumulative count of all violations detected
	// +optional
	TotalViolations int32 `json:"totalViolations,omitempty"`

	// LastViolationTime is the timestamp of the most recent violation
	// +optional
	LastViolationTime *metav1.Time `json:"lastViolationTime,omitempty"`

	// DeploymentViolations tracks per-deployment violation details
	// Limited to the most recent 100 deployments
	// +optional
	// +listType=atomic
	DeploymentViolations []DeploymentViolation `json:"deploymentViolations,omitempty"`
}

// ClusterScopedViolationMetrics tracks violations for cluster-scoped policies
type ClusterScopedViolationMetrics struct {
	// TotalViolations is the cumulative count of all violations detected
	// +optional
	TotalViolations int32 `json:"totalViolations,omitempty"`

	// LastViolationTime is the timestamp of the most recent violation
	// +optional
	LastViolationTime *metav1.Time `json:"lastViolationTime,omitempty"`

	// DeploymentViolations tracks per-deployment violation details
	// Limited to the most recent 100 deployments
	// +optional
	// +listType=atomic
	DeploymentViolations []DeploymentViolation `json:"deploymentViolations,omitempty"`
}

// StackroxPolicyStatus defines the observed state of StackroxPolicy
type StackroxPolicyStatus struct {
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

	// ViolationMetrics tracks violations detected by this policy
	// Updated periodically as violations occur
	// +optional
	ViolationMetrics *NamespaceScopedViolationMetrics `json:"violationMetrics,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:resource:shortName=srxp;sp
// +kubebuilder:subresource:status
// +kubebuilder:printcolumn:name="Policy Name",type=string,JSONPath=`.spec.policyName`
// +kubebuilder:printcolumn:name="Severity",type=string,JSONPath=`.spec.severity`
// +kubebuilder:printcolumn:name="Accepted",type=string,JSONPath=`.status.conditions[?(@.type=="AcceptedBySensor")].status`
// +kubebuilder:printcolumn:name="Age",type=date,JSONPath=`.metadata.creationTimestamp`

// StackroxPolicy is the schema for namespace-scoped policies in secured clusters
// These policies are evaluated locally and never sent to Central's policy API
// Policy definitions are sent to Central only when violations occur (embedded in alerts)
type StackroxPolicy struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   StackroxPolicySpec   `json:"spec,omitempty"`
	Status StackroxPolicyStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// StackroxPolicyList contains a list of StackroxPolicy
type StackroxPolicyList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []StackroxPolicy `json:"items"`
}

func init() {
	SchemeBuilder.Register(&StackroxPolicy{}, &StackroxPolicyList{})
}
