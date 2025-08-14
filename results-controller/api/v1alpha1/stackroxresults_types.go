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

// VulnerabilityInfo represents a vulnerability found in images within the namespace
type VulnerabilityInfo struct {
	// CVE identifier for the vulnerability
	// +kubebuilder:validation:Required
	CVE string `json:"cve"`

	// Severity of the vulnerability (Low, Medium, High, Critical)
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:Enum=Low;Medium;High;Critical;Unknown
	Severity string `json:"severity"`

	// CVSS score for the vulnerability
	// +kubebuilder:validation:Minimum=0
	// +kubebuilder:validation:Maximum=10
	CVSS float64 `json:"cvss"`

	// Summary description of the vulnerability
	Summary string `json:"summary,omitempty"`

	// Whether this vulnerability is fixable
	Fixable bool `json:"fixable"`

	// Version that fixes this vulnerability, if available
	FixedByVersion string `json:"fixedByVersion,omitempty"`

	// List of images in this namespace affected by this vulnerability
	// +kubebuilder:validation:MaxItems=50
	AffectedImages []string `json:"affectedImages,omitempty"`

	// List of deployments in this namespace affected by this vulnerability
	// +kubebuilder:validation:MaxItems=50
	AffectedDeployments []string `json:"affectedDeployments,omitempty"`

	// When this vulnerability was first discovered in the system
	DiscoveredAt *metav1.Time `json:"discoveredAt,omitempty"`

	// When this vulnerability was last scanned
	LastScanned *metav1.Time `json:"lastScanned,omitempty"`
}

// PolicyViolationInfo represents a policy violation (alert) within the namespace
type PolicyViolationInfo struct {
	// Unique identifier for the alert
	// +kubebuilder:validation:Required
	AlertID string `json:"alertId"`

	// Name of the policy that was violated
	// +kubebuilder:validation:Required
	PolicyName string `json:"policyName"`

	// Severity of the policy violation (Low, Medium, High, Critical)
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:Enum=Low;Medium;High;Critical
	Severity string `json:"severity"`

	// Description of what was violated
	Description string `json:"description,omitempty"`

	// Remediation advice for fixing the violation
	Remediation string `json:"remediation,omitempty"`

	// Resource that triggered the violation (deployment, pod, etc.)
	ResourceName string `json:"resourceName,omitempty"`

	// Type of resource that triggered the violation
	ResourceType string `json:"resourceType,omitempty"`

	// When this violation was first detected
	FirstOccurred *metav1.Time `json:"firstOccurred,omitempty"`

	// When this violation was last seen
	LastOccurred *metav1.Time `json:"lastOccurred,omitempty"`

	// Current state of the violation (Active, Resolved, Snoozed)
	// +kubebuilder:validation:Enum=Active;Resolved;Snoozed
	State string `json:"state,omitempty"`

	// Categories this policy belongs to
	Categories []string `json:"categories,omitempty"`
}

// StackRoxResultsSpec defines the desired state of StackRoxResults
// Note: This is intentionally empty as StackRoxResults is status-only
type StackRoxResultsSpec struct {
	// INSERT ADDITIONAL SPEC FIELDS - desired state of cluster
	// Important: Run "make" to regenerate code after modifying this file
}

// StackRoxResultsStatus defines the observed state of StackRoxResults
type StackRoxResultsStatus struct {
	// Vulnerabilities found in images within this namespace
	// +kubebuilder:validation:MaxItems=100
	Vulnerabilities []VulnerabilityInfo `json:"vulnerabilities,omitempty"`

	// Policy violations (alerts) within this namespace
	// +kubebuilder:validation:MaxItems=50
	PolicyViolations []PolicyViolationInfo `json:"policyViolations,omitempty"`

	// When the results were last synchronized from Central
	LastSyncTime *metav1.Time `json:"lastSyncTime,omitempty"`

	// Status of the last synchronization attempt
	// +kubebuilder:validation:Enum=Ready;Error;Syncing;Unknown
	SyncStatus string `json:"syncStatus,omitempty"`

	// Message providing additional details about the sync status
	SyncMessage string `json:"syncMessage,omitempty"`

	// Number of total vulnerabilities found (may exceed the displayed limit)
	TotalVulnerabilities int32 `json:"totalVulnerabilities,omitempty"`

	// Number of total policy violations found (may exceed the displayed limit)
	TotalPolicyViolations int32 `json:"totalPolicyViolations,omitempty"`

	// Summary counts by severity for vulnerabilities
	VulnerabilitySummary map[string]int32 `json:"vulnerabilitySummary,omitempty"`

	// Summary counts by severity for policy violations
	PolicyViolationSummary map[string]int32 `json:"policyViolationSummary,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:resource:shortName=srr
// +kubebuilder:subresource:status
// +kubebuilder:printcolumn:name="Vulnerabilities",type="integer",JSONPath=".status.totalVulnerabilities"
// +kubebuilder:printcolumn:name="Violations",type="integer",JSONPath=".status.totalPolicyViolations"
// +kubebuilder:printcolumn:name="Status",type="string",JSONPath=".status.syncStatus"
// +kubebuilder:printcolumn:name="Last Sync",type="date",JSONPath=".status.lastSyncTime"
// +kubebuilder:printcolumn:name="Age",type="date",JSONPath=".metadata.creationTimestamp"

// +kubebuilder:resource:path=stackroxresults
// StackRoxResults is the Schema for the stackroxresults API
// This resource provides a read-only view of StackRox security results for a specific namespace,
// enabling Kubernetes RBAC-based access to vulnerability and policy violation data.
type StackRoxResults struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   StackRoxResultsSpec   `json:"spec,omitempty"`
	Status StackRoxResultsStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// StackRoxResultsList contains a list of StackRoxResults
type StackRoxResultsList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []StackRoxResults `json:"items"`
}

func init() {
	SchemeBuilder.Register(&StackRoxResults{}, &StackRoxResultsList{})
}

// GetVulnerabilityCountBySeverity returns the count of vulnerabilities by severity
func (r *StackRoxResultsStatus) GetVulnerabilityCountBySeverity(severity string) int32 {
	if r.VulnerabilitySummary == nil {
		return 0
	}
	return r.VulnerabilitySummary[severity]
}

// GetPolicyViolationCountBySeverity returns the count of policy violations by severity
func (r *StackRoxResultsStatus) GetPolicyViolationCountBySeverity(severity string) int32 {
	if r.PolicyViolationSummary == nil {
		return 0
	}
	return r.PolicyViolationSummary[severity]
}

// UpdateVulnerabilitySummary recalculates the vulnerability summary from the current vulnerabilities
func (r *StackRoxResultsStatus) UpdateVulnerabilitySummary() {
	if r.VulnerabilitySummary == nil {
		r.VulnerabilitySummary = make(map[string]int32)
	}

	// Reset counts
	for k := range r.VulnerabilitySummary {
		r.VulnerabilitySummary[k] = 0
	}

	// Count by severity
	for _, vuln := range r.Vulnerabilities {
		r.VulnerabilitySummary[vuln.Severity]++
	}
}

// UpdatePolicyViolationSummary recalculates the policy violation summary from the current violations
func (r *StackRoxResultsStatus) UpdatePolicyViolationSummary() {
	if r.PolicyViolationSummary == nil {
		r.PolicyViolationSummary = make(map[string]int32)
	}

	// Reset counts
	for k := range r.PolicyViolationSummary {
		r.PolicyViolationSummary[k] = 0
	}

	// Count by severity
	for _, violation := range r.PolicyViolations {
		r.PolicyViolationSummary[violation.Severity]++
	}
}

// IsReady returns true if the sync status indicates the results are ready
func (r *StackRoxResultsStatus) IsReady() bool {
	return r.SyncStatus == "Ready"
}

// HasError returns true if the sync status indicates an error
func (r *StackRoxResultsStatus) HasError() bool {
	return r.SyncStatus == "Error"
}
