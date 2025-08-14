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
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestStackRoxResultsStatus_UpdateVulnerabilitySummary(t *testing.T) {
	status := &StackRoxResultsStatus{
		Vulnerabilities: []VulnerabilityInfo{
			{CVE: "CVE-2021-1", Severity: "High"},
			{CVE: "CVE-2021-2", Severity: "High"},
			{CVE: "CVE-2021-3", Severity: "Medium"},
			{CVE: "CVE-2021-4", Severity: "Low"},
			{CVE: "CVE-2021-5", Severity: "Critical"},
		},
	}

	status.UpdateVulnerabilitySummary()

	expected := map[string]int32{
		"High":     2,
		"Medium":   1,
		"Low":      1,
		"Critical": 1,
	}

	if len(status.VulnerabilitySummary) != len(expected) {
		t.Errorf("Expected %d summary entries, got %d", len(expected), len(status.VulnerabilitySummary))
	}

	for severity, expectedCount := range expected {
		if actualCount := status.VulnerabilitySummary[severity]; actualCount != expectedCount {
			t.Errorf("Expected %d %s vulnerabilities, got %d", expectedCount, severity, actualCount)
		}
	}
}

func TestStackRoxResultsStatus_UpdatePolicyViolationSummary(t *testing.T) {
	status := &StackRoxResultsStatus{
		PolicyViolations: []PolicyViolationInfo{
			{AlertID: "alert-1", Severity: "Critical"},
			{AlertID: "alert-2", Severity: "High"},
			{AlertID: "alert-3", Severity: "High"},
			{AlertID: "alert-4", Severity: "Medium"},
		},
	}

	status.UpdatePolicyViolationSummary()

	expected := map[string]int32{
		"Critical": 1,
		"High":     2,
		"Medium":   1,
	}

	if len(status.PolicyViolationSummary) != len(expected) {
		t.Errorf("Expected %d summary entries, got %d", len(expected), len(status.PolicyViolationSummary))
	}

	for severity, expectedCount := range expected {
		if actualCount := status.PolicyViolationSummary[severity]; actualCount != expectedCount {
			t.Errorf("Expected %d %s policy violations, got %d", expectedCount, severity, actualCount)
		}
	}
}

func TestStackRoxResultsStatus_GetVulnerabilityCountBySeverity(t *testing.T) {
	status := &StackRoxResultsStatus{
		VulnerabilitySummary: map[string]int32{
			"High":   5,
			"Medium": 3,
			"Low":    1,
		},
	}

	tests := []struct {
		severity string
		expected int32
	}{
		{"High", 5},
		{"Medium", 3},
		{"Low", 1},
		{"Critical", 0}, // Not present in summary
	}

	for _, test := range tests {
		actual := status.GetVulnerabilityCountBySeverity(test.severity)
		if actual != test.expected {
			t.Errorf("Expected %d %s vulnerabilities, got %d", test.expected, test.severity, actual)
		}
	}
}

func TestStackRoxResultsStatus_GetPolicyViolationCountBySeverity(t *testing.T) {
	status := &StackRoxResultsStatus{
		PolicyViolationSummary: map[string]int32{
			"Critical": 2,
			"High":     4,
			"Medium":   1,
		},
	}

	tests := []struct {
		severity string
		expected int32
	}{
		{"Critical", 2},
		{"High", 4},
		{"Medium", 1},
		{"Low", 0}, // Not present in summary
	}

	for _, test := range tests {
		actual := status.GetPolicyViolationCountBySeverity(test.severity)
		if actual != test.expected {
			t.Errorf("Expected %d %s policy violations, got %d", test.expected, test.severity, actual)
		}
	}
}

func TestStackRoxResultsStatus_IsReady(t *testing.T) {
	tests := []struct {
		name     string
		status   string
		expected bool
	}{
		{"Ready status", "Ready", true},
		{"Error status", "Error", false},
		{"Syncing status", "Syncing", false},
		{"Unknown status", "Unknown", false},
		{"Empty status", "", false},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			status := &StackRoxResultsStatus{
				SyncStatus: test.status,
			}
			actual := status.IsReady()
			if actual != test.expected {
				t.Errorf("Expected IsReady() to return %v for status %s, got %v", test.expected, test.status, actual)
			}
		})
	}
}

func TestStackRoxResultsStatus_HasError(t *testing.T) {
	tests := []struct {
		name     string
		status   string
		expected bool
	}{
		{"Error status", "Error", true},
		{"Ready status", "Ready", false},
		{"Syncing status", "Syncing", false},
		{"Unknown status", "Unknown", false},
		{"Empty status", "", false},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			status := &StackRoxResultsStatus{
				SyncStatus: test.status,
			}
			actual := status.HasError()
			if actual != test.expected {
				t.Errorf("Expected HasError() to return %v for status %s, got %v", test.expected, test.status, actual)
			}
		})
	}
}

func TestVulnerabilityInfo_Validation(t *testing.T) {
	tests := []struct {
		name  string
		vuln  VulnerabilityInfo
		valid bool
	}{
		{
			name: "Valid vulnerability",
			vuln: VulnerabilityInfo{
				CVE:      "CVE-2021-12345",
				Severity: "High",
				CVSS:     7.5,
				Fixable:  true,
			},
			valid: true,
		},
		{
			name: "Valid vulnerability with affected resources",
			vuln: VulnerabilityInfo{
				CVE:                 "CVE-2021-54321",
				Severity:            "Critical",
				CVSS:                9.0,
				Fixable:             false,
				AffectedImages:      []string{"nginx:1.0", "redis:5.0"},
				AffectedDeployments: []string{"web-app", "cache"},
			},
			valid: true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			// Basic validation - ensure required fields are set
			if test.vuln.CVE == "" && test.valid {
				t.Error("Valid vulnerability should have CVE set")
			}
			if test.vuln.Severity == "" && test.valid {
				t.Error("Valid vulnerability should have Severity set")
			}
		})
	}
}

func TestPolicyViolationInfo_Validation(t *testing.T) {
	now := metav1.Now()

	tests := []struct {
		name      string
		violation PolicyViolationInfo
		valid     bool
	}{
		{
			name: "Valid policy violation",
			violation: PolicyViolationInfo{
				AlertID:       "alert-123",
				PolicyName:    "Privileged Container",
				Severity:      "High",
				Description:   "Container runs with privileged access",
				ResourceName:  "web-deployment",
				ResourceType:  "Deployment",
				State:         "Active",
				FirstOccurred: &now,
			},
			valid: true,
		},
		{
			name: "Valid violation with categories",
			violation: PolicyViolationInfo{
				AlertID:    "alert-456",
				PolicyName: "Unscanned Image",
				Severity:   "Medium",
				State:      "Active",
				Categories: []string{"Security", "DevOps"},
			},
			valid: true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			// Basic validation - ensure required fields are set
			if test.violation.AlertID == "" && test.valid {
				t.Error("Valid violation should have AlertID set")
			}
			if test.violation.PolicyName == "" && test.valid {
				t.Error("Valid violation should have PolicyName set")
			}
			if test.violation.Severity == "" && test.valid {
				t.Error("Valid violation should have Severity set")
			}
		})
	}
}
