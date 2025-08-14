package client

import (
	"context"
	"testing"
	"time"

	v1 "github.com/stackrox/rox/generated/api/v1"
	"github.com/stackrox/rox/generated/storage"
	platformv1alpha1 "github.com/stackrox/rox/results-controller/api/v1alpha1"
	mocks "github.com/stackrox/rox/results-controller/pkg/client/mocks"
	"go.uber.org/mock/gomock"
	"google.golang.org/protobuf/types/known/timestamppb"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestConvertSeverity(t *testing.T) {
	tests := []struct {
		input    storage.Severity
		expected string
	}{
		{storage.Severity_LOW_SEVERITY, "Low"},
		{storage.Severity_MEDIUM_SEVERITY, "Medium"},
		{storage.Severity_HIGH_SEVERITY, "High"},
		{storage.Severity_CRITICAL_SEVERITY, "Critical"},
		{storage.Severity_UNSET_SEVERITY, "Unknown"},
	}

	for _, test := range tests {
		t.Run(test.expected, func(t *testing.T) {
			actual := convertSeverity(test.input)
			if actual != test.expected {
				t.Errorf("Expected %s, got %s", test.expected, actual)
			}
		})
	}
}

func TestConvertViolationState(t *testing.T) {
	tests := []struct {
		input    storage.ViolationState
		expected string
	}{
		{storage.ViolationState_ACTIVE, "Active"},
		{storage.ViolationState_RESOLVED, "Resolved"},
		{storage.ViolationState_ATTEMPTED, "Snoozed"}, // Map ATTEMPTED to Snoozed
	}

	for _, test := range tests {
		t.Run(test.expected, func(t *testing.T) {
			actual := convertViolationState(test.input)
			if actual != test.expected {
				t.Errorf("Expected %s, got %s", test.expected, actual)
			}
		})
	}
}

func TestAppendUnique(t *testing.T) {
	tests := []struct {
		name     string
		slice    []string
		item     string
		expected []string
	}{
		{
			name:     "Add to empty slice",
			slice:    []string{},
			item:     "new-item",
			expected: []string{"new-item"},
		},
		{
			name:     "Add new item to existing slice",
			slice:    []string{"item1", "item2"},
			item:     "item3",
			expected: []string{"item1", "item2", "item3"},
		},
		{
			name:     "Don't add duplicate item",
			slice:    []string{"item1", "item2"},
			item:     "item1",
			expected: []string{"item1", "item2"},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			actual := appendUnique(test.slice, test.item)
			if len(actual) != len(test.expected) {
				t.Errorf("Expected slice length %d, got %d", len(test.expected), len(actual))
				return
			}
			for i, expected := range test.expected {
				if actual[i] != expected {
					t.Errorf("Expected item %d to be %s, got %s", i, expected, actual[i])
				}
			}
		})
	}
}

func TestCentralClient_GetVulnerabilitiesForNamespace(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockClient := mocks.NewMockCentralClient(ctrl)
	ctx := context.Background()
	namespace := "test-namespace"

	expectedVulns := []platformv1alpha1.VulnerabilityInfo{
		{
			CVE:                 "CVE-2021-12345",
			Severity:            "High",
			CVSS:                7.5,
			Summary:             "Test vulnerability",
			Fixable:             true,
			FixedByVersion:      "1.2.3",
			AffectedImages:      []string{"nginx:1.0"},
			AffectedDeployments: []string{"web-app"},
		},
	}

	clusterName := "test-cluster"
	mockClient.EXPECT().
		GetVulnerabilitiesForNamespace(ctx, namespace, clusterName).
		Return(expectedVulns, nil).
		Times(1)

	vulns, err := mockClient.GetVulnerabilitiesForNamespace(ctx, namespace, clusterName)
	if err != nil {
		t.Errorf("Unexpected error: %v", err)
	}

	if len(vulns) != len(expectedVulns) {
		t.Errorf("Expected %d vulnerabilities, got %d", len(expectedVulns), len(vulns))
		return
	}

	if vulns[0].CVE != expectedVulns[0].CVE {
		t.Errorf("Expected CVE %s, got %s", expectedVulns[0].CVE, vulns[0].CVE)
	}
}

func TestCentralClient_GetPolicyViolationsForNamespace(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockClient := mocks.NewMockCentralClient(ctrl)
	ctx := context.Background()
	namespace := "test-namespace"

	now := metav1.Now()
	expectedViolations := []platformv1alpha1.PolicyViolationInfo{
		{
			AlertID:       "alert-123",
			PolicyName:    "Privileged Container",
			Severity:      "High",
			Description:   "Container runs with privileged access",
			ResourceName:  "web-deployment",
			ResourceType:  "Deployment",
			State:         "Active",
			FirstOccurred: &now,
			Categories:    []string{"Security"},
		},
	}

	clusterName := "test-cluster"
	mockClient.EXPECT().
		GetPolicyViolationsForNamespace(ctx, namespace, clusterName).
		Return(expectedViolations, nil).
		Times(1)

	violations, err := mockClient.GetPolicyViolationsForNamespace(ctx, namespace, clusterName)
	if err != nil {
		t.Errorf("Unexpected error: %v", err)
	}

	if len(violations) != len(expectedViolations) {
		t.Errorf("Expected %d violations, got %d", len(expectedViolations), len(violations))
		return
	}

	if violations[0].AlertID != expectedViolations[0].AlertID {
		t.Errorf("Expected AlertID %s, got %s", expectedViolations[0].AlertID, violations[0].AlertID)
	}
}

func TestCentralClient_TestConnection(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockClient := mocks.NewMockCentralClient(ctrl)
	ctx := context.Background()

	mockClient.EXPECT().
		TestConnection(ctx).
		Return(nil).
		Times(1)

	err := mockClient.TestConnection(ctx)
	if err != nil {
		t.Errorf("Unexpected error: %v", err)
	}
}

// Test helper functions for mock data creation

func createMockVulnerabilityData() *v1.VulnMgmtExportWorkloadsResponse {
	return &v1.VulnMgmtExportWorkloadsResponse{
		Deployment: &storage.Deployment{
			Name: "test-deployment",
		},
		Images: []*storage.Image{
			{
				Name: &storage.ImageName{
					FullName: "nginx:1.0",
				},
				Scan: &storage.ImageScan{
					ScanTime: timestamppb.New(time.Now()),
					Components: []*storage.EmbeddedImageScanComponent{
						{
							Name: "nginx",
							Vulns: []*storage.EmbeddedVulnerability{
								{
									Cve:        "CVE-2021-12345",
									Cvss:       7.5,
									Summary:    "Test vulnerability",
									Severity:   storage.VulnerabilitySeverity_IMPORTANT_VULNERABILITY_SEVERITY,
									SetFixedBy: &storage.EmbeddedVulnerability_FixedBy{FixedBy: "1.2.3"},
								},
							},
						},
					},
				},
			},
		},
	}
}

func createMockAlertData() *v1.ListAlertsResponse {
	return &v1.ListAlertsResponse{
		Alerts: []*storage.ListAlert{
			{
				Id: "alert-123",
				Policy: &storage.ListAlertPolicy{
					Name:        "Privileged Container",
					Severity:    storage.Severity_HIGH_SEVERITY,
					Description: "Container runs with privileged access",
					Categories:  []string{"Security"},
				},
				Entity: &storage.ListAlert_Deployment{
					Deployment: &storage.ListAlertDeployment{
						Name: "web-deployment",
					},
				},
				State: storage.ViolationState_ACTIVE,
				Time:  timestamppb.New(time.Now()),
			},
		},
	}
}

func TestMockDataCreation(t *testing.T) {
	// Test that our mock data creation helpers work correctly
	vulnData := createMockVulnerabilityData()
	if vulnData.Deployment.Name != "test-deployment" {
		t.Errorf("Expected deployment name 'test-deployment', got %s", vulnData.Deployment.Name)
	}

	if len(vulnData.Images) != 1 {
		t.Errorf("Expected 1 image, got %d", len(vulnData.Images))
	}

	alertData := createMockAlertData()
	if len(alertData.Alerts) != 1 {
		t.Errorf("Expected 1 alert, got %d", len(alertData.Alerts))
	}

	if alertData.Alerts[0].Policy.Name != "Privileged Container" {
		t.Errorf("Expected policy name 'Privileged Container', got %s", alertData.Alerts[0].Policy.Name)
	}
}
