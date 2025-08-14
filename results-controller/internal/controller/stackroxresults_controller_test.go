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

package controller

import (
	"context"
	"os"
	"testing"
	"time"

	"go.uber.org/mock/gomock"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	platformv1alpha1 "github.com/stackrox/rox/results-controller/api/v1alpha1"
	mocks "github.com/stackrox/rox/results-controller/pkg/client/mocks"
)

func TestStackRoxResultsReconciler_Reconcile(t *testing.T) {
	// Setup scheme
	s := runtime.NewScheme()
	_ = platformv1alpha1.AddToScheme(s)
	_ = corev1.AddToScheme(s)

	tests := []struct {
		name            string
		existingObjects []runtime.Object
		setupMock       func(*mocks.MockCentralClient)
		expectedResult  ctrl.Result
		expectError     bool
		validate        func(t *testing.T, r *StackRoxResultsReconciler)
	}{
		{
			name: "Successful reconcile with existing StackRoxResults",
			existingObjects: []runtime.Object{
				&platformv1alpha1.StackRoxResults{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "stackrox-results",
						Namespace: "test-namespace",
					},
					Status: platformv1alpha1.StackRoxResultsStatus{
						SyncStatus: "Ready",
					},
				},
			},
			setupMock: func(mockClient *mocks.MockCentralClient) {
				// No expectations since reconcile doesn't call Central directly in new architecture
			},
			expectedResult: ctrl.Result{},
			expectError:    false,
			validate: func(t *testing.T, r *StackRoxResultsReconciler) {
				// Just verify the resource still exists
				var stackroxResults platformv1alpha1.StackRoxResults
				err := r.Get(context.Background(), types.NamespacedName{
					Name:      "stackrox-results",
					Namespace: "test-namespace",
				}, &stackroxResults)
				if err != nil {
					t.Errorf("Failed to get StackRoxResults: %v", err)
				}
			},
		},
		{
			name:            "Resource not found",
			existingObjects: []runtime.Object{},
			setupMock: func(mockClient *mocks.MockCentralClient) {
				// No expectations for mock client since resource doesn't exist
			},
			expectedResult: ctrl.Result{},
			expectError:    false,
			validate: func(t *testing.T, r *StackRoxResultsReconciler) {
				// Nothing to validate since resource doesn't exist
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			// Create mock controller
			ctrl := gomock.NewController(t)
			defer ctrl.Finish()

			mockCentralClient := mocks.NewMockCentralClient(ctrl)
			test.setupMock(mockCentralClient)

			// Create fake client with existing objects
			fakeClient := fake.NewClientBuilder().
				WithScheme(s).
				WithRuntimeObjects(test.existingObjects...).
				WithStatusSubresource(&platformv1alpha1.StackRoxResults{}).
				Build()

			// Create reconciler
			reconciler := &StackRoxResultsReconciler{
				Client:        fakeClient,
				Scheme:        s,
				CentralClient: mockCentralClient,
				syncInterval:  DefaultSyncInterval,
			}

			// Create reconcile request
			req := reconcile.Request{
				NamespacedName: types.NamespacedName{
					Name:      "stackrox-results",
					Namespace: "test-namespace",
				},
			}

			// Execute reconcile
			result, err := reconciler.Reconcile(context.Background(), req)

			// Validate results
			if test.expectError && err == nil {
				t.Error("Expected error but got none")
			}
			if !test.expectError && err != nil {
				t.Errorf("Unexpected error: %v", err)
			}

			// Check result
			if result != test.expectedResult {
				t.Errorf("Expected result %v, got %v", test.expectedResult, result)
			}

			// Run custom validation
			if test.validate != nil {
				test.validate(t, reconciler)
			}
		})
	}
}

// Test the background sync functionality
func TestStackRoxResultsReconciler_SyncNamespace(t *testing.T) {
	// Setup scheme
	s := runtime.NewScheme()
	_ = platformv1alpha1.AddToScheme(s)
	_ = corev1.AddToScheme(s)

	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockCentralClient := mocks.NewMockCentralClient(ctrl)

	namespace := "test-namespace"
	clusterName := "test-cluster"

	// Setup mock expectations
	mockCentralClient.EXPECT().
		GetVulnerabilitiesForNamespace(gomock.Any(), namespace, clusterName).
		Return([]platformv1alpha1.VulnerabilityInfo{
			{
				CVE:      "CVE-2021-12345",
				Severity: "High",
				CVSS:     7.5,
			},
		}, nil).
		Times(1)

	mockCentralClient.EXPECT().
		GetPolicyViolationsForNamespace(gomock.Any(), namespace, clusterName).
		Return([]platformv1alpha1.PolicyViolationInfo{
			{
				AlertID:    "alert-123",
				PolicyName: "Test Policy",
				Severity:   "Medium",
			},
		}, nil).
		Times(1)

	// Create fake client
	fakeClient := fake.NewClientBuilder().
		WithScheme(s).
		WithStatusSubresource(&platformv1alpha1.StackRoxResults{}).
		Build()

	// Create reconciler
	reconciler := &StackRoxResultsReconciler{
		Client:        fakeClient,
		Scheme:        s,
		CentralClient: mockCentralClient,
		syncInterval:  DefaultSyncInterval,
	}

	// Test syncNamespace (this creates the resource lazily)
	err := reconciler.syncNamespace(context.Background(), namespace, clusterName)
	if err != nil {
		t.Errorf("Unexpected error: %v", err)
	}

	// Verify the StackRoxResults was created and updated
	var stackroxResults platformv1alpha1.StackRoxResults
	err = reconciler.Get(context.Background(), types.NamespacedName{
		Name:      "stackrox-results",
		Namespace: namespace,
	}, &stackroxResults)
	if err != nil {
		t.Errorf("Failed to get StackRoxResults: %v", err)
		return
	}

	if stackroxResults.Status.SyncStatus != "Ready" {
		t.Errorf("Expected sync status 'Ready', got %s", stackroxResults.Status.SyncStatus)
	}

	if len(stackroxResults.Status.Vulnerabilities) != 1 {
		t.Errorf("Expected 1 vulnerability, got %d", len(stackroxResults.Status.Vulnerabilities))
	}

	if len(stackroxResults.Status.PolicyViolations) != 1 {
		t.Errorf("Expected 1 policy violation, got %d", len(stackroxResults.Status.PolicyViolations))
	}
}

func TestStackRoxResultsReconciler_getSyncInterval(t *testing.T) {
	tests := []struct {
		name     string
		envValue string
		expected time.Duration
	}{
		{
			name:     "Default interval",
			envValue: "",
			expected: DefaultSyncInterval,
		},
		{
			name:     "Custom interval from env",
			envValue: "10",
			expected: 10 * time.Minute,
		},
		{
			name:     "Invalid env value uses default",
			envValue: "invalid",
			expected: DefaultSyncInterval,
		},
		{
			name:     "Zero env value uses default",
			envValue: "0",
			expected: DefaultSyncInterval,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			// Reset reconciler's cached interval
			reconciler := &StackRoxResultsReconciler{}

			// Set environment variable
			if test.envValue != "" {
				os.Setenv(SyncIntervalEnvVar, test.envValue)
			} else {
				os.Unsetenv(SyncIntervalEnvVar)
			}
			defer os.Unsetenv(SyncIntervalEnvVar)

			actual := reconciler.getSyncInterval()
			if actual != test.expected {
				t.Errorf("Expected sync interval %v, got %v", test.expected, actual)
			}
		})
	}
}

func TestStackRoxResultsReconciler_isSystemNamespace(t *testing.T) {
	reconciler := &StackRoxResultsReconciler{}

	tests := []struct {
		namespace string
		expected  bool
	}{
		{"kube-system", true},
		{"kube-public", true},
		{"openshift-console", true},
		{"stackrox", true},
		{"user-app", false},
		{"production", false},
		{"development", false},
		{"default", true},
	}

	for _, test := range tests {
		t.Run(test.namespace, func(t *testing.T) {
			actual := reconciler.isSystemNamespace(test.namespace)
			if actual != test.expected {
				t.Errorf("Expected isSystemNamespace(%s) to return %v, got %v",
					test.namespace, test.expected, actual)
			}
		})
	}
}

func TestStackRoxResultsReconciler_getClusterName(t *testing.T) {
	reconciler := &StackRoxResultsReconciler{}

	tests := []struct {
		name     string
		envValue string
		expected string
	}{
		{
			name:     "Default cluster name",
			envValue: "",
			expected: "local-cluster",
		},
		{
			name:     "Custom cluster name from env",
			envValue: "my-cluster",
			expected: "my-cluster",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			// Set environment variable
			if test.envValue != "" {
				os.Setenv("ROX_CLUSTER_NAME", test.envValue)
			} else {
				os.Unsetenv("ROX_CLUSTER_NAME")
			}
			defer os.Unsetenv("ROX_CLUSTER_NAME")

			actual := reconciler.getClusterName()
			if actual != test.expected {
				t.Errorf("Expected cluster name %s, got %s", test.expected, actual)
			}
		})
	}
}
