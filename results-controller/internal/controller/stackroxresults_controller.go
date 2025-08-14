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
	"fmt"
	"os"
	"strconv"
	"time"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller"
	"sigs.k8s.io/controller-runtime/pkg/log"

	"github.com/stackrox/rox/pkg/logging"
	platformv1alpha1 "github.com/stackrox/rox/results-controller/api/v1alpha1"
	centralclient "github.com/stackrox/rox/results-controller/pkg/client"
)

const (
	// DefaultSyncInterval is the default sync interval if not specified
	DefaultSyncInterval = 5 * time.Minute

	// SyncIntervalEnvVar is the environment variable for configuring sync interval
	SyncIntervalEnvVar = "SYNC_INTERVAL_MINUTES"
)

var (
	controllerLog = logging.LoggerForModule()
)

// StackRoxResultsReconciler reconciles a StackRoxResults object
type StackRoxResultsReconciler struct {
	client.Client
	Scheme        *runtime.Scheme
	CentralClient centralclient.CentralClient
	syncInterval  time.Duration
	stopCh        chan struct{}
}

// +kubebuilder:rbac:groups=platform.stackrox.io,resources=stackroxresults,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=platform.stackrox.io,resources=stackroxresults/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=platform.stackrox.io,resources=stackroxresults/finalizers,verbs=update
// +kubebuilder:rbac:groups="",resources=namespaces,verbs=get;list;watch
// +kubebuilder:rbac:groups=apps,resources=deployments,verbs=get;list;watch

// Reconcile is part of the main kubernetes reconciliation loop which aims to
// move the current state of the cluster closer to the desired state.
// In the new architecture, the reconcile method is much simpler since the background
// goroutine handles the actual syncing from Central.
func (r *StackRoxResultsReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	logger := log.FromContext(ctx)

	// Fetch the StackRoxResults instance
	var stackroxResults platformv1alpha1.StackRoxResults
	if err := r.Get(ctx, req.NamespacedName, &stackroxResults); err != nil {
		if errors.IsNotFound(err) {
			// Object not found, it was probably deleted.
			// The background sync will recreate it if needed.
			logger.Info("StackRoxResults resource not found. Background sync will recreate if needed")
			return ctrl.Result{}, nil
		}
		logger.Error(err, "Failed to get StackRoxResults")
		return ctrl.Result{}, err
	}

	// Simple reconcile - just ensure the resource exists and is in a consistent state
	// The background goroutine handles the actual data syncing
	logger.V(1).Info("Reconciled StackRoxResults", "namespace", stackroxResults.Namespace)
	return ctrl.Result{}, nil
}

// getSyncInterval returns the configured sync interval
func (r *StackRoxResultsReconciler) getSyncInterval() time.Duration {
	if r.syncInterval == 0 {
		// Parse from environment variable
		if envVal := os.Getenv(SyncIntervalEnvVar); envVal != "" {
			if minutes, err := strconv.Atoi(envVal); err == nil && minutes > 0 {
				r.syncInterval = time.Duration(minutes) * time.Minute
			} else {
				controllerLog.Warn("Invalid sync interval in environment variable, using default",
					"envVar", SyncIntervalEnvVar, "value", envVal)
				r.syncInterval = DefaultSyncInterval
			}
		} else {
			r.syncInterval = DefaultSyncInterval
		}
		controllerLog.Info("Configured sync interval", "interval", r.syncInterval)
	}
	return r.syncInterval
}

// backgroundSyncLoop runs the background sync process
func (r *StackRoxResultsReconciler) backgroundSyncLoop(ctx context.Context) {
	ticker := time.NewTicker(r.getSyncInterval())
	defer ticker.Stop()

	controllerLog.Info("Starting background sync loop", "interval", r.getSyncInterval())

	// Run initial sync immediately
	r.performFullSync(ctx)

	for {
		select {
		case <-ctx.Done():
			controllerLog.Info("Background sync stopped due to context cancellation")
			return
		case <-r.stopCh:
			controllerLog.Info("Background sync stopped")
			return
		case <-ticker.C:
			r.performFullSync(ctx)
		}
	}
}

// performFullSync syncs all namespaces from Central
func (r *StackRoxResultsReconciler) performFullSync(ctx context.Context) {
	controllerLog.Info("Starting full sync from Central")

	// List all namespaces
	var namespaces corev1.NamespaceList
	if err := r.List(ctx, &namespaces); err != nil {
		controllerLog.Error(err, "Failed to list namespaces during sync")
		return
	}

	clusterName := r.getClusterName()
	syncedCount := 0

	for _, ns := range namespaces.Items {
		// Skip system namespaces
		if r.isSystemNamespace(ns.Name) {
			continue
		}

		if err := r.syncNamespace(ctx, ns.Name, clusterName); err != nil {
			controllerLog.Error(err, "Failed to sync namespace", "namespace", ns.Name)
			continue
		}
		syncedCount++
	}

	controllerLog.Info("Completed full sync", "namespacessynced", syncedCount)
}

// syncNamespace syncs a single namespace from Central
func (r *StackRoxResultsReconciler) syncNamespace(ctx context.Context, namespace, clusterName string) error {
	// Get or create StackRoxResults for this namespace
	stackroxResults := &platformv1alpha1.StackRoxResults{}
	err := r.Get(ctx, types.NamespacedName{
		Name:      "stackrox-results",
		Namespace: namespace,
	}, stackroxResults)

	if err != nil && errors.IsNotFound(err) {
		// Lazy creation - create the resource only when we have data
		stackroxResults = &platformv1alpha1.StackRoxResults{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "stackrox-results",
				Namespace: namespace,
			},
			Spec: platformv1alpha1.StackRoxResultsSpec{},
			Status: platformv1alpha1.StackRoxResultsStatus{
				SyncStatus: "Syncing",
			},
		}
		if err := r.Create(ctx, stackroxResults); err != nil {
			return fmt.Errorf("failed to create StackRoxResults: %w", err)
		}
	} else if err != nil {
		return fmt.Errorf("failed to get StackRoxResults: %w", err)
	}

	// Sync data from Central
	vulnerabilities, err := r.CentralClient.GetVulnerabilitiesForNamespace(ctx, namespace, clusterName)
	if err != nil {
		// Update status to indicate error
		stackroxResults.Status.SyncStatus = "Error"
		stackroxResults.Status.SyncMessage = fmt.Sprintf("Failed to sync vulnerabilities: %v", err)
		r.Status().Update(ctx, stackroxResults)
		return fmt.Errorf("failed to get vulnerabilities: %w", err)
	}

	violations, err := r.CentralClient.GetPolicyViolationsForNamespace(ctx, namespace, clusterName)
	if err != nil {
		// Update status to indicate error
		stackroxResults.Status.SyncStatus = "Error"
		stackroxResults.Status.SyncMessage = fmt.Sprintf("Failed to sync policy violations: %v", err)
		r.Status().Update(ctx, stackroxResults)
		return fmt.Errorf("failed to get policy violations: %w", err)
	}

	// Update the status with new data
	now := metav1.NewTime(time.Now())
	stackroxResults.Status.LastSyncTime = &now
	stackroxResults.Status.SyncStatus = "Ready"
	stackroxResults.Status.SyncMessage = "Successfully synchronized"
	stackroxResults.Status.Vulnerabilities = vulnerabilities
	stackroxResults.Status.PolicyViolations = violations

	// Update summary counts
	stackroxResults.Status.UpdateVulnerabilitySummary()
	stackroxResults.Status.UpdatePolicyViolationSummary()
	stackroxResults.Status.TotalVulnerabilities = int32(len(vulnerabilities))
	stackroxResults.Status.TotalPolicyViolations = int32(len(violations))

	if err := r.Status().Update(ctx, stackroxResults); err != nil {
		return fmt.Errorf("failed to update status: %w", err)
	}

	return nil
}

// getClusterName returns the current cluster name
func (r *StackRoxResultsReconciler) getClusterName() string {
	// TODO: This should be enhanced to get the actual cluster name
	// For now, use environment variable or default
	if clusterName := os.Getenv("ROX_CLUSTER_NAME"); clusterName != "" {
		return clusterName
	}
	return "local-cluster"
}

// isSystemNamespace checks if a namespace should be skipped
func (r *StackRoxResultsReconciler) isSystemNamespace(namespace string) bool {
	systemPrefixes := []string{
		"kube-",
		"openshift-",
		"stackrox",
	}

	for _, prefix := range systemPrefixes {
		if len(namespace) >= len(prefix) && namespace[:len(prefix)] == prefix {
			return true
		}
	}

	systemNamespaces := []string{
		"default",
	}

	for _, sysNs := range systemNamespaces {
		if namespace == sysNs {
			return true
		}
	}

	return false
}

// SetupWithManager sets up the controller with the Manager.
func (r *StackRoxResultsReconciler) SetupWithManager(mgr ctrl.Manager) error {
	// Start the background sync goroutine directly
	r.stopCh = make(chan struct{})
	go r.backgroundSyncLoop(context.Background())

	return ctrl.NewControllerManagedBy(mgr).
		For(&platformv1alpha1.StackRoxResults{}).
		WithOptions(controller.Options{
			MaxConcurrentReconciles: 1, // Process one namespace at a time
		}).
		Complete(r)
}
