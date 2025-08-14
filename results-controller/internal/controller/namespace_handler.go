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

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/util/workqueue"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/event"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	platformv1alpha1 "github.com/stackrox/rox/results-controller/api/v1alpha1"
)

// namespaceEventHandler handles namespace create/delete events to manage StackRoxResults
type namespaceEventHandler struct {
	client client.Client
}

// Create handles namespace creation events
func (h *namespaceEventHandler) Create(ctx context.Context, evt event.CreateEvent, q workqueue.RateLimitingInterface) {
	namespace, ok := evt.Object.(*corev1.Namespace)
	if !ok {
		return
	}

	// Skip system namespaces
	if h.isSystemNamespace(namespace.Name) {
		return
	}

	// Check if StackRoxResults already exists
	var existing platformv1alpha1.StackRoxResults
	err := h.client.Get(ctx, types.NamespacedName{
		Name:      "stackrox-results",
		Namespace: namespace.Name,
	}, &existing)

	if err != nil && errors.IsNotFound(err) {
		// Create StackRoxResults for new namespace
		stackroxResults := &platformv1alpha1.StackRoxResults{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "stackrox-results",
				Namespace: namespace.Name,
			},
			Spec: platformv1alpha1.StackRoxResultsSpec{},
			Status: platformv1alpha1.StackRoxResultsStatus{
				SyncStatus: "Unknown",
			},
		}

		if err := h.client.Create(ctx, stackroxResults); err != nil {
			controllerLog.Error(err, "Failed to create StackRoxResults for new namespace", "namespace", namespace.Name)
			return
		}

		controllerLog.Info("Created StackRoxResults for new namespace", "namespace", namespace.Name)

		// Enqueue reconcile request for the new StackRoxResults
		q.Add(reconcile.Request{
			NamespacedName: types.NamespacedName{
				Name:      "stackrox-results",
				Namespace: namespace.Name,
			},
		})
	}
}

// Update handles namespace update events (currently no-op)
func (h *namespaceEventHandler) Update(ctx context.Context, evt event.UpdateEvent, q workqueue.RateLimitingInterface) {
	// No special handling needed for namespace updates
}

// Delete handles namespace deletion events
func (h *namespaceEventHandler) Delete(ctx context.Context, evt event.DeleteEvent, q workqueue.RateLimitingInterface) {
	namespace, ok := evt.Object.(*corev1.Namespace)
	if !ok {
		return
	}

	// StackRoxResults will be automatically deleted when namespace is deleted
	// due to owner references, so no explicit action needed
	controllerLog.Info("Namespace deleted, StackRoxResults will be cleaned up automatically", "namespace", namespace.Name)
}

// Generic handles generic events (currently no-op)
func (h *namespaceEventHandler) Generic(ctx context.Context, evt event.GenericEvent, q workqueue.RateLimitingInterface) {
	// No special handling needed for generic events
}

// isSystemNamespace checks if a namespace should be skipped
func (h *namespaceEventHandler) isSystemNamespace(namespace string) bool {
	systemNamespaces := []string{
		"kube-system",
		"kube-public",
		"kube-node-lease",
		"default",
	}

	for _, sysNs := range systemNamespaces {
		if namespace == sysNs {
			return true
		}
	}

	// Skip namespaces that start with system prefixes
	systemPrefixes := []string{
		"kube-",
		"openshift-",
		"stackrox",
	}

	for _, prefix := range systemPrefixes {
		if len(namespace) > len(prefix) && namespace[:len(prefix)] == prefix {
			return true
		}
	}

	return false
}
