package augmentedobjs

import (
	"context"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/client-go/kubernetes"
)

// ResourceAugmentationFactory creates augmented resources for policy evaluation
type ResourceAugmentationFactory struct {
	k8sClient kubernetes.Interface
	clusterID string

	// Strategy pattern for different resource types
	strategies map[string]AugmentationStrategy
}

// AugmentationStrategy defines how to augment specific resource types
type AugmentationStrategy interface {
	Augment(ctx context.Context, resource *unstructured.Unstructured) (AugmentedResource, error)
	SupportsKind(kind string) bool
}

// NewResourceAugmentationFactory creates a new factory instance
func NewResourceAugmentationFactory(k8sClient kubernetes.Interface, clusterID string) *ResourceAugmentationFactory {
	factory := &ResourceAugmentationFactory{
		k8sClient:  k8sClient,
		clusterID:  clusterID,
		strategies: make(map[string]AugmentationStrategy),
	}

	// Register specialized strategies for Phase 2
	factory.RegisterStrategy(&ConfigMapAugmentationStrategy{
		client:    k8sClient,
		clusterID: clusterID,
	})

	factory.RegisterStrategy(&SecretAugmentationStrategy{
		client:    k8sClient,
		clusterID: clusterID,
	})

	factory.RegisterStrategy(&ServiceAugmentationStrategy{
		client:    k8sClient,
		clusterID: clusterID,
	})

	factory.RegisterStrategy(&IngressAugmentationStrategy{
		client:    k8sClient,
		clusterID: clusterID,
	})

	// Register generic strategy as fallback
	factory.RegisterStrategy(&GenericAugmentationStrategy{
		client:    k8sClient,
		clusterID: clusterID,
	})

	return factory
}

// RegisterStrategy registers an augmentation strategy for specific resource types
func (raf *ResourceAugmentationFactory) RegisterStrategy(strategy AugmentationStrategy) {
	// Register strategy based on the kinds it supports
	if strategy.SupportsKind("ConfigMap") {
		raf.strategies["ConfigMap"] = strategy
	}
	if strategy.SupportsKind("Secret") {
		raf.strategies["Secret"] = strategy
	}
	if strategy.SupportsKind("Service") {
		raf.strategies["Service"] = strategy
	}
	if strategy.SupportsKind("Ingress") {
		raf.strategies["Ingress"] = strategy
	}

	// Generic strategy supports all kinds
	if _, ok := strategy.(*GenericAugmentationStrategy); ok {
		raf.strategies["generic"] = strategy
	}
}

// AugmentResource creates an augmented resource with context
func (raf *ResourceAugmentationFactory) AugmentResource(ctx context.Context,
	resource *unstructured.Unstructured) (AugmentedResource, error) {
	kind := resource.GetKind()

	// Use specific strategy if available, otherwise generic
	if strategy, exists := raf.strategies[kind]; exists {
		return strategy.Augment(ctx, resource)
	}

	// Fall back to generic strategy
	if genericStrategy, exists := raf.strategies["generic"]; exists {
		return genericStrategy.Augment(ctx, resource)
	}

	// Fallback to minimal augmentation if no strategies available
	return NewGenericAugmentedResource(resource, raf.clusterID), nil
}

// GenericAugmentationStrategy provides basic augmentation for any resource
type GenericAugmentationStrategy struct {
	client    kubernetes.Interface
	clusterID string
}

// Augment creates a minimally augmented resource
func (gas *GenericAugmentationStrategy) Augment(ctx context.Context,
	resource *unstructured.Unstructured) (AugmentedResource, error) {
	// For Phase 1, minimal augmentation
	// Future phases will add relationship discovery
	augmented := NewGenericAugmentedResource(resource, gas.clusterID)

	// TODO: Add relationship discovery in future phases:
	// - For ConfigMaps: find Pods/Deployments that use them
	// - For Services: find Pods/Endpoints they select
	// - For Ingresses: find Services they route to

	return augmented, nil
}

// SupportsKind returns true for all kinds (generic strategy)
func (gas *GenericAugmentationStrategy) SupportsKind(kind string) bool {
	return true
}

// DeploymentCompatibilityAdapter adapts existing deployment-specific code
// This allows backward compatibility during the transition period
type DeploymentCompatibilityAdapter struct {
	augmentedResource AugmentedResource
}

// NewDeploymentCompatibilityAdapter creates an adapter for deployment-like resources
func NewDeploymentCompatibilityAdapter(augmented AugmentedResource) *DeploymentCompatibilityAdapter {
	return &DeploymentCompatibilityAdapter{
		augmentedResource: augmented,
	}
}

// GetResource returns the underlying resource as unstructured
func (dca *DeploymentCompatibilityAdapter) GetResource() *unstructured.Unstructured {
	return dca.augmentedResource.GetResource()
}

// IsDeploymentLikeResource checks if a resource is deployment-like
func IsDeploymentLikeResource(resource *unstructured.Unstructured) bool {
	kind := resource.GetKind()
	return kind == "Deployment" || kind == "StatefulSet" || kind == "DaemonSet" ||
		kind == "ReplicaSet" || kind == "Pod" || kind == "Job" || kind == "CronJob" ||
		kind == "DeploymentConfig" // OpenShift
}

// GetDeploymentLikeKinds returns all kinds that are considered deployment-like
func GetDeploymentLikeKinds() []string {
	return []string{
		"Deployment",
		"StatefulSet",
		"DaemonSet",
		"ReplicaSet",
		"Pod",
		"Job",
		"CronJob",
		"DeploymentConfig", // OpenShift
	}
}
