package augmentedobjs

import (
	"strings"
	"time"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

// AugmentedResource is the universal interface for policy evaluation context
// This replaces deployment-specific interfaces for universal resource support
type AugmentedResource interface {
	GetResource() *unstructured.Unstructured
	GetRelatedResources() map[string][]*unstructured.Unstructured
	GetKind() string
	GetAPIVersion() string
	GetNamespace() string
	GetName() string

	// Dynamic field access for generic evaluation
	GetField(path string) (interface{}, bool, error)
	SetField(path string, value interface{}) error

	// Metadata for evaluation context
	GetAugmentationTimestamp() time.Time
	GetClusterID() string
}

// GenericAugmentedResource implements AugmentedResource for any Kubernetes resource
type GenericAugmentedResource struct {
	Resource  *unstructured.Unstructured
	Related   map[string][]*unstructured.Unstructured
	ClusterID string
	Timestamp time.Time
}

// GetResource returns the underlying Kubernetes resource
func (gar *GenericAugmentedResource) GetResource() *unstructured.Unstructured {
	return gar.Resource
}

// GetRelatedResources returns related resources discovered through relationships
func (gar *GenericAugmentedResource) GetRelatedResources() map[string][]*unstructured.Unstructured {
	if gar.Related == nil {
		return make(map[string][]*unstructured.Unstructured)
	}
	return gar.Related
}

// GetKind returns the resource kind
func (gar *GenericAugmentedResource) GetKind() string {
	return gar.Resource.GetKind()
}

// GetAPIVersion returns the resource API version
func (gar *GenericAugmentedResource) GetAPIVersion() string {
	return gar.Resource.GetAPIVersion()
}

// GetNamespace returns the resource namespace
func (gar *GenericAugmentedResource) GetNamespace() string {
	return gar.Resource.GetNamespace()
}

// GetName returns the resource name
func (gar *GenericAugmentedResource) GetName() string {
	return gar.Resource.GetName()
}

// GetField extracts a field value using dot notation path
func (gar *GenericAugmentedResource) GetField(path string) (interface{}, bool, error) {
	// Handle special cases for metadata access
	if strings.HasPrefix(path, "metadata.") {
		return gar.getMetadataField(path)
	}

	// Use unstructured.NestedFieldCopy for deep field access
	pathParts := strings.Split(path, ".")
	return unstructured.NestedFieldCopy(gar.Resource.Object, pathParts...)
}

// SetField sets a field value using dot notation path
func (gar *GenericAugmentedResource) SetField(path string, value interface{}) error {
	pathParts := strings.Split(path, ".")
	return unstructured.SetNestedField(gar.Resource.Object, value, pathParts...)
}

// GetAugmentationTimestamp returns when this resource was augmented
func (gar *GenericAugmentedResource) GetAugmentationTimestamp() time.Time {
	return gar.Timestamp
}

// GetClusterID returns the cluster ID this resource belongs to
func (gar *GenericAugmentedResource) GetClusterID() string {
	return gar.ClusterID
}

// getMetadataField handles special metadata field access patterns
func (gar *GenericAugmentedResource) getMetadataField(path string) (interface{}, bool, error) {
	// Handle annotation access like metadata.annotations['key']
	if strings.Contains(path, "annotations[") {
		return gar.getAnnotationField(path)
	}

	// Handle label access like metadata.labels['key']
	if strings.Contains(path, "labels[") {
		return gar.getLabelField(path)
	}

	// Standard metadata field access
	pathParts := strings.Split(path, ".")
	return unstructured.NestedFieldCopy(gar.Resource.Object, pathParts...)
}

// getAnnotationField extracts annotation values with bracket notation
func (gar *GenericAugmentedResource) getAnnotationField(path string) (interface{}, bool, error) {
	// Parse: metadata.annotations['cert-manager.io/issuer']
	start := strings.Index(path, "['")
	end := strings.Index(path, "']")
	if start == -1 || end == -1 || end <= start {
		return nil, false, nil
	}

	annotationKey := path[start+2 : end]
	annotations := gar.Resource.GetAnnotations()
	if annotations == nil {
		return nil, false, nil
	}

	value, found := annotations[annotationKey]
	return value, found, nil
}

// getLabelField extracts label values with bracket notation
func (gar *GenericAugmentedResource) getLabelField(path string) (interface{}, bool, error) {
	// Parse: metadata.labels['app']
	start := strings.Index(path, "['")
	end := strings.Index(path, "']")
	if start == -1 || end == -1 || end <= start {
		return nil, false, nil
	}

	labelKey := path[start+2 : end]
	labels := gar.Resource.GetLabels()
	if labels == nil {
		return nil, false, nil
	}

	value, found := labels[labelKey]
	return value, found, nil
}

// NewGenericAugmentedResource creates a new GenericAugmentedResource
func NewGenericAugmentedResource(resource *unstructured.Unstructured, clusterID string) *GenericAugmentedResource {
	return &GenericAugmentedResource{
		Resource:  resource.DeepCopy(),
		Related:   make(map[string][]*unstructured.Unstructured),
		ClusterID: clusterID,
		Timestamp: time.Now(),
	}
}

// AddRelatedResource adds a related resource to the augmented context
func (gar *GenericAugmentedResource) AddRelatedResource(kind string, resource *unstructured.Unstructured) {
	if gar.Related == nil {
		gar.Related = make(map[string][]*unstructured.Unstructured)
	}
	gar.Related[kind] = append(gar.Related[kind], resource.DeepCopy())
}
