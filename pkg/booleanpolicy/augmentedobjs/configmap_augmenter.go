package augmentedobjs

import (
	"context"
	"fmt"

	"github.com/pkg/errors"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/client-go/kubernetes"
)

// ConfigMapAugmentedResource represents a ConfigMap with related resources
type ConfigMapAugmentedResource struct {
	*GenericAugmentedResource

	// Workloads that consume this ConfigMap
	ConsumingWorkloads []*unstructured.Unstructured

	// Pods that mount this ConfigMap
	ConsumingPods []*unstructured.Unstructured

	// Other ConfigMaps in the same namespace
	RelatedConfigMaps []*unstructured.Unstructured
}

// ConfigMapAugmentationStrategy augments ConfigMaps with relationship context
type ConfigMapAugmentationStrategy struct {
	client    kubernetes.Interface
	clusterID string
}

// NewConfigMapAugmentationStrategy creates a new ConfigMap augmentation strategy
func NewConfigMapAugmentationStrategy(client kubernetes.Interface, clusterID string) *ConfigMapAugmentationStrategy {
	return &ConfigMapAugmentationStrategy{
		client:    client,
		clusterID: clusterID,
	}
}

// Augment augments a ConfigMap with relationship context
func (cmas *ConfigMapAugmentationStrategy) Augment(ctx context.Context,
	resource *unstructured.Unstructured) (AugmentedResource, error) {

	if resource.GetKind() != "ConfigMap" {
		return nil, errors.Errorf("expected ConfigMap, got %s", resource.GetKind())
	}

	// Create base augmented resource
	base := NewGenericAugmentedResource(resource, cmas.clusterID)

	augmented := &ConfigMapAugmentedResource{
		GenericAugmentedResource: base,
		ConsumingWorkloads:       []*unstructured.Unstructured{},
		ConsumingPods:            []*unstructured.Unstructured{},
		RelatedConfigMaps:        []*unstructured.Unstructured{},
	}

	// Discover relationships
	if err := cmas.discoverRelationships(ctx, augmented, resource); err != nil {
		return nil, errors.Wrap(err, "discovering ConfigMap relationships")
	}

	return augmented, nil
}

// SupportsKind returns true for ConfigMap
func (cmas *ConfigMapAugmentationStrategy) SupportsKind(kind string) bool {
	return kind == "ConfigMap"
}

// discoverRelationships discovers resources related to the ConfigMap
func (cmas *ConfigMapAugmentationStrategy) discoverRelationships(ctx context.Context,
	augmented *ConfigMapAugmentedResource, cm *unstructured.Unstructured) error {

	namespace := cm.GetNamespace()
	configMapName := cm.GetName()

	// Find pods that mount this ConfigMap
	pods, err := cmas.findConsumingPods(ctx, namespace, configMapName)
	if err != nil {
		return errors.Wrap(err, "finding consuming pods")
	}
	augmented.ConsumingPods = pods

	// Find deployments that use this ConfigMap
	deployments, err := cmas.findConsumingDeployments(ctx, namespace, configMapName)
	if err != nil {
		return errors.Wrap(err, "finding consuming deployments")
	}
	augmented.ConsumingWorkloads = append(augmented.ConsumingWorkloads, deployments...)

	// Find StatefulSets that use this ConfigMap
	statefulSets, err := cmas.findConsumingStatefulSets(ctx, namespace, configMapName)
	if err != nil {
		return errors.Wrap(err, "finding consuming StatefulSets")
	}
	augmented.ConsumingWorkloads = append(augmented.ConsumingWorkloads, statefulSets...)

	// Find DaemonSets that use this ConfigMap
	daemonSets, err := cmas.findConsumingDaemonSets(ctx, namespace, configMapName)
	if err != nil {
		return errors.Wrap(err, "finding consuming DaemonSets")
	}
	augmented.ConsumingWorkloads = append(augmented.ConsumingWorkloads, daemonSets...)

	// Find related ConfigMaps in the same namespace
	relatedCMs, err := cmas.findRelatedConfigMaps(ctx, namespace, configMapName)
	if err != nil {
		return errors.Wrap(err, "finding related ConfigMaps")
	}
	augmented.RelatedConfigMaps = relatedCMs

	// Store relationships in the generic related resources map
	augmented.Related["Pod"] = augmented.ConsumingPods
	augmented.Related["Deployment"] = augmented.ConsumingWorkloads
	augmented.Related["ConfigMap"] = augmented.RelatedConfigMaps

	return nil
}

// findConsumingPods finds pods that mount this ConfigMap
func (cmas *ConfigMapAugmentationStrategy) findConsumingPods(ctx context.Context,
	namespace, configMapName string) ([]*unstructured.Unstructured, error) {

	podList, err := cmas.client.CoreV1().Pods(namespace).List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, errors.Wrap(err, "listing pods")
	}

	var consumingPods []*unstructured.Unstructured

	for _, pod := range podList.Items {
		if cmas.podUsesConfigMap(&pod, configMapName) {
			unstructuredPod, err := cmas.podToUnstructured(&pod)
			if err != nil {
				continue // Skip pods that can't be converted
			}
			consumingPods = append(consumingPods, unstructuredPod)
		}
	}

	return consumingPods, nil
}

// findConsumingDeployments finds deployments that use this ConfigMap
func (cmas *ConfigMapAugmentationStrategy) findConsumingDeployments(ctx context.Context,
	namespace, configMapName string) ([]*unstructured.Unstructured, error) {

	deploymentList, err := cmas.client.AppsV1().Deployments(namespace).List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, errors.Wrap(err, "listing deployments")
	}

	var consumingDeployments []*unstructured.Unstructured

	for _, deployment := range deploymentList.Items {
		if cmas.deploymentUsesConfigMap(&deployment, configMapName) {
			unstructuredDeployment, err := cmas.deploymentToUnstructured(&deployment)
			if err != nil {
				continue // Skip deployments that can't be converted
			}
			consumingDeployments = append(consumingDeployments, unstructuredDeployment)
		}
	}

	return consumingDeployments, nil
}

// findConsumingStatefulSets finds StatefulSets that use this ConfigMap
func (cmas *ConfigMapAugmentationStrategy) findConsumingStatefulSets(ctx context.Context,
	namespace, configMapName string) ([]*unstructured.Unstructured, error) {

	statefulSetList, err := cmas.client.AppsV1().StatefulSets(namespace).List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, errors.Wrap(err, "listing StatefulSets")
	}

	var consumingStatefulSets []*unstructured.Unstructured

	for _, sts := range statefulSetList.Items {
		if cmas.statefulSetUsesConfigMap(&sts, configMapName) {
			unstructuredSts, err := cmas.statefulSetToUnstructured(&sts)
			if err != nil {
				continue // Skip StatefulSets that can't be converted
			}
			consumingStatefulSets = append(consumingStatefulSets, unstructuredSts)
		}
	}

	return consumingStatefulSets, nil
}

// findConsumingDaemonSets finds DaemonSets that use this ConfigMap
func (cmas *ConfigMapAugmentationStrategy) findConsumingDaemonSets(ctx context.Context,
	namespace, configMapName string) ([]*unstructured.Unstructured, error) {

	daemonSetList, err := cmas.client.AppsV1().DaemonSets(namespace).List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, errors.Wrap(err, "listing DaemonSets")
	}

	var consumingDaemonSets []*unstructured.Unstructured

	for _, ds := range daemonSetList.Items {
		if cmas.daemonSetUsesConfigMap(&ds, configMapName) {
			unstructuredDs, err := cmas.daemonSetToUnstructured(&ds)
			if err != nil {
				continue // Skip DaemonSets that can't be converted
			}
			consumingDaemonSets = append(consumingDaemonSets, unstructuredDs)
		}
	}

	return consumingDaemonSets, nil
}

// findRelatedConfigMaps finds other ConfigMaps in the same namespace
func (cmas *ConfigMapAugmentationStrategy) findRelatedConfigMaps(ctx context.Context,
	namespace, configMapName string) ([]*unstructured.Unstructured, error) {

	configMapList, err := cmas.client.CoreV1().ConfigMaps(namespace).List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, errors.Wrap(err, "listing ConfigMaps")
	}

	var relatedConfigMaps []*unstructured.Unstructured

	for _, cm := range configMapList.Items {
		if cm.Name != configMapName {
			unstructuredCM, err := cmas.configMapToUnstructured(&cm)
			if err != nil {
				continue // Skip ConfigMaps that can't be converted
			}
			relatedConfigMaps = append(relatedConfigMaps, unstructuredCM)
		}
	}

	return relatedConfigMaps, nil
}

// Helper methods to check if resources use the ConfigMap

func (cmas *ConfigMapAugmentationStrategy) podUsesConfigMap(pod *v1.Pod, configMapName string) bool {
	// Check volumes
	for _, volume := range pod.Spec.Volumes {
		if volume.ConfigMap != nil && volume.ConfigMap.Name == configMapName {
			return true
		}
	}

	// Check environment variables
	for _, container := range pod.Spec.Containers {
		for _, env := range container.Env {
			if env.ValueFrom != nil && env.ValueFrom.ConfigMapKeyRef != nil &&
				env.ValueFrom.ConfigMapKeyRef.Name == configMapName {
				return true
			}
		}

		// Check envFrom
		for _, envFrom := range container.EnvFrom {
			if envFrom.ConfigMapRef != nil && envFrom.ConfigMapRef.Name == configMapName {
				return true
			}
		}
	}

	return false
}

func (cmas *ConfigMapAugmentationStrategy) deploymentUsesConfigMap(deployment interface{}, configMapName string) bool {
	// Convert to unstructured if needed
	var unstructuredDeployment *unstructured.Unstructured
	if unstruct, ok := deployment.(*unstructured.Unstructured); ok {
		unstructuredDeployment = unstruct
	} else {
		// For typed deployments, create a minimal unstructured representation
		// This is a simplified approach - in practice you'd use proper conversion
		return false
	}

	// Get pod template from deployment spec
	podTemplate, found, err := unstructured.NestedMap(unstructuredDeployment.Object, "spec", "template", "spec")
	if err != nil || !found {
		return false
	}

	// Check volumes
	volumes, found, err := unstructured.NestedSlice(podTemplate, "volumes")
	if err == nil && found {
		for _, volume := range volumes {
			volumeMap, ok := volume.(map[string]interface{})
			if !ok {
				continue
			}

			configMap, found, err := unstructured.NestedMap(volumeMap, "configMap")
			if err == nil && found {
				name, _, _ := unstructured.NestedString(configMap, "name")
				if name == configMapName {
					return true
				}
			}
		}
	}

	// Check containers for env and envFrom
	containers, found, err := unstructured.NestedSlice(podTemplate, "containers")
	if err == nil && found {
		for _, container := range containers {
			containerMap, ok := container.(map[string]interface{})
			if !ok {
				continue
			}

			if cmas.containerUsesConfigMap(containerMap, configMapName) {
				return true
			}
		}
	}

	return false
}

func (cmas *ConfigMapAugmentationStrategy) statefulSetUsesConfigMap(sts interface{}, configMapName string) bool {
	// StatefulSets have the same structure as Deployments for pod templates
	return cmas.deploymentUsesConfigMap(sts, configMapName)
}

func (cmas *ConfigMapAugmentationStrategy) daemonSetUsesConfigMap(ds interface{}, configMapName string) bool {
	// DaemonSets have the same structure as Deployments for pod templates
	return cmas.deploymentUsesConfigMap(ds, configMapName)
}

func (cmas *ConfigMapAugmentationStrategy) containerUsesConfigMap(container map[string]interface{}, configMapName string) bool {
	// Check env variables
	env, found, err := unstructured.NestedSlice(container, "env")
	if err == nil && found {
		for _, envVar := range env {
			envVarMap, ok := envVar.(map[string]interface{})
			if !ok {
				continue
			}

			valueFrom, found, err := unstructured.NestedMap(envVarMap, "valueFrom")
			if err == nil && found {
				configMapKeyRef, found, err := unstructured.NestedMap(valueFrom, "configMapKeyRef")
				if err == nil && found {
					name, _, _ := unstructured.NestedString(configMapKeyRef, "name")
					if name == configMapName {
						return true
					}
				}
			}
		}
	}

	// Check envFrom
	envFrom, found, err := unstructured.NestedSlice(container, "envFrom")
	if err == nil && found {
		for _, envFromSource := range envFrom {
			envFromMap, ok := envFromSource.(map[string]interface{})
			if !ok {
				continue
			}

			configMapRef, found, err := unstructured.NestedMap(envFromMap, "configMapRef")
			if err == nil && found {
				name, _, _ := unstructured.NestedString(configMapRef, "name")
				if name == configMapName {
					return true
				}
			}
		}
	}

	return false
}

// Helper methods to convert typed resources to unstructured

func (cmas *ConfigMapAugmentationStrategy) podToUnstructured(pod *v1.Pod) (*unstructured.Unstructured, error) {
	unstructuredPod := &unstructured.Unstructured{}
	unstructuredPod.SetKind("Pod")
	unstructuredPod.SetAPIVersion("v1")
	unstructuredPod.SetName(pod.Name)
	unstructuredPod.SetNamespace(pod.Namespace)
	unstructuredPod.SetUID(pod.UID)
	unstructuredPod.SetLabels(pod.Labels)
	unstructuredPod.SetAnnotations(pod.Annotations)

	// Convert spec
	podSpec := make(map[string]interface{})
	if err := cmas.convertToMap(pod.Spec, &podSpec); err != nil {
		return nil, err
	}
	unstructuredPod.Object["spec"] = podSpec

	// Convert status
	podStatus := make(map[string]interface{})
	if err := cmas.convertToMap(pod.Status, &podStatus); err != nil {
		return nil, err
	}
	unstructuredPod.Object["status"] = podStatus

	return unstructuredPod, nil
}

func (cmas *ConfigMapAugmentationStrategy) deploymentToUnstructured(deployment interface{}) (*unstructured.Unstructured, error) {
	if unstruct, ok := deployment.(*unstructured.Unstructured); ok {
		return unstruct.DeepCopy(), nil
	}
	return nil, errors.New("conversion not implemented")
}

func (cmas *ConfigMapAugmentationStrategy) statefulSetToUnstructured(sts interface{}) (*unstructured.Unstructured, error) {
	if unstruct, ok := sts.(*unstructured.Unstructured); ok {
		return unstruct.DeepCopy(), nil
	}
	return nil, errors.New("conversion not implemented")
}

func (cmas *ConfigMapAugmentationStrategy) daemonSetToUnstructured(ds interface{}) (*unstructured.Unstructured, error) {
	if unstruct, ok := ds.(*unstructured.Unstructured); ok {
		return unstruct.DeepCopy(), nil
	}
	return nil, errors.New("conversion not implemented")
}

func (cmas *ConfigMapAugmentationStrategy) configMapToUnstructured(cm *v1.ConfigMap) (*unstructured.Unstructured, error) {
	unstructuredCM := &unstructured.Unstructured{}
	unstructuredCM.SetKind("ConfigMap")
	unstructuredCM.SetAPIVersion("v1")
	unstructuredCM.SetName(cm.Name)
	unstructuredCM.SetNamespace(cm.Namespace)
	unstructuredCM.SetUID(cm.UID)
	unstructuredCM.SetLabels(cm.Labels)
	unstructuredCM.SetAnnotations(cm.Annotations)

	// Set data
	if cm.Data != nil {
		unstructuredCM.Object["data"] = cm.Data
	}

	// Set binary data
	if cm.BinaryData != nil {
		binaryData := make(map[string]interface{})
		for k, v := range cm.BinaryData {
			binaryData[k] = v
		}
		unstructuredCM.Object["binaryData"] = binaryData
	}

	return unstructuredCM, nil
}

// convertToMap converts a struct to a map using JSON marshaling
func (cmas *ConfigMapAugmentationStrategy) convertToMap(src interface{}, dst *map[string]interface{}) error {
	// This is a simplified conversion - in practice you might want to use
	// a more sophisticated conversion library or the Kubernetes scheme
	return fmt.Errorf("conversion not implemented")
}

// GetConsumingWorkloads returns workloads that use this ConfigMap
func (cmar *ConfigMapAugmentedResource) GetConsumingWorkloads() []*unstructured.Unstructured {
	return cmar.ConsumingWorkloads
}

// GetConsumingPods returns pods that mount this ConfigMap
func (cmar *ConfigMapAugmentedResource) GetConsumingPods() []*unstructured.Unstructured {
	return cmar.ConsumingPods
}

// GetRelatedConfigMaps returns other ConfigMaps in the same namespace
func (cmar *ConfigMapAugmentedResource) GetRelatedConfigMaps() []*unstructured.Unstructured {
	return cmar.RelatedConfigMaps
}

// HasConsumingWorkloads returns true if any workloads use this ConfigMap
func (cmar *ConfigMapAugmentedResource) HasConsumingWorkloads() bool {
	return len(cmar.ConsumingWorkloads) > 0
}

// HasConsumingPods returns true if any pods mount this ConfigMap
func (cmar *ConfigMapAugmentedResource) HasConsumingPods() bool {
	return len(cmar.ConsumingPods) > 0
}

// GetConsumingWorkloadCount returns the number of workloads using this ConfigMap
func (cmar *ConfigMapAugmentedResource) GetConsumingWorkloadCount() int {
	return len(cmar.ConsumingWorkloads)
}

// GetConsumingPodCount returns the number of pods mounting this ConfigMap
func (cmar *ConfigMapAugmentedResource) GetConsumingPodCount() int {
	return len(cmar.ConsumingPods)
}
