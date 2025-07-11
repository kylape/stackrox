package augmentedobjs

import (
	"context"
	"fmt"

	"github.com/pkg/errors"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/client-go/kubernetes"
)

// ServiceAugmentedResource represents a Service with related resources
type ServiceAugmentedResource struct {
	*GenericAugmentedResource

	// Endpoints behind this service
	Endpoints []*unstructured.Unstructured

	// Pods selected by this service
	SelectedPods []*unstructured.Unstructured

	// Workloads selected by this service
	SelectedWorkloads []*unstructured.Unstructured

	// Ingresses that route to this service
	Ingresses []*unstructured.Unstructured

	// NetworkPolicies that affect this service
	NetworkPolicies []*unstructured.Unstructured
}

// ServiceAugmentationStrategy augments Services with relationship context
type ServiceAugmentationStrategy struct {
	client    kubernetes.Interface
	clusterID string
}

// NewServiceAugmentationStrategy creates a new Service augmentation strategy
func NewServiceAugmentationStrategy(client kubernetes.Interface, clusterID string) *ServiceAugmentationStrategy {
	return &ServiceAugmentationStrategy{
		client:    client,
		clusterID: clusterID,
	}
}

// Augment augments a Service with relationship context
func (sas *ServiceAugmentationStrategy) Augment(ctx context.Context,
	resource *unstructured.Unstructured) (AugmentedResource, error) {

	if resource.GetKind() != "Service" {
		return nil, errors.Errorf("expected Service, got %s", resource.GetKind())
	}

	// Create base augmented resource
	base := NewGenericAugmentedResource(resource, sas.clusterID)

	augmented := &ServiceAugmentedResource{
		GenericAugmentedResource: base,
		Endpoints:                []*unstructured.Unstructured{},
		SelectedPods:             []*unstructured.Unstructured{},
		SelectedWorkloads:        []*unstructured.Unstructured{},
		Ingresses:                []*unstructured.Unstructured{},
		NetworkPolicies:          []*unstructured.Unstructured{},
	}

	// Discover relationships
	if err := sas.discoverRelationships(ctx, augmented, resource); err != nil {
		return nil, errors.Wrap(err, "discovering Service relationships")
	}

	return augmented, nil
}

// SupportsKind returns true for Service
func (sas *ServiceAugmentationStrategy) SupportsKind(kind string) bool {
	return kind == "Service"
}

// discoverRelationships discovers resources related to the Service
func (sas *ServiceAugmentationStrategy) discoverRelationships(ctx context.Context,
	augmented *ServiceAugmentedResource, svc *unstructured.Unstructured) error {

	namespace := svc.GetNamespace()
	serviceName := svc.GetName()

	// Get service selector
	selector, err := sas.getServiceSelector(svc)
	if err != nil {
		return errors.Wrap(err, "getting service selector")
	}

	// Find endpoints for this service
	endpoints, err := sas.findServiceEndpoints(ctx, namespace, serviceName)
	if err != nil {
		return errors.Wrap(err, "finding service endpoints")
	}
	augmented.Endpoints = endpoints

	// Find pods selected by this service
	if selector != nil {
		pods, err := sas.findSelectedPods(ctx, namespace, selector)
		if err != nil {
			return errors.Wrap(err, "finding selected pods")
		}
		augmented.SelectedPods = pods

		// Find workloads that own the selected pods
		workloads, err := sas.findWorkloadsFromPods(ctx, pods)
		if err != nil {
			return errors.Wrap(err, "finding workloads from pods")
		}
		augmented.SelectedWorkloads = workloads
	}

	// Find ingresses that route to this service
	ingresses, err := sas.findIngressesForService(ctx, namespace, serviceName)
	if err != nil {
		return errors.Wrap(err, "finding ingresses for service")
	}
	augmented.Ingresses = ingresses

	// Find network policies that affect this service
	networkPolicies, err := sas.findNetworkPoliciesForService(ctx, namespace, selector)
	if err != nil {
		return errors.Wrap(err, "finding network policies")
	}
	augmented.NetworkPolicies = networkPolicies

	// Store relationships in the generic related resources map
	augmented.Related["Endpoints"] = augmented.Endpoints
	augmented.Related["Pod"] = augmented.SelectedPods
	augmented.Related["Deployment"] = augmented.SelectedWorkloads
	augmented.Related["Ingress"] = augmented.Ingresses
	augmented.Related["NetworkPolicy"] = augmented.NetworkPolicies

	return nil
}

// getServiceSelector extracts the label selector from a Service
func (sas *ServiceAugmentationStrategy) getServiceSelector(svc *unstructured.Unstructured) (labels.Selector, error) {
	selectorMap, found, err := unstructured.NestedStringMap(svc.Object, "spec", "selector")
	if err != nil {
		return nil, errors.Wrap(err, "getting service selector")
	}

	if !found || len(selectorMap) == 0 {
		return nil, nil // Service has no selector (e.g., ExternalName service)
	}

	return labels.SelectorFromSet(selectorMap), nil
}

// findServiceEndpoints finds the Endpoints resource for this Service
func (sas *ServiceAugmentationStrategy) findServiceEndpoints(ctx context.Context,
	namespace, serviceName string) ([]*unstructured.Unstructured, error) {

	endpoints, err := sas.client.CoreV1().Endpoints(namespace).Get(ctx, serviceName, metav1.GetOptions{})
	if err != nil {
		// It's normal for services to not have endpoints if no pods are ready
		return []*unstructured.Unstructured{}, nil
	}

	unstructuredEndpoints, err := sas.endpointsToUnstructured(endpoints)
	if err != nil {
		return []*unstructured.Unstructured{}, err
	}

	return []*unstructured.Unstructured{unstructuredEndpoints}, nil
}

// findSelectedPods finds pods that match the service selector
func (sas *ServiceAugmentationStrategy) findSelectedPods(ctx context.Context,
	namespace string, selector labels.Selector) ([]*unstructured.Unstructured, error) {

	podList, err := sas.client.CoreV1().Pods(namespace).List(ctx, metav1.ListOptions{
		LabelSelector: selector.String(),
	})
	if err != nil {
		return nil, errors.Wrap(err, "listing pods")
	}

	var selectedPods []*unstructured.Unstructured
	for _, pod := range podList.Items {
		unstructuredPod, err := sas.podToUnstructured(&pod)
		if err != nil {
			continue // Skip pods that can't be converted
		}
		selectedPods = append(selectedPods, unstructuredPod)
	}

	return selectedPods, nil
}

// findWorkloadsFromPods finds workloads that own the given pods
func (sas *ServiceAugmentationStrategy) findWorkloadsFromPods(ctx context.Context,
	pods []*unstructured.Unstructured) ([]*unstructured.Unstructured, error) {

	workloadMap := make(map[string]*unstructured.Unstructured)

	for _, pod := range pods {
		// Check owner references to find the workload
		ownerRefs := pod.GetOwnerReferences()
		for _, ownerRef := range ownerRefs {
			if sas.isWorkloadKind(ownerRef.Kind) {
				workloadKey := fmt.Sprintf("%s/%s/%s", ownerRef.Kind, pod.GetNamespace(), ownerRef.Name)
				if _, exists := workloadMap[workloadKey]; !exists {
					workload, err := sas.findWorkloadByOwnerRef(ctx, pod.GetNamespace(), ownerRef)
					if err != nil {
						continue // Skip workloads that can't be found
					}
					workloadMap[workloadKey] = workload
				}
			}
		}
	}

	var workloads []*unstructured.Unstructured
	for _, workload := range workloadMap {
		workloads = append(workloads, workload)
	}

	return workloads, nil
}

// findIngressesForService finds Ingresses that route to this Service
func (sas *ServiceAugmentationStrategy) findIngressesForService(ctx context.Context,
	namespace, serviceName string) ([]*unstructured.Unstructured, error) {

	ingressList, err := sas.client.NetworkingV1().Ingresses(namespace).List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, errors.Wrap(err, "listing ingresses")
	}

	var routingIngresses []*unstructured.Unstructured
	for _, ingress := range ingressList.Items {
		if sas.ingressRoutesToService(&ingress, serviceName) {
			unstructuredIngress, err := sas.ingressToUnstructured(&ingress)
			if err != nil {
				continue // Skip ingresses that can't be converted
			}
			routingIngresses = append(routingIngresses, unstructuredIngress)
		}
	}

	return routingIngresses, nil
}

// findNetworkPoliciesForService finds NetworkPolicies that affect this Service
func (sas *ServiceAugmentationStrategy) findNetworkPoliciesForService(ctx context.Context,
	namespace string, selector labels.Selector) ([]*unstructured.Unstructured, error) {

	if selector == nil {
		return []*unstructured.Unstructured{}, nil
	}

	networkPolicyList, err := sas.client.NetworkingV1().NetworkPolicies(namespace).List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, errors.Wrap(err, "listing network policies")
	}

	var affectingPolicies []*unstructured.Unstructured
	for _, netpol := range networkPolicyList.Items {
		if sas.networkPolicyAffectsSelector(&netpol, selector) {
			unstructuredNetpol, err := sas.networkPolicyToUnstructured(&netpol)
			if err != nil {
				continue // Skip network policies that can't be converted
			}
			affectingPolicies = append(affectingPolicies, unstructuredNetpol)
		}
	}

	return affectingPolicies, nil
}

// Helper methods

func (sas *ServiceAugmentationStrategy) isWorkloadKind(kind string) bool {
	workloadKinds := []string{"Deployment", "StatefulSet", "DaemonSet", "ReplicaSet", "Job", "CronJob"}
	for _, workloadKind := range workloadKinds {
		if kind == workloadKind {
			return true
		}
	}
	return false
}

func (sas *ServiceAugmentationStrategy) findWorkloadByOwnerRef(ctx context.Context,
	namespace string, ownerRef metav1.OwnerReference) (*unstructured.Unstructured, error) {

	switch ownerRef.Kind {
	case "Deployment":
		deployment, err := sas.client.AppsV1().Deployments(namespace).Get(ctx, ownerRef.Name, metav1.GetOptions{})
		if err != nil {
			return nil, err
		}
		return sas.deploymentToUnstructured(deployment)

	case "StatefulSet":
		statefulSet, err := sas.client.AppsV1().StatefulSets(namespace).Get(ctx, ownerRef.Name, metav1.GetOptions{})
		if err != nil {
			return nil, err
		}
		return sas.statefulSetToUnstructured(statefulSet)

	case "DaemonSet":
		daemonSet, err := sas.client.AppsV1().DaemonSets(namespace).Get(ctx, ownerRef.Name, metav1.GetOptions{})
		if err != nil {
			return nil, err
		}
		return sas.daemonSetToUnstructured(daemonSet)

	case "ReplicaSet":
		replicaSet, err := sas.client.AppsV1().ReplicaSets(namespace).Get(ctx, ownerRef.Name, metav1.GetOptions{})
		if err != nil {
			return nil, err
		}
		return sas.replicaSetToUnstructured(replicaSet)

	default:
		return nil, errors.Errorf("unsupported workload kind: %s", ownerRef.Kind)
	}
}

func (sas *ServiceAugmentationStrategy) ingressRoutesToService(ingress interface{}, serviceName string) bool {
	// Convert to unstructured if needed
	var unstructuredIngress *unstructured.Unstructured
	if unstruct, ok := ingress.(*unstructured.Unstructured); ok {
		unstructuredIngress = unstruct
	} else {
		// For typed ingresses, simplified approach
		return false
	}

	// Check if ingress has rules that route to this service
	rules, found, err := unstructured.NestedSlice(unstructuredIngress.Object, "spec", "rules")
	if err != nil || !found {
		return false
	}

	for _, rule := range rules {
		ruleMap, ok := rule.(map[string]interface{})
		if !ok {
			continue
		}

		// Check HTTP paths
		http, found, err := unstructured.NestedMap(ruleMap, "http")
		if err != nil || !found {
			continue
		}

		paths, found, err := unstructured.NestedSlice(http, "paths")
		if err != nil || !found {
			continue
		}

		for _, path := range paths {
			pathMap, ok := path.(map[string]interface{})
			if !ok {
				continue
			}

			backend, found, err := unstructured.NestedMap(pathMap, "backend")
			if err != nil || !found {
				continue
			}

			service, found, err := unstructured.NestedMap(backend, "service")
			if err != nil || !found {
				continue
			}

			name, found, err := unstructured.NestedString(service, "name")
			if err == nil && found && name == serviceName {
				return true
			}
		}
	}

	return false
}

func (sas *ServiceAugmentationStrategy) networkPolicyAffectsSelector(netpol interface{}, selector labels.Selector) bool {
	// Convert to unstructured if needed
	var unstructuredNetpol *unstructured.Unstructured
	if unstruct, ok := netpol.(*unstructured.Unstructured); ok {
		unstructuredNetpol = unstruct
	} else {
		// For typed network policies, simplified approach
		return false
	}

	// Check if network policy's pod selector matches our service selector
	podSelector, found, err := unstructured.NestedStringMap(unstructuredNetpol.Object, "spec", "podSelector", "matchLabels")
	if err != nil || !found {
		return false
	}

	netpolSelector := labels.SelectorFromSet(podSelector)

	// Check if the network policy selector intersects with our service selector
	// This is a simplified check - in practice, you'd want more sophisticated matching
	return netpolSelector.String() == selector.String()
}

// Conversion methods

func (sas *ServiceAugmentationStrategy) podToUnstructured(pod *v1.Pod) (*unstructured.Unstructured, error) {
	unstructuredPod := &unstructured.Unstructured{}
	unstructuredPod.SetKind("Pod")
	unstructuredPod.SetAPIVersion("v1")
	unstructuredPod.SetName(pod.Name)
	unstructuredPod.SetNamespace(pod.Namespace)
	unstructuredPod.SetUID(pod.UID)
	unstructuredPod.SetLabels(pod.Labels)
	unstructuredPod.SetAnnotations(pod.Annotations)
	unstructuredPod.SetOwnerReferences(pod.OwnerReferences)

	return unstructuredPod, nil
}

func (sas *ServiceAugmentationStrategy) endpointsToUnstructured(endpoints *v1.Endpoints) (*unstructured.Unstructured, error) {
	unstructuredEndpoints := &unstructured.Unstructured{}
	unstructuredEndpoints.SetKind("Endpoints")
	unstructuredEndpoints.SetAPIVersion("v1")
	unstructuredEndpoints.SetName(endpoints.Name)
	unstructuredEndpoints.SetNamespace(endpoints.Namespace)
	unstructuredEndpoints.SetUID(endpoints.UID)
	unstructuredEndpoints.SetLabels(endpoints.Labels)
	unstructuredEndpoints.SetAnnotations(endpoints.Annotations)

	return unstructuredEndpoints, nil
}

func (sas *ServiceAugmentationStrategy) deploymentToUnstructured(deployment interface{}) (*unstructured.Unstructured, error) {
	// Implementation depends on the actual deployment type
	return nil, errors.New("conversion not implemented")
}

func (sas *ServiceAugmentationStrategy) statefulSetToUnstructured(statefulSet interface{}) (*unstructured.Unstructured, error) {
	// Implementation depends on the actual statefulset type
	return nil, errors.New("conversion not implemented")
}

func (sas *ServiceAugmentationStrategy) daemonSetToUnstructured(daemonSet interface{}) (*unstructured.Unstructured, error) {
	// Implementation depends on the actual daemonset type
	return nil, errors.New("conversion not implemented")
}

func (sas *ServiceAugmentationStrategy) replicaSetToUnstructured(replicaSet interface{}) (*unstructured.Unstructured, error) {
	// Implementation depends on the actual replicaset type
	return nil, errors.New("conversion not implemented")
}

func (sas *ServiceAugmentationStrategy) ingressToUnstructured(ingress interface{}) (*unstructured.Unstructured, error) {
	// Implementation depends on the actual ingress type
	return nil, errors.New("conversion not implemented")
}

func (sas *ServiceAugmentationStrategy) networkPolicyToUnstructured(netpol interface{}) (*unstructured.Unstructured, error) {
	// Implementation depends on the actual network policy type
	return nil, errors.New("conversion not implemented")
}

// ServiceAugmentedResource methods

// GetEndpoints returns the endpoints for this service
func (sar *ServiceAugmentedResource) GetEndpoints() []*unstructured.Unstructured {
	return sar.Endpoints
}

// GetSelectedPods returns pods selected by this service
func (sar *ServiceAugmentedResource) GetSelectedPods() []*unstructured.Unstructured {
	return sar.SelectedPods
}

// GetSelectedWorkloads returns workloads selected by this service
func (sar *ServiceAugmentedResource) GetSelectedWorkloads() []*unstructured.Unstructured {
	return sar.SelectedWorkloads
}

// GetIngresses returns ingresses that route to this service
func (sar *ServiceAugmentedResource) GetIngresses() []*unstructured.Unstructured {
	return sar.Ingresses
}

// GetNetworkPolicies returns network policies affecting this service
func (sar *ServiceAugmentedResource) GetNetworkPolicies() []*unstructured.Unstructured {
	return sar.NetworkPolicies
}

// HasEndpoints returns true if the service has endpoints
func (sar *ServiceAugmentedResource) HasEndpoints() bool {
	return len(sar.Endpoints) > 0
}

// HasSelectedPods returns true if the service selects any pods
func (sar *ServiceAugmentedResource) HasSelectedPods() bool {
	return len(sar.SelectedPods) > 0
}

// HasIngresses returns true if any ingresses route to this service
func (sar *ServiceAugmentedResource) HasIngresses() bool {
	return len(sar.Ingresses) > 0
}

// HasNetworkPolicies returns true if any network policies affect this service
func (sar *ServiceAugmentedResource) HasNetworkPolicies() bool {
	return len(sar.NetworkPolicies) > 0
}

// GetSelectedPodCount returns the number of pods selected by this service
func (sar *ServiceAugmentedResource) GetSelectedPodCount() int {
	return len(sar.SelectedPods)
}

// GetSelectedWorkloadCount returns the number of workloads selected by this service
func (sar *ServiceAugmentedResource) GetSelectedWorkloadCount() int {
	return len(sar.SelectedWorkloads)
}
