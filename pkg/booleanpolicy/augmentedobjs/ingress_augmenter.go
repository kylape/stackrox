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

// IngressAugmentedResource represents an Ingress with related resources
type IngressAugmentedResource struct {
	*GenericAugmentedResource

	// Backend services referenced by this ingress
	BackendServices []*unstructured.Unstructured

	// TLS secrets referenced by this ingress
	TLSSecrets []*unstructured.Unstructured

	// Workloads behind the ingress (through services)
	BackendWorkloads []*unstructured.Unstructured

	// Pods behind the ingress (through services)
	BackendPods []*unstructured.Unstructured

	// IngressClass used by this ingress
	IngressClass *unstructured.Unstructured

	// Related ingresses in the same namespace
	RelatedIngresses []*unstructured.Unstructured

	// Ingress analysis
	HasTLS              bool
	HostCount           int
	PathCount           int
	BackendServiceCount int
}

// IngressAugmentationStrategy augments Ingresses with relationship context
type IngressAugmentationStrategy struct {
	client    kubernetes.Interface
	clusterID string
}

// NewIngressAugmentationStrategy creates a new Ingress augmentation strategy
func NewIngressAugmentationStrategy(client kubernetes.Interface, clusterID string) *IngressAugmentationStrategy {
	return &IngressAugmentationStrategy{
		client:    client,
		clusterID: clusterID,
	}
}

// Augment augments an Ingress with relationship context
func (ias *IngressAugmentationStrategy) Augment(ctx context.Context,
	resource *unstructured.Unstructured) (AugmentedResource, error) {

	if resource.GetKind() != "Ingress" {
		return nil, errors.Errorf("expected Ingress, got %s", resource.GetKind())
	}

	// Create base augmented resource
	base := NewGenericAugmentedResource(resource, ias.clusterID)

	augmented := &IngressAugmentedResource{
		GenericAugmentedResource: base,
		BackendServices:          []*unstructured.Unstructured{},
		TLSSecrets:               []*unstructured.Unstructured{},
		BackendWorkloads:         []*unstructured.Unstructured{},
		BackendPods:              []*unstructured.Unstructured{},
		RelatedIngresses:         []*unstructured.Unstructured{},
	}

	// Analyze ingress properties
	ias.analyzeIngress(augmented, resource)

	// Discover relationships
	if err := ias.discoverRelationships(ctx, augmented, resource); err != nil {
		return nil, errors.Wrap(err, "discovering Ingress relationships")
	}

	return augmented, nil
}

// SupportsKind returns true for Ingress
func (ias *IngressAugmentationStrategy) SupportsKind(kind string) bool {
	return kind == "Ingress"
}

// analyzeIngress analyzes ingress properties
func (ias *IngressAugmentationStrategy) analyzeIngress(augmented *IngressAugmentedResource,
	ingress *unstructured.Unstructured) {

	// Check for TLS
	tls, found, err := unstructured.NestedSlice(ingress.Object, "spec", "tls")
	if err == nil && found && len(tls) > 0 {
		augmented.HasTLS = true
	}

	// Count hosts and paths
	rules, found, err := unstructured.NestedSlice(ingress.Object, "spec", "rules")
	if err == nil && found {
		augmented.HostCount = len(rules)

		pathCount := 0
		for _, rule := range rules {
			ruleMap, ok := rule.(map[string]interface{})
			if !ok {
				continue
			}

			http, found, err := unstructured.NestedMap(ruleMap, "http")
			if err == nil && found {
				paths, found, err := unstructured.NestedSlice(http, "paths")
				if err == nil && found {
					pathCount += len(paths)
				}
			}
		}
		augmented.PathCount = pathCount
	}
}

// discoverRelationships discovers resources related to the Ingress
func (ias *IngressAugmentationStrategy) discoverRelationships(ctx context.Context,
	augmented *IngressAugmentedResource, ingress *unstructured.Unstructured) error {

	namespace := ingress.GetNamespace()

	// Find backend services
	services, err := ias.findBackendServices(ctx, namespace, ingress)
	if err != nil {
		return errors.Wrap(err, "finding backend services")
	}
	augmented.BackendServices = services
	augmented.BackendServiceCount = len(services)

	// Find TLS secrets
	if augmented.HasTLS {
		secrets, err := ias.findTLSSecrets(ctx, namespace, ingress)
		if err != nil {
			return errors.Wrap(err, "finding TLS secrets")
		}
		augmented.TLSSecrets = secrets
	}

	// Find backend workloads and pods through services
	for _, service := range services {
		// Get service selector to find pods
		selector, err := ias.getServiceSelector(service)
		if err != nil {
			continue // Skip services without valid selectors
		}

		if selector != nil {
			// Find pods selected by this service
			pods, err := ias.findSelectedPods(ctx, namespace, selector)
			if err != nil {
				continue // Skip if we can't find pods
			}
			augmented.BackendPods = append(augmented.BackendPods, pods...)

			// Find workloads that own these pods
			workloads, err := ias.findWorkloadsFromPods(ctx, pods)
			if err != nil {
				continue // Skip if we can't find workloads
			}
			augmented.BackendWorkloads = append(augmented.BackendWorkloads, workloads...)
		}
	}

	// Find ingress class
	ingressClass, err := ias.findIngressClass(ctx, ingress)
	if err == nil && ingressClass != nil {
		augmented.IngressClass = ingressClass
	}

	// Find related ingresses in the same namespace
	relatedIngresses, err := ias.findRelatedIngresses(ctx, namespace, ingress.GetName())
	if err != nil {
		return errors.Wrap(err, "finding related ingresses")
	}
	augmented.RelatedIngresses = relatedIngresses

	// Store relationships in the generic related resources map
	augmented.Related["Service"] = augmented.BackendServices
	augmented.Related["Secret"] = augmented.TLSSecrets
	augmented.Related["Pod"] = augmented.BackendPods
	augmented.Related["Deployment"] = augmented.BackendWorkloads
	augmented.Related["Ingress"] = augmented.RelatedIngresses
	if augmented.IngressClass != nil {
		augmented.Related["IngressClass"] = []*unstructured.Unstructured{augmented.IngressClass}
	}

	return nil
}

// findBackendServices finds services referenced by the ingress
func (ias *IngressAugmentationStrategy) findBackendServices(ctx context.Context,
	namespace string, ingress *unstructured.Unstructured) ([]*unstructured.Unstructured, error) {

	serviceNames := make(map[string]bool)

	// Extract service names from ingress rules
	rules, found, err := unstructured.NestedSlice(ingress.Object, "spec", "rules")
	if err != nil || !found {
		return []*unstructured.Unstructured{}, nil
	}

	for _, rule := range rules {
		ruleMap, ok := rule.(map[string]interface{})
		if !ok {
			continue
		}

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

			serviceName, found, err := unstructured.NestedString(service, "name")
			if err == nil && found {
				serviceNames[serviceName] = true
			}
		}
	}

	// Check default backend
	defaultBackend, found, err := unstructured.NestedMap(ingress.Object, "spec", "defaultBackend")
	if err == nil && found {
		service, found, err := unstructured.NestedMap(defaultBackend, "service")
		if err == nil && found {
			serviceName, found, err := unstructured.NestedString(service, "name")
			if err == nil && found {
				serviceNames[serviceName] = true
			}
		}
	}

	// Fetch the actual service objects
	var services []*unstructured.Unstructured
	for serviceName := range serviceNames {
		service, err := ias.client.CoreV1().Services(namespace).Get(ctx, serviceName, metav1.GetOptions{})
		if err != nil {
			continue // Skip services that don't exist
		}

		unstructuredService, err := ias.serviceToUnstructured(service)
		if err != nil {
			continue // Skip services that can't be converted
		}

		services = append(services, unstructuredService)
	}

	return services, nil
}

// findTLSSecrets finds TLS secrets referenced by the ingress
func (ias *IngressAugmentationStrategy) findTLSSecrets(ctx context.Context,
	namespace string, ingress *unstructured.Unstructured) ([]*unstructured.Unstructured, error) {

	secretNames := make(map[string]bool)

	// Extract secret names from TLS configuration
	tls, found, err := unstructured.NestedSlice(ingress.Object, "spec", "tls")
	if err != nil || !found {
		return []*unstructured.Unstructured{}, nil
	}

	for _, tlsConfig := range tls {
		tlsMap, ok := tlsConfig.(map[string]interface{})
		if !ok {
			continue
		}

		secretName, found, err := unstructured.NestedString(tlsMap, "secretName")
		if err == nil && found {
			secretNames[secretName] = true
		}
	}

	// Fetch the actual secret objects
	var secrets []*unstructured.Unstructured
	for secretName := range secretNames {
		secret, err := ias.client.CoreV1().Secrets(namespace).Get(ctx, secretName, metav1.GetOptions{})
		if err != nil {
			continue // Skip secrets that don't exist
		}

		unstructuredSecret, err := ias.secretToUnstructured(secret)
		if err != nil {
			continue // Skip secrets that can't be converted
		}

		secrets = append(secrets, unstructuredSecret)
	}

	return secrets, nil
}

// findIngressClass finds the IngressClass for this ingress
func (ias *IngressAugmentationStrategy) findIngressClass(ctx context.Context,
	ingress *unstructured.Unstructured) (*unstructured.Unstructured, error) {

	// Check spec.ingressClassName
	ingressClassName, found, err := unstructured.NestedString(ingress.Object, "spec", "ingressClassName")
	if err != nil || !found {
		// Check legacy annotation
		annotations := ingress.GetAnnotations()
		if annotations != nil {
			if className, exists := annotations["kubernetes.io/ingress.class"]; exists {
				ingressClassName = className
			}
		}
	}

	if ingressClassName == "" {
		return nil, nil
	}

	// Fetch the IngressClass
	ingressClass, err := ias.client.NetworkingV1().IngressClasses().Get(ctx, ingressClassName, metav1.GetOptions{})
	if err != nil {
		return nil, err
	}

	return ias.ingressClassToUnstructured(ingressClass)
}

// findRelatedIngresses finds other ingresses in the same namespace
func (ias *IngressAugmentationStrategy) findRelatedIngresses(ctx context.Context,
	namespace, ingressName string) ([]*unstructured.Unstructured, error) {

	ingressList, err := ias.client.NetworkingV1().Ingresses(namespace).List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, errors.Wrap(err, "listing ingresses")
	}

	var relatedIngresses []*unstructured.Unstructured
	for _, ingress := range ingressList.Items {
		if ingress.Name != ingressName {
			unstructuredIngress, err := ias.ingressToUnstructured(&ingress)
			if err != nil {
				continue // Skip ingresses that can't be converted
			}
			relatedIngresses = append(relatedIngresses, unstructuredIngress)
		}
	}

	return relatedIngresses, nil
}

// Helper methods reused from service augmenter

func (ias *IngressAugmentationStrategy) getServiceSelector(service *unstructured.Unstructured) (map[string]string, error) {
	selector, found, err := unstructured.NestedStringMap(service.Object, "spec", "selector")
	if err != nil {
		return nil, errors.Wrap(err, "getting service selector")
	}

	if !found {
		return nil, nil
	}

	return selector, nil
}

func (ias *IngressAugmentationStrategy) findSelectedPods(ctx context.Context,
	namespace string, selector map[string]string) ([]*unstructured.Unstructured, error) {

	labelSelector := metav1.FormatLabelSelector(&metav1.LabelSelector{
		MatchLabels: selector,
	})

	podList, err := ias.client.CoreV1().Pods(namespace).List(ctx, metav1.ListOptions{
		LabelSelector: labelSelector,
	})
	if err != nil {
		return nil, errors.Wrap(err, "listing pods")
	}

	var selectedPods []*unstructured.Unstructured
	for _, pod := range podList.Items {
		unstructuredPod, err := ias.podToUnstructured(&pod)
		if err != nil {
			continue // Skip pods that can't be converted
		}
		selectedPods = append(selectedPods, unstructuredPod)
	}

	return selectedPods, nil
}

func (ias *IngressAugmentationStrategy) findWorkloadsFromPods(ctx context.Context,
	pods []*unstructured.Unstructured) ([]*unstructured.Unstructured, error) {

	workloadMap := make(map[string]*unstructured.Unstructured)

	for _, pod := range pods {
		// Check owner references to find the workload
		ownerRefs := pod.GetOwnerReferences()
		for _, ownerRef := range ownerRefs {
			if ias.isWorkloadKind(ownerRef.Kind) {
				workloadKey := fmt.Sprintf("%s/%s/%s", ownerRef.Kind, pod.GetNamespace(), ownerRef.Name)
				if _, exists := workloadMap[workloadKey]; !exists {
					workload, err := ias.findWorkloadByOwnerRef(ctx, pod.GetNamespace(), ownerRef)
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

func (ias *IngressAugmentationStrategy) isWorkloadKind(kind string) bool {
	workloadKinds := []string{"Deployment", "StatefulSet", "DaemonSet", "ReplicaSet", "Job", "CronJob"}
	for _, workloadKind := range workloadKinds {
		if kind == workloadKind {
			return true
		}
	}
	return false
}

func (ias *IngressAugmentationStrategy) findWorkloadByOwnerRef(ctx context.Context,
	namespace string, ownerRef metav1.OwnerReference) (*unstructured.Unstructured, error) {

	switch ownerRef.Kind {
	case "Deployment":
		deployment, err := ias.client.AppsV1().Deployments(namespace).Get(ctx, ownerRef.Name, metav1.GetOptions{})
		if err != nil {
			return nil, err
		}
		return ias.deploymentToUnstructured(deployment)

	case "StatefulSet":
		statefulSet, err := ias.client.AppsV1().StatefulSets(namespace).Get(ctx, ownerRef.Name, metav1.GetOptions{})
		if err != nil {
			return nil, err
		}
		return ias.statefulSetToUnstructured(statefulSet)

	case "DaemonSet":
		daemonSet, err := ias.client.AppsV1().DaemonSets(namespace).Get(ctx, ownerRef.Name, metav1.GetOptions{})
		if err != nil {
			return nil, err
		}
		return ias.daemonSetToUnstructured(daemonSet)

	case "ReplicaSet":
		replicaSet, err := ias.client.AppsV1().ReplicaSets(namespace).Get(ctx, ownerRef.Name, metav1.GetOptions{})
		if err != nil {
			return nil, err
		}
		return ias.replicaSetToUnstructured(replicaSet)

	default:
		return nil, errors.Errorf("unsupported workload kind: %s", ownerRef.Kind)
	}
}

// Conversion methods

func (ias *IngressAugmentationStrategy) serviceToUnstructured(service *v1.Service) (*unstructured.Unstructured, error) {
	unstructuredService := &unstructured.Unstructured{}
	unstructuredService.SetKind("Service")
	unstructuredService.SetAPIVersion("v1")
	unstructuredService.SetName(service.Name)
	unstructuredService.SetNamespace(service.Namespace)
	unstructuredService.SetUID(service.UID)
	unstructuredService.SetLabels(service.Labels)
	unstructuredService.SetAnnotations(service.Annotations)

	// Set spec
	if service.Spec.Selector != nil {
		unstructuredService.Object["spec"] = map[string]interface{}{
			"selector": service.Spec.Selector,
		}
	}

	return unstructuredService, nil
}

func (ias *IngressAugmentationStrategy) secretToUnstructured(secret *v1.Secret) (*unstructured.Unstructured, error) {
	unstructuredSecret := &unstructured.Unstructured{}
	unstructuredSecret.SetKind("Secret")
	unstructuredSecret.SetAPIVersion("v1")
	unstructuredSecret.SetName(secret.Name)
	unstructuredSecret.SetNamespace(secret.Namespace)
	unstructuredSecret.SetUID(secret.UID)
	unstructuredSecret.SetLabels(secret.Labels)
	unstructuredSecret.SetAnnotations(secret.Annotations)

	// Set type
	if secret.Type != "" {
		unstructuredSecret.Object["type"] = string(secret.Type)
	}

	return unstructuredSecret, nil
}

func (ias *IngressAugmentationStrategy) podToUnstructured(pod *v1.Pod) (*unstructured.Unstructured, error) {
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

func (ias *IngressAugmentationStrategy) ingressToUnstructured(ingress interface{}) (*unstructured.Unstructured, error) {
	// Implementation depends on the actual ingress type
	return nil, errors.New("conversion not implemented")
}

func (ias *IngressAugmentationStrategy) ingressClassToUnstructured(ingressClass interface{}) (*unstructured.Unstructured, error) {
	// Implementation depends on the actual ingress class type
	return nil, errors.New("conversion not implemented")
}

func (ias *IngressAugmentationStrategy) deploymentToUnstructured(deployment interface{}) (*unstructured.Unstructured, error) {
	// Implementation depends on the actual deployment type
	return nil, errors.New("conversion not implemented")
}

func (ias *IngressAugmentationStrategy) statefulSetToUnstructured(statefulSet interface{}) (*unstructured.Unstructured, error) {
	// Implementation depends on the actual statefulset type
	return nil, errors.New("conversion not implemented")
}

func (ias *IngressAugmentationStrategy) daemonSetToUnstructured(daemonSet interface{}) (*unstructured.Unstructured, error) {
	// Implementation depends on the actual daemonset type
	return nil, errors.New("conversion not implemented")
}

func (ias *IngressAugmentationStrategy) replicaSetToUnstructured(replicaSet interface{}) (*unstructured.Unstructured, error) {
	// Implementation depends on the actual replicaset type
	return nil, errors.New("conversion not implemented")
}

// IngressAugmentedResource methods

// GetBackendServices returns services referenced by this ingress
func (iar *IngressAugmentedResource) GetBackendServices() []*unstructured.Unstructured {
	return iar.BackendServices
}

// GetTLSSecrets returns TLS secrets used by this ingress
func (iar *IngressAugmentedResource) GetTLSSecrets() []*unstructured.Unstructured {
	return iar.TLSSecrets
}

// GetBackendWorkloads returns workloads behind this ingress
func (iar *IngressAugmentedResource) GetBackendWorkloads() []*unstructured.Unstructured {
	return iar.BackendWorkloads
}

// GetBackendPods returns pods behind this ingress
func (iar *IngressAugmentedResource) GetBackendPods() []*unstructured.Unstructured {
	return iar.BackendPods
}

// GetIngressClass returns the ingress class for this ingress
func (iar *IngressAugmentedResource) GetIngressClass() *unstructured.Unstructured {
	return iar.IngressClass
}

// GetRelatedIngresses returns other ingresses in the same namespace
func (iar *IngressAugmentedResource) GetRelatedIngresses() []*unstructured.Unstructured {
	return iar.RelatedIngresses
}

// HasTLSEnabled returns true if TLS is configured
func (iar *IngressAugmentedResource) HasTLSEnabled() bool {
	return iar.HasTLS
}

// GetHostCount returns the number of hosts configured
func (iar *IngressAugmentedResource) GetHostCount() int {
	return iar.HostCount
}

// GetPathCount returns the number of paths configured
func (iar *IngressAugmentedResource) GetPathCount() int {
	return iar.PathCount
}

// GetBackendServiceCount returns the number of backend services
func (iar *IngressAugmentedResource) GetBackendServiceCount() int {
	return iar.BackendServiceCount
}

// HasBackendServices returns true if there are backend services
func (iar *IngressAugmentedResource) HasBackendServices() bool {
	return len(iar.BackendServices) > 0
}

// HasTLSSecrets returns true if there are TLS secrets
func (iar *IngressAugmentedResource) HasTLSSecrets() bool {
	return len(iar.TLSSecrets) > 0
}

// HasBackendWorkloads returns true if there are backend workloads
func (iar *IngressAugmentedResource) HasBackendWorkloads() bool {
	return len(iar.BackendWorkloads) > 0
}

// HasIngressClass returns true if an ingress class is configured
func (iar *IngressAugmentedResource) HasIngressClass() bool {
	return iar.IngressClass != nil
}

// GetTLSSecretCount returns the number of TLS secrets
func (iar *IngressAugmentedResource) GetTLSSecretCount() int {
	return len(iar.TLSSecrets)
}

// GetBackendPodCount returns the number of backend pods
func (iar *IngressAugmentedResource) GetBackendPodCount() int {
	return len(iar.BackendPods)
}

// GetBackendWorkloadCount returns the number of backend workloads
func (iar *IngressAugmentedResource) GetBackendWorkloadCount() int {
	return len(iar.BackendWorkloads)
}
