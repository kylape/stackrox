package augmentedobjs

import (
	"context"
	"fmt"
	"sync"

	"github.com/pkg/errors"
	"github.com/stackrox/rox/pkg/logging"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/client-go/kubernetes"
)

var (
	discoveryLog = logging.LoggerForModule()
)

// RelationshipDiscoverer discovers relationships between Kubernetes resources
type RelationshipDiscoverer struct {
	client    kubernetes.Interface
	clusterID string

	// Cache for discovered relationships to avoid repeated API calls
	relationshipCache map[string]map[string][]*unstructured.Unstructured
	cacheMutex        sync.RWMutex
}

// NewRelationshipDiscoverer creates a new relationship discoverer
func NewRelationshipDiscoverer(client kubernetes.Interface, clusterID string) *RelationshipDiscoverer {
	return &RelationshipDiscoverer{
		client:            client,
		clusterID:         clusterID,
		relationshipCache: make(map[string]map[string][]*unstructured.Unstructured),
	}
}

// DiscoverRelationships discovers all relationships for a given resource
func (rd *RelationshipDiscoverer) DiscoverRelationships(ctx context.Context,
	resource *unstructured.Unstructured) (map[string][]*unstructured.Unstructured, error) {

	// Check cache first
	cacheKey := rd.getCacheKey(resource)
	if cached := rd.getCachedRelationships(cacheKey); cached != nil {
		return cached, nil
	}

	relationships := make(map[string][]*unstructured.Unstructured)

	// Discover relationships based on resource type
	switch resource.GetKind() {
	case "ConfigMap":
		if err := rd.discoverConfigMapRelationships(ctx, resource, relationships); err != nil {
			discoveryLog.Warnf("Error discovering ConfigMap relationships: %v", err)
		}
	case "Secret":
		if err := rd.discoverSecretRelationships(ctx, resource, relationships); err != nil {
			discoveryLog.Warnf("Error discovering Secret relationships: %v", err)
		}
	case "Service":
		if err := rd.discoverServiceRelationships(ctx, resource, relationships); err != nil {
			discoveryLog.Warnf("Error discovering Service relationships: %v", err)
		}
	case "Ingress":
		if err := rd.discoverIngressRelationships(ctx, resource, relationships); err != nil {
			discoveryLog.Warnf("Error discovering Ingress relationships: %v", err)
		}
	case "Pod":
		if err := rd.discoverPodRelationships(ctx, resource, relationships); err != nil {
			discoveryLog.Warnf("Error discovering Pod relationships: %v", err)
		}
	case "Deployment", "StatefulSet", "DaemonSet", "ReplicaSet":
		if err := rd.discoverWorkloadRelationships(ctx, resource, relationships); err != nil {
			discoveryLog.Warnf("Error discovering workload relationships: %v", err)
		}
	case "ServiceAccount":
		if err := rd.discoverServiceAccountRelationships(ctx, resource, relationships); err != nil {
			discoveryLog.Warnf("Error discovering ServiceAccount relationships: %v", err)
		}
	case "NetworkPolicy":
		if err := rd.discoverNetworkPolicyRelationships(ctx, resource, relationships); err != nil {
			discoveryLog.Warnf("Error discovering NetworkPolicy relationships: %v", err)
		}
	}

	// Cache the relationships
	rd.cacheRelationships(cacheKey, relationships)

	return relationships, nil
}

// discoverConfigMapRelationships discovers relationships for ConfigMaps
func (rd *RelationshipDiscoverer) discoverConfigMapRelationships(ctx context.Context,
	cm *unstructured.Unstructured, relationships map[string][]*unstructured.Unstructured) error {

	namespace := cm.GetNamespace()
	configMapName := cm.GetName()

	// Find pods that mount this ConfigMap
	pods, err := rd.findPodsUsingConfigMap(ctx, namespace, configMapName)
	if err != nil {
		return errors.Wrap(err, "finding pods using ConfigMap")
	}
	relationships["Pod"] = pods

	// Find workloads that use this ConfigMap
	workloads, err := rd.findWorkloadsUsingConfigMap(ctx, namespace, configMapName)
	if err != nil {
		return errors.Wrap(err, "finding workloads using ConfigMap")
	}
	relationships["Deployment"] = workloads

	return nil
}

// discoverSecretRelationships discovers relationships for Secrets
func (rd *RelationshipDiscoverer) discoverSecretRelationships(ctx context.Context,
	secret *unstructured.Unstructured, relationships map[string][]*unstructured.Unstructured) error {

	namespace := secret.GetNamespace()
	secretName := secret.GetName()

	// Find pods that use this Secret
	pods, err := rd.findPodsUsingSecret(ctx, namespace, secretName)
	if err != nil {
		return errors.Wrap(err, "finding pods using Secret")
	}
	relationships["Pod"] = pods

	// Find workloads that use this Secret
	workloads, err := rd.findWorkloadsUsingSecret(ctx, namespace, secretName)
	if err != nil {
		return errors.Wrap(err, "finding workloads using Secret")
	}
	relationships["Deployment"] = workloads

	// Find ServiceAccounts that use this Secret
	serviceAccounts, err := rd.findServiceAccountsUsingSecret(ctx, namespace, secretName)
	if err != nil {
		return errors.Wrap(err, "finding ServiceAccounts using Secret")
	}
	relationships["ServiceAccount"] = serviceAccounts

	// Find Ingresses that use this Secret (for TLS secrets)
	secretType, found, err := unstructured.NestedString(secret.Object, "type")
	if err == nil && found && secretType == "kubernetes.io/tls" {
		ingresses, err := rd.findIngressesUsingSecret(ctx, namespace, secretName)
		if err != nil {
			return errors.Wrap(err, "finding Ingresses using Secret")
		}
		relationships["Ingress"] = ingresses
	}

	return nil
}

// discoverServiceRelationships discovers relationships for Services
func (rd *RelationshipDiscoverer) discoverServiceRelationships(ctx context.Context,
	service *unstructured.Unstructured, relationships map[string][]*unstructured.Unstructured) error {

	namespace := service.GetNamespace()
	serviceName := service.GetName()

	// Get service selector
	selector, found, err := unstructured.NestedStringMap(service.Object, "spec", "selector")
	if err != nil || !found {
		return nil // Service has no selector (e.g., ExternalName service)
	}

	// Find pods selected by this service
	pods, err := rd.findPodsWithSelector(ctx, namespace, selector)
	if err != nil {
		return errors.Wrap(err, "finding pods selected by Service")
	}
	relationships["Pod"] = pods

	// Find workloads that own these pods
	workloads, err := rd.findWorkloadsFromPods(ctx, pods)
	if err != nil {
		return errors.Wrap(err, "finding workloads from pods")
	}
	relationships["Deployment"] = workloads

	// Find endpoints for this service
	endpoints, err := rd.findEndpointsForService(ctx, namespace, serviceName)
	if err != nil {
		return errors.Wrap(err, "finding endpoints for Service")
	}
	relationships["Endpoints"] = endpoints

	// Find ingresses that route to this service
	ingresses, err := rd.findIngressesForService(ctx, namespace, serviceName)
	if err != nil {
		return errors.Wrap(err, "finding Ingresses for Service")
	}
	relationships["Ingress"] = ingresses

	// Find network policies that affect this service
	networkPolicies, err := rd.findNetworkPoliciesForService(ctx, namespace, selector)
	if err != nil {
		return errors.Wrap(err, "finding NetworkPolicies for Service")
	}
	relationships["NetworkPolicy"] = networkPolicies

	return nil
}

// discoverIngressRelationships discovers relationships for Ingresses
func (rd *RelationshipDiscoverer) discoverIngressRelationships(ctx context.Context,
	ingress *unstructured.Unstructured, relationships map[string][]*unstructured.Unstructured) error {

	namespace := ingress.GetNamespace()

	// Find backend services
	services, err := rd.findBackendServicesForIngress(ctx, namespace, ingress)
	if err != nil {
		return errors.Wrap(err, "finding backend services for Ingress")
	}
	relationships["Service"] = services

	// Find TLS secrets
	secrets, err := rd.findTLSSecretsForIngress(ctx, namespace, ingress)
	if err != nil {
		return errors.Wrap(err, "finding TLS secrets for Ingress")
	}
	relationships["Secret"] = secrets

	// Find backend workloads and pods through services
	var allPods []*unstructured.Unstructured
	var allWorkloads []*unstructured.Unstructured

	for _, service := range services {
		// Get service selector
		selector, found, err := unstructured.NestedStringMap(service.Object, "spec", "selector")
		if err != nil || !found {
			continue
		}

		// Find pods selected by this service
		pods, err := rd.findPodsWithSelector(ctx, namespace, selector)
		if err != nil {
			continue
		}
		allPods = append(allPods, pods...)

		// Find workloads from pods
		workloads, err := rd.findWorkloadsFromPods(ctx, pods)
		if err != nil {
			continue
		}
		allWorkloads = append(allWorkloads, workloads...)
	}

	relationships["Pod"] = allPods
	relationships["Deployment"] = allWorkloads

	return nil
}

// discoverPodRelationships discovers relationships for Pods
func (rd *RelationshipDiscoverer) discoverPodRelationships(ctx context.Context,
	pod *unstructured.Unstructured, relationships map[string][]*unstructured.Unstructured) error {

	namespace := pod.GetNamespace()

	// Find owner workloads
	ownerRefs := pod.GetOwnerReferences()
	var workloads []*unstructured.Unstructured

	for _, ownerRef := range ownerRefs {
		if rd.isWorkloadKind(ownerRef.Kind) {
			workload, err := rd.findWorkloadByOwnerRef(ctx, namespace, ownerRef)
			if err != nil {
				continue
			}
			workloads = append(workloads, workload)
		}
	}
	relationships["Deployment"] = workloads

	// Find services that select this pod
	services, err := rd.findServicesForPod(ctx, namespace, pod)
	if err != nil {
		return errors.Wrap(err, "finding services for Pod")
	}
	relationships["Service"] = services

	// Find ConfigMaps and Secrets used by this pod
	configMaps, secrets, err := rd.findConfigMapsAndSecretsForPod(ctx, namespace, pod)
	if err != nil {
		return errors.Wrap(err, "finding ConfigMaps and Secrets for Pod")
	}
	relationships["ConfigMap"] = configMaps
	relationships["Secret"] = secrets

	return nil
}

// discoverWorkloadRelationships discovers relationships for workloads
func (rd *RelationshipDiscoverer) discoverWorkloadRelationships(ctx context.Context,
	workload *unstructured.Unstructured, relationships map[string][]*unstructured.Unstructured) error {

	namespace := workload.GetNamespace()
	workloadName := workload.GetName()

	// Find pods owned by this workload
	pods, err := rd.findPodsOwnedByWorkload(ctx, namespace, workload.GetKind(), workloadName)
	if err != nil {
		return errors.Wrap(err, "finding pods owned by workload")
	}
	relationships["Pod"] = pods

	// Find services that select pods of this workload
	services, err := rd.findServicesForWorkload(ctx, namespace, workload)
	if err != nil {
		return errors.Wrap(err, "finding services for workload")
	}
	relationships["Service"] = services

	// Find ConfigMaps and Secrets used by this workload
	configMaps, secrets, err := rd.findConfigMapsAndSecretsForWorkload(ctx, workload)
	if err != nil {
		return errors.Wrap(err, "finding ConfigMaps and Secrets for workload")
	}
	relationships["ConfigMap"] = configMaps
	relationships["Secret"] = secrets

	return nil
}

// discoverServiceAccountRelationships discovers relationships for ServiceAccounts
func (rd *RelationshipDiscoverer) discoverServiceAccountRelationships(ctx context.Context,
	sa *unstructured.Unstructured, relationships map[string][]*unstructured.Unstructured) error {

	namespace := sa.GetNamespace()
	saName := sa.GetName()

	// Find pods that use this ServiceAccount
	pods, err := rd.findPodsUsingServiceAccount(ctx, namespace, saName)
	if err != nil {
		return errors.Wrap(err, "finding pods using ServiceAccount")
	}
	relationships["Pod"] = pods

	// Find workloads that use this ServiceAccount
	workloads, err := rd.findWorkloadsUsingServiceAccount(ctx, namespace, saName)
	if err != nil {
		return errors.Wrap(err, "finding workloads using ServiceAccount")
	}
	relationships["Deployment"] = workloads

	// Find secrets referenced by this ServiceAccount
	secrets, err := rd.findSecretsForServiceAccount(ctx, namespace, sa)
	if err != nil {
		return errors.Wrap(err, "finding secrets for ServiceAccount")
	}
	relationships["Secret"] = secrets

	return nil
}

// discoverNetworkPolicyRelationships discovers relationships for NetworkPolicies
func (rd *RelationshipDiscoverer) discoverNetworkPolicyRelationships(ctx context.Context,
	netpol *unstructured.Unstructured, relationships map[string][]*unstructured.Unstructured) error {

	namespace := netpol.GetNamespace()

	// Find pods affected by this NetworkPolicy
	podSelector, found, err := unstructured.NestedStringMap(netpol.Object, "spec", "podSelector", "matchLabels")
	if err != nil || !found {
		return nil
	}

	pods, err := rd.findPodsWithSelector(ctx, namespace, podSelector)
	if err != nil {
		return errors.Wrap(err, "finding pods affected by NetworkPolicy")
	}
	relationships["Pod"] = pods

	// Find workloads that own these pods
	workloads, err := rd.findWorkloadsFromPods(ctx, pods)
	if err != nil {
		return errors.Wrap(err, "finding workloads from pods")
	}
	relationships["Deployment"] = workloads

	// Find services that select these pods
	services, err := rd.findServicesForPods(ctx, namespace, pods)
	if err != nil {
		return errors.Wrap(err, "finding services for pods")
	}
	relationships["Service"] = services

	return nil
}

// Helper methods for finding resources

func (rd *RelationshipDiscoverer) findPodsUsingConfigMap(ctx context.Context,
	namespace, configMapName string) ([]*unstructured.Unstructured, error) {

	podList, err := rd.client.CoreV1().Pods(namespace).List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, err
	}

	var pods []*unstructured.Unstructured
	for _, pod := range podList.Items {
		if rd.podUsesConfigMap(&pod, configMapName) {
			unstructuredPod := rd.podToUnstructured(&pod)
			pods = append(pods, unstructuredPod)
		}
	}

	return pods, nil
}

func (rd *RelationshipDiscoverer) findPodsUsingSecret(ctx context.Context,
	namespace, secretName string) ([]*unstructured.Unstructured, error) {

	podList, err := rd.client.CoreV1().Pods(namespace).List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, err
	}

	var pods []*unstructured.Unstructured
	for _, pod := range podList.Items {
		if rd.podUsesSecret(&pod, secretName) {
			unstructuredPod := rd.podToUnstructured(&pod)
			pods = append(pods, unstructuredPod)
		}
	}

	return pods, nil
}

func (rd *RelationshipDiscoverer) findPodsWithSelector(ctx context.Context,
	namespace string, selector map[string]string) ([]*unstructured.Unstructured, error) {

	labelSelector := labels.SelectorFromSet(selector)
	podList, err := rd.client.CoreV1().Pods(namespace).List(ctx, metav1.ListOptions{
		LabelSelector: labelSelector.String(),
	})
	if err != nil {
		return nil, err
	}

	var pods []*unstructured.Unstructured
	for _, pod := range podList.Items {
		unstructuredPod := rd.podToUnstructured(&pod)
		pods = append(pods, unstructuredPod)
	}

	return pods, nil
}

func (rd *RelationshipDiscoverer) findWorkloadsFromPods(ctx context.Context,
	pods []*unstructured.Unstructured) ([]*unstructured.Unstructured, error) {

	workloadMap := make(map[string]*unstructured.Unstructured)

	for _, pod := range pods {
		ownerRefs := pod.GetOwnerReferences()
		for _, ownerRef := range ownerRefs {
			if rd.isWorkloadKind(ownerRef.Kind) {
				workloadKey := fmt.Sprintf("%s/%s/%s", ownerRef.Kind, pod.GetNamespace(), ownerRef.Name)
				if _, exists := workloadMap[workloadKey]; !exists {
					workload, err := rd.findWorkloadByOwnerRef(ctx, pod.GetNamespace(), ownerRef)
					if err != nil {
						continue
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

// Additional helper methods would go here...
// For brevity, I'll include just the key ones and placeholders for others

func (rd *RelationshipDiscoverer) findWorkloadsUsingConfigMap(ctx context.Context,
	namespace, configMapName string) ([]*unstructured.Unstructured, error) {
	// Implementation would check Deployments, StatefulSets, DaemonSets, etc.
	// This is a placeholder - full implementation would be similar to ConfigMapAugmentationStrategy
	return []*unstructured.Unstructured{}, nil
}

func (rd *RelationshipDiscoverer) findWorkloadsUsingSecret(ctx context.Context,
	namespace, secretName string) ([]*unstructured.Unstructured, error) {
	// Implementation would check Deployments, StatefulSets, DaemonSets, etc.
	// This is a placeholder - full implementation would be similar to SecretAugmentationStrategy
	return []*unstructured.Unstructured{}, nil
}

func (rd *RelationshipDiscoverer) findServiceAccountsUsingSecret(ctx context.Context,
	namespace, secretName string) ([]*unstructured.Unstructured, error) {
	// Implementation would check ServiceAccounts
	return []*unstructured.Unstructured{}, nil
}

func (rd *RelationshipDiscoverer) findIngressesUsingSecret(ctx context.Context,
	namespace, secretName string) ([]*unstructured.Unstructured, error) {
	// Implementation would check Ingresses for TLS secrets
	return []*unstructured.Unstructured{}, nil
}

func (rd *RelationshipDiscoverer) findEndpointsForService(ctx context.Context,
	namespace, serviceName string) ([]*unstructured.Unstructured, error) {
	// Implementation would find Endpoints resource
	return []*unstructured.Unstructured{}, nil
}

func (rd *RelationshipDiscoverer) findIngressesForService(ctx context.Context,
	namespace, serviceName string) ([]*unstructured.Unstructured, error) {
	// Implementation would find Ingresses that route to this service
	return []*unstructured.Unstructured{}, nil
}

func (rd *RelationshipDiscoverer) findNetworkPoliciesForService(ctx context.Context,
	namespace string, selector map[string]string) ([]*unstructured.Unstructured, error) {
	// Implementation would find NetworkPolicies that affect these pods
	return []*unstructured.Unstructured{}, nil
}

func (rd *RelationshipDiscoverer) findBackendServicesForIngress(ctx context.Context,
	namespace string, ingress *unstructured.Unstructured) ([]*unstructured.Unstructured, error) {
	// Implementation would extract service references from ingress rules
	return []*unstructured.Unstructured{}, nil
}

func (rd *RelationshipDiscoverer) findTLSSecretsForIngress(ctx context.Context,
	namespace string, ingress *unstructured.Unstructured) ([]*unstructured.Unstructured, error) {
	// Implementation would extract TLS secret references
	return []*unstructured.Unstructured{}, nil
}

func (rd *RelationshipDiscoverer) findServicesForPod(ctx context.Context,
	namespace string, pod *unstructured.Unstructured) ([]*unstructured.Unstructured, error) {
	// Implementation would find services that select this pod
	return []*unstructured.Unstructured{}, nil
}

func (rd *RelationshipDiscoverer) findConfigMapsAndSecretsForPod(ctx context.Context,
	namespace string, pod *unstructured.Unstructured) ([]*unstructured.Unstructured, []*unstructured.Unstructured, error) {
	// Implementation would extract ConfigMap and Secret references from pod spec
	return []*unstructured.Unstructured{}, []*unstructured.Unstructured{}, nil
}

func (rd *RelationshipDiscoverer) findPodsOwnedByWorkload(ctx context.Context,
	namespace, workloadKind, workloadName string) ([]*unstructured.Unstructured, error) {
	// Implementation would find pods with matching owner references
	return []*unstructured.Unstructured{}, nil
}

func (rd *RelationshipDiscoverer) findServicesForWorkload(ctx context.Context,
	namespace string, workload *unstructured.Unstructured) ([]*unstructured.Unstructured, error) {
	// Implementation would find services that select workload's pods
	return []*unstructured.Unstructured{}, nil
}

func (rd *RelationshipDiscoverer) findConfigMapsAndSecretsForWorkload(ctx context.Context,
	workload *unstructured.Unstructured) ([]*unstructured.Unstructured, []*unstructured.Unstructured, error) {
	// Implementation would extract ConfigMap and Secret references from workload spec
	return []*unstructured.Unstructured{}, []*unstructured.Unstructured{}, nil
}

func (rd *RelationshipDiscoverer) findPodsUsingServiceAccount(ctx context.Context,
	namespace, saName string) ([]*unstructured.Unstructured, error) {
	// Implementation would find pods that use this ServiceAccount
	return []*unstructured.Unstructured{}, nil
}

func (rd *RelationshipDiscoverer) findWorkloadsUsingServiceAccount(ctx context.Context,
	namespace, saName string) ([]*unstructured.Unstructured, error) {
	// Implementation would find workloads that use this ServiceAccount
	return []*unstructured.Unstructured{}, nil
}

func (rd *RelationshipDiscoverer) findSecretsForServiceAccount(ctx context.Context,
	namespace string, sa *unstructured.Unstructured) ([]*unstructured.Unstructured, error) {
	// Implementation would find secrets referenced by ServiceAccount
	return []*unstructured.Unstructured{}, nil
}

func (rd *RelationshipDiscoverer) findServicesForPods(ctx context.Context,
	namespace string, pods []*unstructured.Unstructured) ([]*unstructured.Unstructured, error) {
	// Implementation would find services that select these pods
	return []*unstructured.Unstructured{}, nil
}

// Helper methods for checking resource usage

func (rd *RelationshipDiscoverer) podUsesConfigMap(pod *v1.Pod, configMapName string) bool {
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

		for _, envFrom := range container.EnvFrom {
			if envFrom.ConfigMapRef != nil && envFrom.ConfigMapRef.Name == configMapName {
				return true
			}
		}
	}

	return false
}

func (rd *RelationshipDiscoverer) podUsesSecret(pod *v1.Pod, secretName string) bool {
	// Check volumes
	for _, volume := range pod.Spec.Volumes {
		if volume.Secret != nil && volume.Secret.SecretName == secretName {
			return true
		}
	}

	// Check environment variables
	for _, container := range pod.Spec.Containers {
		for _, env := range container.Env {
			if env.ValueFrom != nil && env.ValueFrom.SecretKeyRef != nil &&
				env.ValueFrom.SecretKeyRef.Name == secretName {
				return true
			}
		}

		for _, envFrom := range container.EnvFrom {
			if envFrom.SecretRef != nil && envFrom.SecretRef.Name == secretName {
				return true
			}
		}
	}

	// Check image pull secrets
	for _, imagePullSecret := range pod.Spec.ImagePullSecrets {
		if imagePullSecret.Name == secretName {
			return true
		}
	}

	return false
}

func (rd *RelationshipDiscoverer) isWorkloadKind(kind string) bool {
	workloadKinds := []string{"Deployment", "StatefulSet", "DaemonSet", "ReplicaSet", "Job", "CronJob"}
	for _, workloadKind := range workloadKinds {
		if kind == workloadKind {
			return true
		}
	}
	return false
}

func (rd *RelationshipDiscoverer) findWorkloadByOwnerRef(ctx context.Context,
	namespace string, ownerRef metav1.OwnerReference) (*unstructured.Unstructured, error) {

	switch ownerRef.Kind {
	case "Deployment":
		deployment, err := rd.client.AppsV1().Deployments(namespace).Get(ctx, ownerRef.Name, metav1.GetOptions{})
		if err != nil {
			return nil, err
		}
		return rd.deploymentToUnstructured(deployment), nil

	case "StatefulSet":
		statefulSet, err := rd.client.AppsV1().StatefulSets(namespace).Get(ctx, ownerRef.Name, metav1.GetOptions{})
		if err != nil {
			return nil, err
		}
		return rd.statefulSetToUnstructured(statefulSet), nil

	case "DaemonSet":
		daemonSet, err := rd.client.AppsV1().DaemonSets(namespace).Get(ctx, ownerRef.Name, metav1.GetOptions{})
		if err != nil {
			return nil, err
		}
		return rd.daemonSetToUnstructured(daemonSet), nil

	case "ReplicaSet":
		replicaSet, err := rd.client.AppsV1().ReplicaSets(namespace).Get(ctx, ownerRef.Name, metav1.GetOptions{})
		if err != nil {
			return nil, err
		}
		return rd.replicaSetToUnstructured(replicaSet), nil

	default:
		return nil, errors.Errorf("unsupported workload kind: %s", ownerRef.Kind)
	}
}

// Conversion methods

func (rd *RelationshipDiscoverer) podToUnstructured(pod *v1.Pod) *unstructured.Unstructured {
	unstructuredPod := &unstructured.Unstructured{}
	unstructuredPod.SetKind("Pod")
	unstructuredPod.SetAPIVersion("v1")
	unstructuredPod.SetName(pod.Name)
	unstructuredPod.SetNamespace(pod.Namespace)
	unstructuredPod.SetUID(pod.UID)
	unstructuredPod.SetLabels(pod.Labels)
	unstructuredPod.SetAnnotations(pod.Annotations)
	unstructuredPod.SetOwnerReferences(pod.OwnerReferences)

	return unstructuredPod
}

func (rd *RelationshipDiscoverer) deploymentToUnstructured(deployment interface{}) *unstructured.Unstructured {
	// Simplified conversion - in practice would use proper conversion
	unstructuredDeployment := &unstructured.Unstructured{}
	unstructuredDeployment.SetKind("Deployment")
	unstructuredDeployment.SetAPIVersion("apps/v1")
	return unstructuredDeployment
}

func (rd *RelationshipDiscoverer) statefulSetToUnstructured(statefulSet interface{}) *unstructured.Unstructured {
	// Simplified conversion - in practice would use proper conversion
	unstructuredStatefulSet := &unstructured.Unstructured{}
	unstructuredStatefulSet.SetKind("StatefulSet")
	unstructuredStatefulSet.SetAPIVersion("apps/v1")
	return unstructuredStatefulSet
}

func (rd *RelationshipDiscoverer) daemonSetToUnstructured(daemonSet interface{}) *unstructured.Unstructured {
	// Simplified conversion - in practice would use proper conversion
	unstructuredDaemonSet := &unstructured.Unstructured{}
	unstructuredDaemonSet.SetKind("DaemonSet")
	unstructuredDaemonSet.SetAPIVersion("apps/v1")
	return unstructuredDaemonSet
}

func (rd *RelationshipDiscoverer) replicaSetToUnstructured(replicaSet interface{}) *unstructured.Unstructured {
	// Simplified conversion - in practice would use proper conversion
	unstructuredReplicaSet := &unstructured.Unstructured{}
	unstructuredReplicaSet.SetKind("ReplicaSet")
	unstructuredReplicaSet.SetAPIVersion("apps/v1")
	return unstructuredReplicaSet
}

// Cache methods

func (rd *RelationshipDiscoverer) getCacheKey(resource *unstructured.Unstructured) string {
	return fmt.Sprintf("%s/%s/%s/%s", resource.GetKind(), resource.GetNamespace(), resource.GetName(), resource.GetUID())
}

func (rd *RelationshipDiscoverer) getCachedRelationships(cacheKey string) map[string][]*unstructured.Unstructured {
	rd.cacheMutex.RLock()
	defer rd.cacheMutex.RUnlock()

	return rd.relationshipCache[cacheKey]
}

func (rd *RelationshipDiscoverer) cacheRelationships(cacheKey string, relationships map[string][]*unstructured.Unstructured) {
	rd.cacheMutex.Lock()
	defer rd.cacheMutex.Unlock()

	rd.relationshipCache[cacheKey] = relationships
}

// ClearCache clears the relationship cache
func (rd *RelationshipDiscoverer) ClearCache() {
	rd.cacheMutex.Lock()
	defer rd.cacheMutex.Unlock()

	rd.relationshipCache = make(map[string]map[string][]*unstructured.Unstructured)
}

// GetCacheSize returns the number of cached relationships
func (rd *RelationshipDiscoverer) GetCacheSize() int {
	rd.cacheMutex.RLock()
	defer rd.cacheMutex.RUnlock()

	return len(rd.relationshipCache)
}
