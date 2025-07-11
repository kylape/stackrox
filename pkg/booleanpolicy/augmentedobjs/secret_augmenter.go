package augmentedobjs

import (
	"context"

	"github.com/pkg/errors"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/client-go/kubernetes"
)

// SecretAugmentedResource represents a Secret with related resources
type SecretAugmentedResource struct {
	*GenericAugmentedResource

	// Workloads that consume this Secret
	ConsumingWorkloads []*unstructured.Unstructured

	// Pods that mount this Secret
	ConsumingPods []*unstructured.Unstructured

	// ServiceAccounts that use this Secret
	ConsumingServiceAccounts []*unstructured.Unstructured

	// Ingresses that use this Secret for TLS
	ConsumingIngresses []*unstructured.Unstructured

	// Other Secrets in the same namespace
	RelatedSecrets []*unstructured.Unstructured

	// Secret type analysis
	SecretType                  string
	IsTLSSecret                 bool
	IsDockerSecret              bool
	IsServiceAccountTokenSecret bool
}

// SecretAugmentationStrategy augments Secrets with relationship context
type SecretAugmentationStrategy struct {
	client    kubernetes.Interface
	clusterID string
}

// NewSecretAugmentationStrategy creates a new Secret augmentation strategy
func NewSecretAugmentationStrategy(client kubernetes.Interface, clusterID string) *SecretAugmentationStrategy {
	return &SecretAugmentationStrategy{
		client:    client,
		clusterID: clusterID,
	}
}

// Augment augments a Secret with relationship context
func (sas *SecretAugmentationStrategy) Augment(ctx context.Context,
	resource *unstructured.Unstructured) (AugmentedResource, error) {

	if resource.GetKind() != "Secret" {
		return nil, errors.Errorf("expected Secret, got %s", resource.GetKind())
	}

	// Create base augmented resource
	base := NewGenericAugmentedResource(resource, sas.clusterID)

	augmented := &SecretAugmentedResource{
		GenericAugmentedResource: base,
		ConsumingWorkloads:       []*unstructured.Unstructured{},
		ConsumingPods:            []*unstructured.Unstructured{},
		ConsumingServiceAccounts: []*unstructured.Unstructured{},
		ConsumingIngresses:       []*unstructured.Unstructured{},
		RelatedSecrets:           []*unstructured.Unstructured{},
	}

	// Analyze secret type
	sas.analyzeSecretType(augmented, resource)

	// Discover relationships
	if err := sas.discoverRelationships(ctx, augmented, resource); err != nil {
		return nil, errors.Wrap(err, "discovering Secret relationships")
	}

	return augmented, nil
}

// SupportsKind returns true for Secret
func (sas *SecretAugmentationStrategy) SupportsKind(kind string) bool {
	return kind == "Secret"
}

// analyzeSecretType analyzes the secret type and sets flags
func (sas *SecretAugmentationStrategy) analyzeSecretType(augmented *SecretAugmentedResource,
	secret *unstructured.Unstructured) {

	secretType, found, err := unstructured.NestedString(secret.Object, "type")
	if err != nil || !found {
		secretType = "Opaque"
	}

	augmented.SecretType = secretType

	// Set type-specific flags
	switch secretType {
	case "kubernetes.io/tls":
		augmented.IsTLSSecret = true
	case "kubernetes.io/dockerconfigjson", "kubernetes.io/dockercfg":
		augmented.IsDockerSecret = true
	case "kubernetes.io/service-account-token":
		augmented.IsServiceAccountTokenSecret = true
	}
}

// discoverRelationships discovers resources related to the Secret
func (sas *SecretAugmentationStrategy) discoverRelationships(ctx context.Context,
	augmented *SecretAugmentedResource, secret *unstructured.Unstructured) error {

	namespace := secret.GetNamespace()
	secretName := secret.GetName()

	// Find pods that mount this Secret
	pods, err := sas.findConsumingPods(ctx, namespace, secretName)
	if err != nil {
		return errors.Wrap(err, "finding consuming pods")
	}
	augmented.ConsumingPods = pods

	// Find workloads that use this Secret
	workloads, err := sas.findConsumingWorkloads(ctx, namespace, secretName)
	if err != nil {
		return errors.Wrap(err, "finding consuming workloads")
	}
	augmented.ConsumingWorkloads = workloads

	// Find ServiceAccounts that use this Secret
	serviceAccounts, err := sas.findConsumingServiceAccounts(ctx, namespace, secretName)
	if err != nil {
		return errors.Wrap(err, "finding consuming service accounts")
	}
	augmented.ConsumingServiceAccounts = serviceAccounts

	// Find Ingresses that use this Secret for TLS (only for TLS secrets)
	if augmented.IsTLSSecret {
		ingresses, err := sas.findConsumingIngresses(ctx, namespace, secretName)
		if err != nil {
			return errors.Wrap(err, "finding consuming ingresses")
		}
		augmented.ConsumingIngresses = ingresses
	}

	// Find related Secrets in the same namespace
	relatedSecrets, err := sas.findRelatedSecrets(ctx, namespace, secretName)
	if err != nil {
		return errors.Wrap(err, "finding related secrets")
	}
	augmented.RelatedSecrets = relatedSecrets

	// Store relationships in the generic related resources map
	augmented.Related["Pod"] = augmented.ConsumingPods
	augmented.Related["Deployment"] = augmented.ConsumingWorkloads
	augmented.Related["ServiceAccount"] = augmented.ConsumingServiceAccounts
	augmented.Related["Ingress"] = augmented.ConsumingIngresses
	augmented.Related["Secret"] = augmented.RelatedSecrets

	return nil
}

// findConsumingPods finds pods that mount this Secret
func (sas *SecretAugmentationStrategy) findConsumingPods(ctx context.Context,
	namespace, secretName string) ([]*unstructured.Unstructured, error) {

	podList, err := sas.client.CoreV1().Pods(namespace).List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, errors.Wrap(err, "listing pods")
	}

	var consumingPods []*unstructured.Unstructured

	for _, pod := range podList.Items {
		if sas.podUsesSecret(&pod, secretName) {
			unstructuredPod, err := sas.podToUnstructured(&pod)
			if err != nil {
				continue // Skip pods that can't be converted
			}
			consumingPods = append(consumingPods, unstructuredPod)
		}
	}

	return consumingPods, nil
}

// findConsumingWorkloads finds workloads that use this Secret
func (sas *SecretAugmentationStrategy) findConsumingWorkloads(ctx context.Context,
	namespace, secretName string) ([]*unstructured.Unstructured, error) {

	var consumingWorkloads []*unstructured.Unstructured

	// Find Deployments
	deployments, err := sas.findConsumingDeployments(ctx, namespace, secretName)
	if err != nil {
		return nil, errors.Wrap(err, "finding consuming deployments")
	}
	consumingWorkloads = append(consumingWorkloads, deployments...)

	// Find StatefulSets
	statefulSets, err := sas.findConsumingStatefulSets(ctx, namespace, secretName)
	if err != nil {
		return nil, errors.Wrap(err, "finding consuming StatefulSets")
	}
	consumingWorkloads = append(consumingWorkloads, statefulSets...)

	// Find DaemonSets
	daemonSets, err := sas.findConsumingDaemonSets(ctx, namespace, secretName)
	if err != nil {
		return nil, errors.Wrap(err, "finding consuming DaemonSets")
	}
	consumingWorkloads = append(consumingWorkloads, daemonSets...)

	return consumingWorkloads, nil
}

// findConsumingDeployments finds deployments that use this Secret
func (sas *SecretAugmentationStrategy) findConsumingDeployments(ctx context.Context,
	namespace, secretName string) ([]*unstructured.Unstructured, error) {

	deploymentList, err := sas.client.AppsV1().Deployments(namespace).List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, errors.Wrap(err, "listing deployments")
	}

	var consumingDeployments []*unstructured.Unstructured

	for _, deployment := range deploymentList.Items {
		if sas.workloadUsesSecret(&deployment, secretName) {
			unstructuredDeployment, err := sas.deploymentToUnstructured(&deployment)
			if err != nil {
				continue // Skip deployments that can't be converted
			}
			consumingDeployments = append(consumingDeployments, unstructuredDeployment)
		}
	}

	return consumingDeployments, nil
}

// findConsumingStatefulSets finds StatefulSets that use this Secret
func (sas *SecretAugmentationStrategy) findConsumingStatefulSets(ctx context.Context,
	namespace, secretName string) ([]*unstructured.Unstructured, error) {

	statefulSetList, err := sas.client.AppsV1().StatefulSets(namespace).List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, errors.Wrap(err, "listing StatefulSets")
	}

	var consumingStatefulSets []*unstructured.Unstructured

	for _, sts := range statefulSetList.Items {
		if sas.workloadUsesSecret(&sts, secretName) {
			unstructuredSts, err := sas.statefulSetToUnstructured(&sts)
			if err != nil {
				continue // Skip StatefulSets that can't be converted
			}
			consumingStatefulSets = append(consumingStatefulSets, unstructuredSts)
		}
	}

	return consumingStatefulSets, nil
}

// findConsumingDaemonSets finds DaemonSets that use this Secret
func (sas *SecretAugmentationStrategy) findConsumingDaemonSets(ctx context.Context,
	namespace, secretName string) ([]*unstructured.Unstructured, error) {

	daemonSetList, err := sas.client.AppsV1().DaemonSets(namespace).List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, errors.Wrap(err, "listing DaemonSets")
	}

	var consumingDaemonSets []*unstructured.Unstructured

	for _, ds := range daemonSetList.Items {
		if sas.workloadUsesSecret(&ds, secretName) {
			unstructuredDs, err := sas.daemonSetToUnstructured(&ds)
			if err != nil {
				continue // Skip DaemonSets that can't be converted
			}
			consumingDaemonSets = append(consumingDaemonSets, unstructuredDs)
		}
	}

	return consumingDaemonSets, nil
}

// findConsumingServiceAccounts finds ServiceAccounts that use this Secret
func (sas *SecretAugmentationStrategy) findConsumingServiceAccounts(ctx context.Context,
	namespace, secretName string) ([]*unstructured.Unstructured, error) {

	serviceAccountList, err := sas.client.CoreV1().ServiceAccounts(namespace).List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, errors.Wrap(err, "listing service accounts")
	}

	var consumingServiceAccounts []*unstructured.Unstructured

	for _, sa := range serviceAccountList.Items {
		if sas.serviceAccountUsesSecret(&sa, secretName) {
			unstructuredSA, err := sas.serviceAccountToUnstructured(&sa)
			if err != nil {
				continue // Skip service accounts that can't be converted
			}
			consumingServiceAccounts = append(consumingServiceAccounts, unstructuredSA)
		}
	}

	return consumingServiceAccounts, nil
}

// findConsumingIngresses finds Ingresses that use this Secret for TLS
func (sas *SecretAugmentationStrategy) findConsumingIngresses(ctx context.Context,
	namespace, secretName string) ([]*unstructured.Unstructured, error) {

	ingressList, err := sas.client.NetworkingV1().Ingresses(namespace).List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, errors.Wrap(err, "listing ingresses")
	}

	var consumingIngresses []*unstructured.Unstructured

	for _, ingress := range ingressList.Items {
		if sas.ingressUsesSecret(&ingress, secretName) {
			unstructuredIngress, err := sas.ingressToUnstructured(&ingress)
			if err != nil {
				continue // Skip ingresses that can't be converted
			}
			consumingIngresses = append(consumingIngresses, unstructuredIngress)
		}
	}

	return consumingIngresses, nil
}

// findRelatedSecrets finds other Secrets in the same namespace
func (sas *SecretAugmentationStrategy) findRelatedSecrets(ctx context.Context,
	namespace, secretName string) ([]*unstructured.Unstructured, error) {

	secretList, err := sas.client.CoreV1().Secrets(namespace).List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, errors.Wrap(err, "listing secrets")
	}

	var relatedSecrets []*unstructured.Unstructured

	for _, secret := range secretList.Items {
		if secret.Name != secretName {
			unstructuredSecret, err := sas.secretToUnstructured(&secret)
			if err != nil {
				continue // Skip secrets that can't be converted
			}
			relatedSecrets = append(relatedSecrets, unstructuredSecret)
		}
	}

	return relatedSecrets, nil
}

// Helper methods to check if resources use the Secret

func (sas *SecretAugmentationStrategy) podUsesSecret(pod *v1.Pod, secretName string) bool {
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

		// Check envFrom
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

func (sas *SecretAugmentationStrategy) workloadUsesSecret(workload interface{}, secretName string) bool {
	// This is a simplified check - you'd need to implement for each workload type
	// For now, just return false as a placeholder
	return false
}

func (sas *SecretAugmentationStrategy) serviceAccountUsesSecret(sa *v1.ServiceAccount, secretName string) bool {
	// Check secrets
	for _, secret := range sa.Secrets {
		if secret.Name == secretName {
			return true
		}
	}

	// Check image pull secrets
	for _, imagePullSecret := range sa.ImagePullSecrets {
		if imagePullSecret.Name == secretName {
			return true
		}
	}

	return false
}

func (sas *SecretAugmentationStrategy) ingressUsesSecret(ingress interface{}, secretName string) bool {
	// This is a simplified check - you'd need to implement for ingress type
	// For now, just return false as a placeholder
	return false
}

// Conversion methods

func (sas *SecretAugmentationStrategy) podToUnstructured(pod *v1.Pod) (*unstructured.Unstructured, error) {
	unstructuredPod := &unstructured.Unstructured{}
	unstructuredPod.SetKind("Pod")
	unstructuredPod.SetAPIVersion("v1")
	unstructuredPod.SetName(pod.Name)
	unstructuredPod.SetNamespace(pod.Namespace)
	unstructuredPod.SetUID(pod.UID)
	unstructuredPod.SetLabels(pod.Labels)
	unstructuredPod.SetAnnotations(pod.Annotations)

	return unstructuredPod, nil
}

func (sas *SecretAugmentationStrategy) deploymentToUnstructured(deployment interface{}) (*unstructured.Unstructured, error) {
	// Implementation depends on the actual deployment type
	return nil, errors.New("conversion not implemented")
}

func (sas *SecretAugmentationStrategy) statefulSetToUnstructured(statefulSet interface{}) (*unstructured.Unstructured, error) {
	// Implementation depends on the actual statefulset type
	return nil, errors.New("conversion not implemented")
}

func (sas *SecretAugmentationStrategy) daemonSetToUnstructured(daemonSet interface{}) (*unstructured.Unstructured, error) {
	// Implementation depends on the actual daemonset type
	return nil, errors.New("conversion not implemented")
}

func (sas *SecretAugmentationStrategy) serviceAccountToUnstructured(sa *v1.ServiceAccount) (*unstructured.Unstructured, error) {
	unstructuredSA := &unstructured.Unstructured{}
	unstructuredSA.SetKind("ServiceAccount")
	unstructuredSA.SetAPIVersion("v1")
	unstructuredSA.SetName(sa.Name)
	unstructuredSA.SetNamespace(sa.Namespace)
	unstructuredSA.SetUID(sa.UID)
	unstructuredSA.SetLabels(sa.Labels)
	unstructuredSA.SetAnnotations(sa.Annotations)

	return unstructuredSA, nil
}

func (sas *SecretAugmentationStrategy) ingressToUnstructured(ingress interface{}) (*unstructured.Unstructured, error) {
	// Implementation depends on the actual ingress type
	return nil, errors.New("conversion not implemented")
}

func (sas *SecretAugmentationStrategy) secretToUnstructured(secret *v1.Secret) (*unstructured.Unstructured, error) {
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

	// Set data (without exposing sensitive values)
	if secret.Data != nil {
		data := make(map[string]interface{})
		for key := range secret.Data {
			data[key] = "<redacted>"
		}
		unstructuredSecret.Object["data"] = data
	}

	return unstructuredSecret, nil
}

// SecretAugmentedResource methods

// GetConsumingWorkloads returns workloads that use this Secret
func (sar *SecretAugmentedResource) GetConsumingWorkloads() []*unstructured.Unstructured {
	return sar.ConsumingWorkloads
}

// GetConsumingPods returns pods that mount this Secret
func (sar *SecretAugmentedResource) GetConsumingPods() []*unstructured.Unstructured {
	return sar.ConsumingPods
}

// GetConsumingServiceAccounts returns service accounts that use this Secret
func (sar *SecretAugmentedResource) GetConsumingServiceAccounts() []*unstructured.Unstructured {
	return sar.ConsumingServiceAccounts
}

// GetConsumingIngresses returns ingresses that use this Secret for TLS
func (sar *SecretAugmentedResource) GetConsumingIngresses() []*unstructured.Unstructured {
	return sar.ConsumingIngresses
}

// GetRelatedSecrets returns other Secrets in the same namespace
func (sar *SecretAugmentedResource) GetRelatedSecrets() []*unstructured.Unstructured {
	return sar.RelatedSecrets
}

// GetSecretType returns the type of this Secret
func (sar *SecretAugmentedResource) GetSecretType() string {
	return sar.SecretType
}

// IsTLS returns true if this is a TLS secret
func (sar *SecretAugmentedResource) IsTLS() bool {
	return sar.IsTLSSecret
}

// IsDocker returns true if this is a Docker registry secret
func (sar *SecretAugmentedResource) IsDocker() bool {
	return sar.IsDockerSecret
}

// IsServiceAccountToken returns true if this is a service account token
func (sar *SecretAugmentedResource) IsServiceAccountToken() bool {
	return sar.IsServiceAccountTokenSecret
}

// HasConsumingWorkloads returns true if any workloads use this Secret
func (sar *SecretAugmentedResource) HasConsumingWorkloads() bool {
	return len(sar.ConsumingWorkloads) > 0
}

// HasConsumingPods returns true if any pods mount this Secret
func (sar *SecretAugmentedResource) HasConsumingPods() bool {
	return len(sar.ConsumingPods) > 0
}

// HasConsumingServiceAccounts returns true if any service accounts use this Secret
func (sar *SecretAugmentedResource) HasConsumingServiceAccounts() bool {
	return len(sar.ConsumingServiceAccounts) > 0
}

// HasConsumingIngresses returns true if any ingresses use this Secret for TLS
func (sar *SecretAugmentedResource) HasConsumingIngresses() bool {
	return len(sar.ConsumingIngresses) > 0
}

// GetConsumingWorkloadCount returns the number of workloads using this Secret
func (sar *SecretAugmentedResource) GetConsumingWorkloadCount() int {
	return len(sar.ConsumingWorkloads)
}

// GetConsumingPodCount returns the number of pods mounting this Secret
func (sar *SecretAugmentedResource) GetConsumingPodCount() int {
	return len(sar.ConsumingPods)
}
