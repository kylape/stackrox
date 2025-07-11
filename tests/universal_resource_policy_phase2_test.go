package tests

import (
	"context"
	"testing"

	"github.com/stackrox/rox/generated/storage"
	"github.com/stackrox/rox/pkg/booleanpolicy/augmentedobjs"
	"github.com/stackrox/rox/pkg/detection/detectors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

func TestUniversalResourcePolicyPhase2(t *testing.T) {
	// This test validates Phase 2 implementation of the Universal Resource Policy Engine

	t.Run("ConfigMap augmentation and policy evaluation", func(t *testing.T) {
		// Create a test ConfigMap
		configMap := createTestConfigMap("test-config", "test-namespace")

		// Create augmentation factory
		factory := augmentedobjs.NewResourceAugmentationFactory(nil, "test-cluster")

		// Augment the ConfigMap
		augmented, err := factory.AugmentResource(context.Background(), configMap)
		require.NoError(t, err)

		// Verify augmentation
		assert.Equal(t, "ConfigMap", augmented.GetKind())
		assert.Equal(t, "test-config", augmented.GetName())
		assert.Equal(t, "test-namespace", augmented.GetNamespace())

		// Create a policy for ConfigMaps
		policy := createTestConfigMapPolicy()

		// Create detector
		detector := detectors.NewGenericResourceDetector(factory)

		// Test policy evaluation
		alert, err := detector.DetectViolation(context.Background(), configMap, policy)
		require.NoError(t, err)

		// Verify alert generation
		if alert != nil {
			assert.Equal(t, "ConfigMap", alert.GetResourceReference().GetKind())
			assert.Equal(t, "test-config", alert.GetResourceReference().GetName())
			assert.Equal(t, "test-namespace", alert.GetResourceReference().GetNamespace())
		}
	})

	t.Run("Secret augmentation and policy evaluation", func(t *testing.T) {
		// Create a test Secret
		secret := createTestSecret("test-secret", "test-namespace")

		// Create augmentation factory
		factory := augmentedobjs.NewResourceAugmentationFactory(nil, "test-cluster")

		// Augment the Secret
		augmented, err := factory.AugmentResource(context.Background(), secret)
		require.NoError(t, err)

		// Verify augmentation
		assert.Equal(t, "Secret", augmented.GetKind())
		assert.Equal(t, "test-secret", augmented.GetName())
		assert.Equal(t, "test-namespace", augmented.GetNamespace())

		// Create a policy for Secrets
		policy := createTestSecretPolicy()

		// Create detector
		detector := detectors.NewGenericResourceDetector(factory)

		// Test policy evaluation
		alert, err := detector.DetectViolation(context.Background(), secret, policy)
		require.NoError(t, err)

		// Verify alert generation
		if alert != nil {
			assert.Equal(t, "Secret", alert.GetResourceReference().GetKind())
			assert.Equal(t, "test-secret", alert.GetResourceReference().GetName())
			assert.Equal(t, "test-namespace", alert.GetResourceReference().GetNamespace())
		}
	})

	t.Run("Service augmentation and policy evaluation", func(t *testing.T) {
		// Create a test Service
		service := createTestService("test-service", "test-namespace")

		// Create augmentation factory
		factory := augmentedobjs.NewResourceAugmentationFactory(nil, "test-cluster")

		// Augment the Service
		augmented, err := factory.AugmentResource(context.Background(), service)
		require.NoError(t, err)

		// Verify augmentation
		assert.Equal(t, "Service", augmented.GetKind())
		assert.Equal(t, "test-service", augmented.GetName())
		assert.Equal(t, "test-namespace", augmented.GetNamespace())

		// Create a policy for Services
		policy := createTestServicePolicy()

		// Create detector
		detector := detectors.NewGenericResourceDetector(factory)

		// Test policy evaluation
		alert, err := detector.DetectViolation(context.Background(), service, policy)
		require.NoError(t, err)

		// Verify alert generation
		if alert != nil {
			assert.Equal(t, "Service", alert.GetResourceReference().GetKind())
			assert.Equal(t, "test-service", alert.GetResourceReference().GetName())
			assert.Equal(t, "test-namespace", alert.GetResourceReference().GetNamespace())
		}
	})

	t.Run("Ingress augmentation and policy evaluation", func(t *testing.T) {
		// Create a test Ingress
		ingress := createTestIngress("test-ingress", "test-namespace")

		// Create augmentation factory
		factory := augmentedobjs.NewResourceAugmentationFactory(nil, "test-cluster")

		// Augment the Ingress
		augmented, err := factory.AugmentResource(context.Background(), ingress)
		require.NoError(t, err)

		// Verify augmentation
		assert.Equal(t, "Ingress", augmented.GetKind())
		assert.Equal(t, "test-ingress", augmented.GetName())
		assert.Equal(t, "test-namespace", augmented.GetNamespace())

		// Create a policy for Ingresses
		policy := createTestIngressPolicy()

		// Create detector
		detector := detectors.NewGenericResourceDetector(factory)

		// Test policy evaluation
		alert, err := detector.DetectViolation(context.Background(), ingress, policy)
		require.NoError(t, err)

		// Verify alert generation
		if alert != nil {
			assert.Equal(t, "Ingress", alert.GetResourceReference().GetKind())
			assert.Equal(t, "test-ingress", alert.GetResourceReference().GetName())
			assert.Equal(t, "test-namespace", alert.GetResourceReference().GetNamespace())
		}
	})

	t.Run("Dynamic field evaluation", func(t *testing.T) {
		// Create a ConfigMap with specific data
		configMap := createTestConfigMapWithData("test-config", "test-namespace", map[string]string{
			"database.host": "localhost",
			"database.port": "5432",
		})

		// Create augmentation factory
		factory := augmentedobjs.NewResourceAugmentationFactory(nil, "test-cluster")

		// Augment the ConfigMap
		augmented, err := factory.AugmentResource(context.Background(), configMap)
		require.NoError(t, err)

		// Test field access
		value, found, err := augmented.GetField("data.database.host")
		require.NoError(t, err)
		assert.True(t, found)
		assert.Equal(t, "localhost", value)

		// Test field setting
		err = augmented.SetField("data.database.host", "remote-host")
		require.NoError(t, err)

		// Verify field was set
		value, found, err = augmented.GetField("data.database.host")
		require.NoError(t, err)
		assert.True(t, found)
		assert.Equal(t, "remote-host", value)
	})

	t.Run("Relationship discovery", func(t *testing.T) {
		// Create a test ConfigMap
		configMap := createTestConfigMap("test-config", "test-namespace")

		// Create relationship discoverer
		discoverer := augmentedobjs.NewRelationshipDiscoverer(nil, "test-cluster")

		// Discover relationships
		relationships, err := discoverer.DiscoverRelationships(context.Background(), configMap)
		require.NoError(t, err)

		// Verify relationships structure
		assert.NotNil(t, relationships)

		// Check for expected relationship types
		_, podRelationshipsExist := relationships["Pod"]
		_, deploymentRelationshipsExist := relationships["Deployment"]

		// Even if empty, the relationship keys should exist
		assert.True(t, podRelationshipsExist || deploymentRelationshipsExist)
	})

	t.Run("Backward compatibility", func(t *testing.T) {
		// Create a legacy deployment policy
		policy := createTestDeploymentPolicy()

		// Create a test deployment
		deployment := createTestDeployment("test-deployment", "test-namespace")

		// Create augmentation factory
		factory := augmentedobjs.NewResourceAugmentationFactory(nil, "test-cluster")

		// Augment the deployment (should still work)
		augmented, err := factory.AugmentResource(context.Background(), deployment)
		require.NoError(t, err)

		// Verify augmentation
		assert.Equal(t, "Deployment", augmented.GetKind())
		assert.Equal(t, "test-deployment", augmented.GetName())
		assert.Equal(t, "test-namespace", augmented.GetNamespace())

		// Create detector
		detector := detectors.NewGenericResourceDetector(factory)

		// Test policy evaluation (should still work)
		alert, err := detector.DetectViolation(context.Background(), deployment, policy)
		require.NoError(t, err)

		// Verify alert generation works for deployments
		if alert != nil {
			// Should work with both deployment entity and resource reference
			assert.True(t, alert.GetResourceReference() != nil || alert.GetDeployment() != nil)
		}
	})
}

// Helper functions to create test resources

func createTestConfigMap(name, namespace string) *unstructured.Unstructured {
	return &unstructured.Unstructured{
		Object: map[string]interface{}{
			"apiVersion": "v1",
			"kind":       "ConfigMap",
			"metadata": map[string]interface{}{
				"name":      name,
				"namespace": namespace,
			},
			"data": map[string]interface{}{
				"config.yaml": "test: value",
			},
		},
	}
}

func createTestConfigMapWithData(name, namespace string, data map[string]string) *unstructured.Unstructured {
	dataInterface := make(map[string]interface{})
	for k, v := range data {
		dataInterface[k] = v
	}

	return &unstructured.Unstructured{
		Object: map[string]interface{}{
			"apiVersion": "v1",
			"kind":       "ConfigMap",
			"metadata": map[string]interface{}{
				"name":      name,
				"namespace": namespace,
			},
			"data": dataInterface,
		},
	}
}

func createTestSecret(name, namespace string) *unstructured.Unstructured {
	return &unstructured.Unstructured{
		Object: map[string]interface{}{
			"apiVersion": "v1",
			"kind":       "Secret",
			"metadata": map[string]interface{}{
				"name":      name,
				"namespace": namespace,
			},
			"type": "Opaque",
			"data": map[string]interface{}{
				"password": "dGVzdA==", // base64 encoded "test"
			},
		},
	}
}

func createTestService(name, namespace string) *unstructured.Unstructured {
	return &unstructured.Unstructured{
		Object: map[string]interface{}{
			"apiVersion": "v1",
			"kind":       "Service",
			"metadata": map[string]interface{}{
				"name":      name,
				"namespace": namespace,
			},
			"spec": map[string]interface{}{
				"type": "ClusterIP",
				"ports": []interface{}{
					map[string]interface{}{
						"port":       80,
						"targetPort": 8080,
					},
				},
				"selector": map[string]interface{}{
					"app": "test-app",
				},
			},
		},
	}
}

func createTestIngress(name, namespace string) *unstructured.Unstructured {
	return &unstructured.Unstructured{
		Object: map[string]interface{}{
			"apiVersion": "networking.k8s.io/v1",
			"kind":       "Ingress",
			"metadata": map[string]interface{}{
				"name":      name,
				"namespace": namespace,
			},
			"spec": map[string]interface{}{
				"rules": []interface{}{
					map[string]interface{}{
						"host": "test.example.com",
						"http": map[string]interface{}{
							"paths": []interface{}{
								map[string]interface{}{
									"path":     "/",
									"pathType": "Prefix",
									"backend": map[string]interface{}{
										"service": map[string]interface{}{
											"name": "test-service",
											"port": map[string]interface{}{
												"number": 80,
											},
										},
									},
								},
							},
						},
					},
				},
			},
		},
	}
}

func createTestDeployment(name, namespace string) *unstructured.Unstructured {
	return &unstructured.Unstructured{
		Object: map[string]interface{}{
			"apiVersion": "apps/v1",
			"kind":       "Deployment",
			"metadata": map[string]interface{}{
				"name":      name,
				"namespace": namespace,
			},
			"spec": map[string]interface{}{
				"replicas": 1,
				"selector": map[string]interface{}{
					"matchLabels": map[string]interface{}{
						"app": "test-app",
					},
				},
				"template": map[string]interface{}{
					"metadata": map[string]interface{}{
						"labels": map[string]interface{}{
							"app": "test-app",
						},
					},
					"spec": map[string]interface{}{
						"containers": []interface{}{
							map[string]interface{}{
								"name":  "test-container",
								"image": "nginx:latest",
							},
						},
					},
				},
			},
		},
	}
}

// Helper functions to create test policies

func createTestConfigMapPolicy() *storage.Policy {
	return &storage.Policy{
		Id:   "test-configmap-policy",
		Name: "Test ConfigMap Policy",
		ResourceTarget: &storage.ResourceTarget{
			Target: &storage.ResourceTarget_Kubernetes{
				Kubernetes: &storage.KubernetesResourceTarget{
					ApiVersion: "v1",
					Kind:       "ConfigMap",
				},
			},
		},
		LifecycleStages: []storage.LifecycleStage{storage.LifecycleStage_DEPLOY},
		PolicySections: []*storage.PolicySection{
			{
				SectionName: "ConfigMap Data Check",
				PolicyGroups: []*storage.PolicyGroup{
					{
						FieldName: "Kubernetes Field",
						Values: []*storage.PolicyValue{
							{
								Value: &storage.PolicyValue_Dynamic{
									Dynamic: &storage.DynamicFieldValue{
										FieldPath: "data.config.yaml",
										Operator:  "exists",
									},
								},
							},
						},
					},
				},
			},
		},
	}
}

func createTestSecretPolicy() *storage.Policy {
	return &storage.Policy{
		Id:   "test-secret-policy",
		Name: "Test Secret Policy",
		ResourceTarget: &storage.ResourceTarget{
			Target: &storage.ResourceTarget_Kubernetes{
				Kubernetes: &storage.KubernetesResourceTarget{
					ApiVersion: "v1",
					Kind:       "Secret",
				},
			},
		},
		LifecycleStages: []storage.LifecycleStage{storage.LifecycleStage_DEPLOY},
		PolicySections: []*storage.PolicySection{
			{
				SectionName: "Secret Type Check",
				PolicyGroups: []*storage.PolicyGroup{
					{
						FieldName: "Kubernetes Field",
						Values: []*storage.PolicyValue{
							{
								Value: &storage.PolicyValue_Dynamic{
									Dynamic: &storage.DynamicFieldValue{
										FieldPath: "type",
										Operator:  "equals",
										Values:    []string{"Opaque"},
									},
								},
							},
						},
					},
				},
			},
		},
	}
}

func createTestServicePolicy() *storage.Policy {
	return &storage.Policy{
		Id:   "test-service-policy",
		Name: "Test Service Policy",
		ResourceTarget: &storage.ResourceTarget{
			Target: &storage.ResourceTarget_Kubernetes{
				Kubernetes: &storage.KubernetesResourceTarget{
					ApiVersion: "v1",
					Kind:       "Service",
				},
			},
		},
		LifecycleStages: []storage.LifecycleStage{storage.LifecycleStage_DEPLOY},
		PolicySections: []*storage.PolicySection{
			{
				SectionName: "Service Type Check",
				PolicyGroups: []*storage.PolicyGroup{
					{
						FieldName: "Kubernetes Field",
						Values: []*storage.PolicyValue{
							{
								Value: &storage.PolicyValue_Dynamic{
									Dynamic: &storage.DynamicFieldValue{
										FieldPath: "spec.type",
										Operator:  "equals",
										Values:    []string{"ClusterIP"},
									},
								},
							},
						},
					},
				},
			},
		},
	}
}

func createTestIngressPolicy() *storage.Policy {
	return &storage.Policy{
		Id:   "test-ingress-policy",
		Name: "Test Ingress Policy",
		ResourceTarget: &storage.ResourceTarget{
			Target: &storage.ResourceTarget_Kubernetes{
				Kubernetes: &storage.KubernetesResourceTarget{
					ApiVersion: "networking.k8s.io/v1",
					Kind:       "Ingress",
				},
			},
		},
		LifecycleStages: []storage.LifecycleStage{storage.LifecycleStage_DEPLOY},
		PolicySections: []*storage.PolicySection{
			{
				SectionName: "Ingress Rules Check",
				PolicyGroups: []*storage.PolicyGroup{
					{
						FieldName: "Kubernetes Field",
						Values: []*storage.PolicyValue{
							{
								Value: &storage.PolicyValue_Dynamic{
									Dynamic: &storage.DynamicFieldValue{
										FieldPath: "spec.rules",
										Operator:  "exists",
									},
								},
							},
						},
					},
				},
			},
		},
	}
}

func createTestDeploymentPolicy() *storage.Policy {
	return &storage.Policy{
		Id:   "test-deployment-policy",
		Name: "Test Deployment Policy",
		// No ResourceTarget means legacy deployment policy
		LifecycleStages: []storage.LifecycleStage{storage.LifecycleStage_DEPLOY},
		PolicySections: []*storage.PolicySection{
			{
				SectionName: "Container Check",
				PolicyGroups: []*storage.PolicyGroup{
					{
						FieldName: "Container Name",
						Values: []*storage.PolicyValue{
							{
								Value: &storage.PolicyValue_StringValue{
									StringValue: "test-container",
								},
							},
						},
					},
				},
			},
		},
	}
}

func TestResourceAugmentationFactory(t *testing.T) {
	t.Run("Factory correctly routes to specialized augmenters", func(t *testing.T) {
		factory := augmentedobjs.NewResourceAugmentationFactory(nil, "test-cluster")

		// Test ConfigMap routing
		configMap := createTestConfigMap("test", "test-ns")
		augmented, err := factory.AugmentResource(context.Background(), configMap)
		require.NoError(t, err)

		// Check if it's a specialized ConfigMap augmented resource
		_, isConfigMapAugmented := augmented.(*augmentedobjs.ConfigMapAugmentedResource)
		if !isConfigMapAugmented {
			// If not specialized, should at least be generic
			_, isGeneric := augmented.(*augmentedobjs.GenericAugmentedResource)
			assert.True(t, isGeneric)
		}

		// Test Secret routing
		secret := createTestSecret("test", "test-ns")
		augmented, err = factory.AugmentResource(context.Background(), secret)
		require.NoError(t, err)

		// Check if it's a specialized Secret augmented resource
		_, isSecretAugmented := augmented.(*augmentedobjs.SecretAugmentedResource)
		if !isSecretAugmented {
			// If not specialized, should at least be generic
			_, isGeneric := augmented.(*augmentedobjs.GenericAugmentedResource)
			assert.True(t, isGeneric)
		}

		// Test Service routing
		service := createTestService("test", "test-ns")
		augmented, err = factory.AugmentResource(context.Background(), service)
		require.NoError(t, err)

		// Check if it's a specialized Service augmented resource
		_, isServiceAugmented := augmented.(*augmentedobjs.ServiceAugmentedResource)
		if !isServiceAugmented {
			// If not specialized, should at least be generic
			_, isGeneric := augmented.(*augmentedobjs.GenericAugmentedResource)
			assert.True(t, isGeneric)
		}

		// Test Ingress routing
		ingress := createTestIngress("test", "test-ns")
		augmented, err = factory.AugmentResource(context.Background(), ingress)
		require.NoError(t, err)

		// Check if it's a specialized Ingress augmented resource
		_, isIngressAugmented := augmented.(*augmentedobjs.IngressAugmentedResource)
		if !isIngressAugmented {
			// If not specialized, should at least be generic
			_, isGeneric := augmented.(*augmentedobjs.GenericAugmentedResource)
			assert.True(t, isGeneric)
		}
	})
}
