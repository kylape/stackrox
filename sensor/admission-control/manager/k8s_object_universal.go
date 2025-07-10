package manager

import (
	openshiftAppsV1 "github.com/openshift/api/apps/v1"
	"github.com/pkg/errors"
	"github.com/stackrox/rox/pkg/k8sutil"
	"github.com/stackrox/rox/pkg/kubernetes"
	apps "k8s.io/api/apps/v1"
	batchV1 "k8s.io/api/batch/v1"
	batchV1beta1 "k8s.io/api/batch/v1beta1"
	core "k8s.io/api/core/v1"
	networkingV1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/serializer"
)

var (
	universalDeserializerUniversal = serializer.NewCodecFactory(runtime.NewScheme()).UniversalDeserializer()
)

// unmarshalK8sObjectUniversal handles any Kubernetes resource type
// This replaces the original unmarshalK8sObject for universal resource support
func unmarshalK8sObjectUniversal(gvk metav1.GroupVersionKind, raw []byte) (k8sutil.Object, error) {
	// First try to unmarshal as specific typed objects for deployment-like resources
	// This maintains compatibility with existing deployment-focused code
	if typedObj, err := unmarshalAsTypedObject(gvk, raw); err == nil {
		return typedObj, nil
	}

	// For all other resources, use unstructured.Unstructured
	var obj unstructured.Unstructured
	if _, _, err := universalDeserializerUniversal.Decode(raw, nil, &obj); err != nil {
		return nil, errors.Wrapf(err, "decoding %s object as unstructured", gvk.Kind)
	}

	return &obj, nil
}

// unmarshalAsTypedObject attempts to unmarshal known workload types as typed objects
func unmarshalAsTypedObject(gvk metav1.GroupVersionKind, raw []byte) (k8sutil.Object, error) {
	var obj k8sutil.Object
	
	switch gvk.Kind {
	case kubernetes.Pod:
		obj = &core.Pod{}
	case kubernetes.Deployment:
		obj = &apps.Deployment{}
	case kubernetes.StatefulSet:
		obj = &apps.StatefulSet{}
	case kubernetes.DaemonSet:
		obj = &apps.DaemonSet{}
	case kubernetes.ReplicationController:
		obj = &core.ReplicationController{}
	case kubernetes.ReplicaSet:
		obj = &apps.ReplicaSet{}
	case kubernetes.CronJob:
		if gvk.Version == "v1beta1" {
			obj = &batchV1beta1.CronJob{}
		} else {
			obj = &batchV1.CronJob{}
		}
	case kubernetes.Job:
		obj = &batchV1.Job{}
	case kubernetes.DeploymentConfig:
		obj = &openshiftAppsV1.DeploymentConfig{}
	// Add some common resource types that might benefit from typed access
	case "Service":
		obj = &core.Service{}
	case "ConfigMap":
		obj = &core.ConfigMap{}
	case "Secret":
		obj = &core.Secret{}
	case "NetworkPolicy":
		obj = &networkingV1.NetworkPolicy{}
	case "Ingress":
		obj = &networkingV1.Ingress{}
	default:
		// Not a known typed resource, caller should use unstructured
		return nil, errors.Errorf("unknown kind for typed unmarshaling: %q", gvk.Kind)
	}

	if _, _, err := universalDeserializerUniversal.Decode(raw, nil, obj); err != nil {
		return nil, errors.Wrapf(err, "decoding %s object", gvk.Kind)
	}

	return obj, nil
}

// IsDeploymentLikeKind checks if a resource kind is deployment-like
func IsDeploymentLikeKind(kind string) bool {
	switch kind {
	case kubernetes.Pod,
		kubernetes.Deployment,
		kubernetes.StatefulSet,
		kubernetes.DaemonSet,
		kubernetes.ReplicationController,
		kubernetes.ReplicaSet,
		kubernetes.CronJob,
		kubernetes.Job,
		kubernetes.DeploymentConfig:
		return true
	default:
		return false
	}
}

// ConvertToUnstructured converts any k8sutil.Object to unstructured.Unstructured
func ConvertToUnstructured(obj k8sutil.Object) (*unstructured.Unstructured, error) {
	// If already unstructured, return as-is
	if u, ok := obj.(*unstructured.Unstructured); ok {
		return u, nil
	}

	// Convert typed object to unstructured
	unstructuredObj, err := runtime.DefaultUnstructuredConverter.ToUnstructured(obj)
	if err != nil {
		return nil, errors.Wrap(err, "converting object to unstructured")
	}

	return &unstructured.Unstructured{Object: unstructuredObj}, nil
}