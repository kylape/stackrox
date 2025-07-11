package manager

import (
	"context"

	"github.com/pkg/errors"
	"github.com/stackrox/rox/generated/storage"
	"github.com/stackrox/rox/pkg/booleanpolicy"
	"github.com/stackrox/rox/pkg/booleanpolicy/augmentedobjs"
	"github.com/stackrox/rox/pkg/detection"
	"github.com/stackrox/rox/pkg/logging"
	"k8s.io/client-go/kubernetes"
	admission "k8s.io/api/admission/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"fmt"
)

var (
	universalLog = logging.LoggerForModule()
)

// UniversalResourceHandler extends the admission controller to handle any Kubernetes resource
type UniversalResourceHandler struct {
	augmentFactory  *augmentedobjs.ResourceAugmentationFactory
	policyCompiler  *detection.UniversalPolicyCompiler
	policySet       PolicySet // Interface to get policies for specific resource types
}

// NewUniversalResourceHandler creates a new universal resource handler
func NewUniversalResourceHandler(k8sClient kubernetes.Interface, clusterID string) *UniversalResourceHandler {
	augmentFactory := augmentedobjs.NewResourceAugmentationFactory(k8sClient, clusterID)
	fieldMetadata := booleanpolicy.FieldMetadataSingleton()
	policyCompiler := detection.NewUniversalPolicyCompiler(fieldMetadata, augmentFactory)

	return &UniversalResourceHandler{
		augmentFactory: augmentFactory,
		policyCompiler: policyCompiler,
		// policySet will be injected by the manager
	}
}

// HandleValidateUniversal processes admission requests for any Kubernetes resource
func (urh *UniversalResourceHandler) HandleValidateUniversal(ctx context.Context, 
	request *admission.AdmissionRequest) (*admission.AdmissionResponse, error) {

	// Parse the Kubernetes object
	resource, err := urh.parseAdmissionObject(request)
	if err != nil {
		universalLog.Warnf("Failed to parse admission object: %v", err)
		return &admission.AdmissionResponse{
			UID:     request.UID,
			Allowed: true, // Allow by default on parse errors to avoid blocking
			Result:  &metav1.Status{Message: "Failed to parse object"},
		}, nil
	}

	// Get policies that target this resource type
	policies := urh.getPoliciesForResource(resource.GetKind(), resource.GetAPIVersion())
	if len(policies) == 0 {
		universalLog.Debugf("No policies target %s/%s, allowing", resource.GetKind(), resource.GetName())
		return &admission.AdmissionResponse{
			UID:     request.UID,
			Allowed: true,
		}, nil
	}

	universalLog.Infof("Evaluating %d policies for %s/%s", len(policies), resource.GetKind(), resource.GetName())

	// Evaluate policies using the generic detector
	var violations []*storage.Alert
	for _, policy := range policies {
		detector, err := urh.policyCompiler.CompilePolicy(policy)
		if err != nil {
			universalLog.Errorf("Error compiling policy %s: %v", policy.GetName(), err)
			continue
		}

		if alert, err := detector.DetectViolation(ctx, resource, policy); err != nil {
			universalLog.Errorf("Error detecting policy %s: %v", policy.GetName(), err)
		} else if alert != nil {
			violations = append(violations, alert)
		}
	}

	return urh.buildAdmissionResponse(violations, request)
}

// parseAdmissionObject parses the admission request object as unstructured
func (urh *UniversalResourceHandler) parseAdmissionObject(request *admission.AdmissionRequest) (*unstructured.Unstructured, error) {
	if request.Object.Raw == nil {
		return nil, errors.New("admission request object is nil")
	}

	// Try to unmarshal using the universal handler
	obj, err := unmarshalK8sObjectUniversal(request.Kind, request.Object.Raw)
	if err != nil {
		return nil, errors.Wrapf(err, "unmarshaling %s object", request.Kind.Kind)
	}

	// Convert to unstructured if needed
	return ConvertToUnstructured(obj)
}

// getPoliciesForResource gets policies that apply to the specified resource type
func (urh *UniversalResourceHandler) getPoliciesForResource(kind, apiVersion string) []*storage.Policy {
	if urh.policySet == nil {
		return nil
	}
	return urh.policySet.GetPoliciesForResource(kind, apiVersion)
}

// buildAdmissionResponse creates an admission response based on policy violations
func (urh *UniversalResourceHandler) buildAdmissionResponse(violations []*storage.Alert,
	request *admission.AdmissionRequest) (*admission.AdmissionResponse, error) {

	response := &admission.AdmissionResponse{
		UID: request.UID,
	}

	if len(violations) == 0 {
		response.Allowed = true
		return response, nil
	}

	// Check if any violations have enforcement actions
	var enforcementActions []storage.EnforcementAction
	var messages []string

	for _, alert := range violations {
		policy := alert.GetPolicy()
		if policy != nil {
			enforcementActions = append(enforcementActions, policy.GetEnforcementActions()...)
			// Get message from violations
			for _, violation := range alert.GetViolations() {
				if violation.GetMessage() != "" {
					messages = append(messages, violation.GetMessage())
				}
			}
		}
	}

	// Determine if request should be denied
	shouldDeny := urh.shouldDenyRequest(enforcementActions, request.Operation)

	if shouldDeny {
		response.Allowed = false
		response.Result = &metav1.Status{
			Code:    403,
			Message: urh.buildDenialMessage(messages),
		}
	} else {
		response.Allowed = true
		// Add warnings for violations without enforcement
		for _, message := range messages {
			response.Warnings = append(response.Warnings, message)
		}
	}

	return response, nil
}

// shouldDenyRequest determines if the request should be denied based on enforcement actions
func (urh *UniversalResourceHandler) shouldDenyRequest(enforcementActions []storage.EnforcementAction,
	operation admission.Operation) bool {

	for _, action := range enforcementActions {
		switch action {
		case storage.EnforcementAction_FAIL_DEPLOYMENT_CREATE_ENFORCEMENT:
			if operation == admission.Create {
				return true
			}
		case storage.EnforcementAction_FAIL_DEPLOYMENT_UPDATE_ENFORCEMENT:
			if operation == admission.Update {
				return true
			}
		case storage.EnforcementAction_FAIL_KUBE_REQUEST_ENFORCEMENT:
			// This applies to any operation
			return true
		}
	}

	return false
}

// buildDenialMessage creates a user-friendly denial message
func (urh *UniversalResourceHandler) buildDenialMessage(messages []string) string {
	if len(messages) == 0 {
		return "Resource violates security policies"
	}

	if len(messages) == 1 {
		return messages[0]
	}

	result := "Resource violates multiple security policies:"
	for i, message := range messages {
		result += fmt.Sprintf("\n%d. %s", i+1, message)
	}

	return result
}

// PolicySet interface for getting policies by resource type
type PolicySet interface {
	GetPoliciesForResource(kind, apiVersion string) []*storage.Policy
	GetPoliciesForResourceInNamespace(kind, apiVersion, namespace string) []*storage.Policy
}

// SetPolicySet injects the policy set (called by the manager)
func (urh *UniversalResourceHandler) SetPolicySet(policySet PolicySet) {
	urh.policySet = policySet
}