package detectors

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/pkg/errors"
	"github.com/stackrox/rox/generated/storage"
	"github.com/stackrox/rox/pkg/booleanpolicy/augmentedobjs"
	"github.com/stackrox/rox/pkg/booleanpolicy/evaluator"
	"github.com/stackrox/rox/pkg/protocompat"
	"github.com/stackrox/rox/pkg/uuid"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

// GenericResourceDetector handles policy detection for any Kubernetes resource
type GenericResourceDetector struct {
	augmentFactory *augmentedobjs.ResourceAugmentationFactory
}

// NewGenericResourceDetector creates a new generic resource detector
func NewGenericResourceDetector(augmentFactory *augmentedobjs.ResourceAugmentationFactory) *GenericResourceDetector {
	return &GenericResourceDetector{
		augmentFactory: augmentFactory,
	}
}

// DetectViolation evaluates a policy against a Kubernetes resource
func (grd *GenericResourceDetector) DetectViolation(ctx context.Context,
	resource *unstructured.Unstructured,
	policy *storage.Policy) (*storage.Alert, error) {

	// Check if policy applies to this resource type
	if !grd.policyAppliesToResource(policy, resource) {
		return nil, nil
	}

	// Augment resource with evaluation context
	augmented, err := grd.augmentFactory.AugmentResource(ctx, resource)
	if err != nil {
		return nil, errors.Wrapf(err, "augmenting resource %s/%s",
			resource.GetKind(), resource.GetName())
	}

	// Evaluate policy against augmented resource
	violations, matched := grd.evaluatePolicy(augmented, policy)
	if !matched {
		return nil, nil
	}

	// Create alert
	alert := &storage.Alert{
		Id:       uuid.NewV4().String(),
		Policy:   policy,
		ResourceReference: &storage.ResourceReference{
			ApiVersion: resource.GetAPIVersion(),
			Kind:       resource.GetKind(),
			Namespace:  resource.GetNamespace(),
			Name:       resource.GetName(),
			Uid:        string(resource.GetUID()),
		},
		Time:         protocompat.TimestampNow(),
		FirstOccurred: protocompat.TimestampNow(),
		State:        storage.ViolationState_ACTIVE,
		EntityType:   storage.Alert_RESOURCE, // Use generic resource type
		ClusterId:    augmented.GetClusterID(),
		ClusterName:  grd.getClusterName(augmented.GetClusterID()),
		Namespace:    resource.GetNamespace(),
		NamespaceId:  grd.getNamespaceId(resource.GetNamespace()),
	}

	// Set lifecycle stage
	if len(policy.GetLifecycleStages()) > 0 {
		alert.LifecycleStage = policy.GetLifecycleStages()[0]
	} else {
		alert.LifecycleStage = storage.LifecycleStage_DEPLOY
	}

	// Build violation message from policy sections
	alert.ViolationMessage = grd.buildViolationMessage(violations, policy, resource)

	return alert, nil
}

// evaluatePolicy evaluates a policy against an augmented resource
func (grd *GenericResourceDetector) evaluatePolicy(augmented augmentedobjs.AugmentedResource,
	policy *storage.Policy) ([]*PolicyViolation, bool) {

	var violations []*PolicyViolation

	// Evaluate each policy section
	for _, section := range policy.GetPolicySections() {
		sectionViolated, sectionViolations := grd.evaluatePolicySection(augmented, section)
		if sectionViolated {
			violations = append(violations, sectionViolations...)
		} else {
			// All sections must pass for policy to pass (AND logic)
			return nil, false
		}
	}

	return violations, len(violations) > 0
}

// evaluatePolicySection evaluates a single policy section
func (grd *GenericResourceDetector) evaluatePolicySection(augmented augmentedobjs.AugmentedResource,
	section *storage.PolicySection) (bool, []*PolicyViolation) {

	var violations []*PolicyViolation

	// Evaluate each policy group in the section
	for _, group := range section.GetPolicyGroups() {
		groupViolated, groupViolations := grd.evaluatePolicyGroup(augmented, group)
		if groupViolated {
			violations = append(violations, groupViolations...)
		} else {
			// All groups in a section must pass (AND logic)
			return false, nil
		}
	}

	return len(violations) > 0, violations
}

// evaluatePolicyGroup evaluates a single policy group
func (grd *GenericResourceDetector) evaluatePolicyGroup(augmented augmentedobjs.AugmentedResource,
	group *storage.PolicyGroup) (bool, []*PolicyViolation) {

	fieldName := group.GetFieldName()

	// Handle dynamic Kubernetes Field criteria
	if fieldName == "Kubernetes Field" {
		return grd.evaluateDynamicField(augmented, group)
	}

	// For other field types, use existing evaluation logic
	// This maintains backward compatibility with deployment-focused policies
	return grd.evaluateStaticField(augmented, group)
}

// evaluateDynamicField evaluates dynamic Kubernetes field criteria
func (grd *GenericResourceDetector) evaluateDynamicField(augmented augmentedobjs.AugmentedResource,
	group *storage.PolicyGroup) (bool, []*PolicyViolation) {

	var violations []*PolicyViolation

	for _, value := range group.GetValues() {
		var violated bool
		var violation *PolicyViolation

		if dynamicValue := value.GetDynamic(); dynamicValue != nil {
			violated, violation = grd.evaluateDynamicValue(augmented, dynamicValue, group)
		} else if value.GetValue() != "" {
			violated, violation = grd.evaluateLegacyDynamicValue(augmented, value.GetValue(), group)
		}

		if violated {
			violations = append(violations, violation)
			// For OR operator, any match is sufficient
			if group.GetBooleanOperator() == storage.BooleanOperator_OR {
				return true, violations
			}
		} else if group.GetBooleanOperator() == storage.BooleanOperator_AND {
			// For AND operator, all values must match
			return false, nil
		}
	}

	// If we get here with OR operator, no values matched
	// If we get here with AND operator, all values matched
	return group.GetBooleanOperator() == storage.BooleanOperator_AND && len(violations) > 0, violations
}

// evaluateDynamicValue evaluates a DynamicFieldValue against the resource
func (grd *GenericResourceDetector) evaluateDynamicValue(augmented augmentedobjs.AugmentedResource,
	dynamicValue *storage.DynamicFieldValue, group *storage.PolicyGroup) (bool, *PolicyViolation) {

	evaluator := evaluator.NewDynamicFieldEvaluator(
		dynamicValue.GetFieldPath(),
		dynamicValue.GetOperator(),
		dynamicValue.GetValues(),
		group.GetNegate(),
	)

	result, matched := evaluator.Evaluate(augmented)
	if matched {
		return true, &PolicyViolation{
			FieldName:   "Kubernetes Field",
			FieldPath:   dynamicValue.GetFieldPath(),
			Operator:    dynamicValue.GetOperator(),
			ExpectedValues: dynamicValue.GetValues(),
			ActualValue: grd.getActualValue(augmented, dynamicValue.GetFieldPath()),
			Message:     grd.buildDynamicViolationMessage(dynamicValue, augmented),
		}
	}

	return false, nil
}

// evaluateLegacyDynamicValue evaluates legacy string-encoded dynamic values
func (grd *GenericResourceDetector) evaluateLegacyDynamicValue(augmented augmentedobjs.AugmentedResource,
	value string, group *storage.PolicyGroup) (bool, *PolicyViolation) {

	// Parse: "field=spec.type,operator=equals,value=LoadBalancer"
	params := grd.parseKeyValuePairs(value)

	fieldPath, hasField := params["field"]
	operator, hasOperator := params["operator"]
	fieldValue, hasValue := params["value"]

	if !hasField || !hasOperator {
		return false, nil
	}

	values := []string{}
	if hasValue {
		values = append(values, fieldValue)
	}

	evaluator := evaluator.NewDynamicFieldEvaluator(fieldPath, operator, values, group.GetNegate())
	result, matched := evaluator.Evaluate(augmented)

	if matched {
		return true, &PolicyViolation{
			FieldName:   "Kubernetes Field",
			FieldPath:   fieldPath,
			Operator:    operator,
			ExpectedValues: values,
			ActualValue: grd.getActualValue(augmented, fieldPath),
			Message:     fmt.Sprintf("Field %s %s %v", fieldPath, operator, values),
		}
	}

	return false, nil
}

// evaluateStaticField evaluates non-dynamic fields (for backward compatibility)
func (grd *GenericResourceDetector) evaluateStaticField(augmented augmentedobjs.AugmentedResource,
	group *storage.PolicyGroup) (bool, []*PolicyViolation) {

	// For Phase 1, we'll focus on dynamic fields
	// Static field evaluation can be added in future phases
	return false, nil
}

// policyAppliesToResource checks if a policy targets the given resource
func (grd *GenericResourceDetector) policyAppliesToResource(policy *storage.Policy,
	resource *unstructured.Unstructured) bool {

	target := policy.GetResourceTarget()
	if target == nil {
		// Legacy policy without target - only applies to deployment-like resources
		return augmentedobjs.IsDeploymentLikeResource(resource)
	}

	switch t := target.GetTarget().(type) {
	case *storage.ResourceTarget_Deployment:
		return augmentedobjs.IsDeploymentLikeResource(resource)
	case *storage.ResourceTarget_Kubernetes:
		return grd.kubernetesTargetMatches(t.Kubernetes, resource)
	default:
		return false
	}
}

// kubernetesTargetMatches checks if a KubernetesResourceTarget matches the resource
func (grd *GenericResourceDetector) kubernetesTargetMatches(target *storage.KubernetesResourceTarget,
	resource *unstructured.Unstructured) bool {

	// Check kind
	if target.GetKind() != resource.GetKind() {
		return false
	}

	// Check API version (if specified)
	if target.GetApiVersion() != "" && target.GetApiVersion() != resource.GetAPIVersion() {
		return false
	}

	// Check namespace filter (if specified)
	namespaces := target.GetNamespaces()
	if len(namespaces) > 0 {
		resourceNamespace := resource.GetNamespace()
		for _, ns := range namespaces {
			if ns == resourceNamespace {
				return true
			}
		}
		return false
	}

	return true
}

// Helper methods

func (grd *GenericResourceDetector) getActualValue(augmented augmentedobjs.AugmentedResource, fieldPath string) string {
	value, found, err := augmented.GetField(fieldPath)
	if err != nil || !found {
		return "<not set>"
	}
	return fmt.Sprintf("%v", value)
}

func (grd *GenericResourceDetector) parseKeyValuePairs(input string) map[string]string {
	result := make(map[string]string)
	pairs := strings.Split(input, ",")
	for _, pair := range pairs {
		kv := strings.SplitN(pair, "=", 2)
		if len(kv) == 2 {
			result[kv[0]] = kv[1]
		}
	}
	return result
}

func (grd *GenericResourceDetector) getClusterName(clusterID string) string {
	// TODO: Implement cluster name lookup
	return "unknown"
}

func (grd *GenericResourceDetector) getNamespaceId(namespace string) string {
	// TODO: Implement namespace ID lookup
	return ""
}

func (grd *GenericResourceDetector) buildViolationMessage(violations []*PolicyViolation,
	policy *storage.Policy, resource *unstructured.Unstructured) string {

	if len(violations) == 0 {
		return fmt.Sprintf("Policy '%s' violated", policy.GetName())
	}

	var messages []string
	for _, violation := range violations {
		messages = append(messages, violation.Message)
	}

	return fmt.Sprintf("Resource %s/%s violates policy '%s': %s",
		resource.GetKind(), resource.GetName(), policy.GetName(),
		strings.Join(messages, "; "))
}

func (grd *GenericResourceDetector) buildDynamicViolationMessage(dynamicValue *storage.DynamicFieldValue,
	augmented augmentedobjs.AugmentedResource) string {

	actualValue := grd.getActualValue(augmented, dynamicValue.GetFieldPath())
	
	switch dynamicValue.GetOperator() {
	case "exists":
		return fmt.Sprintf("Field %s does not exist", dynamicValue.GetFieldPath())
	case "equals":
		return fmt.Sprintf("Field %s has value '%s', expected one of %v",
			dynamicValue.GetFieldPath(), actualValue, dynamicValue.GetValues())
	case "contains":
		return fmt.Sprintf("Field %s value '%s' does not contain any of %v",
			dynamicValue.GetFieldPath(), actualValue, dynamicValue.GetValues())
	default:
		return fmt.Sprintf("Field %s failed %s check against %v",
			dynamicValue.GetFieldPath(), dynamicValue.GetOperator(), dynamicValue.GetValues())
	}
}

// PolicyViolation represents a single policy violation
type PolicyViolation struct {
	FieldName      string
	FieldPath      string
	Operator       string
	ExpectedValues []string
	ActualValue    string
	Message        string
}