package detection

import (
	"context"

	"github.com/pkg/errors"
	"github.com/stackrox/rox/generated/storage"
	"github.com/stackrox/rox/pkg/booleanpolicy"
	"github.com/stackrox/rox/pkg/booleanpolicy/augmentedobjs"
	"github.com/stackrox/rox/pkg/detection/detectors"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

// UniversalPolicyCompiler compiles policies for any resource type
type UniversalPolicyCompiler struct {
	fieldMetadata   *booleanpolicy.FieldMetadata
	augmentFactory  *augmentedobjs.ResourceAugmentationFactory
}

// NewUniversalPolicyCompiler creates a new universal policy compiler
func NewUniversalPolicyCompiler(fieldMetadata *booleanpolicy.FieldMetadata,
	augmentFactory *augmentedobjs.ResourceAugmentationFactory) *UniversalPolicyCompiler {
	return &UniversalPolicyCompiler{
		fieldMetadata:  fieldMetadata,
		augmentFactory: augmentFactory,
	}
}

// CompilePolicy compiles a policy into the appropriate detector
func (upc *UniversalPolicyCompiler) CompilePolicy(policy *storage.Policy) (ResourceDetector, error) {
	// Determine target resource type
	target := policy.GetResourceTarget()
	if target == nil {
		// Backward compatibility: default to deployment
		target = &storage.ResourceTarget{
			Target: &storage.ResourceTarget_Deployment{
				Deployment: &storage.DeploymentTarget{},
			},
		}
	}

	switch t := target.GetTarget().(type) {
	case *storage.ResourceTarget_Deployment:
		return upc.compileDeploymentPolicy(policy)
	case *storage.ResourceTarget_Kubernetes:
		return upc.compileKubernetesResourcePolicy(policy, t.Kubernetes)
	default:
		return nil, errors.Errorf("unknown resource target type: %T", t)
	}
}

// compileDeploymentPolicy compiles a traditional deployment-focused policy
func (upc *UniversalPolicyCompiler) compileDeploymentPolicy(policy *storage.Policy) (ResourceDetector, error) {
	// For Phase 1, we use the generic detector even for deployment policies
	// This provides a unified path and testing ground
	// In future phases, we can optimize with specialized deployment detectors
	return detectors.NewGenericResourceDetector(upc.augmentFactory), nil
}

// compileKubernetesResourcePolicy compiles a universal Kubernetes resource policy
func (upc *UniversalPolicyCompiler) compileKubernetesResourcePolicy(policy *storage.Policy,
	target *storage.KubernetesResourceTarget) (ResourceDetector, error) {

	// Validate policy sections contain supported criteria
	for _, section := range policy.GetPolicySections() {
		for _, group := range section.GetPolicyGroups() {
			if err := upc.validatePolicyGroup(group); err != nil {
				return nil, errors.Wrapf(err, "invalid policy group for field %s", group.GetFieldName())
			}
		}
	}

	return detectors.NewGenericResourceDetector(upc.augmentFactory), nil
}

// validatePolicyGroup validates that a policy group is supported
func (upc *UniversalPolicyCompiler) validatePolicyGroup(group *storage.PolicyGroup) error {
	fieldName := group.GetFieldName()

	// Check if field is known
	if _, err := upc.fieldMetadata.FindField(fieldName); err != nil {
		return errors.Errorf("unknown field: %s", fieldName)
	}

	// For Kubernetes Field, validate dynamic values
	if fieldName == "Kubernetes Field" {
		return upc.validateDynamicFieldGroup(group)
	}

	return nil
}

// validateDynamicFieldGroup validates dynamic field policy groups
func (upc *UniversalPolicyCompiler) validateDynamicFieldGroup(group *storage.PolicyGroup) error {
	if len(group.GetValues()) == 0 {
		return errors.New("no values specified")
	}

	for _, value := range group.GetValues() {
		if dynamicValue := value.GetDynamic(); dynamicValue != nil {
			if err := upc.validateDynamicValue(dynamicValue); err != nil {
				return err
			}
		} else if value.GetValue() == "" {
			return errors.New("empty value specified")
		}
		// Legacy string values are validated at runtime
	}

	return nil
}

// validateDynamicValue validates a DynamicFieldValue
func (upc *UniversalPolicyCompiler) validateDynamicValue(dynamicValue *storage.DynamicFieldValue) error {
	if dynamicValue.GetFieldPath() == "" {
		return errors.New("field_path is required")
	}

	if dynamicValue.GetOperator() == "" {
		return errors.New("operator is required")
	}

	// Validate operator
	supportedOperators := []string{"equals", "contains", "exists", "regex_match", ">", "<", ">=", "<="}
	operatorValid := false
	for _, op := range supportedOperators {
		if dynamicValue.GetOperator() == op {
			operatorValid = true
			break
		}
	}
	if !operatorValid {
		return errors.Errorf("unsupported operator: %s", dynamicValue.GetOperator())
	}

	// Validate that values are provided for operators that need them
	needsValues := dynamicValue.GetOperator() != "exists"
	if needsValues && len(dynamicValue.GetValues()) == 0 {
		return errors.Errorf("operator %s requires values", dynamicValue.GetOperator())
	}

	return nil
}

// ResourceDetector interface for universal resource detection
type ResourceDetector interface {
	DetectViolation(ctx context.Context, resource *unstructured.Unstructured, policy *storage.Policy) (*storage.Alert, error)
}