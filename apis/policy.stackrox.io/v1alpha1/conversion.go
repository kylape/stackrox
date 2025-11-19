/*
Copyright 2024.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package v1alpha1

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"

	commonv1 "github.com/stackrox/rox/pkg/apis/common/v1"
	"github.com/stackrox/rox/generated/storage"
	"google.golang.org/protobuf/types/known/timestamppb"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// ToStoragePolicy converts a StackroxPolicySpec to a storage.Policy protobuf message
// This is used by the local policy controller to convert CRD specs to the format
// expected by sensor for policy evaluation.
//
// Key differences from Central's SecurityPolicy conversion:
// - Source is always PolicySource_LOCAL
// - No cluster ID resolution (policies are implicitly local)
// - No notifier ID resolution (notifier names are preserved as-is)
// - Policy ID is generated locally based on namespace/name hash
func ToStoragePolicy(spec *StackroxPolicySpec, namespace, name string, isClusterScoped bool) (*storage.Policy, error) {
	policy := &storage.Policy{
		// Generate a deterministic local policy ID
		Id: generateLocalPolicyID(namespace, name, isClusterScoped),

		// Basic policy metadata
		Name:        spec.PolicyName,
		Description: spec.Description,
		Rationale:   spec.Rationale,
		Remediation: spec.Remediation,
		Disabled:    spec.Disabled,
		Categories:  spec.Categories,

		// Policy source and timing
		Source:      storage.PolicySource_LOCAL,
		LastUpdated: timestamppb.Now(),

		// Severity
		Severity: parseSeverity(spec.Severity),

		// Lifecycle stages
		LifecycleStages: convertLifecycleStages(spec.LifecycleStages),

		// Event source
		EventSource: convertEventSource(spec.EventSource),

		// Enforcement actions
		EnforcementActions: convertEnforcementActions(spec.EnforcementActions),

		// Notifiers (kept as names, will be resolved by sensor when sending alerts)
		Notifiers: spec.Notifiers,

		// Policy criteria
		PolicySections: convertPolicySections(spec.PolicySections),

		// MITRE ATT&CK
		MitreAttackVectors: convertMitreVectors(spec.MitreAttackVectors),

		// Scope and exclusions
		Scope:      convertScopes(spec.Scope, namespace, isClusterScoped),
		Exclusions: convertExclusions(spec.Exclusions),

		// Policy version (must be 1.1 for runtime policies)
		PolicyVersion: "1.1",

		// Local policies are always considered "custom" (not default)
		IsDefault: false,

		// Local policies criteria are not locked
		CriteriaLocked:     false,
		MitreVectorsLocked: false,
	}

	return policy, nil
}

// generateLocalPolicyID creates a deterministic ID for local policies
// Format: local-<sha256-hash-prefix>
// The hash is based on namespace/name to ensure uniqueness and stability
func generateLocalPolicyID(namespace, name string, isClusterScoped bool) string {
	var identifier string
	if isClusterScoped {
		identifier = fmt.Sprintf("cluster/%s", name)
	} else {
		identifier = fmt.Sprintf("namespace/%s/%s", namespace, name)
	}

	hash := sha256.Sum256([]byte(identifier))
	hashHex := hex.EncodeToString(hash[:])

	// Use first 16 characters of hash for a reasonably short but unique ID
	return fmt.Sprintf("local-%s", hashHex[:16])
}

func parseSeverity(severity string) storage.Severity {
	switch strings.ToUpper(severity) {
	case "LOW_SEVERITY":
		return storage.Severity_LOW_SEVERITY
	case "MEDIUM_SEVERITY":
		return storage.Severity_MEDIUM_SEVERITY
	case "HIGH_SEVERITY":
		return storage.Severity_HIGH_SEVERITY
	case "CRITICAL_SEVERITY":
		return storage.Severity_CRITICAL_SEVERITY
	default:
		return storage.Severity_UNSET_SEVERITY
	}
}

func convertLifecycleStages(stages []commonv1.LifecycleStage) []storage.LifecycleStage {
	result := make([]storage.LifecycleStage, 0, len(stages))
	for _, stage := range stages {
		switch stage {
		case commonv1.LifecycleStageDeploy:
			result = append(result, storage.LifecycleStage_DEPLOY)
		case commonv1.LifecycleStageRuntime:
			result = append(result, storage.LifecycleStage_RUNTIME)
			// Note: BUILD is not supported for local policies
		}
	}
	return result
}

func convertEventSource(source commonv1.EventSource) storage.EventSource {
	switch source {
	case commonv1.EventSourceDeploymentEvent:
		return storage.EventSource_DEPLOYMENT_EVENT
	case commonv1.EventSourceAuditLogEvent:
		return storage.EventSource_AUDIT_LOG_EVENT
	case commonv1.EventSourceNodeEvent:
		return storage.EventSource_NODE_EVENT
	default:
		return storage.EventSource_NOT_APPLICABLE
	}
}

func convertEnforcementActions(actions []commonv1.EnforcementAction) []storage.EnforcementAction {
	result := make([]storage.EnforcementAction, 0, len(actions))
	for _, action := range actions {
		switch action {
		case commonv1.EnforcementActionScaleToZero:
			result = append(result, storage.EnforcementAction_SCALE_TO_ZERO_ENFORCEMENT)
		case commonv1.EnforcementActionUnsatisfiableNodeConstraint:
			result = append(result, storage.EnforcementAction_UNSATISFIABLE_NODE_CONSTRAINT_ENFORCEMENT)
		case commonv1.EnforcementActionKillPod:
			result = append(result, storage.EnforcementAction_KILL_POD_ENFORCEMENT)
		case commonv1.EnforcementActionFailKubeRequest:
			result = append(result, storage.EnforcementAction_FAIL_KUBE_REQUEST_ENFORCEMENT)
		case commonv1.EnforcementActionFailDeploymentCreate:
			result = append(result, storage.EnforcementAction_FAIL_DEPLOYMENT_CREATE_ENFORCEMENT)
		case commonv1.EnforcementActionFailDeploymentUpdate:
			result = append(result, storage.EnforcementAction_FAIL_DEPLOYMENT_UPDATE_ENFORCEMENT)
			// Note: FAIL_BUILD_ENFORCEMENT is not supported for local policies
		}
	}
	return result
}

func convertPolicySections(sections []commonv1.PolicySection) []*storage.PolicySection {
	result := make([]*storage.PolicySection, 0, len(sections))
	for _, section := range sections {
		result = append(result, &storage.PolicySection{
			SectionName:  section.SectionName,
			PolicyGroups: convertPolicyGroups(section.PolicyGroups),
		})
	}
	return result
}

func convertPolicyGroups(groups []commonv1.PolicyGroup) []*storage.PolicyGroup {
	result := make([]*storage.PolicyGroup, 0, len(groups))
	for _, group := range groups {
		result = append(result, &storage.PolicyGroup{
			FieldName:       group.FieldName,
			BooleanOperator: convertBooleanOperator(group.BooleanOperator),
			Negate:          group.Negate,
			Values:          convertPolicyValues(group.Values),
		})
	}
	return result
}

func convertBooleanOperator(op commonv1.BooleanOperator) storage.BooleanOperator {
	switch op {
	case commonv1.BooleanOperatorAnd:
		return storage.BooleanOperator_AND
	default:
		return storage.BooleanOperator_OR
	}
}

func convertPolicyValues(values []commonv1.PolicyValue) []*storage.PolicyValue {
	result := make([]*storage.PolicyValue, 0, len(values))
	for _, value := range values {
		result = append(result, &storage.PolicyValue{
			Value: value.Value,
		})
	}
	return result
}

func convertMitreVectors(vectors []commonv1.MitreAttackVectors) []*storage.Policy_MitreAttackVectors {
	result := make([]*storage.Policy_MitreAttackVectors, 0, len(vectors))
	for _, vector := range vectors {
		result = append(result, &storage.Policy_MitreAttackVectors{
			Tactic:     vector.Tactic,
			Techniques: vector.Techniques,
		})
	}
	return result
}

func convertScopes(scopes []commonv1.Scope, namespace string, isClusterScoped bool) []*storage.Scope {
	result := make([]*storage.Scope, 0, len(scopes)+1)

	// For namespace-scoped StackroxPolicy, automatically add an implicit namespace scope
	// This ensures the policy only evaluates resources in its own namespace
	if !isClusterScoped && namespace != "" {
		result = append(result, &storage.Scope{
			Namespace: namespace,
		})
	}

	// Add any explicitly configured scopes from the spec
	for _, scope := range scopes {
		// For namespace-scoped policies, reject scopes that reference other namespaces
		// This prevents privilege escalation where a namespace-scoped policy tries to
		// evaluate resources in other namespaces
		if !isClusterScoped {
			if scope.Namespace != "" && scope.Namespace != namespace {
				log.Warnf("Ignoring scope with namespace %q in namespace-scoped policy (policy namespace: %q). "+
					"Namespace-scoped policies can only evaluate resources in their own namespace.",
					scope.Namespace, namespace)
				continue
			}
			// Also block namespace selectors - they could select other namespaces
			if scope.NamespaceSelector != nil {
				log.Warnf("Ignoring scope with namespace selector in namespace-scoped policy (policy namespace: %q). "+
					"Namespace-scoped policies cannot use namespace selectors.",
					namespace)
				continue
			}
		}

		storageScope := &storage.Scope{
			Namespace: scope.Namespace,
		}

		// Convert namespace selector if present (only for cluster-scoped policies)
		if scope.NamespaceSelector != nil {
			storageScope.NamespaceSelector = convertLabelSelector(scope.NamespaceSelector)
		}

		// Convert workload selector if present
		if scope.WorkloadSelector != nil {
			storageScope.WorkloadSelector = convertLabelSelector(scope.WorkloadSelector)
		}

		result = append(result, storageScope)
	}
	return result
}

func convertLabelSelector(selector *metav1.LabelSelector) *storage.LabelSelector {
	if selector == nil {
		return nil
	}

	result := &storage.LabelSelector{
		MatchLabels: selector.MatchLabels,
	}

	if len(selector.MatchExpressions) > 0 {
		result.Requirements = make([]*storage.LabelSelector_Requirement, 0, len(selector.MatchExpressions))
		for _, expr := range selector.MatchExpressions {
			result.Requirements = append(result.Requirements, &storage.LabelSelector_Requirement{
				Key:    expr.Key,
				Op:     convertLabelSelectorOperator(expr.Operator),
				Values: expr.Values,
			})
		}
	}

	return result
}

func convertLabelSelectorOperator(op metav1.LabelSelectorOperator) storage.LabelSelector_Operator {
	switch op {
	case metav1.LabelSelectorOpIn:
		return storage.LabelSelector_IN
	case metav1.LabelSelectorOpNotIn:
		return storage.LabelSelector_NOT_IN
	case metav1.LabelSelectorOpExists:
		return storage.LabelSelector_EXISTS
	case metav1.LabelSelectorOpDoesNotExist:
		return storage.LabelSelector_NOT_EXISTS
	default:
		return storage.LabelSelector_UNKNOWN
	}
}

func convertExclusions(exclusions []commonv1.Exclusion) []*storage.Exclusion {
	result := make([]*storage.Exclusion, 0, len(exclusions))
	for _, exclusion := range exclusions {
		storageExclusion := &storage.Exclusion{
			Name: exclusion.Name,
		}

		// Convert deployment exclusion if present
		if exclusion.Deployment != nil {
			storageExclusion.Deployment = &storage.Exclusion_Deployment{
				Name: exclusion.Deployment.Name,
			}

			if exclusion.Deployment.Scope != nil {
				storageExclusion.Deployment.Scope = &storage.Scope{
					Namespace: exclusion.Deployment.Scope.Namespace,
				}

				// Convert workload selector for deployment scope
				if exclusion.Deployment.Scope.WorkloadSelector != nil {
					storageExclusion.Deployment.Scope.WorkloadSelector = convertLabelSelector(exclusion.Deployment.Scope.WorkloadSelector)
				}
			}
		}

		// Convert image exclusion if present
		if exclusion.Image != nil {
			storageExclusion.Image = &storage.Exclusion_Image{
				Name: exclusion.Image.Name,
			}
		}

		// Convert expiration if present
		if exclusion.Expiration != nil {
			storageExclusion.Expiration = timestamppb.New(exclusion.Expiration.Time)
		}

		result = append(result, storageExclusion)
	}
	return result
}
