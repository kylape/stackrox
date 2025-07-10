package manager

import (
	"github.com/stackrox/rox/generated/storage"
	"github.com/stackrox/rox/pkg/detection"
)

// UniversalPolicySet implements PolicySet interface for filtering policies by resource type
type UniversalPolicySet struct {
	policySet *detection.PolicySet
}

// NewUniversalPolicySet creates a new universal policy set wrapper
func NewUniversalPolicySet(policySet *detection.PolicySet) *UniversalPolicySet {
	return &UniversalPolicySet{
		policySet: policySet,
	}
}

// GetPoliciesForResource returns policies that target the specified resource type
func (ups *UniversalPolicySet) GetPoliciesForResource(kind, apiVersion string) []*storage.Policy {
	var policies []*storage.Policy
	
	for _, compiledPolicy := range ups.policySet.GetCompiledPolicies() {
		policy := compiledPolicy.Policy()
		
		// Check if this policy has a resource target for the specified kind
		if ups.policyAppliesToResource(policy, kind, apiVersion) {
			policies = append(policies, policy)
		}
	}
	
	return policies
}

// GetPoliciesForResourceInNamespace returns policies that target the specified resource type in a namespace
func (ups *UniversalPolicySet) GetPoliciesForResourceInNamespace(kind, apiVersion, namespace string) []*storage.Policy {
	// For now, just return all policies for the resource type
	// In the future, this could filter by namespace-specific rules
	return ups.GetPoliciesForResource(kind, apiVersion)
}

// policyAppliesToResource checks if a policy applies to the given resource type
func (ups *UniversalPolicySet) policyAppliesToResource(policy *storage.Policy, kind, apiVersion string) bool {
	// If policy has no resource target, it's a legacy deployment-only policy
	resourceTarget := policy.GetResourceTarget()
	if resourceTarget == nil {
		// Legacy policies apply only to deployment-like resources
		return IsDeploymentLikeKind(kind)
	}
	
	switch target := resourceTarget.GetTarget().(type) {
	case *storage.ResourceTarget_Deployment:
		// Deployment target applies only to deployment-like resources
		return IsDeploymentLikeKind(kind)
		
	case *storage.ResourceTarget_Kubernetes:
		// Kubernetes target - check if it matches the resource
		if target.Kubernetes.GetApiVersion() != "" && target.Kubernetes.GetApiVersion() != apiVersion {
			return false
		}
		if target.Kubernetes.GetKind() != "" && target.Kubernetes.GetKind() != kind {
			return false
		}
		return true
		
	default:
		// Unknown target type, default to deployment-like
		return IsDeploymentLikeKind(kind)
	}
}