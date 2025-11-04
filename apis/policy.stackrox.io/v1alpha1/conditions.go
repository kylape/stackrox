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
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// Condition types for StackroxPolicy and ClusterStackroxPolicy status
const (
	// ConditionAcceptedBySensor indicates whether sensor has loaded the policy
	// into its runtime evaluation engine
	// Status=True: Policy is actively being evaluated by sensor for runtime violations
	// Status=False: Policy was rejected or failed to load in sensor
	// Status=Unknown: Sensor has not yet processed this policy
	ConditionAcceptedBySensor = "AcceptedBySensor"

	// ConditionAcceptedByAdmissionControl indicates whether admission-control has loaded
	// the policy into its deployment-time evaluation engine
	// Status=True: Policy is actively being evaluated by admission control for deploy-time violations
	// Status=False: Policy was rejected or failed to load in admission control
	// Status=Unknown: Admission control has not yet processed this policy
	ConditionAcceptedByAdmissionControl = "AcceptedByAdmissionControl"
)

// Condition reasons for policy acceptance/rejection
const (
	// Success reasons
	ReasonPolicyLoaded       = "PolicyLoaded"       // Policy successfully loaded into evaluation engine
	ReasonPolicyUpdated      = "PolicyUpdated"      // Policy successfully updated in evaluation engine
	ReasonPolicyDisabled     = "PolicyDisabled"     // Policy is disabled, not evaluating
	ReasonNotApplicable      = "NotApplicable"      // Policy doesn't apply to this component (e.g., RUNTIME-only for admission-control)

	// Failure reasons
	ReasonConversionError    = "ConversionError"    // Failed to convert CRD to storage.Policy
	ReasonValidationError    = "ValidationError"    // Policy validation failed
	ReasonInvalidCriteria    = "InvalidCriteria"    // Policy criteria are invalid or unsupported
	ReasonInternalError      = "InternalError"      // Internal error loading policy
)

// Condition messages
const (
	MessagePolicyLoaded                = "Policy successfully loaded and is being evaluated"
	MessagePolicyUpdated               = "Policy successfully updated and is being evaluated"
	MessagePolicyDisabled              = "Policy is disabled and will not be evaluated"
	MessageRuntimeOnlyNotForAdmission  = "Policy has only RUNTIME lifecycle stages, not applicable to admission control"
	MessageDeployOnlyNotForSensor      = "Policy has only DEPLOY lifecycle stages, not applicable to sensor runtime evaluation"
	MessageConversionError             = "Failed to convert policy spec to internal format"
	MessageValidationError             = "Policy validation failed"
	MessageInvalidCriteria             = "Policy criteria are invalid or unsupported"
	MessageInternalError               = "Internal error occurred while processing policy"
)

// NewCondition creates a new condition with the given parameters
func NewCondition(conditionType string, status metav1.ConditionStatus, reason, message string) metav1.Condition {
	return metav1.Condition{
		Type:               conditionType,
		Status:             status,
		LastTransitionTime: metav1.Now(),
		Reason:             reason,
		Message:            message,
		ObservedGeneration: 0, // Will be set by the caller with the actual generation
	}
}

// SetCondition adds or updates a condition in the conditions list
// If the condition with the same type exists and its status hasn't changed,
// only the message and reason are updated without changing LastTransitionTime
func SetCondition(conditions []metav1.Condition, newCondition metav1.Condition) []metav1.Condition {
	if conditions == nil {
		conditions = []metav1.Condition{}
	}

	// Find existing condition with same type
	for i, condition := range conditions {
		if condition.Type == newCondition.Type {
			// If status is changing, update LastTransitionTime
			if condition.Status != newCondition.Status {
				newCondition.LastTransitionTime = metav1.Now()
			} else {
				// Status unchanged, preserve LastTransitionTime
				newCondition.LastTransitionTime = condition.LastTransitionTime
			}
			conditions[i] = newCondition
			return conditions
		}
	}

	// Condition doesn't exist, append it
	conditions = append(conditions, newCondition)
	return conditions
}

// GetCondition returns the condition with the given type, or nil if not found
func GetCondition(conditions []metav1.Condition, conditionType string) *metav1.Condition {
	for i := range conditions {
		if conditions[i].Type == conditionType {
			return &conditions[i]
		}
	}
	return nil
}

// IsConditionTrue returns true if the condition exists and has status True
func IsConditionTrue(conditions []metav1.Condition, conditionType string) bool {
	condition := GetCondition(conditions, conditionType)
	return condition != nil && condition.Status == metav1.ConditionTrue
}

// IsConditionFalse returns true if the condition exists and has status False
func IsConditionFalse(conditions []metav1.Condition, conditionType string) bool {
	condition := GetCondition(conditions, conditionType)
	return condition != nil && condition.Status == metav1.ConditionFalse
}

// IsConditionUnknown returns true if the condition doesn't exist or has status Unknown
func IsConditionUnknown(conditions []metav1.Condition, conditionType string) bool {
	condition := GetCondition(conditions, conditionType)
	return condition == nil || condition.Status == metav1.ConditionUnknown
}

// IsPolicyAccepted returns true if the policy is accepted by at least one component
// A policy is considered "accepted" if either sensor or admission-control has
// successfully loaded it (or marked it as NotApplicable, which means it was
// successfully processed but doesn't apply to that component)
func IsPolicyAccepted(conditions []metav1.Condition) bool {
	sensorCondition := GetCondition(conditions, ConditionAcceptedBySensor)
	admissionCondition := GetCondition(conditions, ConditionAcceptedByAdmissionControl)

	sensorAccepted := sensorCondition != nil &&
		(sensorCondition.Status == metav1.ConditionTrue ||
			sensorCondition.Reason == ReasonNotApplicable)

	admissionAccepted := admissionCondition != nil &&
		(admissionCondition.Status == metav1.ConditionTrue ||
			admissionCondition.Reason == ReasonNotApplicable)

	return sensorAccepted || admissionAccepted
}

// ShouldApplyToSensor returns true if the policy should be evaluated by sensor
// Sensor evaluates policies with RUNTIME lifecycle stage
func ShouldApplyToSensor(spec *StackroxPolicySpec) bool {
	for _, stage := range spec.LifecycleStages {
		if stage == "RUNTIME" {
			return true
		}
	}
	return false
}

// ShouldApplyToAdmissionControl returns true if the policy should be evaluated by admission control
// Admission control evaluates policies with DEPLOY lifecycle stage
func ShouldApplyToAdmissionControl(spec *StackroxPolicySpec) bool {
	for _, stage := range spec.LifecycleStages {
		if stage == "DEPLOY" {
			return true
		}
	}
	return false
}
