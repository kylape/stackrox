package localpolicy

import (
	"context"
	"fmt"
	"time"

	policyv1alpha1 "github.com/stackrox/rox/apis/policy.stackrox.io/v1alpha1"
	"github.com/stackrox/rox/generated/storage"
	"github.com/stackrox/rox/pkg/logging"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/dynamic/dynamicinformer"
	"k8s.io/client-go/tools/cache"
)

var (
	log = logging.LoggerForModule()

	// GVR for StackroxPolicy (namespace-scoped)
	stackroxPolicyGVR = schema.GroupVersionResource{
		Group:    "policy.stackrox.io",
		Version:  "v1alpha1",
		Resource: "stackroxpolicies",
	}

	// GVR for ClusterStackroxPolicy (cluster-scoped)
	clusterStackroxPolicyGVR = schema.GroupVersionResource{
		Group:    "policy.stackrox.io",
		Version:  "v1alpha1",
		Resource: "clusterstackroxpolicies",
	}
)

// Manager manages local policy informers for admission control deploy-time evaluation
type Manager struct {
	dynamicClient dynamic.Interface
	stopCh        chan struct{}

	policyInformer        cache.SharedIndexInformer
	clusterPolicyInformer cache.SharedIndexInformer

	// TODO: Add reference to admission control's policy evaluator
	// policyEvaluator *admissioncontrol.PolicyEvaluator
}

// NewManager creates a new local policy informer manager for admission control
func NewManager(dynamicClient dynamic.Interface /* TODO: add policyEvaluator */) *Manager {
	return &Manager{
		dynamicClient: dynamicClient,
		stopCh:        make(chan struct{}),
		// policyEvaluator: policyEvaluator,
	}
}

// Start begins watching StackroxPolicy and ClusterStackroxPolicy CRs
// Filters for policies with DEPLOY lifecycle stage
func (m *Manager) Start(ctx context.Context) error {
	log.Info("Starting local policy informers for admission control deploy-time evaluation")

	// Create dynamic informer factory
	factory := dynamicinformer.NewDynamicSharedInformerFactory(m.dynamicClient, 10*time.Minute)

	// Get StackroxPolicy informer (namespace-scoped)
	m.policyInformer = factory.ForResource(stackroxPolicyGVR).Informer()

	// Get ClusterStackroxPolicy informer (cluster-scoped)
	m.clusterPolicyInformer = factory.ForResource(clusterStackroxPolicyGVR).Informer()

	// Register event handlers for StackroxPolicy
	_, err := m.policyInformer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc:    m.handlePolicyAdd,
		UpdateFunc: m.handlePolicyUpdate,
		DeleteFunc: m.handlePolicyDelete,
	})
	if err != nil {
		return fmt.Errorf("failed to add event handler for StackroxPolicy: %w", err)
	}

	// Register event handlers for ClusterStackroxPolicy
	_, err = m.clusterPolicyInformer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc:    m.handleClusterPolicyAdd,
		UpdateFunc: m.handleClusterPolicyUpdate,
		DeleteFunc: m.handleClusterPolicyDelete,
	})
	if err != nil {
		return fmt.Errorf("failed to add event handler for ClusterStackroxPolicy: %w", err)
	}

	// Start informers
	factory.Start(m.stopCh)

	// Wait for cache sync
	synced := factory.WaitForCacheSync(m.stopCh)
	if !synced[stackroxPolicyGVR] {
		return fmt.Errorf("failed to sync StackroxPolicy cache")
	}
	if !synced[clusterStackroxPolicyGVR] {
		return fmt.Errorf("failed to sync ClusterStackroxPolicy cache")
	}

	log.Info("Local policy informers started successfully")
	return nil
}

// Stop halts the informers
func (m *Manager) Stop() {
	log.Info("Stopping local policy informers")
	close(m.stopCh)
}

// handlePolicyAdd processes new StackroxPolicy CRs
func (m *Manager) handlePolicyAdd(obj interface{}) {
	unstructuredObj, ok := obj.(*unstructured.Unstructured)
	if !ok {
		log.Errorf("Expected *unstructured.Unstructured but got %T", obj)
		return
	}

	// Convert unstructured to typed StackroxPolicy
	policy := &policyv1alpha1.StackroxPolicy{}
	if err := runtime.DefaultUnstructuredConverter.FromUnstructured(unstructuredObj.Object, policy); err != nil {
		log.Errorf("Failed to convert unstructured to StackroxPolicy: %v", err)
		return
	}

	log.Infof("Processing new StackroxPolicy: %s/%s", policy.Namespace, policy.Name)

	// Check if policy has DEPLOY lifecycle stage
	if !policyv1alpha1.ShouldApplyToAdmissionControl(&policy.Spec) {
		log.Debugf("Policy %s/%s does not have DEPLOY stage, marking as not applicable",
			policy.Namespace, policy.Name)
		m.updateStatusNotApplicable(policy)
		return
	}

	// Convert CRD to storage.Policy
	storagePolicy, err := policyv1alpha1.ToStoragePolicy(
		&policy.Spec,
		policy.Namespace,
		policy.Name,
		false, // not cluster-scoped
	)
	if err != nil {
		log.Errorf("Failed to convert StackroxPolicy %s/%s: %v",
			policy.Namespace, policy.Name, err)
		m.updateStatusError(policy, policyv1alpha1.ReasonConversionError, err)
		return
	}

	// Load policy into sensor's runtime evaluation engine
	if err := m.loadPolicyIntoEvaluator(storagePolicy); err != nil {
		log.Errorf("Failed to load policy %s into sensor evaluator: %v",
			storagePolicy.GetId(), err)
		m.updateStatusError(policy, policyv1alpha1.ReasonInternalError, err)
		return
	}

	// Update status - success
	log.Infof("Successfully loaded StackroxPolicy %s/%s into sensor (ID: %s)",
		policy.Namespace, policy.Name, storagePolicy.GetId())
	m.updateStatusSuccess(policy, storagePolicy.GetId())
}

// handlePolicyUpdate processes updated StackroxPolicy CRs
func (m *Manager) handlePolicyUpdate(oldObj, newObj interface{}) {
	oldUnstructured, ok := oldObj.(*unstructured.Unstructured)
	if !ok {
		log.Errorf("Expected *unstructured.Unstructured but got %T", oldObj)
		return
	}

	newUnstructured, ok := newObj.(*unstructured.Unstructured)
	if !ok {
		log.Errorf("Expected *unstructured.Unstructured but got %T", newObj)
		return
	}

	// Convert to typed objects
	oldPolicy := &policyv1alpha1.StackroxPolicy{}
	if err := runtime.DefaultUnstructuredConverter.FromUnstructured(oldUnstructured.Object, oldPolicy); err != nil {
		log.Errorf("Failed to convert old unstructured to StackroxPolicy: %v", err)
		return
	}

	newPolicy := &policyv1alpha1.StackroxPolicy{}
	if err := runtime.DefaultUnstructuredConverter.FromUnstructured(newUnstructured.Object, newPolicy); err != nil {
		log.Errorf("Failed to convert new unstructured to StackroxPolicy: %v", err)
		return
	}

	// Ignore updates that don't change the spec
	if oldPolicy.Generation == newPolicy.Generation {
		log.Debugf("Ignoring status-only update for StackroxPolicy %s/%s",
			newPolicy.Namespace, newPolicy.Name)
		return
	}

	log.Infof("Processing updated StackroxPolicy: %s/%s", newPolicy.Namespace, newPolicy.Name)

	// Treat update as delete + add
	m.handlePolicyDelete(oldObj)
	m.handlePolicyAdd(newObj)
}

// handlePolicyDelete processes deleted StackroxPolicy CRs
func (m *Manager) handlePolicyDelete(obj interface{}) {
	var unstructuredObj *unstructured.Unstructured
	var ok bool

	unstructuredObj, ok = obj.(*unstructured.Unstructured)
	if !ok {
		// Handle DeletedFinalStateUnknown
		tombstone, ok := obj.(cache.DeletedFinalStateUnknown)
		if !ok {
			log.Errorf("Expected *unstructured.Unstructured or DeletedFinalStateUnknown but got %T", obj)
			return
		}
		unstructuredObj, ok = tombstone.Obj.(*unstructured.Unstructured)
		if !ok {
			log.Errorf("DeletedFinalStateUnknown contained unexpected object: %T", tombstone.Obj)
			return
		}
	}

	// Convert to typed StackroxPolicy
	policy := &policyv1alpha1.StackroxPolicy{}
	if err := runtime.DefaultUnstructuredConverter.FromUnstructured(unstructuredObj.Object, policy); err != nil {
		log.Errorf("Failed to convert unstructured to StackroxPolicy: %v", err)
		return
	}

	log.Infof("Processing deleted StackroxPolicy: %s/%s", policy.Namespace, policy.Name)

	// Get the local policy ID from status
	if policy.Status.LocalPolicyID == "" {
		log.Debugf("Policy %s/%s has no LocalPolicyID, nothing to remove",
			policy.Namespace, policy.Name)
		return
	}

	// Remove from sensor's evaluation engine
	if err := m.removePolicyFromEvaluator(policy.Status.LocalPolicyID); err != nil {
		log.Errorf("Failed to remove policy %s from sensor evaluator: %v",
			policy.Status.LocalPolicyID, err)
		return
	}

	log.Infof("Successfully removed StackroxPolicy %s/%s from sensor",
		policy.Namespace, policy.Name)
}

// handleClusterPolicyAdd processes new ClusterStackroxPolicy CRs
func (m *Manager) handleClusterPolicyAdd(obj interface{}) {
	unstructuredObj, ok := obj.(*unstructured.Unstructured)
	if !ok {
		log.Errorf("Expected *unstructured.Unstructured but got %T", obj)
		return
	}

	// Convert unstructured to typed ClusterStackroxPolicy
	policy := &policyv1alpha1.ClusterStackroxPolicy{}
	if err := runtime.DefaultUnstructuredConverter.FromUnstructured(unstructuredObj.Object, policy); err != nil {
		log.Errorf("Failed to convert unstructured to ClusterStackroxPolicy: %v", err)
		return
	}

	log.Infof("Processing new ClusterStackroxPolicy: %s", policy.Name)

	// Check if policy has DEPLOY lifecycle stage
	if !policyv1alpha1.ShouldApplyToAdmissionControl(&policy.Spec) {
		log.Debugf("ClusterStackroxPolicy %s does not have DEPLOY stage, marking as not applicable", policy.Name)
		m.updateClusterPolicyStatusNotApplicable(policy)
		return
	}

	// Convert CRD to storage.Policy (cluster-scoped)
	storagePolicy, err := policyv1alpha1.ToStoragePolicy(
		&policy.Spec,
		"", // no namespace for cluster-scoped
		policy.Name,
		true, // cluster-scoped
	)
	if err != nil {
		log.Errorf("Failed to convert ClusterStackroxPolicy %s: %v", policy.Name, err)
		m.updateClusterPolicyStatusError(policy, policyv1alpha1.ReasonConversionError, err)
		return
	}

	// Load policy into sensor's runtime evaluation engine
	if err := m.loadPolicyIntoEvaluator(storagePolicy); err != nil {
		log.Errorf("Failed to load cluster policy %s into sensor evaluator: %v",
			storagePolicy.GetId(), err)
		m.updateClusterPolicyStatusError(policy, policyv1alpha1.ReasonInternalError, err)
		return
	}

	log.Infof("Successfully loaded ClusterStackroxPolicy %s into sensor (ID: %s)",
		policy.Name, storagePolicy.GetId())
	m.updateClusterPolicyStatusSuccess(policy, storagePolicy.GetId())
}

// handleClusterPolicyUpdate processes updated ClusterStackroxPolicy CRs
func (m *Manager) handleClusterPolicyUpdate(oldObj, newObj interface{}) {
	oldUnstructured, ok := oldObj.(*unstructured.Unstructured)
	if !ok {
		log.Errorf("Expected *unstructured.Unstructured but got %T", oldObj)
		return
	}

	newUnstructured, ok := newObj.(*unstructured.Unstructured)
	if !ok {
		log.Errorf("Expected *unstructured.Unstructured but got %T", newObj)
		return
	}

	// Convert to typed objects
	oldPolicy := &policyv1alpha1.ClusterStackroxPolicy{}
	if err := runtime.DefaultUnstructuredConverter.FromUnstructured(oldUnstructured.Object, oldPolicy); err != nil {
		log.Errorf("Failed to convert old unstructured to ClusterStackroxPolicy: %v", err)
		return
	}

	newPolicy := &policyv1alpha1.ClusterStackroxPolicy{}
	if err := runtime.DefaultUnstructuredConverter.FromUnstructured(newUnstructured.Object, newPolicy); err != nil {
		log.Errorf("Failed to convert new unstructured to ClusterStackroxPolicy: %v", err)
		return
	}

	// Ignore updates that don't change the spec
	if oldPolicy.Generation == newPolicy.Generation {
		log.Debugf("Ignoring status-only update for ClusterStackroxPolicy %s", newPolicy.Name)
		return
	}

	log.Infof("Processing updated ClusterStackroxPolicy: %s", newPolicy.Name)

	// Treat update as delete + add
	m.handleClusterPolicyDelete(oldObj)
	m.handleClusterPolicyAdd(newObj)
}

// handleClusterPolicyDelete processes deleted ClusterStackroxPolicy CRs
func (m *Manager) handleClusterPolicyDelete(obj interface{}) {
	var unstructuredObj *unstructured.Unstructured
	var ok bool

	unstructuredObj, ok = obj.(*unstructured.Unstructured)
	if !ok {
		// Handle DeletedFinalStateUnknown
		tombstone, ok := obj.(cache.DeletedFinalStateUnknown)
		if !ok {
			log.Errorf("Expected *unstructured.Unstructured or DeletedFinalStateUnknown but got %T", obj)
			return
		}
		unstructuredObj, ok = tombstone.Obj.(*unstructured.Unstructured)
		if !ok {
			log.Errorf("DeletedFinalStateUnknown contained unexpected object: %T", tombstone.Obj)
			return
		}
	}

	// Convert to typed ClusterStackroxPolicy
	policy := &policyv1alpha1.ClusterStackroxPolicy{}
	if err := runtime.DefaultUnstructuredConverter.FromUnstructured(unstructuredObj.Object, policy); err != nil {
		log.Errorf("Failed to convert unstructured to ClusterStackroxPolicy: %v", err)
		return
	}

	log.Infof("Processing deleted ClusterStackroxPolicy: %s", policy.Name)

	// Get the local policy ID from status
	if policy.Status.LocalPolicyID == "" {
		log.Debugf("ClusterStackroxPolicy %s has no LocalPolicyID, nothing to remove", policy.Name)
		return
	}

	// Remove from sensor's evaluation engine
	if err := m.removePolicyFromEvaluator(policy.Status.LocalPolicyID); err != nil {
		log.Errorf("Failed to remove cluster policy %s from sensor evaluator: %v",
			policy.Status.LocalPolicyID, err)
		return
	}

	log.Infof("Successfully removed ClusterStackroxPolicy %s from sensor", policy.Name)
}

// loadPolicyIntoEvaluator loads a policy into sensor's runtime evaluation engine
func (m *Manager) loadPolicyIntoEvaluator(policy *storage.Policy) error {
	// TODO: Integrate with sensor's policy evaluator
	// m.policyEvaluator.AddPolicy(policy)
	log.Debugf("Would load policy %s into sensor evaluator", policy.GetId())
	return nil
}

// removePolicyFromEvaluator removes a policy from sensor's runtime evaluation engine
func (m *Manager) removePolicyFromEvaluator(policyID string) error {
	// TODO: Integrate with sensor's policy evaluator
	// m.policyEvaluator.RemovePolicy(policyID)
	log.Debugf("Would remove policy %s from sensor evaluator", policyID)
	return nil
}

// updateStatusSuccess updates the policy status with success condition
func (m *Manager) updateStatusSuccess(policy *policyv1alpha1.StackroxPolicy, localPolicyID string) {
	condition := policyv1alpha1.NewCondition(
		policyv1alpha1.ConditionAcceptedByAdmissionControl,
		metav1.ConditionTrue,
		policyv1alpha1.ReasonPolicyLoaded,
		policyv1alpha1.MessagePolicyLoaded,
	)
	condition.ObservedGeneration = policy.Generation

	m.updateStatus(policy, condition, localPolicyID)
}

// updateStatusNotApplicable updates the policy status indicating it's not for sensor
func (m *Manager) updateStatusNotApplicable(policy *policyv1alpha1.StackroxPolicy) {
	condition := policyv1alpha1.NewCondition(
		policyv1alpha1.ConditionAcceptedByAdmissionControl,
		metav1.ConditionTrue,
		policyv1alpha1.ReasonNotApplicable,
		policyv1alpha1.MessageRuntimeOnlyNotForAdmissionControl,
	)
	condition.ObservedGeneration = policy.Generation

	m.updateStatus(policy, condition, "")
}

// updateStatusError updates the policy status with error condition
func (m *Manager) updateStatusError(policy *policyv1alpha1.StackroxPolicy, reason string, err error) {
	var message string
	switch reason {
	case policyv1alpha1.ReasonConversionError:
		message = policyv1alpha1.MessageConversionError + ": " + err.Error()
	case policyv1alpha1.ReasonInternalError:
		message = policyv1alpha1.MessageInternalError + ": " + err.Error()
	default:
		message = err.Error()
	}

	condition := policyv1alpha1.NewCondition(
		policyv1alpha1.ConditionAcceptedByAdmissionControl,
		metav1.ConditionFalse,
		reason,
		message,
	)
	condition.ObservedGeneration = policy.Generation

	m.updateStatus(policy, condition, "")
}

// updateStatus updates the policy status with the given condition
func (m *Manager) updateStatus(policy *policyv1alpha1.StackroxPolicy, condition metav1.Condition, localPolicyID string) {
	// TODO: Use dynamic client to update status subresource
	// For now, logging what would be updated
	log.Infof("Would update StackroxPolicy %s/%s status: Type=%s, Status=%s, Reason=%s, LocalID=%s",
		policy.Namespace, policy.Name, condition.Type, condition.Status, condition.Reason, localPolicyID)

	// Example implementation (using dynamic client):
	/*
	ctx := context.Background()

	// Clone policy to avoid modifying cache
	policyCopy := policy.DeepCopy()

	// Update conditions
	policyCopy.Status.Conditions = policyv1alpha1.SetCondition(
		policyCopy.Status.Conditions,
		condition,
	)

	// Set local policy ID if provided
	if localPolicyID != "" {
		policyCopy.Status.LocalPolicyID = localPolicyID
	}

	// Update last evaluated timestamp
	now := metav1.Now()
	policyCopy.Status.LastEvaluated = &now

	// Convert to unstructured for dynamic client
	unstructuredObj, err := runtime.DefaultUnstructuredConverter.ToUnstructured(policyCopy)
	if err != nil {
		log.Errorf("Failed to convert policy to unstructured: %v", err)
		return
	}

	// Update status subresource using dynamic client
	_, err = m.dynamicClient.Resource(stackroxPolicyGVR).
		Namespace(policy.Namespace).
		UpdateStatus(ctx, &unstructured.Unstructured{Object: unstructuredObj}, metav1.UpdateOptions{})
	if err != nil {
		if errors.IsConflict(err) {
			// Retry on conflict
			log.Warnf("Conflict updating status for %s/%s, will retry", policy.Namespace, policy.Name)
		} else {
			log.Errorf("Failed to update status for %s/%s: %v", policy.Namespace, policy.Name, err)
		}
	}
	*/
}

// updateClusterPolicyStatusSuccess updates the cluster policy status with success condition
func (m *Manager) updateClusterPolicyStatusSuccess(policy *policyv1alpha1.ClusterStackroxPolicy, localPolicyID string) {
	condition := policyv1alpha1.NewCondition(
		policyv1alpha1.ConditionAcceptedByAdmissionControl,
		metav1.ConditionTrue,
		policyv1alpha1.ReasonPolicyLoaded,
		policyv1alpha1.MessagePolicyLoaded,
	)
	condition.ObservedGeneration = policy.Generation

	m.updateClusterPolicyStatus(policy, condition, localPolicyID)
}

// updateClusterPolicyStatusNotApplicable updates the cluster policy status indicating it's not for sensor
func (m *Manager) updateClusterPolicyStatusNotApplicable(policy *policyv1alpha1.ClusterStackroxPolicy) {
	condition := policyv1alpha1.NewCondition(
		policyv1alpha1.ConditionAcceptedByAdmissionControl,
		metav1.ConditionTrue,
		policyv1alpha1.ReasonNotApplicable,
		policyv1alpha1.MessageRuntimeOnlyNotForAdmissionControl,
	)
	condition.ObservedGeneration = policy.Generation

	m.updateClusterPolicyStatus(policy, condition, "")
}

// updateClusterPolicyStatusError updates the cluster policy status with error condition
func (m *Manager) updateClusterPolicyStatusError(policy *policyv1alpha1.ClusterStackroxPolicy, reason string, err error) {
	var message string
	switch reason {
	case policyv1alpha1.ReasonConversionError:
		message = policyv1alpha1.MessageConversionError + ": " + err.Error()
	case policyv1alpha1.ReasonInternalError:
		message = policyv1alpha1.MessageInternalError + ": " + err.Error()
	default:
		message = err.Error()
	}

	condition := policyv1alpha1.NewCondition(
		policyv1alpha1.ConditionAcceptedByAdmissionControl,
		metav1.ConditionFalse,
		reason,
		message,
	)
	condition.ObservedGeneration = policy.Generation

	m.updateClusterPolicyStatus(policy, condition, "")
}

// updateClusterPolicyStatus updates the cluster policy status with the given condition
func (m *Manager) updateClusterPolicyStatus(policy *policyv1alpha1.ClusterStackroxPolicy, condition metav1.Condition, localPolicyID string) {
	// TODO: Use dynamic client to update status subresource
	// For now, logging what would be updated
	log.Infof("Would update ClusterStackroxPolicy %s status: Type=%s, Status=%s, Reason=%s, LocalID=%s",
		policy.Name, condition.Type, condition.Status, condition.Reason, localPolicyID)
}
