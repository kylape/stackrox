package localpolicy

import (
	"context"
	"time"

	policyv1alpha1 "github.com/stackrox/rox/apis/policy.stackrox.io/v1alpha1"
	"github.com/stackrox/rox/generated/storage"
	"github.com/stackrox/rox/pkg/logging"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/cache"
)

var (
	log = logging.LoggerForModule()
)

// Manager manages local policy informers for admission control deploy-time evaluation
type Manager struct {
	k8sClient kubernetes.Interface
	stopCh    chan struct{}

	// TODO: Add reference to admission control's policy evaluator
	// policyEvaluator *admissioncontrol.PolicyEvaluator
}

// NewManager creates a new local policy informer manager for admission control
func NewManager(k8sClient kubernetes.Interface /* TODO: add policyEvaluator */) *Manager {
	return &Manager{
		k8sClient: k8sClient,
		stopCh:    make(chan struct{}),
		// policyEvaluator: policyEvaluator,
	}
}

// Start begins watching StackroxPolicy and ClusterStackroxPolicy CRs
// Filters for policies with DEPLOY lifecycle stage
func (m *Manager) Start(ctx context.Context) error {
	log.Info("Starting local policy informers for admission control deploy-time evaluation")

	// Create informer factory
	// TODO: Replace with generated clientset for policy.stackrox.io
	// For now, using dynamic client or custom informers
	factory := informers.NewSharedInformerFactory(m.k8sClient, 10*time.Minute)

	// TODO: Get StackroxPolicy informer
	// policyInformer := factory.Policy().V1alpha1().StackroxPolicies()

	// TODO: Get ClusterStackroxPolicy informer
	// clusterPolicyInformer := factory.Policy().V1alpha1().ClusterStackroxPolicies()

	// Register event handlers for StackroxPolicy
	// policyInformer.Informer().AddEventHandler(cache.ResourceEventHandlerFuncs{
	// 	AddFunc:    m.handlePolicyAdd,
	// 	UpdateFunc: m.handlePolicyUpdate,
	// 	DeleteFunc: m.handlePolicyDelete,
	// })

	// Register event handlers for ClusterStackroxPolicy
	// clusterPolicyInformer.Informer().AddEventHandler(cache.ResourceEventHandlerFuncs{
	// 	AddFunc:    m.handleClusterPolicyAdd,
	// 	UpdateFunc: m.handleClusterPolicyUpdate,
	// 	DeleteFunc: m.handleClusterPolicyDelete,
	// })

	// Start informers
	// factory.Start(m.stopCh)
	// factory.WaitForCacheSync(m.stopCh)

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
	policy, ok := obj.(*policyv1alpha1.StackroxPolicy)
	if !ok {
		log.Errorf("Expected StackroxPolicy but got %T", obj)
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

	// Load policy into admission control's deploy-time evaluation engine
	if err := m.loadPolicyIntoEvaluator(storagePolicy); err != nil {
		log.Errorf("Failed to load policy %s into admission control evaluator: %v",
			storagePolicy.GetId(), err)
		m.updateStatusError(policy, policyv1alpha1.ReasonInternalError, err)
		return
	}

	// Update status - success
	log.Infof("Successfully loaded StackroxPolicy %s/%s into admission control (ID: %s)",
		policy.Namespace, policy.Name, storagePolicy.GetId())
	m.updateStatusSuccess(policy, storagePolicy.GetId())
}

// handlePolicyUpdate processes updated StackroxPolicy CRs
func (m *Manager) handlePolicyUpdate(oldObj, newObj interface{}) {
	oldPolicy, ok := oldObj.(*policyv1alpha1.StackroxPolicy)
	if !ok {
		log.Errorf("Expected StackroxPolicy but got %T", oldObj)
		return
	}

	newPolicy, ok := newObj.(*policyv1alpha1.StackroxPolicy)
	if !ok {
		log.Errorf("Expected StackroxPolicy but got %T", newObj)
		return
	}

	// Ignore updates that don't change the spec
	if oldPolicy.Generation == newPolicy.Generation {
		log.Debugf("Ignoring status-only update for StackroxPolicy %s/%s",
			newPolicy.Namespace, newPolicy.Name)
		return
	}

	log.Infof("Processing updated StackroxPolicy: %s/%s", newPolicy.Namespace, newPolicy.Name)

	// TODO: Implement update logic similar to Add
	// Should remove old policy and add new one, or update in-place
}

// handlePolicyDelete processes deleted StackroxPolicy CRs
func (m *Manager) handlePolicyDelete(obj interface{}) {
	policy, ok := obj.(*policyv1alpha1.StackroxPolicy)
	if !ok {
		// Handle DeletedFinalStateUnknown
		tombstone, ok := obj.(cache.DeletedFinalStateUnknown)
		if !ok {
			log.Errorf("Expected StackroxPolicy or DeletedFinalStateUnknown but got %T", obj)
			return
		}
		policy, ok = tombstone.Obj.(*policyv1alpha1.StackroxPolicy)
		if !ok {
			log.Errorf("DeletedFinalStateUnknown contained unexpected object: %T", tombstone.Obj)
			return
		}
	}

	log.Infof("Processing deleted StackroxPolicy: %s/%s", policy.Namespace, policy.Name)

	// Get the local policy ID from status
	if policy.Status.LocalPolicyID == "" {
		log.Debugf("Policy %s/%s has no LocalPolicyID, nothing to remove",
			policy.Namespace, policy.Name)
		return
	}

	// Remove from admission control's evaluation engine
	if err := m.removePolicyFromEvaluator(policy.Status.LocalPolicyID); err != nil {
		log.Errorf("Failed to remove policy %s from admission control evaluator: %v",
			policy.Status.LocalPolicyID, err)
		return
	}

	log.Infof("Successfully removed StackroxPolicy %s/%s from admission control",
		policy.Namespace, policy.Name)
}

// handleClusterPolicyAdd processes new ClusterStackroxPolicy CRs
func (m *Manager) handleClusterPolicyAdd(obj interface{}) {
	policy, ok := obj.(*policyv1alpha1.ClusterStackroxPolicy)
	if !ok {
		log.Errorf("Expected ClusterStackroxPolicy but got %T", obj)
		return
	}

	log.Infof("Processing new ClusterStackroxPolicy: %s", policy.Name)

	// TODO: Similar logic to StackroxPolicy but with isClusterScoped=true
}

// handleClusterPolicyUpdate processes updated ClusterStackroxPolicy CRs
func (m *Manager) handleClusterPolicyUpdate(oldObj, newObj interface{}) {
	// TODO: Implement similar to handlePolicyUpdate
}

// handleClusterPolicyDelete processes deleted ClusterStackroxPolicy CRs
func (m *Manager) handleClusterPolicyDelete(obj interface{}) {
	// TODO: Implement similar to handlePolicyDelete
}

// loadPolicyIntoEvaluator loads a policy into admission control's deploy-time evaluation engine
func (m *Manager) loadPolicyIntoEvaluator(policy *storage.Policy) error {
	// TODO: Integrate with admission control's policy evaluator
	// m.policyEvaluator.AddPolicy(policy)
	log.Debugf("Would load policy %s into admission control evaluator", policy.GetId())
	return nil
}

// removePolicyFromEvaluator removes a policy from admission control's deploy-time evaluation engine
func (m *Manager) removePolicyFromEvaluator(policyID string) error {
	// TODO: Integrate with admission control's policy evaluator
	// m.policyEvaluator.RemovePolicy(policyID)
	log.Debugf("Would remove policy %s from admission control evaluator", policyID)
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

// updateStatusNotApplicable updates the policy status indicating it's not for admission control
func (m *Manager) updateStatusNotApplicable(policy *policyv1alpha1.StackroxPolicy) {
	condition := policyv1alpha1.NewCondition(
		policyv1alpha1.ConditionAcceptedByAdmissionControl,
		metav1.ConditionTrue,
		policyv1alpha1.ReasonNotApplicable,
		policyv1alpha1.MessageRuntimeOnlyNotForAdmission,
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
	// TODO: Use generated clientset to update status
	// For now, logging what would be updated
	log.Infof("Would update StackroxPolicy %s/%s status: Type=%s, Status=%s, Reason=%s, LocalID=%s",
		policy.Namespace, policy.Name, condition.Type, condition.Status, condition.Reason, localPolicyID)

	// Example implementation (requires generated clientset):
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

	// Update status subresource
	_, err := m.policyClient.PolicyV1alpha1().StackroxPolicies(policy.Namespace).UpdateStatus(
		ctx,
		policyCopy,
		metav1.UpdateOptions{},
	)
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
