package localpolicy

import (
	"context"
	"fmt"
	"sort"
	"sync"
	"time"

	policyv1alpha1 "github.com/stackrox/rox/apis/policy.stackrox.io/v1alpha1"
	"github.com/stackrox/rox/generated/storage"
	"github.com/stackrox/rox/pkg/logging"
	k8serrors "k8s.io/apimachinery/pkg/api/errors"
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

const (
	// maxStatusUpdateRetries is the maximum number of retries for status updates on optimistic concurrency conflicts
	maxStatusUpdateRetries = 5

	// maxDeploymentViolationsTracked limits per-deployment tracking to prevent unbounded CRD growth
	// With ~100 bytes per deployment, 100 deployments = ~10KB (well within CRD limits)
	maxDeploymentViolationsTracked = 100
)

// PolicyDetector is the interface for policy detection (avoid circular dependency)
type PolicyDetector interface {
	AddLocalPolicy(policy *storage.Policy) error
	RemoveLocalPolicy(policyID string) error
}

// deploymentViolationMetrics tracks violations for a specific deployment
type deploymentViolationMetrics struct {
	deploymentID      string
	deploymentName    string
	namespace         string
	violationCount    int32
	lastViolationTime time.Time
}

// violationMetrics tracks accumulated violations for a policy
type violationMetrics struct {
	totalViolations       int32
	lastViolationTime     time.Time
	violationsByNamespace map[string]int32 // Deprecated, kept for backward compat
	// Map of deploymentID -> per-deployment metrics
	deploymentViolations map[string]*deploymentViolationMetrics
}

// policyRef tracks CRD reference for a local policy
type policyRef struct {
	namespace   string // Empty for cluster-scoped
	name        string
	isClusterScoped bool
}

// Manager manages local policy informers for sensor runtime evaluation
type Manager struct {
	dynamicClient dynamic.Interface
	detector      PolicyDetector
	stopCh        chan struct{}

	policyInformer        cache.SharedIndexInformer
	clusterPolicyInformer cache.SharedIndexInformer

	// Violation tracking
	violationsMu      sync.Mutex
	pendingViolations map[string]*violationMetrics // policyID -> metrics
	policyRefs        map[string]*policyRef        // policyID -> CRD reference
	updateTicker      *time.Ticker
}

// NewManager creates a new local policy informer manager for sensor
func NewManager(dynamicClient dynamic.Interface, detector PolicyDetector) *Manager {
	return &Manager{
		dynamicClient:     dynamicClient,
		detector:          detector,
		stopCh:            make(chan struct{}),
		pendingViolations: make(map[string]*violationMetrics),
		policyRefs:        make(map[string]*policyRef),
		updateTicker:      time.NewTicker(30 * time.Second), // Batch updates every 30 seconds
	}
}

// RecordViolation is called by the detector when a local policy violation occurs
// This implements the detector.ViolationRecorder interface
func (m *Manager) RecordViolation(policyID string, deploymentID string, deploymentName string, namespace string, timestamp time.Time) {
	m.violationsMu.Lock()
	defer m.violationsMu.Unlock()

	metrics, exists := m.pendingViolations[policyID]
	if !exists {
		metrics = &violationMetrics{
			violationsByNamespace: make(map[string]int32),
			deploymentViolations:  make(map[string]*deploymentViolationMetrics),
		}
		m.pendingViolations[policyID] = metrics
	}

	// Update aggregate metrics
	metrics.totalViolations++
	metrics.lastViolationTime = timestamp
	if namespace != "" {
		metrics.violationsByNamespace[namespace]++
	}

	// Update per-deployment metrics
	deplMetrics, exists := metrics.deploymentViolations[deploymentID]
	if !exists {
		// Check if we need to evict an old deployment to stay under limit
		if len(metrics.deploymentViolations) >= maxDeploymentViolationsTracked {
			m.evictOldestDeployment(metrics)
		}

		deplMetrics = &deploymentViolationMetrics{
			deploymentID:   deploymentID,
			deploymentName: deploymentName,
			namespace:      namespace,
		}
		metrics.deploymentViolations[deploymentID] = deplMetrics
	}

	deplMetrics.violationCount++
	deplMetrics.lastViolationTime = timestamp

	log.Debugf("Recorded violation for local policy %s in deployment %s/%s (total: %d, deployment: %d)",
		policyID, namespace, deploymentName, metrics.totalViolations, deplMetrics.violationCount)
}

// evictOldestDeployment removes the deployment with the oldest lastViolationTime
// to keep the tracked deployments under maxDeploymentViolationsTracked
func (m *Manager) evictOldestDeployment(metrics *violationMetrics) {
	var oldestID string
	var oldestTime time.Time

	for id, deplMetrics := range metrics.deploymentViolations {
		if oldestID == "" || deplMetrics.lastViolationTime.Before(oldestTime) {
			oldestID = id
			oldestTime = deplMetrics.lastViolationTime
		}
	}

	if oldestID != "" {
		evictedDepl := metrics.deploymentViolations[oldestID]
		delete(metrics.deploymentViolations, oldestID)
		log.Infof("Evicted deployment %s/%s from violation tracking (limit: %d, last violation: %s)",
			evictedDepl.namespace, evictedDepl.deploymentName,
			maxDeploymentViolationsTracked, evictedDepl.lastViolationTime)
	}
}

// Start begins watching StackroxPolicy and ClusterStackroxPolicy CRs
// Filters for policies with RUNTIME lifecycle stage
func (m *Manager) Start(ctx context.Context) error {
	log.Info("Starting local policy informers for sensor runtime evaluation")

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

	// Start periodic violation metrics update goroutine
	go m.runPeriodicUpdates()

	log.Info("Local policy informers started successfully")
	return nil
}

// runPeriodicUpdates runs in a goroutine and periodically flushes violation metrics to CRD status
func (m *Manager) runPeriodicUpdates() {
	for {
		select {
		case <-m.stopCh:
			m.updateTicker.Stop()
			return
		case <-m.updateTicker.C:
			m.flushViolationMetrics()
		}
	}
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

	// Check if policy has RUNTIME lifecycle stage
	if !policyv1alpha1.ShouldApplyToSensor(&policy.Spec) {
		log.Debugf("Policy %s/%s does not have RUNTIME stage, marking as not applicable",
			policy.Namespace, policy.Name)
		m.updateStatusNotApplicable(policy)
		return
	}

	// Convert CRD to storage.Policy
	storagePolicy, err := policyv1alpha1.ToStoragePolicy(
		&policy.Spec,
		policy.Namespace,
		policy.Name,
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

	// Store CRD reference for violation tracking
	m.storePolicyRef(storagePolicy.GetId(), &policyRef{
		namespace:       policy.Namespace,
		name:            policy.Name,
		isClusterScoped: false,
	})

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

	// Remove policy reference for violation tracking
	m.removePolicyRef(policy.Status.LocalPolicyID)

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

	// Check if policy has RUNTIME lifecycle stage
	if !policyv1alpha1.ShouldApplyToSensorClusterScoped(&policy.Spec) {
		log.Debugf("ClusterStackroxPolicy %s does not have RUNTIME stage, marking as not applicable", policy.Name)
		m.updateClusterPolicyStatusNotApplicable(policy)
		return
	}

	// Convert CRD to storage.Policy (cluster-scoped)
	storagePolicy, err := policyv1alpha1.ToStoragePolicyFromClusterSpec(
		&policy.Spec,
		policy.Name,
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

	// Store CRD reference for violation tracking
	m.storePolicyRef(storagePolicy.GetId(), &policyRef{
		namespace:       "", // cluster-scoped
		name:            policy.Name,
		isClusterScoped: true,
	})

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

	// Remove policy reference for violation tracking
	m.removePolicyRef(policy.Status.LocalPolicyID)

	log.Infof("Successfully removed ClusterStackroxPolicy %s from sensor", policy.Name)
}

// loadPolicyIntoEvaluator loads a policy into sensor's runtime evaluation engine
func (m *Manager) loadPolicyIntoEvaluator(policy *storage.Policy) error {
	if m.detector == nil {
		return fmt.Errorf("detector not initialized")
	}
	return m.detector.AddLocalPolicy(policy)
}

// removePolicyFromEvaluator removes a policy from sensor's runtime evaluation engine
func (m *Manager) removePolicyFromEvaluator(policyID string) error {
	if m.detector == nil {
		return fmt.Errorf("detector not initialized")
	}
	return m.detector.RemoveLocalPolicy(policyID)
}

// updateStatusSuccess updates the policy status with success condition
func (m *Manager) updateStatusSuccess(policy *policyv1alpha1.StackroxPolicy, localPolicyID string) {
	condition := policyv1alpha1.NewCondition(
		policyv1alpha1.ConditionAcceptedBySensor,
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
		policyv1alpha1.ConditionAcceptedBySensor,
		metav1.ConditionTrue,
		policyv1alpha1.ReasonNotApplicable,
		policyv1alpha1.MessageDeployOnlyNotForSensor,
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
		policyv1alpha1.ConditionAcceptedBySensor,
		metav1.ConditionFalse,
		reason,
		message,
	)
	condition.ObservedGeneration = policy.Generation

	m.updateStatus(policy, condition, "")
}

// updateStatus updates the policy status with the given condition
// Retries on optimistic concurrency conflicts by fetching fresh object and reapplying changes
func (m *Manager) updateStatus(policy *policyv1alpha1.StackroxPolicy, condition metav1.Condition, localPolicyID string) {
	ctx := context.Background()

	// Retry loop for optimistic concurrency conflicts
	for retryCount := 0; retryCount < maxStatusUpdateRetries; retryCount++ {
		// Fetch fresh copy from API server to get latest resourceVersion
		unstructuredObj, err := m.dynamicClient.Resource(stackroxPolicyGVR).
			Namespace(policy.Namespace).
			Get(ctx, policy.Name, metav1.GetOptions{})
		if err != nil {
			if k8serrors.IsNotFound(err) {
				log.Debugf("Policy %s/%s not found, possibly deleted", policy.Namespace, policy.Name)
				return
			}
			log.Errorf("Failed to get policy %s/%s for status update: %v", policy.Namespace, policy.Name, err)
			return
		}

		// Convert to typed policy to manipulate status
		policyCopy := &policyv1alpha1.StackroxPolicy{}
		if err := runtime.DefaultUnstructuredConverter.FromUnstructured(unstructuredObj.Object, policyCopy); err != nil {
			log.Errorf("Failed to convert unstructured to StackroxPolicy: %v", err)
			return
		}

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

		// Convert back to unstructured for dynamic client
		unstructuredUpdated, err := runtime.DefaultUnstructuredConverter.ToUnstructured(policyCopy)
		if err != nil {
			log.Errorf("Failed to convert policy to unstructured: %v", err)
			return
		}

		// Try to update status subresource
		_, err = m.dynamicClient.Resource(stackroxPolicyGVR).
			Namespace(policy.Namespace).
			UpdateStatus(ctx, &unstructured.Unstructured{Object: unstructuredUpdated}, metav1.UpdateOptions{})
		if err != nil {
			if k8serrors.IsConflict(err) {
				log.Debugf("Conflict updating status for %s/%s (retry %d/%d): %v",
					policy.Namespace, policy.Name, retryCount+1, maxStatusUpdateRetries, err)
				// Exponential backoff
				time.Sleep(time.Duration(retryCount+1) * 100 * time.Millisecond)
				continue
			}
			log.Errorf("Failed to update status for %s/%s: %v", policy.Namespace, policy.Name, err)
			return
		}

		// Success!
		log.Infof("Updated StackroxPolicy %s/%s status: Type=%s, Status=%s, Reason=%s, LocalID=%s",
			policy.Namespace, policy.Name, condition.Type, condition.Status, condition.Reason, localPolicyID)
		return
	}

	// Exhausted retries
	log.Errorf("Failed to update status for %s/%s after %d retries due to conflicts",
		policy.Namespace, policy.Name, maxStatusUpdateRetries)
}

// updateClusterPolicyStatusSuccess updates the cluster policy status with success condition
func (m *Manager) updateClusterPolicyStatusSuccess(policy *policyv1alpha1.ClusterStackroxPolicy, localPolicyID string) {
	condition := policyv1alpha1.NewCondition(
		policyv1alpha1.ConditionAcceptedBySensor,
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
		policyv1alpha1.ConditionAcceptedBySensor,
		metav1.ConditionTrue,
		policyv1alpha1.ReasonNotApplicable,
		policyv1alpha1.MessageDeployOnlyNotForSensor,
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
		policyv1alpha1.ConditionAcceptedBySensor,
		metav1.ConditionFalse,
		reason,
		message,
	)
	condition.ObservedGeneration = policy.Generation

	m.updateClusterPolicyStatus(policy, condition, "")
}

// updateClusterPolicyStatus updates the cluster policy status with the given condition
// Retries on optimistic concurrency conflicts by fetching fresh object and reapplying changes
func (m *Manager) updateClusterPolicyStatus(policy *policyv1alpha1.ClusterStackroxPolicy, condition metav1.Condition, localPolicyID string) {
	ctx := context.Background()

	// Retry loop for optimistic concurrency conflicts
	for retryCount := 0; retryCount < maxStatusUpdateRetries; retryCount++ {
		// Fetch fresh copy from API server to get latest resourceVersion
		unstructuredObj, err := m.dynamicClient.Resource(clusterStackroxPolicyGVR).
			Get(ctx, policy.Name, metav1.GetOptions{})
		if err != nil {
			if k8serrors.IsNotFound(err) {
				log.Debugf("ClusterStackroxPolicy %s not found, possibly deleted", policy.Name)
				return
			}
			log.Errorf("Failed to get ClusterStackroxPolicy %s for status update: %v", policy.Name, err)
			return
		}

		// Convert to typed policy to manipulate status
		policyCopy := &policyv1alpha1.ClusterStackroxPolicy{}
		if err := runtime.DefaultUnstructuredConverter.FromUnstructured(unstructuredObj.Object, policyCopy); err != nil {
			log.Errorf("Failed to convert unstructured to ClusterStackroxPolicy: %v", err)
			return
		}

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

		// Convert back to unstructured for dynamic client
		unstructuredUpdated, err := runtime.DefaultUnstructuredConverter.ToUnstructured(policyCopy)
		if err != nil {
			log.Errorf("Failed to convert cluster policy to unstructured: %v", err)
			return
		}

		// Try to update status subresource (cluster-scoped, no namespace)
		_, err = m.dynamicClient.Resource(clusterStackroxPolicyGVR).
			UpdateStatus(ctx, &unstructured.Unstructured{Object: unstructuredUpdated}, metav1.UpdateOptions{})
		if err != nil {
			if k8serrors.IsConflict(err) {
				log.Debugf("Conflict updating status for ClusterStackroxPolicy %s (retry %d/%d): %v",
					policy.Name, retryCount+1, maxStatusUpdateRetries, err)
				// Exponential backoff
				time.Sleep(time.Duration(retryCount+1) * 100 * time.Millisecond)
				continue
			}
			log.Errorf("Failed to update status for ClusterStackroxPolicy %s: %v", policy.Name, err)
			return
		}

		// Success!
		log.Infof("Updated ClusterStackroxPolicy %s status: Type=%s, Status=%s, Reason=%s, LocalID=%s",
			policy.Name, condition.Type, condition.Status, condition.Reason, localPolicyID)
		return
	}

	// Exhausted retries
	log.Errorf("Failed to update status for ClusterStackroxPolicy %s after %d retries due to conflicts",
		policy.Name, maxStatusUpdateRetries)
}

// storePolicyRef stores the CRD reference for a local policy ID
func (m *Manager) storePolicyRef(policyID string, ref *policyRef) {
	m.violationsMu.Lock()
	defer m.violationsMu.Unlock()
	m.policyRefs[policyID] = ref
}

// removePolicyRef removes the CRD reference for a local policy ID
func (m *Manager) removePolicyRef(policyID string) {
	m.violationsMu.Lock()
	defer m.violationsMu.Unlock()
	delete(m.policyRefs, policyID)
	delete(m.pendingViolations, policyID) // Also clear any pending violations
}

// flushViolationMetrics updates CRD status with accumulated violation metrics
func (m *Manager) flushViolationMetrics() {
	m.violationsMu.Lock()

	// Copy pending violations and clear them
	violations := make(map[string]*violationMetrics)
	for policyID, metrics := range m.pendingViolations {
		violations[policyID] = metrics
	}
	m.pendingViolations = make(map[string]*violationMetrics)

	// Copy policy refs for lookup
	refs := make(map[string]*policyRef)
	for policyID, ref := range m.policyRefs {
		refs[policyID] = ref
	}

	m.violationsMu.Unlock()

	if len(violations) == 0 {
		return
	}

	log.Debugf("Flushing violation metrics for %d policies", len(violations))

	ctx := context.Background()

	// Update each policy's CRD status
	for policyID, metrics := range violations {
		ref, exists := refs[policyID]
		if !exists {
			log.Warnf("No CRD reference found for policy %s, skipping metrics update", policyID)
			continue
		}

		if err := m.updateViolationMetrics(ctx, policyID, ref, metrics); err != nil {
			log.Errorf("Failed to update violation metrics for policy %s: %v", policyID, err)
		}
	}
}

// buildDeploymentViolationsMap merges existing and new per-deployment violations
// Returns a map of deploymentID -> violation data for easier manipulation
func (m *Manager) buildDeploymentViolationsMap(existingMetrics map[string]interface{},
	newMetrics *violationMetrics, isClusterScoped bool) map[string]map[string]interface{} {

	deploymentViolationsMap := make(map[string]map[string]interface{})

	// Start with existing deployment violations from CRD status
	if existingDeployments, ok := existingMetrics["deploymentViolations"].([]interface{}); ok {
		for _, deplInterface := range existingDeployments {
			if deplMap, ok := deplInterface.(map[string]interface{}); ok {
				// Extract deployment reference
				if deplRef, ok := deplMap["deploymentRef"].(map[string]interface{}); ok {
					name, _ := deplRef["name"].(string)
					namespace := ""
					if ns, ok := deplRef["namespace"].(string); ok {
						namespace = ns
					}

					// Create unique key (name for namespace-scoped, namespace/name for cluster-scoped)
					key := name
					if isClusterScoped && namespace != "" {
						key = namespace + "/" + name
					}

					deploymentViolationsMap[key] = deplMap
				}
			}
		}
	}

	// Merge new deployment violations
	for _, deplMetrics := range newMetrics.deploymentViolations {
		// Create unique key
		key := deplMetrics.deploymentName
		if isClusterScoped && deplMetrics.namespace != "" {
			key = deplMetrics.namespace + "/" + deplMetrics.deploymentName
		}

		existing, exists := deploymentViolationsMap[key]
		if exists {
			// Accumulate violation count
			existingCount := int32(0)
			if count, ok := existing["violationCount"].(int64); ok {
				existingCount = int32(count)
			}
			existing["violationCount"] = int64(existingCount + deplMetrics.violationCount)
			existing["lastTriggered"] = deplMetrics.lastViolationTime.Format(time.RFC3339)
		} else {
			// Create new entry
			deplRef := map[string]interface{}{
				"name": deplMetrics.deploymentName,
			}
			if isClusterScoped && deplMetrics.namespace != "" {
				deplRef["namespace"] = deplMetrics.namespace
			}

			deploymentViolationsMap[key] = map[string]interface{}{
				"deploymentRef":  deplRef,
				"violationCount": int64(deplMetrics.violationCount),
				"lastTriggered":  deplMetrics.lastViolationTime.Format(time.RFC3339),
			}
		}
	}

	return deploymentViolationsMap
}

// sortAndLimitDeploymentViolations converts map to sorted slice and enforces limit
// Returns deployments sorted by lastTriggered (most recent first), limited to maxDeploymentViolationsTracked
func (m *Manager) sortAndLimitDeploymentViolations(deploymentsMap map[string]map[string]interface{}) []interface{} {
	// Convert map to slice for sorting
	type deploymentEntry struct {
		key           string
		data          map[string]interface{}
		lastTriggered time.Time
	}

	entries := make([]deploymentEntry, 0, len(deploymentsMap))
	for key, data := range deploymentsMap {
		lastTriggered := time.Time{}
		if lastTriggeredStr, ok := data["lastTriggered"].(string); ok {
			if parsed, err := time.Parse(time.RFC3339, lastTriggeredStr); err == nil {
				lastTriggered = parsed
			}
		}

		entries = append(entries, deploymentEntry{
			key:           key,
			data:          data,
			lastTriggered: lastTriggered,
		})
	}

	// Sort by lastTriggered descending (most recent first)
	sort.Slice(entries, func(i, j int) bool {
		return entries[i].lastTriggered.After(entries[j].lastTriggered)
	})

	// Apply limit
	limit := maxDeploymentViolationsTracked
	if len(entries) > limit {
		log.Infof("Limiting deployment violations from %d to %d (keeping most recent)",
			len(entries), limit)
		entries = entries[:limit]
	}

	// Convert to []interface{} for unstructured
	result := make([]interface{}, len(entries))
	for i, entry := range entries {
		result[i] = entry.data
	}

	return result
}

// updateViolationMetrics updates a single policy's violation metrics in CRD status
// Retries on optimistic concurrency conflicts
func (m *Manager) updateViolationMetrics(ctx context.Context, policyID string, ref *policyRef, metrics *violationMetrics) error {
	var gvr schema.GroupVersionResource
	var namespace string

	if ref.isClusterScoped {
		gvr = clusterStackroxPolicyGVR
		namespace = "" // cluster-scoped
	} else {
		gvr = stackroxPolicyGVR
		namespace = ref.namespace
	}

	// Retry loop for optimistic concurrency conflicts
	for retryCount := 0; retryCount < maxStatusUpdateRetries; retryCount++ {
		// Fetch current policy to get latest resourceVersion
		var unstructuredObj *unstructured.Unstructured
		var err error

		if ref.isClusterScoped {
			unstructuredObj, err = m.dynamicClient.Resource(gvr).Get(ctx, ref.name, metav1.GetOptions{})
		} else {
			unstructuredObj, err = m.dynamicClient.Resource(gvr).Namespace(namespace).Get(ctx, ref.name, metav1.GetOptions{})
		}

		if err != nil {
			if k8serrors.IsNotFound(err) {
				log.Debugf("Policy %s/%s not found, possibly deleted", namespace, ref.name)
				return nil
			}
			return fmt.Errorf("failed to get policy %s/%s: %w", namespace, ref.name, err)
		}

		// Extract current status
		status, exists, err := unstructured.NestedMap(unstructuredObj.Object, "status")
		if err != nil {
			return fmt.Errorf("failed to get status: %w", err)
		}
		if !exists {
			status = make(map[string]interface{})
		}

		// Get existing violation metrics or create new
		existingMetrics, _, _ := unstructured.NestedMap(status, "violationMetrics")
		if existingMetrics == nil {
			existingMetrics = make(map[string]interface{})
		}

		// Accumulate aggregate metrics (add to existing counts)
		var totalViolations int32
		if existing, ok := existingMetrics["totalViolations"].(int64); ok {
			totalViolations = int32(existing)
		}
		totalViolations += metrics.totalViolations

		// Build per-deployment violations array
		deploymentViolationsMap := m.buildDeploymentViolationsMap(existingMetrics, metrics, ref.isClusterScoped)

		// Convert map to sorted slice (by last triggered, most recent first)
		deploymentViolations := m.sortAndLimitDeploymentViolations(deploymentViolationsMap)

		// Update violation metrics
		violationMetrics := map[string]interface{}{
			"totalViolations":      int64(totalViolations),
			"lastViolationTime":    metrics.lastViolationTime.Format(time.RFC3339),
			"deploymentViolations": deploymentViolations,
		}

		// Update status
		if err := unstructured.SetNestedMap(status, violationMetrics, "violationMetrics"); err != nil {
			return fmt.Errorf("failed to set violation metrics: %w", err)
		}

		if err := unstructured.SetNestedMap(unstructuredObj.Object, status, "status"); err != nil {
			return fmt.Errorf("failed to set status: %w", err)
		}

		// Try to update CRD status
		if ref.isClusterScoped {
			_, err = m.dynamicClient.Resource(gvr).UpdateStatus(ctx, unstructuredObj, metav1.UpdateOptions{})
		} else {
			_, err = m.dynamicClient.Resource(gvr).Namespace(namespace).UpdateStatus(ctx, unstructuredObj, metav1.UpdateOptions{})
		}

		if err != nil {
			if k8serrors.IsConflict(err) {
				log.Debugf("Conflict updating violation metrics for policy %s/%s (retry %d/%d): %v",
					namespace, ref.name, retryCount+1, maxStatusUpdateRetries, err)
				// Exponential backoff
				time.Sleep(time.Duration(retryCount+1) * 100 * time.Millisecond)
				continue
			}
			return fmt.Errorf("failed to update status: %w", err)
		}

		// Success!
		log.Infof("Updated violation metrics for policy %s (total: %d, new: %d, deployments: %d)",
			policyID, totalViolations, metrics.totalViolations, len(deploymentViolations))
		return nil
	}

	// Exhausted retries
	return fmt.Errorf("failed to update violation metrics for policy %s/%s after %d retries due to conflicts",
		namespace, ref.name, maxStatusUpdateRetries)
}
