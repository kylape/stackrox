package unified

import (
	"github.com/stackrox/rox/generated/internalapi/sensor"
	"github.com/stackrox/rox/generated/storage"
	"github.com/stackrox/rox/pkg/booleanpolicy"
	"github.com/stackrox/rox/pkg/booleanpolicy/augmentedobjs"
	"github.com/stackrox/rox/pkg/detection/deploytime"
	"github.com/stackrox/rox/pkg/detection/runtime"
	"github.com/stackrox/rox/pkg/kubernetes"
)

type detectorImpl struct {
	deploytimeDetector deploytime.Detector
	runtimeDetector    runtime.Detector
}

func (d *detectorImpl) ReconcilePolicies(newList []*storage.Policy) {
	reconcilePolicySets(newList, d.deploytimeDetector.PolicySet(), func(p *storage.Policy) bool {
		return isLifecycleStage(p, storage.LifecycleStage_DEPLOY)
	})
	reconcilePolicySets(newList, d.runtimeDetector.PolicySet(), func(p *storage.Policy) bool {
		return isLifecycleStage(p, storage.LifecycleStage_RUNTIME)
	})
}

func (d *detectorImpl) DetectDeployment(ctx deploytime.DetectionContext, enhancedDeployment booleanpolicy.EnhancedDeployment) []*storage.Alert {
	alerts, err := d.deploytimeDetector.Detect(ctx, enhancedDeployment)
	if err != nil {
		log.Errorf("Error running detection on deployment %q: %v", enhancedDeployment.Deployment.GetName(), err)
	}
	return alerts
}

func (d *detectorImpl) DetectProcess(enhancedDeployment booleanpolicy.EnhancedDeployment, process *storage.ProcessIndicator, processNotInBaseline bool) []*storage.Alert {
	alerts, err := d.runtimeDetector.DetectForDeploymentAndProcess(enhancedDeployment, process, processNotInBaseline)
	if err != nil {
		log.Errorf("Error running runtime policies for deployment %q and process %q: %v", enhancedDeployment.Deployment.GetName(), process.GetSignal().GetExecFilePath(), err)
	}
	return alerts
}

func (d *detectorImpl) DetectKubeEventForDeployment(enhancedDeployment booleanpolicy.EnhancedDeployment, kubeEvent *storage.KubernetesEvent) []*storage.Alert {
	alerts, err := d.runtimeDetector.DetectForDeploymentAndKubeEvent(enhancedDeployment, kubeEvent)
	if err != nil {
		log.Errorf("Error running runtime policies for kubernetes event %s: %v", kubernetes.EventAsString(kubeEvent), err)
	}
	return alerts
}

func (d *detectorImpl) DetectNetworkFlowForDeployment(
	enhancedDeployment booleanpolicy.EnhancedDeployment,
	flow *augmentedobjs.NetworkFlowDetails,
) []*storage.Alert {
	alerts, err := d.runtimeDetector.DetectForDeploymentAndNetworkFlow(enhancedDeployment, flow)
	if err != nil {
		log.Errorf("Error running runtime policies for network flow %v: %v", flow, err)
	}
	return alerts
}

func (d *detectorImpl) DetectAuditLogEvents(auditEvents *sensor.AuditEvents) []*storage.Alert {
	alerts, err := d.runtimeDetector.DetectForAuditEvents(auditEvents.GetEvents())
	if err != nil {
		log.Errorf("Error evaluating runtime policies for audit events: %q", err)
		return nil
	}
	return alerts
}

// UpsertPolicy adds or updates a single policy in the appropriate detector(s)
func (d *detectorImpl) UpsertPolicy(policy *storage.Policy) error {
	var errs []error

	// Add to runtime detector if policy has RUNTIME lifecycle stage
	if isLifecycleStage(policy, storage.LifecycleStage_RUNTIME) {
		if err := d.runtimeDetector.PolicySet().UpsertPolicy(policy); err != nil {
			errs = append(errs, err)
			log.Errorf("Failed to upsert policy %s to runtime detector: %v", policy.GetId(), err)
		} else {
			log.Debugf("Upserted policy %s to runtime detector", policy.GetId())
		}
	}

	// Add to deploy detector if policy has DEPLOY lifecycle stage
	if isLifecycleStage(policy, storage.LifecycleStage_DEPLOY) {
		if err := d.deploytimeDetector.PolicySet().UpsertPolicy(policy); err != nil {
			errs = append(errs, err)
			log.Errorf("Failed to upsert policy %s to deploy detector: %v", policy.GetId(), err)
		} else {
			log.Debugf("Upserted policy %s to deploy detector", policy.GetId())
		}
	}

	if len(errs) > 0 {
		return errs[0] // Return first error
	}
	return nil
}

// RemovePolicy removes a policy from both detectors
func (d *detectorImpl) RemovePolicy(policyID string) {
	log.Debugf("Removing policy %s from both runtime and deploy detectors", policyID)
	d.runtimeDetector.PolicySet().RemovePolicy(policyID)
	d.deploytimeDetector.PolicySet().RemovePolicy(policyID)
}
