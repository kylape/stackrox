# Policy-as-Code Implementation Status

## Overview

This document tracks the implementation status of the policy-as-code feature, which enables
StackRox to evaluate security policies defined as Kubernetes Custom Resources locally in
secured clusters.

**Branch**: `feature/policy-as-code-v3-phase1`
**Last Updated**: 2025-11-06

## Feature Summary

Enable administrators to define StackRox security policies as Kubernetes Custom Resources (CRDs)
that are evaluated locally by sensor and admission-control, without being sent to Central.

### Key Components

1. **StackroxPolicy** - Namespace-scoped policy CRD
2. **ClusterStackroxPolicy** - Cluster-scoped policy CRD
3. **Local Policy Informers** - Watch CRDs and load into evaluation engines
4. **Conversion Logic** - Convert CRD format to storage.Policy
5. **Status Tracking** - Report acceptance/errors back to CRD status

## Implementation Progress

### ✅ Phase 1: Foundation (COMPLETED)

#### CRD Definitions
- [x] Common API types (`pkg/apis/common/v1/policy_spec.go`)
  - PolicySections, Scopes, Exclusions, LabelSelectors
  - EventSource, EnforcementActions, MITRE ATT&CK
  - Protobuf-compatible types

- [x] StackroxPolicy CRD (`apis/policy.stackrox.io/v1alpha1/stackroxpolicy_types.go`)
  - Namespace-scoped policy definition
  - Supports DEPLOY and RUNTIME lifecycle stages
  - Status conditions: AcceptedBySensor, AcceptedByAdmissionControl

- [x] ClusterStackroxPolicy CRD (`apis/policy.stackrox.io/v1alpha1/clusterstackroxpolicy_types.go`)
  - Cluster-scoped policy definition
  - Same spec as StackroxPolicy but no namespace field

- [x] Generated CRD manifests
  - `config/crd/bases/policy.stackrox.io_stackroxpolicies.yaml`
  - `config/crd/bases/policy.stackrox.io_clusterstackroxpolicies.yaml`
  - Generated with controller-gen
  - Includes OpenAPI validation schemas

#### Conversion Logic
- [x] CRD to storage.Policy conversion (`apis/policy.stackrox.io/v1alpha1/conversion.go`)
  - Converts StackroxPolicySpec → storage.Policy protobuf
  - Generates deterministic local policy IDs (SHA256 hash of namespace/name)
  - Marks policies with `PolicySource_LOCAL`
  - Handles scope/exclusion conversions with label selectors
  - Function: `ToStoragePolicy(spec, namespace, name, isClusterScoped)`

#### Status Management
- [x] Condition types and helpers (`apis/policy.stackrox.io/v1alpha1/conditions.go`)
  - `ConditionAcceptedBySensor` - Runtime policy acceptance
  - `ConditionAcceptedByAdmissionControl` - Deploy-time policy acceptance
  - Helper functions:
    - `ShouldApplyToSensor(spec)` - Check for RUNTIME lifecycle
    - `ShouldApplyToAdmissionControl(spec)` - Check for DEPLOY lifecycle
    - `NewCondition()` - Create condition with timestamp
    - `SetCondition()` - Update condition list
  - Reason codes: PolicyLoaded, NotApplicable, ConversionError, InternalError

#### Informers
- [x] Sensor informer (`sensor/kubernetes/localpolicy/informer.go`)
  - Uses dynamic client (no typed client generation needed)
  - Watches StackroxPolicy and ClusterStackroxPolicy CRDs
  - Filters for RUNTIME lifecycle stage
  - Event handlers: Add, Update, Delete with tombstone handling
  - Converts unstructured → typed → storage.Policy
  - Status update helpers (currently log-only)
  - 564 lines of code

- [x] Admission-control informer (`sensor/admission-control/localpolicy/informer.go`)
  - Same structure as sensor informer
  - Filters for DEPLOY lifecycle stage
  - Updates AcceptedByAdmissionControl condition
  - 564 lines of code

#### Integration
- [x] Wired into sensor main (`sensor/kubernetes/main.go`)
  - Creates manager with dynamic client at line 109
  - Starts informers at line 115 after sensor.Start()
  - Stops informers during shutdown (lines 125, 132)
  - Non-fatal initialization

- [x] Wired into admission-control main (`sensor/admission-control/main.go`)
  - Creates in-cluster config and dynamic client at line 94
  - Starts informers at line 103 after manager.Start()
  - Stops informers in all shutdown paths (lines 155-179)
  - Graceful handling of initialization failures

### ⏳ Phase 2: Policy Evaluation Integration (PENDING)

#### Sensor Runtime Evaluation
- [ ] Locate sensor's runtime policy evaluator
  - Find detector that evaluates process/network/audit events
  - Understand the policy loading/unloading API

- [ ] Integrate informer with evaluator
  - Implement `loadPolicyIntoEvaluator(policy *storage.Policy)`
  - Implement `removePolicyFromEvaluator(policyID string)`
  - Handle policy updates (remove old + add new)

- [ ] Test runtime policy evaluation
  - Deploy test StackroxPolicy with RUNTIME stage
  - Verify it triggers on process/network events
  - Verify alerts are generated

#### Admission Control Deploy-time Evaluation
- [ ] Locate admission-control's policy evaluator
  - Find deploy-time detector that evaluates admission requests
  - Understand the policy loading/unloading API

- [ ] Integrate informer with evaluator
  - Implement `loadPolicyIntoEvaluator(policy *storage.Policy)`
  - Implement `removePolicyFromEvaluator(policyID string)`
  - Handle policy updates

- [ ] Test deploy-time policy evaluation
  - Deploy test StackroxPolicy with DEPLOY stage
  - Verify it triggers on deployment admission requests
  - Verify enforcement actions work

### ⏳ Phase 3: Status Updates (PENDING)

#### Status Subresource Updates
- [ ] Implement status updates with dynamic client
  - Uncomment status update code in informers
  - Use `dynamicClient.Resource(gvr).UpdateStatus()`
  - Convert typed → unstructured for update

- [ ] Add retry logic with exponential backoff
  - Handle conflict errors (optimistic locking)
  - Retry up to N times
  - Log persistent failures

- [ ] Test status updates
  - Verify AcceptedBySensor condition is set
  - Verify AcceptedByAdmissionControl condition is set
  - Verify LocalPolicyID and LastEvaluated are populated
  - Verify error conditions work (ConversionError, InternalError)

### ⏳ Phase 4: Testing (PENDING)

#### Unit Tests
- [ ] Conversion logic tests
  - Test `ToStoragePolicy()` with various inputs
  - Test local policy ID generation
  - Test lifecycle stage conversion
  - Test scope/exclusion conversion

- [ ] Informer tests
  - Mock dynamic informer
  - Test event handlers (Add, Update, Delete)
  - Test lifecycle filtering
  - Test tombstone handling
  - Test status update logic

#### Integration Tests
- [ ] End-to-end CRD tests
  - Deploy StackroxPolicy CRD
  - Verify informer picks it up
  - Verify conversion succeeds
  - Verify policy is loaded
  - Verify status is updated

- [ ] Multi-lifecycle tests
  - Deploy policy with both DEPLOY and RUNTIME stages
  - Verify both sensor and admission-control pick it up
  - Verify both set their respective conditions

#### E2E Tests
- [ ] Runtime policy evaluation test
  - Deploy policy that detects specific process
  - Trigger the process
  - Verify alert is generated

- [ ] Deploy-time policy evaluation test
  - Deploy policy that blocks privileged containers
  - Attempt to deploy privileged pod
  - Verify it's blocked

## File Structure

```
apis/policy.stackrox.io/v1alpha1/
├── groupversion_info.go             # API group registration
├── stackroxpolicy_types.go          # StackroxPolicy CRD (144 lines)
├── clusterstackroxpolicy_types.go   # ClusterStackroxPolicy CRD (75 lines)
├── conditions.go                    # Status helpers (175 lines)
├── conversion.go                    # CRD → storage.Policy (332 lines)
└── zz_generated.deepcopy.go         # Generated deepcopy (323 lines)

pkg/apis/common/v1/
├── doc.go                           # Package documentation
└── policy_spec.go                   # Shared policy types (168 lines)

config/crd/bases/
├── policy.stackrox.io_stackroxpolicies.yaml          # StackroxPolicy CRD manifest (613 lines)
└── policy.stackrox.io_clusterstackroxpolicies.yaml   # ClusterStackroxPolicy CRD manifest (611 lines)

sensor/kubernetes/localpolicy/
└── informer.go                      # Sensor runtime informer (564 lines)

sensor/admission-control/localpolicy/
└── informer.go                      # Admission-control informer (564 lines)
```

## Protobuf Changes

### Modified Files
- `proto/storage/policy.proto` - Added `PolicySource_LOCAL` enum value
- `proto/storage/scope.proto` - Added label selector support for scopes
- `generated/storage/policy.pb.go` - Generated protobuf code
- `generated/storage/scope.pb.go` - Generated protobuf code
- `generated/storage/scope_vtproto.pb.go` - Generated vtproto code

### Swagger/OpenAPI Updates
- `generated/api/v1/alert_service.swagger.json` - Updated with policy source
- `generated/api/v1/policy_service.swagger.json` - Updated with policy source
- `generated/api/v1/detection_service.swagger.json` - Updated schemas

## Commits

1. `e2eb016e37` - Add common types for secured cluster policies
2. `743b79834e` - Add StackroxPolicy and ClusterStackroxPolicy CRDs
3. `ad9155c0f5` - Add protobuf support for local policies and label selectors
4. `910733351c` - Fix: Use existing LabelSelector from labels.proto
5. `686b1a042e` - Generate CRD manifests, deepcopy, and protobuf code
6. `c701c63d8b` - Add conversion from CRD to sensor policy format
7. `f2d88110ef` - Add status conditions and helpers
8. `e6eb0c243c` - Add informer skeletons for sensor and admission-control
9. `d6a38f0d14` - Update informers to use dynamic client
10. `2f4dae0d75` - Wire up informers in sensor and admission-control

## Next Steps (Priority Order)

1. **Integrate with Policy Evaluators** - Most critical
   - Find sensor's runtime detector
   - Find admission-control's deploy detector
   - Implement load/unload policy methods

2. **Enable Status Updates** - Important for user feedback
   - Uncomment status update code
   - Add retry logic
   - Test status conditions

3. **Add Unit Tests** - Critical for maintainability
   - Conversion logic tests
   - Informer event handler tests

4. **Add Integration Tests** - Critical for reliability
   - CRD lifecycle tests
   - Policy evaluation tests

5. **Documentation** - Important for users
   - User guide for creating policies
   - Examples of common policies
   - Troubleshooting guide

## Known Limitations

1. **No Typed Client** - Using dynamic client for now
   - Works fine but less type-safe
   - Can generate typed client later if needed

2. **Status Updates Disabled** - Currently log-only
   - Easy to enable once tested
   - Need to validate update permissions

3. **No Policy Evaluation** - Informers work but policies aren't evaluated yet
   - Requires integration with detector components
   - Next major milestone

4. **No Tests** - Implementation complete but untested
   - Need unit tests for conversion
   - Need integration tests for informers
   - Need E2E tests for policy evaluation

## Design Decisions

### Why Dynamic Client?
- **Faster iteration**: No code generation needed
- **Simpler**: Works immediately without generated clientsets
- **Good enough**: Type safety comes from conversion to typed structs
- **Can upgrade later**: Easy to add typed clients if needed

### Why Separate Informers?
- **Different lifecycle stages**: Sensor watches RUNTIME, admission-control watches DEPLOY
- **Different conditions**: Each sets its own status condition
- **Clean separation**: Easier to understand and test

### Why Local Policy IDs?
- **Deterministic**: SHA256(namespace + name + clusterScoped)
- **No Central dependency**: Can generate without Central API
- **Conflict-free**: Different namespaces get different IDs

### Why Non-Fatal Initialization?
- **Graceful degradation**: Sensor/admission-control work without local policies
- **Easier debugging**: System starts even if CRDs aren't installed
- **Better UX**: Don't block critical functionality

## References

- [Kubernetes Custom Resources](https://kubernetes.io/docs/concepts/extend-kubernetes/api-extension/custom-resources/)
- [Controller-runtime](https://book.kubebuilder.io/)
- [Dynamic Client](https://pkg.go.dev/k8s.io/client-go/dynamic)
- [StackRox Policy Engine](sensor/common/detector/)
