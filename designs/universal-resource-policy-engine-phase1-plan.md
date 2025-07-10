# Universal Resource Policy Engine - Phase 1 Implementation Plan

## Overview

This document provides a detailed implementation plan for **Phase 1: Foundation** of the Universal Resource Policy Engine. Phase 1 establishes the core infrastructure needed to support policies on any Kubernetes resource, not just deployments.

**Duration**: 2-3 months  
**Goal**: Enable policy evaluation on any Kubernetes resource while maintaining backward compatibility

## Phase 1 Scope

### In Scope
- Extend policy protobuf with ResourceTarget
- Create universal AugmentedResource interface
- Implement generic resource augmentation
- Add "Kubernetes Field" criteria type
- Create GenericResourceDetector
- Update admission controller to process all resources
- Extend storage for non-deployment alerts

### Out of Scope (Future Phases)
- Specialized resource augmenters (ConfigMap, Service specific logic)
- Complex relationship discovery
- JSONPath support
- Cross-resource policies
- UI changes (Phase 4)

## Detailed Work Breakdown

### Work Package 1: Protobuf Schema Changes (Week 1-2)

#### 1.1 Extend Policy Protobuf
**File**: `proto/storage/policy.proto`

```protobuf
message Policy {
  // Existing fields...
  string id = 1;
  string name = 2;
  repeated LifecycleStage lifecycle_stages = 9;
  repeated PolicySection policy_sections = 20;
  
  // NEW: Specify what type of resource this policy evaluates
  ResourceTarget resource_target = 23;
}

message ResourceTarget {
  oneof target {
    DeploymentTarget deployment = 1;  // Backward compatible (default)
    KubernetesResourceTarget kubernetes = 2;  // NEW
  }
}

message KubernetesResourceTarget {
  string api_version = 1;  // "v1", "networking.k8s.io/v1", etc.
  string kind = 2;         // "ConfigMap", "Service", "Ingress", etc.
  
  // Optional: limit to specific namespaces (empty = all namespaces)
  repeated string namespaces = 3;
}

message DeploymentTarget {
  // Empty for now, allows future deployment-specific options
}
```

#### 1.2 Extend Alert Protobuf
**File**: `proto/storage/alert.proto`

```protobuf
message Alert {
  // Existing fields...
  string id = 1;
  Policy policy = 4;
  
  // Change from deployment_id to resource reference
  oneof entity {
    string deployment_id = 13 [deprecated = true];  // Backward compatibility
    ResourceReference resource = 50;  // NEW
  }
}

message ResourceReference {
  string api_version = 1;
  string kind = 2;
  string namespace = 3;
  string name = 4;
  string uid = 5;
}
```

**Tasks**:
- [ ] Update protobuf definitions
- [ ] Run `make proto-generated-srcs` to generate Go code
- [ ] Update any direct protobuf field access to use getters
- [ ] Add migration logic for existing policies (default to DeploymentTarget)

**Dependencies**: None  
**Risk**: Breaking changes to existing policies  
**Mitigation**: Default ResourceTarget to deployment, extensive backward compatibility testing

#### 1.3 Add Dynamic Field Criteria
**File**: `proto/storage/policy.proto`

```protobuf
message PolicyValue {
  oneof value {
    string value = 1;                    // Existing
    DynamicFieldValue dynamic = 2;       // NEW
  }
}

message DynamicFieldValue {
  string field_path = 1;        // "spec.type", "metadata.annotations['key']"
  string operator = 2;          // "equals", "contains", "exists", ">", "regex_match"
  repeated string values = 3;   // Values to match against
}
```

**Tasks**:
- [ ] Define DynamicFieldValue message
- [ ] Update PolicyGroup validation logic
- [ ] Add new field name "Kubernetes Field" to fieldnames/list.go
- [ ] Test protobuf generation and validation

### Work Package 2: Universal Context Model (Week 2-4)

#### 2.1 Create AugmentedResource Interface
**File**: `pkg/booleanpolicy/augmentedobjs/augmented_resource.go`

```go
package augmentedobjs

import (
    "k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

// AugmentedResource is the universal interface for policy evaluation context
type AugmentedResource interface {
    GetResource() *unstructured.Unstructured
    GetRelatedResources() map[string][]*unstructured.Unstructured
    GetKind() string
    GetAPIVersion() string
    GetNamespace() string
    GetName() string
    
    // Dynamic field access for generic evaluation
    GetField(path string) (interface{}, bool, error)
    SetField(path string, value interface{}) error
    
    // Metadata for evaluation context
    GetAugmentationTimestamp() time.Time
    GetClusterID() string
}

// Generic implementation for any Kubernetes resource
type GenericAugmentedResource struct {
    Resource    *unstructured.Unstructured
    Related     map[string][]*unstructured.Unstructured
    ClusterID   string
    Timestamp   time.Time
}

func (gar *GenericAugmentedResource) GetResource() *unstructured.Unstructured {
    return gar.Resource
}

func (gar *GenericAugmentedResource) GetRelatedResources() map[string][]*unstructured.Unstructured {
    return gar.Related
}

func (gar *GenericAugmentedResource) GetKind() string {
    return gar.Resource.GetKind()
}

func (gar *GenericAugmentedResource) GetAPIVersion() string {
    return gar.Resource.GetAPIVersion()
}

func (gar *GenericAugmentedResource) GetNamespace() string {
    return gar.Resource.GetNamespace()
}

func (gar *GenericAugmentedResource) GetName() string {
    return gar.Resource.GetName()
}

func (gar *GenericAugmentedResource) GetField(path string) (interface{}, bool, error) {
    return unstructured.NestedFieldCopy(gar.Resource.Object, 
                                       strings.Split(path, ".")...)
}

func (gar *GenericAugmentedResource) SetField(path string, value interface{}) error {
    return unstructured.SetNestedField(gar.Resource.Object, value,
                                      strings.Split(path, ".")...)
}

func (gar *GenericAugmentedResource) GetAugmentationTimestamp() time.Time {
    return gar.Timestamp
}

func (gar *GenericAugmentedResource) GetClusterID() string {
    return gar.ClusterID
}
```

**Tasks**:
- [ ] Define AugmentedResource interface
- [ ] Implement GenericAugmentedResource
- [ ] Add field path utilities (dot notation parsing)
- [ ] Add comprehensive unit tests
- [ ] Update existing EnhancedDeployment to implement interface

#### 2.2 Resource Augmentation Factory
**File**: `pkg/booleanpolicy/augmentedobjs/factory.go`

```go
type ResourceAugmentationFactory struct {
    k8sClient     kubernetes.Interface
    clusterID     string
    
    // Strategy pattern for different resource types
    strategies    map[string]AugmentationStrategy
}

type AugmentationStrategy interface {
    Augment(ctx context.Context, resource *unstructured.Unstructured) (AugmentedResource, error)
    SupportsKind(kind string) bool
}

// Generic strategy that works for any resource
type GenericAugmentationStrategy struct {
    client kubernetes.Interface
}

func (gas *GenericAugmentationStrategy) Augment(ctx context.Context, 
                                               resource *unstructured.Unstructured) (AugmentedResource, error) {
    // For Phase 1, minimal augmentation
    // Just wrap the resource with basic metadata
    return &GenericAugmentedResource{
        Resource:  resource.DeepCopy(),
        Related:   make(map[string][]*unstructured.Unstructured),
        ClusterID: gas.clusterID,
        Timestamp: time.Now(),
    }, nil
}

func (gas *GenericAugmentationStrategy) SupportsKind(kind string) bool {
    return true // Generic strategy supports everything
}

func (raf *ResourceAugmentationFactory) AugmentResource(ctx context.Context,
                                                       resource *unstructured.Unstructured) (AugmentedResource, error) {
    kind := resource.GetKind()
    
    // Use specific strategy if available, otherwise generic
    if strategy, exists := raf.strategies[kind]; exists {
        return strategy.Augment(ctx, resource)
    }
    
    // Fall back to generic strategy
    generic := &GenericAugmentationStrategy{client: raf.k8sClient}
    return generic.Augment(ctx, resource)
}
```

**Tasks**:
- [ ] Create augmentation factory interface
- [ ] Implement generic augmentation strategy
- [ ] Add strategy registration mechanism
- [ ] Create backward compatibility adapter for DeploymentMeta
- [ ] Add integration tests

### Work Package 3: Dynamic Field Evaluation (Week 3-5)

#### 3.1 Dynamic Field Query Builder
**File**: `pkg/booleanpolicy/querybuilders/dynamic_field.go`

```go
type DynamicFieldQueryBuilder struct {
    fieldPath string
}

func ForDynamicField(fieldPath string) *DynamicFieldQueryBuilder {
    return &DynamicFieldQueryBuilder{fieldPath: fieldPath}
}

func (qb *DynamicFieldQueryBuilder) FieldQueriesForGroup(group *storage.PolicyGroup) []*query.FieldQuery {
    var fieldQueries []*query.FieldQuery
    
    for _, value := range group.GetValues() {
        if dynamicValue := value.GetDynamic(); dynamicValue != nil {
            fq := &query.FieldQuery{
                Field:    fmt.Sprintf("dynamic.%s", dynamicValue.GetFieldPath()),
                Values:   dynamicValue.GetValues(),
                Operator: group.GetBooleanOperator(),
                Negate:   group.GetNegate(),
                
                // Store metadata for evaluation
                Metadata: map[string]string{
                    "operator":   dynamicValue.GetOperator(),
                    "fieldPath":  dynamicValue.GetFieldPath(),
                },
            }
            fieldQueries = append(fieldQueries, fq)
        }
    }
    
    return fieldQueries
}
```

**Tasks**:
- [ ] Create dynamic field query builder
- [ ] Add field metadata registration for "Kubernetes Field"
- [ ] Implement dynamic field evaluation logic
- [ ] Add operator support (equals, contains, exists, regex, comparisons)
- [ ] Create comprehensive test suite

#### 3.2 Dynamic Field Evaluator
**File**: `pkg/booleanpolicy/evaluator/dynamic_field_evaluator.go`

```go
type DynamicFieldEvaluator struct {
    fieldPath string
    operator  string
    values    []string
    negate    bool
}

func (dfe *DynamicFieldEvaluator) Evaluate(resource AugmentedResource) (*Result, bool) {
    value, found, err := resource.GetField(dfe.fieldPath)
    if err != nil {
        log.Warnf("Error accessing field %s: %v", dfe.fieldPath, err)
        return nil, false
    }
    
    matched := dfe.evaluateValue(value, found)
    if dfe.negate {
        matched = !matched
    }
    
    if matched {
        return &Result{
            Matches: map[string][]pathutil.PathAndValueHolder{
                dfe.fieldPath: {
                    {
                        Path:  dfe.fieldPath,
                        Value: value,
                    },
                },
            },
        }, true
    }
    
    return nil, false
}

func (dfe *DynamicFieldEvaluator) evaluateValue(value interface{}, found bool) bool {
    switch dfe.operator {
    case "exists":
        return found
    case "equals":
        return found && dfe.stringMatches(fmt.Sprintf("%v", value))
    case "contains":
        return found && dfe.stringContains(fmt.Sprintf("%v", value))
    case "regex_match":
        return found && dfe.regexMatches(fmt.Sprintf("%v", value))
    case ">", "<", ">=", "<=":
        return found && dfe.numericCompare(value)
    default:
        log.Warnf("Unknown operator: %s", dfe.operator)
        return false
    }
}
```

**Tasks**:
- [ ] Implement dynamic field evaluator
- [ ] Add support for all operators
- [ ] Handle type conversions (string, numeric, boolean)
- [ ] Add error handling for invalid field paths
- [ ] Create unit tests for each operator

### Work Package 4: Generic Detection Engine (Week 4-6)

#### 4.1 Resource-Agnostic Policy Compiler
**File**: `pkg/detection/policy_compiler_universal.go`

```go
type UniversalPolicyCompiler struct {
    fieldMetadata *booleanpolicy.FieldMetadata
}

func (upc *UniversalPolicyCompiler) CompilePolicy(policy *storage.Policy) (CompiledPolicy, error) {
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

func (upc *UniversalPolicyCompiler) compileKubernetesResourcePolicy(policy *storage.Policy,
                                                                   target *storage.KubernetesResourceTarget) (CompiledPolicy, error) {
    compiled := &universalCompiledPolicy{
        policy:      policy,
        targetKind:  target.GetKind(),
        targetAPI:   target.GetApiVersion(),
        namespaces:  target.GetNamespaces(),
    }
    
    // Compile policy sections using dynamic field support
    for _, section := range policy.GetPolicySections() {
        sectionCompiler := &UniversalSectionCompiler{
            fieldMetadata: upc.fieldMetadata,
            targetKind:    target.GetKind(),
        }
        
        compiledSection, err := sectionCompiler.Compile(section)
        if err != nil {
            return nil, errors.Wrapf(err, "compiling section %s", section.GetSectionName())
        }
        
        compiled.sections = append(compiled.sections, compiledSection)
    }
    
    return compiled, nil
}
```

**Tasks**:
- [ ] Create universal policy compiler
- [ ] Update existing deployment compiler for backward compatibility
- [ ] Add resource type validation
- [ ] Implement section compilation for dynamic fields
- [ ] Add comprehensive testing

#### 4.2 Generic Resource Detector
**File**: `pkg/detection/detectors/generic_resource_detector.go`

```go
type GenericResourceDetector struct {
    policyEvaluator PolicyEvaluator
    augmentFactory  *augmentedobjs.ResourceAugmentationFactory
}

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
    violations, matched := grd.policyEvaluator.Evaluate(augmented, policy)
    if !matched {
        return nil, nil
    }
    
    // Create alert
    alert := &storage.Alert{
        Id:       uuid.NewV4().String(),
        Policy:   policy,
        Resource: &storage.ResourceReference{
            ApiVersion: resource.GetAPIVersion(),
            Kind:       resource.GetKind(),
            Namespace:  resource.GetNamespace(),
            Name:       resource.GetName(),
            Uid:        string(resource.GetUID()),
        },
        Time:     protocompat.TimestampNow(),
        State:    storage.ViolationState_ACTIVE,
        Severity: policy.GetSeverity(),
    }
    
    // Build violation message from policy sections
    alert.ViolationMessage = grd.buildViolationMessage(violations, policy)
    
    return alert, nil
}

func (grd *GenericResourceDetector) policyAppliesToResource(policy *storage.Policy,
                                                           resource *unstructured.Unstructured) bool {
    target := policy.GetResourceTarget()
    if target == nil {
        // Legacy policy without target - only applies to deployments
        return isDeploymentLikeResource(resource)
    }
    
    switch t := target.GetTarget().(type) {
    case *storage.ResourceTarget_Deployment:
        return isDeploymentLikeResource(resource)
    case *storage.ResourceTarget_Kubernetes:
        return t.Kubernetes.GetKind() == resource.GetKind() &&
               t.Kubernetes.GetApiVersion() == resource.GetAPIVersion() &&
               grd.namespaceMatches(t.Kubernetes.GetNamespaces(), resource.GetNamespace())
    default:
        return false
    }
}

func isDeploymentLikeResource(resource *unstructured.Unstructured) bool {
    kind := resource.GetKind()
    return kind == "Deployment" || kind == "StatefulSet" || kind == "DaemonSet" ||
           kind == "ReplicaSet" || kind == "Pod" || kind == "Job" || kind == "CronJob"
}
```

**Tasks**:
- [ ] Implement generic resource detector
- [ ] Add resource type matching logic
- [ ] Create violation message builder
- [ ] Add namespace filtering support
- [ ] Integrate with existing detection pipeline

### Work Package 5: Admission Controller Extension (Week 5-7)

#### 5.1 Universal Resource Processing
**File**: `sensor/admission-control/manager/manager.go`

```go
func (m *Manager) ProcessRequest(req *admission.AdmissionRequest) (*admission.AdmissionResponse, error) {
    // Parse any Kubernetes object (remove resource type filtering)
    obj, err := m.unmarshalK8sObject(req)
    if err != nil {
        return nil, err
    }
    
    // Get policies that target this resource type
    policies := m.policySet.GetPoliciesForResource(obj.GetKind(), obj.GetAPIVersion())
    
    // Skip if no policies target this resource
    if len(policies) == 0 {
        log.Debugf("No policies target %s/%s, allowing", obj.GetKind(), obj.GetName())
        return m.allow(), nil
    }
    
    log.Infof("Evaluating %d policies for %s/%s", len(policies), obj.GetKind(), obj.GetName())
    
    // Evaluate policies using appropriate detector
    var violations []*storage.Alert
    for _, policy := range policies {
        detector := m.createDetectorForPolicy(policy)
        
        if alert, err := detector.DetectViolation(ctx, obj, policy); err != nil {
            log.Errorf("Error detecting policy %s: %v", policy.GetName(), err)
        } else if alert != nil {
            violations = append(violations, alert)
        }
    }
    
    return m.buildAdmissionResponse(violations, req)
}

func (m *Manager) createDetectorForPolicy(policy *storage.Policy) ResourceDetector {
    target := policy.GetResourceTarget()
    
    if target == nil || target.GetDeployment() != nil {
        // Legacy deployment policy or explicit deployment target
        return m.deploymentDetector
    } else if target.GetKubernetes() != nil {
        // Generic Kubernetes resource policy
        return m.genericDetector
    }
    
    // Fallback
    return m.genericDetector
}
```

**Tasks**:
- [ ] Remove resource type filtering from admission controller
- [ ] Add policy-to-resource matching logic
- [ ] Update request processing pipeline
- [ ] Integrate generic detector
- [ ] Add extensive integration tests

#### 5.2 Policy Set Extension
**File**: `central/detection/policy_set.go`

```go
type PolicySet interface {
    // Existing methods...
    GetCompiledPolicies() []CompiledPolicy
    
    // NEW: Get policies that apply to specific resource types
    GetPoliciesForResource(kind, apiVersion string) []*storage.Policy
    GetPoliciesForResourceInNamespace(kind, apiVersion, namespace string) []*storage.Policy
}

func (ps *policySetImpl) GetPoliciesForResource(kind, apiVersion string) []*storage.Policy {
    ps.mutex.RLock()
    defer ps.mutex.RUnlock()
    
    var policies []*storage.Policy
    
    for _, policy := range ps.policies {
        if ps.policyAppliesToResource(policy, kind, apiVersion) {
            policies = append(policies, policy)
        }
    }
    
    return policies
}

func (ps *policySetImpl) policyAppliesToResource(policy *storage.Policy, kind, apiVersion string) bool {
    target := policy.GetResourceTarget()
    
    if target == nil {
        // Legacy policy - only applies to deployment-like resources
        return isDeploymentLikeKind(kind)
    }
    
    switch t := target.GetTarget().(type) {
    case *storage.ResourceTarget_Deployment:
        return isDeploymentLikeKind(kind)
    case *storage.ResourceTarget_Kubernetes:
        return t.Kubernetes.GetKind() == kind && 
               (t.Kubernetes.GetApiVersion() == "" || t.Kubernetes.GetApiVersion() == apiVersion)
    default:
        return false
    }
}
```

**Tasks**:
- [ ] Extend PolicySet interface
- [ ] Add resource filtering methods
- [ ] Update policy compilation pipeline
- [ ] Add caching for performance
- [ ] Create comprehensive test suite

### Work Package 6: Storage and API Updates (Week 6-8)

#### 6.1 Alert Storage Migration
**File**: `central/alert/datastore/datastore_impl.go`

```go
func (ds *datastoreImpl) UpsertAlert(ctx context.Context, alert *storage.Alert) error {
    // Handle both legacy deployment_id and new resource reference
    if alert.GetDeploymentId() != "" && alert.GetResource() == nil {
        // Migrate legacy alerts to new format
        deployment, exists, err := ds.deployments.GetDeployment(ctx, alert.GetDeploymentId())
        if err != nil {
            return err
        }
        if exists {
            alert.Resource = &storage.ResourceReference{
                ApiVersion: "apps/v1",
                Kind:       "Deployment",
                Namespace:  deployment.GetNamespace(),
                Name:       deployment.GetName(),
                Uid:        deployment.GetId(),
            }
        }
    }
    
    return ds.storage.Upsert(ctx, alert)
}

func (ds *datastoreImpl) GetAlertsForResource(ctx context.Context, 
                                            resource *storage.ResourceReference) ([]*storage.Alert, error) {
    // New method to get alerts for any resource type
    query := search.NewQueryBuilder().
        AddExactMatches(search.ResourceKind, resource.GetKind()).
        AddExactMatches(search.ResourceName, resource.GetName()).
        AddExactMatches(search.Namespace, resource.GetNamespace()).
        ProtoQuery()
    
    return ds.SearchRawAlerts(ctx, query)
}
```

**Tasks**:
- [ ] Add migration logic for existing alerts
- [ ] Create new query methods for resource-based lookups
- [ ] Update search indexing for new fields
- [ ] Add backward compatibility preservation
- [ ] Performance testing for new queries

#### 6.2 Central API Extensions
**File**: `central/alert/service/service_impl.go`

```go
func (s *serviceImpl) GetAlertsForResource(ctx context.Context, 
                                          req *v1.GetAlertsForResourceRequest) (*v1.GetAlertsResponse, error) {
    // Validate resource reference
    if req.GetResource() == nil {
        return nil, errors.New("resource reference is required")
    }
    
    // Get alerts from datastore
    alerts, err := s.datastore.GetAlertsForResource(ctx, req.GetResource())
    if err != nil {
        return nil, err
    }
    
    // Convert to API format
    var alertList []*storage.ListAlert
    for _, alert := range alerts {
        listAlert, err := s.alertToListAlert(alert)
        if err != nil {
            log.Warnf("Error converting alert %s: %v", alert.GetId(), err)
            continue
        }
        alertList = append(alertList, listAlert)
    }
    
    return &v1.GetAlertsResponse{Alerts: alertList}, nil
}
```

**Tasks**:
- [ ] Add new API methods for resource-based queries
- [ ] Update existing methods to handle both deployment_id and resource
- [ ] Add proper validation and error handling
- [ ] Update API documentation
- [ ] Add integration tests

### Work Package 7: Testing and Validation (Week 7-8)

#### 7.1 Integration Test Suite
**File**: `tests/universal_resource_policy_test.go`

```go
func TestUniversalResourcePolicyEngine(t *testing.T) {
    // Test ConfigMap policy
    t.Run("ConfigMap policy evaluation", func(t *testing.T) {
        policy := fixtures.ConfigMapSecurityPolicy()
        configMap := fixtures.InsecureConfigMap()
        
        alert, err := testDetector.DetectViolation(ctx, configMap, policy)
        require.NoError(t, err)
        assert.NotNil(t, alert)
        assert.Equal(t, "ConfigMap", alert.GetResource().GetKind())
    })
    
    // Test Service policy
    t.Run("Service policy evaluation", func(t *testing.T) {
        policy := fixtures.LoadBalancerPolicyCheck()
        service := fixtures.LoadBalancerService()
        
        alert, err := testDetector.DetectViolation(ctx, service, policy)
        require.NoError(t, err)
        assert.NotNil(t, alert)
        assert.Equal(t, "Service", alert.GetResource().GetKind())
    })
    
    // Test backward compatibility
    t.Run("Legacy deployment policy still works", func(t *testing.T) {
        policy := fixtures.PrivilegedPodPolicy() // Legacy policy without ResourceTarget
        deployment := fixtures.PrivilegedDeployment()
        
        alert, err := testDetector.DetectViolation(ctx, deployment, policy)
        require.NoError(t, err)
        assert.NotNil(t, alert)
    })
}
```

**Tasks**:
- [ ] Create comprehensive integration test suite
- [ ] Test all supported resource types
- [ ] Validate backward compatibility
- [ ] Test dynamic field evaluation
- [ ] Performance testing with large numbers of resources

#### 7.2 Migration Testing
**File**: `tests/migration_test.go`

```go
func TestPolicyMigration(t *testing.T) {
    // Test that existing policies work without ResourceTarget
    existingPolicies := []*storage.Policy{
        fixtures.PrivilegedContainerPolicy(),
        fixtures.LatestTagPolicy(),
        fixtures.HighCVSSPolicy(),
    }
    
    for _, policy := range existingPolicies {
        t.Run(fmt.Sprintf("Legacy policy %s", policy.GetName()), func(t *testing.T) {
            // Should work with existing deployment
            deployment := fixtures.TestDeployment()
            
            detector := createTestDetector()
            alert, err := detector.DetectViolation(ctx, deployment, policy)
            
            // Should not error (may or may not create alert depending on policy)
            require.NoError(t, err)
        })
    }
}
```

**Tasks**:
- [ ] Test migration of existing policies
- [ ] Validate no breaking changes to existing alerts
- [ ] Test performance impact
- [ ] Load testing with mixed old/new policies

## Risk Mitigation

### High-Risk Items

1. **Breaking Changes to Existing Policies**
   - **Risk**: Existing policies stop working
   - **Mitigation**: Extensive backward compatibility testing, gradual rollout
   
2. **Performance Impact**
   - **Risk**: New dynamic evaluation is slower than hardcoded fields
   - **Mitigation**: Performance benchmarking, caching strategies

3. **Admission Controller Stability**
   - **Risk**: Changes break admission control for critical workloads
   - **Mitigation**: Feature flags, canary deployments, extensive testing

### Medium-Risk Items

1. **Storage Schema Changes**
   - **Risk**: Alert storage breaks during migration
   - **Mitigation**: Database migration scripts, backward compatibility

2. **API Compatibility**
   - **Risk**: Existing API clients break
   - **Mitigation**: API versioning, deprecated field support

## Success Criteria

### Functional Requirements
- [ ] Can create policies targeting ConfigMaps, Services, Ingresses
- [ ] Dynamic field evaluation works for basic operators (equals, exists, contains)
- [ ] Existing deployment policies continue to work unchanged
- [ ] Admission controller processes all resource types
- [ ] Alerts created for non-deployment resources

### Performance Requirements
- [ ] Policy evaluation performance within 10% of current baseline
- [ ] Admission controller latency under 100ms for new resource types
- [ ] No significant memory increase in Sensor/Central

### Quality Requirements
- [ ] 90%+ test coverage for new code
- [ ] Zero breaking changes to existing APIs
- [ ] Documentation updated for new features

## Dependencies

### Internal Dependencies
- None (this is the foundation phase)

### External Dependencies
- Kubernetes 1.20+ (for unstructured.Unstructured improvements)
- No new external libraries required

## Timeline

```
Week 1-2:  Protobuf schema changes
Week 2-4:  Universal context model
Week 3-5:  Dynamic field evaluation  
Week 4-6:  Generic detection engine
Week 5-7:  Admission controller extension
Week 6-8:  Storage and API updates
Week 7-8:  Testing and validation
```

**Estimated Duration**: 8 weeks (2 months)  
**Resource Requirements**: 2-3 engineers  
**Critical Path**: Protobuf changes → Context model → Detection engine → Admission controller

## Next Steps

1. **Week 1**: Begin protobuf schema design and review
2. **Week 1**: Set up development environment and testing infrastructure  
3. **Week 2**: Start implementation of core interfaces
4. **Week 4**: First integration milestone - basic ConfigMap policy
5. **Week 6**: Feature complete milestone - all components working
6. **Week 8**: Quality milestone - testing complete, ready for Phase 2

This plan provides the foundation needed for the Universal Resource Policy Engine while maintaining strict backward compatibility and minimizing risk to existing functionality.
