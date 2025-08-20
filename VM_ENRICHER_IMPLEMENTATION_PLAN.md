# Virtual Machine Enricher Implementation Plan

## Status: Phase 1 Complete ✅

Phase 1 has been successfully implemented with the VM enricher following the established node enricher pattern while maintaining data model separation.

## Completed in Phase 1

### File Structure Created:
- **`pkg/virtualmachines/enricher/enricher.go`**: VM enricher interface with `EnrichVirtualMachineWithVulnerabilities` method
- **`pkg/virtualmachines/enricher/enricher_impl.go`**: Complete implementation with Scanner V4 client integration
- **`pkg/virtualmachines/enricher/singleton.go`**: VM enricher singleton with namespace-independent Scanner V4 client creation
- **`pkg/virtualmachines/enricher/vm_convert.go`**: VM vulnerability conversion pipeline
- **`pkg/virtualmachines/enricher/vm_convert_utils.go`**: Utility functions for severity mapping and CVSS scoring
- **`central/sensor/service/pipeline/virtualmachineindex/pipeline.go`**: Updated to integrate VM enricher

### Key Features Implemented:
✅ **Scanner V4 Integration**: Reuses existing Scanner V4 infrastructure with namespace-independent endpoints  
✅ **Type Safety**: Proper conversion from VM IndexReportEvent → IndexReport → Scanner V4 IndexReport  
✅ **VM-Specific Processing**: Uses `EmbeddedImageScanComponent` (current proto definition)  
✅ **Error Handling**: Graceful degradation with appropriate VM notes  
✅ **Debug Logging**: Success logging for enrichment operations  
✅ **Data Model Separation**: Independent from node enricher as advised by data modeling team

## Remaining Implementation Phases

---

## Phase 2: Testing Strategy

### 2.1 Unit Tests
**Files to create:**
- `pkg/virtualmachines/enricher/enricher_impl_test.go`
- `pkg/virtualmachines/enricher/vm_convert_test.go`
- `pkg/virtualmachines/enricher/vm_convert_utils_test.go`
- `central/sensor/service/pipeline/virtualmachineindex/pipeline_test.go`

**Test Coverage Areas:**
- VM enricher with valid Scanner V4 responses
- VM enricher with Scanner V4 client failures
- VM enricher with malformed index reports
- Vulnerability conversion accuracy (severity mapping, CVSS scoring)
- Error handling and VM notes assignment
- Pipeline integration with mocked enricher

### 2.2 Integration Tests
**Requirements:**
- Test with real Scanner V4 responses
- Test VM pipeline end-to-end
- Test Scanner V4 client creation and connection
- Verify database storage of enriched VMs

### 2.3 Test Commands
```bash
# Run VM enricher unit tests
go test ./pkg/virtualmachines/enricher/...

# Run VM pipeline tests  
go test ./central/sensor/service/pipeline/virtualmachineindex/...

# Run full validation
make go-unit-tests
make golangci-lint
```

---

## Phase 3: Future Component Type Migration

### 3.1 Prepare for Scanner Component Switch
**Issue**: VMs currently use `EmbeddedImageScanComponent` but should use proper VM components

**Implementation Strategy:**
1. **Create conversion interface/factory pattern**
2. **Keep conversion logic isolated in `vm_convert.go`** 
3. **Use feature flags to switch between component types**

**Files to modify when ready:**
- `pkg/virtualmachines/enricher/vm_convert.go`: Update `createEmbeddedImageComponent()` function
- `proto/storage/virtual_machine.proto`: Update component field type (when new proto is available)

### 3.2 Migration Steps (Future)
```go
// Example future migration in vm_convert.go
func createEmbeddedVMComponent(pkg *v4.Package, vulns []*storage.EmbeddedVulnerability) *storage.EmbeddedVMScanComponent {
    return &storage.EmbeddedVMScanComponent{  // New type
        Name:    pkg.GetName(),
        Version: pkg.GetVersion(), 
        Vulns:   vulns,
        // VM-specific fields
    }
}
```

---

## Phase 4: Advanced Features (Optional)

### 4.1 Risk Management Integration
**Files to create/modify:**
- `central/risk/manager/manager.go`: Add `CalculateRiskAndUpsertVirtualMachine` method
- `central/risk/scorer/virtualmachine/scorer.go`: VM-specific risk scoring logic

**Integration:**
- Add risk calculation to VM pipeline after enrichment
- Follow node risk management patterns

### 4.2 CVE Suppression Support
**Files to modify:**
- `pkg/virtualmachines/enricher/enricher_impl.go`: Add CVE suppressor parameter
- `pkg/virtualmachines/enricher/singleton.go`: Inject CVE suppressor dependency

**Implementation:**
```go
// Example addition to enricher interface
type VirtualMachineEnricher interface {
    EnrichVirtualMachineWithVulnerabilities(vm *storage.VirtualMachine, indexReport *v4.IndexReport) error
    // Future: SuppressCVEs, etc.
}
```

### 4.3 Metrics and Observability
**Areas to add:**
- VM enrichment success/failure rates
- Scanner V4 performance metrics for VMs  
- Enrichment duration tracking
- Component count distributions

**Files to create:**
- `pkg/virtualmachines/enricher/metrics.go`: VM-specific metrics

---

## Phase 5: Production Readiness

### 5.1 Configuration and Feature Flags
**Considerations:**
- Feature flag for VM scanning enablement
- Scanner V4 endpoint configuration override
- Timeout and retry configuration
- Resource limits and concurrency controls

### 5.2 Documentation
**Files to create/update:**
- Update VM scanning documentation
- Add troubleshooting guide for VM enrichment
- Document VM vs node scanning differences
- Add operational runbooks

### 5.3 Performance Validation
**Testing Areas:**
- VM enrichment throughput vs node enrichment
- Scanner V4 load with VM scanning enabled
- Memory usage patterns with VM vulnerability data
- Database performance with VM scan storage

---

## Implementation Notes

### Scanner Client Reuse
The VM enricher reuses Scanner V4 infrastructure by calling the same `client.NewGRPCScanner()` that nodes use, ensuring consistency and reliability.

### Data Model Separation Benefits
- **Clear separation of concerns**: VM and node vulnerability data remain independent
- **Independent schema evolution**: VM and node models can evolve separately
- **Distinct vulnerability handling**: Each resource type has appropriate processing logic

### Error Handling Strategy
VM enricher follows the same error handling patterns as node enricher:
- Graceful degradation when Scanner V4 is unavailable
- Appropriate VM notes for different failure scenarios
- Detailed error logging for troubleshooting

### Future-Proofing Considerations
- Component type abstraction ready for migration
- Scanner client dependency injection for testing
- Conversion logic isolated for easy modification
- Consistent patterns with existing enricher implementations

---

## Commands for Next Session

```bash
# Continue with Phase 2 - Testing
cd /root/src/stackrox

# Create test files
touch pkg/virtualmachines/enricher/enricher_impl_test.go
touch pkg/virtualmachines/enricher/vm_convert_test.go
touch central/sensor/service/pipeline/virtualmachineindex/pipeline_test.go

# Run tests
go test ./pkg/virtualmachines/enricher/...
make go-unit-tests
```

This plan ensures systematic completion of the VM enricher implementation while maintaining code quality and following established patterns.