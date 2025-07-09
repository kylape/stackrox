# StackRox Installation Method Unification Analysis

**Date:** 2025-07-09  
**Author:** Analysis by Claude Code  
**Issue:** [kylape/stackrox#4](https://github.com/kylape/stackrox/issues/4)

## Executive Summary

This document analyzes two approaches for combining StackRox installation methods to achieve operator-only installation. After comprehensive analysis, **Approach 2: Go-Based Installer Integration** is recommended as the optimal path forward.

## Problem Statement

Currently, StackRox supports multiple installation methods:
- Direct Helm chart deployment
- Operator-based deployment (using embedded Helm charts)
- Go-based installer (development-focused)

The goal is to consolidate to a single operator-only installation method while maintaining enterprise-grade capabilities.

## Approach Analysis

### Approach 1: Delete Helm Chart, Use Go-Based Installer

**Current Installer Capabilities:**
- **Components**: Central, Central DB, Scanner V4, Sensor, Collector, Admission Controller
- **Configuration**: 9 basic options in installer.yaml
- **Deployment**: Development-optimized, single-binary tool
- **Architecture**: Generator pattern with prioritized resource creation
- **Limitations**: Missing 90% of Helm chart features

**Pros:**
- Simplified architecture with single deployment method
- Reduced maintenance burden
- Better performance (direct Kubernetes API vs Helm rendering)
- Smaller binary size

**Cons:**
- **Massive feature gap**: 391 missing configuration options
- **High development cost**: 18-25 weeks estimated
- **Production readiness**: Lacks enterprise features (persistence, monitoring, security)
- **Complete rewrite**: Operator reconcilers need total reconstruction
- **High risk**: Breaking changes to existing workflows

### Approach 2: Go-Based Installer Integration

**Helm Chart Capabilities:**
- **Components**: Complete StackRox platform deployment
- **Configuration**: 400+ options across Central and Secured Cluster charts
- **Features**: Meta-templating, multi-environment support, advanced security
- **Architecture**: Sophisticated template system with 50+ helper functions
- **Integration**: Foundation for current operator functionality

**Pros:**
- **Incremental implementation**: 8-12 weeks estimated
- **Preserve sophistication**: Maintain enterprise-grade capabilities
- **Lower risk**: Evolutionary rather than revolutionary change
- **Natural operator integration**: Fits existing architecture
- **Feature parity**: Inherit all current capabilities

**Cons:**
- **Dual system transition**: Temporary complexity during migration
- **Installer enhancement required**: Need to add missing features
- **Learning curve**: Team needs to understand installer patterns

## Feature Parity Analysis

| Capability | Helm Charts | Current Installer | Gap |
|------------|-------------|-------------------|-----|
| **Configuration Options** | 400+ | 9 | 391 options |
| **Production Features** | Complete | Basic | Security, monitoring, persistence |
| **Multi-cluster Support** | Yes | No | Full feature |
| **Certificate Management** | Advanced | Basic | Rotation, external CA |
| **Storage Options** | Multiple | EmptyDir only | PVC, external storage |
| **Networking** | Advanced | Basic | Service mesh, policies |
| **Monitoring** | Prometheus | None | Full observability stack |
| **Security** | Enterprise | Basic | PSPs, SCCs, RBAC |
| **Customization** | Meta-templating | Hardcoded | Dynamic configuration |

## Operator Integration Analysis

### Current Operator Architecture
- Uses `helm-operator-plugins` framework
- Translates Custom Resources to Helm values
- Leverages embedded Helm charts for resource generation
- Implements pre-reconciliation extensions for validation

### Approach 1: Standalone Installer Integration
**Requirements:**
- Replace Helm engine with direct Kubernetes API client
- Implement resource generation equivalent to Helm templates
- Redesign value translation system (CR → Kubernetes Resources)
- Custom implementation of complex template logic

**Complexity: HIGH** (18-25 weeks)

### Approach 2: Installer Generator Integration
**Requirements:**
- Create configuration translation layer (CR → Installer Config)
- Use installer generators within operator reconcilers
- Adapt existing extension system
- Maintain operator lifecycle management

**Complexity: MODERATE** (8-12 weeks)

## Risk Assessment

### Approach 1 Risks
- **High**: Complete feature loss during development
- **High**: Extended development timeline
- **Medium**: Operator workflow disruption
- **High**: Potential for significant regressions

### Approach 2 Risks
- **Low**: Incremental development approach
- **Low**: Existing functionality preserved
- **Low**: Gradual migration path
- **Medium**: Temporary dual-system complexity

## Recommendation: Approach 2

**Rationale:**
1. **Lower Risk**: Incremental changes rather than complete rewrite
2. **Faster Implementation**: Leverage existing installer generators
3. **Better Maintainability**: Single source of truth for resource generation
4. **Proven Patterns**: Installer's generator system is battle-tested
5. **Future-Proof**: Sets foundation for unified deployment strategy

## Implementation Strategy

### Phase 1: Enhanced Installer Development (6-8 weeks)
1. **Add Missing Configuration Options**
   - Expand installer.yaml to support production scenarios
   - Add storage, networking, and security configurations
   - Implement advanced deployment patterns

2. **Certificate Management Enhancement**
   - External CA support
   - Certificate rotation capabilities
   - Browser-friendly development certificates

3. **Production Features**
   - Persistent volume support
   - Resource scaling options
   - Monitoring integration

### Phase 2: Operator Integration (4-6 weeks)
1. **Configuration Translation Layer**
   - Map operator CRs to installer config
   - Maintain backward compatibility
   - Add validation and defaulting

2. **Generator Integration**
   - Replace Helm reconcilers with installer generators
   - Adapt extension system
   - Preserve operator lifecycle management

### Phase 3: Helm Chart Simplification (2-3 weeks)
1. **Remove Customer-Facing Features**
   - Eliminate complex meta-templating
   - Remove direct deployment paths
   - Simplify for operator-only use

2. **Create Operator Installation Chart**
   - New simplified chart for operator deployment
   - Basic configuration options
   - Focus on operator lifecycle

## Technical Implementation Details

### Current Installer Architecture
```
installer/
├── main.go                    # CLI interface
├── manifest/
│   ├── manifest.go           # Core engine
│   ├── ca.go                 # Certificate Authority
│   ├── central.go            # Central service
│   ├── central_db.go         # PostgreSQL
│   ├── scanner.go            # Scanner v1/v2
│   ├── scannerv4.go          # Scanner v4
│   ├── sensor.go             # Sensor agent
│   ├── collector.go          # Collector DaemonSet
│   ├── admission_control.go  # Admission Controller
│   └── config_controller.go  # Config Controller
```

### Operator Integration Points
```go
// New translator interface
type InstallerConfigTranslator interface {
    TranslateToInstallerConfig(ctx context.Context, cr *platform.Central) (*manifest.Config, error)
}

// Modified reconciler structure
func (r *Reconciler) reconcileWithInstaller(ctx context.Context, cr *platform.Central) error {
    config := translateCRToInstallerConfig(cr)
    generators := manifest.GeneratorSets["central"]
    
    manifestGen := manifest.New(config, r.client, r.restConfig)
    return manifestGen.Apply(ctx, *generators)
}
```

## Success Criteria

1. **Single Installation Method**: Operator-only deployment
2. **Feature Parity**: Preserve all current enterprise capabilities
3. **Maintained UX**: Existing operator user experience unchanged
4. **Reduced Complexity**: Simplified overall system architecture
5. **Enhanced Development**: Improved development workflow with installer

## Conclusion

Approach 2 (Go-Based Installer Integration) provides the optimal balance of technical feasibility, risk mitigation, and feature preservation. This approach achieves the strategic goal of operator-only installation while maintaining the significant engineering investment in the current system and providing a clear path forward for long-term maintainability.

The implementation leverages the strengths of both systems: the installer's efficient resource generation patterns and the Helm charts' comprehensive enterprise capabilities, resulting in a unified, maintainable solution that serves both development and production needs.