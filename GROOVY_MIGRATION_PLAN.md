# Groovy to Go Test Migration Plan

**Status**: Proof of Concept Complete
**Date Started**: 2025-11-04
**Approach**: Ginkgo/Gomega BDD Framework

## Executive Summary

This document outlines the plan to migrate ~55-60 active Groovy/Spock tests from `qa-tests-backend/` to Go using the Ginkgo/Gomega BDD testing framework. The migration preserves the behavioral testing patterns from Spock while leveraging Go's type safety and tooling.

## Why Ginkgo?

### Alignment with Groovy/Spock Patterns

The existing Groovy tests use Spock's BDD structure:

```groovy
def "Verify response for basic auth"() {
    when:
    "Authentication is requested"
    def status = AuthService.getAuthStatus()

    then:
    "User info should be correct"
    assert status.userId == "admin"

    cleanup:
    // Resource cleanup
}
```

Ginkgo provides equivalent BDD constructs:

```go
It("should return valid auth status for admin user", func() {
    By("When getting auth status with basic auth")
    status, err := authService.GetAuthStatus(ctx, &v1.Empty{})
    Expect(err).NotTo(HaveOccurred())

    By("Then the response should contain admin user info")
    Expect(status.GetUserId()).To(Equal("admin"))

    DeferCleanup(func() {
        // Resource cleanup
    })
})
```

### What We Preserve

- ✅ **Behavioral structure**: `Describe/Context/It` = Features/Scenarios/Examples
- ✅ **Readable narratives**: `By()` steps = `given/when/then`
- ✅ **Parameterized tests**: `DescribeTable` = `@Unroll` with `where:` blocks
- ✅ **Async testing**: `Eventually/Consistently` = `withRetry()` helpers
- ✅ **Resource cleanup**: `DeferCleanup` = `cleanup:` blocks
- ✅ **Test organization**: Labels = Tags (`@Tag("BAT")`)

### What We Gain

- ✅ **Type safety**: Compile-time checking vs runtime errors
- ✅ **Better IDE support**: Go tooling, navigation, refactoring
- ✅ **Parallel execution**: Built-in Ginkgo parallelization
- ✅ **Unified codebase**: Same language as production code

## Architecture Principles

### 1. Keep It Simple - No Custom Frameworks

**YES ✅ Use Ginkgo directly:**
```go
var _ = Describe("Policy Tests", func() {
    var conn *grpc.ClientConn

    BeforeEach(func() {
        conn = centralgrpc.GRPCConnectionToCentral(GinkgoT())
        DeferCleanup(func() { conn.Close() })
    })

    It("should create policies", func() {
        svc := v1.NewPolicyServiceClient(conn)
        // Direct gRPC usage
    })
})
```

**NO ❌ Don't build custom BDD wrappers:**
```go
// Avoid this - unnecessary abstraction
type StackRoxBDDSuite struct {
    resourceTracker *ResourceTracker
    chaosManager    *ChaosManager
}
func (s *StackRoxBDDSuite) Given(desc string, fn func()) { ... }
```

### 2. Direct gRPC Client Usage

Follow existing StackRox patterns (roxctl, etc.) - use raw gRPC service clients:

```go
// Pattern from existing codebase
conn := centralgrpc.GRPCConnectionToCentral(GinkgoT())
policySvc := v1.NewPolicyServiceClient(conn)
alertSvc := v1.NewAlertServiceClient(conn)
```

### 3. Resource Management with DeferCleanup

Ginkgo's `DeferCleanup` handles resource cleanup automatically:

```go
It("should manage resources", func() {
    policy := createPolicy(...)
    DeferCleanup(func() { deletePolicy(policy.Id) })

    deployment := createDeployment(...)
    DeferCleanup(func() { deleteDeployment(deployment.Name) })

    // Test logic - cleanup happens automatically
})
```

## Proof of Concept Results

### PoC Test: AuthServiceTest

**Source**: `qa-tests-backend/src/test/groovy/AuthServiceTest.groovy` (74 lines)
**Target**: `tests/auth_service_test.go` (119 lines)
**Commit**: `5e5c9e482f`

### What Works ✅

1. **Test compiles successfully** - Type-safe Go code
2. **Ginkgo suite initialization** - Standard pattern established
3. **BDD structure preserved** - Readable test narrative
4. **Labels/Tags working** - `Label("BAT", "COMPATIBILITY")`
5. **DeferCleanup pattern** - Resource management
6. **Direct gRPC clients** - Following existing patterns

### What's Pending ⏳

1. **Test execution setup** - Need port-forward or in-cluster runner
2. **Token generation helper** - Required for API token auth test
3. **Integration with CI** - Build tags and test selection

### Patterns Established

#### Test Suite Initialization
```go
//go:build test_e2e || test_compatibility

package tests

import (
    "testing"
    . "github.com/onsi/ginkgo/v2"
    . "github.com/onsi/gomega"
)

func TestAuthService(t *testing.T) {
    RegisterFailHandler(Fail)
    RunSpecs(t, "AuthService Suite")
}
```

#### BDD Test Structure
```go
var _ = Describe("AuthService", Label("BAT", "COMPATIBILITY"), func() {
    var (
        conn        *grpc.ClientConn
        authService v1.AuthServiceClient
        ctx         context.Context
    )

    BeforeEach(func() {
        conn = centralgrpc.GRPCConnectionToCentral(GinkgoT())
        authService = v1.NewAuthServiceClient(conn)
        ctx = context.Background()
        DeferCleanup(func() { conn.Close() })
    })

    Context("Basic Authentication", func() {
        It("should return valid auth status", func() {
            By("When getting auth status")
            status, err := authService.GetAuthStatus(ctx, &v1.Empty{})
            Expect(err).NotTo(HaveOccurred())

            By("Then user should be admin")
            Expect(status.GetUserId()).To(Equal("admin"))
        })
    })
})
```

#### Helper Functions
```go
// Convert proto repeated fields to Go maps
func makeAttributeMap(attrs []*v1.UserAttribute) map[string][]string {
    result := make(map[string][]string)
    for _, attr := range attrs {
        result[attr.GetKey()] = attr.GetValues()
    }
    return result
}
```

## Migration Phases

### Phase 1: Foundation & Simple Tests (4-6 weeks)

**Goal**: Establish patterns and migrate standalone tests

**Tasks**:
1. ✅ Create Ginkgo PoC (AuthServiceTest) - **DONE**
2. Set up test execution environment
3. Document migration patterns
4. Migrate 5-10 simple tests:
   - IntegrationHealthTest (19 lines)
   - NodeTest (49 lines)
   - ClustersTest (64 lines)
   - NamespaceTest (88 lines)

**Success Criteria**:
- All simple tests migrated and passing
- Team can run tests locally and in CI
- Migration documentation complete

### Phase 2: Complex Tests & Helpers (8-12 weeks)

**Goal**: Migrate tests requiring shared infrastructure

**Tasks**:
1. Migrate token generation helpers
2. Migrate deployment management utilities
3. Migrate complex tests:
   - AuthServiceTest (complete token auth)
   - Policy tests
   - Integration tests
   - Network tests

**Success Criteria**:
- Complex test patterns documented
- Shared helper library established
- 50%+ of tests migrated

### Phase 3: Remaining Tests & Cleanup (6-8 weeks)

**Goal**: Complete migration and retire Groovy tests

**Tasks**:
1. Migrate remaining tests
2. Migrate ChaosMonkey (simple pod-killing only)
3. Update CI pipelines
4. Remove qa-tests-backend

**Success Criteria**:
- 100% active Groovy tests migrated
- CI running Go tests exclusively
- Documentation complete

## Test Categorization

### Simple Tests (High Priority)
Tests with minimal dependencies, no complex setup:
- IntegrationHealthTest
- NodeTest
- ClustersTest
- NamespaceTest
- CertExpiryTest

### Medium Complexity
Tests requiring shared helpers or external services:
- AuthServiceTest (token generation)
- Policy tests (policy CRUD)
- Alert tests
- Deployment tests

### Complex Tests
Tests with extensive setup, external integrations, or stateful scenarios:
- AdmissionControllerTest (chaos monkey)
- IntegrationsTest (external services)
- ImageScanningTest (registry integration)
- PolicyFieldsTest (173 scenarios)

## Migration Guidelines

### 1. File Naming
- Groovy: `AuthServiceTest.groovy`
- Go: `auth_service_test.go` (suite: `auth_service_suite_test.go`)

### 2. Build Tags
All tests use build tags for categorization:
```go
//go:build test_e2e || test_compatibility
```

### 3. Test Labels
Use Ginkgo labels for test selection:
```go
Describe("Feature", Label("BAT", "COMPATIBILITY"), func() {
    // Tests
})
```

### 4. Context Naming
- Use `Context` for grouping related scenarios
- Use descriptive names: "Basic Authentication", "API Token Authentication"

### 5. Assertion Patterns

**Groovy**:
```groovy
assert status.userId == "admin"
assert permissions.resourceToAccessCount > 0
```

**Ginkgo/Gomega**:
```go
Expect(status.GetUserId()).To(Equal("admin"))
Expect(permissions.GetResourceToAccess()).NotTo(BeEmpty())
```

### 6. Nested Assertions

**Groovy** (`with` block):
```groovy
status.authProvider.with {
    assert name == "Login with username/password"
    assert type == "basic"
}
```

**Go** (explicit):
```go
authProvider := status.GetAuthProvider()
Expect(authProvider.GetName()).To(Equal("Login with username/password"))
Expect(authProvider.GetType()).To(Equal("basic"))
```

### 7. Async/Polling

**Groovy**:
```groovy
withRetry(120, 10) {
    def alerts = getAlerts()
    assert alerts.size() == 1
}
```

**Ginkgo**:
```go
Eventually(func() []*storage.Alert {
    return getAlerts()
}, "2m", "10s").Should(HaveLen(1))
```

## Environment Setup

### Required Environment Variables
```bash
export ROX_ADMIN_PASSWORD=<password>
export API_ENDPOINT=<central-endpoint>  # e.g., localhost:18443
export KUBECONFIG=<path-to-kubeconfig>
```

### Running Tests

**All tests**:
```bash
go test -v -tags test_e2e ./tests
```

**Specific test**:
```bash
go test -v -tags test_e2e -run TestAuthService ./tests
```

**With labels**:
```bash
ginkgo -v --label-filter="BAT" ./tests
```

**Parallel execution**:
```bash
ginkgo -v -p --procs=8 ./tests
```

## Reference Documentation

### Scratchpad Documents
Detailed research and planning documents:
- `/root/workspace/scratchpad/stackrox-e2e-tests/2025-09-25-groovy-to-go-migration-plan.md`
- `/root/workspace/scratchpad/stackrox-e2e-tests/2025-09-25-migration-plan-critique.md`
- `/root/workspace/scratchpad/stackrox-e2e-tests/2025-09-25-qa-tests-backend-overview.md`

### Related Work
- **Piotr's refactoring**: `remotes/origin/piotr/ROX-29771-refactor-nongroovy-common`
- **ARM CI**: `remotes/origin/rc-gke-arm-nongroovy`

### External Resources
- [Ginkgo Documentation](https://onsi.github.io/ginkgo/)
- [Gomega Matchers](https://onsi.github.io/gomega/)
- Existing Go tests: `tests/` directory

## Success Metrics

### Quantitative
- 100% of active Groovy tests migrated
- Test execution time ≤ 120 minutes (maintain parity)
- Parallel execution: 8+ concurrent processes
- Zero flaky test rate increase

### Qualitative
- Clear BDD test descriptions
- Easy to understand test failures
- Simple for new developers to write tests
- Better IDE experience than Groovy

## Next Steps

1. **Set up test execution** - Port-forward script or in-cluster runner
2. **Migrate token helpers** - Enable API token authentication tests
3. **Create migration template** - Document for team use
4. **Migrate next 3-5 simple tests** - Validate patterns
5. **Team review** - Get feedback on approach

## Open Questions

1. **Test execution environment**: In-cluster pod vs port-forward?
2. **CI integration**: New jobs or update existing?
3. **Groovy deprecation timeline**: When to remove qa-tests-backend?
4. **Chaos engineering scope**: Just ChaosMonkey or more?

## Decision Log

| Date | Decision | Rationale |
|------|----------|-----------|
| 2025-11-04 | Use Ginkgo/Gomega | Preserves BDD patterns from Spock |
| 2025-11-04 | No custom frameworks | Keep it simple, use Ginkgo directly |
| 2025-11-04 | Direct gRPC clients | Follow existing StackRox patterns (roxctl) |
| 2025-11-04 | AuthServiceTest as PoC | Good BDD structure, minimal dependencies |
