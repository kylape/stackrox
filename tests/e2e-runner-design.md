# Implementation Plan: Go-based E2E Test Runner

## Overview
Convert the bash-based E2E test orchestrator to Go with support for testing against existing StackRox deployments, centralized configuration management, and integrated build/test functionality.

## Project Structure

```
tests/
├── e2e-runner/
│   └── main.go                 # CLI entry point
├── e2e/
│   ├── config/
│   │   ├── config.go          # Configuration types and loading
│   │   ├── validation.go      # Configuration validation
│   │   └── defaults.go        # Default values and env var mapping
│   ├── build/
│   │   ├── manager.go         # Build orchestration (absorbs Makefile)
│   │   ├── targets.go         # Build target definitions
│   │   ├── docker.go          # Docker/container operations
│   │   └── dependencies.go    # Dependency management
│   ├── gotest/
│   │   ├── runner.go          # Go test execution (absorbs go-test.sh)
│   │   ├── parser.go          # Go test output parsing
│   │   ├── coverage.go        # Coverage collection and reporting
│   │   └── filtering.go       # Test filtering and selection
│   ├── deploy/
│   │   ├── manager.go         # Deployment orchestration
│   │   ├── operator.go        # Operator-based deployment
│   │   ├── helm.go            # Helm-based deployment
│   │   └── teardown.go        # Resource cleanup
│   ├── testsuites/
│   │   ├── runner.go          # Test suite orchestration
│   │   ├── api.go             # API test execution
│   │   ├── roxctl.go          # roxctl test execution
│   │   ├── proxy.go           # Proxy test execution
│   │   └── destructive.go     # Destructive test execution
│   ├── k8s/
│   │   ├── client.go          # Kubernetes client utilities
│   │   ├── wait.go            # Resource waiting functions
│   │   └── resources.go       # Resource management helpers
│   ├── health/
│   │   ├── monitor.go         # Health monitoring
│   │   ├── logs.go            # Log analysis
│   │   └── restarts.go        # Pod restart detection
│   ├── artifacts/
│   │   ├── collector.go       # Log and artifact collection
│   │   ├── junit.go           # JUnit XML generation
│   │   └── storage.go         # Artifact storage
│   └── utils/
│       ├── exec.go            # Command execution helpers
│       ├── retry.go           # Retry logic
│       └── files.go           # File operations
├── config/
│   ├── default.yaml           # Default configuration
│   ├── openshift.yaml         # OpenShift-specific overrides
│   └── examples/              # Example configurations
└── testdata/                  # Test data files
```

## Core Infrastructure

### Configuration System

Create a hierarchical configuration system supporting existing deployments:

```go
// tests/e2e/config/config.go
type Config struct {
    // Cluster Configuration
    Cluster ClusterConfig `yaml:"cluster"`
    
    // StackRox Configuration
    StackRox StackRoxConfig `yaml:"stackrox"`
    
    // Build Configuration
    Build BuildConfig `yaml:"build"`
    
    // Test Configuration
    Tests TestConfig `yaml:"tests"`
    
    // Deployment Configuration
    Deploy DeployConfig `yaml:"deploy"`
    
    // Artifacts Configuration
    Artifacts ArtifactsConfig `yaml:"artifacts"`
}

type StackRoxConfig struct {
    // Existing deployment settings
    UseExisting     bool     `yaml:"useExisting"`
    CentralNS       string   `yaml:"centralNamespace"`
    SensorNS        string   `yaml:"sensorNamespace"`
    
    // Connection settings
    Endpoint        string   `yaml:"endpoint" env:"API_ENDPOINT"`
    Username        string   `yaml:"username" env:"ROX_USERNAME"`
    Password        string   `yaml:"password" env:"ROX_ADMIN_PASSWORD"`
    
    // TLS settings
    TLS             TLSConfig `yaml:"tls"`
    
    // Feature flags
    FeatureFlags    map[string]string `yaml:"featureFlags"`
}

type BuildConfig struct {
    Enabled         bool              `yaml:"enabled"`
    Targets         []string          `yaml:"targets"`
    Tags            []string          `yaml:"tags"`
    Parallel        bool              `yaml:"parallel"`
    MaxParallel     int               `yaml:"maxParallel"`
    Cache           bool              `yaml:"cache"`
    Environment     map[string]string `yaml:"environment"`
    
    // Docker/Image settings
    Registry        string            `yaml:"registry"`
    ImageTag        string            `yaml:"imageTag"`
    PushImages      bool              `yaml:"pushImages"`
}

type TestConfig struct {
    // Go test settings (from go-test.sh)
    GoTest          GoTestConfig      `yaml:"goTest"`
    
    // Test suite settings
    Suites          []string          `yaml:"suites"`
    Parallel        bool              `yaml:"parallel"`
    FailFast        bool              `yaml:"failfast"`
    Timeout         time.Duration     `yaml:"timeout"`
    
    // Suite-specific configurations
    API             APITestConfig     `yaml:"api"`
    Roxctl          RoxctlTestConfig  `yaml:"roxctl"`
    Proxy           ProxyTestConfig   `yaml:"proxy"`
    Destructive     DestructiveConfig `yaml:"destructive"`
}

type GoTestConfig struct {
    Enabled         bool              `yaml:"enabled"`
    Tags            []string          `yaml:"tags"`
    Packages        []string          `yaml:"packages"`
    Timeout         time.Duration     `yaml:"timeout"`
    Race            bool              `yaml:"race"`
    Cover           bool              `yaml:"cover"`
    CoverProfile    string            `yaml:"coverProfile"`
    Verbose         bool              `yaml:"verbose"`
    Parallel        int               `yaml:"parallel"`
    Count           int               `yaml:"count"`
    Short           bool              `yaml:"short"`
    Args            []string          `yaml:"args"`
}
```

### Build System Integration

Absorb Makefile functionality into Go:

```go
// tests/e2e/build/manager.go
type BuildManager struct {
    config    *config.BuildConfig
    rootDir   string
    executor  *utils.Executor
}

type BuildTarget struct {
    Name         string            `yaml:"name"`
    Description  string            `yaml:"description"`
    Commands     []BuildCommand    `yaml:"commands"`
    Dependencies []string          `yaml:"dependencies"`
    Outputs      []string          `yaml:"outputs"`
    Environment  map[string]string `yaml:"environment"`
}

type BuildCommand struct {
    Name        string            `yaml:"name"`
    Command     string            `yaml:"command"`
    Args        []string          `yaml:"args"`
    WorkDir     string            `yaml:"workDir"`
    Environment map[string]string `yaml:"environment"`
    Parallel    bool              `yaml:"parallel"`
}

func (bm *BuildManager) Build(ctx context.Context, targets []string) error
func (bm *BuildManager) Clean(ctx context.Context) error
func (bm *BuildManager) GetDependencyGraph() (*DependencyGraph, error)
```

### Go Test Integration

Absorb go-test.sh functionality:

```go
// tests/e2e/gotest/runner.go
type GoTestRunner struct {
    config   *config.GoTestConfig
    rootDir  string
    executor *utils.Executor
}

type GoTestResult struct {
    Package    string        `json:"package"`
    Status     TestStatus    `json:"status"`
    Duration   time.Duration `json:"duration"`
    Tests      []TestCase    `json:"tests"`
    Coverage   *Coverage     `json:"coverage,omitempty"`
    Output     string        `json:"output"`
    Error      error         `json:"error,omitempty"`
}

type TestCase struct {
    Name     string        `json:"name"`
    Status   TestStatus    `json:"status"`
    Duration time.Duration `json:"duration"`
    Output   string        `json:"output"`
    Error    string        `json:"error,omitempty"`
}

func (gtr *GoTestRunner) RunTests(ctx context.Context, packages []string) (*GoTestResults, error)
func (gtr *GoTestRunner) RunWithFilter(ctx context.Context, filter TestFilter) (*GoTestResults, error)
func (gtr *GoTestRunner) GenerateCoverage(ctx context.Context, profiles []string) (*CoverageReport, error)
```

### Test Suite Framework

```go
// tests/e2e/testsuites/runner.go
type TestSuiteRunner struct {
    config     *config.Config
    client     kubernetes.Interface
    deployment *StackRoxInfo
    artifacts  *artifacts.Collector
    builder    *build.BuildManager
    goTest     *gotest.GoTestRunner
}

type TestSuite interface {
    Name() string
    Prerequisites() []string
    Run(ctx context.Context, env *TestEnvironment) *TestResult
    Cleanup(ctx context.Context, env *TestEnvironment) error
}

type TestEnvironment struct {
    Config     *config.Config
    Client     kubernetes.Interface
    StackRox   *StackRoxInfo
    Builder    *build.BuildManager
    GoTest     *gotest.GoTestRunner
    TempDir    string
    Logger     *slog.Logger
}

type StackRoxInfo struct {
    CentralNamespace string `json:"centralNamespace"`
    SensorNamespace  string `json:"sensorNamespace"`
    Endpoint         string `json:"endpoint"`
    Version          string `json:"version"`
    Components       map[string]ComponentStatus `json:"components"`
}
```

## CLI Interface

```bash
# Test against existing StackRox deployment
e2e-runner --config=existing.yaml

# Build, deploy fresh, and test
e2e-runner --config=fresh.yaml --build --deploy

# Run only Go tests
e2e-runner --go-test-only --tags="test,test_e2e" --packages="./..."

# Run specific build targets and test suites
e2e-runner --build-targets=central,sensor --suites=api,roxctl

# Build everything
e2e-runner --build-only --targets=all

# Cleanup mode
e2e-runner --cleanup --namespace=test-stackrox

# Advanced usage
e2e-runner \
  --stackrox.endpoint=central.example.com:443 \
  --stackrox.useExisting=true \
  --tests.parallel=true \
  --build.enabled=false
```

## Configuration Examples

```yaml
# tests/config/existing-deployment.yaml
cluster:
  kubeconfig: ~/.kube/config
  flavor: kubernetes

stackrox:
  useExisting: true
  centralNamespace: stackrox
  sensorNamespace: stackrox
  endpoint: localhost:8000
  username: admin
  # password set via ROX_ADMIN_PASSWORD env var
  tls:
    skipVerify: true

build:
  enabled: false  # Don't build when using existing deployment

tests:
  goTest:
    enabled: true
    tags: [test, test_e2e]
    packages: [./tests]
    race: true
    cover: true
    timeout: 30m
    parallel: 5
    
  suites: [api, roxctl]
  parallel: true
  timeout: 45m

artifacts:
  baseDir: /tmp/e2e-artifacts
  collect:
    logs: true
    events: true
  formats: [junit, json]

deploy:
  mode: none  # Don't deploy when using existing
```

```yaml
# tests/config/fresh-deployment.yaml
stackrox:
  useExisting: false
  centralNamespace: e2e-central
  sensorNamespace: e2e-sensor

build:
  enabled: true
  targets: [central, sensor, roxctl]
  parallel: true
  maxParallel: 4
  imageTag: e2e-test
  
tests:
  goTest:
    enabled: true
    tags: [test, test_e2e]
    packages: [./tests, ./tests/bad-ca]
    
  suites: [api, roxctl, proxy, destructive]

deploy:
  mode: operator
  cleanup: true
  central:
    namespace: e2e-central
    replicas: 1
  sensor:
    namespace: e2e-sensor
    collectionMethod: core_bpf
```

```yaml
# tests/config/build-targets.yaml - Build system configuration
build:
  targets:
    - name: all
      description: Build all components
      dependencies: [proto, central, sensor, roxctl, scanner]
      
    - name: proto
      description: Generate protobuf artifacts
      commands:
        - name: proto-gen
          command: make
          args: [proto-generated-srcs]
          
    - name: central
      description: Build Central binary
      commands:
        - name: build-central
          command: make
          args: [bin/central]
      outputs: [bin/central]
      
    - name: sensor
      description: Build Sensor binary  
      commands:
        - name: build-sensor
          command: make
          args: [bin/kubernetes]
      outputs: [bin/kubernetes]
      
    - name: roxctl
      description: Build roxctl CLI
      commands:
        - name: build-roxctl
          command: make
          args: [bin/roxctl]
      outputs: [bin/roxctl]
```

## Implementation Strategy

### Core Components First
1. **Configuration System**: YAML loading, validation, environment overrides
2. **Build Integration**: Replace Makefile calls with native Go execution
3. **Go Test Integration**: Replace go-test.sh with structured Go test runner
4. **CLI Framework**: Command-line interface with comprehensive flag support

### Test Infrastructure  
1. **Test Suite Framework**: Pluggable test suite architecture
2. **Health Monitoring**: Component status checking and log analysis
3. **Artifact Collection**: Structured artifact gathering and reporting
4. **Kubernetes Integration**: Native client-go usage replacing kubectl calls

### Test Suite Implementation
1. **API Test Suite**: Integration with existing Go tests
2. **Roxctl Test Suite**: Execute and parse roxctl tests
3. **Proxy Test Suite**: Network proxy testing
4. **Destructive Test Suite**: Destructive testing with proper cleanup

### Integration & Polish
1. **Error Handling**: Comprehensive error handling and recovery
2. **Logging**: Structured logging with multiple output formats
3. **Documentation**: Usage examples and migration guides
4. **Testing**: Unit and integration tests for the framework itself

## Benefits Delivered

1. **Existing Deployment Support**: Easy configuration for testing against running StackRox
2. **Integrated Build System**: Native Go build orchestration replacing Makefiles
3. **Unified Test Execution**: Single tool for builds, deployments, and tests
4. **Better Reliability**: Type safety, structured error handling, comprehensive logging
5. **Enhanced Performance**: Parallel execution, efficient resource usage
6. **Easier Maintenance**: Clear separation of concerns, testable components
7. **Flexible Configuration**: YAML-based config with environment and CLI overrides

## Migration Benefits

- **Single Binary**: Replace multiple bash scripts with one Go executable
- **Type Safety**: Eliminate bash variable and subprocess issues
- **Better Error Messages**: Structured error handling with context
- **Improved Performance**: Native parallel execution and caching
- **Enhanced Observability**: Structured logging and detailed reporting
- **Easier Testing**: Unit testable components vs bash script testing