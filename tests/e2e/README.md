# StackRox E2E Test Runner

A Go-based test runner for StackRox E2E tests with support for existing deployments, integrated build functionality, and centralized configuration management.

## Phase 1 Implementation Status

This is the Phase 1 implementation of the E2E runner design. The following components are implemented:

### ✅ Completed Components

1. **Project Structure**: Complete directory structure under `tests/`
2. **Configuration System**: YAML-based configuration with environment overrides
3. **CLI Framework**: Comprehensive command-line interface with flag support
4. **Utilities**: Command execution, retry logic, and file operations
5. **Validation**: Configuration validation with detailed error messages

### 🚧 Phase 1 Components

- **Configuration System** (`tests/e2e/config/`)
  - YAML configuration loading with defaults
  - Environment variable overrides
  - Comprehensive validation
  - Support for existing deployment configuration

- **CLI Framework** (`tests/e2e-runner/main.go`)
  - Comprehensive flag-based configuration
  - Multiple execution modes (build-only, test-only, etc.)
  - Signal handling and graceful shutdown
  - Structured logging

- **Utilities** (`tests/e2e/utils/`)
  - Command execution with streaming output
  - Retry logic with exponential backoff
  - File operations with path expansion
  - Comprehensive error handling

## Usage

### Building the E2E Runner

```bash
# Build the e2e-runner binary
go build -o bin/e2e-runner ./tests/e2e-runner

# Or run directly
go run ./tests/e2e-runner [options]
```

### Basic Usage Examples

```bash
# Show help
./bin/e2e-runner -help

# Test against existing StackRox deployment
./bin/e2e-runner -config tests/config/examples/existing-deployment.yaml

# Show resolved configuration
./bin/e2e-runner -config tests/config/default.yaml -show-config

# Validate configuration
./bin/e2e-runner -config tests/config/examples/fresh-deployment.yaml -validate-config

# Override config with flags
./bin/e2e-runner \
  -stackrox.useExisting=true \
  -stackrox.endpoint=localhost:8000 \
  -suites=api,roxctl \
  -verbose
```

### Configuration Files

Example configurations are provided in `tests/config/examples/`:

- `existing-deployment.yaml` - For testing against existing StackRox
- `fresh-deployment.yaml` - For fresh deployments  
- `openshift.yaml` - OpenShift-specific configuration

## Configuration

The runner uses a hierarchical configuration system:

1. **Default values** (in code)
2. **YAML configuration file** (if provided)
3. **Environment variables** (standard StackRox env vars)
4. **Command-line flags** (highest priority)

### Key Configuration Sections

- `cluster`: Kubernetes cluster connection settings
- `stackrox`: StackRox deployment and connection settings
- `build`: Build system configuration (Phase 2)
- `tests`: Test execution configuration
- `deploy`: Deployment configuration (Phase 2)
- `artifacts`: Test artifact collection settings

## Testing

Run the tests for the implemented components:

```bash
# Test configuration system
go test ./tests/e2e/config

# Test utilities
go test ./tests/e2e/utils

# Test with verbose output
go test -v ./tests/e2e/...
```

## Next Steps (Phase 2+)

The following components will be implemented in subsequent phases:

1. **Build System Integration** - Replace Makefile functionality
2. **Go Test Integration** - Replace go-test.sh functionality
3. **Test Suite Framework** - Pluggable test suite architecture
4. **Kubernetes Integration** - Native client-go usage
5. **Health Monitoring** - Component status and log analysis
6. **Artifact Collection** - Structured artifact gathering

## Development

To extend the runner:

1. Add new configuration options to `config/config.go`
2. Update validation in `config/validation.go`
3. Add CLI flags in `e2e-runner/main.go`
4. Implement new functionality in appropriate packages

The modular design allows for incremental implementation of additional features while maintaining backward compatibility.