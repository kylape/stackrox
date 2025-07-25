package config

import (
	"os"
	"path/filepath"
	"time"
)

// setDefaults sets default values for the configuration
func setDefaults(config *Config) {
	// Cluster defaults
	if config.Cluster.Kubeconfig == "" {
		if home, err := os.UserHomeDir(); err == nil {
			config.Cluster.Kubeconfig = filepath.Join(home, ".kube", "config")
		}
	}
	if config.Cluster.Flavor == "" {
		config.Cluster.Flavor = "kubernetes"
	}
	if config.Cluster.Capabilities == nil {
		config.Cluster.Capabilities = make(map[string]bool)
	}

	// StackRox defaults
	if config.StackRox.CentralNS == "" {
		config.StackRox.CentralNS = "stackrox"
	}
	if config.StackRox.SensorNS == "" {
		config.StackRox.SensorNS = "stackrox"
	}
	if config.StackRox.Username == "" {
		config.StackRox.Username = "admin"
	}
	if config.StackRox.Endpoint == "" {
		config.StackRox.Endpoint = "localhost:8000"
	}
	// TLS defaults
	config.StackRox.TLS.SkipVerify = true // Default to skip verify for dev environments

	// Build defaults
	config.Build.Enabled = true
	if len(config.Build.Targets) == 0 {
		config.Build.Targets = []string{"central", "sensor", "roxctl"}
	}
	config.Build.Parallel = true
	if config.Build.MaxParallel == 0 {
		config.Build.MaxParallel = 4
	}
	config.Build.Cache = true
	if config.Build.Environment == nil {
		config.Build.Environment = make(map[string]string)
	}

	// Test defaults
	setTestDefaults(&config.Tests)

	// Deploy defaults
	if config.Deploy.Mode == "" {
		config.Deploy.Mode = "none"
	}
	if config.Deploy.Central.Namespace == "" {
		config.Deploy.Central.Namespace = config.StackRox.CentralNS
	}
	if config.Deploy.Central.Replicas == 0 {
		config.Deploy.Central.Replicas = 1
	}
	if config.Deploy.Sensor.Namespace == "" {
		config.Deploy.Sensor.Namespace = config.StackRox.SensorNS
	}
	if config.Deploy.Sensor.CollectionMethod == "" {
		config.Deploy.Sensor.CollectionMethod = "core_bpf"
	}

	// Artifacts defaults
	if config.Artifacts.BaseDir == "" {
		config.Artifacts.BaseDir = "/tmp/e2e-artifacts"
	}
	if len(config.Artifacts.Formats) == 0 {
		config.Artifacts.Formats = []string{"junit", "json"}
	}
	// Collect defaults
	config.Artifacts.Collect.Logs = true
	config.Artifacts.Collect.Events = true
	config.Artifacts.Collect.Describe = true
}

// setTestDefaults sets default values for test configuration
func setTestDefaults(tests *TestConfig) {
	// Go test defaults
	setGoTestDefaults(&tests.GoTest)

	// Test suite defaults
	if len(tests.Suites) == 0 {
		tests.Suites = []string{"api"}
	}
	tests.Parallel = true
	tests.FailFast = false
	if tests.Timeout == 0 {
		tests.Timeout = 45 * time.Minute
	}

	// API test defaults
	tests.API.Enabled = true
	if len(tests.API.Tags) == 0 {
		tests.API.Tags = []string{"test", "test_e2e"}
	}
	if tests.API.Timeout == 0 {
		tests.API.Timeout = 30 * time.Minute
	}
	tests.API.Race = true
	tests.API.Cover = true

	// Roxctl test defaults
	tests.Roxctl.Enabled = true
	if tests.Roxctl.Timeout == 0 {
		tests.Roxctl.Timeout = 15 * time.Minute
	}

	// Proxy test defaults
	tests.Proxy.Enabled = true
	if tests.Proxy.ServerName == "" {
		tests.Proxy.ServerName = "localhost"
	}
	if tests.Proxy.Timeout == 0 {
		tests.Proxy.Timeout = 10 * time.Minute
	}

	// Destructive test defaults
	tests.Destructive.Enabled = true
	if tests.Destructive.Timeout == 0 {
		tests.Destructive.Timeout = 20 * time.Minute
	}
}

// setGoTestDefaults sets default values for Go test configuration
func setGoTestDefaults(goTest *GoTestConfig) {
	goTest.Enabled = true
	if len(goTest.Tags) == 0 {
		goTest.Tags = []string{"test", "test_e2e"}
	}
	if len(goTest.Packages) == 0 {
		goTest.Packages = []string{"./tests"}
	}
	if goTest.Timeout == 0 {
		goTest.Timeout = 30 * time.Minute
	}
	goTest.Race = true
	goTest.Cover = true
	if goTest.CoverProfile == "" {
		goTest.CoverProfile = "coverage.out"
	}
	goTest.Verbose = true
	if goTest.Parallel == 0 {
		goTest.Parallel = 5
	}
	if goTest.Count == 0 {
		goTest.Count = 1
	}
}

// GetDefaultConfig returns a configuration with all defaults set
func GetDefaultConfig() *Config {
	config := &Config{}
	setDefaults(config)
	return config
}