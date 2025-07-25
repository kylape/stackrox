package config

import (
	"fmt"
	"os"
	"path/filepath"
	"time"

	"gopkg.in/yaml.v3"
)

// Config represents the complete configuration for the e2e test runner
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

type ClusterConfig struct {
	Kubeconfig   string          `yaml:"kubeconfig" env:"KUBECONFIG"`
	Context      string          `yaml:"context" env:"KUBE_CONTEXT"`
	Namespace    string          `yaml:"namespace" env:"KUBE_NAMESPACE"`
	Flavor       string          `yaml:"flavor" env:"ORCHESTRATOR_FLAVOR"` // kubernetes, openshift
	Capabilities map[string]bool `yaml:"capabilities"`
}

type StackRoxConfig struct {
	// Existing deployment settings
	UseExisting bool   `yaml:"useExisting"`
	CentralNS   string `yaml:"centralNamespace"`
	SensorNS    string `yaml:"sensorNamespace"`

	// Connection settings
	Endpoint string `yaml:"endpoint" env:"API_ENDPOINT"`
	Username string `yaml:"username" env:"ROX_USERNAME"`
	Password string `yaml:"password" env:"ROX_ADMIN_PASSWORD"`

	// TLS settings
	TLS TLSConfig `yaml:"tls"`

	// Feature flags
	FeatureFlags map[string]string `yaml:"featureFlags"`
}

type TLSConfig struct {
	SkipVerify bool   `yaml:"skipVerify"`
	CAFile     string `yaml:"caFile"`
	CertFile   string `yaml:"certFile"`
	KeyFile    string `yaml:"keyFile"`
}

type BuildConfig struct {
	Enabled     bool              `yaml:"enabled"`
	Targets     []string          `yaml:"targets"`
	Tags        []string          `yaml:"tags"`
	Parallel    bool              `yaml:"parallel"`
	MaxParallel int               `yaml:"maxParallel"`
	Cache       bool              `yaml:"cache"`
	Environment map[string]string `yaml:"environment"`

	// Docker/Image settings
	Registry   string `yaml:"registry"`
	ImageTag   string `yaml:"imageTag"`
	PushImages bool   `yaml:"pushImages"`
}

type TestConfig struct {
	// Go test settings (from go-test.sh)
	GoTest GoTestConfig `yaml:"goTest"`

	// Test suite settings
	Suites   []string      `yaml:"suites"`
	Parallel bool          `yaml:"parallel"`
	FailFast bool          `yaml:"failFast"`
	Timeout  time.Duration `yaml:"timeout"`

	// Suite-specific configurations
	API         APITestConfig     `yaml:"api"`
	Roxctl      RoxctlTestConfig  `yaml:"roxctl"`
	Proxy       ProxyTestConfig   `yaml:"proxy"`
	Destructive DestructiveConfig `yaml:"destructive"`
}

type GoTestConfig struct {
	Enabled      bool          `yaml:"enabled"`
	Tags         []string      `yaml:"tags"`
	Packages     []string      `yaml:"packages"`
	Timeout      time.Duration `yaml:"timeout"`
	Race         bool          `yaml:"race"`
	Cover        bool          `yaml:"cover"`
	CoverProfile string        `yaml:"coverProfile"`
	Verbose      bool          `yaml:"verbose"`
	Parallel     int           `yaml:"parallel"`
	Count        int           `yaml:"count"`
	Short        bool          `yaml:"short"`
	Args         []string      `yaml:"args"`
}

type APITestConfig struct {
	Enabled bool          `yaml:"enabled"`
	Tags    []string      `yaml:"tags"`
	Timeout time.Duration `yaml:"timeout"`
	Race    bool          `yaml:"race"`
	Cover   bool          `yaml:"cover"`
}

type RoxctlTestConfig struct {
	Enabled bool          `yaml:"enabled"`
	Tests   []RoxctlTest  `yaml:"tests"`
	Timeout time.Duration `yaml:"timeout"`
}

type RoxctlTest struct {
	Name        string            `yaml:"name"`
	Script      string            `yaml:"script"`
	Args        []string          `yaml:"args"`
	Environment map[string]string `yaml:"env"`
	Timeout     time.Duration     `yaml:"timeout"`
}

type ProxyTestConfig struct {
	Enabled     bool          `yaml:"enabled"`
	ServerName  string        `yaml:"serverName"`
	Timeout     time.Duration `yaml:"timeout"`
	SkipCleanup bool          `yaml:"skipCleanup"`
}

type DestructiveConfig struct {
	Enabled bool          `yaml:"enabled"`
	Timeout time.Duration `yaml:"timeout"`
}

type DeployConfig struct {
	Mode string `yaml:"mode"` // none, operator, helm

	// Cleanup settings
	Cleanup bool `yaml:"cleanup"`

	// Component settings
	Central CentralDeployConfig `yaml:"central"`
	Sensor  SensorDeployConfig  `yaml:"sensor"`
}

type CentralDeployConfig struct {
	Namespace string `yaml:"namespace"`
	Replicas  int    `yaml:"replicas"`
}

type SensorDeployConfig struct {
	Namespace        string `yaml:"namespace"`
	CollectionMethod string `yaml:"collectionMethod"`
}

type ArtifactsConfig struct {
	BaseDir string   `yaml:"baseDir"`
	Collect Collect  `yaml:"collect"`
	Formats []string `yaml:"formats"`
}

type Collect struct {
	Logs     bool `yaml:"logs"`
	Events   bool `yaml:"events"`
	Describe bool `yaml:"describe"`
}

// LoadConfig loads configuration from file with environment variable overrides
func LoadConfig(configPath string) (*Config, error) {
	config := &Config{}

	// Set defaults first
	setDefaults(config)

	// Load from file if provided
	if configPath != "" {
		if err := loadFromFile(config, configPath); err != nil {
			return nil, fmt.Errorf("failed to load config from file %s: %w", configPath, err)
		}
	}

	// Apply environment variable overrides
	if err := applyEnvOverrides(config); err != nil {
		return nil, fmt.Errorf("failed to apply environment overrides: %w", err)
	}

	return config, nil
}

// loadFromFile loads configuration from a YAML file
func loadFromFile(config *Config, path string) error {
	// Expand ~ to home directory
	if path[0] == '~' {
		home, err := os.UserHomeDir()
		if err != nil {
			return fmt.Errorf("failed to get user home directory: %w", err)
		}
		path = filepath.Join(home, path[1:])
	}

	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("failed to read config file: %w", err)
	}

	if err := yaml.Unmarshal(data, config); err != nil {
		return fmt.Errorf("failed to unmarshal YAML: %w", err)
	}

	return nil
}

// applyEnvOverrides applies environment variable overrides to the configuration
func applyEnvOverrides(config *Config) error {
	// Apply environment variables using struct tags
	if kubeconfig := os.Getenv("KUBECONFIG"); kubeconfig != "" {
		config.Cluster.Kubeconfig = kubeconfig
	}
	if context := os.Getenv("KUBE_CONTEXT"); context != "" {
		config.Cluster.Context = context
	}
	if namespace := os.Getenv("KUBE_NAMESPACE"); namespace != "" {
		config.Cluster.Namespace = namespace
	}
	if flavor := os.Getenv("ORCHESTRATOR_FLAVOR"); flavor != "" {
		config.Cluster.Flavor = flavor
	}

	if endpoint := os.Getenv("API_ENDPOINT"); endpoint != "" {
		config.StackRox.Endpoint = endpoint
	}
	if username := os.Getenv("ROX_USERNAME"); username != "" {
		config.StackRox.Username = username
	}
	if password := os.Getenv("ROX_ADMIN_PASSWORD"); password != "" {
		config.StackRox.Password = password
	}

	return nil
}

// SaveConfig saves the configuration to a YAML file
func (c *Config) SaveConfig(path string) error {
	data, err := yaml.Marshal(c)
	if err != nil {
		return fmt.Errorf("failed to marshal config to YAML: %w", err)
	}

	if err := os.WriteFile(path, data, 0644); err != nil {
		return fmt.Errorf("failed to write config file: %w", err)
	}

	return nil
}