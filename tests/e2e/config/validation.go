package config

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// ValidationError represents a configuration validation error
type ValidationError struct {
	Field   string
	Message string
}

func (e ValidationError) Error() string {
	return fmt.Sprintf("validation error for field %s: %s", e.Field, e.Message)
}

// ValidationErrors represents multiple validation errors
type ValidationErrors []ValidationError

func (e ValidationErrors) Error() string {
	if len(e) == 0 {
		return "no validation errors"
	}
	if len(e) == 1 {
		return e[0].Error()
	}

	var messages []string
	for _, err := range e {
		messages = append(messages, err.Error())
	}
	return fmt.Sprintf("multiple validation errors: %s", strings.Join(messages, "; "))
}

// Validate validates the configuration and returns any errors
func (c *Config) Validate() error {
	var errors ValidationErrors

	// Validate cluster configuration
	if err := c.validateCluster(); err != nil {
		errors = append(errors, err...)
	}

	// Validate StackRox configuration
	if err := c.validateStackRox(); err != nil {
		errors = append(errors, err...)
	}

	// Validate build configuration
	if err := c.validateBuild(); err != nil {
		errors = append(errors, err...)
	}

	// Validate test configuration
	if err := c.validateTests(); err != nil {
		errors = append(errors, err...)
	}

	// Validate deploy configuration
	if err := c.validateDeploy(); err != nil {
		errors = append(errors, err...)
	}

	// Validate artifacts configuration
	if err := c.validateArtifacts(); err != nil {
		errors = append(errors, err...)
	}

	if len(errors) > 0 {
		return errors
	}

	return nil
}

// validateCluster validates cluster configuration
func (c *Config) validateCluster() ValidationErrors {
	var errors ValidationErrors

	// Validate kubeconfig file exists
	if c.Cluster.Kubeconfig != "" {
		kubeconfig := c.Cluster.Kubeconfig
		if kubeconfig[0] == '~' {
			if home, err := os.UserHomeDir(); err == nil {
				kubeconfig = filepath.Join(home, kubeconfig[1:])
			}
		}
		if _, err := os.Stat(kubeconfig); os.IsNotExist(err) {
			errors = append(errors, ValidationError{
				Field:   "cluster.kubeconfig",
				Message: fmt.Sprintf("kubeconfig file does not exist: %s", kubeconfig),
			})
		}
	}

	// Validate cluster flavor
	validFlavors := []string{"kubernetes", "openshift"}
	if c.Cluster.Flavor != "" && !contains(validFlavors, c.Cluster.Flavor) {
		errors = append(errors, ValidationError{
			Field:   "cluster.flavor",
			Message: fmt.Sprintf("invalid cluster flavor %s, must be one of: %s", c.Cluster.Flavor, strings.Join(validFlavors, ", ")),
		})
	}

	return errors
}

// validateStackRox validates StackRox configuration
func (c *Config) validateStackRox() ValidationErrors {
	var errors ValidationErrors

	// If using existing deployment, validate required fields
	if c.StackRox.UseExisting {
		if c.StackRox.Endpoint == "" {
			errors = append(errors, ValidationError{
				Field:   "stackrox.endpoint",
				Message: "endpoint is required when using existing deployment",
			})
		}
		if c.StackRox.Username == "" {
			errors = append(errors, ValidationError{
				Field:   "stackrox.username",
				Message: "username is required when using existing deployment",
			})
		}
		if c.StackRox.Password == "" {
			errors = append(errors, ValidationError{
				Field:   "stackrox.password",
				Message: "password is required when using existing deployment",
			})
		}
	}

	// Validate TLS configuration
	if c.StackRox.TLS.CAFile != "" {
		if _, err := os.Stat(c.StackRox.TLS.CAFile); os.IsNotExist(err) {
			errors = append(errors, ValidationError{
				Field:   "stackrox.tls.caFile",
				Message: fmt.Sprintf("CA file does not exist: %s", c.StackRox.TLS.CAFile),
			})
		}
	}

	return errors
}

// validateBuild validates build configuration
func (c *Config) validateBuild() ValidationErrors {
	var errors ValidationErrors

	// Validate max parallel
	if c.Build.MaxParallel < 1 {
		errors = append(errors, ValidationError{
			Field:   "build.maxParallel",
			Message: "maxParallel must be at least 1",
		})
	}

	// Validate build targets if specified
	validTargets := []string{"all", "proto", "central", "sensor", "roxctl", "scanner", "migrator", "admission-control"}
	for _, target := range c.Build.Targets {
		if !contains(validTargets, target) {
			errors = append(errors, ValidationError{
				Field:   "build.targets",
				Message: fmt.Sprintf("invalid build target %s, valid targets: %s", target, strings.Join(validTargets, ", ")),
			})
		}
	}

	return errors
}

// validateTests validates test configuration
func (c *Config) validateTests() ValidationErrors {
	var errors ValidationErrors

	// Validate test timeout
	if c.Tests.Timeout <= 0 {
		errors = append(errors, ValidationError{
			Field:   "tests.timeout",
			Message: "timeout must be greater than 0",
		})
	}

	// Validate test suites
	validSuites := []string{"api", "roxctl", "proxy", "destructive"}
	for _, suite := range c.Tests.Suites {
		if !contains(validSuites, suite) {
			errors = append(errors, ValidationError{
				Field:   "tests.suites",
				Message: fmt.Sprintf("invalid test suite %s, valid suites: %s", suite, strings.Join(validSuites, ", ")),
			})
		}
	}

	// Validate Go test configuration
	if c.Tests.GoTest.Enabled {
		if c.Tests.GoTest.Timeout <= 0 {
			errors = append(errors, ValidationError{
				Field:   "tests.goTest.timeout",
				Message: "goTest timeout must be greater than 0",
			})
		}
		if c.Tests.GoTest.Parallel < 1 {
			errors = append(errors, ValidationError{
				Field:   "tests.goTest.parallel",
				Message: "goTest parallel must be at least 1",
			})
		}
		if c.Tests.GoTest.Count < 1 {
			errors = append(errors, ValidationError{
				Field:   "tests.goTest.count",
				Message: "goTest count must be at least 1",
			})
		}
	}

	// Validate individual test suite timeouts
	if c.Tests.API.Timeout <= 0 {
		errors = append(errors, ValidationError{
			Field:   "tests.api.timeout",
			Message: "API test timeout must be greater than 0",
		})
	}
	if c.Tests.Roxctl.Timeout <= 0 {
		errors = append(errors, ValidationError{
			Field:   "tests.roxctl.timeout",
			Message: "roxctl test timeout must be greater than 0",
		})
	}

	return errors
}

// validateDeploy validates deployment configuration
func (c *Config) validateDeploy() ValidationErrors {
	var errors ValidationErrors

	// Validate deploy mode
	validModes := []string{"none", "operator", "helm"}
	if !contains(validModes, c.Deploy.Mode) {
		errors = append(errors, ValidationError{
			Field:   "deploy.mode",
			Message: fmt.Sprintf("invalid deploy mode %s, must be one of: %s", c.Deploy.Mode, strings.Join(validModes, ", ")),
		})
	}

	// Validate deployment configuration consistency
	if c.StackRox.UseExisting && c.Deploy.Mode != "none" {
		errors = append(errors, ValidationError{
			Field:   "deploy.mode",
			Message: "deploy mode must be 'none' when using existing StackRox deployment",
		})
	}

	// Validate central configuration
	if c.Deploy.Central.Replicas < 1 {
		errors = append(errors, ValidationError{
			Field:   "deploy.central.replicas",
			Message: "central replicas must be at least 1",
		})
	}

	// Validate sensor collection method
	validCollectionMethods := []string{"core_bpf", "ebpf", "kernel_module", "no_collection"}
	if c.Deploy.Sensor.CollectionMethod != "" && !contains(validCollectionMethods, c.Deploy.Sensor.CollectionMethod) {
		errors = append(errors, ValidationError{
			Field:   "deploy.sensor.collectionMethod",
			Message: fmt.Sprintf("invalid collection method %s, must be one of: %s", c.Deploy.Sensor.CollectionMethod, strings.Join(validCollectionMethods, ", ")),
		})
	}

	return errors
}

// validateArtifacts validates artifacts configuration
func (c *Config) validateArtifacts() ValidationErrors {
	var errors ValidationErrors

	// Validate base directory
	if c.Artifacts.BaseDir == "" {
		errors = append(errors, ValidationError{
			Field:   "artifacts.baseDir",
			Message: "baseDir cannot be empty",
		})
	}

	// Validate formats
	validFormats := []string{"junit", "json", "yaml"}
	for _, format := range c.Artifacts.Formats {
		if !contains(validFormats, format) {
			errors = append(errors, ValidationError{
				Field:   "artifacts.formats",
				Message: fmt.Sprintf("invalid format %s, valid formats: %s", format, strings.Join(validFormats, ", ")),
			})
		}
	}

	return errors
}

// contains checks if a slice contains a string
func contains(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}

// ValidateTimeout validates a timeout duration
func ValidateTimeout(timeout time.Duration, fieldName string) error {
	if timeout <= 0 {
		return ValidationError{
			Field:   fieldName,
			Message: "timeout must be greater than 0",
		}
	}
	if timeout > 24*time.Hour {
		return ValidationError{
			Field:   fieldName,
			Message: "timeout cannot exceed 24 hours",
		}
	}
	return nil
}