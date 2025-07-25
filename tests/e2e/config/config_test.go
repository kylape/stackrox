package config

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLoadConfig(t *testing.T) {
	// Test loading default configuration
	cfg, err := LoadConfig("")
	require.NoError(t, err)
	assert.NotNil(t, cfg)

	// Verify defaults are set
	assert.Equal(t, "kubernetes", cfg.Cluster.Flavor)
	assert.Equal(t, "stackrox", cfg.StackRox.CentralNS)
	assert.Equal(t, "admin", cfg.StackRox.Username)
	assert.True(t, cfg.Build.Enabled)
	assert.True(t, cfg.Tests.GoTest.Enabled)
}

func TestLoadConfigFromFile(t *testing.T) {
	// Create a temporary config file
	tempDir := t.TempDir()
	configFile := filepath.Join(tempDir, "test-config.yaml")
	
	configContent := `
cluster:
  flavor: openshift
stackrox:
  centralNamespace: test-ns
  username: testuser
build:
  enabled: false
`
	
	err := os.WriteFile(configFile, []byte(configContent), 0644)
	require.NoError(t, err)

	// Load configuration from file
	cfg, err := LoadConfig(configFile)
	require.NoError(t, err)

	// Verify file values override defaults
	assert.Equal(t, "openshift", cfg.Cluster.Flavor)
	assert.Equal(t, "test-ns", cfg.StackRox.CentralNS)
	assert.Equal(t, "testuser", cfg.StackRox.Username)
	assert.False(t, cfg.Build.Enabled)
}

func TestConfigValidation(t *testing.T) {
	cfg := GetDefaultConfig()
	
	// Valid configuration should pass
	err := cfg.Validate()
	assert.NoError(t, err)

	// Invalid cluster flavor should fail
	cfg.Cluster.Flavor = "invalid"
	err = cfg.Validate()
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid cluster flavor")

	// Reset and test StackRox validation
	cfg = GetDefaultConfig()
	cfg.StackRox.UseExisting = true
	cfg.StackRox.Password = "" // Required when using existing
	err = cfg.Validate()
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "password is required")
}

func TestEnvironmentOverrides(t *testing.T) {
	// Set environment variables
	os.Setenv("API_ENDPOINT", "test-endpoint:8443")
	os.Setenv("ROX_USERNAME", "test-user")
	defer func() {
		os.Unsetenv("API_ENDPOINT")
		os.Unsetenv("ROX_USERNAME")
	}()

	cfg, err := LoadConfig("")
	require.NoError(t, err)

	// Verify environment variables were applied
	assert.Equal(t, "test-endpoint:8443", cfg.StackRox.Endpoint)
	assert.Equal(t, "test-user", cfg.StackRox.Username)
}

func TestConfigSave(t *testing.T) {
	cfg := GetDefaultConfig()
	cfg.StackRox.Username = "saved-user"
	
	tempDir := t.TempDir()
	configFile := filepath.Join(tempDir, "saved-config.yaml")
	
	// Save configuration
	err := cfg.SaveConfig(configFile)
	require.NoError(t, err)

	// Load it back
	loadedCfg, err := LoadConfig(configFile)
	require.NoError(t, err)
	
	assert.Equal(t, cfg.StackRox.Username, loadedCfg.StackRox.Username)
}

func TestTimeoutValidation(t *testing.T) {
	// Valid timeout
	err := ValidateTimeout(30*time.Minute, "test.timeout")
	assert.NoError(t, err)

	// Zero timeout should fail
	err = ValidateTimeout(0, "test.timeout")
	assert.Error(t, err)

	// Excessive timeout should fail
	err = ValidateTimeout(25*time.Hour, "test.timeout")
	assert.Error(t, err)
}