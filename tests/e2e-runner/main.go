package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/stackrox/rox/tests/e2e/config"
	"gopkg.in/yaml.v3"
)

const (
	appName    = "e2e-runner"
	appVersion = "1.0.0"
)

// CLI holds the command line interface state
type CLI struct {
	config *config.Config
	logger *slog.Logger
}

// Flags holds all command line flags
type Flags struct {
	// Config flags
	ConfigFile string
	DryRun     bool
	Verbose    bool
	LogLevel   string
	LogFormat  string

	// Mode flags
	BuildOnly      bool
	GoTestOnly     bool
	Deploy         bool
	Cleanup        bool
	ShowConfig     bool
	ValidateConfig bool

	// Build flags
	BuildTargets string
	BuildTags    string

	// Test flags
	TestSuites  string
	TestTags    string  
	TestPackages string
	TestTimeout string
	Parallel    bool
	FailFast    bool

	// StackRox flags
	StackRoxUseExisting      bool
	StackRoxEndpoint         string
	StackRoxUsername         string
	StackRoxPassword         string
	StackRoxCentralNamespace string
	StackRoxSensorNamespace  string
	StackRoxSkipTLSVerify    bool

	// Cluster flags
	Kubeconfig      string
	KubeContext     string
	KubeNamespace   string
	ClusterFlavor   string

	// Artifacts flags
	ArtifactsDir string

	// Other flags
	Help    bool
	Version bool
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}

func run() error {
	// Parse command line flags
	flags := parseFlags()

	if flags.Help {
		printUsage()
		return nil
	}

	if flags.Version {
		fmt.Printf("%s version %s\n", appName, appVersion)
		return nil
	}

	// Setup logging
	logger := setupLogging(flags.LogLevel, flags.LogFormat, flags.Verbose)

	// Create CLI instance
	cli := &CLI{
		logger: logger,
	}

	// Load configuration
	cfg, err := cli.loadConfig(flags)
	if err != nil {
		return fmt.Errorf("failed to load configuration: %w", err)
	}
	cli.config = cfg

	// Apply flag overrides to configuration
	if err := cli.applyFlagOverrides(flags); err != nil {
		return fmt.Errorf("failed to apply flag overrides: %w", err)
	}

	// Validate configuration
	if err := cfg.Validate(); err != nil {
		return fmt.Errorf("configuration validation failed: %w", err)
	}

	// Handle special modes
	if flags.ShowConfig {
		return cli.showConfig()
	}

	if flags.ValidateConfig {
		logger.Info("Configuration is valid")
		return nil
	}

	// Setup context with signal handling
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Handle signals gracefully
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		sig := <-sigChan
		logger.Info("Received signal, shutting down", "signal", sig)
		cancel()
	}()

	// Execute the main logic
	return cli.execute(ctx, flags)
}

func parseFlags() *Flags {
	flags := &Flags{}

	// Config flags
	flag.StringVar(&flags.ConfigFile, "config", "", "Path to configuration file")
	flag.BoolVar(&flags.DryRun, "dry-run", false, "Show what would be done without executing")
	flag.BoolVar(&flags.Verbose, "verbose", false, "Enable verbose logging")
	flag.StringVar(&flags.LogLevel, "log-level", "info", "Log level (debug, info, warn, error)")
	flag.StringVar(&flags.LogFormat, "log-format", "text", "Log format (text, json)")

	// Mode flags
	flag.BoolVar(&flags.BuildOnly, "build-only", false, "Only build, don't run tests")
	flag.BoolVar(&flags.GoTestOnly, "go-test-only", false, "Only run Go tests")
	flag.BoolVar(&flags.Deploy, "deploy", false, "Deploy StackRox before running tests")
	flag.BoolVar(&flags.Cleanup, "cleanup", false, "Cleanup resources and exit")
	flag.BoolVar(&flags.ShowConfig, "show-config", false, "Show resolved configuration and exit")
	flag.BoolVar(&flags.ValidateConfig, "validate-config", false, "Validate configuration and exit")

	// Build flags
	flag.StringVar(&flags.BuildTargets, "build-targets", "", "Comma-separated list of build targets")
	flag.StringVar(&flags.BuildTags, "build-tags", "", "Comma-separated list of build tags")

	// Test flags
	flag.StringVar(&flags.TestSuites, "suites", "", "Comma-separated list of test suites to run")
	flag.StringVar(&flags.TestTags, "tags", "", "Comma-separated list of test tags")
	flag.StringVar(&flags.TestPackages, "packages", "", "Comma-separated list of Go packages to test")
	flag.StringVar(&flags.TestTimeout, "timeout", "", "Test timeout duration")
	flag.BoolVar(&flags.Parallel, "parallel", false, "Run tests in parallel")
	flag.BoolVar(&flags.FailFast, "fail-fast", false, "Stop on first test failure")

	// StackRox flags
	flag.BoolVar(&flags.StackRoxUseExisting, "stackrox.useExisting", false, "Use existing StackRox deployment")
	flag.StringVar(&flags.StackRoxEndpoint, "stackrox.endpoint", "", "StackRox API endpoint")
	flag.StringVar(&flags.StackRoxUsername, "stackrox.username", "", "StackRox username")
	flag.StringVar(&flags.StackRoxPassword, "stackrox.password", "", "StackRox password")
	flag.StringVar(&flags.StackRoxCentralNamespace, "stackrox.centralNamespace", "", "Central namespace")
	flag.StringVar(&flags.StackRoxSensorNamespace, "stackrox.sensorNamespace", "", "Sensor namespace")
	flag.BoolVar(&flags.StackRoxSkipTLSVerify, "stackrox.skipTLSVerify", false, "Skip TLS verification")

	// Cluster flags
	flag.StringVar(&flags.Kubeconfig, "kubeconfig", "", "Path to kubeconfig file")
	flag.StringVar(&flags.KubeContext, "kube-context", "", "Kubernetes context name")
	flag.StringVar(&flags.KubeNamespace, "kube-namespace", "", "Kubernetes namespace")
	flag.StringVar(&flags.ClusterFlavor, "cluster-flavor", "", "Cluster flavor (kubernetes, openshift)")

	// Artifacts flags
	flag.StringVar(&flags.ArtifactsDir, "artifacts-dir", "", "Directory to store test artifacts")

	// Other flags
	flag.BoolVar(&flags.Help, "help", false, "Show help message")
	flag.BoolVar(&flags.Help, "h", false, "Show help message")
	flag.BoolVar(&flags.Version, "version", false, "Show version information")

	flag.Parse()

	return flags
}

func setupLogging(logLevel, logFormat string, verbose bool) *slog.Logger {
	var level slog.Level
	switch strings.ToLower(logLevel) {
	case "debug":
		level = slog.LevelDebug
	case "info":
		level = slog.LevelInfo
	case "warn", "warning":
		level = slog.LevelWarn
	case "error":
		level = slog.LevelError
	default:
		level = slog.LevelInfo
	}

	if verbose {
		level = slog.LevelDebug
	}

	var handler slog.Handler
	opts := &slog.HandlerOptions{Level: level}

	switch strings.ToLower(logFormat) {
	case "json":
		handler = slog.NewJSONHandler(os.Stderr, opts)
	default:
		handler = slog.NewTextHandler(os.Stderr, opts)
	}

	return slog.New(handler)
}

func (cli *CLI) loadConfig(flags *Flags) (*config.Config, error) {
	if flags.ConfigFile == "" {
		// Try to find default config files
		possiblePaths := []string{
			"./e2e-config.yaml",
			"./tests/config/default.yaml",
			"~/.stackrox/e2e-config.yaml",
		}

		for _, path := range possiblePaths {
			if expanded, err := expandPath(path); err == nil {
				if _, err := os.Stat(expanded); err == nil {
					flags.ConfigFile = expanded
					cli.logger.Info("Using default config file", "path", expanded)
					break
				}
			}
		}
	}

	cfg, err := config.LoadConfig(flags.ConfigFile)
	if err != nil {
		return nil, fmt.Errorf("failed to load config: %w", err)
	}

	return cfg, nil
}

func (cli *CLI) applyFlagOverrides(flags *Flags) error {
	cfg := cli.config

	// Apply StackRox overrides
	if flags.StackRoxUseExisting {
		cfg.StackRox.UseExisting = true
	}
	if flags.StackRoxEndpoint != "" {
		cfg.StackRox.Endpoint = flags.StackRoxEndpoint
	}
	if flags.StackRoxUsername != "" {
		cfg.StackRox.Username = flags.StackRoxUsername
	}
	if flags.StackRoxPassword != "" {
		cfg.StackRox.Password = flags.StackRoxPassword
	}
	if flags.StackRoxCentralNamespace != "" {
		cfg.StackRox.CentralNS = flags.StackRoxCentralNamespace
	}
	if flags.StackRoxSensorNamespace != "" {
		cfg.StackRox.SensorNS = flags.StackRoxSensorNamespace
	}
	if flags.StackRoxSkipTLSVerify {
		cfg.StackRox.TLS.SkipVerify = true
	}

	// Apply cluster overrides
	if flags.Kubeconfig != "" {
		cfg.Cluster.Kubeconfig = flags.Kubeconfig
	}
	if flags.KubeContext != "" {
		cfg.Cluster.Context = flags.KubeContext
	}
	if flags.KubeNamespace != "" {
		cfg.Cluster.Namespace = flags.KubeNamespace
	}
	if flags.ClusterFlavor != "" {
		cfg.Cluster.Flavor = flags.ClusterFlavor
	}

	// Apply build overrides
	if flags.BuildTargets != "" {
		cfg.Build.Targets = strings.Split(flags.BuildTargets, ",")
	}
	if flags.BuildTags != "" {
		cfg.Build.Tags = strings.Split(flags.BuildTags, ",")
	}

	// Apply test overrides
	if flags.TestSuites != "" {
		cfg.Tests.Suites = strings.Split(flags.TestSuites, ",")
	}
	if flags.TestTags != "" {
		cfg.Tests.GoTest.Tags = strings.Split(flags.TestTags, ",")
	}
	if flags.TestPackages != "" {
		cfg.Tests.GoTest.Packages = strings.Split(flags.TestPackages, ",")
	}
	if flags.TestTimeout != "" {
		timeout, err := time.ParseDuration(flags.TestTimeout)
		if err != nil {
			return fmt.Errorf("invalid timeout format: %w", err)
		}
		cfg.Tests.Timeout = timeout
		cfg.Tests.GoTest.Timeout = timeout
	}
	if flags.Parallel {
		cfg.Tests.Parallel = true
	}
	if flags.FailFast {
		cfg.Tests.FailFast = true
	}

	// Apply artifacts overrides
	if flags.ArtifactsDir != "" {
		cfg.Artifacts.BaseDir = flags.ArtifactsDir
	}

	return nil
}

func (cli *CLI) showConfig() error {
	// Print configuration in YAML format to stdout
	data, err := yaml.Marshal(cli.config)
	if err != nil {
		return fmt.Errorf("failed to marshal config to YAML: %w", err)
	}
	fmt.Print(string(data))
	return nil
}

func (cli *CLI) execute(ctx context.Context, flags *Flags) error {
	cli.logger.Info("Starting e2e runner", 
		"version", appVersion,
		"config", flags.ConfigFile)

	// Handle cleanup mode
	if flags.Cleanup {
		return cli.cleanup(ctx)
	}

	// Handle build-only mode
	if flags.BuildOnly {
		return cli.buildOnly(ctx)
	}

	// Handle go-test-only mode
	if flags.GoTestOnly {
		return cli.goTestOnly(ctx)
	}

	// Handle full execution
	return cli.executeAll(ctx, flags)
}

func (cli *CLI) cleanup(ctx context.Context) error {
	cli.logger.Info("Starting cleanup")
	// TODO: Implement cleanup logic
	return fmt.Errorf("cleanup not implemented yet")
}

func (cli *CLI) buildOnly(ctx context.Context) error {
	cli.logger.Info("Starting build-only mode")
	// TODO: Implement build-only logic
	return fmt.Errorf("build-only not implemented yet")
}

func (cli *CLI) goTestOnly(ctx context.Context) error {
	cli.logger.Info("Starting go-test-only mode")
	// TODO: Implement go-test-only logic
	return fmt.Errorf("go-test-only not implemented yet")
}

func (cli *CLI) executeAll(ctx context.Context, flags *Flags) error {
	cli.logger.Info("Starting full execution")
	// TODO: Implement full execution logic
	return fmt.Errorf("full execution not implemented yet")
}

func expandPath(path string) (string, error) {
	if path == "" {
		return path, nil
	}
	
	if path[0] != '~' {
		return path, nil
	}
	
	if len(path) == 1 || path[1] == '/' {
		home, err := os.UserHomeDir()
		if err != nil {
			return "", fmt.Errorf("failed to get user home directory: %w", err)
		}
		return filepath.Join(home, path[1:]), nil
	}
	
	return "", fmt.Errorf("~user expansion not supported")
}

func printUsage() {
	fmt.Printf(`%s - StackRox E2E Test Runner

USAGE:
    %s [OPTIONS]

DESCRIPTION:
    A comprehensive test runner for StackRox E2E tests with support for building,
    deploying, and testing against existing or fresh StackRox deployments.

OPTIONS:
    Configuration:
        -config <file>              Configuration file path
        -dry-run                    Show what would be done without executing
        -verbose                    Enable verbose logging
        -log-level <level>          Log level (debug, info, warn, error)
        -log-format <format>        Log format (text, json)

    Execution Modes:
        -build-only                 Only build, don't run tests
        -go-test-only               Only run Go tests
        -deploy                     Deploy StackRox before running tests
        -cleanup                    Cleanup resources and exit
        -show-config                Show resolved configuration and exit
        -validate-config            Validate configuration and exit

    Build Options:
        -build-targets <targets>    Comma-separated list of build targets
        -build-tags <tags>          Comma-separated list of build tags

    Test Options:
        -suites <suites>           Comma-separated list of test suites
        -tags <tags>               Comma-separated list of test tags
        -packages <packages>       Comma-separated list of Go packages
        -timeout <duration>        Test timeout duration
        -parallel                  Run tests in parallel
        -fail-fast                 Stop on first test failure

    StackRox Options:
        -stackrox.useExisting      Use existing StackRox deployment
        -stackrox.endpoint <url>   StackRox API endpoint
        -stackrox.username <user>  StackRox username
        -stackrox.password <pass>  StackRox password
        -stackrox.centralNamespace Central namespace
        -stackrox.sensorNamespace  Sensor namespace
        -stackrox.skipTLSVerify    Skip TLS verification

    Cluster Options:
        -kubeconfig <file>         Path to kubeconfig file
        -kube-context <context>    Kubernetes context name
        -kube-namespace <ns>       Kubernetes namespace
        -cluster-flavor <flavor>   Cluster flavor (kubernetes, openshift)

    Other Options:
        -artifacts-dir <dir>       Directory to store test artifacts
        -help, -h                  Show this help message
        -version                   Show version information

EXAMPLES:
    # Test against existing StackRox deployment
    %s -config existing.yaml -stackrox.useExisting

    # Build, deploy fresh, and test
    %s -config fresh.yaml -deploy -build-targets central,sensor

    # Run only Go tests with custom tags
    %s -go-test-only -tags "test,test_e2e" -packages "./tests"

    # Run specific test suites in parallel
    %s -suites api,roxctl -parallel -timeout 30m

    # Show configuration without running
    %s -config my-config.yaml -show-config

CONFIGURATION:
    Configuration can be provided via YAML files and overridden with command-line
    flags and environment variables. See the examples in tests/config/ for sample
    configurations.

`, appName, appName, appName, appName, appName, appName, appName)
}