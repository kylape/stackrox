package cmd

import (
	"encoding/json"
	"fmt"
	"io"
	"os"

	"github.com/spf13/cobra"
	"github.com/stackrox/rox/acscli/internal/output"
)

var (
	// Global flags
	outputFormat string
	jsonInput    string
	dryRun       bool
	fields       string
	endpoint     string
	apiToken     string
	insecure     bool

	// Version info (set at build time)
	version   = "dev"
	commit    = "unknown"
	buildDate = "unknown"
)

// rootCmd represents the base command
var rootCmd = &cobra.Command{
	Use:   "acs",
	Short: "ACS CLI - Agentic-first CLI for Red Hat Advanced Cluster Security",
	Long: `ACS CLI provides full API access to Red Hat Advanced Cluster Security (StackRox).

Designed for both human users and AI agents, with features like:
  - JSON-first output (default when not a TTY)
  - Schema introspection (acs schema <service>.<method>)
  - Raw JSON input (--json flag)
  - Dry-run mode for mutations (--dry-run)
  - Field filtering (--fields)

Examples:
  # Scan an image
  acs image scan --image quay.io/myorg/app:latest

  # List policies with field filtering
  acs policy list --fields id,name,severity

  # Create a policy from JSON
  acs policy create --json '{"name": "My Policy", ...}'

  # Get schema for a method
  acs schema image.scan

  # Use a workflow skill
  acs +check-image quay.io/myorg/app:latest`,
	SilenceUsage:  true,
	SilenceErrors: true,
	PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
		// Determine output format based on TTY
		if outputFormat == "" {
			if isTerminal(os.Stdout) {
				outputFormat = "table"
			} else {
				outputFormat = "json"
			}
		}
		return nil
	},
}

// Execute runs the root command
func Execute() error {
	err := rootCmd.Execute()
	if err != nil {
		// Output error as JSON if in JSON mode
		if outputFormat == "json" || !isTerminal(os.Stderr) {
			errObj := map[string]interface{}{
				"error":   true,
				"message": err.Error(),
			}
			json.NewEncoder(os.Stderr).Encode(errObj)
		} else {
			fmt.Fprintln(os.Stderr, "Error:", err)
		}
	}
	return err
}

func init() {
	// Output format
	rootCmd.PersistentFlags().StringVarP(&outputFormat, "output", "o", "",
		"Output format: json, table, ndjson (default: json if not TTY, table if TTY)")

	// JSON input for mutations
	rootCmd.PersistentFlags().StringVar(&jsonInput, "json", "",
		"JSON input for request body (use @filename to read from file)")

	// Dry-run mode
	rootCmd.PersistentFlags().BoolVar(&dryRun, "dry-run", false,
		"Validate request without executing (for mutations)")

	// Field filtering
	rootCmd.PersistentFlags().StringVar(&fields, "fields", "",
		"Comma-separated list of fields to include in response")

	// Connection settings
	rootCmd.PersistentFlags().StringVarP(&endpoint, "endpoint", "e", "",
		"ACS Central endpoint (env: ROX_ENDPOINT)")
	rootCmd.PersistentFlags().StringVar(&apiToken, "token", "",
		"API token for authentication (env: ROX_API_TOKEN)")
	rootCmd.PersistentFlags().BoolVar(&insecure, "insecure", false,
		"Skip TLS certificate verification")

	// Add subcommands
	rootCmd.AddCommand(newVersionCmd())
	rootCmd.AddCommand(newSchemaCmd())
}

// isTerminal checks if the given writer is a terminal
func isTerminal(w io.Writer) bool {
	if f, ok := w.(*os.File); ok {
		stat, err := f.Stat()
		if err != nil {
			return false
		}
		return (stat.Mode() & os.ModeCharDevice) != 0
	}
	return false
}

// GetOutputFormat returns the current output format
func GetOutputFormat() string {
	return outputFormat
}

// GetDryRun returns whether dry-run mode is enabled
func GetDryRun() bool {
	return dryRun
}

// GetFields returns the field filter
func GetFields() string {
	return fields
}

// GetJSONInput returns the JSON input string
func GetJSONInput() string {
	return jsonInput
}

// NewOutputWriter creates an output writer based on current settings
func NewOutputWriter() output.Writer {
	switch outputFormat {
	case "json":
		return output.NewJSONWriter(os.Stdout)
	case "ndjson":
		return output.NewNDJSONWriter(os.Stdout)
	case "table":
		return output.NewTableWriter(os.Stdout)
	default:
		return output.NewJSONWriter(os.Stdout)
	}
}
