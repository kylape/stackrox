// Package skills implements high-level workflow commands for the acs CLI.
// Skills combine multiple API calls into common workflows, reducing agent
// context usage and providing semantic shortcuts.
//
// Skills are prefixed with "+" to distinguish them from raw API commands:
//   - acs +check-image quay.io/myorg/app:latest
//   - acs +policy-export --dir ./policies
package skills

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/spf13/cobra"
	"github.com/stackrox/rox/acscli/internal/client"
)

// RegisterSkills adds all skill commands to the root command
func RegisterSkills(root *cobra.Command) {
	root.AddCommand(NewCheckImageCmd())
	root.AddCommand(NewPolicyExportCmd())
	root.AddCommand(NewPolicyImportCmd())
	root.AddCommand(NewComplianceReportCmd())
}

// getClient creates an API client from environment variables
func getClient() (*client.Client, error) {
	cfg := client.Config{
		Endpoint: os.Getenv("ROX_ENDPOINT"),
		Token:    os.Getenv("ROX_API_TOKEN"),
		Insecure: os.Getenv("ROX_INSECURE") == "true",
	}
	return client.NewClient(cfg)
}

// outputResult handles output formatting based on the format flag
func outputResult(result interface{}, format string) error {
	// Auto-detect format based on TTY
	if format == "" {
		if fileInfo, _ := os.Stdout.Stat(); (fileInfo.Mode() & os.ModeCharDevice) != 0 {
			format = "json" // Use JSON with pretty-print for TTY
		} else {
			format = "json"
		}
	}

	enc := json.NewEncoder(os.Stdout)
	if format != "compact" {
		enc.SetIndent("", "  ")
	}
	return enc.Encode(result)
}

// outputError writes an error to stderr in JSON format
func outputError(err error) {
	errObj := map[string]interface{}{
		"error":   true,
		"message": err.Error(),
	}
	json.NewEncoder(os.Stderr).Encode(errObj)
}

// SkillResult is the common result structure for skill commands
type SkillResult struct {
	Skill   string      `json:"skill"`
	Status  string      `json:"status"` // "success", "fail", "partial"
	Summary string      `json:"summary,omitempty"`
	Data    interface{} `json:"data,omitempty"`
	Errors  []string    `json:"errors,omitempty"`
}

// NewSkillResult creates a new skill result
func NewSkillResult(skill string) *SkillResult {
	return &SkillResult{
		Skill:  skill,
		Status: "success",
		Errors: []string{},
	}
}

// AddError adds an error to the result and updates status
func (r *SkillResult) AddError(err error) {
	r.Errors = append(r.Errors, err.Error())
	if r.Status == "success" {
		r.Status = "partial"
	}
}

// SetFailed marks the result as failed
func (r *SkillResult) SetFailed() {
	r.Status = "fail"
}

// CVESummary summarizes vulnerability counts by severity
type CVESummary struct {
	Critical int `json:"critical"`
	High     int `json:"high"`
	Medium   int `json:"medium"`
	Low      int `json:"low"`
	Total    int `json:"total"`
	Fixable  int `json:"fixable"`
}

// PolicyViolation represents a policy violation
type PolicyViolation struct {
	PolicyID   string `json:"policy_id"`
	PolicyName string `json:"policy_name"`
	Severity   string `json:"severity"`
	Message    string `json:"message,omitempty"`
}

// formatSeverityDistribution creates a human-readable severity summary
func formatSeverityDistribution(cves CVESummary) string {
	return fmt.Sprintf("CRITICAL: %d, HIGH: %d, MEDIUM: %d, LOW: %d (Total: %d, Fixable: %d)",
		cves.Critical, cves.High, cves.Medium, cves.Low, cves.Total, cves.Fixable)
}
