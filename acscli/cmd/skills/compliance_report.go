package skills

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/spf13/cobra"
	"github.com/stackrox/rox/acscli/internal/client"
)

// ComplianceReportResult is the result of the +compliance-report skill
type ComplianceReportResult struct {
	Standard   string            `json:"standard,omitempty"`
	Cluster    string            `json:"cluster,omitempty"`
	Status     string            `json:"status"` // "pass", "fail", "partial"
	Summary    ComplianceSummary `json:"summary"`
	Controls   []ControlResult   `json:"controls,omitempty"`
	Standards  []StandardResult  `json:"standards,omitempty"`
}

// ComplianceSummary provides overall compliance metrics
type ComplianceSummary struct {
	TotalControls int     `json:"total_controls"`
	Passing       int     `json:"passing"`
	Failing       int     `json:"failing"`
	Skipped       int     `json:"skipped"`
	PassRate      float64 `json:"pass_rate"`
}

// ControlResult represents a single compliance control result
type ControlResult struct {
	ControlID   string `json:"control_id"`
	ControlName string `json:"control_name"`
	Status      string `json:"status"` // "pass", "fail", "skip"
	Message     string `json:"message,omitempty"`
}

// StandardResult represents results for a compliance standard
type StandardResult struct {
	StandardID   string            `json:"standard_id"`
	StandardName string            `json:"standard_name"`
	Summary      ComplianceSummary `json:"summary"`
}

// NewComplianceReportCmd creates the +compliance-report command
func NewComplianceReportCmd() *cobra.Command {
	var (
		standard  string
		cluster   string
		outputFmt string
		dryRun    bool
		verbose   bool
	)

	cmd := &cobra.Command{
		Use:   "+compliance-report",
		Short: "Generate compliance status report",
		Long: `+compliance-report generates a compliance report for one or more standards.

This workflow skill:
  1. Retrieves available compliance standards
  2. Fetches compliance results (aggregated or per-cluster)
  3. Formats results with pass/fail percentages

Examples:
  # Report on all standards
  acs +compliance-report

  # Report for a specific standard
  acs +compliance-report --standard PCI_DSS

  # Report for a specific cluster
  acs +compliance-report --cluster my-cluster

  # Detailed report with individual controls
  acs +compliance-report --standard HIPAA --verbose`,
		RunE: func(cmd *cobra.Command, args []string) error {
			// Handle dry-run
			if dryRun {
				result := map[string]interface{}{
					"skill":    "+compliance-report",
					"dry_run":  true,
					"standard": standard,
					"cluster":  cluster,
					"steps": []map[string]string{
						{"step": "standards", "method": "GET", "path": "/v1/compliance/standards"},
						{"step": "results", "method": "GET", "path": "/v1/compliance/aggregatedresults"},
					},
				}
				return outputResult(result, outputFmt)
			}

			c, err := getClient()
			if err != nil {
				return fmt.Errorf("failed to create client: %w", err)
			}

			result := &ComplianceReportResult{
				Standard: standard,
				Cluster:  cluster,
				Status:   "pass",
			}

			// Step 1: Get available standards
			standardsResp, err := c.Get("/v1/compliance/standards")
			if err != nil {
				return fmt.Errorf("failed to get compliance standards: %w", err)
			}

			var standardsData map[string]interface{}
			if err := json.Unmarshal(standardsResp, &standardsData); err != nil {
				return fmt.Errorf("failed to parse standards response: %w", err)
			}

			standardsList, _ := standardsData["standards"].([]interface{})

			// Filter standards if specified
			var targetStandards []map[string]interface{}
			for _, s := range standardsList {
				std, ok := s.(map[string]interface{})
				if !ok {
					continue
				}
				stdID, _ := std["id"].(string)
				stdName, _ := std["name"].(string)

				if standard != "" {
					// Match by ID or name (case-insensitive)
					if strings.EqualFold(stdID, standard) ||
						strings.EqualFold(stdName, standard) ||
						strings.Contains(strings.ToLower(stdID), strings.ToLower(standard)) {
						targetStandards = append(targetStandards, std)
					}
				} else {
					targetStandards = append(targetStandards, std)
				}
			}

			if len(targetStandards) == 0 {
				if standard != "" {
					return fmt.Errorf("compliance standard not found: %s", standard)
				}
				return fmt.Errorf("no compliance standards configured")
			}

			// Step 2: Get aggregated compliance results
			resultsPath := "/v1/compliance/aggregatedresults"
			queryParams := []string{}

			if cluster != "" {
				queryParams = append(queryParams, fmt.Sprintf("where.query=Cluster:%s", cluster))
			}

			if len(queryParams) > 0 {
				resultsPath = fmt.Sprintf("%s?%s", resultsPath, strings.Join(queryParams, "&"))
			}

			resultsResp, err := c.Get(resultsPath)
			if err != nil {
				return fmt.Errorf("failed to get compliance results: %w", err)
			}

			var resultsData map[string]interface{}
			if err := json.Unmarshal(resultsResp, &resultsData); err != nil {
				return fmt.Errorf("failed to parse results response: %w", err)
			}

			// Process results
			result.Standards = []StandardResult{}
			totalPassing := 0
			totalFailing := 0
			totalSkipped := 0
			totalControls := 0

			// The aggregatedresults response has results organized by domain
			if resultsList, ok := resultsData["results"].([]interface{}); ok {
				for _, res := range resultsList {
					r, ok := res.(map[string]interface{})
					if !ok {
						continue
					}

					// Extract aggregation keys
					aggregationKeys, _ := r["aggregationKeys"].([]interface{})
					var stdID, stdName string

					for _, key := range aggregationKeys {
						if k, ok := key.(map[string]interface{}); ok {
							scope, _ := k["scope"].(string)
							if scope == "STANDARD" {
								stdID, _ = k["id"].(string)
							}
						}
					}

					// Find standard name
					for _, std := range targetStandards {
						if id, _ := std["id"].(string); id == stdID {
							stdName, _ = std["name"].(string)
							break
						}
					}

					// Extract pass/fail counts from numPassing and numFailing
					numPassing := 0
					numFailing := 0

					if np, ok := r["numPassing"].(float64); ok {
						numPassing = int(np)
					}
					if nf, ok := r["numFailing"].(float64); ok {
						numFailing = int(nf)
					}

					total := numPassing + numFailing
					if total == 0 {
						continue
					}

					passRate := float64(numPassing) / float64(total) * 100

					stdResult := StandardResult{
						StandardID:   stdID,
						StandardName: stdName,
						Summary: ComplianceSummary{
							TotalControls: total,
							Passing:       numPassing,
							Failing:       numFailing,
							PassRate:      passRate,
						},
					}

					result.Standards = append(result.Standards, stdResult)

					totalPassing += numPassing
					totalFailing += numFailing
					totalControls += total
				}
			}

			// Calculate overall summary
			result.Summary = ComplianceSummary{
				TotalControls: totalControls,
				Passing:       totalPassing,
				Failing:       totalFailing,
				Skipped:       totalSkipped,
			}

			if totalControls > 0 {
				result.Summary.PassRate = float64(totalPassing) / float64(totalControls) * 100
			}

			// Determine overall status
			if totalFailing > 0 {
				if totalPassing > 0 {
					result.Status = "partial"
				} else {
					result.Status = "fail"
				}
			}

			// Get detailed control results if verbose
			if verbose && len(targetStandards) == 1 {
				stdID, _ := targetStandards[0]["id"].(string)
				result.Controls = getControlResults(c, stdID, cluster)
			}

			return outputResult(result, outputFmt)
		},
	}

	cmd.Flags().StringVarP(&standard, "standard", "s", "", "Compliance standard (e.g., PCI_DSS, HIPAA, NIST_800_53)")
	cmd.Flags().StringVarP(&cluster, "cluster", "c", "", "Filter by cluster name")
	cmd.Flags().StringVarP(&outputFmt, "output", "o", "", "Output format: json, table (default: auto)")
	cmd.Flags().BoolVar(&dryRun, "dry-run", false, "Preview request without executing")
	cmd.Flags().BoolVarP(&verbose, "verbose", "v", false, "Include individual control results")

	return cmd
}

// getControlResults fetches individual control results for a standard
func getControlResults(c *client.Client, standardID, cluster string) []ControlResult {
	var controls []ControlResult

	// Get run results for detailed control info
	path := fmt.Sprintf("/v1/compliance/runresults?standardId=%s&unit=CONTROL", standardID)
	if cluster != "" {
		path = fmt.Sprintf("%s&where.query=Cluster:%s", path, cluster)
	}

	resp, err := c.Get(path)
	if err != nil {
		return controls
	}

	var data map[string]interface{}
	if err := json.Unmarshal(resp, &data); err != nil {
		return controls
	}

	if results, ok := data["results"].([]interface{}); ok {
		for _, res := range results {
			r, ok := res.(map[string]interface{})
			if !ok {
				continue
			}

			control := ControlResult{}

			if aggKeys, ok := r["aggregationKeys"].([]interface{}); ok {
				for _, key := range aggKeys {
					if k, ok := key.(map[string]interface{}); ok {
						if scope, _ := k["scope"].(string); scope == "CONTROL" {
							control.ControlID, _ = k["id"].(string)
						}
					}
				}
			}

			// Determine pass/fail
			numPassing := 0.0
			numFailing := 0.0
			if np, ok := r["numPassing"].(float64); ok {
				numPassing = np
			}
			if nf, ok := r["numFailing"].(float64); ok {
				numFailing = nf
			}

			if numFailing > 0 {
				control.Status = "fail"
			} else if numPassing > 0 {
				control.Status = "pass"
			} else {
				control.Status = "skip"
			}

			controls = append(controls, control)
		}
	}

	return controls
}
