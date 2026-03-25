package skills

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/spf13/cobra"
)

// CheckImageResult is the result of the +check-image skill
type CheckImageResult struct {
	Image      string            `json:"image"`
	Status     string            `json:"status"` // "PASS" or "FAIL"
	Scan       *ScanResult       `json:"scan,omitempty"`
	Violations []PolicyViolation `json:"violations,omitempty"`
	Summary    string            `json:"summary,omitempty"`
}

// ScanResult contains vulnerability scan information
type ScanResult struct {
	ImageID      string     `json:"image_id,omitempty"`
	Components   int        `json:"components"`
	CVEs         CVESummary `json:"cves"`
	ScanTime     string     `json:"scan_time,omitempty"`
	DataSource   string     `json:"data_source,omitempty"`
	ScannerNotes []string   `json:"scanner_notes,omitempty"`
}

// NewCheckImageCmd creates the +check-image command
func NewCheckImageCmd() *cobra.Command {
	var (
		outputFmt string
		dryRun    bool
		noScan    bool
		noPolicy  bool
	)

	cmd := &cobra.Command{
		Use:   "+check-image <image>",
		Short: "Perform full security assessment of a container image",
		Long: `+check-image performs a comprehensive security check on a container image.

This workflow skill combines:
  1. Image vulnerability scan (POST /v1/images/scan)
  2. Policy violation check (POST /v1/detect/build)

The result includes:
  - Pass/fail status based on policy violations
  - CVE counts by severity (critical, high, medium, low)
  - Count of fixable vulnerabilities
  - List of policy violations with severity

Examples:
  # Check an image
  acs +check-image nginx:latest

  # Check with JSON output for parsing
  acs +check-image quay.io/myorg/app:v1.2.3 --output json

  # Skip policy check, scan only
  acs +check-image alpine:3.18 --no-policy`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			imageName := args[0]

			// Handle dry-run
			if dryRun {
				result := map[string]interface{}{
					"skill":   "+check-image",
					"dry_run": true,
					"image":   imageName,
					"steps": []map[string]string{
						{"step": "scan", "method": "POST", "path": "/v1/images/scan"},
						{"step": "detect", "method": "POST", "path": "/v1/detect/build"},
					},
				}
				return outputResult(result, outputFmt)
			}

			c, err := getClient()
			if err != nil {
				return fmt.Errorf("failed to create client: %w", err)
			}

			result := &CheckImageResult{
				Image:      imageName,
				Status:     "PASS",
				Violations: []PolicyViolation{},
			}

			// Step 1: Scan the image
			if !noScan {
				scanReq := map[string]interface{}{
					"imageName": imageName,
				}
				scanResp, err := c.Post("/v1/images/scan", scanReq)
				if err != nil {
					return fmt.Errorf("image scan failed: %w", err)
				}

				var scanData map[string]interface{}
				if err := json.Unmarshal(scanResp, &scanData); err != nil {
					return fmt.Errorf("failed to parse scan response: %w", err)
				}

				result.Scan = parseScanResult(scanData)
			}

			// Step 2: Check against policies
			if !noPolicy && result.Scan != nil && result.Scan.ImageID != "" {
				detectReq := map[string]interface{}{
					"imageId": result.Scan.ImageID,
				}
				detectResp, err := c.Post("/v1/detect/build", detectReq)
				if err != nil {
					// Policy check failure is non-fatal; continue with scan results
					result.Summary = fmt.Sprintf("Scan complete. Policy check failed: %v", err)
				} else {
					var detectData map[string]interface{}
					if err := json.Unmarshal(detectResp, &detectData); err != nil {
						result.Summary = fmt.Sprintf("Scan complete. Failed to parse policy check: %v", err)
					} else {
						result.Violations = parseViolations(detectData)
						if len(result.Violations) > 0 {
							result.Status = "FAIL"
						}
					}
				}
			}

			// Generate summary
			if result.Summary == "" {
				result.Summary = generateCheckImageSummary(result)
			}

			return outputResult(result, outputFmt)
		},
	}

	cmd.Flags().StringVarP(&outputFmt, "output", "o", "", "Output format: json, table (default: auto)")
	cmd.Flags().BoolVar(&dryRun, "dry-run", false, "Preview request without executing")
	cmd.Flags().BoolVar(&noScan, "no-scan", false, "Skip vulnerability scan (use existing scan data)")
	cmd.Flags().BoolVar(&noPolicy, "no-policy", false, "Skip policy violation check")

	return cmd
}

// parseScanResult extracts scan information from the API response
func parseScanResult(data map[string]interface{}) *ScanResult {
	result := &ScanResult{}

	// Extract image ID
	if id, ok := data["id"].(string); ok {
		result.ImageID = id
	}

	// Extract scan info
	if scan, ok := data["scan"].(map[string]interface{}); ok {
		if scanTime, ok := scan["scanTime"].(string); ok {
			result.ScanTime = scanTime
		}
		if dataSource, ok := scan["dataSource"].(map[string]interface{}); ok {
			if name, ok := dataSource["name"].(string); ok {
				result.DataSource = name
			}
		}

		// Count components
		if components, ok := scan["components"].([]interface{}); ok {
			result.Components = len(components)

			// Count vulnerabilities by severity
			for _, comp := range components {
				if c, ok := comp.(map[string]interface{}); ok {
					if vulns, ok := c["vulns"].([]interface{}); ok {
						for _, vuln := range vulns {
							if v, ok := vuln.(map[string]interface{}); ok {
								severity := strings.ToUpper(fmt.Sprintf("%v", v["severity"]))
								switch severity {
								case "CRITICAL_VULNERABILITY_SEVERITY", "CRITICAL":
									result.CVEs.Critical++
								case "IMPORTANT_VULNERABILITY_SEVERITY", "HIGH":
									result.CVEs.High++
								case "MODERATE_VULNERABILITY_SEVERITY", "MEDIUM":
									result.CVEs.Medium++
								case "LOW_VULNERABILITY_SEVERITY", "LOW":
									result.CVEs.Low++
								}
								result.CVEs.Total++

								// Check if fixable
								if fixedBy, ok := v["fixedBy"].(string); ok && fixedBy != "" {
									result.CVEs.Fixable++
								}
							}
						}
					}
				}
			}
		}

		// Extract scanner notes
		if notes, ok := scan["notes"].([]interface{}); ok {
			for _, note := range notes {
				if n, ok := note.(string); ok {
					result.ScannerNotes = append(result.ScannerNotes, n)
				}
			}
		}
	}

	return result
}

// parseViolations extracts policy violations from the detection response
func parseViolations(data map[string]interface{}) []PolicyViolation {
	var violations []PolicyViolation

	// The response structure has alerts containing violations
	if alerts, ok := data["alerts"].([]interface{}); ok {
		for _, alert := range alerts {
			if a, ok := alert.(map[string]interface{}); ok {
				violation := PolicyViolation{}

				if policy, ok := a["policy"].(map[string]interface{}); ok {
					if id, ok := policy["id"].(string); ok {
						violation.PolicyID = id
					}
					if name, ok := policy["name"].(string); ok {
						violation.PolicyName = name
					}
					if severity, ok := policy["severity"].(string); ok {
						violation.Severity = normalizeSeverity(severity)
					}
				}

				// Get violation message
				if violationsList, ok := a["violations"].([]interface{}); ok && len(violationsList) > 0 {
					if firstViol, ok := violationsList[0].(map[string]interface{}); ok {
						if msg, ok := firstViol["message"].(string); ok {
							violation.Message = msg
						}
					}
				}

				if violation.PolicyName != "" {
					violations = append(violations, violation)
				}
			}
		}
	}

	return violations
}

// normalizeSeverity converts API severity values to consistent format
func normalizeSeverity(severity string) string {
	severity = strings.ToUpper(severity)
	switch {
	case strings.Contains(severity, "CRITICAL"):
		return "CRITICAL"
	case strings.Contains(severity, "HIGH"), strings.Contains(severity, "IMPORTANT"):
		return "HIGH"
	case strings.Contains(severity, "MEDIUM"), strings.Contains(severity, "MODERATE"):
		return "MEDIUM"
	case strings.Contains(severity, "LOW"):
		return "LOW"
	default:
		return severity
	}
}

// generateCheckImageSummary creates a human-readable summary
func generateCheckImageSummary(result *CheckImageResult) string {
	var parts []string

	if result.Status == "PASS" {
		parts = append(parts, "PASS: No policy violations found.")
	} else {
		parts = append(parts, fmt.Sprintf("FAIL: %d policy violation(s) found.", len(result.Violations)))
	}

	if result.Scan != nil {
		parts = append(parts, fmt.Sprintf("Scanned %d components.", result.Scan.Components))
		if result.Scan.CVEs.Total > 0 {
			parts = append(parts, fmt.Sprintf("Found %d CVEs (%d critical, %d high, %d fixable).",
				result.Scan.CVEs.Total,
				result.Scan.CVEs.Critical,
				result.Scan.CVEs.High,
				result.Scan.CVEs.Fixable))
		} else {
			parts = append(parts, "No CVEs found.")
		}
	}

	return strings.Join(parts, " ")
}
