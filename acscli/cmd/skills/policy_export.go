package skills

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"
)

// PolicyExportResult is the result of the +policy-export skill
type PolicyExportResult struct {
	Exported int               `json:"exported"`
	Dir      string            `json:"dir"`
	Format   string            `json:"format"`
	Severity map[string]int    `json:"by_severity"`
	Files    []string          `json:"files,omitempty"`
	Errors   []string          `json:"errors,omitempty"`
}

// NewPolicyExportCmd creates the +policy-export command
func NewPolicyExportCmd() *cobra.Command {
	var (
		outputDir  string
		format     string
		query      string
		outputFmt  string
		dryRun     bool
		includeAll bool
	)

	cmd := &cobra.Command{
		Use:   "+policy-export",
		Short: "Export security policies to files for GitOps/version control",
		Long: `+policy-export exports policies from ACS Central to local files.

This workflow skill:
  1. Lists policies (with optional filtering via --query)
  2. Exports each policy to a separate file
  3. Supports JSON and YAML formats

Useful for:
  - Backing up policies
  - GitOps workflows
  - Migrating policies between environments
  - Policy review and auditing

Examples:
  # Export all policies to ./policies directory
  acs +policy-export --dir ./policies

  # Export only critical policies
  acs +policy-export --dir ./policies --query "Severity:CRITICAL"

  # Export as YAML
  acs +policy-export --dir ./policies --format yaml

  # Preview what would be exported
  acs +policy-export --dir ./policies --dry-run`,
		RunE: func(cmd *cobra.Command, args []string) error {
			// Handle dry-run
			if dryRun {
				result := map[string]interface{}{
					"skill":   "+policy-export",
					"dry_run": true,
					"dir":     outputDir,
					"format":  format,
					"query":   query,
					"steps": []map[string]string{
						{"step": "list", "method": "GET", "path": "/v1/policies"},
						{"step": "export", "method": "POST", "path": "/v1/policies/export"},
					},
				}
				return outputResult(result, outputFmt)
			}

			c, err := getClient()
			if err != nil {
				return fmt.Errorf("failed to create client: %w", err)
			}

			// Create output directory
			if err := os.MkdirAll(outputDir, 0755); err != nil {
				return fmt.Errorf("failed to create output directory: %w", err)
			}

			// Step 1: List policies
			path := "/v1/policies"
			if query != "" {
				path = fmt.Sprintf("%s?query=%s", path, query)
			}

			listResp, err := c.Get(path)
			if err != nil {
				return fmt.Errorf("failed to list policies: %w", err)
			}

			var listData map[string]interface{}
			if err := json.Unmarshal(listResp, &listData); err != nil {
				return fmt.Errorf("failed to parse policy list: %w", err)
			}

			policies, ok := listData["policies"].([]interface{})
			if !ok {
				return fmt.Errorf("unexpected policy list format")
			}

			if len(policies) == 0 {
				result := &PolicyExportResult{
					Exported: 0,
					Dir:      outputDir,
					Format:   format,
					Severity: map[string]int{},
				}
				return outputResult(result, outputFmt)
			}

			// Collect policy IDs
			var policyIDs []string
			for _, p := range policies {
				if policy, ok := p.(map[string]interface{}); ok {
					if id, ok := policy["id"].(string); ok {
						policyIDs = append(policyIDs, id)
					}
				}
			}

			// Step 2: Export policies (gets full policy details)
			exportReq := map[string]interface{}{
				"policyIds": policyIDs,
			}
			exportResp, err := c.Post("/v1/policies/export", exportReq)
			if err != nil {
				return fmt.Errorf("failed to export policies: %w", err)
			}

			var exportData map[string]interface{}
			if err := json.Unmarshal(exportResp, &exportData); err != nil {
				return fmt.Errorf("failed to parse export response: %w", err)
			}

			exportedPolicies, ok := exportData["policies"].([]interface{})
			if !ok {
				return fmt.Errorf("unexpected export response format")
			}

			// Step 3: Write policy files
			result := &PolicyExportResult{
				Dir:      outputDir,
				Format:   format,
				Severity: map[string]int{},
				Files:    []string{},
				Errors:   []string{},
			}

			for _, p := range exportedPolicies {
				policy, ok := p.(map[string]interface{})
				if !ok {
					continue
				}

				name, _ := policy["name"].(string)
				id, _ := policy["id"].(string)
				severity, _ := policy["severity"].(string)

				// Track severity counts
				sevKey := normalizeSeverity(severity)
				result.Severity[sevKey]++

				// Skip system policies unless includeAll
				if !includeAll {
					if isSystem, ok := policy["isDefault"].(bool); ok && isSystem {
						continue
					}
				}

				// Generate filename
				filename := sanitizeFilename(name)
				if filename == "" {
					filename = id
				}

				var ext string
				if format == "yaml" {
					ext = ".yaml"
				} else {
					ext = ".json"
				}
				filePath := filepath.Join(outputDir, filename+ext)

				// Write file
				if err := writePolicyFile(filePath, policy, format); err != nil {
					result.Errors = append(result.Errors, fmt.Sprintf("%s: %v", name, err))
					continue
				}

				result.Files = append(result.Files, filePath)
				result.Exported++
			}

			return outputResult(result, outputFmt)
		},
	}

	cmd.Flags().StringVarP(&outputDir, "dir", "d", "./policies", "Output directory for policy files")
	cmd.Flags().StringVarP(&format, "format", "f", "json", "Output format: json, yaml")
	cmd.Flags().StringVarP(&query, "query", "q", "", "Filter policies by query (e.g., 'Severity:CRITICAL')")
	cmd.Flags().StringVarP(&outputFmt, "output", "o", "", "Command output format: json, table (default: auto)")
	cmd.Flags().BoolVar(&dryRun, "dry-run", false, "Preview what would be exported")
	cmd.Flags().BoolVar(&includeAll, "include-system", false, "Include system/default policies")

	return cmd
}

// sanitizeFilename converts a policy name to a safe filename
func sanitizeFilename(name string) string {
	// Replace spaces and special characters
	name = strings.ToLower(name)
	name = strings.Map(func(r rune) rune {
		switch {
		case r >= 'a' && r <= 'z':
			return r
		case r >= '0' && r <= '9':
			return r
		case r == '-' || r == '_':
			return r
		case r == ' ':
			return '-'
		default:
			return -1
		}
	}, name)

	// Collapse multiple dashes
	for strings.Contains(name, "--") {
		name = strings.ReplaceAll(name, "--", "-")
	}

	// Trim leading/trailing dashes
	name = strings.Trim(name, "-")

	// Limit length
	if len(name) > 100 {
		name = name[:100]
	}

	return name
}

// writePolicyFile writes a policy to a file in the specified format
func writePolicyFile(path string, policy map[string]interface{}, format string) error {
	var data []byte
	var err error

	// Remove internal fields that shouldn't be exported
	policyClean := make(map[string]interface{})
	for k, v := range policy {
		// Skip internal metadata fields
		if k == "lastUpdated" || k == "SORTName" || k == "SORTLifecycleStage" || k == "SORTEnforcement" {
			continue
		}
		policyClean[k] = v
	}

	switch format {
	case "yaml":
		data, err = yaml.Marshal(policyClean)
	default:
		data, err = json.MarshalIndent(policyClean, "", "  ")
	}

	if err != nil {
		return err
	}

	return os.WriteFile(path, data, 0644)
}
