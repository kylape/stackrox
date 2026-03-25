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

// PolicyImportResult is the result of the +policy-import skill
type PolicyImportResult struct {
	Imported int               `json:"imported"`
	Skipped  int               `json:"skipped"`
	Updated  int               `json:"updated"`
	Created  int               `json:"created"`
	Source   string            `json:"source"`
	Policies []ImportedPolicy  `json:"policies,omitempty"`
	Errors   []string          `json:"errors,omitempty"`
}

// ImportedPolicy records the result of importing a single policy
type ImportedPolicy struct {
	Name   string `json:"name"`
	ID     string `json:"id,omitempty"`
	Action string `json:"action"` // "created", "updated", "skipped"
	Error  string `json:"error,omitempty"`
}

// NewPolicyImportCmd creates the +policy-import command
func NewPolicyImportCmd() *cobra.Command {
	var (
		inputDir   string
		inputFile  string
		outputFmt  string
		dryRun     bool
		update     bool
		skipErrors bool
	)

	cmd := &cobra.Command{
		Use:   "+policy-import",
		Short: "Import security policies from files",
		Long: `+policy-import imports policies from local files into ACS Central.

This workflow skill:
  1. Reads policy files from a directory or single file
  2. Validates each policy against the schema
  3. Creates or updates policies in ACS Central

Supports both JSON and YAML formats (detected by file extension).

Examples:
  # Import all policies from a directory
  acs +policy-import --dir ./policies

  # Import a single policy file
  acs +policy-import --file my-policy.yaml

  # Update existing policies (instead of skipping)
  acs +policy-import --dir ./policies --update

  # Preview what would be imported
  acs +policy-import --dir ./policies --dry-run`,
		RunE: func(cmd *cobra.Command, args []string) error {
			// Validate input
			if inputDir == "" && inputFile == "" {
				return fmt.Errorf("either --dir or --file must be specified")
			}
			if inputDir != "" && inputFile != "" {
				return fmt.Errorf("--dir and --file are mutually exclusive")
			}

			// Collect policy files
			var files []string
			var source string

			if inputFile != "" {
				files = []string{inputFile}
				source = inputFile
			} else {
				source = inputDir
				entries, err := os.ReadDir(inputDir)
				if err != nil {
					return fmt.Errorf("failed to read directory: %w", err)
				}
				for _, entry := range entries {
					if entry.IsDir() {
						continue
					}
					name := entry.Name()
					if strings.HasSuffix(name, ".json") || strings.HasSuffix(name, ".yaml") || strings.HasSuffix(name, ".yml") {
						files = append(files, filepath.Join(inputDir, name))
					}
				}
			}

			if len(files) == 0 {
				return fmt.Errorf("no policy files found")
			}

			// Handle dry-run
			if dryRun {
				result := map[string]interface{}{
					"skill":   "+policy-import",
					"dry_run": true,
					"source":  source,
					"files":   len(files),
					"update":  update,
					"steps": []map[string]string{
						{"step": "validate", "description": "Parse and validate policy files"},
						{"step": "check", "method": "GET", "path": "/v1/policies (check existing)"},
						{"step": "import", "method": "POST", "path": "/v1/policies/import"},
					},
				}
				return outputResult(result, outputFmt)
			}

			c, err := getClient()
			if err != nil {
				return fmt.Errorf("failed to create client: %w", err)
			}

			// Read and parse all policy files
			var policies []map[string]interface{}
			result := &PolicyImportResult{
				Source:   source,
				Policies: []ImportedPolicy{},
				Errors:   []string{},
			}

			for _, file := range files {
				policy, err := readPolicyFile(file)
				if err != nil {
					errMsg := fmt.Sprintf("%s: %v", filepath.Base(file), err)
					result.Errors = append(result.Errors, errMsg)
					if !skipErrors {
						return fmt.Errorf("failed to read %s: %w", file, err)
					}
					continue
				}
				policies = append(policies, policy)
			}

			if len(policies) == 0 {
				return fmt.Errorf("no valid policies to import")
			}

			// Get existing policies to determine create vs update
			listResp, err := c.Get("/v1/policies")
			if err != nil {
				return fmt.Errorf("failed to list existing policies: %w", err)
			}

			var listData map[string]interface{}
			if err := json.Unmarshal(listResp, &listData); err != nil {
				return fmt.Errorf("failed to parse policy list: %w", err)
			}

			existingPolicies := make(map[string]string) // name -> id
			if existingList, ok := listData["policies"].([]interface{}); ok {
				for _, p := range existingList {
					if policy, ok := p.(map[string]interface{}); ok {
						name, _ := policy["name"].(string)
						id, _ := policy["id"].(string)
						if name != "" && id != "" {
							existingPolicies[name] = id
						}
					}
				}
			}

			// Import policies using the import endpoint
			importReq := map[string]interface{}{
				"policies": policies,
				"metadata": map[string]interface{}{
					"overwrite": update,
				},
			}

			importResp, err := c.Post("/v1/policies/import", importReq)
			if err != nil {
				return fmt.Errorf("policy import failed: %w", err)
			}

			var importData map[string]interface{}
			if err := json.Unmarshal(importResp, &importData); err != nil {
				return fmt.Errorf("failed to parse import response: %w", err)
			}

			// Process import results
			if responses, ok := importData["responses"].([]interface{}); ok {
				for _, resp := range responses {
					if r, ok := resp.(map[string]interface{}); ok {
						imported := ImportedPolicy{}

						if policy, ok := r["policy"].(map[string]interface{}); ok {
							imported.Name, _ = policy["name"].(string)
							imported.ID, _ = policy["id"].(string)
						}

						if succeeded, ok := r["succeeded"].(bool); ok && succeeded {
							// Check if it was an update or create
							if _, exists := existingPolicies[imported.Name]; exists && update {
								imported.Action = "updated"
								result.Updated++
							} else {
								imported.Action = "created"
								result.Created++
							}
							result.Imported++
						} else {
							imported.Action = "skipped"
							result.Skipped++
							if errors, ok := r["errors"].([]interface{}); ok && len(errors) > 0 {
								if errMsg, ok := errors[0].(map[string]interface{}); ok {
									if msg, ok := errMsg["message"].(string); ok {
										imported.Error = msg
									}
								}
							}
						}

						result.Policies = append(result.Policies, imported)
					}
				}
			}

			return outputResult(result, outputFmt)
		},
	}

	cmd.Flags().StringVarP(&inputDir, "dir", "d", "", "Directory containing policy files")
	cmd.Flags().StringVarP(&inputFile, "file", "f", "", "Single policy file to import")
	cmd.Flags().StringVarP(&outputFmt, "output", "o", "", "Command output format: json, table (default: auto)")
	cmd.Flags().BoolVar(&dryRun, "dry-run", false, "Preview what would be imported")
	cmd.Flags().BoolVar(&update, "update", false, "Update existing policies instead of skipping")
	cmd.Flags().BoolVar(&skipErrors, "skip-errors", false, "Continue importing even if some files fail")

	return cmd
}

// readPolicyFile reads a policy from a JSON or YAML file
func readPolicyFile(path string) (map[string]interface{}, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var policy map[string]interface{}

	ext := strings.ToLower(filepath.Ext(path))
	switch ext {
	case ".yaml", ".yml":
		if err := yaml.Unmarshal(data, &policy); err != nil {
			return nil, fmt.Errorf("invalid YAML: %w", err)
		}
	case ".json":
		if err := json.Unmarshal(data, &policy); err != nil {
			return nil, fmt.Errorf("invalid JSON: %w", err)
		}
	default:
		// Try JSON first, then YAML
		if err := json.Unmarshal(data, &policy); err != nil {
			if err := yaml.Unmarshal(data, &policy); err != nil {
				return nil, fmt.Errorf("unknown format (not JSON or YAML)")
			}
		}
	}

	// Validate required fields
	if _, ok := policy["name"]; !ok {
		return nil, fmt.Errorf("policy missing required field: name")
	}

	return policy, nil
}
