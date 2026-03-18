package cmd

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/spf13/cobra"
	"github.com/stackrox/rox/acscli/internal/schema"
)

func newSchemaCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "schema [service[.method]]",
		Short: "Introspect API schemas",
		Long: `Query API schemas for services and methods.

Without arguments, lists all available services.
With a service name, lists methods in that service.
With service.method, shows full schema for that method.

Examples:
  # List all services
  acs schema

  # List methods in ImageService
  acs schema image

  # Get schema for image scan method
  acs schema image.scan

  # Get schema for policy create
  acs schema policy.create`,
		Args: cobra.MaximumNArgs(1),
		RunE: runSchema,
	}

	return cmd
}

func runSchema(cmd *cobra.Command, args []string) error {
	loader := schema.NewLoader()

	// No arguments: list services
	if len(args) == 0 {
		return listServices(loader)
	}

	query := args[0]

	// Check if it's service.method format
	if strings.Contains(query, ".") {
		parts := strings.SplitN(query, ".", 2)
		return showMethodSchema(loader, parts[0], parts[1])
	}

	// Just service name: list methods
	return listMethods(loader, query)
}

func listServices(loader *schema.Loader) error {
	services := loader.ListServices()
	sort.Strings(services)

	if GetOutputFormat() == "json" || !isTerminal(os.Stdout) {
		result := map[string]interface{}{
			"services": services,
			"count":    len(services),
		}
		return json.NewEncoder(os.Stdout).Encode(result)
	}

	fmt.Println("Available services:")
	for _, svc := range services {
		fmt.Printf("  %s\n", svc)
	}
	fmt.Printf("\nTotal: %d services\n", len(services))
	fmt.Println("\nUse 'acs schema <service>' to list methods")
	return nil
}

func listMethods(loader *schema.Loader, service string) error {
	methods, err := loader.ListMethods(service)
	if err != nil {
		return err
	}
	sort.Strings(methods)

	if GetOutputFormat() == "json" || !isTerminal(os.Stdout) {
		result := map[string]interface{}{
			"service": service,
			"methods": methods,
			"count":   len(methods),
		}
		return json.NewEncoder(os.Stdout).Encode(result)
	}

	fmt.Printf("Methods in %s:\n", service)
	for _, method := range methods {
		fmt.Printf("  %s.%s\n", service, method)
	}
	fmt.Printf("\nTotal: %d methods\n", len(methods))
	fmt.Println("\nUse 'acs schema <service>.<method>' for full schema")
	return nil
}

func showMethodSchema(loader *schema.Loader, service, method string) error {
	methodSchema, err := loader.GetMethodSchema(service, method)
	if err != nil {
		return err
	}

	if GetOutputFormat() == "json" || !isTerminal(os.Stdout) {
		return json.NewEncoder(os.Stdout).Encode(methodSchema)
	}

	// Human-readable format
	fmt.Printf("Schema for %s.%s\n", service, method)
	fmt.Println(strings.Repeat("─", 50))

	if methodSchema.Description != "" {
		fmt.Printf("\n%s\n", methodSchema.Description)
	}

	fmt.Printf("\nHTTP: %s %s\n", methodSchema.HTTP.Method, methodSchema.HTTP.Path)

	if len(methodSchema.Parameters) > 0 {
		fmt.Println("\nParameters:")
		for name, param := range methodSchema.Parameters {
			required := ""
			if param.Required {
				required = " (required)"
			}
			fmt.Printf("  --%s %s%s\n", name, param.Type, required)
			if param.Description != "" {
				fmt.Printf("      %s\n", param.Description)
			}
		}
	}

	if methodSchema.RequestBody != nil {
		fmt.Println("\nRequest Body (--json):")
		prettyJSON, _ := json.MarshalIndent(methodSchema.RequestBody, "  ", "  ")
		fmt.Printf("  %s\n", string(prettyJSON))
	}

	if methodSchema.Response != nil {
		fmt.Println("\nResponse:")
		prettyJSON, _ := json.MarshalIndent(methodSchema.Response, "  ", "  ")
		fmt.Printf("  %s\n", string(prettyJSON))
	}

	return nil
}
