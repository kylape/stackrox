//go:build ignore

// Generator tool for creating CLI commands from OpenAPI/Swagger specs.
// Run with: go run ./acscli/tools/generate
package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"
)

func main() {
	var (
		swaggerDir = flag.String("swagger-dir", "generated/api/v1", "Directory containing swagger.json files")
		outputDir  = flag.String("output-dir", "acscli/generated", "Output directory for generated commands")
		verbose    = flag.Bool("verbose", false, "Verbose output")
	)
	flag.Parse()

	// Find swagger files
	pattern := filepath.Join(*swaggerDir, "*_service.swagger.json")
	files, err := filepath.Glob(pattern)
	if err != nil {
		log.Fatalf("Failed to find swagger files: %v", err)
	}

	if len(files) == 0 {
		log.Fatalf("No swagger files found in %s", *swaggerDir)
	}

	if *verbose {
		log.Printf("Found %d swagger files", len(files))
	}

	// Parse all swagger files
	parser := NewParser()
	var services []*Service
	for _, file := range files {
		if *verbose {
			log.Printf("Parsing %s", file)
		}
		svc, err := parser.ParseFile(file)
		if err != nil {
			log.Printf("Warning: failed to parse %s: %v", file, err)
			continue
		}
		if len(svc.Methods) > 0 {
			services = append(services, svc)
		}
	}

	if *verbose {
		log.Printf("Parsed %d services with methods", len(services))
	}

	// Create output directory
	if err := os.MkdirAll(*outputDir, 0755); err != nil {
		log.Fatalf("Failed to create output directory: %v", err)
	}

	// Generate code
	gen := NewGenerator(*outputDir)

	// Generate service command files
	for _, svc := range services {
		if *verbose {
			log.Printf("Generating %s (%d methods)", svc.Name, len(svc.Methods))
		}
		if err := gen.GenerateService(svc); err != nil {
			log.Printf("Warning: failed to generate %s: %v", svc.Name, err)
			continue
		}
	}

	// Generate registry file that wires all services together
	if err := gen.GenerateRegistry(services); err != nil {
		log.Fatalf("Failed to generate registry: %v", err)
	}

	fmt.Printf("Generated %d service commands in %s\n", len(services), *outputDir)
}
