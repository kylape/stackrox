package schema

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// Loader loads and queries API schemas from OpenAPI specs
type Loader struct {
	swaggerDir string
	schemas    map[string]*swaggerSpec // service name -> spec
	loaded     bool
}

// swaggerSpec represents a parsed swagger.json file
type swaggerSpec struct {
	BasePath string                          `json:"basePath"`
	Info     swaggerInfo                     `json:"info"`
	Paths    map[string]map[string]operation `json:"paths"`
	Defs     map[string]definition           `json:"definitions"`
}

type swaggerInfo struct {
	Title   string `json:"title"`
	Version string `json:"version"`
}

type operation struct {
	Summary     string      `json:"summary"`
	Description string      `json:"description"`
	OperationID string      `json:"operationId"`
	Parameters  []parameter `json:"parameters"`
	Responses   map[string]response
}

type parameter struct {
	Name        string      `json:"name"`
	In          string      `json:"in"`
	Description string      `json:"description"`
	Required    bool        `json:"required"`
	Type        string      `json:"type"`
	Schema      *schemaRef  `json:"schema"`
	Default     interface{} `json:"default"`
	Enum        []string    `json:"enum"`
}

type response struct {
	Description string     `json:"description"`
	Schema      *schemaRef `json:"schema"`
}

type schemaRef struct {
	Ref        string                 `json:"$ref"`
	Type       string                 `json:"type"`
	Properties map[string]interface{} `json:"properties"`
	Items      *schemaRef             `json:"items"`
}

type definition struct {
	Type       string                 `json:"type"`
	Properties map[string]interface{} `json:"properties"`
	Required   []string               `json:"required"`
}

// NewLoader creates a new schema loader
func NewLoader() *Loader {
	// Default to looking for swagger files in the generated directory
	// This will be populated at build time or found at runtime
	swaggerDir := os.Getenv("ACS_SWAGGER_DIR")
	if swaggerDir == "" {
		// Try common locations
		candidates := []string{
			"./generated/api/v1",
			"../generated/api/v1",
			"/opt/workspace/src/stackrox/generated/api/v1",
		}
		for _, dir := range candidates {
			if _, err := os.Stat(dir); err == nil {
				swaggerDir = dir
				break
			}
		}
	}

	return &Loader{
		swaggerDir: swaggerDir,
		schemas:    make(map[string]*swaggerSpec),
	}
}

// loadSchemas loads all swagger specs
func (l *Loader) loadSchemas() error {
	if l.loaded {
		return nil
	}

	if l.swaggerDir == "" {
		// Return placeholder data if no swagger dir found
		l.loaded = true
		return nil
	}

	files, err := filepath.Glob(filepath.Join(l.swaggerDir, "*.swagger.json"))
	if err != nil {
		return fmt.Errorf("failed to find swagger files: %w", err)
	}

	for _, file := range files {
		data, err := os.ReadFile(file)
		if err != nil {
			continue
		}

		var spec swaggerSpec
		if err := json.Unmarshal(data, &spec); err != nil {
			continue
		}

		// Extract service name from filename (e.g., "image_service.swagger.json" -> "image")
		base := filepath.Base(file)
		name := strings.TrimSuffix(base, ".swagger.json")
		name = strings.TrimSuffix(name, "_service")
		name = strings.ToLower(name)

		l.schemas[name] = &spec
	}

	l.loaded = true
	return nil
}

// ListServices returns all available service names
func (l *Loader) ListServices() []string {
	l.loadSchemas()

	// If no schemas loaded, return placeholder list
	if len(l.schemas) == 0 {
		return []string{
			"alert",
			"apitoken",
			"auth",
			"authprovider",
			"backup",
			"cluster",
			"compliance",
			"config",
			"credential",
			"deployment",
			"detection",
			"externalbakcup",
			"group",
			"image",
			"imageintegration",
			"integration",
			"namespace",
			"networkpolicy",
			"node",
			"notifier",
			"permission",
			"pod",
			"policy",
			"probe",
			"process",
			"rbac",
			"reportconfiguration",
			"role",
			"search",
			"secret",
			"sensor",
			"serviceaccount",
			"simgage",
			"summary",
			"telemetry",
			"user",
			"vulnmgmt",
		}
	}

	var services []string
	for name := range l.schemas {
		services = append(services, name)
	}
	return services
}

// ListMethods returns all methods for a service
func (l *Loader) ListMethods(service string) ([]string, error) {
	l.loadSchemas()

	service = strings.ToLower(service)
	spec, ok := l.schemas[service]
	if !ok {
		// Return placeholder methods if service not found
		return l.getPlaceholderMethods(service), nil
	}

	methodSet := make(map[string]bool)
	for _, pathOps := range spec.Paths {
		for _, op := range pathOps {
			if op.OperationID != "" {
				// Convert operation ID to method name
				method := l.operationToMethod(op.OperationID)
				methodSet[method] = true
			}
		}
	}

	var methods []string
	for method := range methodSet {
		methods = append(methods, method)
	}
	return methods, nil
}

// GetMethodSchema returns the full schema for a method
func (l *Loader) GetMethodSchema(service, method string) (*MethodSchema, error) {
	l.loadSchemas()

	service = strings.ToLower(service)
	method = strings.ToLower(method)

	spec, ok := l.schemas[service]
	if !ok {
		// Return placeholder schema
		return l.getPlaceholderSchema(service, method), nil
	}

	// Find the operation
	for path, pathOps := range spec.Paths {
		for httpMethod, op := range pathOps {
			opMethod := l.operationToMethod(op.OperationID)
			if strings.ToLower(opMethod) == method {
				return l.buildMethodSchema(service, opMethod, httpMethod, path, &op, spec), nil
			}
		}
	}

	return nil, fmt.Errorf("method %s.%s not found", service, method)
}

func (l *Loader) operationToMethod(operationID string) string {
	// Convert "ImageService_ScanImage" to "scan"
	// or "ScanImage" to "scan"
	parts := strings.Split(operationID, "_")
	name := parts[len(parts)-1]

	// Remove common prefixes
	for _, prefix := range []string{"Get", "List", "Create", "Update", "Delete", "Post", "Put", "Patch"} {
		if strings.HasPrefix(name, prefix) {
			name = strings.TrimPrefix(name, prefix)
			if name == "" {
				name = strings.ToLower(prefix)
			}
			break
		}
	}

	return strings.ToLower(name)
}

func (l *Loader) buildMethodSchema(service, method, httpMethod, path string, op *operation, spec *swaggerSpec) *MethodSchema {
	schema := &MethodSchema{
		Service:     service,
		Method:      method,
		Description: op.Summary,
		HTTP: HTTPInfo{
			Method: strings.ToUpper(httpMethod),
			Path:   spec.BasePath + path,
		},
		Parameters: make(map[string]Parameter),
	}

	// Add parameters
	for _, p := range op.Parameters {
		if p.In == "body" {
			// Body parameter becomes request body
			if p.Schema != nil {
				schema.RequestBody = l.resolveSchema(p.Schema, spec)
			}
		} else {
			param := Parameter{
				Name:        p.Name,
				Type:        p.Type,
				Description: p.Description,
				Required:    p.Required,
				Default:     p.Default,
				Enum:        p.Enum,
				Location:    p.In,
			}
			schema.Parameters[p.Name] = param
		}
	}

	// Add response schema
	if resp, ok := op.Responses["200"]; ok && resp.Schema != nil {
		schema.Response = l.resolveSchema(resp.Schema, spec)
	}

	return schema
}

func (l *Loader) resolveSchema(ref *schemaRef, spec *swaggerSpec) interface{} {
	if ref == nil {
		return nil
	}

	if ref.Ref != "" {
		// Resolve $ref
		// Format: "#/definitions/storageImage"
		refName := strings.TrimPrefix(ref.Ref, "#/definitions/")
		if def, ok := spec.Defs[refName]; ok {
			return map[string]interface{}{
				"type":       def.Type,
				"properties": def.Properties,
				"required":   def.Required,
			}
		}
		return map[string]interface{}{"$ref": refName}
	}

	if ref.Type == "array" && ref.Items != nil {
		return map[string]interface{}{
			"type":  "array",
			"items": l.resolveSchema(ref.Items, spec),
		}
	}

	return map[string]interface{}{
		"type":       ref.Type,
		"properties": ref.Properties,
	}
}

func (l *Loader) getPlaceholderMethods(service string) []string {
	// Common methods for most services
	common := []string{"get", "list", "create", "update", "delete"}

	// Service-specific methods
	specific := map[string][]string{
		"image":      {"scan", "get", "list", "delete"},
		"policy":     {"get", "list", "create", "update", "delete", "dryrun", "export", "import"},
		"alert":      {"get", "list", "resolve", "snooze", "delete"},
		"cluster":    {"get", "list", "delete", "getbundle"},
		"deployment": {"get", "list", "check"},
		"compliance": {"getresults", "getstatus", "trigger"},
	}

	if methods, ok := specific[service]; ok {
		return methods
	}
	return common
}

func (l *Loader) getPlaceholderSchema(service, method string) *MethodSchema {
	// Generate a reasonable placeholder based on conventions
	httpMethod := "GET"
	path := fmt.Sprintf("/v1/%s", service)

	switch {
	case method == "list":
		path = fmt.Sprintf("/v1/%ss", service)
	case method == "get":
		path = fmt.Sprintf("/v1/%ss/{id}", service)
	case method == "create":
		httpMethod = "POST"
		path = fmt.Sprintf("/v1/%ss", service)
	case method == "update":
		httpMethod = "PUT"
		path = fmt.Sprintf("/v1/%ss/{id}", service)
	case method == "delete":
		httpMethod = "DELETE"
		path = fmt.Sprintf("/v1/%ss/{id}", service)
	case method == "scan":
		httpMethod = "POST"
		path = fmt.Sprintf("/v1/%ss/scan", service)
	}

	// Use regex to detect common patterns
	createPattern := regexp.MustCompile(`^(create|add|post)`)
	if createPattern.MatchString(method) {
		httpMethod = "POST"
	}

	return &MethodSchema{
		Service:     service,
		Method:      method,
		Description: fmt.Sprintf("%s %s", strings.Title(method), service),
		HTTP: HTTPInfo{
			Method: httpMethod,
			Path:   path,
		},
		Parameters: map[string]Parameter{
			"id": {
				Name:        "id",
				Type:        "string",
				Description: "Resource ID",
				Required:    true,
				Location:    "path",
			},
		},
	}
}
