//go:build ignore

package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

// Service represents a parsed API service
type Service struct {
	Name        string
	DisplayName string
	Description string
	Methods     []*Method
}

// Method represents an API method
type Method struct {
	Name        string
	DisplayName string
	Description string
	HTTPMethod  string
	Path        string
	Parameters  []*Parameter
	HasBody     bool
	BodySchema  interface{}
}

// Parameter represents a method parameter
type Parameter struct {
	Name        string
	VarName     string // Safe Go variable name
	FlagName    string
	Type        string
	GoType      string
	Description string
	Required    bool
	Location    string // path, query, header
	Default     interface{}
}

// Parser parses OpenAPI/Swagger specs
type Parser struct{}

// NewParser creates a new parser
func NewParser() *Parser {
	return &Parser{}
}

// swaggerSpec represents the swagger.json structure
type swaggerSpec struct {
	Info struct {
		Title string `json:"title"`
	} `json:"info"`
	BasePath string                          `json:"basePath"`
	Paths    map[string]map[string]operation `json:"paths"`
}

type operation struct {
	Summary     string      `json:"summary"`
	Description string      `json:"description"`
	OperationID string      `json:"operationId"`
	Parameters  []parameter `json:"parameters"`
	Tags        []string    `json:"tags"`
}

type parameter struct {
	Name        string      `json:"name"`
	In          string      `json:"in"`
	Description string      `json:"description"`
	Required    bool        `json:"required"`
	Type        string      `json:"type"`
	Format      string      `json:"format"`
	Default     interface{} `json:"default"`
	Schema      *schemaRef  `json:"schema"`
}

type schemaRef struct {
	Ref  string `json:"$ref"`
	Type string `json:"type"`
}

// ParseFile parses a swagger file into a Service
func (p *Parser) ParseFile(path string) (*Service, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var spec swaggerSpec
	if err := json.Unmarshal(data, &spec); err != nil {
		return nil, err
	}

	// Extract service name from filename
	// e.g., "image_service.swagger.json" -> "image"
	base := filepath.Base(path)
	name := strings.TrimSuffix(base, ".swagger.json")
	name = strings.TrimSuffix(name, "_service")
	name = strings.ToLower(name)

	// Create display name
	displayName := toDisplayName(name)

	svc := &Service{
		Name:        name,
		DisplayName: displayName,
		Description: spec.Info.Title,
	}

	// Parse methods from paths
	var methods []*Method
	for path, pathOps := range spec.Paths {
		for httpMethod, op := range pathOps {
			if op.OperationID == "" {
				continue
			}

			method := p.parseOperation(httpMethod, path, &op)
			if method != nil {
				methods = append(methods, method)
			}
		}
	}

	// Sort methods by name for consistent output
	sort.Slice(methods, func(i, j int) bool {
		return methods[i].Name < methods[j].Name
	})

	svc.Methods = methods
	return svc, nil
}

func (p *Parser) parseOperation(httpMethod, path string, op *operation) *Method {
	// Extract method name from operation ID
	// e.g., "ImageService_ScanImage" -> "scan"
	name := extractMethodName(op.OperationID)
	if name == "" {
		return nil
	}

	// Make name unique by prepending HTTP method for non-GET operations
	// This handles cases where same endpoint has different methods (e.g., GET/POST)
	httpMethodUpper := strings.ToUpper(httpMethod)
	if httpMethodUpper != "GET" {
		// Check if name already starts with the HTTP verb
		lowerName := strings.ToLower(name)
		httpLower := strings.ToLower(httpMethod)
		if !strings.HasPrefix(lowerName, httpLower) && !strings.HasPrefix(lowerName, "create") &&
			!strings.HasPrefix(lowerName, "update") && !strings.HasPrefix(lowerName, "delete") &&
			!strings.HasPrefix(lowerName, "post") && !strings.HasPrefix(lowerName, "put") &&
			!strings.HasPrefix(lowerName, "patch") {
			name = httpLower + name
		}
	}

	method := &Method{
		Name:        name,
		DisplayName: toDisplayName(name),
		Description: sanitizeDescription(op.Summary),
		HTTPMethod:  httpMethodUpper,
		Path:        path,
	}

	// Parse parameters
	for _, param := range op.Parameters {
		if param.In == "body" {
			method.HasBody = true
			if param.Schema != nil {
				method.BodySchema = param.Schema.Ref
			}
			continue
		}

		goType := toGoType(param.Type, param.Format)
		// Skip array types - they need special flag handling
		if goType == "" {
			continue
		}
		p := &Parameter{
			Name:        param.Name,
			VarName:     toVarName(param.Name),
			FlagName:    toFlagName(param.Name),
			Type:        param.Type,
			GoType:      goType,
			Description: sanitizeDescription(param.Description),
			Required:    param.Required,
			Location:    param.In,
			Default:     param.Default,
		}
		method.Parameters = append(method.Parameters, p)
	}

	return method
}

// extractMethodName extracts a clean method name from operation ID
func extractMethodName(operationID string) string {
	// Handle "ServiceName_MethodName" format
	parts := strings.Split(operationID, "_")
	if len(parts) >= 2 {
		// Include service prefix if it helps disambiguate (e.g., ClusterCVE vs NodeCVE)
		servicePart := parts[0]
		methodPart := parts[len(parts)-1]

		// Extract unique prefix from service name (e.g., "ClusterCVEService" -> "cluster")
		servicePart = strings.TrimSuffix(servicePart, "Service")
		// If service has multiple parts (like ClusterCVE), use the first distinctive part
		if strings.Contains(servicePart, "CVE") {
			// Keep prefix before CVE (e.g., "Cluster", "Node")
			prefix := strings.ToLower(strings.Split(servicePart, "CVE")[0])
			if prefix != "" {
				return cleanMethodName(prefix + methodPart)
			}
		}
		return cleanMethodName(methodPart)
	}
	return cleanMethodName(operationID)
}

// cleanMethodName normalizes a method name
func cleanMethodName(name string) string {
	// Convert CamelCase to lowercase
	name = strings.ToLower(name)

	// Remove common prefixes that are redundant
	prefixes := []string{"get", "list", "create", "update", "delete", "post", "put", "patch"}
	for _, prefix := range prefixes {
		if strings.HasPrefix(name, prefix) && len(name) > len(prefix) {
			// Keep the prefix as the action
			return name
		}
	}

	return name
}

// toDisplayName converts a snake_case or lowercase name to display format
func toDisplayName(name string) string {
	// Replace underscores with spaces and title case
	name = strings.ReplaceAll(name, "_", " ")
	words := strings.Fields(name)
	for i, word := range words {
		if len(word) > 0 {
			words[i] = strings.ToUpper(word[:1]) + word[1:]
		}
	}
	return strings.Join(words, " ")
}

// toFlagName converts a parameter name to flag format
func toFlagName(name string) string {
	// Convert camelCase to kebab-case
	re := regexp.MustCompile(`([a-z])([A-Z])`)
	name = re.ReplaceAllString(name, "${1}-${2}")

	// Convert dots to dashes (e.g., "pagination.limit" -> "pagination-limit")
	name = strings.ReplaceAll(name, ".", "-")

	return strings.ToLower(name)
}

// toVarName converts a parameter name to a valid Go variable name
func toVarName(name string) string {
	// Replace dots with underscores for valid Go identifiers
	name = strings.ReplaceAll(name, ".", "_")
	// Replace dashes with underscores
	name = strings.ReplaceAll(name, "-", "_")
	return name
}

// sanitizeDescription cleans up description for use in Go code
func sanitizeDescription(desc string) string {
	// Replace newlines with spaces
	desc = strings.ReplaceAll(desc, "\n", " ")
	desc = strings.ReplaceAll(desc, "\r", " ")
	// Collapse multiple spaces
	for strings.Contains(desc, "  ") {
		desc = strings.ReplaceAll(desc, "  ", " ")
	}
	// Escape quotes
	desc = strings.ReplaceAll(desc, `"`, `\"`)
	// Trim
	desc = strings.TrimSpace(desc)
	return desc
}

// toGoType maps swagger types to Go types
func toGoType(swaggerType, format string) string {
	switch swaggerType {
	case "string":
		return "string"
	case "integer":
		switch format {
		case "int64":
			return "int64"
		case "int32":
			return "int32"
		default:
			return "int"
		}
	case "number":
		switch format {
		case "float":
			return "float32"
		default:
			return "float64"
		}
	case "boolean":
		return "bool"
	case "array":
		// Skip array types for now - they need special handling
		return ""
	default:
		return "string"
	}
}
