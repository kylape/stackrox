package input

import (
	"encoding/json"
	"fmt"
	"os"
	"regexp"
	"strings"
	"unicode"
)

// ValidationError represents an input validation error
type ValidationError struct {
	Field   string `json:"field"`
	Message string `json:"message"`
	Value   string `json:"value,omitempty"`
}

func (e *ValidationError) Error() string {
	return fmt.Sprintf("%s: %s", e.Field, e.Message)
}

// Validator validates CLI inputs with agent-safety in mind
type Validator struct {
	// AllowedPathPrefixes restricts file paths to specific directories
	AllowedPathPrefixes []string
}

// NewValidator creates a new input validator
func NewValidator() *Validator {
	return &Validator{
		AllowedPathPrefixes: []string{
			"/tmp",
			".",
			os.Getenv("HOME"),
		},
	}
}

// ValidateResourceID validates a resource ID
// Agents may hallucinate IDs; this catches common errors
func (v *Validator) ValidateResourceID(id string) error {
	if id == "" {
		return &ValidationError{Field: "id", Message: "resource ID cannot be empty"}
	}

	// Check for control characters (agents sometimes include these)
	for _, r := range id {
		if unicode.IsControl(r) {
			return &ValidationError{
				Field:   "id",
				Message: "resource ID contains control characters",
				Value:   id,
			}
		}
	}

	// Check for URL-like patterns that shouldn't be in IDs
	if strings.Contains(id, "?") || strings.Contains(id, "#") {
		return &ValidationError{
			Field:   "id",
			Message: "resource ID contains query parameters or fragments",
			Value:   id,
		}
	}

	// Check for double-encoding (already URL-encoded strings)
	if strings.Contains(id, "%") {
		return &ValidationError{
			Field:   "id",
			Message: "resource ID appears to be URL-encoded; provide raw value",
			Value:   id,
		}
	}

	return nil
}

// ValidateFilePath validates a file path for safety
func (v *Validator) ValidateFilePath(path string) error {
	if path == "" {
		return &ValidationError{Field: "path", Message: "file path cannot be empty"}
	}

	// Check for path traversal
	if strings.Contains(path, "..") {
		return &ValidationError{
			Field:   "path",
			Message: "path traversal not allowed",
			Value:   path,
		}
	}

	// Check for null bytes
	if strings.ContainsRune(path, 0) {
		return &ValidationError{
			Field:   "path",
			Message: "path contains null bytes",
			Value:   path,
		}
	}

	// Check for dangerous patterns
	dangerous := []string{
		"/etc/passwd",
		"/etc/shadow",
		"/.ssh/",
		"/.aws/",
		"/.kube/",
		"/proc/",
		"/sys/",
	}
	pathLower := strings.ToLower(path)
	for _, d := range dangerous {
		if strings.Contains(pathLower, d) {
			return &ValidationError{
				Field:   "path",
				Message: "access to this path is not allowed",
				Value:   path,
			}
		}
	}

	return nil
}

// ValidateJSON validates and parses JSON input
// Handles both inline JSON and @filename references
func (v *Validator) ValidateJSON(input string) (map[string]interface{}, error) {
	if input == "" {
		return nil, nil
	}

	var data []byte
	var err error

	// Check for @filename syntax
	if strings.HasPrefix(input, "@") {
		filename := strings.TrimPrefix(input, "@")
		if err := v.ValidateFilePath(filename); err != nil {
			return nil, err
		}
		data, err = os.ReadFile(filename)
		if err != nil {
			return nil, &ValidationError{
				Field:   "json",
				Message: fmt.Sprintf("failed to read file: %v", err),
				Value:   filename,
			}
		}
	} else {
		data = []byte(input)
	}

	// Check for control characters in JSON
	for i, b := range data {
		if b < 0x20 && b != '\n' && b != '\r' && b != '\t' {
			return nil, &ValidationError{
				Field:   "json",
				Message: fmt.Sprintf("control character at position %d", i),
			}
		}
	}

	var result map[string]interface{}
	if err := json.Unmarshal(data, &result); err != nil {
		return nil, &ValidationError{
			Field:   "json",
			Message: fmt.Sprintf("invalid JSON: %v", err),
		}
	}

	return result, nil
}

// ValidateImageName validates a container image name
func (v *Validator) ValidateImageName(image string) error {
	if image == "" {
		return &ValidationError{Field: "image", Message: "image name cannot be empty"}
	}

	// Basic image name validation
	// Format: [registry/][namespace/]repository[:tag][@digest]
	validPattern := regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9._/-]*[a-zA-Z0-9](:[a-zA-Z0-9._-]+)?(@sha256:[a-fA-F0-9]{64})?$`)
	if !validPattern.MatchString(image) {
		return &ValidationError{
			Field:   "image",
			Message: "invalid image name format",
			Value:   image,
		}
	}

	return nil
}

// ValidateQuery validates a search query string
func (v *Validator) ValidateQuery(query string) error {
	if query == "" {
		return nil // Empty queries are allowed
	}

	// Check for control characters
	for _, r := range query {
		if unicode.IsControl(r) && r != '\n' && r != '\r' && r != '\t' {
			return &ValidationError{
				Field:   "query",
				Message: "query contains control characters",
				Value:   query,
			}
		}
	}

	// Limit query length to prevent abuse
	if len(query) > 4096 {
		return &ValidationError{
			Field:   "query",
			Message: "query exceeds maximum length (4096 characters)",
		}
	}

	return nil
}

// ValidateEndpoint validates an API endpoint URL
func (v *Validator) ValidateEndpoint(endpoint string) error {
	if endpoint == "" {
		return nil // Will use default
	}

	// Basic format validation
	endpointPattern := regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9.-]*:[0-9]+$`)
	if !endpointPattern.MatchString(endpoint) {
		// Also allow URLs
		urlPattern := regexp.MustCompile(`^https?://[a-zA-Z0-9][a-zA-Z0-9.-]*(:[0-9]+)?(/.*)?$`)
		if !urlPattern.MatchString(endpoint) {
			return &ValidationError{
				Field:   "endpoint",
				Message: "invalid endpoint format (expected host:port or URL)",
				Value:   endpoint,
			}
		}
	}

	return nil
}
