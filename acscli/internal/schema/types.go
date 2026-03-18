package schema

// MethodSchema represents the schema for an API method
type MethodSchema struct {
	Service     string               `json:"service"`
	Method      string               `json:"method"`
	Description string               `json:"description,omitempty"`
	HTTP        HTTPInfo             `json:"http"`
	Parameters  map[string]Parameter `json:"parameters,omitempty"`
	RequestBody interface{}          `json:"request_body,omitempty"`
	Response    interface{}          `json:"response,omitempty"`
}

// HTTPInfo describes the HTTP endpoint
type HTTPInfo struct {
	Method string `json:"method"`
	Path   string `json:"path"`
}

// Parameter describes an API parameter
type Parameter struct {
	Name        string      `json:"name"`
	Type        string      `json:"type"`
	Description string      `json:"description,omitempty"`
	Required    bool        `json:"required,omitempty"`
	Default     interface{} `json:"default,omitempty"`
	Enum        []string    `json:"enum,omitempty"`
	Location    string      `json:"location,omitempty"` // path, query, header
}

// ServiceSchema represents a service with its methods
type ServiceSchema struct {
	Name        string   `json:"name"`
	Description string   `json:"description,omitempty"`
	Methods     []string `json:"methods"`
}
